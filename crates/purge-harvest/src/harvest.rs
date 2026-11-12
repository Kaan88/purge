//! The harvest orchestrator: one inventory entry in, one `purge.fp/0` fingerprint out (ENGINE_PLAN.md
//! §5.2 "Fingerprint", §6.1, §3.4 `purge-engine harvest … -o fp.json`).
//!
//! The harvest runs **before** the app's uninstaller and only reads. Its order is fixed, because each
//! step feeds the next:
//!
//! 1. machine facts: Windows edition and build, the interactive user, the environment, the guard facts;
//! 2. the Inno Setup uninstall log, when the entry has one ([`crate::inno_map`]);
//! 3. the identity (`purge-identity`): names, vendors, tokens, proposed main exes;
//! 4. the validated roots ([`crate::roots`]) and the exe set under them ([`crate::exes`]);
//! 5. the registry anchors ([`crate::anchors`]) and the harvested tokens ([`crate::tokens`]);
//! 6. the files the installer declares outside the roots, and the linked sparse packages
//!    ([`crate::appx_link`]);
//! 7. with all anchors known: the reference snapshot ([`crate::refsnap`]), the subtree baselines
//!    ([`crate::subtree`]), the file-association journal ([`crate::assoc`]) and the co-product
//!    candidates ([`crate::coproducts`]);
//! 8. the stamps: Windows, user SID, install time.
//!
//! Nothing here fails. A fact that cannot be read becomes a line in the fingerprint's `warnings` and
//! the harvest goes on with less: fewer anchors only ever mean fewer findings.
//!
//! The output is deterministic: the same sources give a byte-identical document ([`to_json`]).
//!
//! # What the uninstall step adds later
//!
//! `window.t_start`, `window.t_end`, `verify_gone` and `co_removed` stay empty here. The co-product
//! *candidates* are returned in the [`HarvestReport`]; which of them really disappeared is known only
//! after the uninstaller ran.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use purge_guard::prefix;
use purge_identity::identity::{AppIdentity, IdentityHints};
use purge_identity::kbdata::Kb;
use purge_identity::tokenizer::vendor_key;
use purge_index::baseline::Baseline;
use purge_index::matcher::AnchorSet;
use purge_model::{
    AppRef, FileTime, Fingerprint, FingerprintSchema, InventoryDoc, InventoryEntry, OsInfo,
    TimeWindow,
};
use purge_source::filesystem::FileSystemSource;
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;

use crate::anchors::{self, AnchorInput, ModifiedProgId};
use crate::appx_link::{self, LinkedPackage};
use crate::assoc;
use crate::coproducts::{self, CoProductPre};
use crate::exes::{self, ExeLimits};
use crate::inno_map::{self, UserBinding};
use crate::refsnap::{self, HarvestCtx};
use crate::roots::{self, InnoRootFacts, RejectedRoot, RootEnv, env_map};
use crate::subtree::{self, SubtreeOptions};
use crate::tokens::{self, DroppedToken, TokenInput};

/// The value of an Inno Setup Uninstall key that names the app directory.
const INNO_APP_PATH: &str = "Inno Setup: App Path";

/// The three sources a harvest reads.
#[derive(Clone, Copy)]
pub struct Sources<'a> {
    /// The registry.
    pub reg: &'a dyn RegistrySource,
    /// The file system.
    pub fs: &'a dyn FileSystemSource,
    /// Machine and session facts.
    pub sys: &'a dyn SystemSource,
}

impl<'a> Sources<'a> {
    /// The sources of one object that implements all three (a fixture, the live machine).
    pub fn of<S>(source: &'a S) -> Self
    where
        S: RegistrySource + FileSystemSource + SystemSource,
    {
        Self {
            reg: source,
            fs: source,
            sys: source,
        }
    }
}

/// What the Inno Setup log gave, in numbers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InnoSummary {
    /// Canonical path of the log, when the entry has an Inno uninstaller.
    pub log_path: Option<String>,
    /// The log was read and parsed.
    pub parsed: bool,
    /// Records in the log, of every type.
    pub raw_records: usize,
    /// Records in the fingerprint.
    pub records: usize,
}

/// A fingerprint with the facts the document has no field for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarvestReport {
    /// The fingerprint.
    pub fingerprint: Fingerprint,
    /// Root claims that did not pass validation.
    pub rejected_roots: Vec<RejectedRoot>,
    /// Pre-existing or shared ProgIDs the app added verbs to; not in P.
    pub modified_progids: Vec<ModifiedProgId>,
    /// Candidate tokens that were not kept.
    pub dropped_tokens: Vec<DroppedToken>,
    /// The linked sparse packages, with their locations.
    pub linked_packages: Vec<LinkedPackage>,
    /// The Inno Setup log.
    pub inno: InnoSummary,
    /// Entries that may be removed together with the app.
    pub co_candidates: Vec<CoProductPre>,
    /// The reference scan read every key of its scope.
    pub refsnap_complete: bool,
}

/// Harvests `entry`: see the module documentation. `baseline` is used only when it is for exactly the
/// Windows the sources describe; `kb` supplies vendor aliases.
pub fn harvest(
    entry: &InventoryEntry,
    inventory: &InventoryDoc,
    sources: Sources<'_>,
    baseline: Option<&Baseline>,
    kb: &Kb,
) -> Fingerprint {
    harvest_report(entry, inventory, sources, baseline, kb).fingerprint
}

/// The vendor keys the knowledge base lists for the entry's publisher, when it is a mega-vendor.
fn kb_aliases(entry: &InventoryEntry, kb: &Kb) -> Vec<String> {
    let Some(publisher) = entry.publisher.as_deref() else {
        return Vec::new();
    };
    let key = vendor_key(publisher);
    if key.is_empty() {
        return Vec::new();
    }
    let at_boundary = |name: &str| {
        key.strip_prefix(name)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
    };
    kb.mega_vendors
        .entries()
        .iter()
        .find(|v| {
            std::iter::once(&v.vendor)
                .chain(&v.aliases)
                .any(|n| at_boundary(n))
        })
        .map(|v| {
            std::iter::once(&v.vendor)
                .chain(&v.aliases)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// The known accounts as (name, SID): the profile directory names, and the interactive user.
fn known_users(
    sys: &dyn SystemSource,
    env: &BTreeMap<String, String>,
    user_sid: &str,
) -> Vec<(String, String)> {
    let mut users: Vec<(String, String)> = Vec::new();
    let mut add = |name: &str, sid: &str| {
        let name = name.trim();
        if !name.is_empty()
            && !sid.is_empty()
            && !users
                .iter()
                .any(|(n, s)| n.eq_ignore_ascii_case(name) && s.eq_ignore_ascii_case(sid))
        {
            users.push((name.to_owned(), sid.to_owned()));
        }
    };
    if let Some(name) = env.get("USERNAME") {
        add(name, user_sid);
    }
    for profile in sys.profiles().unwrap_or_default() {
        if let Some(name) = prefix::leaf(profile.path.trim_end_matches('\\')) {
            add(name, &profile.sid);
        }
    }
    users
}

/// The earliest of the entry's install-time hints.
fn install_time(entry: &InventoryEntry) -> Option<FileTime> {
    entry.install_time_evidence.iter().map(|e| e.time).min()
}

/// Like [`harvest`], with the facts the fingerprint has no field for.
pub fn harvest_report(
    entry: &InventoryEntry,
    inventory: &InventoryDoc,
    sources: Sources<'_>,
    baseline: Option<&Baseline>,
    kb: &Kb,
) -> HarvestReport {
    let Sources { reg, fs, sys } = sources;
    let mut warnings: Vec<String> = Vec::new();

    // 1. Machine facts.
    let os = sys.os_info().unwrap_or_else(|e| {
        warnings.push(format!(
            "harvest: the Windows edition and build could not be read ({e}); no baseline is used"
        ));
        OsInfo {
            edition: String::new(),
            build: 0,
            ubr: 0,
        }
    });
    let user_sid = sys.user_sid().unwrap_or_else(|e| {
        warnings.push(format!(
            "harvest: the interactive user could not be determined ({e}); per-user registrations are not read"
        ));
        String::new()
    });
    let env_vars = sys.env().unwrap_or_else(|e| {
        warnings.push(format!("harvest: the environment could not be read ({e})"));
        BTreeMap::new()
    });
    let env = env_map(&env_vars);
    let (root_env, root_warnings) = RootEnv::from_sources(reg, sys, entry, inventory);
    warnings.extend(root_warnings);
    let guard = root_env.guard();

    let mut user_sids: Vec<String> = Vec::new();
    for sid in std::iter::once(&user_sid).chain(entry.hive_sid.as_ref()) {
        if !sid.is_empty() && !user_sids.iter().any(|s| s.eq_ignore_ascii_case(sid)) {
            user_sids.push(sid.clone());
        }
    }
    let matching_baseline = baseline.filter(|b| b.is_for(&os.edition, os.build, os.ubr));
    if let (Some(b), None) = (baseline, matching_baseline) {
        warnings.push(format!(
            "harvest: the baseline is for {}-{}.{}, not for this Windows ({}); it is not used",
            b.edition(),
            b.build(),
            b.ubr(),
            os.baseline_name()
        ));
    }

    // 2. The Inno Setup uninstall log.
    let binding = UserBinding {
        hive_sid: entry.hive_sid.clone(),
        users: known_users(sys, &env_vars, &user_sid),
    };
    let inno = inno_map::read(fs, entry, &binding, &env, guard);
    warnings.extend(inno.warnings.iter().cloned());

    // 3. Identity.
    let hints = IdentityHints {
        inno_app_name: inno.app_name.clone(),
        kb_aliases: kb_aliases(entry, kb),
        env: env_vars.clone(),
        ..IdentityHints::default()
    }
    .with_arp_urls(reg, entry);
    let identity = AppIdentity::resolve_with(entry, &inventory.entries, fs, &hints);
    warnings.extend(identity.warnings().iter().cloned());

    // 4. Roots and the exe set.
    let inno_facts = InnoRootFacts {
        app_path: reg
            .value(&entry.key_path, INNO_APP_PATH)
            .ok()
            .and_then(|d| d.string())
            .filter(|s| !s.trim().is_empty()),
        log_app_dirs: inno.app_dirs.clone(),
    };
    let root_set = roots::collect(fs, entry, &inno_facts, &env, &root_env);
    warnings.extend(root_set.rejected.iter().map(|r| format!("roots: {r}")));
    if root_set.roots.is_empty() {
        warnings
            .push("roots: the app has no validated root; nothing can be attributed by path".into());
    }
    let exe_set = exes::collect(
        fs,
        &root_set.roots,
        identity.main_exes(),
        ExeLimits::default(),
    );
    warnings.extend(exe_set.warnings.iter().cloned());

    // 5. Anchors and tokens.
    let anchor_harvest = anchors::collect(AnchorInput {
        reg,
        fs,
        sys,
        roots: &root_set.roots,
        exes: &exe_set.files,
        guard,
        env: &env_vars,
        user_sids: &user_sids,
        baseline: matching_baseline,
    });
    warnings.extend(anchor_harvest.warnings.iter().cloned());
    let token_harvest = tokens::harvest(TokenInput {
        entry,
        inventory: &inventory.entries,
        progids: &anchor_harvest.anchors.progids,
        aumids: &anchor_harvest.anchors.aumids,
        inno_app_id: inno.app_id.as_deref(),
        foreign_names: &anchor_harvest.foreign_names,
        baseline: matching_baseline,
    });

    // 6. Files outside the roots, and the sparse packages.
    let outside_root_files = inno
        .log_path
        .as_deref()
        .map(|log| inno_map::outside_root_files(&inno.records, &root_set.roots, log))
        .unwrap_or_default();
    let appx = appx_link::link(sys, &root_set.roots, guard);
    warnings.extend(appx.warnings.iter().cloned());
    let mut fp_anchors = anchor_harvest.anchors;
    fp_anchors.package_full_names = appx.full_names();
    fp_anchors.package_families = appx.families();

    let inno_summary = InnoSummary {
        log_path: inno.log_path.clone(),
        parsed: inno.parsed,
        raw_records: inno.raw_records,
        records: inno.records.len(),
    };
    let mut fp = Fingerprint {
        schema: FingerprintSchema,
        app: AppRef {
            program_id: entry.program_id.clone(),
            display_name: entry.display_name.clone(),
        },
        identity: identity.snapshot(),
        roots: root_set.roots,
        exes: exe_set.files,
        outside_root_files,
        anchors: fp_anchors,
        tokens: token_harvest.tokens,
        inno: inno.records,
        ref_snapshot: Vec::new(),
        subtrees: Vec::new(),
        ext_journal: Vec::new(),
        co_removed: Vec::new(),
        os,
        user_sid,
        window: TimeWindow {
            install_time: install_time(entry),
            t_start: None,
            t_end: None,
        },
        verify_gone: None,
        warnings: Vec::new(),
    };

    // 7. Everything that needs the full anchor set.
    let anchor_set = AnchorSet::from_fingerprint(&fp);
    let ctx = HarvestCtx {
        reg,
        fs,
        sys,
        anchors: &anchor_set,
        roots: &fp.roots,
        inno: &fp.inno,
        baseline,
        inventory: &inventory.entries,
        target: entry,
    };
    let (snapshot, subtrees, journal, co_candidates) = if anchor_set.is_empty() {
        warnings.push(
            "harvest: the app has no anchor; the reference snapshot, the subtree baselines and the \
             association journal are empty"
                .into(),
        );
        (
            refsnap::RefSnap {
                complete: true,
                ..refsnap::RefSnap::default()
            },
            subtree::SubtreeCapture::default(),
            assoc::AssocJournal::default(),
            coproducts::candidates(&ctx),
        )
    } else {
        let snapshot = refsnap::capture_report(&ctx);
        let keys = subtree::keys(&ctx, &snapshot.entries);
        let subtrees = subtree::capture_with(&ctx, &keys, &SubtreeOptions::default());
        let journal = assoc::capture_detailed(&ctx);
        (snapshot, subtrees, journal, coproducts::candidates(&ctx))
    };
    warnings.extend(snapshot.warnings.iter().cloned());
    warnings.extend(subtrees.warnings.iter().cloned());
    warnings.extend(journal.warnings.iter().cloned());
    let refsnap_complete = snapshot.complete;

    fp.ref_snapshot = snapshot.entries;
    fp.subtrees = subtrees.subtrees;
    fp.ext_journal = journal.records.into_iter().map(|r| r.entry).collect();
    fp.warnings = warnings;

    HarvestReport {
        fingerprint: fp,
        rejected_roots: root_set.rejected,
        modified_progids: anchor_harvest.modified_progids,
        dropped_tokens: token_harvest.dropped,
        linked_packages: appx.packages,
        inno: inno_summary,
        co_candidates,
        refsnap_complete,
    }
}

/// The fingerprint as the text of an `fp.json` file: pretty-printed JSON with a final newline. The same
/// fingerprint always gives the same bytes.
pub fn to_json(fp: &Fingerprint) -> String {
    let mut text = serde_json::to_string_pretty(fp).expect("a fingerprint serialises to JSON");
    text.push('\n');
    text
}

/// Writes the fingerprint to `path` ([`to_json`]).
pub fn write(fp: &Fingerprint, path: &Path) -> io::Result<()> {
    std::fs::write(path, to_json(fp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchors::ModifiedReason;
    use crate::inno_map::testlog;
    use purge_guard::canon::GuardEnv;
    use purge_model::{InnoRecordKind, RootKind, RootSource, SourceTrust, Target};
    use purge_source::fixture::{Fixture, FixtureBuilder};
    use purge_source::types::{KnownFolder, PackageInfo, PackageSignatureKind};

    const SID: &str = GuardEnv::SAMPLE_SID;
    const CODE: &str = r"C:\Program Files\Microsoft VS Code";
    const CODE_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{EA457B21-F73E-494C-ACAB-524FDE069978}_is1";
    const CODE_GUID: &str = "EA457B21-F73E-494C-ACAB-524FDE069978";
    const CODE_PKG: &str = "Microsoft.VisualStudioCode_1.106.0.0_x64__8wekyb3d8bbwe";
    const EDGE_PKG: &str = "Microsoft.MicrosoftEdge.Stable_142.0.3595.65_neutral__8wekyb3d8bbwe";

    fn machine() -> FixtureBuilder {
        Fixture::builder()
            .os("Professional", 26100, 1742)
            .user_sid(SID)
            .profile(SID, r"C:\Users\tester")
            .env("USERNAME", "tester")
            .env("SYSTEMDRIVE", "C:")
            .env("WINDIR", r"C:\Windows")
            .env("SYSTEMROOT", r"C:\Windows")
            .env("PROGRAMFILES", r"C:\Program Files")
            .env("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
            .env("PROGRAMDATA", r"C:\ProgramData")
            .env("PUBLIC", r"C:\Users\Public")
            .env("APPDATA", r"C:\Users\tester\AppData\Roaming")
            .env("LOCALAPPDATA", r"C:\Users\tester\AppData\Local")
            .known_folder(KnownFolder::Documents, r"C:\Users\tester\Documents")
            .admin_only_roots(&[
                r"C:\Program Files",
                r"C:\Program Files (x86)",
                r"C:\Windows",
            ])
            .volume(r"C:\", Some(0xAABB_CCDD), true, "NTFS")
            .key(r"HKLM\SYSTEM\ControlSet001\Services")
            .now(134_000_000_000_000_000)
    }

    fn sparse(full_name: &str, family: &str, external: &str) -> PackageInfo {
        PackageInfo {
            full_name: full_name.into(),
            family: family.into(),
            install_location: None,
            external_location: Some(external.into()),
            sparse: true,
            users: vec![SID.into()],
            is_framework: false,
            is_resource: false,
            signature_kind: PackageSignatureKind::Developer,
        }
    }

    fn command(b: FixtureBuilder, key: &str, verb: &str, command: &str) -> FixtureBuilder {
        b.sz(&format!(r"{key}\shell\{verb}\command"), "", command)
    }

    /// A machine with VS Code (system installer), Notepad and Edge.
    fn vscode_machine() -> Fixture {
        let code_exe = format!(r#""{CODE}\Code.exe" "%1""#);
        let log = testlog::build(
            "{{EA457B21-F73E-494C-ACAB-524FDE069978}",
            "Microsoft Visual Studio Code",
            crate::inno::MAX_SUPPORTED_VERSION,
            testlog::ADMIN,
            true,
            &[
                (testlog::START, 0, &["PC", "tester", CODE, ""]),
                (
                    testlog::FILE,
                    0,
                    &[r"C:\Program Files\Microsoft VS Code\Code.exe"],
                ),
                (testlog::DIR, 0, &[r"C:\Program Files\Microsoft VS Code"]),
                (testlog::KEY, testlog::HKCR, &["VSCode.txt"]),
                (
                    testlog::KEY,
                    testlog::HKLM,
                    &[r"Software\Classes\VSCodeSourceFile"],
                ),
                (
                    testlog::VALUE,
                    testlog::HKCU,
                    &["Environment", "VSCODE_TEST"],
                ),
                (testlog::END, 0, &[]),
            ],
        );
        let mut b = machine()
            // The Uninstall key, as Inno Setup writes it.
            .sz(CODE_KEY, "DisplayName", "Microsoft Visual Studio Code")
            .sz(CODE_KEY, "DisplayVersion", "1.106.0")
            .sz(CODE_KEY, "Publisher", "Microsoft Corporation")
            .sz(
                CODE_KEY,
                "InstallLocation",
                r"C:\Program Files\Microsoft VS Code\",
            )
            .sz(CODE_KEY, "Inno Setup: App Path", CODE)
            .sz(
                CODE_KEY,
                "DisplayIcon",
                r"C:\Program Files\Microsoft VS Code\Code.exe",
            )
            .sz(
                CODE_KEY,
                "UninstallString",
                r#""C:\Program Files\Microsoft VS Code\unins000.exe""#,
            )
            .sz(CODE_KEY, "URLInfoAbout", "https://code.visualstudio.com/")
            .key_lwt(CODE_KEY, 133_900_000_000_000_000)
            // Its files.
            .file(&format!(r"{CODE}\Code.exe"), 150_000_000)
            .file(&format!(r"{CODE}\unins000.exe"), 3_000_000)
            .file(&format!(r"{CODE}\ffmpeg.dll"), 2_000_000)
            .file(&format!(r"{CODE}\bin\rg.exe"), 20_000_000)
            .file(&format!(r"{CODE}\resources\app\package.json"), 100)
            .file_content(&format!(r"{CODE}\unins000.dat"), log)
            // Another app.
            .sz(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Other",
                "DisplayName",
                "Other Editor",
            )
            .sz(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Other",
                "UninstallString",
                r#""C:\Program Files\Other\uninstall.exe""#,
            )
            .file(r"C:\Program Files\Other\uninstall.exe", 10)
            .file(r"C:\Program Files\Other\other.exe", 10)
            // References to the app.
            .sz(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Code.exe",
                "",
                r"C:\Program Files\Microsoft VS Code\Code.exe",
            )
            .sz(r"HKLM\SOFTWARE\Classes\.txt", "", "txtfile")
            .sz(
                r"HKLM\SOFTWARE\Classes\.txt\OpenWithProgids",
                "VSCode.txt",
                "",
            )
            .sz(
                r"HKLM\SOFTWARE\Classes\VSCode.txt\DefaultIcon",
                "",
                r"C:\Program Files\Microsoft VS Code\resources\app\resources\win32\default.ico",
            )
            .sz(
                &format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Run"),
                "Code Updater",
                r#""C:\Program Files\Microsoft VS Code\bin\rg.exe" --update"#,
            )
            .package(sparse(
                CODE_PKG,
                "Microsoft.VisualStudioCode_8wekyb3d8bbwe",
                r"C:\Program Files\Microsoft VS Code\69047191fc\appx",
            ))
            .package(sparse(
                EDGE_PKG,
                "Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe",
                r"C:\Program Files (x86)\Microsoft\Edge\Application",
            ));
        // The app's ProgIDs, machine-wide and (the URL protocol) per-user.
        for progid in ["VSCode.txt", "VSCode.json", "VSCodeSourceFile"] {
            b = command(
                b,
                &format!(r"HKLM\SOFTWARE\Classes\{progid}"),
                "open",
                &code_exe,
            );
        }
        b = command(
            b,
            &format!(r"HKU\{SID}_Classes\vscode"),
            "open",
            &format!(r#""{CODE}\Code.exe" --open-url -- "%1""#),
        );
        // `txtfile` ships with Windows; the app added a verb to it.
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\txtfile",
            "open",
            r"%SystemRoot%\system32\NOTEPAD.EXE %1",
        );
        b = command(b, r"HKLM\SOFTWARE\Classes\txtfile", "VSCode", &code_exe);
        b = command(
            b,
            r"HKLM\SOFTWARE\Classes\Other.Document",
            "open",
            r#""C:\Program Files\Other\other.exe" "%1""#,
        );
        b.build()
    }

    fn inventory_of(f: &Fixture) -> InventoryDoc {
        purge_inventory::arp::inventory(f, f, f, 0).doc
    }

    fn entry_named<'a>(doc: &'a InventoryDoc, name: &str) -> &'a InventoryEntry {
        doc.entries
            .iter()
            .find(|e| e.display_name == name)
            .unwrap_or_else(|| panic!("no entry {name:?} in {:?}", doc.entries))
    }

    #[test]
    fn vscode_shaped_fixture_gives_a_complete_fingerprint() {
        let f = vscode_machine();
        let doc = inventory_of(&f);
        let entry = entry_named(&doc, "Microsoft Visual Studio Code");
        let report = harvest_report(entry, &doc, Sources::of(&f), None, Kb::shipped());
        let fp = &report.fingerprint;

        // Roots: one InstallRoot, admin-only, with its volume.
        assert_eq!(fp.roots.len(), 1, "{:?}", fp.roots);
        assert_eq!(fp.roots[0].path, CODE);
        assert_eq!(fp.roots[0].kind, RootKind::InstallRoot);
        assert_eq!(fp.roots[0].trust, SourceTrust::AdminOnly);
        assert_eq!(fp.roots[0].volume_serial, Some(0xAABB_CCDD));
        assert!(fp.roots[0].parent_existed);
        assert!(
            report.rejected_roots.is_empty(),
            "{:?}",
            report.rejected_roots
        );

        // The exe set, with Code.exe as the main exe.
        let exes: Vec<(&str, bool)> = fp.exes.iter().map(|e| (e.path.as_str(), e.main)).collect();
        assert_eq!(
            exes,
            [
                (r"C:\Program Files\Microsoft VS Code\bin\rg.exe", false),
                (r"C:\Program Files\Microsoft VS Code\Code.exe", true),
                (r"C:\Program Files\Microsoft VS Code\ffmpeg.dll", false),
                (r"C:\Program Files\Microsoft VS Code\unins000.exe", false),
            ]
        );

        // P: the VSCode ProgIDs and the protocol; `txtfile` was only modified.
        assert_eq!(
            fp.anchors.progids,
            ["vscode", "VSCode.json", "VSCode.txt", "VSCodeSourceFile"]
        );
        assert_eq!(
            report.modified_progids,
            [ModifiedProgId {
                name: "txtfile".into(),
                reason: ModifiedReason::ForeignCommand
            }]
        );
        assert_eq!(fp.anchors.run_entries.len(), 1);
        assert_eq!(fp.anchors.run_entries[0].name, "Code Updater");

        // The linked sparse package is VS Code's, never Edge's.
        assert_eq!(fp.anchors.package_full_names, [CODE_PKG]);
        assert_eq!(
            fp.anchors.package_families,
            ["Microsoft.VisualStudioCode_8wekyb3d8bbwe"]
        );

        // Tokens: the AppId GUID, without braces.
        assert_eq!(fp.tokens.len(), 1, "{:?}", fp.tokens);
        assert_eq!(fp.tokens[0].token, CODE_GUID);
        assert_eq!(fp.tokens[0].source.0, "arp:key");

        // The Inno records: HKCU bound to the installing user, key-create on the keys.
        assert!(report.inno.parsed);
        assert_eq!(report.inno.raw_records, 7);
        assert_eq!(report.inno.records, fp.inno.len());
        let key_creates: Vec<&Target> = fp
            .inno
            .iter()
            .filter(|r| r.key_create)
            .map(|r| &r.target)
            .collect();
        assert_eq!(
            key_creates,
            [
                &Target::RegKey {
                    path: r"HKLM\SOFTWARE\Classes\VSCode.txt".into()
                },
                &Target::RegKey {
                    path: r"HKLM\SOFTWARE\Classes\VSCodeSourceFile".into()
                },
            ]
        );
        let user_value = fp
            .inno
            .iter()
            .find(|r| r.kind == InnoRecordKind::RegDeleteValue)
            .expect("the HKCU value record");
        assert!(user_value.user_hive);
        assert_eq!(
            user_value.target,
            Target::RegValue {
                path: format!(r"HKU\{SID}\Environment"),
                name: "VSCODE_TEST".into()
            }
        );

        // The second half ran: references, subtrees, journal.
        assert!(report.refsnap_complete);
        assert!(
            fp.ref_snapshot.iter().any(|e| matches!(
                &e.target,
                Target::RegValue { path, .. } if path.ends_with(r"App Paths\Code.exe")
            )),
            "{:?}",
            fp.ref_snapshot
        );
        assert!(
            fp.subtrees
                .iter()
                .any(|s| s.key.ends_with(r"Classes\VSCode.txt"))
        );
        assert!(
            fp.ext_journal
                .iter()
                .any(|j| j.ext == ".txt" && j.openwith_ours == ["VSCode.txt"])
        );

        // The stamps.
        assert_eq!(fp.os.baseline_name(), "Professional-26100.1742");
        assert_eq!(fp.user_sid, SID);
        assert!(fp.window.install_time.is_some());
        assert_eq!((fp.window.t_start, fp.window.t_end), (None, None));
        assert!(fp.verify_gone.is_none() && fp.co_removed.is_empty());
        assert!(fp.identity.mega_vendor);
        assert!(
            fp.identity
                .names
                .iter()
                .any(|n| n == "Microsoft Visual Studio Code")
        );
        // A fixture records no key owners, which the subtree harvest reports; nothing else is amiss.
        assert!(
            fp.warnings.iter().all(|w| w.starts_with("subtree:")),
            "{:?}",
            fp.warnings
        );

        // `harvest` is the fingerprint of the report.
        assert_eq!(
            &harvest(entry, &doc, Sources::of(&f), None, Kb::shipped()),
            fp
        );
    }

    #[test]
    fn the_same_fixture_gives_byte_identical_json() {
        let first = {
            let f = vscode_machine();
            let doc = inventory_of(&f);
            let entry = entry_named(&doc, "Microsoft Visual Studio Code");
            to_json(&harvest(entry, &doc, Sources::of(&f), None, Kb::shipped()))
        };
        let second = {
            let f = vscode_machine();
            let doc = inventory_of(&f);
            let entry = entry_named(&doc, "Microsoft Visual Studio Code");
            to_json(&harvest(entry, &doc, Sources::of(&f), None, Kb::shipped()))
        };
        assert_eq!(first, second);
        assert!(
            first.starts_with("{\n  \"schema\": \"purge.fp/0\""),
            "{}",
            &first[..60]
        );
        assert!(first.ends_with("}\n"));
        // It is a valid fingerprint document and survives a round trip unchanged.
        let parsed: Fingerprint = serde_json::from_str(&first).unwrap();
        assert_eq!(to_json(&parsed), first);

        // And it reaches the disk as the same bytes.
        let dir = std::env::temp_dir().join(format!("purge-harvest-fp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fp.json");
        write(&parsed, &path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rule_t_a_per_user_entry_gives_user_writable_roots() {
        let app = r"C:\Users\tester\AppData\Local\Programs\Tool";
        let key = format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Uninstall\Tool");
        let log = testlog::build(
            "Tool",
            "Tool",
            crate::inno::MAX_SUPPORTED_VERSION,
            0,
            true,
            &[
                (testlog::START, 0, &["PC", "somebody-else", app, ""]),
                (
                    testlog::KEY,
                    testlog::HKCU,
                    &[r"Software\Classes\Tool.File"],
                ),
                (testlog::END, 0, &[]),
            ],
        );
        let f = command(
            machine()
                .sz(&key, "DisplayName", "Tool")
                .sz(&key, "InstallLocation", app)
                .sz(&key, "UninstallString", &format!(r#""{app}\unins000.exe""#))
                .file(&format!(r"{app}\Tool.exe"), 1_000)
                .file(&format!(r"{app}\unins000.exe"), 1_000)
                .file_content(&format!(r"{app}\unins000.dat"), log)
                // Even a directory only administrators can write is not trusted through an HKU entry.
                .admin_only_writable(app, true),
            &format!(r"HKU\{SID}_Classes\Tool.File"),
            "open",
            &format!(r#""{app}\Tool.exe" "%1""#),
        )
        .build();
        let doc = inventory_of(&f);
        let entry = entry_named(&doc, "Tool");
        assert_eq!(entry.hive_sid.as_deref(), Some(SID));
        let report = harvest_report(entry, &doc, Sources::of(&f), None, Kb::shipped());
        let fp = &report.fingerprint;
        assert_eq!(
            fp.roots.len(),
            1,
            "{:?} / {:?}",
            fp.roots,
            report.rejected_roots
        );
        assert_eq!(fp.roots[0].path, app);
        assert_eq!(fp.roots[0].source, RootSource::ArpInstallLocation);
        assert_eq!(fp.roots[0].trust, SourceTrust::UserWritable);
        assert_eq!(fp.anchors.progids, ["Tool.File"]);
        // The log's HKCU record is bound to the hive of the entry, whatever account the log names.
        assert_eq!(
            fp.inno.iter().map(|r| &r.target).collect::<Vec<_>>(),
            [&Target::RegKey {
                path: format!(r"HKU\{SID}_Classes\Tool.File")
            }]
        );
        assert!(fp.inno[0].user_hive && fp.inno[0].key_create);
    }

    #[test]
    fn an_entry_without_a_usable_root_still_gives_a_document() {
        // InstallLocation is Program Files itself; the uninstaller sits in the Windows directory.
        let key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Broken";
        let f = machine()
            .sz(key, "DisplayName", "Broken App")
            .sz(key, "InstallLocation", r"C:\Program Files\")
            .sz(key, "UninstallString", r"C:\Windows\uninst.exe /S")
            .file(r"C:\Windows\uninst.exe", 10)
            .dir(r"C:\Program Files")
            .build();
        let doc = inventory_of(&f);
        let entry = entry_named(&doc, "Broken App");
        let report = harvest_report(entry, &doc, Sources::of(&f), None, Kb::shipped());
        let fp = &report.fingerprint;
        assert!(fp.roots.is_empty(), "{:?}", fp.roots);
        assert!(!report.rejected_roots.is_empty());
        assert!(fp.exes.is_empty() && fp.anchors.progids.is_empty());
        assert!(fp.ref_snapshot.is_empty() && fp.subtrees.is_empty());
        assert!(
            fp.warnings.iter().any(|w| w.contains("rejected")),
            "{:?}",
            fp.warnings
        );
        assert!(fp.warnings.iter().any(|w| w.contains("no validated root")));
        assert_eq!(fp.app.display_name, "Broken App");
        serde_json::from_str::<Fingerprint>(&to_json(fp)).unwrap();
    }

    #[test]
    fn kb_aliases_come_from_the_mega_vendor_entry_of_the_publisher() {
        let mut entry = crate::roots::tests_support::entry("X", "X");
        assert!(kb_aliases(&entry, Kb::shipped()).is_empty());
        entry.publisher = Some("Microsoft Corporation".into());
        let aliases = kb_aliases(&entry, Kb::shipped());
        assert!(aliases.iter().any(|a| a == "microsoft"), "{aliases:?}");
        entry.publisher = Some("Nobody In Particular Ltd".into());
        assert!(kb_aliases(&entry, Kb::shipped()).is_empty());
    }

    // -----------------------------------------------------------------------------------------------------
    // Real rig snapshots
    // -----------------------------------------------------------------------------------------------------

    fn run_main_key(run_json: &Path) -> Option<String> {
        let text = std::fs::read_to_string(run_json).ok()?;
        let value: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
        value
            .get("main")
            .and_then(|m| m.get("key"))
            .and_then(|k| k.as_str())
            .map(str::to_owned)
    }

    /// With `PURGE_RUNS_DIR` (e.g. `vm/runs`): harvests VS Code, Git, Firefox and Notepad++ from their
    /// post-install snapshots and prints a summary. `PURGE_OVERLAY_DIR`, when set, holds one directory
    /// per app with file contents the snapshot lacks (`<overlay>\<app>\C\Program Files\…\unins000.dat`).
    #[test]
    #[ignore = "needs PURGE_RUNS_DIR with the vscode, git, firefox and npp runs"]
    fn harvests_the_rig_snapshots() {
        let Some(runs) = std::env::var_os("PURGE_RUNS_DIR") else {
            eprintln!("PURGE_RUNS_DIR not set; skipping");
            return;
        };
        let overlay_root = std::env::var_os("PURGE_OVERLAY_DIR").map(std::path::PathBuf::from);
        let baselines = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../kb/baselines");

        // (run, a word of the DisplayName, the family prefix of the sparse package it must link)
        let apps: [(&str, &str, Option<&str>); 4] = [
            (
                "vscode",
                "Visual Studio Code",
                Some("Microsoft.VisualStudioCode_"),
            ),
            ("git", "Git", None),
            ("firefox", "Firefox", None),
            ("npp", "Notepad++", Some("NotepadPlusPlus_")),
        ];
        for (app, name_part, package) in apps {
            let dir = Path::new(&runs).join(app);
            let snap = dir.join(format!("snap-{app}-1.tsv.gz"));
            let lists = dir.join(format!("lists-{app}-1.json"));
            let overlay = overlay_root
                .as_ref()
                .map(|o| o.join(app))
                .filter(|o| o.is_dir());
            let started = std::time::Instant::now();
            let f = Fixture::from_snap(
                &snap,
                lists.is_file().then_some(lists.as_path()),
                overlay.as_deref(),
            )
            .unwrap_or_else(|e| panic!("{}: {e}", snap.display()));
            let loaded = started.elapsed();

            let doc = inventory_of(&f);
            let main_key = run_main_key(&dir.join("run.json"));
            let entry = main_key
                .as_deref()
                .and_then(|key| {
                    doc.entries.iter().find(|e| {
                        prefix::eq_ci(&e.key_path, key)
                            || prefix::leaf(&e.key_path)
                                .zip(prefix::leaf(key))
                                .is_some_and(|(a, b)| prefix::eq_ci(a, b))
                    })
                })
                .or_else(|| {
                    doc.entries
                        .iter()
                        .find(|e| e.display_name.contains(name_part))
                })
                .unwrap_or_else(|| panic!("{app}: no inventory entry for {name_part:?}"));

            use purge_source::system::SystemSource;
            let os = f.os_info().unwrap();
            let baseline = Baseline::select(&baselines, &os.edition, os.build, os.ubr);
            let started = std::time::Instant::now();
            let report = harvest_report(
                entry,
                &doc,
                Sources::of(&f),
                baseline.as_ref(),
                Kb::shipped(),
            );
            let took = started.elapsed();
            let fp = &report.fingerprint;

            eprintln!("== {app}: {} ({})", fp.app.display_name, fp.app.program_id);
            eprintln!(
                "   fixture loaded in {loaded:?}, harvested in {took:?}; baseline {}: {}",
                os.baseline_name(),
                if baseline.is_some() { "loaded" } else { "none" }
            );
            for root in &fp.roots {
                eprintln!(
                    "   root {:?} {:?} {:?} {}",
                    root.kind, root.source, root.trust, root.path
                );
            }
            for rejected in &report.rejected_roots {
                eprintln!("   rejected: {rejected}");
            }
            eprintln!(
                "   exes {} ({} main), |P| {}, modified ProgIDs {}, CLSIDs {}, AppIDs {}, TypeLibs {}, AUMIDs {}, Run {}",
                fp.exes.len(),
                fp.main_exes().count(),
                fp.anchors.progids.len(),
                report.modified_progids.len(),
                fp.anchors.clsids.len(),
                fp.anchors.appids.len(),
                fp.anchors.typelibs.len(),
                fp.anchors.aumids.len(),
                fp.anchors.run_entries.len()
            );
            eprintln!("   P: {:?}", fp.anchors.progids);
            eprintln!("   modified: {:?}", report.modified_progids);
            eprintln!("   AUMIDs: {:?}", fp.anchors.aumids);
            eprintln!(
                "   tokens: {:?}; dropped: {:?}",
                fp.tokens
                    .iter()
                    .map(|t| (&t.token, &t.source.0))
                    .collect::<Vec<_>>(),
                report.dropped_tokens
            );
            eprintln!(
                "   inno: log {:?}, parsed {}, {} raw record(s), {} mapped; {} file(s) outside the roots",
                report.inno.log_path,
                report.inno.parsed,
                report.inno.raw_records,
                report.inno.records,
                fp.outside_root_files.len()
            );
            eprintln!(
                "   refsnap {} (complete {}), subtrees {}, ext journal {}, co-product candidates {:?}",
                fp.ref_snapshot.len(),
                report.refsnap_complete,
                fp.subtrees.len(),
                fp.ext_journal.len(),
                report
                    .co_candidates
                    .iter()
                    .map(|c| &c.app.display_name)
                    .collect::<Vec<_>>()
            );
            eprintln!("   packages: {:?}", fp.anchors.package_full_names);
            for warning in &fp.warnings {
                eprintln!("   warning: {warning}");
            }

            // The linked sparse packages are exactly the app's own.
            match package {
                Some(prefix) => {
                    assert_eq!(
                        fp.anchors.package_full_names.len(),
                        1,
                        "{app}: {:?}",
                        fp.anchors.package_full_names
                    );
                    assert!(
                        fp.anchors.package_full_names[0].starts_with(prefix),
                        "{app}: {:?}",
                        fp.anchors.package_full_names
                    );
                }
                None => assert!(
                    fp.anchors.package_full_names.is_empty(),
                    "{app}: {:?}",
                    fp.anchors.package_full_names
                ),
            }
            assert!(
                fp.anchors
                    .package_full_names
                    .iter()
                    .all(|p| !p.to_ascii_lowercase().contains("edge")),
                "{app}: the Edge sparse package must never be linked"
            );
            assert!(!fp.roots.is_empty(), "{app}: no root");
            if app == "vscode" {
                assert!(fp.anchors.progids.iter().any(|p| p.starts_with("VSCode.")));
                assert!(
                    !fp.anchors
                        .progids
                        .iter()
                        .any(|p| p.eq_ignore_ascii_case("txtfile"))
                );
            }
            if app == "firefox" {
                assert!(
                    fp.tokens.iter().any(|t| t.token == "308046B0AF4A39CB"),
                    "firefox: {:?} / {:?}",
                    fp.tokens,
                    report.dropped_tokens
                );
            }
            // Deterministic on real data too.
            let again = harvest(
                entry,
                &doc,
                Sources::of(&f),
                baseline.as_ref(),
                Kb::shipped(),
            );
            assert_eq!(to_json(&again), to_json(fp), "{app}: not deterministic");
        }
    }
}
