//! Co-product candidates: other inventory entries that may disappear together with the target
//! (ENGINE_PLAN.md §5.2 "co-removed products").
//!
//! Firefox's uninstaller also removes the Mozilla Maintenance Service, which has an ARP entry and a
//! directory of its own. Once it is gone nothing can be learned about it, so the harvest summarises
//! every entry that plausibly goes with the target **before** the uninstaller runs. After the uninstall
//! the runner's diff of disappeared entries picks from these ([`co_removed`]).
//!
//! # Who is a candidate
//!
//! An entry other than the target with the **same vendor** (equal vendor keys of the two publishers)
//! and at least one tie to the target ([`CoProductReason`]):
//!
//! - one of its directories lies inside a root of the target;
//! - it shares a vendor directory with the target: a root of the target and a directory of the entry
//!   have the same parent, and that parent is not a shared system location (a known folder, a volume
//!   root, a directory of clean Windows);
//! - the target's Inno log touches its ARP key or its directories;
//! - the target ships a program named after it: an exe of the target's roots (or of its uninstaller's
//!   directory) is named like the entry's product name without the vendor (`maintenanceservice.exe`
//!   and `maintenanceservice_installer.exe` for "Mozilla Maintenance Service").
//!
//! Sharing only the vendor is not enough: Thunderbird does not go when Firefox is uninstalled, although
//! both are Mozilla's and both sit directly in `Program Files`.
//!
//! A candidate is a guess about what the uninstaller will do, not evidence of ownership. Nothing here
//! attributes a file or key to the target; the directories of a [`CoProductPre`] are the entry's own
//! claims and are not validated roots.
//!
//! # The candidate's own fingerprint
//!
//! A co-removed product's leftovers are attributed through its own identity, roots and anchors, never
//! through the target's (ENGINE_PLAN.md §5.2, §5.4, §6). So every candidate is harvested like a target
//! of its own while it is still installed ([`CoProductPre::fingerprint`]): the same orchestrator, the
//! same root validation. [`co_removed`] hands that fingerprint on for the candidates that really
//! disappeared, and the scanners then run once more with it. The candidates of a candidate are not
//! followed: only what the target takes with it is looked at.

use std::cell::Cell;
use std::collections::BTreeSet;

use purge_guard::prefix;
use purge_identity::kbdata::Kb;
use purge_identity::tokenizer::{full_name_key, vendor_key};
use purge_model::{
    AppRef, CoRemovedProduct, Fingerprint, InventoryDoc, InventoryEntry, InventorySchema,
    ProgramId, Target,
};
use serde::{Deserialize, Serialize};

use crate::harvest::{self, Sources};
use crate::refsnap::{HarvestCtx, source_key};

/// Why an entry may disappear with the target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CoProductReason {
    /// A directory of the entry lies inside this root of the target.
    InsideTargetRoot {
        /// The entry's directory.
        dir: String,
    },
    /// The entry and the target sit side by side in this vendor directory.
    SharedVendorDir {
        /// The shared parent directory.
        dir: String,
    },
    /// The target's Inno log has a record on this path or key of the entry.
    InnoLog {
        /// The record's target.
        target: String,
    },
    /// The target ships this file, which is named after the entry.
    NamedInTargetRoot {
        /// The file's path.
        file: String,
    },
}

/// The pre-harvest summary of one co-product candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoProductPre {
    /// The entry.
    pub app: AppRef,
    /// Canonical path of its Uninstall key.
    pub key_path: String,
    /// The directories its ARP entry names (`InstallLocation`, the uninstaller's and the icon's
    /// directory), as claimed: not validated roots.
    pub roots: Vec<String>,
    /// GUIDs and hex tokens of at least 12 digits found in its key name and installer ids.
    pub tokens: Vec<String>,
    /// Why it is a candidate; never empty.
    pub reasons: Vec<CoProductReason>,
    /// Its own fingerprint, harvested while it was still installed. `None` when it was not harvested
    /// (a document written before this field existed); its leftovers can then not be attributed.
    #[serde(default)]
    pub fingerprint: Option<Box<Fingerprint>>,
}

thread_local! {
    /// Set while a candidate's own fingerprint is being harvested on this thread.
    static IN_CO_HARVEST: Cell<bool> = const { Cell::new(false) };
}

/// Resets [`IN_CO_HARVEST`] when the candidate harvest ends, also by a panic.
struct CoHarvestGuard;

impl Drop for CoHarvestGuard {
    fn drop(&mut self) {
        IN_CO_HARVEST.with(|flag| flag.set(false));
    }
}

/// Harvests a candidate as a target of its own, from the same sources and before the uninstaller
/// runs. The harvest only reads and never fails; its own co-product candidates are not followed.
fn harvest_candidate(ctx: &HarvestCtx<'_>, entry: &InventoryEntry) -> Box<Fingerprint> {
    IN_CO_HARVEST.with(|flag| flag.set(true));
    let _guard = CoHarvestGuard;
    let inventory = InventoryDoc {
        schema: InventorySchema,
        entries: ctx.inventory.to_vec(),
        msi_only: Vec::new(),
    };
    let sources = Sources {
        reg: ctx.reg,
        fs: ctx.fs,
        sys: ctx.sys,
    };
    Box::new(harvest::harvest(
        entry,
        &inventory,
        sources,
        ctx.baseline,
        Kb::shipped(),
    ))
}

/// Lower-case letters and digits only.
fn compact(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// The vendor key of an entry's publisher, in compact form; `None` when it has none.
fn vendor_of(entry: &InventoryEntry) -> Option<String> {
    let key = compact(&vendor_key(entry.publisher.as_deref()?));
    (!key.is_empty()).then_some(key)
}

/// The compact product names of an entry: its display name and key name, without versions and the
/// like, and without the leading vendor name when something remains.
fn product_names(entry: &InventoryEntry, vendor: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in [entry.display_name.as_str(), entry.program_id.key_name()] {
        let full = compact(&full_name_key(name));
        let product = match full.strip_prefix(vendor) {
            Some(rest) if !rest.is_empty() => rest.to_owned(),
            _ => full,
        };
        if !product.is_empty() && !out.contains(&product) {
            out.push(product);
        }
    }
    out
}

/// The shortest product name that may be matched against file names.
const MIN_PRODUCT_NAME: usize = 6;

/// The path of the program a command line or an icon reference names, as far as it can be told
/// without a full parser: the quoted first argument, or the text up to the first `.exe`, or the text
/// without a trailing icon index.
fn command_path(text: &str) -> Option<String> {
    let text = text.trim();
    let path = if let Some(rest) = text.strip_prefix('"') {
        rest.split('"').next().unwrap_or(rest).to_owned()
    } else if let Some(at) = text.to_ascii_lowercase().find(".exe") {
        text[..at + 4].to_owned()
    } else {
        match text.rsplit_once(',') {
            Some((path, index)) if index.trim().trim_start_matches('-').parse::<u32>().is_ok() => {
                path.to_owned()
            }
            _ => text.to_owned(),
        }
    };
    let path = path.trim().trim_end_matches(prefix::SEP);
    let bytes = path.as_bytes();
    (bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\')
        .then(|| path.to_owned())
}

/// The directories an entry's ARP values name, each once, in a fixed order.
fn entry_dirs(entry: &InventoryEntry) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |dir: Option<String>| {
        if let Some(dir) = dir {
            // A drive root is nobody's directory.
            if prefix::depth(&dir) >= 2 && !out.iter().any(|d| prefix::is_same(d, &dir)) {
                out.push(dir);
            }
        }
    };
    add(entry
        .install_location
        .as_deref()
        .and_then(|location| command_path(location.trim().trim_matches('"'))));
    for command in [
        &entry.uninstall_string,
        &entry.quiet_uninstall_string,
        &entry.display_icon,
    ] {
        add(command
            .as_deref()
            .and_then(command_path)
            .and_then(|file| prefix::parent(&file).map(str::to_owned)));
    }
    out
}

fn is_hex_token(run: &str) -> bool {
    run.len() >= 12 && run.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_guid(run: &str) -> bool {
    let parts: Vec<&str> = run.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8usize, 4, 4, 4, 12])
            .all(|(part, len)| part.len() == len && part.chars().all(|c| c.is_ascii_hexdigit()))
}

/// The GUIDs and hex tokens (at least 12 digits) in `text`, as whole runs of letters, digits and `-`.
fn tokens_in(text: &str, out: &mut Vec<String>) {
    for run in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
        let run = run.trim_matches('-');
        if (is_guid(run) || is_hex_token(run)) && !out.iter().any(|t| t.eq_ignore_ascii_case(run)) {
            out.push(run.to_owned());
        }
    }
}

struct TargetFacts<'a> {
    ctx: &'a HarvestCtx<'a>,
    vendor: String,
    products: Vec<String>,
    /// Exe files of the target: (path, compact stem).
    files: Vec<(String, String)>,
    /// Folded paths of the shared system locations.
    system_dirs: BTreeSet<String>,
}

impl<'a> TargetFacts<'a> {
    fn new(ctx: &'a HarvestCtx<'a>, vendor: String) -> Self {
        let mut files: Vec<(String, String)> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut add = |path: String| {
            let Some(name) = prefix::leaf(&path) else {
                return;
            };
            let Some((stem, ext)) = name.rsplit_once('.') else {
                return;
            };
            if ext.eq_ignore_ascii_case("exe") && seen.insert(prefix::fold(&path)) {
                let stem = compact(stem);
                files.push((path, stem));
            }
        };
        for path in ctx.exe_paths() {
            add(path.to_owned());
        }
        // The top level of each root and of the uninstaller's directory, in case the exe set is partial.
        let mut dirs: Vec<String> = ctx.roots.iter().map(|root| root.path.clone()).collect();
        dirs.extend(entry_dirs(ctx.target));
        for dir in dirs {
            let mut entries = ctx.fs.list_dir(&dir).unwrap_or_default();
            entries.sort_by_key(|entry| prefix::fold(&entry.name));
            for entry in entries {
                add(format!("{dir}\\{}", entry.name));
            }
        }

        let system_dirs = ctx
            .sys
            .known_folders()
            .unwrap_or_default()
            .into_values()
            .map(|path| prefix::fold(path.trim_end_matches(prefix::SEP)))
            .collect();
        Self {
            products: product_names(ctx.target, &vendor),
            ctx,
            vendor,
            files,
            system_dirs,
        }
    }

    /// Whether a directory is a shared system location, where being neighbours means nothing.
    fn is_system_dir(&self, dir: &str) -> bool {
        const NAMES: [&str; 9] = [
            "program files",
            "program files (x86)",
            "programdata",
            "common files",
            "programs",
            "appdata",
            "local",
            "locallow",
            "roaming",
        ];
        let folded = prefix::fold(dir.trim_end_matches(prefix::SEP));
        prefix::depth(&folded) < 2
            || self.system_dirs.contains(&folded)
            || prefix::leaf(&folded).is_some_and(|leaf| NAMES.contains(&leaf))
            || self
                .ctx
                .matching_baseline()
                .is_some_and(|baseline| baseline.has_path(&folded))
    }

    fn reasons(&self, entry: &InventoryEntry, dirs: &[String]) -> Vec<CoProductReason> {
        let ctx = self.ctx;
        let mut out = Vec::new();

        for dir in dirs {
            if ctx
                .roots
                .iter()
                .any(|root| prefix::is_same_or_inside(dir, &root.path))
            {
                out.push(CoProductReason::InsideTargetRoot { dir: dir.clone() });
            }
        }

        let mut shared: Vec<String> = Vec::new();
        for dir in dirs {
            let Some(parent) = prefix::parent(dir) else {
                continue;
            };
            let neighbours = ctx.roots.iter().any(|root| {
                !prefix::is_same(&root.path, dir)
                    && prefix::parent(&root.path).is_some_and(|p| prefix::is_same(p, parent))
            });
            if neighbours
                && !self.is_system_dir(parent)
                && !shared.iter().any(|s| prefix::is_same(s, parent))
            {
                shared.push(parent.to_owned());
            }
        }
        out.extend(
            shared
                .into_iter()
                .map(|dir| CoProductReason::SharedVendorDir { dir }),
        );

        // The log's unbound `HKCU` is the target's user; the entry's key path is already bound.
        let bound = ctx.bind_sid();
        let sid = bound.as_deref();
        let arp_key = source_key(&entry.key_path, sid);
        let logged = ctx.inno.iter().find_map(|record| match &record.target {
            Target::Path { path } => dirs
                .iter()
                .any(|dir| prefix::is_same_or_inside(path, dir))
                .then(|| path.clone()),
            Target::RegKey { path } | Target::RegValue { path, .. } => {
                prefix::is_same_or_inside(&source_key(path, sid), &arp_key).then(|| path.clone())
            }
            _ => None,
        });
        out.extend(logged.map(|target| CoProductReason::InnoLog { target }));

        let named = product_names(entry, &self.vendor)
            .into_iter()
            .filter(|product| {
                product.chars().count() >= MIN_PRODUCT_NAME
                    // A sibling install of the same product is not a component of this one.
                    && !self.products.contains(product)
            })
            .find_map(|product| {
                self.files
                    .iter()
                    .find(|(_, stem)| stem.starts_with(&product))
                    .map(|(path, _)| path.clone())
            });
        out.extend(named.map(|file| CoProductReason::NamedInTargetRoot { file }));

        out
    }
}

/// The entries of the inventory that may disappear with the target, in inventory order.
pub fn candidates(ctx: &HarvestCtx<'_>) -> Vec<CoProductPre> {
    // The harvest of a candidate: what goes with *it* is not this target's business, and following it
    // would never end for two entries that are each other's candidate.
    if IN_CO_HARVEST.with(Cell::get) {
        return Vec::new();
    }
    let Some(vendor) = vendor_of(ctx.target) else {
        return Vec::new();
    };
    let target = TargetFacts::new(ctx, vendor);
    let mut out = Vec::new();
    for entry in ctx.inventory {
        if entry.program_id == ctx.target.program_id
            || prefix::is_same(&entry.key_path, &ctx.target.key_path)
            || vendor_of(entry).as_deref() != Some(target.vendor.as_str())
        {
            continue;
        }
        let dirs = entry_dirs(entry);
        let reasons = target.reasons(entry, &dirs);
        if reasons.is_empty() {
            continue;
        }
        let mut tokens = Vec::new();
        let ids = [
            Some(entry.program_id.key_name()),
            entry.product_code.as_deref(),
            entry.upgrade_code.as_deref(),
            entry.inno_app_id.as_deref(),
        ];
        for id in ids.into_iter().flatten() {
            tokens_in(id, &mut tokens);
        }
        out.push(CoProductPre {
            app: AppRef {
                program_id: entry.program_id.clone(),
                display_name: entry.display_name.clone(),
            },
            key_path: entry.key_path.clone(),
            roots: dirs,
            tokens,
            reasons,
            fingerprint: Some(harvest_candidate(ctx, entry)),
        });
    }
    out
}

/// The co-removed products of the fingerprint: the candidates whose entry disappeared during the
/// uninstall, in candidate order, each with the fingerprint harvested for it while it was installed. An
/// entry that disappeared without having been a candidate is not listed, because nothing was harvested
/// for it.
pub fn co_removed(candidates: &[CoProductPre], disappeared: &[ProgramId]) -> Vec<CoRemovedProduct> {
    candidates
        .iter()
        .filter(|candidate| disappeared.contains(&candidate.app.program_id))
        .map(|candidate| CoRemovedProduct {
            app: candidate.app.clone(),
            fingerprint: candidate.fingerprint.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_index::matcher::AnchorSet;
    use purge_model::{Root, RootKind, RootSource, SourceTrust};
    use purge_source::fixture::Fixture;

    use crate::roots::tests_support::entry;

    const PLAYER: &str = r"C:\Program Files\Zorblat Player";
    const SERVICE: &str = r"C:\Program Files (x86)\Zorblat Update Service";
    const SID: &str = "S-1-5-21-1-2-3-1001";

    fn zorblat(key: &str, name: &str, dir: &str, uninstaller: &str) -> InventoryEntry {
        let mut e = entry(key, name);
        e.publisher = Some("Zorblat".into());
        e.install_location = Some(dir.to_owned());
        e.uninstall_string = Some(format!("\"{dir}\\{uninstaller}\""));
        e
    }

    /// A player that ships the installer of the vendor's update service, which has an ARP entry and a
    /// directory of its own. Each is the other's candidate by the rules of this module.
    #[test]
    fn a_candidate_is_harvested_as_a_target_of_its_own() {
        let fixture = Fixture::builder()
            .os("Professional", 26100, 1)
            .user_sid(SID)
            .profile(SID, r"C:\Users\tester")
            .env("SYSTEMDRIVE", "C:")
            .env("WINDIR", r"C:\Windows")
            .env("SYSTEMROOT", r"C:\Windows")
            .env("PROGRAMFILES", r"C:\Program Files")
            .env("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
            .env("PROGRAMDATA", r"C:\ProgramData")
            .env("PUBLIC", r"C:\Users\Public")
            .admin_only_roots(&[r"C:\Program Files", r"C:\Program Files (x86)"])
            .volume(r"C:\", Some(0xAABB_CCDD), true, "NTFS")
            .key(r"HKLM\SOFTWARE")
            .file(&format!(r"{PLAYER}\player.exe"), 700_000)
            .file(&format!(r"{PLAYER}\updateservice_installer.exe"), 200_000)
            .file(&format!(r"{PLAYER}\uninstall.exe"), 100_000)
            .file(&format!(r"{SERVICE}\updateservice.exe"), 250_000)
            .file(&format!(r"{SERVICE}\uninstall.exe"), 100_000)
            .build();
        let inventory = vec![
            zorblat("ZorblatPlayer", "Zorblat Player", PLAYER, "uninstall.exe"),
            zorblat(
                "ZorblatUpdateService",
                "Zorblat Update Service",
                SERVICE,
                "uninstall.exe",
            ),
        ];
        let mut anchors = AnchorSet::new();
        anchors.add_root(PLAYER);
        let roots = vec![Root {
            path: PLAYER.into(),
            kind: RootKind::InstallRoot,
            source: RootSource::ArpInstallLocation,
            trust: SourceTrust::AdminOnly,
            volume_serial: None,
            parent_existed: true,
        }];
        let ctx = HarvestCtx {
            reg: &fixture,
            fs: &fixture,
            sys: &fixture,
            anchors: &anchors,
            roots: &roots,
            inno: &[],
            baseline: None,
            inventory: &inventory,
            target: &inventory[0],
            cutoff: None,
        };

        let found = candidates(&ctx);
        assert_eq!(found.len(), 1, "{found:#?}");
        let service = &found[0];
        assert_eq!(service.app.display_name, "Zorblat Update Service");
        let fp = service
            .fingerprint
            .as_deref()
            .expect("the candidate has a fingerprint of its own");
        // Its own identity and its own validated root, not the target's.
        assert_eq!(fp.app, service.app);
        assert!(
            fp.identity
                .names
                .iter()
                .any(|n| n == "Zorblat Update Service")
        );
        assert_eq!(
            fp.roots.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
            [SERVICE]
        );
        // What goes with the candidate is not followed, and nothing of the session is in it yet.
        assert!(fp.co_removed.is_empty());
        assert!(fp.window.t_start.is_none() && fp.window.t_end.is_none());
        // The flag is cleared again: a second harvest on this thread sees the candidate as before.
        assert_eq!(candidates(&ctx), found);

        // Only a candidate that disappeared is co-removed, and it brings its fingerprint.
        let removed = co_removed(&found, std::slice::from_ref(&service.app.program_id));
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].fingerprint, service.fingerprint);
        assert!(co_removed(&found, &[]).is_empty());

        // A summary written before the field existed still reads; it has no fingerprint.
        let mut json = serde_json::to_value(&found).unwrap();
        json[0].as_object_mut().unwrap().remove("fingerprint");
        let old: Vec<CoProductPre> = serde_json::from_value(json).unwrap();
        assert!(old[0].fingerprint.is_none());
        assert!(
            co_removed(&old, std::slice::from_ref(&service.app.program_id))[0]
                .fingerprint
                .is_none()
        );
    }

    #[test]
    fn command_paths() {
        let ff = r"C:\Program Files\Mozilla Firefox";
        assert_eq!(
            command_path(&format!(r#""{ff}\uninstall\helper.exe" /S"#)).as_deref(),
            Some(format!(r"{ff}\uninstall\helper.exe").as_str())
        );
        assert_eq!(
            command_path(&format!(r"{ff}\firefox.exe,0")).as_deref(),
            Some(format!(r"{ff}\firefox.exe").as_str())
        );
        assert_eq!(
            command_path(r"C:\Program Files\App\unins000.exe /SILENT").as_deref(),
            Some(r"C:\Program Files\App\unins000.exe")
        );
        assert_eq!(
            command_path(r"C:\Program Files\App\app.ico,-3").as_deref(),
            Some(r"C:\Program Files\App\app.ico")
        );
        assert_eq!(command_path(&format!("{ff}\\")).as_deref(), Some(ff));
        assert_eq!(command_path("MsiExec.exe /X{0}"), None);
        assert_eq!(command_path(r"C:\"), None);
        assert_eq!(command_path(""), None);
    }

    #[test]
    fn tokens() {
        let mut out = Vec::new();
        tokens_in("{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1", &mut out);
        tokens_in("Mozilla Firefox 308046B0AF4A39CB", &mut out);
        tokens_in("MozillaMaintenanceService", &mut out);
        tokens_in("{771fd6b0-fa20-440a-a002-3b3bac16dc50}", &mut out);
        tokens_in("deadbeef 2024-01-02", &mut out);
        assert_eq!(
            out,
            ["771FD6B0-FA20-440A-A002-3B3BAC16DC50", "308046B0AF4A39CB"]
        );
    }

    #[test]
    fn compact_names() {
        assert_eq!(
            compact("Mozilla Maintenance-Service"),
            "mozillamaintenanceservice"
        );
        assert_eq!(compact("Notepad++ (64-bit)"), "notepad64bit");
    }
}
