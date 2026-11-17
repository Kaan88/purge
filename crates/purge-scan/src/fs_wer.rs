//! Scanner FS-WER (ENGINE_PLAN.md §5.6; M1b package M1B-S-DIAG): the Windows Error Reporting reports of
//! the removed app's programs (crashes, hangs, non-critical events).
//!
//! # What is looked at
//!
//! The report stores `ReportArchive` and `ReportQueue` below `%ProgramData%\Microsoft\Windows\WER` and
//! below each profile's `%LOCALAPPDATA%\Microsoft\Windows\WER` (the profiles the guard knows), each
//! listed once, by name only. A report directory there is looked at when its name is `AppCrash_`,
//! `AppHang_` or `NonCritical_` followed by a prefix of the file name of one of the app's exes (WER cuts
//! the program name short) and then `_`. The prefix must be the whole name or at least
//! [`MIN_NAME_PREFIX`] characters of it; this only bounds what is read, the decision comes next.
//!
//! The report directory is listed once, and its `Report.wer` is read (at most [`MAX_REPORT_BYTES`];
//! UTF-16 LE with or without its byte-order mark, or UTF-8). The report is offered only when its
//! `AppPath=` line, the full path of the program that crashed, is in the guard's canonical form inside an
//! InstallRoot of the app or one of its exe files. Every `AppPath=` line of the file must say the same.
//! Not offered:
//!
//! - a report without `Report.wer`, with one that is larger than the cap, cannot be read or decoded,
//!   or has no `AppPath=`;
//! - a report whose program has the app's exe name but lies elsewhere (another product's `app.exe`);
//! - a report directory holding a directory or a reparse point (not the shape WER writes).
//!
//! The WER stores themselves (and `Temp`) are never candidates (guard rule `fs.wer-root`).
//!
//! # What a candidate says
//!
//! `Target::Path` (the report directory), `Action::Quarantine`, `Category::Privacy`, the size and file
//! count of the one listing. The evidence is what the report's content says: the program it names points
//! into the app (`PointsIntoInstallRoot`, recorded with Value scope because it is about a line of the
//! file, not about the directory), lowered to Tier B: a report is at most Likely in M1b, never
//! preselected. A program inside another app's root, or one another app's records name, blocks it.
//!
//! Reports in `%ProgramData%` stay denied by the guard's `fs.programdata.microsoft` rule; the plan shows
//! them as protected.
//!
//! # Reads
//!
//! One `list_dir()` of each WER store, then per report directory whose name matches one `list_dir()` and
//! one `read_bytes()`. No registry read.
//!
//! # Missing data
//!
//! There is no scan-warning channel for scanners yet: a store or report that cannot be read
//! (`AccessDenied`, `NotCaptured`) makes no candidate; the spots are marked `// warning:`.

use purge_guard::canon::canon_path;
use purge_guard::prefix;
use purge_model::{
    Action, AnchorKind, AnchorRef, Blocker, Candidate, Category, Evidence, EvidenceKind, Facts,
    Scope, SourceTrust, Target,
};
use purge_source::types::{DirEntry, SourceError};

use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner, anchor_trust, weakest};
use crate::fs_installdir::{clean_path, has_extension, is_plain_dir, join};

/// The scanner's catalog id.
pub const ID: &str = "FS-WER";

/// The report stores below a `WER` directory.
pub const REPORT_STORES: [&str; 2] = ["ReportArchive", "ReportQueue"];

/// The kinds of report directory looked at, as their names start.
pub const REPORT_KINDS: [&str; 3] = ["AppCrash_", "AppHang_", "NonCritical_"];

/// The report file of a report directory.
pub const REPORT_FILE: &str = "Report.wer";

/// The most bytes of a `Report.wer` read; a larger file is not read at all.
pub const MAX_REPORT_BYTES: usize = 1 << 20;

/// The shortest prefix of an exe name a report directory's name may carry (when the name is longer).
pub const MIN_NAME_PREFIX: usize = 4;

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[
    RootSpec::fs(
        r"%ProgramData%\Microsoft\Windows\WER\ReportArchive",
        Some(2),
    ),
    RootSpec::fs(r"%ProgramData%\Microsoft\Windows\WER\ReportQueue", Some(2)),
    RootSpec::fs(
        r"%LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive",
        Some(2),
    ),
    RootSpec::fs(r"%LOCALAPPDATA%\Microsoft\Windows\WER\ReportQueue", Some(2)),
];

/// The FS-WER scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsWer;

impl Scanner for FsWer {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        let names = exe_names(ctx);
        if names.is_empty() {
            return Vec::new();
        }
        let mut out: Vec<Candidate> = Vec::new();
        for store in wer_stores(ctx) {
            let entries = match ctx.fs.list_dir(&store) {
                Ok(entries) => entries,
                Err(SourceError::NotFound) => continue,
                // warning: the WER store cannot be listed (access denied, not captured, a reparse
                // point): none of its reports is offered.
                Err(_) => continue,
            };
            // warning: a store with more entries than a listing may hold is not enumerable.
            if entries.len() > ctx.limits.max_dir_entries {
                continue;
            }
            for entry in &entries {
                if !is_plain_dir(&entry.meta) || !names_an_exe(&entry.name, &names) {
                    continue;
                }
                let dir = join(&store, &entry.name);
                if out.iter().any(
                    |c| matches!(&c.target, Target::Path { path } if prefix::is_same(path, &dir)),
                ) {
                    continue;
                }
                out.extend(report_candidate(ctx, &dir));
            }
        }
        out
    }
}

/// The file names of the app's exes (`.exe` files of `fp.exes`).
fn exe_names(ctx: &ScanCtx<'_>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for exe in &ctx.fp.exes {
        let Some(name) = prefix::leaf(&exe.path) else {
            continue;
        };
        if has_extension(name, &["exe"]) && !out.iter().any(|n| prefix::eq_ci(n, name)) {
            out.push(name.to_owned());
        }
    }
    out
}

/// The WER report stores of this machine, canonical: `ReportArchive` and `ReportQueue` below
/// `%ProgramData%\Microsoft\Windows\WER` and below every profile's `%LOCALAPPDATA%` one.
fn wer_stores(ctx: &ScanCtx<'_>) -> Vec<String> {
    let guard = ctx.guard;
    let mut out: Vec<String> = Vec::new();
    let bases = std::iter::once(guard.program_data.as_str())
        .chain(guard.profiles.iter().map(|p| p.local_appdata.as_str()))
        .filter(|dir| !dir.trim().is_empty());
    for base in bases {
        for store in REPORT_STORES {
            let input = format!(
                r"{}\Microsoft\Windows\WER\{store}",
                base.trim().trim_end_matches(prefix::SEP)
            );
            let Ok(canon) = canon_path(&input, guard, None) else {
                continue;
            };
            if canon.needs_long_name {
                continue;
            }
            if !out.iter().any(|have| prefix::is_same(have, &canon.path)) {
                out.push(canon.path);
            }
        }
    }
    out
}

/// Whether a report directory's name is one of [`REPORT_KINDS`] followed by a prefix of one of `names`
/// (the whole name, or at least [`MIN_NAME_PREFIX`] characters of it) and `_`.
pub fn names_an_exe(dir_name: &str, names: &[String]) -> bool {
    let Some(rest) = REPORT_KINDS.iter().find_map(|kind| {
        dir_name
            .get(..kind.len())
            .filter(|head| head.eq_ignore_ascii_case(kind))
            .map(|_| &dir_name[kind.len()..])
    }) else {
        return false;
    };
    rest.match_indices('_').any(|(at, _)| {
        let head = &rest[..at];
        names.iter().any(|name| {
            let needed = name.chars().count().min(MIN_NAME_PREFIX);
            head.chars().count() >= needed
                && name
                    .get(..head.len())
                    .is_some_and(|start| start.eq_ignore_ascii_case(head))
        })
    })
}

/// The text of a `Report.wer`: UTF-16 LE (with its byte-order mark, or without one when the text
/// starts with an ASCII character) or UTF-8 (with or without its mark). `None` when it decodes as
/// neither.
pub fn decode_report(bytes: &[u8]) -> Option<String> {
    fn utf16le(bytes: &[u8]) -> Option<String> {
        if bytes.len() % 2 != 0 {
            return None;
        }
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units).ok()
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return utf16le(rest);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return std::str::from_utf8(rest).ok().map(str::to_owned);
    }
    if bytes.len() >= 2 && bytes[0] != 0 && bytes[1] == 0 {
        return utf16le(bytes);
    }
    std::str::from_utf8(bytes)
        .ok()
        .filter(|text| !text.contains('\0'))
        .map(str::to_owned)
}

/// The program a report names (`AppPath=`), when it has the line and every such line says the same.
pub fn report_app_path(text: &str) -> Option<&str> {
    const KEY: &str = "AppPath=";
    let mut found: Option<&str> = None;
    for line in text.lines() {
        let line = line.trim_start_matches('\u{feff}').trim();
        let Some(value) = line
            .get(..KEY.len())
            .filter(|head| head.eq_ignore_ascii_case(KEY))
            .map(|_| line[KEY.len()..].trim())
        else {
            continue;
        };
        match found {
            Some(seen) if !prefix::eq_ci(seen, value) => return None,
            _ => found = Some(value),
        }
    }
    found.filter(|value| !value.is_empty())
}

/// The candidate for the report directory `dir`, or nothing.
fn report_candidate(ctx: &ScanCtx<'_>, dir: &str) -> Option<Candidate> {
    // warning: a report directory that cannot be listed (access denied, not captured) is not offered.
    let entries: Vec<DirEntry> = ctx.fs.list_dir(dir).ok()?;
    if entries.len() > ctx.limits.max_dir_entries {
        return None;
    }
    // WER writes files only: anything else is not a report as this scanner knows one.
    if entries
        .iter()
        .any(|e| e.meta.is_dir() || e.meta.is_reparse_point())
    {
        return None;
    }
    let report = entries
        .iter()
        .find(|e| prefix::eq_ci(&e.name, REPORT_FILE))?;
    if report.meta.size > MAX_REPORT_BYTES as u64 {
        return None;
    }
    // warning: a `Report.wer` that cannot be read (access denied, not captured) offers nothing.
    let bytes = ctx
        .fs
        .read_bytes(&join(dir, &report.name), MAX_REPORT_BYTES + 1)
        .ok()?;
    if bytes.len() > MAX_REPORT_BYTES {
        return None;
    }
    let text = decode_report(&bytes)?;
    let program = program_of(ctx, report_app_path(&text)?)?;
    let trust = if let Some(root) = ctx.inside_install_root(&program) {
        root.trust
    } else if ctx.is_app_file(&program) {
        anchor_trust(
            ctx.fp,
            &AnchorRef {
                kind: AnchorKind::Exe,
                text: program.clone(),
            },
        )
    } else {
        // Another product's program of the same name, or a copy elsewhere.
        return None;
    };

    let mut b = ctx.candidate(
        ID,
        Target::Path {
            path: dir.to_owned(),
        },
        Action::Quarantine,
        Category::Privacy,
    );
    // The report's own words, which anyone who can write the report can choose.
    let trust = weakest(trust, SourceTrust::UserWritable);
    let evidence = Evidence::new(
        EvidenceKind::PointsIntoInstallRoot,
        Scope::Value,
        trust,
        format!("wer:{program}"),
    )
    .map(|e| {
        e.with_detail(
            Facts::new()
                .with("path", program.clone())
                .with("file", REPORT_FILE),
        )
    });
    b.evidence_also(evidence);
    b.cap_at_tier_b("a crash report is the app's by the program it names only");
    for blocker in ctx.other_apps.path_blockers(&program) {
        if matches!(
            blocker,
            Blocker::InsideOtherApp { .. } | Blocker::ReferencedByOtherApp { .. }
        ) {
            b.blocker(blocker);
        }
    }
    let size: u64 = entries.iter().map(|e| e.meta.size).sum();
    b.size_bytes(size)
        .child_count(u32::try_from(entries.len()).unwrap_or(u32::MAX));
    b.common_blockers();
    Some(b.build())
}

/// The program a report names, canonical; `None` when it is not one absolute drive path the guard can
/// vouch for.
fn program_of(ctx: &ScanCtx<'_>, app_path: &str) -> Option<String> {
    let clean = clean_path(app_path)?;
    let canon = canon_path(&clean, ctx.guard, None).ok()?;
    (!canon.needs_long_name).then_some(canon.path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_are_well_formed() {
        assert!(ROOTS.iter().all(RootSpec::is_well_formed));
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn report_names_carry_a_prefix_of_an_exe_name() {
        let exes = names(&["7zFM.exe", "MicrosoftEdgeUpdate.exe", "ab.exe"]);
        for good in [
            "AppCrash_7zFM.exe_3b5e1c_cab_0123",
            "apphang_7zfm.exe_1_2",
            "NonCritical_MicrosoftEdgeUp_9f_abc",
            "AppCrash_ab.exe_1",
        ] {
            assert!(names_an_exe(good, &exes), "{good}");
        }
        for bad in [
            "AppCrash_7z.e_1",
            "AppCrash_7zF_1",
            "AppCrash_other.exe_1",
            "Critical_7zFM.exe_1",
            "AppCrash_7zFM.exe",
            "7zFM.exe_1",
            "AppCrash_a_1",
        ] {
            assert!(!names_an_exe(bad, &exes), "{bad}");
        }
    }

    #[test]
    fn reports_decode_from_utf16_and_utf8() {
        let text = "Version=1\r\nAppPath=C:\\Program Files\\App\\app.exe\r\n";
        let mut utf16: Vec<u8> = vec![0xFF, 0xFE];
        utf16.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode_report(&utf16).as_deref(), Some(text));
        let bare: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(decode_report(&bare).as_deref(), Some(text));
        assert_eq!(decode_report(text.as_bytes()).as_deref(), Some(text));
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend(text.as_bytes());
        assert_eq!(decode_report(&bom).as_deref(), Some(text));
        assert_eq!(decode_report(&[0xFF, 0xFE, 0x41]), None);
        assert_eq!(decode_report(&[0xC3, 0x28]), None);
    }

    #[test]
    fn app_path_lines_must_agree() {
        assert_eq!(
            report_app_path("A=1\nAppPath=C:\\x\\a.exe\r\nB=2"),
            Some("C:\\x\\a.exe")
        );
        assert!(
            report_app_path("apppath=C:\\x\\a.exe\nAppPath=c:\\X\\A.exe")
                .is_some_and(|p| p.eq_ignore_ascii_case("C:\\x\\a.exe"))
        );
        assert_eq!(
            report_app_path("AppPath=C:\\x\\a.exe\nAppPath=C:\\y\\a.exe"),
            None
        );
        assert_eq!(report_app_path("AppName=a.exe"), None);
        assert_eq!(report_app_path("AppPath="), None);
    }
}
