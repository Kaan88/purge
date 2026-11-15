//! FS-UNINSTALLER (ENGINE_PLAN.md §5.6): leftover uninstaller files and their directory
//! (`UninstallerArtifact`).
//!
//! The fingerprint does not keep the `UninstallString`, so the uninstaller is recognised by where it is
//! and what it is called, and only in directories the harvest validated:
//!
//! - in an InstallRoot, or in the root the harvest read from the uninstaller's own location
//!   (`RootSource::UninstallerDir`): a file directly in the directory named like an uninstaller
//!   (`unins000.exe`, `uninstall.exe`, `Uninst.exe`…) and, next to an Inno Setup uninstaller, its
//!   `unins000.dat` log and `unins000.msg` message file;
//! - the uninstaller's own directory, when it is a subdirectory of an InstallRoot (`<root>\uninstall`,
//!   or an `UninstallerDir` root strictly inside an InstallRoot).
//!
//! # Whose uninstaller
//!
//! A name like `uninstall.exe` and a place in the app's folder do not make a file the app's: other
//! tools live in shared folders with uninstallers of their own, registered or not. The fingerprint
//! names the app's own uninstaller files (`Fingerprint::uninstallers`: the program of the
//! `UninstallString`, and the Inno log and message file of the same number).
//!
//! - **A file** that is one of them keeps the evidence of its place and name (Tier A). Any other
//!   file named like an uninstaller gets the same evidence at Tier B: listed, never preselected.
//! - **A directory** is Tier A only when it holds one of them (or is the directory the harvest read
//!   from the uninstaller's location). Whatever it holds that is neither one of them, nor named
//!   `unins…`, nor named by the installer's log, is unproven: the directory gets
//!   `UnmatchedChildren` and is not preselected.
//!
//! A root guessed from `DisplayIcon` is not searched: nothing ties a file named `uninstall.exe` there to
//! this app. Every candidate needs verify-gone (removing the uninstaller of an app that is still
//! installed would strand it), and one another app's records point at is blocked by the common blockers.
//!
//! MSI `*{ProductCode}*` caches and `InstallShield Installation Information\{ProductCode}` belong to the
//! MSI work of M1b.

use purge_guard::prefix;
use purge_model::{
    Action, Blocker, Candidate, Category, InnoRecordKind, Root, RootKind, RootSource, Target,
};
use purge_source::types::FileMeta;

use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};
use crate::fs_installdir::{emit, extension, is_plain_dir, join, list, measure, sized, stem};

/// The scanner's catalog id.
pub const ID: &str = "FS-UNINSTALLER";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[
    RootSpec::fs(r"%ProgramFiles%", None),
    RootSpec::fs(r"%ProgramData%", None),
    RootSpec::fs(r"%USERPROFILE%", None),
];

/// Names of a subdirectory of an InstallRoot that holds the uninstaller.
const UNINSTALLER_DIR_NAMES: &[&str] = &["uninstall", "uninst", "uninstaller"];

/// The FS-UNINSTALLER scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsUninstaller;

impl Scanner for FsUninstaller {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        let mut out = Vec::new();
        for root in &ctx.fp.roots {
            if !searched(root) {
                continue;
            }
            let Ok(meta) = ctx.fs.metadata(&root.path) else {
                continue;
            };
            if !is_plain_dir(&meta) {
                continue;
            }
            // The uninstaller's own directory inside an InstallRoot.
            if root.source == RootSource::UninstallerDir
                && prefix::parent(&root.path)
                    .is_some_and(|parent| ctx.inside_install_root(parent).is_some())
            {
                directory(ctx, &root.path, &meta, true, &mut out);
            }
            let Some(entries) = list(ctx, &root.path) else {
                continue;
            };
            for entry in &entries {
                let path = join(&root.path, &entry.name);
                if is_plain_dir(&entry.meta) {
                    let named = UNINSTALLER_DIR_NAMES
                        .iter()
                        .any(|n| entry.name.eq_ignore_ascii_case(n));
                    if named && root.kind == RootKind::InstallRoot {
                        let from_harvest = ctx.fp.roots.iter().any(|r| {
                            r.source == RootSource::UninstallerDir
                                && prefix::is_same(&r.path, &path)
                        });
                        directory(ctx, &path, &entry.meta, from_harvest, &mut out);
                    }
                } else if !entry.meta.is_dir()
                    && !entry.meta.is_reparse_point()
                    && let Some(what) = uninstaller_file(&entry.name)
                {
                    artifact(ctx, &path, &entry.meta, what, own(ctx, &path), &mut out);
                }
            }
        }
        out
    }
}

/// Whether the uninstaller is looked for directly in this root.
fn searched(root: &Root) -> bool {
    match root.kind {
        RootKind::InstallRoot => true,
        RootKind::InferredRoot => root.source == RootSource::UninstallerDir,
        RootKind::ReferencedDataDir => false,
    }
}

/// What kind of uninstaller file `name` is, if any.
///
/// - `unins` + three digits + `.exe`, `.dat` or `.msg`: an Inno Setup uninstaller, its log or its
///   messages;
/// - any other `.exe` whose name starts with `unins` (`uninstall.exe`, `Uninst.exe`, `uninstaller.exe`,
///   `Uninstall App.exe`).
fn uninstaller_file(name: &str) -> Option<&'static str> {
    let ext = extension(name)?.to_ascii_lowercase();
    let stem = stem(name).to_ascii_lowercase();
    let rest = stem.strip_prefix("unins")?;
    let inno = rest.len() == 3 && rest.bytes().all(|b| b.is_ascii_digit());
    match ext.as_str() {
        "exe" if inno => Some("Inno Setup uninstaller"),
        "dat" if inno => Some("Inno Setup uninstall log"),
        "msg" if inno => Some("Inno Setup uninstaller messages"),
        "exe" => Some("uninstaller"),
        _ => None,
    }
}

/// Whether `path` is one of the app's own uninstaller files.
fn own(ctx: &ScanCtx<'_>, path: &str) -> bool {
    ctx.fp
        .uninstallers
        .iter()
        .any(|file| prefix::is_same(file, path))
}

/// Offers an uninstaller directory. `from_harvest`: it is the directory the harvest read from the
/// uninstaller's own location.
fn directory(
    ctx: &ScanCtx<'_>,
    path: &str,
    meta: &FileMeta,
    from_harvest: bool,
    out: &mut Vec<Candidate>,
) {
    let holds_own = ctx
        .fp
        .uninstallers
        .iter()
        .any(|file| prefix::is_inside(file, path));
    let unproven = unproven_files(ctx, path);
    let Some(mut b) = builder(
        ctx,
        path,
        "uninstaller directory",
        from_harvest || holds_own,
    ) else {
        return;
    };
    match unproven {
        Some(0) => {}
        Some(n) => {
            b.blocker(Blocker::UnmatchedChildren { n });
        }
        // Not read to the end: nothing in it is shown to be the uninstaller's.
        None => {
            b.blocker(Blocker::UnmatchedChildren { n: 1 });
        }
    }
    sized(&mut b, &measure(ctx, path, meta));
    emit(out, b);
}

/// The number of files under `dir` that are not shown to belong to the uninstaller: not one of the
/// app's own uninstaller files, not named like an uninstaller file, and not named by a file record of
/// the installer's log. `None` when the directory could not be read to the end.
fn unproven_files(ctx: &ScanCtx<'_>, dir: &str) -> Option<u32> {
    let logged = |file: &str| {
        ctx.fp.inno.iter().any(|r| {
            r.kind == InnoRecordKind::DeleteFile
                && !r.existed_before
                && !r.shared
                && matches!(&r.target, Target::Path { path } if prefix::is_same(path, file))
        })
    };
    let mut count = 0u32;
    let mut visited = 0usize;
    let mut stack = vec![(dir.trim_end_matches(prefix::SEP).to_owned(), 0u32)];
    while let Some((dir, depth)) = stack.pop() {
        let entries = list(ctx, &dir)?;
        for entry in &entries {
            visited += 1;
            if visited > ctx.limits.max_walk_entries {
                return None;
            }
            let child = join(&dir, &entry.name);
            if is_plain_dir(&entry.meta) {
                if depth >= ctx.limits.max_depth {
                    return None;
                }
                stack.push((child, depth + 1));
            } else if entry.meta.is_dir() || entry.meta.is_reparse_point() {
                // A link: whatever is behind it is not the uninstaller's.
                count = count.saturating_add(1);
            } else if !own(ctx, &child) && !uninstaller_named(&entry.name) && !logged(&child) {
                count = count.saturating_add(1);
            }
        }
    }
    Some(count)
}

/// Whether a file in an uninstaller directory is named like a part of the uninstaller: `unins…` with
/// any extension (`uninstall.exe`, `uninstall.log`, `unins000.dat`).
fn uninstaller_named(name: &str) -> bool {
    name.get(..5)
        .is_some_and(|start| start.eq_ignore_ascii_case("unins"))
}

/// Offers one uninstaller file. `own`: it is one of the app's own uninstaller files.
fn artifact(
    ctx: &ScanCtx<'_>,
    path: &str,
    meta: &FileMeta,
    what: &str,
    own: bool,
    out: &mut Vec<Candidate>,
) {
    let Some(mut b) = builder(ctx, path, what, own) else {
        return;
    };
    sized(&mut b, &measure(ctx, path, meta));
    emit(out, b);
}

/// The candidate for an uninstaller file or directory with its evidence and common blockers. Unless
/// it is the app's `own`, place and name are Tier B: they are not the app's alone.
fn builder<'a>(
    ctx: &'a ScanCtx<'a>,
    path: &str,
    what: &str,
    own: bool,
) -> Option<crate::framework::CandidateBuilder<'a>> {
    let mut b = ctx.candidate(
        ID,
        Target::Path {
            path: path.to_owned(),
        },
        Action::Quarantine,
        Category::AppFiles,
    );
    // Under an InstallRoot the file is the app's by its place as well.
    b.inside_install_root();
    if !b.uninstaller_artifact(what) {
        return None;
    }
    if !own {
        b.cap_at_tier_b("not the app's own uninstaller");
    }
    b.require_verify_gone().common_blockers();
    Some(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninstaller_names() {
        assert_eq!(
            uninstaller_file("unins000.exe"),
            Some("Inno Setup uninstaller")
        );
        assert_eq!(
            uninstaller_file("UNINS001.DAT"),
            Some("Inno Setup uninstall log")
        );
        assert_eq!(
            uninstaller_file("unins000.msg"),
            Some("Inno Setup uninstaller messages")
        );
        assert_eq!(uninstaller_file("uninstall.exe"), Some("uninstaller"));
        assert_eq!(uninstaller_file("Uninst.exe"), Some("uninstaller"));
        assert_eq!(uninstaller_file("Uninstall App.exe"), Some("uninstaller"));
        for name in [
            "uninstall.dat",
            "uninstall.log",
            "unins0000.dat",
            "unins00.msg",
            "git.exe",
            "reinstall.exe",
            "unins000",
            "uninstall.exe.config",
        ] {
            assert_eq!(uninstaller_file(name), None, "{name}");
        }
    }
}
