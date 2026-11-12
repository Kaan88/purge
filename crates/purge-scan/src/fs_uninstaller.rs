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
//! A root guessed from `DisplayIcon` is not searched: nothing ties a file named `uninstall.exe` there to
//! this app. Every candidate needs verify-gone (removing the uninstaller of an app that is still
//! installed would strand it), and one another app's records point at is blocked by the common blockers.
//!
//! MSI `*{ProductCode}*` caches and `InstallShield Installation Information\{ProductCode}` belong to the
//! MSI work of M1b.

use purge_guard::prefix;
use purge_model::{Action, Candidate, Category, Root, RootKind, RootSource, Target};
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
                artifact(ctx, &root.path, &meta, "uninstaller directory", &mut out);
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
                        artifact(ctx, &path, &entry.meta, "uninstaller directory", &mut out);
                    }
                } else if !entry.meta.is_dir()
                    && !entry.meta.is_reparse_point()
                    && let Some(what) = uninstaller_file(&entry.name)
                {
                    artifact(ctx, &path, &entry.meta, what, &mut out);
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

/// Offers one uninstaller file or directory.
fn artifact(ctx: &ScanCtx<'_>, path: &str, meta: &FileMeta, what: &str, out: &mut Vec<Candidate>) {
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
        return;
    }
    b.require_verify_gone().common_blockers();
    sized(&mut b, &measure(ctx, path, meta));
    emit(out, b);
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
