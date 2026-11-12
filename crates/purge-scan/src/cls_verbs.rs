//! CLS-VERBS (ENGINE_PLAN.md §5.6): shell verbs under `*`, `AllFilesystemObjects`, `Folder`, `Directory`,
//! `Directory\Background`, `Drive`, `DesktopBackground` and `LibraryFolder\Background`.
//!
//! # What is looked at
//!
//! `<Classes root>\<object>\shell\<verb>` in the physical hives (`HKLM\SOFTWARE\Classes`,
//! `HKU\<SID>_Classes`), for the eight shell objects above.
//!
//! # What is offered
//!
//! - **The verb key** (`DeleteKey`) when a `command` below it launches a file of the app (its program is
//!   in the exe set or under an InstallRoot, present or dangling), or when the exact key is an Inno
//!   key-create record, a proven owned skeleton or carries a harvested token in its name; never when a
//!   `command` below it launches something else. The launch is recorded as a Tier A `ChainedRef` to the
//!   launched file. As for every key of this package, a baseline for exactly this Windows must be loaded
//!   and must not have the key.
//! - **Values only** otherwise: the values of the verb that point into the app (see
//!   [`classes::value_candidates`](crate::cls_progid::classes)).
//! - **The parent `shell` key** only through `ProvenOwnedSkeleton` (Git leaves
//!   `LibraryFolder\background\shell` behind, empty). The shell objects themselves and a `shell` key that
//!   is not proven are never offered: they are structural (§5.10).
//!
//! Context-menu handlers (`shellex`) belong to the COM scanners of M1b.

use purge_model::{Candidate, Category, Tier};

use crate::cls_progid::classes::{self, KeyScan};
use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "CLS-VERBS";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[
    RootSpec::reg(r"*\SOFTWARE\Classes\[*]\shell", None),
    RootSpec::reg(r"*\SOFTWARE\Classes\AllFilesystemObjects\shell", None),
    RootSpec::reg(r"*\SOFTWARE\Classes\Folder\shell", None),
    RootSpec::reg(r"*\SOFTWARE\Classes\Directory\shell", None),
    RootSpec::reg(r"*\SOFTWARE\Classes\Directory\Background\shell", None),
    RootSpec::reg(r"*\SOFTWARE\Classes\Drive\shell", None),
    RootSpec::reg(r"*\SOFTWARE\Classes\DesktopBackground\shell", None),
    RootSpec::reg(r"*\SOFTWARE\Classes\LibraryFolder\Background\shell", None),
];

/// The shell objects whose verbs are scanned, as paths below a Classes root (without the `shell` key).
const OBJECTS: &[&[&str]] = &[
    &["*"],
    &["AllFilesystemObjects"],
    &["Folder"],
    &["Directory"],
    &["Directory", "Background"],
    &["Drive"],
    &["DesktopBackground"],
    &["LibraryFolder", "Background"],
];

/// The CLS-VERBS scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClsVerbs;

impl Scanner for ClsVerbs {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, app: &AppIdentityView) -> Vec<Candidate> {
        let mut out = Vec::new();
        for root in classes::classes_roots(ctx) {
            for object in OBJECTS {
                let Some(shell) = root
                    .child(object[0])
                    .and_then(|key| classes::existing_path(ctx, &key, &object[1..]))
                    .and_then(|key| classes::existing_child(ctx, &key, "shell"))
                else {
                    continue;
                };
                scan_shell(ctx, app, &shell, &mut out);
            }
        }
        out
    }
}

/// The verbs of one `shell` key, then the key itself as a possible skeleton.
fn scan_shell(ctx: &ScanCtx<'_>, app: &AppIdentityView, shell: &str, out: &mut Vec<Candidate>) {
    let Ok(verbs) = ctx.reg.subkeys(shell) else {
        return;
    };
    // A `shell` key with more verbs than any real one is not walked.
    if verbs.len() <= ctx.limits.max_key_children {
        for verb in verbs {
            let Some(scan) = KeyScan::read(ctx, app, &format!("{shell}\\{verb}")) else {
                continue;
            };
            let offer = if scan.foreign_command() {
                None
            } else {
                let chain = scan.launch().map(|path| (Tier::A, path));
                classes::key_candidate(ctx, ID, &scan, Category::ShellCom, chain)
            };
            match offer {
                Some(builder) => out.push(builder.build()),
                None => out.extend(classes::value_candidates(
                    ctx,
                    ID,
                    &scan,
                    Category::ShellCom,
                )),
            }
        }
    }
    out.extend(classes::skeleton_candidate(
        ctx,
        ID,
        shell,
        Category::ShellCom,
    ));
}
