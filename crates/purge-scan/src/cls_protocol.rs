//! CLS-PROTOCOL (ENGINE_PLAN.md §5.6): `Classes\<scheme>` keys with a `URL Protocol` value.
//!
//! # What is looked at
//!
//! Every direct subkey of a physical Classes root (`HKLM\SOFTWARE\Classes`, `HKU\<SID>_Classes`) that
//! holds a `URL Protocol` value and is neither an extension nor one of Windows' containers. VS Code's
//! per-user install leaves `HKU\<SID>_Classes\vscode` this way.
//!
//! # What is offered
//!
//! - **The scheme key** (`DeleteKey`) when a `shell\<verb>\command` below it launches a file of the app
//!   (its program is in the exe set or under an InstallRoot, present or dangling) and none launches
//!   something else. The launch is recorded as a Tier A `ChainedRef` to the launched file, next to an
//!   Inno key-create record and harvested tokens in the key's name where they hold. A baseline for
//!   exactly this Windows must be loaded and must not have the key, so a scheme Windows ships (`mailto`,
//!   `http`) that the app took over is never offered as a key.
//! - **Values only** otherwise: the values below the scheme that point into the app.
//!
//! A scheme with no value pointing into the app is not the app's and yields nothing.
//!
//! # Blockers
//!
//! The common ones, and `ReferencedByOtherApp` when another app has the scheme among its ProgID anchors.

use purge_model::{AnchorKind, Candidate, Category, Tier};

use crate::cls_progid::classes::{self, KeyScan};
use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "CLS-PROTOCOL";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[RootSpec::reg(r"*\SOFTWARE\Classes", None)];

/// The value that marks a Classes key as a URL scheme.
const URL_PROTOCOL: &str = "URL Protocol";

/// The CLS-PROTOCOL scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClsProtocol;

impl Scanner for ClsProtocol {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, app: &AppIdentityView) -> Vec<Candidate> {
        let mut out = Vec::new();
        for root in classes::classes_roots(ctx) {
            for scheme in root.names().filter(|name| !classes::is_reserved(name)) {
                let key = root.key_of(scheme);
                if ctx.reg.value(&key, URL_PROTOCOL).is_err() {
                    continue;
                }
                let Some(scan) = KeyScan::read(ctx, app, &key) else {
                    continue;
                };
                if scan.app_ref().is_none() {
                    continue;
                }
                let offer = match scan.launch() {
                    Some(path) if !scan.foreign_command() => classes::key_candidate(
                        ctx,
                        ID,
                        &scan,
                        Category::Association,
                        Some((Tier::A, path)),
                    ),
                    _ => None,
                };
                match offer {
                    Some(mut builder) => {
                        if let Some(blocker) =
                            ctx.other_apps.anchor_blocker(AnchorKind::ProgId, scheme)
                        {
                            builder.blocker(blocker);
                        }
                        out.push(builder.build());
                    }
                    None => out.extend(classes::value_candidates(
                        ctx,
                        ID,
                        &scan,
                        Category::Association,
                    )),
                }
            }
        }
        out
    }
}
