//! CLS-AUMID (ENGINE_PLAN.md §5.6): `Classes\AppUserModelId\<AUMID>` keys.
//!
//! # What is looked at
//!
//! `<Classes root>\AppUserModelId\<AUMID>` in the physical hives (`HKLM\SOFTWARE\Classes`,
//! `HKU\<SID>_Classes`), for the AUMIDs of the fingerprint's anchor set only (Firefox:
//! `FirefoxToast-<hash>`). The `AppUserModelId` container is never offered.
//!
//! # What is offered
//!
//! - **The AUMID key** (`DeleteKey`), given a baseline for exactly this Windows that does not have it.
//!   Evidence, as far as each holds for this exact key: an Inno key-create record, `ProvenOwnedSkeleton`,
//!   a harvested token in the key's name, and a `ChainedRef`: Tier A to the path when a value of the key
//!   (`IconUri`, `IconPath`…) points into an InstallRoot or at a file of the exe set, otherwise Tier B to
//!   the AUMID itself (in the anchor set on the harvest's word alone).
//! - **Values only** otherwise: the values of the key that point into the app.
//!
//! # Blockers
//!
//! The common ones, and `ReferencedByOtherApp` when another app has the same AUMID among its anchors.

use purge_guard::prefix;
use purge_model::{AnchorKind, Candidate, Category, Tier};

use crate::cls_progid::classes::{self, KeyScan};
use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "CLS-AUMID";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[RootSpec::reg(r"*\SOFTWARE\Classes\AppUserModelId", None)];

/// The container of the per-AUMID keys.
const CONTAINER: &str = "AppUserModelId";

/// The CLS-AUMID scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClsAumid;

impl Scanner for ClsAumid {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, app: &AppIdentityView) -> Vec<Candidate> {
        let aumids = &ctx.fp.anchors.aumids;
        let mut out: Vec<Candidate> = Vec::new();
        if aumids.is_empty() {
            return out;
        }
        for root in classes::classes_roots(ctx) {
            let Some(container) = root.child(CONTAINER) else {
                continue;
            };
            for (i, aumid) in aumids.iter().enumerate() {
                // An AUMID is one key name; anything else is not looked up, and neither is a repeat.
                let repeated = aumids[..i].iter().any(|a| prefix::eq_ci(a, aumid));
                if aumid.is_empty() || aumid.contains(prefix::SEP) || repeated {
                    continue;
                }
                let Some(scan) = classes::existing_child(ctx, &container, aumid)
                    .and_then(|key| KeyScan::read(ctx, app, &key))
                else {
                    continue;
                };
                let chain = match scan.app_ref() {
                    Some(path) => (Tier::A, path),
                    None => (Tier::B, aumid.as_str()),
                };
                match classes::key_candidate(ctx, ID, &scan, Category::Registration, Some(chain)) {
                    Some(mut builder) => {
                        if let Some(blocker) =
                            ctx.other_apps.anchor_blocker(AnchorKind::Aumid, aumid)
                        {
                            builder.blocker(blocker);
                        }
                        out.push(builder.build());
                    }
                    None => out.extend(classes::value_candidates(
                        ctx,
                        ID,
                        &scan,
                        Category::Registration,
                    )),
                }
            }
        }
        out
    }
}
