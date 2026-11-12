//! CLS-TOASTS (ENGINE_PLAN.md §5.6): `ApplicationAssociationToasts` values `<ProgID>_<.ext>`.
//!
//! Windows remembers in this key that it already asked "how do you want to open this file?" for a
//! (ProgID, extension) pair. The scanner reads the key of the interactive user (`Fingerprint::user_sid`)
//! and of the machine, splits every value name at its last `_.` into ProgID and extension, and offers
//! the value when the ProgID is, exactly, one of P. A value of any other ProgID is not looked at twice.
//!
//! Evidence, Value scope: `ChainedRef` to the owned ProgID, and `InPreUninstallRefSnapshot` from the
//! reference snapshot or, for the user's key, from the extension journal when it lists the value name
//! (`ExtJournalEntry::toast_values`). The key itself is a value container and is never offered.
//!
//! Every candidate carries `group = "File associations"` in its evidence details (see
//! `cls_assoc::handler`).

use purge_guard::prefix;
use purge_model::{Candidate, Facts};

use crate::cls_assoc::handler;
use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "CLS-TOASTS";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[RootSpec::reg(
    r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts",
    Some(0),
)];

/// The keys the scanner reads single values from (entries of
/// `purge_guard::containers::VALUE_CONTAINERS`).
const VALUE_CONTAINERS: &[&str] =
    &[r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts"];

/// The key below a user hive.
const USER_TOASTS: &str = r"Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts";

/// The machine's key.
const MACHINE_TOASTS: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts";

/// The CLS-TOASTS scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClsToasts;

impl Scanner for ClsToasts {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn value_containers(&self) -> &[&'static str] {
        VALUE_CONTAINERS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        let mut out = Vec::new();
        let sid = ctx.fp.user_sid.trim();
        let user_key = (!sid.is_empty()).then(|| format!(r"HKU\{sid}\{USER_TOASTS}"));
        let keys = user_key
            .iter()
            .map(|key| (key.as_str(), true))
            .chain([(MACHINE_TOASTS, false)]);
        for (key, is_user) in keys {
            let Ok(values) = ctx.reg.values(key) else {
                continue;
            };
            for value in &values {
                let Some((name, ext)) = split_toast_name(&value.name) else {
                    continue;
                };
                let Some(progid) = handler::progid_in_p(ctx, name) else {
                    continue;
                };
                let listed = is_user
                    && ctx.fp.ext_journal.iter().any(|entry| {
                        entry
                            .toast_values
                            .iter()
                            .any(|toast| prefix::eq_ci(toast, &value.name))
                    });
                let facts = Facts::new().with("ext", ext);
                out.extend(handler::progid_value(
                    ctx,
                    ID,
                    key,
                    &value.name,
                    progid,
                    listed,
                    &facts,
                ));
            }
        }
        out
    }
}

/// Splits a toast value name `<ProgID>_<.ext>` at its last `_.`; `None` when it has no such shape.
/// ProgIDs may contain `_`, extensions never do after their dot.
pub fn split_toast_name(name: &str) -> Option<(&str, &str)> {
    let at = name.rfind("_.")?;
    let (progid, ext) = (&name[..at], &name[at + 1..]);
    (!progid.is_empty() && ext.len() > 1).then_some((progid, ext))
}
