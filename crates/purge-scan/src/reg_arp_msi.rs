//! Scanner REG-ARP-MSI (ENGINE_PLAN.md §5.6, §5.5): Windows Installer registration left for one of the
//! app's MSI products that Windows Installer no longer knows.
//!
//! # Which products
//!
//! Only the products of the fingerprint (`fp.msi`), each only when [`ScanCtx::product_gone`] says that
//! Windows Installer knows its ProductCode in no context (a source error, an empty answer or any known
//! context is "not gone": nothing is offered for that product). An entry whose recorded packed code is
//! not the packed form of its ProductCode is skipped, as the plan skips it when it opens the guard. The
//! packed codes are computed with `purge_index::ownership::pack_guid` from the fingerprint's codes,
//! never found by matching a product name in `InstallProperties` or anywhere else.
//!
//! # Targets
//!
//! Exactly the MSI shapes the guard's `reg.installer` rule lets through for a gone product (C-GUARD),
//! each only when it exists now, with `P` the packed ProductCode:
//!
//! - keys `...\Installer\UserData\<sid>\Products\<P>` for every `<sid>` under `UserData`;
//! - keys `HKLM\SOFTWARE\Classes\Installer\Products\<P>` and `...\Classes\Installer\Features\<P>`;
//! - for a per-user product, the key `HKU\<sid>\Software\Microsoft\Installer\Products\<P>` of its user;
//! - values named `<P>` under `...\Installer\UpgradeCodes\<U>` and
//!   `HKLM\SOFTWARE\Classes\Installer\UpgradeCodes\<U>`, `U` the packed UpgradeCode of the fingerprint
//!   (none recorded: no UpgradeCodes candidate);
//! - values named `<P>` under `...\UserData\<sid>\Components\<C>` for every component the ownership
//!   index lists `P` as a client of, under the product's own `<sid>` (`S-1-5-18` for a per-machine
//!   product, the user's for a per-user one). The index is read once per scan; nothing is opened here.
//!
//! The parent keys (`Products`, `UpgradeCodes\<U>`, `Components\<C>`) are never candidates: they hold
//! other products' entries. A component another product is also a client of loses only the app's value.
//! `HKU\<sid>\Software\Microsoft\Installer\Features\<P>` and the per-user `UpgradeCodes` are not offered:
//! the guard lets no such shape through. The cached `.msi` under `%SystemRoot%\Installer` is not offered
//! in M1b (a Windows-managed directory).
//!
//! # Evidence
//!
//! `InstallerManifest(Msi)` (`msi_registration`, Tier A in every scope): the target is Windows
//! Installer's record of the app's own product. `Category::Registration`, harm Low.
//!
//! # Reads
//!
//! One `subkeys()` of `UserData` per scan, then per product one `key_info()` per `UserData` SID, two
//! for the Classes keys, one for the user's key and one `value()` per UpgradeCodes key: at most 16 per
//! product code with up to ten SIDs under `UserData`. The sealing's content rule reads each value
//! candidate again, in `build` and in `run` (every scanner's value candidates pay that).
//!
//! A component value whose data is not a path of the app (a registry key path, a `C?\` shared-DLL
//! path, a file outside the roots) is held to Tier B by that content rule: offered, not preselected.

use purge_guard::prefix;
use purge_index::ownership::{MACHINE_SID, USERDATA, area, pack_guid};
use purge_model::{Action, Blocker, Candidate, Category, MsiContext, MsiFacts, Target};
use purge_source::types::KeyInfo;

use crate::framework::{AppIdentityView, CandidateBuilder, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "REG-ARP-MSI";

/// The machine's Windows Installer registration in the Classes.
const CLASSES_INSTALLER: &str = r"HKLM\SOFTWARE\Classes\Installer";

/// `...\Installer\UpgradeCodes`: one key per packed UpgradeCode, one value per packed ProductCode.
const UPGRADE_CODES: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes";

/// What the scanner reads.
const ROOTS: &[RootSpec] = &[
    RootSpec::reg(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData",
        Some(3),
    ),
    RootSpec::reg(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes",
        Some(1),
    ),
    RootSpec::reg(r"HKLM\SOFTWARE\Classes\Installer\Products", Some(0)),
    RootSpec::reg(r"HKLM\SOFTWARE\Classes\Installer\Features", Some(0)),
    RootSpec::reg(r"HKLM\SOFTWARE\Classes\Installer\UpgradeCodes", Some(1)),
    RootSpec::reg(r"HKU\*\SOFTWARE\Microsoft\Installer\Products", Some(0)),
];

/// The keys single values are offered from (entries of `purge_guard::containers::M1B_VALUE_CONTAINERS`,
/// spelled exactly as there).
const VALUE_CONTAINERS: &[&str] = &[
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\*",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Components\*",
    r"HKLM\SOFTWARE\Classes\Installer\UpgradeCodes\*",
];

/// The REG-ARP-MSI scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegArpMsi;

impl Scanner for RegArpMsi {
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
        let fp = ctx.fp;
        let mut out: Vec<Candidate> = Vec::new();
        // `UserData` is listed once, for the first product that is gone.
        let mut sids: Option<Vec<String>> = None;
        for msi in &fp.msi {
            let Some(packed) = pack_guid(msi.product_code.trim()) else {
                continue;
            };
            if !packed.eq_ignore_ascii_case(msi.packed_code.trim()) {
                continue;
            }
            if !ctx.product_gone(&msi.product_code) {
                continue;
            }
            let sids = sids.get_or_insert_with(|| userdata_sids(ctx));
            for candidate in product_candidates(ctx, msi, &packed, sids) {
                if !out
                    .iter()
                    .any(|c| ctx.same_target(&c.target, &candidate.target))
                {
                    out.push(candidate);
                }
            }
        }
        out
    }
}

/// The SIDs under `UserData`, as found; empty when the key is missing or cannot be listed (unknown is
/// never a candidate). A name that is not shaped like a SID is left out.
fn userdata_sids(ctx: &ScanCtx<'_>) -> Vec<String> {
    match ctx.reg.subkeys(USERDATA) {
        Ok(names) => names.into_iter().filter(|s| is_sid(s)).collect(),
        Err(_) => Vec::new(),
    }
}

/// `S-1-...` with digits, letters and dashes only: a SID as Windows Installer writes it.
fn is_sid(text: &str) -> bool {
    text.len() > 4
        && text[..4].eq_ignore_ascii_case("S-1-")
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// The `UserData` SID the product's component clients are registered under.
fn context_sid(msi: &MsiFacts) -> Option<&str> {
    match msi.context {
        MsiContext::Machine => Some(MACHINE_SID),
        MsiContext::UserManaged | MsiContext::UserUnmanaged => {
            msi.user_sid.as_deref().map(str::trim).filter(|s| is_sid(s))
        }
    }
}

/// Every candidate of one gone product.
fn product_candidates(
    ctx: &ScanCtx<'_>,
    msi: &MsiFacts,
    packed: &str,
    sids: &[String],
) -> Vec<Candidate> {
    let mut out = Vec::new();
    let code = msi.product_code.as_str();

    // Keys.
    let mut keys: Vec<(String, &'static str)> = sids
        .iter()
        .map(|sid| {
            (
                format!(r"{USERDATA}\{sid}\Products\{packed}"),
                "UserData\\Products",
            )
        })
        .collect();
    keys.push((
        format!(r"{CLASSES_INSTALLER}\Products\{packed}"),
        "Classes\\Products",
    ));
    keys.push((
        format!(r"{CLASSES_INSTALLER}\Features\{packed}"),
        "Classes\\Features",
    ));
    if msi.context != MsiContext::Machine
        && let Some(sid) = msi.user_sid.as_deref().map(str::trim).filter(|s| is_sid(s))
    {
        keys.push((
            format!(r"HKU\{sid}\Software\Microsoft\Installer\Products\{packed}"),
            "User\\Products",
        ));
    }
    for (key, store) in keys {
        // Absent, or unknown: no candidate.
        let Ok(info) = ctx.reg.key_info(&key) else {
            continue;
        };
        let mut b = ctx.candidate(
            ID,
            Target::RegKey { path: key.clone() },
            Action::DeleteKey,
            Category::Registration,
        );
        b = b.msi_registration(code, store);
        key_owner_blockers(ctx, &mut b, &key, &info);
        b.baseline_blocker()
            .existed_before_blocker()
            .other_app_blockers();
        out.push(b.build());
    }

    // UpgradeCodes values.
    if let Some(upgrade) = msi
        .upgrade_code
        .as_deref()
        .and_then(|u| pack_guid(u.trim()))
    {
        for (base, store) in [
            (UPGRADE_CODES, "UpgradeCodes"),
            (
                r"HKLM\SOFTWARE\Classes\Installer\UpgradeCodes",
                "Classes\\UpgradeCodes",
            ),
        ] {
            let key = format!(r"{base}\{upgrade}");
            if ctx.reg.value(&key, packed).is_err() {
                continue;
            }
            out.push(value_candidate(ctx, code, store, key, packed));
        }
    }

    // Component client values, from the ownership index. An incomplete component read lists some
    // components and not others: nothing is offered from it.
    let ix = &ctx.ext.ownership;
    if let Some(sid) = context_sid(msi)
        && ix.stats().complete(area::COMPONENTS)
        && sids.iter().any(|s| prefix::eq_ci(s, sid))
    {
        let mut seen: Vec<String> = Vec::new();
        for (component, _) in ix.components_of(packed) {
            let Some(packed_component) = pack_guid(component) else {
                continue;
            };
            if seen.contains(&packed_component) {
                continue;
            }
            let key = format!(r"{USERDATA}\{sid}\Components\{packed_component}");
            seen.push(packed_component);
            out.push(value_candidate(ctx, code, "Components", key, packed));
        }
    }
    out
}

/// The candidate for the value named `packed` of `key`.
fn value_candidate(
    ctx: &ScanCtx<'_>,
    code: &str,
    store: &'static str,
    key: String,
    packed: &str,
) -> Candidate {
    let mut b = ctx.candidate(
        ID,
        Target::RegValue {
            path: key,
            name: packed.to_owned(),
        },
        Action::DeleteValue,
        Category::Registration,
    );
    b = b.msi_registration(code, store);
    b.baseline_blocker()
        .existed_before_blocker()
        .other_app_blockers();
    b.build()
}

/// `TrustedInstallerOwned` and `RegLink` from the key's information as read for the existence check
/// (the rule of `CandidateBuilder::owner_blockers`, without opening the key a second time).
fn key_owner_blockers(ctx: &ScanCtx<'_>, b: &mut CandidateBuilder<'_>, key: &str, info: &KeyInfo) {
    let fp = ctx.fp;
    let ti = info.ti_owned == Some(true)
        || fp
            .subtrees
            .iter()
            .any(|s| s.ti_owned && ctx.same_key(&s.key, key))
        || fp
            .ext_journal
            .iter()
            .any(|e| e.ti_owned && ctx.same_key(&e.key, key));
    if ti {
        b.blocker(Blocker::TrustedInstallerOwned);
    }
    if info.is_link {
        b.blocker(Blocker::RegLink);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_are_well_formed_and_cover_the_containers() {
        assert!(ROOTS.iter().all(RootSpec::is_well_formed));
        for container in VALUE_CONTAINERS {
            assert!(
                purge_guard::containers::M1B_VALUE_CONTAINERS.contains(container),
                "{container}"
            );
            let folded = container.to_ascii_lowercase();
            assert!(
                ROOTS
                    .iter()
                    .any(|r| folded.starts_with(&format!("{}\\", r.pattern.to_ascii_lowercase()))),
                "{container}"
            );
        }
    }

    #[test]
    fn sid_shape() {
        assert!(is_sid("S-1-5-18"));
        assert!(is_sid("S-1-5-21-1-2-3-1001"));
        assert!(!is_sid("S-1-"));
        assert!(!is_sid("Components"));
        assert!(!is_sid(r"S-1-5\x"));
        assert!(!is_sid("S-1-5-18 "));
    }
}
