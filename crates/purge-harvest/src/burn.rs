//! Harvest of WiX Burn bundle facts and dependency records (M1b, contract C-FP).
//!
//! A Burn bundle's ARP entry names the bundle; its MSI packages are separate products, linked to it only
//! through the dependency records Burn writes: `<Classes>\Installer\Dependencies\<P>\Dependents\<B>`,
//! where `P` is a package's provider key and `B` the bundle id (or the bundle's own provider key). The
//! ownership index reads those records once ([`OwnershipIndex::burn_providers_in`],
//! [`OwnershipIndex::burn_dependents`]); this module reads only the bundle's own Uninstall values and,
//! per package, one value of its dependency key and one value of its product registration.
//!
//! - `bundle_id`: the ARP key name.
//! - `provider_key`: the `BundleProviderKey` value.
//! - `cache_path`: the directory of `BundleCachePath`, only when it is the bundle's own folder of the
//!   entry's Package Cache: a direct child named exactly the bundle id, of `%ProgramData%\Package Cache`
//!   for a machine entry, of that user's `%LOCALAPPDATA%\Package Cache` for a per-user entry (R2a S7; a
//!   hostile or broken value such as `C:\Windows\x.exe`, or another bundle's folder, gives none).
//! - `packages`: every provider key `P` whose dependents list the bundle id or the bundle's provider key,
//!   in the records the entry's own writer could have made (R2a S6): a machine bundle sees the machine's
//!   records (`HKLM\SOFTWARE\Classes\Installer\Dependencies`) only, a per-user bundle the machine's and
//!   its own user's. A record from the user's hive never ties a product installed for the machine to the
//!   bundle; such a package is left out with a warning. `product_code` is `P` when `P` is a GUID, else
//!   the default value of `P`'s dependency key, read in the hive the record came from, when that is a
//!   GUID. `other_dependents` are `P`'s dependents other than this bundle, merged over every hive (more
//!   only ever keeps more). `cache_dir` is the product's `SourceList\LastUsedSource` directory when it is
//!   a direct child of the entry's Package Cache named by the ProductCode, alone or followed by
//!   `v<version>` (Burn's folder for an MSI package).
//!
//! A package is the app's ([`BurnHarvest::children`]) only when no other bundle or product depends on it
//! and Windows Installer lists its product as installed: the Python Launcher shared by two Pythons is
//! nobody's in particular.

use purge_guard::canon::{GuardEnv, canon_key};
use purge_guard::prefix;
use purge_index::ownership::{MACHINE_DEPENDENCIES, OwnershipIndex, pack_guid};
use purge_model::{BurnFacts, BurnPackage, InventoryEntry, MsiContext};
use purge_source::registry::RegistrySource;
use purge_win::env::EnvMap;

use crate::msi::braced_upper;
use crate::roots::{canon_file, clean_value, parent_dir};

/// What the harvest read about a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnHarvest {
    /// The facts for the fingerprint.
    pub facts: BurnFacts,
    /// Packed product codes of the packages that are the app's: no other dependent, product installed.
    pub children: Vec<String>,
    /// Lines for the fingerprint's warnings.
    pub warnings: Vec<String>,
}

/// The dependency root of one hive: the machine's (`None`), or the user's Classes for `Some(sid)`.
fn dependency_root(sid: Option<&str>, guard: &GuardEnv) -> Option<String> {
    match sid {
        None => Some(MACHINE_DEPENDENCIES.to_owned()),
        Some(sid) => {
            let input = format!("HKU\\{sid}\\Software\\Classes\\Installer\\Dependencies");
            canon_key(&input, None, guard, None)
                .ok()
                .map(|k| k.key_path())
        }
    }
}

/// The Package Cache of the entry's writer, canonical: `%ProgramData%\Package Cache` for a machine
/// entry, the `%LOCALAPPDATA%\Package Cache` of the entry's own user for a per-user entry. `None` when
/// that folder is not known.
fn entry_cache_root(entry: &InventoryEntry, guard: &GuardEnv) -> Option<String> {
    let base = match entry.hive_sid.as_deref() {
        None => guard.program_data.as_str(),
        Some(sid) => guard
            .profiles
            .iter()
            .find(|p| p.sid.eq_ignore_ascii_case(sid.trim()))?
            .local_appdata
            .as_str(),
    };
    if base.trim().is_empty() {
        return None;
    }
    canon_file(
        &format!("{}\\Package Cache", base.trim_end_matches('\\')),
        guard,
    )
}

/// Whether `dir` (canonical) is a direct child of `root` whose name `leaf_ok` accepts.
fn cache_child(dir: &str, root: Option<&str>, leaf_ok: impl Fn(&str) -> bool) -> bool {
    let (Some(root), Some(parent), Some(leaf)) = (root, prefix::parent(dir), prefix::leaf(dir))
    else {
        return false;
    };
    prefix::is_same(root, parent) && leaf_ok(leaf)
}

/// Whether a Package Cache folder name is Burn's folder for the MSI package `product_code` (`{GUID}`):
/// the code itself, or the code followed by `v<version>`.
fn is_package_folder(leaf: &str, product_code: &str) -> bool {
    let code = product_code.trim();
    if code.is_empty() {
        return false;
    }
    let (Some(head), Some(rest)) = (leaf.get(..code.len()), leaf.get(code.len()..)) else {
        return false;
    };
    head.eq_ignore_ascii_case(code) && (rest.is_empty() || rest.starts_with(['v', 'V']))
}

/// The string data of one value, trimmed, when it is a non-empty string.
fn string_value(reg: &dyn RegistrySource, key: &str, name: &str) -> Option<String> {
    reg.value(key, name)
        .ok()
        .and_then(|d| d.string())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// The ProductCode a provider key stands for: the key name when it is a GUID, else its default value
/// in `root` (the dependency root of the hive its record was read from).
fn product_of_provider(
    reg: &dyn RegistrySource,
    root: Option<&str>,
    provider: &str,
) -> Option<String> {
    if let Some(code) = braced_upper(provider) {
        return Some(code);
    }
    root.and_then(|root| string_value(reg, &format!("{root}\\{provider}"), ""))
        .and_then(|value| braced_upper(&value))
}

/// The Package Cache directory Windows Installer last installed the product from
/// (`SourceList\LastUsedSource`, `n;<index>;<path>`), when it is Burn's folder for the product in the
/// entry's own Package Cache (`cache_root`).
fn product_cache_dir(
    reg: &dyn RegistrySource,
    product_code: &str,
    entry: &InventoryEntry,
    guard: &GuardEnv,
    cache_root: Option<&str>,
) -> Option<String> {
    let packed = pack_guid(product_code)?;
    let key = match entry.hive_sid.as_deref() {
        None => format!(r"HKLM\SOFTWARE\Classes\Installer\Products\{packed}\SourceList"),
        Some(sid) => {
            format!(r"HKU\{sid}\Software\Microsoft\Installer\Products\{packed}\SourceList")
        }
    };
    let raw = string_value(reg, &key, "LastUsedSource")?;
    let mut parts = raw.splitn(3, ';');
    let (kind, _, path) = (parts.next()?, parts.next()?, parts.next()?);
    if !kind.eq_ignore_ascii_case("n") {
        return None;
    }
    let dir = canon_file(path.trim().trim_end_matches('\\'), guard)?;
    cache_child(&dir, cache_root, |leaf| {
        is_package_folder(leaf, product_code)
    })
    .then_some(dir)
}

/// Harvests the bundle of `entry`. See the module documentation.
pub fn harvest(
    reg: &dyn RegistrySource,
    entry: &InventoryEntry,
    ix: &OwnershipIndex,
    env: &EnvMap,
    guard: &GuardEnv,
) -> BurnHarvest {
    let mut warnings = Vec::new();
    let bundle_id = prefix::leaf(&entry.key_path).unwrap_or("").to_owned();
    let provider_key = string_value(reg, &entry.key_path, "BundleProviderKey");
    let user_sid = entry.hive_sid.as_deref();
    let cache_root = entry_cache_root(entry, guard);
    let cache_path = string_value(reg, &entry.key_path, "BundleCachePath").and_then(|raw| {
        let dir = clean_value(&raw, env)
            .and_then(|file| canon_file(&file, guard))
            .as_deref()
            .and_then(parent_dir);
        let own = |leaf: &str| !bundle_id.is_empty() && prefix::eq_ci(leaf, &bundle_id);
        match dir {
            Some(dir) if cache_child(&dir, cache_root.as_deref(), own) => Some(dir),
            _ => {
                warnings.push(format!(
                    "burn: BundleCachePath {raw:?} is not in the bundle's own folder of its Package \
                     Cache; the bundle has no cache folder"
                ));
                None
            }
        }
    });
    let is_self = |name: &str| {
        prefix::eq_ci(name, &bundle_id)
            || provider_key
                .as_deref()
                .is_some_and(|pk| prefix::eq_ci(name, pk))
    };

    // (provider, listed in the machine's records), from the records the entry's writer could make.
    let mut providers: Vec<(String, bool)> = Vec::new();
    for dependent in std::iter::once(bundle_id.as_str()).chain(provider_key.as_deref()) {
        if dependent.is_empty() {
            continue;
        }
        for found in ix.burn_providers_in(dependent, user_sid) {
            if is_self(found.provider) {
                continue;
            }
            match providers
                .iter_mut()
                .find(|(p, _)| prefix::eq_ci(p, found.provider))
            {
                Some((_, machine)) => *machine |= found.machine,
                None => providers.push((found.provider.to_owned(), found.machine)),
            }
        }
    }
    providers.sort_by_key(|(p, _)| prefix::fold(p));

    let mut packages = Vec::new();
    let mut children = Vec::new();
    for (provider, machine_record) in providers {
        let hive = if machine_record { None } else { user_sid };
        let root = dependency_root(hive, guard);
        let product_code = product_of_provider(reg, root.as_deref(), &provider);
        // A user's own record cannot tie a product installed for the machine, or for another user, to
        // the bundle.
        let foreign_product = product_code
            .as_deref()
            .and_then(pack_guid)
            .and_then(|packed| ix.installed(&packed))
            .is_some_and(|p| {
                p.context == MsiContext::Machine
                    || p.user_sid.as_deref().is_some_and(|sid| {
                        user_sid.is_none_or(|own| !sid.eq_ignore_ascii_case(own.trim()))
                    })
            });
        if !machine_record && foreign_product {
            warnings.push(format!(
                "burn: the package {provider} is named only in the user's own dependency records, \
                 but its product is installed for the machine or another user; it is not the \
                 bundle's"
            ));
            continue;
        }
        let mut other_dependents: Vec<String> = ix
            .burn_dependents(&provider)
            .iter()
            .filter(|d| !is_self(d))
            .cloned()
            .collect();
        other_dependents.sort_by_key(|d| prefix::fold(d));
        let cache_dir = product_code
            .as_deref()
            .and_then(|code| product_cache_dir(reg, code, entry, guard, cache_root.as_deref()));
        if let Some(code) = &product_code {
            let packed = pack_guid(code).unwrap_or_default();
            if !other_dependents.is_empty() {
                warnings.push(format!(
                    "burn: the package {provider} ({code}) has other dependents ({}); it is not the \
                     app's",
                    other_dependents.join(", ")
                ));
            } else if ix.installed(&packed).is_none() {
                warnings.push(format!(
                    "burn: the package {provider} ({code}) is not an installed product; it is not \
                     harvested"
                ));
            } else if !children.contains(&packed) {
                children.push(packed);
            }
        }
        packages.push(BurnPackage {
            provider_key: provider,
            product_code,
            cache_dir,
            other_dependents,
        });
    }

    let mut dependents_at_harvest: Vec<String> = provider_key
        .as_deref()
        .map(|pk| ix.burn_dependents(pk))
        .unwrap_or_default()
        .iter()
        .filter(|d| !is_self(d))
        .cloned()
        .collect();
    dependents_at_harvest.sort_by_key(|d| prefix::fold(d));

    BurnHarvest {
        facts: BurnFacts {
            bundle_id,
            provider_key,
            cache_path,
            packages,
            dependents_at_harvest,
        },
        children,
        warnings,
    }
}
