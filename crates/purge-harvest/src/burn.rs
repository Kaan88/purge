//! Harvest of WiX Burn bundle facts and dependency records (M1b, contract C-FP).
//!
//! A Burn bundle's ARP entry names the bundle; its MSI packages are separate products, linked to it only
//! through the dependency records Burn writes: `<Classes>\Installer\Dependencies\<P>\Dependents\<B>`,
//! where `P` is a package's provider key and `B` the bundle id (or the bundle's own provider key). The
//! ownership index reads those records once ([`OwnershipIndex::burn_dependents`]); this module reads
//! only the bundle's own Uninstall values and, per package, one value of its dependency key and one value
//! of its product registration.
//!
//! - `bundle_id`: the ARP key name.
//! - `provider_key`: the `BundleProviderKey` value.
//! - `cache_path`: the directory of `BundleCachePath`, only when it is a direct child of a Package Cache
//!   root (a hostile or broken value such as `C:\Windows\x.exe` gives none).
//! - `packages`: every provider key `P` whose dependents list the bundle id or the bundle's provider key.
//!   `product_code` is `P` when `P` is a GUID, else the default value of `P`'s dependency key when that
//!   is a GUID. `other_dependents` are `P`'s dependents other than this bundle. `cache_dir` is the
//!   product's `SourceList\LastUsedSource` directory when it is a direct child of a Package Cache root.
//!
//! A package is the app's ([`BurnHarvest::children`]) only when no other bundle or product depends on it
//! and Windows Installer lists its product as installed: the Python Launcher shared by two Pythons is
//! nobody's in particular.

use purge_guard::canon::{GuardEnv, canon_key};
use purge_guard::prefix;
use purge_index::ownership::{MACHINE_DEPENDENCIES, OwnershipIndex, pack_guid};
use purge_model::{BurnFacts, BurnPackage, InventoryEntry};
use purge_source::registry::RegistrySource;
use purge_win::env::EnvMap;

use crate::msi::braced_upper;
use crate::roots::{canon_file, clean_value, is_package_cache_entry, parent_dir};

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

/// The dependency roots a bundle's records can be in: the machine's, and the user's for a per-user entry.
fn dependency_roots(entry: &InventoryEntry, guard: &GuardEnv) -> Vec<String> {
    let mut roots = vec![MACHINE_DEPENDENCIES.to_owned()];
    if let Some(sid) = entry.hive_sid.as_deref() {
        let input = format!("HKU\\{sid}\\Software\\Classes\\Installer\\Dependencies");
        if let Ok(key) = canon_key(&input, None, guard, None) {
            roots.push(key.key_path());
        }
    }
    roots
}

/// The string data of one value, trimmed, when it is a non-empty string.
fn string_value(reg: &dyn RegistrySource, key: &str, name: &str) -> Option<String> {
    reg.value(key, name)
        .ok()
        .and_then(|d| d.string())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// The ProductCode a provider key stands for: the key name when it is a GUID, else its default value.
fn product_of_provider(
    reg: &dyn RegistrySource,
    roots: &[String],
    provider: &str,
) -> Option<String> {
    if let Some(code) = braced_upper(provider) {
        return Some(code);
    }
    roots
        .iter()
        .find_map(|root| string_value(reg, &format!("{root}\\{provider}"), ""))
        .and_then(|value| braced_upper(&value))
}

/// The Package Cache directory Windows Installer last installed the product from
/// (`SourceList\LastUsedSource`, `n;<index>;<path>`), when it is a direct child of a Package Cache root.
fn product_cache_dir(
    reg: &dyn RegistrySource,
    product_code: &str,
    entry: &InventoryEntry,
    guard: &GuardEnv,
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
    is_package_cache_entry(&dir, guard).then_some(dir)
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
    let cache_path = string_value(reg, &entry.key_path, "BundleCachePath").and_then(|raw| {
        let dir = clean_value(&raw, env)
            .and_then(|file| canon_file(&file, guard))
            .as_deref()
            .and_then(parent_dir);
        match dir {
            Some(dir) if is_package_cache_entry(&dir, guard) => Some(dir),
            _ => {
                warnings.push(format!(
                    "burn: BundleCachePath {raw:?} is not in a direct child of a Package Cache root; \
                     the bundle has no cache folder"
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

    let mut providers: Vec<String> = Vec::new();
    for dependent in std::iter::once(bundle_id.as_str()).chain(provider_key.as_deref()) {
        if dependent.is_empty() {
            continue;
        }
        for provider in ix.burn_providers_of(dependent) {
            if !is_self(provider) && !providers.iter().any(|p| prefix::eq_ci(p, provider)) {
                providers.push(provider.to_owned());
            }
        }
    }
    providers.sort_by_key(|p| prefix::fold(p));

    let roots = dependency_roots(entry, guard);
    let mut packages = Vec::new();
    let mut children = Vec::new();
    for provider in providers {
        let product_code = product_of_provider(reg, &roots, &provider);
        let mut other_dependents: Vec<String> = ix
            .burn_dependents(&provider)
            .iter()
            .filter(|d| !is_self(d))
            .cloned()
            .collect();
        other_dependents.sort_by_key(|d| prefix::fold(d));
        let cache_dir = product_code
            .as_deref()
            .and_then(|code| product_cache_dir(reg, code, entry, guard));
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
