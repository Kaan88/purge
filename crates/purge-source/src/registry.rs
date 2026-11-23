//! The [`RegistrySource`] trait: read-only access to the registry for every scanner (ENGINE_PLAN.md §3.2,
//! §5.6 "scanners read only via purge-source").
//!
//! Key paths are the canonical strings `purge-guard` canonicalisation produces:
//! `HKLM\SOFTWARE\…`, `HKLM\SYSTEM\ControlSet00N\…`, `HKU\<SID>\…`, `HKU\<SID>_Classes\…`. The registry view
//! is explicit in the path: the 32-bit view is addressed through its `WOW6432Node` segment, everything else
//! is the 64-bit view. Lookups are case-insensitive. Registry links are reported by
//! [`KeyInfo::is_link`] and never followed.

use crate::types::{ExistsState, KeyInfo, RegData, RegValue, SourceError, SourceResult};
/// Read-only registry access. Object safe; implementations are shared across scanner threads.
pub trait RegistrySource: Send + Sync {
    /// Metadata of a key. [`SourceError::NotFound`] when the key does not exist.
    fn key_info(&self, key: &str) -> SourceResult<KeyInfo>;

    /// Names of the direct subkeys of a key, in a stable order. A link key's own subkeys only (the link is
    /// not followed).
    fn subkeys(&self, key: &str) -> SourceResult<Vec<String>>;

    /// Every value of a key, in a stable order.
    fn values(&self, key: &str) -> SourceResult<Vec<RegValue>>;

    /// One value by name (`""` is the default value). [`SourceError::NotFound`] when the key or the value
    /// does not exist.
    fn value(&self, key: &str, name: &str) -> SourceResult<RegData>;

    /// The SIDs of the user hives loaded under `HKU`, without `.DEFAULT` and without the `_Classes` hives.
    /// Includes the service SIDs (`S-1-5-18/19/20`) when loaded.
    fn loaded_user_sids(&self) -> SourceResult<Vec<String>>;

    /// `N` of the `ControlSet00N` that `CurrentControlSet` points to (`HKLM\SYSTEM\Select\Current`).
    fn current_control_set(&self) -> SourceResult<u32>;

    /// Tri-state existence of a key: `Present`, `Absent` on [`SourceError::NotFound`], `Unknown` on any
    /// other error.
    fn key_exists(&self, key: &str) -> ExistsState {
        match self.key_info(key) {
            Ok(_) => ExistsState::Present,
            Err(SourceError::NotFound) => ExistsState::Absent,
            Err(_) => ExistsState::Unknown,
        }
    }

    /// A [`KeyWalker`] over this source, for one walk on one thread. The default reads through
    /// [`RegistrySource::key_info`], [`RegistrySource::values`] and [`RegistrySource::subkeys`];
    /// a source may answer with one that reads the same thing more cheaply.
    fn walker(&self) -> Box<dyn KeyWalker + '_> {
        Box::new(PlainWalker {
            source: self,
            key: String::new(),
        })
    }
}

/// Reads key after key of a registry walk: [`KeyWalker::enter`] a key, then read its values and subkey
/// names. Gives exactly what [`RegistrySource::key_info`], [`RegistrySource::values`] and
/// [`RegistrySource::subkeys`] give for the key, except that [`KeyInfo::ti_owned`] may be left `None`
/// (a walk does not ask for it).
///
/// A walker may keep the keys above the last one it entered open and open the next key below them,
/// instead of opening every key from its hive root; a source makes sure that this reads the same
/// keys as a fresh open, with the same refusal of a path through a link, for any key a caller enters
/// next, listed before or not (see `live::LiveRegistry`). It lives for one walk on one thread and is
/// dropped with it.
pub trait KeyWalker {
    /// Opens `key` and reads its metadata, as [`RegistrySource::key_info`].
    fn enter(&mut self, key: &str) -> SourceResult<KeyInfo>;

    /// The values of the key last entered, as [`RegistrySource::values`]. A walker may have read
    /// them already when the key was entered and return those: the values are then the key's values
    /// at [`KeyWalker::enter`], not at this call, and a failure of that read is reported here. A
    /// caller that needs the values as they are now enters the key again.
    fn values(&mut self) -> SourceResult<Vec<RegValue>>;

    /// The subkey names of the key last entered, as [`RegistrySource::subkeys`].
    fn subkeys(&mut self) -> SourceResult<Vec<String>>;
}

/// The default [`KeyWalker`]: every call goes to the source by path.
struct PlainWalker<'a, R: RegistrySource + ?Sized> {
    source: &'a R,
    key: String,
}

impl<R: RegistrySource + ?Sized> KeyWalker for PlainWalker<'_, R> {
    fn enter(&mut self, key: &str) -> SourceResult<KeyInfo> {
        key.clone_into(&mut self.key);
        self.source.key_info(key)
    }

    fn values(&mut self) -> SourceResult<Vec<RegValue>> {
        self.source.values(&self.key)
    }

    fn subkeys(&mut self) -> SourceResult<Vec<String>> {
        self.source.subkeys(&self.key)
    }
}

/// Splits a canonical key path into its segments, dropping empty ones (doubled or trailing separators).
pub(crate) fn split_key(path: &str) -> Vec<&str> {
    path.split('\\').filter(|s| !s.is_empty()).collect()
}

/// The `ControlSet00N` segment name for `n`.
pub(crate) fn control_set_name(n: u32) -> String {
    format!("ControlSet{n:03}")
}

/// Rewrites a `HKLM\SYSTEM\CurrentControlSet` prefix in split segments to `ControlSet00N`.
pub(crate) fn map_current_control_set(segs: &mut [String], n: u32) {
    if segs.len() >= 3
        && segs[0].eq_ignore_ascii_case("HKLM")
        && segs[1].eq_ignore_ascii_case("SYSTEM")
        && segs[2].eq_ignore_ascii_case("CurrentControlSet")
    {
        segs[2] = control_set_name(n);
    }
}

/// Whether a path names a registry key (as opposed to a file path).
pub(crate) fn is_registry_path(path: &str) -> bool {
    let first = path.split('\\').next().unwrap_or("");
    ["HKLM", "HKU", "HKCU", "HKCR", "HKCC"]
        .iter()
        .any(|r| first.eq_ignore_ascii_case(r))
        || first.len() > 5 && first[..5].eq_ignore_ascii_case("HKEY_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_ccs() {
        assert_eq!(
            split_key("HKLM\\SOFTWARE\\\\X\\"),
            vec!["HKLM", "SOFTWARE", "X"]
        );
        let mut s: Vec<String> = split_key("HKLM\\SYSTEM\\CurrentControlSet\\Services\\x")
            .into_iter()
            .map(String::from)
            .collect();
        map_current_control_set(&mut s, 1);
        assert_eq!(s.join("\\"), "HKLM\\SYSTEM\\ControlSet001\\Services\\x");
        let mut s = vec![
            "HKLM".to_string(),
            "SOFTWARE".to_string(),
            "CurrentControlSet".to_string(),
        ];
        map_current_control_set(&mut s, 2);
        assert_eq!(s[2], "CurrentControlSet");
    }

    #[test]
    fn registry_path_detection() {
        assert!(is_registry_path("HKLM\\SOFTWARE"));
        assert!(is_registry_path("hku\\S-1-5-18"));
        assert!(is_registry_path("HKEY_LOCAL_MACHINE\\SOFTWARE"));
        assert!(!is_registry_path("C:\\Program Files"));
        assert!(!is_registry_path("HKLMX\\a"));
    }
}
