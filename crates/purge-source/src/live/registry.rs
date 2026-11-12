//! [`LiveRegistry`]: [`RegistrySource`] over `purge_win::reg` (ENGINE_PLAN.md §3.2, §5.10 G1).
//!
//! Every query translates the canonical key path ([`super::regpath`]) and opens it component by component
//! with `REG_OPTION_OPEN_LINK` and an explicit view, so a link key is opened as itself: its
//! `SymbolicLinkValue` is reported through [`KeyInfo::link_target`] and its target is never read. A path
//! that would have to pass through a link fails with [`SourceError::ReparsePoint`].

use std::sync::OnceLock;

use purge_model::FileTime;
use purge_win::reg::{self, Key};

use super::errors::{ERROR_FILE_NOT_FOUND, map_win32};
use super::regpath::{RegLocation, translate_key};
use crate::registry::RegistrySource;
use crate::types::{KeyInfo, RegData, RegValue, SourceError, SourceResult};

/// The live registry, read only. Cheap to create; the current control set is cached once it has been read
/// successfully.
#[derive(Debug, Default)]
pub struct LiveRegistry {
    control_set: OnceLock<u32>,
}

impl LiveRegistry {
    /// A live registry source.
    pub fn new() -> Self {
        Self::default()
    }

    /// Where a canonical key path is opened (root, subpath, view).
    fn locate(&self, key: &str) -> SourceResult<RegLocation> {
        translate_key(key, || self.current_control_set())
    }

    /// Opens a canonical key path.
    fn open(&self, key: &str) -> SourceResult<Key> {
        let loc = self.locate(key)?;
        Key::open(loc.root, &loc.path, loc.view).map_err(map_win32)
    }

    fn read_control_set() -> SourceResult<u32> {
        let name = reg::current_control_set().map_err(map_win32)?;
        name.strip_prefix("ControlSet")
            .and_then(|digits| digits.parse::<u32>().ok())
            .ok_or(SourceError::Other(ERROR_FILE_NOT_FOUND))
    }
}

/// Converts a `purge-win` value to the source type (complete data, no hash).
pub(crate) fn to_reg_value(v: reg::RegValue) -> RegValue {
    RegValue {
        name: v.name,
        data: RegData::new(v.ty, v.data),
    }
}

impl RegistrySource for LiveRegistry {
    fn key_info(&self, key: &str) -> SourceResult<KeyInfo> {
        let k = self.open(key)?;
        let info = k.info().map_err(map_win32)?;
        // A key whose `SymbolicLinkValue` cannot be read is reported as "not a link": the open itself
        // succeeded with `REG_OPTION_OPEN_LINK`, so nothing was followed either way.
        let link_target = k.link_target().ok().flatten();
        // Reading the security descriptor may be refused where the key itself is readable.
        let ti_owned = k.security().ok().map(|s| s.trusted_installer());
        Ok(KeyInfo {
            lwt: FileTime(info.last_write_time),
            n_values: info.n_values,
            n_subkeys: info.n_subkeys,
            is_link: link_target.is_some(),
            link_target,
            ti_owned,
        })
    }

    fn subkeys(&self, key: &str) -> SourceResult<Vec<String>> {
        self.open(key)?.subkey_names().map_err(map_win32)
    }

    fn values(&self, key: &str) -> SourceResult<Vec<RegValue>> {
        Ok(self
            .open(key)?
            .values()
            .map_err(map_win32)?
            .into_iter()
            .map(to_reg_value)
            .collect())
    }

    fn value(&self, key: &str, name: &str) -> SourceResult<RegData> {
        match self.open(key)?.value(name).map_err(map_win32)? {
            Some(v) => Ok(RegData::new(v.ty, v.data)),
            None => Err(SourceError::NotFound),
        }
    }

    fn loaded_user_sids(&self) -> SourceResult<Vec<String>> {
        reg::loaded_user_sids().map_err(map_win32)
    }

    fn current_control_set(&self) -> SourceResult<u32> {
        if let Some(&n) = self.control_set.get() {
            return Ok(n);
        }
        let n = Self::read_control_set()?;
        Ok(*self.control_set.get_or_init(|| n))
    }
}
