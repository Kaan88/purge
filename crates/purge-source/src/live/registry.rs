//! [`LiveRegistry`]: [`RegistrySource`] over `purge_win::reg` (ENGINE_PLAN.md §3.2, §5.10 G1).
//!
//! Every query translates the canonical key path ([`super::regpath`]) and opens it component by component
//! with `REG_OPTION_OPEN_LINK` and an explicit view, so a link key is opened as itself: its
//! `SymbolicLinkValue` is reported through [`KeyInfo::link_target`] and its target is never read. A path
//! that would have to pass through a link fails with [`SourceError::ReparsePoint`].

use std::sync::OnceLock;

use purge_model::FileTime;
use purge_win::reg::{self, Key, RegRoot, RegView};

use super::errors::{ERROR_FILE_NOT_FOUND, map_win32};
use super::regpath::{RegLocation, translate_key};
use crate::registry::{KeyWalker, RegistrySource};
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

    fn walker(&self) -> Box<dyn KeyWalker + '_> {
        Box::new(LiveWalker {
            registry: self,
            chain: None,
            info: None,
        })
    }
}

/// The keys of the path a [`LiveWalker`] entered last, still open: the physical root and view, and for
/// each component of the path below the root its name (as the path spells it) and its handle.
struct Chain {
    root: RegRoot,
    view: RegView,
    keys: Vec<(String, Key)>,
}

/// The [`KeyWalker`] of the live registry: it keeps the keys of the last path open and opens the next
/// key from the deepest of them that is also an ancestor of it, one component at a time with
/// `Key::open_component`, i.e. with exactly the opens, views, access rights and link checks of
/// `Key::open` of the whole path. A walk enters a key right after its parent or a sibling, so a key
/// costs one open instead of one per component, and one open for its values and subkeys instead of
/// three. The security descriptor is not read ([`KeyInfo::ti_owned`] is `None`).
///
/// Only a whole component that is spelled exactly the same is reused, and only as an ancestor: the key
/// itself is always opened anew, for reading. When an open below a kept key fails, the key is opened
/// again from its root and that result counts, so a kept key that was deleted meanwhile reads exactly
/// as a fresh open would. The walker lives for one walk (a kept key that was renamed during the walk
/// reads as it was before the rename, the same snapshot inconsistency any non-atomic walk has).
struct LiveWalker<'a> {
    registry: &'a LiveRegistry,
    chain: Option<Chain>,
    /// The `RegQueryInfoKey` answer of the key last entered (sizes the subkey name buffer).
    info: Option<reg::KeyInfo>,
}

impl LiveWalker<'_> {
    fn open(&mut self, key: &str) -> SourceResult<()> {
        let loc = self.registry.locate(key)?;
        let comps: Vec<&str> = loc.path.split('\\').filter(|c| !c.is_empty()).collect();
        let kept = self
            .chain
            .take()
            .filter(|c| c.root == loc.root && c.view == loc.view && !comps.is_empty());
        let mut keys: Vec<(String, Key)> = Vec::with_capacity(comps.len());
        if let Some(chain) = kept {
            // Ancestors only: the last component is opened anew, for reading.
            let ancestors = comps.len() - 1;
            for ((name, handle), comp) in chain.keys.into_iter().zip(&comps[..ancestors]) {
                if name != *comp {
                    break;
                }
                keys.push((name, handle));
            }
        }
        let reused = keys.len();
        let mut failed = None;
        for (i, comp) in comps.iter().enumerate().skip(reused) {
            let last = i + 1 == comps.len();
            let opened = match keys.last() {
                Some((_, parent)) => parent.open_component(comp, last),
                None => Key::root(loc.root, loc.view).open_component(comp, last),
            };
            match opened {
                Ok(handle) => keys.push(((*comp).to_owned(), handle)),
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        match failed {
            None if !comps.is_empty() => {
                self.chain = Some(Chain {
                    root: loc.root,
                    view: loc.view,
                    keys,
                });
                Ok(())
            }
            // A kept ancestor may be stale: the answer is the one of a fresh open.
            Some(_) if reused > 0 => {
                drop(keys);
                let handle = Key::open(loc.root, &loc.path, loc.view).map_err(map_win32)?;
                self.chain = Some(Chain {
                    root: loc.root,
                    view: loc.view,
                    keys: vec![(String::new(), handle)],
                });
                // Only the key itself is known to be right; nothing is kept as an ancestor.
                Ok(())
            }
            Some(e) => Err(map_win32(e)),
            // The root itself: opened as `Key::open` opens it, nothing kept.
            None => {
                let handle = Key::open(loc.root, &loc.path, loc.view).map_err(map_win32)?;
                self.chain = Some(Chain {
                    root: loc.root,
                    view: loc.view,
                    keys: vec![(String::new(), handle)],
                });
                Ok(())
            }
        }
    }

    fn current(&self) -> SourceResult<&Key> {
        self.chain
            .as_ref()
            .and_then(|c| c.keys.last())
            .map(|(_, k)| k)
            .ok_or(SourceError::NotFound)
    }
}

impl KeyWalker for LiveWalker<'_> {
    fn enter(&mut self, key: &str) -> SourceResult<KeyInfo> {
        self.info = None;
        if let Err(e) = self.open(key) {
            self.chain = None;
            return Err(e);
        }
        let k = self.current()?;
        let info = k.info().map_err(map_win32)?;
        // As `LiveRegistry::key_info`. A key without values has no `SymbolicLinkValue`, so it is no
        // link and nothing needs asking.
        let link_target = if info.n_values == 0 {
            k.note_no_values();
            None
        } else {
            k.link_target().ok().flatten()
        };
        self.info = Some(info);
        Ok(KeyInfo {
            lwt: FileTime(info.last_write_time),
            n_values: info.n_values,
            n_subkeys: info.n_subkeys,
            is_link: link_target.is_some(),
            link_target,
            ti_owned: None,
        })
    }

    fn values(&mut self) -> SourceResult<Vec<RegValue>> {
        Ok(self
            .current()?
            .values()
            .map_err(map_win32)?
            .into_iter()
            .map(to_reg_value)
            .collect())
    }

    fn subkeys(&mut self) -> SourceResult<Vec<String>> {
        let k = self.current()?;
        match &self.info {
            Some(info) => k.subkey_names_after(info),
            None => k.subkey_names(),
        }
        .map_err(map_win32)
    }
}
