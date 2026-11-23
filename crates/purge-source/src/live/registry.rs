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
            values: None,
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
/// A key that has values is read when it is entered: its values are what a walk asks for next, and
/// they also say whether the key is a link (`Key::link_target_with_values`), so the key is not asked
/// for `SymbolicLinkValue` by name as well. The values are read up to the count the key reported when
/// it was entered (`Key::values_counted`), without the extra call that only ends an enumeration:
/// values are enumerated in the order they were added, so a value added between the count and the
/// read is left out (a read by path may or may not see it) and no counted value is lost. The subkey
/// names are always enumerated to the end of the list (`Key::subkey_names_after`; the count only
/// sizes the buffers): subkeys are enumerated sorted by name, so stopping at the count would lose a
/// subkey that was there all along whenever another one is created before it meanwhile. For a key
/// nobody changes while it is read both are what the reads by path give.
///
/// Only a whole component that is spelled exactly the same is reused, and only as an ancestor: the key
/// itself is always opened anew, for reading. When an open below a kept key fails, the key is opened
/// again from its root and that result counts, so a kept key that was deleted meanwhile reads exactly
/// as a fresh open would. The link check of a kept key is skipped only when the key was entered with
/// subkeys of its own (`Key::link_target_with_info`), which no link key has; every other kept key is
/// asked again before a path goes below it, whatever the caller entered or listed before. The walker
/// lives for one walk. Two differences from fresh opens remain, both from changes made during the walk:
/// a kept key that was renamed reads as it was before the rename (the same snapshot inconsistency any
/// non-atomic walk has), and an entered ordinary key that gets a `REG_LINK` `SymbolicLinkValue` is
/// still read below (the kernel does not follow it either; a fresh open refuses it as a link).
struct LiveWalker<'a> {
    registry: &'a LiveRegistry,
    chain: Option<Chain>,
    /// The `RegQueryInfoKey` answer of the key last entered (sizes the subkey name buffer, and counts
    /// the values and subkeys to read).
    info: Option<reg::KeyInfo>,
    /// The values of the key last entered, when `enter` read them to see whether the key is a link;
    /// [`KeyWalker::values`] hands them out once.
    values: Option<Result<Vec<reg::RegValue>, purge_win::os::Win32Error>>,
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
        self.values = None;
        if let Err(e) = self.open(key) {
            self.chain = None;
            return Err(e);
        }
        let k = self.current()?;
        let info = k.info().map_err(map_win32)?;
        // As `LiveRegistry::key_info` (a key without values is not asked). "No link" is remembered on
        // the handle only for a key with subkeys of its own, which no link key has, so a link key
        // entered before its target was written is asked again when a path goes below it.
        //
        // A key with values is read here, once: a walk reads the values of every key it enters, and
        // they show whether the key is a link without a separate question (`SymbolicLinkValue` is
        // one of them). When they cannot be read, the key is asked by name as before, and
        // `KeyWalker::values` reports the failed read.
        let (link_target, values) = if info.n_values == 0 {
            (k.link_target_with_info(&info).ok().flatten(), None)
        } else {
            match k.values_counted(&info) {
                Ok(values) => (
                    k.link_target_with_values(&info, &values).ok().flatten(),
                    Some(Ok(values)),
                ),
                Err(e) => (k.link_target_with_info(&info).ok().flatten(), Some(Err(e))),
            }
        };
        self.info = Some(info);
        self.values = values;
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
        let values = match self.values.take() {
            Some(read) => read,
            None => self.current()?.values(),
        };
        Ok(values
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
