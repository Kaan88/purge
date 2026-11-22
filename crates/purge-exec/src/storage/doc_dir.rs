//! The broker's document directories: `<data root>\fp`, `fp\msitables` and `<data root>\baseline` as
//! checked `Store` directories (DECISIONS 2026-11-22, "fp checked" and "baseline checked").
//!
//! The broker writes, replaces, removes and sweeps files in these directories while elevated. They
//! are admin-only on a correct install (`install.ps1` creates `fp` with the `Store` descriptor; the
//! others are created by Purge), but a directory a standard user could write (ACL drift, a restored
//! backup, a future installer bug) would let a junction to `\RPC Control` and an object symbolic link
//! turn a rename by path into an overwrite of any file, and a delete by path into a delete of any
//! file. So they are checked like `sessions` and `Quarantine`: each directory is opened **by path**
//! without following a final reparse point, bound to the checked chain by its final path (the checked
//! parent's final path plus its name, [`IntegrityFailure::FinalPathMismatch`] otherwise) and judged by
//! [`verdict`] as [`ObjectKind::Store`] on that same handle (a failing object is renamed aside,
//! [`StorageError::Integrity`]). Every **file** in them is then created, opened, replaced, listed and
//! deleted relative to the directory's checked handle (`NtCreateFile` with that handle as root and one
//! name component), a reparse point at the name opened itself, never followed ([`DocDir`]).
//!
//! # Upgrade of `fp`
//!
//! A broker before "fp checked" created `fp` by path when it was missing, so on such a machine `fp`
//! inherits its DACL from the data root: admin-only, but not protected, which the check refuses. Its
//! fingerprints cannot all be made again (a program that is gone cannot be harvested), so when such an
//! `fp` is renamed aside its fingerprints are moved into the new one ([`StorageRoots::fp_dir`]): only
//! when the old directory passes the `Store` verdict but for the protected flag (no reparse point,
//! owner Administrators or SYSTEM, nobody else may write), and only files named `fp-<sha256>.json`
//! that pass the `StoreFile` verdict on a handle opened relative to the old directory (a plain file,
//! one link, owner Administrators or SYSTEM, nobody else may write) and hold at most
//! [`MAX_MIGRATED_BYTES`]. Each is renamed into the new `fp` by that handle. Nothing else is moved.
//! An upgrade that stopped after the rename (the new `fp` could not be made, the broker ended) is
//! finished by the next use: an `fp` holding no fingerprint takes them, by the same rules, from the
//! newest `fp.rejected-*` when that directory passes the `Store` verdict as it is now. A name the new
//! `fp` already has is never replaced (the old file stays aside), so the move is never done twice.
//!
//! # Pruning
//!
//! [`StorageRoots::prune_rejected`] removes what these directories renamed aside more than a given age
//! ago (the broker: 30 days at its start), by the time in the name, deleting a rejected directory's
//! contents relative to handles without following anything. It creates no directory: `fp\msitables`
//! and `baseline` are pruned only when they exist.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use purge_model::FileTime;
use purge_model::exec::session::SessionId;
use purge_win::fs_write::{self, FsError};
use purge_win::secure;

use super::{
    CheckedDir, IntegrityFailure, ObjectFacts, ObjectKind, Parent, REPLACE_RETRY_MS, StorageError,
    StorageRoots, at, ext, io, is_store_name, os_error, same_path, sys, verdict,
};

/// The largest fingerprint moved from an old `fp` (the broker reads no larger one).
pub const MAX_MIGRATED_BYTES: u64 = 64 << 20;
/// How deep [`StorageRoots::prune_rejected`] goes into a rejected directory.
const PRUNE_DEPTH: u32 = 16;

/// The fingerprint directory under the data root.
pub const FP_DIR: &str = "fp";
/// The MSI table cache directory under [`FP_DIR`].
pub const MSI_TABLES_DIR: &str = "msitables";
/// The local baseline cache directory under the data root (BASELINE_LOCAL_DESIGN.md §5).
pub const BASELINE_DIR: &str = "baseline";

/// `FILETIME` of the Unix epoch (100 ns ticks since 1601).
const UNIX_EPOCH_FILETIME: i64 = 116_444_736_000_000_000;

impl StorageRoots {
    /// `<data root>\fp`.
    pub fn fp_path(&self) -> PathBuf {
        self.data_root.join(FP_DIR)
    }

    /// `<data root>\fp\msitables`.
    pub fn msi_tables_path(&self) -> PathBuf {
        self.fp_path().join(MSI_TABLES_DIR)
    }

    /// `<data root>\fp`, after checking the data root and `fp` (created with the `Store` descriptor
    /// when missing, as the installer does). A failing `fp` is renamed aside and refused this time; the
    /// next use creates a new one. The exception is the `fp` an older broker made by path (see the
    /// module documentation, "Upgrade of `fp`"): it is renamed aside, a new one is created at once,
    /// its fingerprints are moved over, and the use goes on.
    pub fn fp_dir(&self) -> Result<DocDir, StorageError> {
        let root = self.checked_data_root()?;
        let dir = self.fp_child(&root)?;
        Ok(DocDir {
            roots: self.clone(),
            dir,
        })
    }

    /// `<data root>\fp\msitables`, after checking the data root, `fp` and `msitables` (each created with
    /// the `Store` descriptor when missing).
    pub fn msi_tables_dir(&self) -> Result<DocDir, StorageError> {
        let root = self.checked_data_root()?;
        let fp = self.fp_child(&root)?;
        let dir = self
            .child_dir(
                &fp,
                MSI_TABLES_DIR,
                ObjectKind::Store,
                super::Create::IfAbsent,
            )?
            .ok_or_else(|| io("open", &self.msi_tables_path(), FsError::NotFound))?;
        Ok(DocDir {
            roots: self.clone(),
            dir,
        })
    }

    /// `<data root>\baseline`.
    pub fn baseline_path(&self) -> PathBuf {
        self.data_root.join(BASELINE_DIR)
    }

    /// `<data root>\baseline`, the local baseline cache, after checking the data root and `baseline`
    /// (created with the `Store` descriptor when missing). A failing one is renamed aside and refused
    /// this time; the next use creates a new one, and the cache is built again.
    pub fn baseline_dir(&self) -> Result<DocDir, StorageError> {
        let root = self.checked_data_root()?;
        let dir = self
            .child_dir(
                &root,
                BASELINE_DIR,
                ObjectKind::Store,
                super::Create::IfAbsent,
            )?
            .ok_or_else(|| io("open", &self.baseline_path(), FsError::NotFound))?;
        Ok(DocDir {
            roots: self.clone(),
            dir,
        })
    }

    /// `fp` under the checked data root, with the upgrade of an old `fp` (module documentation).
    fn fp_child(&self, root: &CheckedDir) -> Result<CheckedDir, StorageError> {
        // Judged before the check renames it aside (which also replaces its DACL): whether it is an
        // old broker's `fp`, and which object that was.
        let upgrade = self.old_fp(root);
        let open = || {
            self.child_dir(root, FP_DIR, ObjectKind::Store, super::Create::IfAbsent)?
                .ok_or_else(|| io("open", &self.fp_path(), FsError::NotFound))
        };
        let dir = match open() {
            Err(StorageError::Integrity {
                failure: IntegrityFailure::UnprotectedDacl,
                renamed_to: Some(aside),
                ..
            }) if upgrade.is_some() => {
                let fresh = open()?;
                self.migrate_fingerprints(root, &aside, upgrade, &fresh);
                return Ok(fresh);
            }
            other => other?,
        };
        // An upgrade that stopped between the rename and the move (the new `fp` could not be made,
        // or the broker ended) left the fingerprints in the newest `fp.rejected-*`: an `fp` without a
        // fingerprint takes them from there, under the same per-file rules.
        if !has_fingerprints(&dir)
            && let Some(aside) = newest_rejected_fp(root)
        {
            self.migrate_fingerprints(root, &self.data_root.join(aside), None, &dir);
        }
        Ok(dir)
    }

    /// The identity of `fp` when it is a directory an older broker made by path: it would pass the
    /// `Store` verdict but for its unprotected (inherited) DACL. `None` for anything else, a missing
    /// `fp` and an `fp` that passes.
    fn old_fp(&self, root: &CheckedDir) -> Option<super::FileId> {
        let path = self.fp_path();
        let handle = secure::open_for_security(&ext(&path).ok()?).ok()?;
        let facts = at::facts(&handle).ok()?;
        let final_path = at::final_path(&handle).ok()?;
        let expected = format!(r"{}\{FP_DIR}", root.final_path.trim_end_matches('\\'));
        if !same_path(Path::new(&expected), Path::new(&final_path)) || facts.reparse_tag != 0 {
            return None;
        }
        let security = secure::handle_security(&handle).ok()?;
        if security.dacl_protected {
            return None;
        }
        let as_protected = ObjectFacts {
            reparse_tag: facts.reparse_tag,
            is_dir: facts.is_dir,
            n_links: facts.n_links,
            owner: security.owner,
            dacl_protected: true,
            dacl: security.dacl,
        };
        verdict(&self.policy, ObjectKind::Store, &as_protected)
            .is_ok()
            .then_some(facts.file_id)
    }

    /// Moves the fingerprints of an old `fp`, renamed aside to `aside`, into `fresh`: see the module
    /// documentation. `old`: the identity judged before the rename (the upgrade itself); `None` for an
    /// upgrade that stopped before the move, where the renamed directory must pass the `Store` verdict
    /// as it is now (its descriptor was replaced when it was renamed aside). A name `fresh` already has
    /// is never replaced: whatever is there stays, and the old file stays aside, so a second run moves
    /// nothing twice. Returns how many were moved; whatever is not moved stays where it is.
    fn migrate_fingerprints(
        &self,
        root: &CheckedDir,
        aside: &Path,
        old: Option<super::FileId>,
        fresh: &CheckedDir,
    ) -> usize {
        let Ok(handle) = ext(aside)
            .and_then(|p| secure::open_for_security(&p).map_err(|e| io("open", aside, e)))
        else {
            return 0;
        };
        let (Ok(facts), Ok(final_path)) = (at::facts(&handle), at::final_path(&handle)) else {
            return 0;
        };
        let leaf = aside
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let expected = format!(r"{}\{leaf}", root.final_path.trim_end_matches('\\'));
        if facts.reparse_tag != 0
            || !facts.is_dir
            || !same_path(Path::new(&expected), Path::new(&final_path))
        {
            return 0;
        }
        match old {
            Some(old) if facts.file_id != old => return 0,
            Some(_) => {}
            None => {
                let judged =
                    self.check_handle(aside, ObjectKind::Store, Some(root.as_parent()), &handle);
                if !matches!(judged, Ok(Ok(_))) {
                    return 0;
                }
            }
        }
        let parent = Parent {
            handle: &handle,
            final_path: &final_path,
        };
        let names = at::open_at(
            &handle,
            "",
            at::Open {
                access: at::FILE_LIST_DIRECTORY | at::FILE_READ_ATTRIBUTES,
                share: at::SHARE_ALL,
                create: None,
                kind: at::Kind::Dir,
            },
        )
        .and_then(|listing| at::list_names(&listing));
        let Ok(names) = names else {
            return 0;
        };
        let mut moved = 0;
        for name in names.iter().filter(|name| is_fingerprint_name(name)) {
            let Ok(file) = at::open_at(
                &handle,
                name,
                at::Open {
                    access: at::DELETE | at::READ_CONTROL | at::FILE_READ_ATTRIBUTES,
                    share: at::SHARE_READ,
                    create: None,
                    kind: at::Kind::File,
                },
            ) else {
                continue;
            };
            let path = aside.join(name);
            let judged = self.check_handle(&path, ObjectKind::StoreFile, Some(parent), &file);
            let Ok(Ok((facts, _))) = judged else {
                continue;
            };
            if facts.size > MAX_MIGRATED_BYTES {
                continue;
            }
            if at::rename_at(&file, &fresh.handle, name, false).is_ok() {
                moved += 1;
            }
        }
        if moved > 0 {
            let _ = at::flush_dir_at(&fresh.handle);
        }
        moved
    }

    /// Removes what `fp`, `fp\msitables` and `baseline` renamed aside (`<name>.rejected-<utc>[-n]`)
    /// more than `max_age` ago, by the time in its name: `fp.rejected-*` and `baseline.rejected-*`
    /// in the data root, and every `*.rejected-*` inside `fp`, `fp\msitables` and `baseline`. What the
    /// other directories of the store renamed aside (`sessions`, a session, `Quarantine`, the index)
    /// is kept: it may hold a journal or quarantined data someone recovers by hand. A directory is
    /// emptied first, each entry opened relative to its directory's handle and deleted through its own
    /// handle, a link deleted as a link and never followed, at most [`PRUNE_DEPTH`] levels deep.
    /// Failures are skipped. Returns how many top-level rejected objects were removed.
    pub fn prune_rejected(&self, max_age: Duration) -> usize {
        let ticks = u64::try_from(max_age.as_nanos() / 100).unwrap_or(u64::MAX);
        let cutoff = SessionId::new(FileTime(sys::now().0.saturating_sub(ticks)), 0);
        let cutoff = &cutoff.as_str()[..16];
        let old = |name: &str| rejected_stamp(name).is_some_and(|stamp| stamp < cutoff);
        let Ok(root) = self.checked_data_root() else {
            return 0;
        };
        let mut removed = prune_in(&root.handle, |name| {
            (name.starts_with("fp.rejected-") || name.starts_with("baseline.rejected-"))
                && old(name)
        });
        // Checked, never created: a cache directory that does not exist has nothing to prune, and an
        // engine on a host with an exact baseline makes none (L3).
        let existing = |parent: &CheckedDir, leaf: &str| {
            self.child_dir(parent, leaf, ObjectKind::Store, super::Create::Never)
                .ok()
                .flatten()
        };
        if let Some(fp) = existing(&root, FP_DIR) {
            removed += prune_in(&fp.handle, old);
            if let Some(tables) = existing(&fp, MSI_TABLES_DIR) {
                removed += prune_in(&tables.handle, old);
            }
        }
        if let Some(baseline) = existing(&root, BASELINE_DIR) {
            removed += prune_in(&baseline.handle, old);
        }
        removed
    }
}

/// Whether the directory behind `dir` holds a stored fingerprint ([`is_fingerprint_name`]); a
/// directory that cannot be listed counts as holding one (nothing is moved into it).
fn has_fingerprints(dir: &CheckedDir) -> bool {
    at::open_at(
        &dir.handle,
        "",
        at::Open {
            access: at::FILE_LIST_DIRECTORY | at::FILE_READ_ATTRIBUTES,
            share: at::SHARE_ALL,
            create: None,
            kind: at::Kind::Dir,
        },
    )
    .and_then(|listing| at::list_names(&listing))
    .map_or(true, |names| names.iter().any(|n| is_fingerprint_name(n)))
}

/// The newest `fp.rejected-<utc>[-n]` in the data root behind `root`, by the time and number in its
/// name.
fn newest_rejected_fp(root: &CheckedDir) -> Option<String> {
    let names = at::open_at(
        &root.handle,
        "",
        at::Open {
            access: at::FILE_LIST_DIRECTORY | at::FILE_READ_ATTRIBUTES,
            share: at::SHARE_ALL,
            create: None,
            kind: at::Kind::Dir,
        },
    )
    .and_then(|listing| at::list_names(&listing))
    .ok()?;
    names
        .into_iter()
        .filter(|name| name.starts_with("fp.rejected-"))
        .filter_map(|name| {
            let stamp = rejected_stamp(&name)?.to_owned();
            let n: u32 = name
                .rsplit_once(&stamp)
                .and_then(|(_, rest)| rest.strip_prefix('-'))
                .map_or(Some(1), |n| n.parse().ok())?;
            Some(((stamp, n), name))
        })
        .max()
        .map(|(_, name)| name)
}

/// A store refusal as a cache sees it ([`DocDir::read_file`] and the others): a file over the limit
/// is [`std::io::ErrorKind::InvalidData`], anything else (a planted object renamed aside, a name the
/// store does not accept, a failed call) [`std::io::ErrorKind::Other`] with the refusal as its text.
/// Never [`std::io::ErrorKind::NotFound`], which a cache reads as "no such file".
pub fn io_error(error: StorageError) -> std::io::Error {
    match error {
        StorageError::TooLarge { .. } => {
            std::io::Error::new(std::io::ErrorKind::InvalidData, error)
        }
        other => std::io::Error::other(other),
    }
}

/// Whether `name` is a stored fingerprint's: `fp-<64 lower-case hex>.json`.
fn is_fingerprint_name(name: &str) -> bool {
    name.strip_prefix("fp-")
        .and_then(|rest| rest.strip_suffix(".json"))
        .is_some_and(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// The `yyyyMMddTHHmmssZ` of a name the store renamed aside (`<leaf>.rejected-<stamp>[-n]`).
fn rejected_stamp(name: &str) -> Option<&str> {
    let at = name.rfind(".rejected-")? + ".rejected-".len();
    let stamp = name.get(at..at + 16)?;
    let rest = &name[at + 16..];
    let bytes = stamp.as_bytes();
    let shape = bytes.iter().enumerate().all(|(i, b)| match i {
        8 => *b == b'T',
        15 => *b == b'Z',
        _ => b.is_ascii_digit(),
    });
    let suffix = rest.is_empty()
        || rest
            .strip_prefix('-')
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    (shape && suffix).then_some(stamp)
}

/// Removes the entries of the directory behind `dir` whose names `remove` accepts
/// ([`delete_at`]); returns how many went.
fn prune_in(dir: &impl std::os::windows::io::AsHandle, remove: impl Fn(&str) -> bool) -> usize {
    let names = at::open_at(
        dir,
        "",
        at::Open {
            access: at::FILE_LIST_DIRECTORY | at::FILE_READ_ATTRIBUTES,
            share: at::SHARE_ALL,
            create: None,
            kind: at::Kind::Dir,
        },
    )
    .and_then(|listing| at::list_names(&listing));
    let Ok(names) = names else {
        return 0;
    };
    names
        .iter()
        .filter(|name| remove(name))
        .filter(|name| delete_at(dir, name, PRUNE_DEPTH))
        .count()
}

/// Deletes `leaf` of the directory behind `dir`, opened relative to it without following a reparse
/// point: a file, or a link of any kind, through its own handle; a plain directory after its entries
/// (depth permitting). Whether it went.
fn delete_at(dir: &impl std::os::windows::io::AsHandle, leaf: &str, depth: u32) -> bool {
    let Ok(handle) = at::open_at(
        dir,
        leaf,
        at::Open {
            access: at::DELETE | at::FILE_LIST_DIRECTORY | at::FILE_READ_ATTRIBUTES,
            share: at::SHARE_ALL,
            create: None,
            kind: at::Kind::File,
        },
    ) else {
        return false;
    };
    let Ok(facts) = at::facts(&handle) else {
        return false;
    };
    if facts.is_dir && facts.reparse_tag == 0 {
        if depth == 0 {
            return false;
        }
        if let Ok(names) = at::list_names(&handle) {
            for name in names {
                delete_at(&handle, &name, depth - 1);
            }
        }
    }
    at::dispose(&handle).is_ok()
}

/// A checked document directory (`fp`, `fp\msitables` or `baseline`) and the handle it was checked
/// through. Every file is reached relative to that handle, by one plain name Purge generates
/// (ASCII letters, digits, `.`, `_`, `-`), never by path. The files are [`ObjectKind::StoreFile`]s:
/// a file, not a reparse point, one link, owner Administrators or SYSTEM, nobody else may write.
#[derive(Debug)]
pub struct DocDir {
    roots: StorageRoots,
    dir: CheckedDir,
}

impl DocDir {
    /// The path the directory was checked at, for messages.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The checked directory.
    pub fn dir(&self) -> &CheckedDir {
        &self.dir
    }

    fn leaf_path(&self, leaf: &str) -> Result<PathBuf, StorageError> {
        let path = self.dir.path.join(leaf);
        if is_store_name(leaf) {
            Ok(path)
        } else {
            Err(StorageError::InvalidPath(path.display().to_string()))
        }
    }

    /// The bytes of the file `leaf`, opened relative to the directory's handle and checked as a store
    /// file on the handle it is read through; `Ok(None)` when nothing has the name. An object that
    /// fails the check is renamed aside ([`StorageError::Integrity`]); a file over `max` bytes is
    /// [`StorageError::TooLarge`], nothing of it read.
    pub fn read(&self, leaf: &str, max: u64) -> Result<Option<Vec<u8>>, StorageError> {
        let path = self.leaf_path(leaf)?;
        let opened = self.roots.open_file_at(
            &self.dir,
            leaf,
            ObjectKind::StoreFile,
            at::Open {
                access: at::GENERIC_READ | at::READ_CONTROL,
                // A writer may replace the name meanwhile; this handle keeps reading the old file.
                share: at::SHARE_ALL,
                create: None,
                kind: at::Kind::File,
            },
        )?;
        let Some((file, facts)) = opened else {
            return Ok(None);
        };
        let too_large = |bytes| StorageError::TooLarge {
            path: path.clone(),
            bytes,
            max,
        };
        if facts.size > max {
            return Err(too_large(facts.size));
        }
        let mut bytes = Vec::new();
        file.take(max.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| io("read", &path, os_error(&e)))?;
        if bytes.len() as u64 > max {
            return Err(too_large(bytes.len() as u64));
        }
        Ok(Some(bytes))
    }

    /// Replaces the file `leaf` with `bytes`, atomically: the temporary file `temp` is created new in
    /// this directory relative to its handle (`StoreFile` descriptor), written and flushed, then
    /// renamed over `leaf` through its own handle and the directory's. Readers see the old document or
    /// the new one, never a mix.
    ///
    /// An object at `leaf` that fails its check is refused and renamed aside, never replaced. An
    /// object at `temp` (a crash's leftover, or something planted) is removed when it passes the
    /// check as Purge's own file and otherwise refused and renamed aside; nothing at either name is
    /// ever followed. On a failure after the temporary file was created, it is deleted through its
    /// handle.
    pub fn replace(&self, leaf: &str, temp: &str, bytes: &[u8]) -> Result<(), StorageError> {
        let dest = self.leaf_path(leaf)?;
        let temp_path = self.leaf_path(temp)?;
        if leaf.eq_ignore_ascii_case(temp) {
            return Err(StorageError::InvalidPath(temp_path.display().to_string()));
        }
        let inspect_only = at::Open {
            access: at::READ_CONTROL | at::FILE_READ_ATTRIBUTES,
            share: at::SHARE_ALL,
            create: None,
            kind: at::Kind::File,
        };
        // The document being replaced must pass its own check: a planted object is refused and
        // renamed aside, never silently replaced.
        self.roots
            .open_file_at(&self.dir, leaf, ObjectKind::StoreFile, inspect_only)?;
        // Whatever has the temporary name is opened itself and checked: Purge's own leftover is
        // deleted through the checked handle, anything else is refused and renamed aside.
        let stale = at::Open {
            access: at::DELETE | at::READ_CONTROL | at::FILE_READ_ATTRIBUTES,
            ..inspect_only
        };
        if let Some((stale, _)) =
            self.roots
                .open_file_at(&self.dir, temp, ObjectKind::StoreFile, stale)?
        {
            at::dispose(&stale).map_err(|e| io("delete", &temp_path, e))?;
        }
        let (file, _) = self
            .roots
            .create_file_at(&self.dir, temp, ObjectKind::StoreFile)?;
        let written = write_and_replace(&file, bytes, &temp_path, &self.dir, leaf, &dest);
        if written.is_err() {
            let _ = at::dispose(&file);
        }
        written
    }

    /// The plain files of this directory (one link, not a directory, not a reparse point of any kind)
    /// whose names Purge could have made, with their last write times: listed through the
    /// directory's handle and each judged on a handle opened relative to it, without following
    /// anything. Anything else is left out. An error only when the directory cannot be listed.
    pub fn list(&self) -> Result<Vec<(String, SystemTime)>, StorageError> {
        let names = at::open_at(
            &self.dir.handle,
            "",
            at::Open {
                access: at::FILE_LIST_DIRECTORY | at::FILE_READ_ATTRIBUTES,
                share: at::SHARE_ALL,
                create: None,
                kind: at::Kind::Dir,
            },
        )
        .and_then(|listing| at::list_names(&listing))
        .map_err(|e| io("list", self.path(), e))?;
        let mut files = Vec::with_capacity(names.len());
        for name in names.into_iter().filter(|name| is_store_name(name)) {
            let Ok(handle) = at::open_at(
                &self.dir.handle,
                &name,
                at::Open {
                    access: at::FILE_READ_ATTRIBUTES,
                    share: at::SHARE_ALL,
                    create: None,
                    kind: at::Kind::File,
                },
            ) else {
                continue;
            };
            let Ok(facts) = at::facts(&handle) else {
                continue;
            };
            if !facts.is_dir && facts.reparse_tag == 0 && facts.n_links == 1 {
                files.push((name, system_time(facts.last_write)));
            }
        }
        Ok(files)
    }

    /// Deletes the file `leaf`, opened relative to the directory's handle and checked as a store file
    /// on that handle, through that handle. `Ok(false)` when nothing has the name. An object that
    /// fails the check (a link, a directory, a file someone else owns) is not deleted: it is renamed
    /// aside ([`StorageError::Integrity`]).
    pub fn remove(&self, leaf: &str) -> Result<bool, StorageError> {
        let path = self.leaf_path(leaf)?;
        let opened = self.roots.open_file_at(
            &self.dir,
            leaf,
            ObjectKind::StoreFile,
            at::Open {
                access: at::DELETE | at::READ_CONTROL | at::FILE_READ_ATTRIBUTES,
                share: at::SHARE_ALL,
                create: None,
                kind: at::Kind::File,
            },
        )?;
        let Some((file, _)) = opened else {
            return Ok(false);
        };
        at::dispose(&file).map_err(|e| io("delete", &path, e))?;
        Ok(true)
    }

    /// [`DocDir::read`] as a cache reads a file: a missing one is [`std::io::ErrorKind::NotFound`] (a
    /// miss), one over `max` bytes [`std::io::ErrorKind::InvalidData`], any other refusal ([`io_error`])
    /// another error, which a cache takes as a miss too.
    pub fn read_file(&self, name: &str, max: u64) -> std::io::Result<Vec<u8>> {
        self.read(name, max)
            .map_err(io_error)?
            .ok_or_else(|| std::io::ErrorKind::NotFound.into())
    }

    /// [`DocDir::replace`] for a cache.
    pub fn replace_file(&self, name: &str, temp: &str, bytes: &[u8]) -> std::io::Result<()> {
        self.replace(name, temp, bytes).map_err(io_error)
    }

    /// [`DocDir::remove`] for a cache: nothing at the name is [`std::io::ErrorKind::NotFound`].
    pub fn remove_file(&self, name: &str) -> std::io::Result<()> {
        match self.remove(name).map_err(io_error)? {
            true => Ok(()),
            false => Err(std::io::ErrorKind::NotFound.into()),
        }
    }

    /// [`DocDir::list`] for a cache: a directory that cannot be listed lists nothing.
    pub fn list_files(&self) -> Vec<(String, SystemTime)> {
        self.list().unwrap_or_default()
    }

    /// Deletes the files of this directory that `is_temp` accepts and that were last written before
    /// `before`: only names Purge generates, and only a plain file with one link (not a directory, not
    /// a reparse point of any kind), opened relative to the directory's handle without following
    /// anything and deleted through that handle. A file another handle holds open is left. Failures
    /// are ignored: a file left stays harmless. Returns how many were deleted.
    pub fn sweep(&self, is_temp: impl Fn(&str) -> bool, before: SystemTime) -> usize {
        let Some(cutoff) = filetime(before) else {
            return 0;
        };
        let listing = at::open_at(
            &self.dir.handle,
            "",
            at::Open {
                access: at::FILE_LIST_DIRECTORY | at::FILE_READ_ATTRIBUTES,
                share: at::SHARE_ALL,
                create: None,
                kind: at::Kind::Dir,
            },
        );
        let Ok(names) = listing.and_then(|listing| at::list_names(&listing)) else {
            return 0;
        };
        let mut removed = 0;
        for name in names
            .iter()
            .filter(|name| is_store_name(name) && is_temp(name))
        {
            let Ok(handle) = at::open_at(
                &self.dir.handle,
                name,
                at::Open {
                    access: at::DELETE | at::FILE_READ_ATTRIBUTES,
                    share: at::SHARE_NONE,
                    create: None,
                    kind: at::Kind::File,
                },
            ) else {
                continue;
            };
            let Ok(facts) = at::facts(&handle) else {
                continue;
            };
            let plain = !facts.is_dir && facts.reparse_tag == 0 && facts.n_links == 1;
            if plain && facts.last_write < cutoff && at::dispose(&handle).is_ok() {
                removed += 1;
            }
        }
        removed
    }
}

/// Writes `bytes` to the temporary file, flushes it and renames it over `leaf` of `dir`.
fn write_and_replace(
    file: &File,
    bytes: &[u8],
    temp_path: &Path,
    dir: &CheckedDir,
    leaf: &str,
    dest: &Path,
) -> Result<(), StorageError> {
    let mut writer = file;
    writer
        .write_all(bytes)
        .map_err(|e| io("write", temp_path, os_error(&e)))?;
    fs_write::flush(file).map_err(|e| io("flush", temp_path, e))?;
    let mut waits = REPLACE_RETRY_MS.iter();
    loop {
        match at::rename_at(file, &dir.handle, leaf, true) {
            Ok(()) => return Ok(()),
            // A reader that does not share delete access holds the old document: wait a little.
            Err(e @ (FsError::SharingViolation | FsError::AccessDenied)) => match waits.next() {
                Some(&ms) => std::thread::sleep(Duration::from_millis(ms)),
                None => return Err(io("replace", dest, e)),
            },
            Err(e) => return Err(io("replace", dest, e)),
        }
    }
}

/// `time` as a `FILETIME`, or `None` before 1970 or past the range.
fn filetime(time: SystemTime) -> Option<i64> {
    let since = time.duration_since(UNIX_EPOCH).ok()?;
    let ticks = i64::try_from(since.as_nanos() / 100).ok()?;
    ticks.checked_add(UNIX_EPOCH_FILETIME)
}

/// A `FILETIME` as a [`SystemTime`]; one before 1970 is the Unix epoch.
fn system_time(filetime: i64) -> SystemTime {
    let ticks = u64::try_from(filetime.saturating_sub(UNIX_EPOCH_FILETIME)).unwrap_or(0);
    UNIX_EPOCH + Duration::from_nanos(ticks.saturating_mul(100))
}
