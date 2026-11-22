//! The broker's caches in its store: the MSI table cache `<data root>\fp\msitables` and the local
//! baseline cache `<data root>\baseline`, each reached through purge-exec's checked handle on its
//! directory, never by path (DECISIONS 2026-11-22, "fp checked" and "baseline checked").
//!
//! The engine's `DiskTableCache` and `LocalCache::open` open the directory and its files by path,
//! which is safe only while nobody but administrators can write the directory and its ancestors. The
//! broker is elevated, so it does not rely on that: every use opens the store's checked directory
//! ([`StorageRoots::msi_tables_dir`], [`StorageRoots::baseline_dir`]: the data root and the
//! directories judged as store directories, a failing one renamed aside) and reads, replaces, lists
//! and removes the cache files relative to that handle ([`DocDir`]). The files, their names and their
//! formats are the engine's (`purge_index::ownership::cache`, `purge_index::local_baseline::cache`),
//! so the medium engine reads what the broker wrote.

use std::io;
use std::sync::Arc;
use std::time::SystemTime;

use purge_engine::pipeline::{
    LocalCacheSource, SharedLocalCacheSource, SharedTableCacheSource, TableCacheSource,
};
use purge_exec::storage::{DocDir, StorageError, StorageRoots};
use purge_index::local_baseline::{CacheFiles, LocalCache};
use purge_index::ownership::cache::{
    CacheKey, MAX_CACHE_FILE, TableCache, decode_cache_file, encode_cache_file, temp_file_name,
};
use purge_source::sysobj::MsiTables;

/// The source of the broker's MSI table cache: the store's checked `fp\msitables`, opened anew for
/// every engine call.
#[derive(Debug, Clone)]
pub struct StoreTableCaches {
    store: StorageRoots,
}

impl StoreTableCaches {
    /// The source over `store`.
    pub fn new(store: StorageRoots) -> Self {
        StoreTableCaches { store }
    }

    /// The source as the engine settings hold it.
    pub fn shared(store: StorageRoots) -> SharedTableCacheSource {
        SharedTableCacheSource(Arc::new(Self::new(store)))
    }
}

impl TableCacheSource for StoreTableCaches {
    /// The checked directory, or `None` (the call caches in memory) when it fails its check or cannot
    /// be opened or created.
    fn open(&self) -> Option<Box<dyn TableCache>> {
        let dir = self.store.msi_tables_dir().ok()?;
        Some(Box::new(CheckedTableCache { dir }))
    }
}

/// One engine call's MSI table cache over the checked `fp\msitables` handle. As the engine's cache, a
/// file that cannot be read or fails its check is a miss and a write that fails is silent.
#[derive(Debug)]
pub struct CheckedTableCache {
    dir: DocDir,
}

impl TableCache for CheckedTableCache {
    fn get(&self, key: &CacheKey) -> Option<MsiTables> {
        let bytes = self.dir.read(&key.file_name(), MAX_CACHE_FILE).ok()??;
        decode_cache_file(key, &bytes)
    }

    fn put(&self, key: &CacheKey, tables: &MsiTables) {
        if let Some(bytes) = encode_cache_file(key, tables) {
            let _ = self
                .dir
                .replace(&key.file_name(), &temp_file_name(key), &bytes);
        }
    }
}

/// The source of the broker's local baseline cache: the store's checked `baseline`, opened anew for
/// every pipeline step and for the background build.
#[derive(Debug, Clone)]
pub struct StoreLocalCaches {
    store: StorageRoots,
}

impl StoreLocalCaches {
    /// The source over `store`.
    pub fn new(store: StorageRoots) -> Self {
        StoreLocalCaches { store }
    }

    /// The source as the engine settings hold it.
    pub fn shared(store: StorageRoots) -> SharedLocalCacheSource {
        SharedLocalCacheSource(Arc::new(Self::new(store)))
    }
}

impl LocalCacheSource for StoreLocalCaches {
    /// The cache over the checked directory, or `None` (no cache for the step, the build stores
    /// nothing) when the directory fails its check or cannot be opened or created.
    fn open(&self, writable: bool) -> Option<LocalCache> {
        let dir = self.store.baseline_dir().ok()?;
        let path = dir.path().to_path_buf();
        Some(LocalCache::with_files(
            &path,
            Arc::new(CheckedCacheFiles { dir }),
            writable,
        ))
    }
}

/// The local baseline cache's files, relative to the checked `baseline` handle: listed, read,
/// replaced and removed through [`DocDir`], each file judged as a store file on the handle it is used
/// through.
#[derive(Debug)]
pub struct CheckedCacheFiles {
    dir: DocDir,
}

/// A store refusal as the cache sees it: a missing file is [`io::ErrorKind::NotFound`] (a miss), a
/// file over the limit [`io::ErrorKind::InvalidData`], anything else (a planted object renamed aside,
/// a name the store does not accept) another error, which the cache treats as a miss too.
fn io_error(error: StorageError) -> io::Error {
    match error {
        StorageError::TooLarge { .. } => io::Error::new(io::ErrorKind::InvalidData, error),
        other => io::Error::other(other),
    }
}

impl CacheFiles for CheckedCacheFiles {
    fn list(&self) -> Vec<(String, SystemTime)> {
        self.dir.list().unwrap_or_default()
    }

    fn read(&self, name: &str, max: u64) -> io::Result<Vec<u8>> {
        self.dir
            .read(name, max)
            .map_err(io_error)?
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }

    fn replace(&self, name: &str, temp: &str, bytes: &[u8]) -> io::Result<()> {
        self.dir.replace(name, temp, bytes).map_err(io_error)
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        match self.dir.remove(name).map_err(io_error)? {
            true => Ok(()),
            false => Err(io::ErrorKind::NotFound.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_refusals_map_to_the_errors_the_cache_reads() {
        let too_large = io_error(StorageError::TooLarge {
            path: r"C:\ProgramData\Purge\baseline\x.sets".into(),
            bytes: 3,
            max: 2,
        });
        assert_eq!(too_large.kind(), io::ErrorKind::InvalidData);
        let refused = io_error(StorageError::InvalidPath("a b".into()));
        assert_ne!(refused.kind(), io::ErrorKind::NotFound);
        assert_ne!(refused.kind(), io::ErrorKind::InvalidData);
    }
}
