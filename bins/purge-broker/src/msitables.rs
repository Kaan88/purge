//! The broker's MSI table cache: `<data root>\fp\msitables`, reached through purge-exec's checked
//! handle on it, never by path (DECISIONS 2026-11-22, "fp checked").
//!
//! The engine's `DiskTableCache` opens the directory and its files by path, which is safe only while
//! nobody but administrators can write the directory and its ancestors. The broker is elevated, so it
//! does not rely on that: every engine call opens the store's checked `fp\msitables`
//! ([`StorageRoots::msi_tables_dir`]: the data root, `fp` and `msitables` judged as store directories,
//! a failing one renamed aside) and reads and replaces the cache files relative to that handle
//! ([`FpDir::read`], [`FpDir::replace`]). The files, their names and their format are the engine's
//! (`purge_index::ownership::cache`), so the medium engine reads what the broker wrote.

use purge_engine::pipeline::{SharedTableCacheSource, TableCacheSource};
use purge_exec::storage::{FpDir, StorageRoots};
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
        SharedTableCacheSource(std::sync::Arc::new(Self::new(store)))
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
    dir: FpDir,
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
