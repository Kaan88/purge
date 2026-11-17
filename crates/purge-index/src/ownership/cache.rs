//! Caches of MSI tables for the ownership index (M1b, contract C-OWNERSHIP).
//!
//! Reading every installed product's cached package is the slow part of the index, so the tables are
//! cached by ([`CacheKey`]) the package's canonical path, size and modification time, as read from the
//! file system when the index is built. A changed package has another key and is read again.
//!
//! Two caches implement [`TableCache`]:
//! - [`MemTableCache`]: in memory, for tests and unelevated runs.
//! - [`DiskTableCache`]: one JSON file per key in a directory that only administrators can write. A cache
//!   a standard user could write could remove blocks (tables with the rows of another product left out),
//!   so [`DiskTableCache::open`] refuses any other directory. A file that cannot be read, is larger than
//!   [`MAX_CACHE_FILE`], does not parse, has another schema than [`CACHE_SCHEMA`] or another key is a miss:
//!   never an error and never partial data.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use purge_guard::prefix::fold;
use purge_source::filesystem::FileSystemSource;
use purge_source::sysobj::MsiTables;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The `schema` of a cache file.
pub const CACHE_SCHEMA: &str = "purge.msitables/1";

/// The largest cache file read or written, in bytes.
pub const MAX_CACHE_FILE: u64 = 16 * 1024 * 1024;

/// Where a package's tables are cached.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheKey {
    /// The package's canonical path (`LocalPackage`).
    pub local_package: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its last-write time (`FILETIME`).
    pub mtime: u64,
}

impl CacheKey {
    /// The identity the caches compare: the folded path, the size and the time.
    fn id(&self) -> String {
        format!("{}|{}|{}", fold(&self.local_package), self.size, self.mtime)
    }

    /// The name of the key's cache file: the SHA-256 of its identity, in lower-case hex, with `.json`.
    pub fn file_name(&self) -> String {
        let digest = Sha256::digest(self.id().as_bytes());
        let mut name = String::with_capacity(69);
        for b in digest {
            name.push_str(&format!("{b:02x}"));
        }
        name.push_str(".json");
        name
    }

    /// The same package, size and time (the path compared without regard to case).
    pub fn same(&self, other: &CacheKey) -> bool {
        self.id() == other.id()
    }
}

/// A cache of MSI tables, shared by the index's reader threads.
pub trait TableCache: Sync {
    /// The tables cached under `key`, if any.
    fn get(&self, key: &CacheKey) -> Option<MsiTables>;
    /// Caches `tables` under `key`. Failing to store is silent: the next run reads the package again.
    fn put(&self, key: &CacheKey, tables: &MsiTables);
}

/// An in-memory [`TableCache`].
#[derive(Debug, Default)]
pub struct MemTableCache {
    map: Mutex<HashMap<String, MsiTables>>,
}

impl MemTableCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of cached packages.
    pub fn len(&self) -> usize {
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl TableCache for MemTableCache {
    fn get(&self, key: &CacheKey) -> Option<MsiTables> {
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key.id())
            .cloned()
    }

    fn put(&self, key: &CacheKey, tables: &MsiTables) {
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.id(), tables.clone());
    }
}

/// A cache file as written.
#[derive(Serialize)]
struct CacheFileOut<'a> {
    schema: &'a str,
    key: &'a CacheKey,
    tables: &'a MsiTables,
}

/// A cache file as read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheFileIn {
    schema: String,
    key: CacheKey,
    tables: MsiTables,
}

/// A [`TableCache`] of one JSON file per key in an admin-only directory.
#[derive(Debug)]
pub struct DiskTableCache {
    dir: PathBuf,
}

/// Distinguishes the temporary files of concurrent writers in one process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl DiskTableCache {
    /// A cache in `dir`, or `None` unless `fs` says that only administrators (and the system) can write
    /// `dir` and every ancestor. An error from `fs` (the directory missing, access denied, a path that is
    /// not UTF-8) is `None` as well. The directory is not created here.
    pub fn open(dir: &Path, fs: &dyn FileSystemSource) -> Option<DiskTableCache> {
        let path = dir.to_str()?;
        match fs.is_admin_only_writable(path) {
            Ok(true) => Some(DiskTableCache {
                dir: dir.to_path_buf(),
            }),
            _ => None,
        }
    }

    /// The cache directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn file(&self, key: &CacheKey) -> PathBuf {
        self.dir.join(key.file_name())
    }

    fn read(&self, key: &CacheKey) -> Option<MsiTables> {
        let file = fs::File::open(self.file(key)).ok()?;
        if file.metadata().ok()?.len() > MAX_CACHE_FILE {
            return None;
        }
        let mut bytes = Vec::new();
        file.take(MAX_CACHE_FILE + 1).read_to_end(&mut bytes).ok()?;
        if bytes.len() as u64 > MAX_CACHE_FILE {
            return None;
        }
        let parsed: CacheFileIn = serde_json::from_slice(&bytes).ok()?;
        if parsed.schema != CACHE_SCHEMA || !parsed.key.same(key) {
            return None;
        }
        // The limits every source enforces hold for cached tables too.
        Some(parsed.tables.limited())
    }

    fn write(&self, key: &CacheKey, tables: &MsiTables) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(&CacheFileOut {
            schema: CACHE_SCHEMA,
            key,
            tables,
        })?;
        if bytes.len() as u64 > MAX_CACHE_FILE {
            return Ok(());
        }
        let target = self.file(key);
        let temp = self.dir.join(format!(
            "{}.{}.{}.tmp",
            key.file_name(),
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut file = fs::File::create_new(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp, &target)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

impl TableCache for DiskTableCache {
    fn get(&self, key: &CacheKey) -> Option<MsiTables> {
        self.read(key)
    }

    fn put(&self, key: &CacheKey, tables: &MsiTables) {
        let _ = self.write(key, tables);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(path: &str, size: u64, mtime: u64) -> CacheKey {
        CacheKey {
            local_package: path.into(),
            size,
            mtime,
        }
    }

    #[test]
    fn file_name_is_sha256_hex_of_the_folded_identity() {
        let a = key(r"C:\Windows\Installer\1a.msi", 10, 20);
        let b = key(r"c:\windows\installer\1A.MSI", 10, 20);
        assert_eq!(a.file_name(), b.file_name());
        assert!(a.same(&b));
        let name = a.file_name();
        assert_eq!(name.len(), 64 + 5);
        assert!(
            name[..64]
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(
            a.file_name(),
            key(r"C:\Windows\Installer\1a.msi", 11, 20).file_name()
        );
        assert_ne!(
            a.file_name(),
            key(r"C:\Windows\Installer\1a.msi", 10, 21).file_name()
        );
    }

    #[test]
    fn memory_cache_round_trip() {
        let cache = MemTableCache::new();
        let k = key(r"C:\Windows\Installer\1a.msi", 1, 2);
        assert!(cache.get(&k).is_none());
        let tables = MsiTables {
            custom_action_count: 4,
            ..MsiTables::default()
        };
        cache.put(&k, &tables);
        assert_eq!(cache.get(&k), Some(tables));
        assert!(
            cache
                .get(&key(r"C:\Windows\Installer\1a.msi", 1, 3))
                .is_none()
        );
        assert_eq!(cache.len(), 1);
    }
}
