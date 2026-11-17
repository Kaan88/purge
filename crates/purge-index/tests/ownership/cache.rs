//! The table caches.

use std::path::Path;

use purge_index::ownership::{
    CACHE_SCHEMA, CacheKey, DiskTableCache, MAX_CACHE_FILE, MemTableCache, OwnershipIndex,
    OwnershipInput, TableCache,
};
use purge_model::FileTime;
use purge_source::fixture::Fixture;
use purge_source::metered::{Meter, MeteredSystem, Op};
use purge_source::sysobj::MsiTables;
use purge_source::types::FileTimes;

use crate::rows::{row, tables};
use crate::*;

const LP: &str = r"C:\Windows\Installer\1a.msi";

fn fixture(size: u64, mtime: u64) -> Fixture {
    let mut fx = base();
    fx.add_file(LP, size);
    fx.set_times(
        LP,
        FileTimes {
            created: None,
            modified: Some(FileTime(mtime)),
            accessed: None,
        },
    );
    fx.set_msi_tables(
        LP,
        tables(vec![row("r", 2, r"SOFTWARE\Cached", Some("V"), Some("1"))]),
    );
    fx
}

/// Builds with a metered system source and returns the index and the number of `msi_tables` calls.
fn metered_build(fx: &Fixture, cache: &dyn TableCache) -> (OwnershipIndex, u64) {
    let meter = Meter::new();
    let sys = MeteredSystem::new(fx, &meter);
    let products = [machine(P1, LP)];
    let ix = OwnershipIndex::build(&OwnershipInput {
        reg: fx,
        fs: fx,
        sys: &sys,
        products: &products,
        cache: Some(cache),
        threads: 2,
    });
    (ix, meter.snapshot().get(Op::SysMsiTables).calls)
}

#[test]
fn cache_hit_skips_msi_tables_call() {
    let fx = fixture(100, 133_000_000_000_000_000);
    let cache = MemTableCache::new();
    let (first, calls) = metered_build(&fx, &cache);
    assert_eq!(calls, 1);
    assert_eq!(first.stats().packages_read, 1);
    assert_eq!(cache.len(), 1);
    let (second, calls) = metered_build(&fx, &cache);
    assert_eq!(calls, 0, "a cache hit reads no package");
    assert_eq!(second.stats().packages_cached, 1);
    assert_eq!(second.stats().packages_read, 0);
    assert_eq!(second.key_owners(r"HKLM\SOFTWARE\Cached").len(), 1);
}

#[test]
fn cache_key_changes_with_size_or_mtime() {
    let cache = MemTableCache::new();
    let (_, calls) = metered_build(&fixture(100, 1_000), &cache);
    assert_eq!(calls, 1);
    let (_, calls) = metered_build(&fixture(101, 1_000), &cache);
    assert_eq!(calls, 1, "another size is another key");
    let (_, calls) = metered_build(&fixture(100, 1_001), &cache);
    assert_eq!(calls, 1, "another time is another key");
    let (_, calls) = metered_build(&fixture(100, 1_000), &cache);
    assert_eq!(calls, 0);
    assert_eq!(cache.len(), 3);
}

#[test]
fn truncated_tables_are_not_cached() {
    let mut fx = fixture(100, 5);
    let mut t = tables(Vec::new());
    t.truncated = true;
    fx.set_msi_tables(LP, t);
    let cache = MemTableCache::new();
    let (ix, _) = metered_build(&fx, &cache);
    assert_eq!(ix.unreadable().len(), 1);
    assert!(cache.is_empty());
}

fn key() -> CacheKey {
    CacheKey {
        local_package: LP.into(),
        size: 100,
        mtime: 7,
    }
}

/// A fixture that knows `dir` and says whether only administrators can write it.
fn fs_for(dir: &str, admin_only: bool) -> Fixture {
    let mut fx = Fixture::new();
    fx.add_dir(dir);
    fx.set_admin_only_writable(dir, admin_only);
    fx
}

fn open(dir: &TempDir) -> DiskTableCache {
    DiskTableCache::open(&dir.0, &fs_for(&dir.path_str(), true)).expect("admin-only dir")
}

fn sample() -> MsiTables {
    tables(vec![row("r", 2, r"SOFTWARE\Disk", Some("V"), Some("1"))])
}

#[test]
fn disk_cache_refused_when_dir_user_writable() {
    let dir = TempDir::new("refused");
    let path = dir.path_str();
    assert!(DiskTableCache::open(&dir.0, &fs_for(&path, false)).is_none());
    // An unknown directory (the source cannot say) is refused too.
    assert!(DiskTableCache::open(&dir.0, &Fixture::new()).is_none());
    assert!(DiskTableCache::open(&dir.0, &fs_for(&path, true)).is_some());
}

#[test]
fn disk_cache_round_trip() {
    let dir = TempDir::new("roundtrip");
    let cache = open(&dir);
    assert!(cache.get(&key()).is_none());
    cache.put(&key(), &sample());
    assert_eq!(cache.get(&key()), Some(sample()));
    let other = CacheKey { mtime: 8, ..key() };
    assert!(cache.get(&other).is_none());
    let file = dir.0.join(key().file_name());
    let text = std::fs::read_to_string(file).unwrap();
    assert!(text.contains(CACHE_SCHEMA));
}

fn write(dir: &Path, bytes: &[u8]) {
    std::fs::write(dir.join(key().file_name()), bytes).unwrap();
}

#[test]
fn disk_cache_corrupt_file_is_miss() {
    let dir = TempDir::new("corrupt");
    let cache = open(&dir);
    for bytes in [&b"{not json"[..], b"", b"null", &[0xff, 0xfe, 0x00][..]] {
        write(&dir.0, bytes);
        assert!(cache.get(&key()).is_none());
    }
    // Valid JSON for another key (a file renamed into place) is a miss as well.
    cache.put(&key(), &sample());
    let other = CacheKey { size: 1, ..key() };
    std::fs::rename(dir.0.join(key().file_name()), dir.0.join(other.file_name())).unwrap();
    assert!(cache.get(&other).is_none());
    // A build over a corrupt cache reads the package and works.
    write(&dir.0, b"garbage");
    let fx = fixture(100, 7);
    let meter = Meter::new();
    let sys = MeteredSystem::new(&fx, &meter);
    let products = [machine(P1, LP)];
    let ix = OwnershipIndex::build(&OwnershipInput {
        reg: &fx,
        fs: &fx,
        sys: &sys,
        products: &products,
        cache: Some(&cache),
        threads: 1,
    });
    assert_eq!(meter.snapshot().get(Op::SysMsiTables).calls, 1);
    assert_eq!(ix.key_owners(r"HKLM\SOFTWARE\Cached").len(), 1);
    assert!(ix.unreadable().is_empty());
}

#[test]
fn disk_cache_wrong_schema_is_miss() {
    let dir = TempDir::new("schema");
    let cache = open(&dir);
    cache.put(&key(), &sample());
    let good = std::fs::read_to_string(dir.0.join(key().file_name())).unwrap();
    let bad = good.replace(CACHE_SCHEMA, "purge.msitables/2");
    assert_ne!(good, bad);
    write(&dir.0, bad.as_bytes());
    assert!(cache.get(&key()).is_none());
    // An unknown member is refused as well.
    let extra = good.replacen('{', r#"{"extra":1,"#, 1);
    write(&dir.0, extra.as_bytes());
    assert!(cache.get(&key()).is_none());
}

#[test]
fn disk_cache_oversized_file_is_miss() {
    let dir = TempDir::new("oversized");
    let cache = open(&dir);
    cache.put(&key(), &sample());
    let good = std::fs::read(dir.0.join(key().file_name())).unwrap();
    // The same valid document, padded with whitespace past the cap.
    let mut big = good.clone();
    big.resize(usize::try_from(MAX_CACHE_FILE).unwrap() + 1, b' ');
    write(&dir.0, &big);
    assert!(cache.get(&key()).is_none());
    // Exactly at the cap it is read.
    big.truncate(usize::try_from(MAX_CACHE_FILE).unwrap());
    write(&dir.0, &big);
    assert_eq!(cache.get(&key()), Some(sample()));
}
