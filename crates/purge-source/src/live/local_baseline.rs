//! [`LiveLocal`]: the [`LocalSources`] of the running machine (BASELINE_LOCAL_DESIGN.md §3.1).
//!
//! S1 lists `%SystemRoot%\WinSxS\Manifests` once and reads each file by path through [`LiveFileSystem`];
//! S2 opens the default profile's `NTUSER.DAT` with `purge-win` `offreg` (a read-only handle parsed in
//! this process, never mounted; transaction logs are not replayed); S3 walks `HKU\.DEFAULT` through
//! [`LiveRegistry`]; S4 lists packages through `purge-win` `appx` ([`LiveSystem`], machine-wide when
//! elevated) and reads each inbox package's `AppxManifest.xml` by path. Nothing here writes.

use std::path::Path;

use purge_win::offreg::{HiveItem, HiveLimits, OfflineHive, OffregError};

use super::{LiveFileSystem, LiveRegistry, LiveSystem};
use crate::local_baseline::{
    HiveEntry, HiveWalk, InboxPackages, LocalSources, MAX_WALK_DEPTH, MAX_WALK_KEYS, ManifestIter,
    SYSTEM_DEFAULT_KEY, collect_inbox_packages, default_hive_path, list_manifests, walk_registry,
};
use crate::types::{SourceError, SourceResult};

/// The local sources of this machine.
#[derive(Debug, Default)]
pub struct LiveLocal {
    /// The registry (S3, the profile list, the provisioned list, the package repository).
    pub registry: LiveRegistry,
    /// The filesystem (S1 files, S4 manifests).
    pub fs: LiveFileSystem,
    /// Machine facts (`%SystemRoot%`, the package list, elevation).
    pub system: LiveSystem,
}

impl LiveLocal {
    /// Local sources of the running machine.
    pub fn new() -> Self {
        Self::default()
    }
}

/// An offreg error in the source vocabulary.
fn map_offreg(e: OffregError) -> SourceError {
    match e {
        OffregError::Unavailable(w) => SourceError::Other(w.0),
        OffregError::Open(w) | OffregError::Read { error: w, .. } => {
            if w.is_not_found() {
                SourceError::NotFound
            } else if w.is_access_denied() {
                SourceError::AccessDenied
            } else {
                SourceError::Other(w.0)
            }
        }
    }
}

impl LocalSources for LiveLocal {
    fn manifests(&self) -> SourceResult<ManifestIter<'_>> {
        list_manifests(&self.fs, &self.system)
    }

    fn default_hive(&self, visit: &mut dyn FnMut(HiveEntry<'_>)) -> SourceResult<HiveWalk> {
        let path = default_hive_path(&self.registry, &self.system)?;
        let hive = OfflineHive::open(Path::new(&path)).map_err(map_offreg)?;
        let limits = HiveLimits {
            max_depth: MAX_WALK_DEPTH,
            max_keys: MAX_WALK_KEYS,
        };
        let summary = hive
            .walk(limits, |item| match item {
                HiveItem::Key { path } => visit(HiveEntry::Key { path }),
                HiveItem::Value { key, name, kind } => visit(HiveEntry::Value { key, name, kind }),
            })
            .map_err(map_offreg)?;
        Ok(HiveWalk {
            origin: path,
            keys: summary.keys,
            values: summary.values,
            capped: !summary.is_complete(),
            ..HiveWalk::default()
        })
    }

    fn system_default(&self, visit: &mut dyn FnMut(HiveEntry<'_>)) -> SourceResult<HiveWalk> {
        walk_registry(&self.registry, SYSTEM_DEFAULT_KEY, visit)
    }

    fn inbox_packages(&self) -> SourceResult<InboxPackages> {
        collect_inbox_packages(&self.registry, &self.fs, &self.system)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::local_baseline::InboxReason;

    /// win-unit, read only, no elevation needed: every live source returns data.
    #[test]
    fn live_sources_return_data() {
        let local = LiveLocal::new();

        let t = Instant::now();
        let path = default_hive_path(&local.registry, &local.system).expect("default hive path");
        let (mut keys, mut values) = (0u64, 0u64);
        let s2 = local
            .default_hive(&mut |e| match e {
                HiveEntry::Key { .. } => keys += 1,
                HiveEntry::Value { .. } => values += 1,
            })
            .expect("S2");
        eprintln!("S2 {path}: {s2:?} in {:?}", t.elapsed());
        assert!(s2.is_complete() && s2.keys == keys && s2.values == values);
        assert!(s2.keys > 100, "{s2:?}");

        let t = Instant::now();
        let mut keys = 0u64;
        let s3 = local
            .system_default(&mut |e| keys += matches!(e, HiveEntry::Key { .. }) as u64)
            .expect("S3");
        eprintln!("S3: {s3:?} in {:?}", t.elapsed());
        assert!(s3.keys > 100 && s3.keys == keys, "{s3:?}");

        let t = Instant::now();
        let s4 = local.inbox_packages().expect("S4");
        let read = s4.packages.iter().filter(|p| p.manifest.is_ok()).count();
        let prog_ids: usize = s4
            .packages
            .iter()
            .map(|p| p.repository_prog_ids.len())
            .sum();
        let system = s4
            .packages
            .iter()
            .filter(|p| p.reason == InboxReason::System)
            .count();
        eprintln!(
            "S4: {} inbox ({system} System), {read} manifests read, {prog_ids} repository ProgIDs, {} not inbox, machine-wide {}, provisioned {:?}, repository {:?} in {:?}",
            s4.packages.len(),
            s4.not_inbox,
            s4.machine_wide,
            s4.provisioned,
            s4.repository,
            t.elapsed()
        );
        for p in s4.packages.iter().filter(|p| p.manifest.is_err()) {
            eprintln!("  unreadable: {} {:?}", p.full_name, p.manifest);
        }
        assert!(read > 0 && s4.repository.is_ok());

        let t = Instant::now();
        let mut n = 0usize;
        let mut bytes = 0usize;
        let mut failed = 0usize;
        for (_, read) in local.manifests().expect("S1 listing") {
            n += 1;
            match read() {
                Ok(b) => bytes += b.len(),
                Err(_) => failed += 1,
            }
            if n >= 500 {
                break;
            }
        }
        eprintln!(
            "S1: first {n} manifests, {bytes} bytes, {failed} unreadable, in {:?}",
            t.elapsed()
        );
        assert!(n > 0 && failed == 0);
    }
}
