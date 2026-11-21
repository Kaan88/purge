//! The M1b steps add no whole-registry walk: every key a harvest walks is in the reference scan's
//! scope, or in the Windows Installer component registrations the ownership index reads.

use std::sync::Mutex;

use purge_index::ownership::USERDATA;
use purge_index::refscan::Scope;
use purge_source::registry::{KeyWalker, RegistrySource};
use purge_source::types::{KeyInfo, RegData, RegValue, SourceResult};

use super::msi::ZIP;
use super::*;

/// A registry that records every key its walkers enter.
struct Recording<'a> {
    inner: &'a Fixture,
    entered: Mutex<Vec<String>>,
}

struct RecordingWalker<'a> {
    inner: Box<dyn KeyWalker + 'a>,
    entered: &'a Mutex<Vec<String>>,
}

impl KeyWalker for RecordingWalker<'_> {
    fn enter(&mut self, key: &str) -> SourceResult<KeyInfo> {
        self.entered.lock().unwrap().push(key.to_owned());
        self.inner.enter(key)
    }

    fn values(&mut self) -> SourceResult<Vec<RegValue>> {
        self.inner.values()
    }

    fn subkeys(&mut self) -> SourceResult<Vec<String>> {
        self.inner.subkeys()
    }
}

impl RegistrySource for Recording<'_> {
    fn key_info(&self, key: &str) -> SourceResult<KeyInfo> {
        self.inner.key_info(key)
    }

    fn subkeys(&self, key: &str) -> SourceResult<Vec<String>> {
        self.inner.subkeys(key)
    }

    fn values(&self, key: &str) -> SourceResult<Vec<RegValue>> {
        RegistrySource::values(self.inner, key)
    }

    fn value(&self, key: &str, name: &str) -> SourceResult<RegData> {
        self.inner.value(key, name)
    }

    fn loaded_user_sids(&self) -> SourceResult<Vec<String>> {
        self.inner.loaded_user_sids()
    }

    fn current_control_set(&self) -> SourceResult<u32> {
        self.inner.current_control_set()
    }

    fn walker(&self) -> Box<dyn KeyWalker + '_> {
        Box::new(RecordingWalker {
            inner: self.inner.walker(),
            entered: &self.entered,
        })
    }
}

fn under(key: &str, root: &str) -> bool {
    let (k, r) = (key.to_ascii_lowercase(), root.to_ascii_lowercase());
    k == r || k.starts_with(&format!("{r}\\"))
}

#[test]
fn harvest_adds_no_walk() {
    let f = super::msi::seven_zip_fixture();
    let rec = Recording {
        inner: &f,
        entered: Mutex::new(Vec::new()),
    };
    let doc = inventory_of(&f);
    let entry = doc
        .entries
        .iter()
        .find(|e| e.product_code.as_deref() == Some(ZIP))
        .unwrap();
    let sources = Sources {
        reg: &rec,
        fs: &f,
        sys: &f,
    };
    let report = harvest_report_with(
        entry,
        &doc,
        sources,
        purge_index::baseline_view::BaselineView::empty(),
        Kb::shipped(),
        &HarvestOpts::default(),
    );
    assert!(!report.fingerprint.roots.is_empty());

    let scope = Scope::for_sids(&f, &[SID]).unwrap();
    let entered = rec.entered.into_inner().unwrap();
    assert!(!entered.is_empty(), "the reference scan walks");
    let stray: Vec<&String> = entered
        .iter()
        .filter(|k| !scope.contains(k) && !under(k, USERDATA))
        .collect();
    assert!(stray.is_empty(), "walked outside the scope: {stray:?}");
    // Below `UserData`, only the component registrations.
    let stray: Vec<&String> = entered
        .iter()
        .filter(|k| under(k, USERDATA))
        .filter(|k| {
            let rest = &k[USERDATA.len()..];
            let segs: Vec<&str> = rest.split('\\').filter(|s| !s.is_empty()).collect();
            segs.len() > 1 && !segs[1].eq_ignore_ascii_case("Components")
        })
        .collect();
    assert!(stray.is_empty(), "walked outside the components: {stray:?}");
}
