//! The real VS Code rig run (ignored unless `PURGE_RUNS_DIR` is set, e.g. to `vm/runs`).
//!
//! The fingerprint inputs are rebuilt from the post-install snapshot `snap-vscode-1` the way the harvest
//! journals them (P = the `VSCode*` ProgIDs, one journal entry per `.ext` with a value of P in
//! `OpenWithProgids`). CLS-ASSOC then scans the post-uninstall snapshot `snap-vscode-2` with the shipped
//! baseline of the rig image, and the test reports how many of the skeleton keys of the frozen truth
//! (`vm/truth/frozen/vscode/truth.json`: leftover `.ext` and `.ext\OpenWithProgids` keys) are covered by
//! key candidates carrying `ProvenOwnedSkeleton`. Every truth key that is absent from the baseline must
//! be covered.

use std::path::{Path, PathBuf};

use purge_guard::prefix;
use purge_index::baseline::Baseline;
use purge_model::{Candidate, EvidenceKind, ExtJournalEntry, Target};
use purge_scan::cls_assoc::ClsAssoc;
use purge_source::fixture::Fixture;
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;

use crate::world::{CLASSES, World, fingerprint};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn load_snap(dir: &Path, n: u32) -> Fixture {
    let snap = dir.join(format!("snap-vscode-{n}.tsv.gz"));
    let lists = dir.join(format!("lists-vscode-{n}.json"));
    Fixture::from_snap(&snap, lists.is_file().then_some(lists.as_path()), None)
        .unwrap_or_else(|e| panic!("cannot load {}: {e:?}", snap.display()))
}

/// The leftover `RegKey` targets of a truth file. The file is pretty-printed JSON with one field per
/// line, which is all this reader relies on (the crate has no JSON dependency).
fn truth_leftover_keys(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let field = |line: &str, name: &str| -> Option<String> {
        let rest = line.trim().strip_prefix(&format!("\"{name}\": \""))?;
        let raw = rest.trim_end_matches(',').strip_suffix('"')?;
        Some(raw.replace("\\\\", "\\"))
    };
    let (mut ty, mut key, mut out) = (String::new(), String::new(), Vec::new());
    for line in text.lines() {
        if let Some(v) = field(line, "type") {
            ty = v;
        } else if let Some(v) = field(line, "path") {
            key = v;
        } else if let Some(label) = field(line, "label") {
            if label == "leftover" && ty == "RegKey" {
                out.push(std::mem::take(&mut key));
            }
            ty.clear();
        }
    }
    out
}

/// Whether a truth key is an association skeleton: `<Classes>\<.ext>` or its `OpenWithProgids`.
fn is_skeleton_key(key: &str) -> bool {
    let Some(rest) = prefix::strip_prefix(key, CLASSES) else {
        return false;
    };
    let mut segs = prefix::segments(rest);
    match (segs.next(), segs.next(), segs.next()) {
        (Some(ext), None, _) => ext.starts_with('.'),
        (Some(ext), Some(sub), None) => {
            ext.starts_with('.') && prefix::eq_ci(sub, "OpenWithProgids")
        }
        _ => false,
    }
}

/// The journal the harvest would have written from the post-install snapshot.
fn journal_from(snap: &Fixture, progids: &[String]) -> Vec<ExtJournalEntry> {
    let in_p = |name: &str| progids.iter().any(|p| prefix::eq_ci(p, name));
    let mut out = Vec::new();
    for ext in snap.subkeys(CLASSES).expect("the Classes root is captured") {
        if !ext.starts_with('.') {
            continue;
        }
        let key = format!(r"{CLASSES}\{ext}");
        let owp = snap
            .values(&format!(r"{key}\OpenWithProgids"))
            .unwrap_or_default();
        let (ours, others): (Vec<String>, Vec<String>) =
            owp.into_iter().map(|v| v.name).partition(|name| in_p(name));
        if ours.is_empty() {
            continue;
        }
        let values = snap.values(&key).unwrap_or_default();
        let subkeys = snap.subkeys(&key).unwrap_or_default();
        out.push(ExtJournalEntry {
            ext: ext.clone(),
            key,
            openwith_ours: ours,
            openwith_others: others,
            subkey_count: u32::try_from(subkeys.len()).unwrap(),
            default: values
                .iter()
                .find(|v| v.name.is_empty())
                .and_then(|v| v.data.string()),
            previous_default: None,
            other_values: values
                .iter()
                .filter(|v| !v.name.is_empty())
                .map(|v| v.name.clone())
                .collect(),
            other_subkeys: subkeys
                .into_iter()
                .filter(|s| !prefix::eq_ci(s, "OpenWithProgids"))
                .collect(),
            ti_owned: false,
            vendor_backup: None,
            file_exts_key: None,
            toast_values: Vec::new(),
        });
    }
    out
}

fn covers(candidates: &[&Candidate], key: &str) -> bool {
    candidates.iter().any(|c| match &c.target {
        Target::RegKey { path } => prefix::is_same_or_inside(key, path),
        _ => false,
    })
}

#[test]
#[ignore = "needs PURGE_RUNS_DIR with the vscode run"]
fn real_vscode_skeletons_are_covered() {
    let Some(runs) = std::env::var_os("PURGE_RUNS_DIR") else {
        eprintln!("PURGE_RUNS_DIR not set; skipping");
        return;
    };
    let dir = Path::new(&runs).join("vscode");
    let installed = load_snap(&dir, 1);
    let after = load_snap(&dir, 2);

    // P: the ProgIDs VS Code registers. All of them are named `VSCode…`.
    let progids: Vec<String> = installed
        .subkeys(CLASSES)
        .expect("the Classes root is captured")
        .into_iter()
        .filter(|name| prefix::fold(name).starts_with("vscode"))
        .collect();
    let progid_refs: Vec<&str> = progids.iter().map(String::as_str).collect();
    let mut fp = fingerprint(&progid_refs);
    fp.os = after.os_info().expect("the snapshot records the OS");
    fp.user_sid = after.user_sid().expect("the snapshot records the user");
    fp.ext_journal = journal_from(&installed, &progids);
    let journalled = fp.ext_journal.len();

    let baseline = Baseline::select(
        &repo_root().join("kb").join("baselines"),
        &fp.os.edition,
        fp.os.build,
        fp.os.ubr,
    )
    .expect("a baseline for the rig image is shipped");

    let mut world = World::new(after, fp);
    world.baseline = Some(purge_index::baseline_view::BaselineView::exact(baseline));
    let out = world.scan(&ClsAssoc);

    let proven: Vec<&Candidate> = out
        .iter()
        .filter(|c| {
            matches!(c.target, Target::RegKey { .. })
                && c.blockers.is_empty()
                && c.evidence
                    .iter()
                    .any(|e| e.kind == EvidenceKind::ProvenOwnedSkeleton)
        })
        .collect();
    let values = out
        .iter()
        .filter(|c| matches!(c.target, Target::RegValue { .. }))
        .count();

    let truth = truth_leftover_keys(
        &repo_root()
            .join("vm")
            .join("truth")
            .join("frozen")
            .join("vscode")
            .join("truth.json"),
    );
    let skeletons: Vec<&String> = truth.iter().filter(|k| is_skeleton_key(k)).collect();
    let baseline = world.baseline.as_ref().unwrap();
    let (mut covered, mut missed_new, mut in_baseline) = (0, Vec::new(), 0);
    for key in &skeletons {
        if covers(&proven, key) {
            covered += 1;
        } else if baseline.has_key(key) {
            in_baseline += 1;
        } else {
            missed_new.push(key.as_str());
        }
    }
    eprintln!(
        "P: {} ProgIDs; journal: {journalled} extensions; candidates: {} ({} proven keys, {values} values)",
        progids.len(),
        out.len(),
        proven.len(),
    );
    eprintln!(
        "truth skeleton keys: {}; covered by ProvenOwnedSkeleton keys: {covered}; uncovered and in the \
         baseline: {in_baseline}; uncovered and absent from the baseline: {}",
        skeletons.len(),
        missed_new.len()
    );
    for key in &missed_new {
        eprintln!("  not covered: {key}");
    }
    // Precision: a proven key that the truth does not list is a key the uninstall did not leave behind
    // as the app's (or that existed before the install).
    let extra: Vec<&Target> = proven
        .iter()
        .map(|c| &c.target)
        .filter(|t| match t {
            Target::RegKey { path } => !truth.iter().any(|k| prefix::is_same(k, path)),
            _ => true,
        })
        .collect();
    for target in &extra {
        eprintln!("  proven but not in the truth: {target:?}");
    }
    assert!(!skeletons.is_empty(), "the truth lists skeleton keys");
    assert!(
        missed_new.is_empty(),
        "skeleton keys absent from the baseline are all covered"
    );
    assert!(extra.is_empty(), "no proven key outside the truth");
}
