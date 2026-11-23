//! Tests of the consent view model and the pages (M3-CONSENT). Pure: no dialog is shown. What the Win32
//! layer does with the pages (paging, gating, the arming delay, the cursor's monitor) is VM work.

use purge_exec::expiry::{ExpiringBackup, ExpiringItem, ExpiryId};
use purge_exec::plan_in::{
    BoundPlan, ExecRequest, ExecSettings, Selection, bind, confirm_hash, selection_hash,
};
use purge_inventory::quiet::QuietCommand;
use purge_model::exec::op::OpId;
use purge_model::{
    Action, AppRef, Band, Blocker, Candidate, CandidateId, Category, Decision, FileTime, Harm,
    InstallerKind, Origin, Reversibility, ScanMode, Target, Tool,
};
use purge_plan::emit::{ScanDoc, ScanSchema};
use purge_rpc::methods::{ConfirmCode, RestorePoint};
use purge_win::taskdialog::{self, Icon as DialogIcon};

use super::dialog::{self, PRIMARY};
use super::text::{LINE_COST, Stamp};
use super::view::{
    ConflictKind, ConsentView, DELETE_AFTER_NOTE, DELETE_BACKUPS_NOW_WARNING,
    DELETE_BACKUPS_NOW_WARNING_ONE, DELETE_NOW_WARNING, DELETE_NOW_WARNING_ONE, Facts, OTHER_SHOWN,
    PAGE_CHARS, PAGE_ENTRIES, PurgeUnit, Reason, RecoverFacts, RecoverKind, RestoreFacts,
    UninstallFacts, Variant, ViewError, split_purge, view, view_delete_backups_now,
    view_delete_backups_now_user_data, view_delete_now, view_delete_now_user_data, view_purge,
    view_purge_user_data, view_recover, view_restore, view_uninstall,
};

// ---------------------------------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------------------------------

fn cid(id: &str) -> CandidateId {
    CandidateId(id.to_owned())
}

fn path(p: &str) -> Target {
    Target::Path { path: p.to_owned() }
}

fn key(p: &str) -> Target {
    Target::RegKey { path: p.to_owned() }
}

struct Spec {
    id: String,
    target: Target,
    action: Action,
    band: Band,
    preselected: bool,
    category: Category,
    size: Option<u64>,
    children: Vec<String>,
    blockers: Vec<Blocker>,
}

impl Spec {
    fn safe(id: &str, target: Target, action: Action) -> Spec {
        Spec {
            id: id.to_owned(),
            target,
            action,
            band: Band::Safe,
            preselected: true,
            category: Category::AppFiles,
            size: None,
            children: Vec::new(),
            blockers: Vec::new(),
        }
    }

    fn file(id: &str, p: &str) -> Spec {
        Spec::safe(id, path(p), Action::Quarantine)
    }

    fn user_data(id: &str, p: &str) -> Spec {
        Spec {
            band: Band::Likely,
            preselected: false,
            category: Category::UserData,
            ..Spec::file(id, p)
        }
    }

    fn category(mut self, c: Category) -> Spec {
        self.category = c;
        self
    }

    fn size(mut self, n: u64) -> Spec {
        self.size = Some(n);
        self
    }

    fn ticked(mut self, band: Band) -> Spec {
        self.band = band;
        self.preselected = false;
        self
    }

    fn with_children(mut self, kids: &[&str]) -> Spec {
        self.children = kids.iter().map(|k| (*k).to_owned()).collect();
        self
    }

    fn blocker(mut self, blocker: Blocker) -> Spec {
        self.blockers.push(blocker);
        self
    }

    fn build(self) -> Candidate {
        Candidate {
            id: cid(&self.id),
            target: self.target,
            action: self.action,
            owner: AppRef {
                program_id: "HKLM|64|VendorApp".parse().unwrap(),
                display_name: "Vendor App".into(),
            },
            origin: Origin::Scanner,
            scanner: "TEST".into(),
            category: self.category,
            evidence: Vec::new(),
            blockers: self.blockers,
            harm: Harm::Low,
            reversibility: Reversibility::Full,
            children: self.children.iter().map(|c| cid(c)).collect(),
            size_bytes: self.size,
            child_count: None,
            item_fp: None,
            object_fp: None,
            display_name: None,
            owner_program: None,
            decision: Some(Decision {
                band: self.band,
                preselected: self.preselected,
                score: 9,
                explanation: "test".into(),
            }),
        }
    }
}

fn scan_doc(items: Vec<Candidate>, absorbed: Vec<Candidate>) -> ScanDoc {
    let mut scan = ScanDoc {
        schema: ScanSchema,
        app: "vendor-app".into(),
        tool: Tool::Purge,
        mode: ScanMode::Post,
        policy_version: "m1a.6".into(),
        plan_hash: String::new(),
        items,
        absorbed,
    };
    scan.plan_hash = purge_plan::hash::plan_hash(&scan.items, &scan.policy_version, scan.mode);
    scan
}

/// A bound plan over `specs` (all of them selected, whatever their band) and `absorbed`.
fn plan_with(specs: Vec<Spec>, absorbed: Vec<Spec>) -> BoundPlan {
    plan_full(specs, absorbed, true)
}

fn plan_full(specs: Vec<Spec>, absorbed: Vec<Spec>, allow_irreversible: bool) -> BoundPlan {
    let items: Vec<Candidate> = specs.into_iter().map(Spec::build).collect();
    let absorbed: Vec<Candidate> = absorbed.into_iter().map(Spec::build).collect();
    let ids: Vec<CandidateId> = items.iter().map(|c| c.id.clone()).collect();
    let scan = scan_doc(items, absorbed);
    let confirm = confirm_hash(scan.plan_hash.parse().unwrap(), selection_hash(&ids)).to_string();
    bind(&ExecRequest {
        scan,
        confirm,
        selection: Selection::Ids(ids),
        allow_irreversible,
        settings: ExecSettings::default(),
    })
    .expect("the fixture plan binds")
}

fn plan(specs: Vec<Spec>) -> BoundPlan {
    plan_with(specs, Vec::new())
}

/// A bound plan over `specs` and `absorbed` that selects only `chosen` (candidate ids).
fn plan_selecting(specs: Vec<Spec>, absorbed: Vec<Spec>, chosen: &[&str]) -> BoundPlan {
    let items: Vec<Candidate> = specs.into_iter().map(Spec::build).collect();
    let absorbed: Vec<Candidate> = absorbed.into_iter().map(Spec::build).collect();
    let ids: Vec<CandidateId> = chosen.iter().map(|id| cid(id)).collect();
    let scan = scan_doc(items, absorbed);
    let confirm = confirm_hash(scan.plan_hash.parse().unwrap(), selection_hash(&ids)).to_string();
    bind(&ExecRequest {
        scan,
        confirm,
        selection: Selection::Ids(ids),
        allow_irreversible: false,
        settings: ExecSettings::default(),
    })
    .expect("the fixture plan binds")
}

fn facts() -> Facts {
    Facts {
        delete_after: false,
        app_name: "Mozilla Firefox".into(),
        restorable_until: Some(Stamp {
            year: 2026,
            month: 12,
            day: 21,
            hour: 0,
            minute: 0,
        }),
        restore_point: false,
    }
}

/// A registry value of the Vendor key: `bind` compares every pair of selected paths, which is slow for
/// thousands of file items in a debug build and quick for values.
fn value_spec(i: usize) -> Spec {
    Spec::safe(
        &format!("c-{i:05}"),
        Target::RegValue {
            path: r"HKLM\SOFTWARE\Vendor".into(),
            name: format!("Item{i:05}"),
        },
        Action::DeleteValue,
    )
    .category(Category::Registration)
}

fn user_data_plan(n: usize) -> BoundPlan {
    plan(
        (0..n)
            .map(|i| value_spec(i).category(Category::UserData))
            .collect(),
    )
}

/// Every line of text the view puts in front of the user.
fn every_line(v: &ConsentView) -> Vec<&str> {
    let mut out: Vec<&str> = vec![&v.instruction, &v.button, &v.footer];
    out.extend(v.summary.iter().map(String::as_str));
    out.extend(v.attention.iter().map(|e| e.text.as_str()));
    out.extend(v.others.iter().map(|e| e.text.as_str()));
    out.extend(v.others_more.as_deref());
    out.extend(v.verification.as_deref());
    out
}

/// Characters that must never reach the dialog: controls (a line break is the separator between
/// lines, never inside one), bidirectional and other invisible characters.
fn assert_clean(line: &str) {
    for c in line.chars() {
        let u = c as u32;
        let bad = c.is_control()
            || matches!(u, 0x200B..=0x200F | 0x2028..=0x202F | 0x2060..=0x206F | 0xFEFF)
            || (c.is_whitespace() && c != ' ');
        assert!(!bad, "{c:?} reaches the dialog in {line:?}");
    }
}

fn ids(entries: &[super::view::Entry]) -> Vec<&str> {
    entries.iter().map(|e| e.id.as_str()).collect()
}

fn entry<'a>(v: &'a ConsentView, id: &str) -> &'a super::view::Entry {
    v.attention
        .iter()
        .chain(&v.others)
        .find(|e| e.id == id)
        .unwrap_or_else(|| panic!("{id} is in neither list"))
}

// ---------------------------------------------------------------------------------------------------
// Counts, attention, text
// ---------------------------------------------------------------------------------------------------

fn mixed_plan() -> BoundPlan {
    plan(vec![
        Spec::file("c1", r"C:\Program Files\Vendor").size(5 << 20),
        Spec::safe("c2", key(r"HKLM\SOFTWARE\Vendor"), Action::DeleteKey)
            .category(Category::Registration),
        Spec::user_data("c3", r"C:\Users\u\Documents\Vendor").size(3 << 20),
        Spec::file("c4", r"C:\Users\u\AppData\Local\Vendor\cache")
            .category(Category::Cache)
            .size(2 << 30),
        Spec::safe("c5", key(r"HKLM\SOFTWARE\Classes\.vnd"), Action::DeleteKey)
            .category(Category::Association),
        Spec::safe(
            "c6",
            Target::RegValue {
                path: r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run"
                    .into(),
                name: "Vendor Updater".into(),
            },
            Action::DeleteValue,
        )
        .category(Category::Startup),
        Spec::safe(
            "c7",
            Target::AppxPackage {
                full_name: "Vendor.App_1.0.0.0_x64__abcdefghijklm".into(),
            },
            Action::RemovePackage,
        )
        .category(Category::Package),
        Spec::file("c8", r"C:\Tools\ticked").ticked(Band::Weak),
    ])
}

#[test]
fn counts_groups_and_the_attention_set_of_a_mixed_plan() {
    let v = view(&mixed_plan(), &facts()).unwrap();
    let c = &v.counts;
    assert_eq!(
        (c.items, c.skipped, c.chosen, c.ticked, c.irreversible),
        (8, 0, 6, 2, 1)
    );
    let groups: Vec<(&str, u32)> = c
        .groups
        .iter()
        .map(|g| (g.group.label(), g.items))
        .collect();
    assert_eq!(
        groups,
        [
            ("files and folders", 4),
            ("registry keys and values", 2),
            ("file and protocol associations", 1),
            ("packages", 1),
        ]
    );
    assert_eq!(c.groups[0].bytes, (5 << 20) + (3 << 20) + (2 << 30));

    // Exactly user data, ticked, over 1 GB and no-undo items, in plan order; the rest are others.
    assert_eq!(ids(&v.attention), ["c3", "c4", "c7", "c8"]);
    assert_eq!(ids(&v.others), ["c1", "c2", "c5", "c6"]);
    assert_eq!(
        v.attention[0].reasons,
        [Reason::UserData, Reason::NotChosen]
    );
    assert_eq!(v.attention[1].reasons, [Reason::Large]);
    assert_eq!(v.attention[2].reasons, [Reason::Irreversible]);
    assert_eq!(v.attention[3].reasons, [Reason::NotChosen]);
    assert!(v.others.iter().all(|e| e.reasons.is_empty()));
    assert!(v.attention.iter().all(|e| e.text.starts_with('\u{26A0}')));
    assert!(v.others.iter().all(|e| e.text.starts_with('\u{2022}')));
    // Path, kind (the verb), band, size and the reasons are on the attention line.
    let big = &entry(&v, "c4").text;
    assert!(big.contains("Move to quarantine"), "{big}");
    assert!(
        big.contains(r#""C:\Users\u\AppData\Local\Vendor\cache""#),
        "{big}"
    );
    assert!(
        big.contains("2.0 GB") && big.contains("Safe") && big.contains("over 1 GB"),
        "{big}"
    );

    // Something that cannot be put back says so in the words that promise the undo.
    assert_eq!(v.icon, super::view::Icon::Warning);
    assert_eq!(
        v.instruction,
        r#"Remove 8 leftovers of "Mozilla Firefox"? 1 cannot be put back."#
    );
    assert_eq!(v.button, "Remove 8 items");
    assert!(
        v.summary
            .iter()
            .any(|l| l.contains("1 item cannot be put back after this"))
    );
    assert!(
        v.summary
            .iter()
            .any(|l| l.contains("restore the rest from History & undo until 2026-12-21"))
    );
    assert!(!v.summary.iter().any(|l| l.contains("restore everything")));
    assert_eq!(
        v.verification.as_deref(),
        Some("I reviewed the items marked \u{26A0}")
    );
}

#[test]
fn the_plain_quarantine_dialog_follows_the_design_table() {
    let specs: Vec<Spec> = (0..22)
        .map(|i| match i {
            0 => Spec::file("c-0", r"C:\Program Files\Mozilla Firefox").size(300 << 20),
            1 => Spec::file("c-1", r"C:\Users\u\Tools\extra").ticked(Band::Likely),
            _ => Spec::safe(
                &format!("c-{i}"),
                key(&format!(r"HKLM\SOFTWARE\Mozilla\Key{i}")),
                Action::DeleteKey,
            )
            .category(Category::Registration),
        })
        .collect();
    let mut f = facts();
    f.restore_point = true;
    let bound = plan(specs);
    let v = view(&bound, &f).unwrap();
    assert_eq!(v.variant, Variant::Quarantine);
    assert_eq!(v.icon, super::view::Icon::Shield);
    assert_eq!(
        v.instruction,
        r#"Move 22 leftovers of "Mozilla Firefox" to quarantine?"#
    );
    assert_eq!(v.button, "Move 22 items to quarantine");
    assert!(
        v.summary
            .contains(&"21 chosen by Purge as safe, 1 ticked by you.".to_owned())
    );
    assert!(
        v.summary
            .contains(&"Files and folders: 2 (300.0 MB)".to_owned()),
        "{:?}",
        v.summary
    );
    assert!(
        v.summary
            .contains(&"Registry keys and values: 20".to_owned())
    );
    assert!(
        v.summary.contains(
            &"You can restore everything from History & undo until 2026-12-21.".to_owned()
        )
    );
    assert!(
        v.summary
            .contains(&"Windows is asked for a restore point first.".to_owned())
    );
    assert_eq!(ids(&v.attention), ["c-1"]);
    assert_eq!(v.others.len(), 20 + 1);
    assert!(v.others_more.is_none());
    assert!(
        v.footer
            .starts_with("Shown by the administrator part of Purge. Code ")
    );
    assert!(v.footer.ends_with(&format!("{}.", v.code)));
    // Nothing of a second prompt unless the request asked to delete instead of keeping in
    // quarantine; then the dialog says that one follows and that this one approves the move only,
    // and it is still the same move with the same code.
    assert!(!v.summary.iter().any(|line| line.contains("second prompt")));
    let mut then_delete = f.clone();
    then_delete.delete_after = true;
    let d = view(&bound, &then_delete).unwrap();
    assert_eq!(
        d.summary.last().map(String::as_str),
        Some(DELETE_AFTER_NOTE)
    );
    assert!(DELETE_AFTER_NOTE.contains("a second prompt names the quarantined files"));
    assert!(DELETE_AFTER_NOTE.contains("Nothing is deleted without it"));
    assert!(DELETE_AFTER_NOTE.contains("this prompt approves the move only"));
    assert_eq!(
        (&d.instruction, &d.button, d.code, d.variant),
        (&v.instruction, &v.button, v.code, v.variant)
    );
    assert_eq!(d.summary[..d.summary.len() - 1], v.summary[..]);
    taskdialog::check(&dialog::pages(&d), PRIMARY).unwrap();
    // No restore point line and no date unless the facts say so.
    let mut f = facts();
    f.restorable_until = None;
    let v = view(&plan(vec![Spec::file("a", r"C:\a")]), &f).unwrap();
    assert!(
        !v.summary
            .iter()
            .any(|l| l.contains("restore") || l.contains("Windows is asked"))
    );
    assert_eq!(v.summary[0], "All 1 chosen by Purge as safe.");
    assert_eq!(
        v.instruction,
        r#"Move 1 leftover of "Mozilla Firefox" to quarantine?"#
    );
    assert_eq!(v.button, "Move 1 item to quarantine");
    assert!(v.verification.is_none());
}

#[test]
fn the_dialog_shows_what_the_executor_will_run() {
    let p = mixed_plan();
    let v = view(&p, &facts()).unwrap();
    // One entry per bound item, drawn from its op: the op's target and the op's verb.
    assert_eq!(v.attention.len() + v.others.len(), p.items().len());
    for item in p.items() {
        let op = item
            .exec_op
            .as_ref()
            .expect("the fixture items all resolve");
        let candidate = p.candidate(item).unwrap();
        let e = entry(&v, &candidate.id.0);
        let shown_target = match op.target() {
            Target::Path { path } | Target::RegKey { path } => format!("\"{path}\""),
            Target::RegValue { path, name } => format!("\"{path}\" value \"{name}\""),
            Target::AppxPackage { full_name } => format!("package \"{full_name}\""),
            other => panic!("unexpected {other:?}"),
        };
        assert!(
            e.text.contains(&shown_target),
            "{} lacks {shown_target}",
            e.text
        );
        let verb = match op.name() {
            "QuarantineMove" => "Move to quarantine",
            "DeleteKeyTree" => "Delete registry key and everything below it",
            "DeleteValue" => "Delete registry value",
            "RemovePackage" => "Remove package for good",
            other => panic!("unexpected {other}"),
        };
        assert!(e.text.contains(verb), "{} lacks {verb}", e.text);
    }
    // The code is the confirm hash's, as plan.create states it, and the view knows its plan.
    let expected = ConfirmCode::of(&confirm_hash(p.plan_hash(), p.selection_hash()));
    assert_eq!(v.code, expected);
    assert!(v.describes_plan(&p));
    let other = plan(vec![Spec::file("x", r"C:\other")]);
    assert!(!v.describes_plan(&other));
    // A view of a different selection of the same scan is not this plan's view.
    let again = view(&p, &facts()).unwrap();
    assert_eq!(
        again, v,
        "the view is a pure function of the plan and the facts"
    );
}

#[test]
fn an_item_the_run_leaves_alone_is_named_but_not_counted() {
    // A service without its scan-time digest is journalled as skipped: no op.
    let skipped = Spec::safe(
        "svc",
        Target::Service {
            name: "VendorSvc".into(),
        },
        Action::DeleteKey,
    )
    .category(Category::System);
    let p = plan(vec![Spec::file("f", r"C:\Vendor"), skipped]);
    let v = view(&p, &facts()).unwrap();
    assert_eq!((v.counts.items, v.counts.skipped), (1, 1));
    assert_eq!(v.button, "Move 1 item to quarantine");
    let e = entry(&v, "svc");
    assert!(
        e.text.contains("Leave alone") && e.text.contains(r#"service "VendorSvc""#),
        "{}",
        e.text
    );
    assert!(
        v.summary
            .iter()
            .any(|l| l.contains("Left alone: 1 listed item"))
    );
    assert!(v.describes_plan(&p));
    // Nothing to run at all: no dialog.
    let only = plan(vec![Spec::safe(
        "svc",
        Target::Service {
            name: "VendorSvc".into(),
        },
        Action::DeleteKey,
    )]);
    assert_eq!(view(&only, &facts()), Err(ViewError::NothingToRun));
}

#[test]
fn a_removal_without_undo_the_user_did_not_confirm_is_left_alone_and_says_so() {
    let package = Spec::safe(
        "pkg",
        Target::AppxPackage {
            full_name: "Vendor.App_1.0.0.0_x64__abcdefghijklm".into(),
        },
        Action::RemovePackage,
    )
    .category(Category::Package);
    let p = plan_full(
        vec![Spec::file("f", r"C:\Vendor"), package],
        Vec::new(),
        false,
    );
    let v = view(&p, &facts()).unwrap();
    // The executor decides the package as not done without the acknowledgement: the dialog does not
    // promise to remove it, does not count it, and does not warn of an undo it will not take away.
    assert_eq!(
        (v.counts.items, v.counts.skipped, v.counts.irreversible),
        (1, 1, 0)
    );
    assert_eq!(v.button, "Move 1 item to quarantine");
    assert_eq!(v.icon, super::view::Icon::Shield);
    let e = entry(&v, "pkg");
    assert!(
        e.text
            .contains("Leave alone (a removal without undo was not confirmed)"),
        "{}",
        e.text
    );
    assert!(!e.text.contains("Remove package for good"));
    assert!(v.describes_plan(&p));
    // The same plan with the acknowledgement removes it and says that it cannot be put back.
    let ack = plan_full(
        vec![
            Spec::file("f", r"C:\Vendor"),
            Spec::safe(
                "pkg",
                Target::AppxPackage {
                    full_name: "Vendor.App_1.0.0.0_x64__abcdefghijklm".into(),
                },
                Action::RemovePackage,
            )
            .category(Category::Package),
        ],
        Vec::new(),
        true,
    );
    let v = view(&ack, &facts()).unwrap();
    assert_eq!((v.counts.items, v.counts.irreversible), (2, 1));
    assert!(entry(&v, "pkg").text.contains("Remove package for good"));
}

#[test]
fn an_absorbed_item_that_needs_attention_is_listed_with_its_parent() {
    let parent = Spec::file("p", r"C:\Program Files\Vendor").with_children(&["k1", "k2"]);
    let kids = vec![
        Spec::file("k1", r"C:\Program Files\Vendor\bin\app.exe"),
        Spec {
            category: Category::UserData,
            ..Spec::file("k2", r"C:\Program Files\Vendor\My Documents")
        },
    ];
    let p = plan_with(vec![parent, Spec::file("q", r"C:\Other")], kids);
    let v = view(&p, &facts()).unwrap();
    assert_eq!(ids(&v.attention), ["p", "k2"]);
    assert!(v.attention[0].reasons.contains(&Reason::Inside));
    assert!(v.attention[0].text.contains("2 items inside it"));
    assert_eq!(v.attention[1].reasons, [Reason::UserData]);
    assert!(v.attention[1].text.contains("Taken with its parent"));
    assert_eq!(
        v.counts.items, 2,
        "the absorbed items are not ops of their own"
    );
    assert_eq!(v.counts.inside, 2);
    assert!(v.verification.is_some());
    // Without a child that needs attention the parent is an ordinary item and says what is inside.
    let calm = plan_with(
        vec![Spec::file("p", r"C:\Program Files\Vendor").with_children(&["k1"])],
        vec![Spec::file("k1", r"C:\Program Files\Vendor\bin\app.exe")],
    );
    let v = view(&calm, &facts()).unwrap();
    assert!(v.attention.is_empty());
    assert!(v.others[0].text.contains("1 item inside it"));
}

#[test]
fn user_data_below_a_ticked_parent_is_listed_and_makes_the_parent_user_data() {
    // The parent is Likely, so collapse does not absorb it: the user-data folder below it stays an
    // item of its own (review M4). The user ticks the parent alone.
    let parent = Spec::file("p", r"C:\Program Files\Vendor").ticked(Band::Likely);
    let saves = Spec::user_data("saves", r"C:\Program Files\Vendor\saves");
    let p = plan_selecting(vec![parent, saves], Vec::new(), &["p"]);
    let v = view(&p, &facts()).unwrap();
    assert_eq!(ids(&v.attention), ["p", "saves"]);
    // The parent is not user data by its own category, but what it takes with it is.
    assert!(
        v.attention[0].reasons.contains(&Reason::UserData),
        "{:?}",
        v.attention[0].reasons
    );
    assert!(v.attention[0].reasons.contains(&Reason::NotChosen));
    assert!(
        v.attention[0].text.contains("user data"),
        "{}",
        v.attention[0].text
    );
    assert!(
        v.attention[0].text.contains("1 item inside it"),
        "{}",
        v.attention[0].text
    );
    assert_eq!(v.attention[1].reasons, [Reason::UserData]);
    assert!(v.attention[1].text.contains("Taken with its parent"));
    assert!(
        v.attention[1]
            .text
            .contains(r#""C:\Program Files\Vendor\saves""#),
        "{}",
        v.attention[1].text
    );
    assert_eq!((v.counts.items, v.counts.inside), (1, 1));
    assert!(v.describes_plan(&p));

    // A candidate the scanner marks with the user-data blocker (its category stays AppFiles) is user
    // data in the dialog too.
    let blocked = Spec::file("p", r"C:\Program Files\Vendor")
        .ticked(Band::Likely)
        .blocker(Blocker::UserData);
    let p = plan_selecting(vec![blocked], Vec::new(), &["p"]);
    let v = view(&p, &facts()).unwrap();
    assert_eq!(ids(&v.attention), ["p"]);
    assert!(v.attention[0].reasons.contains(&Reason::UserData));
    assert!(v.attention[0].text.contains("user data"));
}

// ---------------------------------------------------------------------------------------------------
// Paging
// ---------------------------------------------------------------------------------------------------

fn page_counts(v: &ConsentView) -> Vec<usize> {
    v.attention_pages().iter().map(|p| p.len()).collect()
}

#[test]
fn the_attention_list_pages_at_40_41_and_5000_and_loses_nothing() {
    for (n, expected) in [
        (0, vec![]),
        (1, vec![1]),
        (39, vec![39]),
        (40, vec![40]),
        (41, vec![40, 1]),
        (80, vec![40, 40]),
        (81, vec![40, 40, 1]),
    ] {
        let v = view(&plan_for_pages(n), &facts()).unwrap();
        assert_eq!(page_counts(&v), expected, "{n} entries");
        let flat: Vec<&str> = v
            .attention_pages()
            .iter()
            .flat_map(|p| p.iter())
            .map(|e| e.id.as_str())
            .collect();
        assert_eq!(flat, ids(&v.attention));
        assert_eq!(v.attention.len(), n);
    }
    let v = view(&user_data_plan(5000), &facts()).unwrap();
    let counts = page_counts(&v);
    assert_eq!(counts.len(), 125);
    assert!(counts.iter().all(|c| *c == PAGE_ENTRIES));
    assert_eq!(v.attention.len(), 5000);
    assert_eq!(v.counts.items, 5000);
    // Dialog pages: every entry is on a page, the primary button and the box only on the last.
    let pages = dialog::pages(&v);
    assert_eq!(pages.len(), 125);
    taskdialog::check(&pages, PRIMARY).unwrap();
    let on_pages: usize = pages
        .iter()
        .map(|p| p.content.matches("Delete registry value:").count())
        .sum();
    assert_eq!(on_pages, 5000);
}

/// `n` user-data items, so `n` attention entries, over a plan of `n` items.
fn plan_for_pages(n: usize) -> BoundPlan {
    if n == 0 {
        plan(vec![Spec::file("a", r"C:\a")])
    } else {
        user_data_plan(n)
    }
}

#[test]
fn a_page_closes_early_when_its_text_would_grow_too_large() {
    let long = "x".repeat(1_000);
    let mut v = view(&plan_for_pages(0), &facts()).unwrap();
    v.attention = (0..100)
        .map(|i| super::view::Entry {
            id: format!("e{i}"),
            text: format!("{i}{long}"),
            reasons: vec![Reason::UserData],
        })
        .collect();
    let pages = v.attention_pages();
    assert!(pages.len() > 100 / PAGE_ENTRIES + 1, "{}", pages.len());
    for p in &pages {
        let chars: usize = p.iter().map(|e| e.text.chars().count() + 1).sum();
        assert!(p.len() == 1 || chars <= PAGE_CHARS, "{chars}");
        assert!(p.len() <= PAGE_ENTRIES);
    }
    let flat: Vec<&str> = pages
        .iter()
        .flat_map(|p| p.iter())
        .map(|e| e.id.as_str())
        .collect();
    assert_eq!(flat, ids(&v.attention), "no entry is dropped");
}

#[test]
fn five_thousand_items_hide_no_attention_item() {
    // 4,950 ordinary items and 50 attention items scattered through them.
    let specs: Vec<Spec> = (0..5000)
        .map(|i| {
            if i % 100 == 7 {
                value_spec(i).category(Category::UserData)
            } else {
                value_spec(i)
            }
        })
        .collect();
    let v = view(&plan(specs), &facts()).unwrap();
    assert_eq!(v.attention.len(), 50);
    assert_eq!(v.others.len(), OTHER_SHOWN);
    assert_eq!(
        v.others_more.as_deref(),
        Some("and 4,850 more of the same kinds: 4,850 registry keys and values.")
    );
    assert_eq!(v.counts.items, 5000);
    for i in (7..5000).step_by(100) {
        assert!(
            v.attention.iter().any(|e| e.id == format!("c-{i:05}")),
            "{i}"
        );
    }
    assert!(
        v.attention
            .iter()
            .all(|e| e.reasons.contains(&Reason::UserData))
    );
    // The others are in plan order, the first 100 non-attention ones.
    assert_eq!(v.others[0].id, "c-00000");
    assert_eq!(v.others[1].id, "c-00001");
    // Two pages of 40 hold the 50; the last has the button, the box, the others and the rest.
    let pages = dialog::pages(&v);
    assert_eq!(pages.len(), 2);
    let last = &pages[1];
    assert!(
        last.expanded
            .as_ref()
            .unwrap()
            .ends_with("4,850 registry keys and values.")
    );
    assert_eq!(
        last.expanded.as_ref().unwrap().lines().count(),
        OTHER_SHOWN + 1
    );
}

// ---------------------------------------------------------------------------------------------------
// Names and paths that mislead
// ---------------------------------------------------------------------------------------------------

#[test]
fn rlo_and_line_breaks_in_names_and_paths_never_reach_the_dialog() {
    let evil_path = "C:\\Users\\u\\Docs\\evil\u{202e}gpj.exe\n\u{26A0} Move to quarantine: \"C:\\Temp\" \u{b7} Safe";
    let evil_value = "Run\r\nAll safe\u{2028}\u{200b}\u{0}";
    let evil_key = "HKLM\\SOFTWARE\\Vendor\u{202a}\u{2066}\u{85}x";
    let p = plan(vec![
        Spec::file("a", evil_path),
        Spec::safe(
            "b",
            Target::RegValue {
                path: evil_key.into(),
                name: evil_value.into(),
            },
            Action::DeleteValue,
        )
        .category(Category::Registration),
        Spec::file("ok", r"C:\Program Files\Vendor"),
    ]);
    let mut f = facts();
    f.app_name = "Fire\u{202e}fox\nSafe".into();
    let v = view(&p, &f).unwrap();
    for line in every_line(&v) {
        assert_clean(line);
    }
    // The odd names are attention entries, flagged, and show their escapes.
    assert_eq!(ids(&v.attention), ["a", "b"]);
    assert!(
        v.attention
            .iter()
            .all(|e| e.reasons.contains(&Reason::EscapedName))
    );
    let a = &entry(&v, "a").text;
    assert!(a.contains(r"evil\u{202e}gpj.exe\u{a}"), "{a}");
    assert!(
        entry(&v, "b")
            .text
            .contains(r"Run\u{d}\u{a}All safe\u{2028}\u{200b}\u{0}")
    );
    // The fake line cannot close its quotes, so it stays inside the one pair around the path.
    assert_eq!(a.matches('"').count(), 2, "{a}");
    assert!(
        v.instruction.contains(r"Fire\u{202e}fox\u{a}Safe"),
        "{}",
        v.instruction
    );
    assert_eq!(v.instruction.matches('"').count(), 2);
    assert!(v.summary.iter().any(|l| l.contains("look-alike")));
    // The ordinary item is not flagged.
    assert!(v.others.iter().any(|e| e.id == "ok"));
    // Every page the dialog would show is clean too, line by line.
    for page in dialog::pages(&v) {
        for text in [&page.instruction, &page.content] {
            for line in text.split('\n') {
                assert_clean(line);
            }
        }
        for line in page.expanded.iter().flat_map(|e| e.split('\n')) {
            assert_clean(line);
        }
        assert!(!page.content.contains('\0') && !page.instruction.contains('\0'));
    }
    taskdialog::check(&dialog::pages(&v), PRIMARY).unwrap();
}

#[test]
fn long_names_are_cut_in_the_middle_flagged_and_listed_in_full_attention() {
    let long = format!("{}-the-end.exe", "n".repeat(200));
    let p = plan(vec![
        Spec::file("long", &format!(r"C:\Program Files\Vendor\{long}")),
        Spec::file("plain", r"C:\Program Files\Vendor\app.exe"),
    ]);
    let v = view(&p, &facts()).unwrap();
    assert_eq!(ids(&v.attention), ["long"]);
    assert_eq!(v.attention[0].reasons, [Reason::ShortenedName]);
    let e = &v.attention[0].text;
    assert!(e.contains("-the-end.exe\""), "{e}");
    assert!(e.contains("characters not shown]"), "{e}");
    assert!(e.contains("name is shortened"), "{e}");
    assert!(!e.contains(&"n".repeat(100)));
    assert!(
        v.summary
            .iter()
            .any(|l| l.contains("longer than 80 characters"))
    );
    // A path of many short components is cut as a whole, keeping both ends.
    let deep = format!(r"C:\{}\final.txt", vec!["d"; 400].join("\\"));
    let v = view(&plan(vec![Spec::file("deep", &deep)]), &facts()).unwrap();
    let e = entry(&v, "deep");
    assert!(e.reasons.contains(&Reason::ShortenedName));
    assert!(
        e.text.contains(r#""C:\d\d"#) && e.text.contains(r#"\final.txt""#),
        "{}",
        e.text
    );
    assert!(
        e.text.chars().count() < LINE_COST + 200,
        "{}",
        e.text.chars().count()
    );
}

#[test]
fn look_alike_names_cannot_pass_for_the_real_one() {
    let p = plan(vec![
        Spec::file("fake", "C:\\Program Files\\Mozill\u{430}"),
        Spec::file("space", "C:\\Program Files \\Mozilla"),
        Spec::file("twice", "C:\\Program  Files\\Mozilla"),
        Spec::file("real", r"C:\Program Files\Mozilla"),
        Spec::file(
            "script",
            "C:\\Users\\\u{43f}\u{43e}\u{43b}\u{44c}\u{437}\u{43e}\u{432}\u{430}\u{442}\u{435}\u{43b}\u{44c}\\Docs",
        ),
    ]);
    let v = view(&p, &facts()).unwrap();
    assert_eq!(ids(&v.attention), ["fake", "space", "twice"]);
    assert!(entry(&v, "fake").text.contains(r"Mozill\u{430}"));
    assert!(entry(&v, "space").text.contains(r"Files\u{20}\Mozilla"));
    assert!(entry(&v, "twice").text.contains(r"Program \u{20}Files"));
    // The real path and a path in a script of its own are shown as they are.
    assert!(
        entry(&v, "real")
            .text
            .contains(r#""C:\Program Files\Mozilla""#)
    );
    assert!(entry(&v, "script").text.contains("\u{43f}\u{43e}\u{43b}"));
}

#[test]
fn a_name_cannot_fake_a_band_or_a_reason_outside_its_quotes() {
    let p = plan(vec![Spec::file(
        "x",
        "C:\\a\" \u{b7} Safe \u{b7} \"C:\\harmless",
    )]);
    let v = view(&p, &facts()).unwrap();
    let e = entry(&v, "x");
    assert_eq!(e.text.matches('"').count(), 2);
    let inner_start = e.text.find('"').unwrap();
    let inner_end = e.text.rfind('"').unwrap();
    assert!(e.text[inner_start..=inner_end].contains(r"\u{22}"));
    assert!(e.reasons.contains(&Reason::EscapedName));
}

// ---------------------------------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------------------------------

#[test]
fn the_pages_follow_the_layout_of_design_8() {
    let v = view(&mixed_plan(), &facts()).unwrap();
    let pages = dialog::pages(&v);
    assert_eq!(pages.len(), 1);
    let page = &pages[0];
    taskdialog::check(&pages, PRIMARY).unwrap();
    assert_eq!(page.title, "Purge security prompt");
    assert_eq!(page.icon, DialogIcon::Warning);
    assert_eq!(page.instruction, v.instruction);
    assert_eq!(page.buttons.len(), 1);
    assert_eq!(page.buttons[0].id, PRIMARY);
    assert_eq!(page.buttons[0].label, v.button);
    assert_eq!(page.default_button, None, "Cancel is the default");
    assert_eq!(page.verification, v.verification);
    assert_eq!(page.gated_button, Some(PRIMARY));
    assert_eq!(page.footer.as_deref(), Some(v.footer.as_str()));
    assert!(page.content.starts_with(&v.summary[0]));
    assert!(page.content.contains("\u{26A0} Needs your attention (4)"));
    for e in &v.attention {
        assert!(page.content.contains(&e.text));
    }
    let expanded = page.expanded.as_ref().unwrap();
    for e in &v.others {
        assert!(expanded.contains(&e.text));
    }
    for e in &v.attention {
        assert!(
            !expanded.contains(&e.text),
            "attention entries are never folded away"
        );
    }
    // The attention list is in the content, which is never collapsed.
    assert!(!page.content.is_empty());

    // No attention entry: no box, no gate, nothing in the content but the summary.
    let calm = view(
        &plan(vec![Spec::file("a", r"C:\a"), Spec::file("b", r"C:\b")]),
        &facts(),
    )
    .unwrap();
    let pages = dialog::pages(&calm);
    taskdialog::check(&pages, PRIMARY).unwrap();
    assert!(pages[0].verification.is_none() && pages[0].gated_button.is_none());
    assert!(!pages[0].content.contains("Needs your attention"));
    assert_eq!(pages[0].icon, DialogIcon::Shield);
}

#[test]
fn paged_dialogs_carry_the_button_and_the_box_on_the_last_page_only() {
    let v = view(&user_data_plan(85), &facts()).unwrap();
    let pages = dialog::pages(&v);
    assert_eq!(pages.len(), 3);
    taskdialog::check(&pages, PRIMARY).unwrap();
    for (i, page) in pages.iter().enumerate() {
        let last = i == 2;
        assert_eq!(!page.buttons.is_empty(), last, "button on page {i}");
        assert_eq!(page.verification.is_some(), last, "box on page {i}");
        assert_eq!(page.gated_button.is_some(), last);
        assert_eq!(page.expanded.is_some(), last && !v.others.is_empty());
        assert_eq!(page.default_button, None);
        assert_eq!(
            page.footer.as_deref(),
            Some(v.footer.as_str()),
            "the code is on every page"
        );
        assert_eq!(page.instruction, v.instruction);
        assert_eq!(page.content.contains("Use Next to continue"), !last);
    }
    assert!(pages[0].content.starts_with(&v.summary[0]));
    assert!(
        pages[1]
            .content
            .starts_with("\u{26A0} Needs your attention: 41 to 80 of 85 (page 2 of 3)")
    );
    assert!(pages[2].content.contains("81 to 85 of 85 (page 3 of 3)"));
    // A user-data item is on exactly one page.
    for e in &v.attention {
        assert_eq!(
            pages.iter().filter(|p| p.content.contains(&e.text)).count(),
            1
        );
    }
}

const _: () = assert!(PRIMARY >= purge_win::taskdialog::MIN_BUTTON_ID);

#[test]
fn the_primary_id_is_a_custom_id_and_the_literals_are_the_designs() {
    assert_eq!(super::text::TITLE, "Purge security prompt");
}

// ---------------------------------------------------------------------------------------------------
// Restore and recover
// ---------------------------------------------------------------------------------------------------

fn session_plan() -> BoundPlan {
    plan(vec![
        Spec::file("a", r"C:\Program Files\Vendor"),
        Spec::safe("b", key(r"HKLM\SOFTWARE\Vendor"), Action::DeleteKey)
            .category(Category::Registration),
        Spec::user_data("c", r"C:\Users\u\Documents\Vendor"),
        Spec::safe(
            "d",
            Target::AppxPackage {
                full_name: "Vendor.App_1.0.0.0_x64__abcdefghijklm".into(),
            },
            Action::RemovePackage,
        )
        .category(Category::Package),
    ])
}

#[test]
fn restore_lists_conflicts_as_attention_items() {
    let p = session_plan();
    let facts = RestoreFacts {
        app_name: "Vendor App".into(),
        ops: vec![OpId(1), OpId(2), OpId(3)],
        conflicts: vec![
            (OpId(1), ConflictKind::WillOverwrite),
            (OpId(3), ConflictKind::PlaceTaken),
        ],
    };
    let v = view_restore(&p, &facts).unwrap();
    assert_eq!(v.variant, Variant::Restore);
    assert_eq!(v.instruction, r#"Restore 3 items of "Vendor App"?"#);
    assert_eq!(v.button, "Restore 3 items");
    assert_eq!(v.icon, super::view::Icon::Shield);
    assert_eq!(ids(&v.attention), ["a", "c"]);
    assert_eq!(
        v.attention[0].reasons,
        [Reason::Conflict(ConflictKind::WillOverwrite)]
    );
    assert_eq!(
        v.attention[1].reasons,
        [Reason::Conflict(ConflictKind::PlaceTaken)]
    );
    assert!(v.attention[0].text.contains("Put back:") && v.attention[0].text.contains("replaced"));
    assert!(v.attention[1].text.contains("skipped"));
    assert_eq!(ids(&v.others), ["b"]);
    assert!(
        v.summary
            .iter()
            .any(|l| l.contains("1 item will replace something"))
    );
    assert!(
        v.summary
            .iter()
            .any(|l| l.contains("1 item will be skipped"))
    );
    assert!(v.verification.is_some());
    assert_eq!(v.counts.items, 3);
    // The code covers exactly the shown selection.
    let want = ConfirmCode::of(&confirm_hash(
        p.plan_hash(),
        selection_hash(&[cid("a"), cid("b"), cid("c")]),
    ));
    assert_eq!(v.code, want);
    assert!(
        !v.describes_plan(&p),
        "a partial restore is not the whole plan"
    );
    // No conflict, no attention, no box.
    let calm = view_restore(
        &p,
        &RestoreFacts {
            app_name: "Vendor App".into(),
            ops: vec![OpId(2)],
            conflicts: vec![],
        },
    )
    .unwrap();
    assert!(calm.attention.is_empty() && calm.verification.is_none());
    assert_eq!(calm.button, "Restore 1 item");
}

#[test]
fn restore_refuses_what_cannot_be_put_back_or_is_not_in_the_plan() {
    let p = session_plan();
    let restore = |ops: Vec<OpId>, conflicts| {
        view_restore(
            &p,
            &RestoreFacts {
                app_name: "x".into(),
                ops,
                conflicts,
            },
        )
    };
    assert_eq!(
        restore(vec![OpId(4)], vec![]),
        Err(ViewError::NotRestorable(OpId(4)))
    );
    assert_eq!(
        restore(vec![OpId(9)], vec![]),
        Err(ViewError::UnknownOp(OpId(9)))
    );
    assert_eq!(
        restore(vec![OpId(1), OpId(1)], vec![]),
        Err(ViewError::DuplicateOp(OpId(1)))
    );
    assert_eq!(restore(vec![], vec![]), Err(ViewError::NothingToRun));
    assert_eq!(
        restore(vec![OpId(1)], vec![(OpId(2), ConflictKind::PlaceTaken)]),
        Err(ViewError::UnknownOp(OpId(2)))
    );
}

fn recover_facts(kind: RecoverKind, ops: Vec<OpId>) -> RecoverFacts {
    RecoverFacts {
        kind,
        app_name: "Vendor App".into(),
        session: "20261115T101502Z-9f3a6c1d2b7e4a50".into(),
        started: Some(Stamp {
            year: 2026,
            month: 11,
            day: 15,
            hour: 10,
            minute: 15,
        }),
        done: 1,
        total: 4,
        ops,
    }
}

#[test]
fn recover_names_the_session_its_progress_and_the_user_data_still_to_change() {
    let p = session_plan();
    let v = view_recover(
        &p,
        &recover_facts(RecoverKind::Resume, vec![OpId(2), OpId(3), OpId(4)]),
    )
    .unwrap();
    assert_eq!(v.variant, Variant::Recover(RecoverKind::Resume));
    assert_eq!(v.instruction, r#"Finish the cleanup of "Vendor App"?"#);
    assert_eq!(v.button, "Finish the cleanup");
    let intro = v
        .summary
        .iter()
        .find(|l| l.starts_with("An earlier cleanup"))
        .unwrap();
    assert_eq!(
        intro,
        "An earlier cleanup was interrupted (session 20261115T101502Z-9f3a6c1d2b7e4a50, started 2026-11-15 10:15 UTC): 1 of 4 items are done."
    );
    assert!(
        v.summary
            .iter()
            .any(|l| l == "Finishing it changes 3 items:")
    );
    // User data and the item without an undo, not the ticked/large rules of a fresh run.
    assert_eq!(ids(&v.attention), ["c", "d"]);
    assert_eq!(v.attention[0].reasons, [Reason::UserData]);
    assert_eq!(v.attention[1].reasons, [Reason::Irreversible]);
    assert_eq!(ids(&v.others), ["b"]);
    assert!(v.attention[0].text.contains("Move to quarantine"));

    let v = view_recover(
        &p,
        &recover_facts(RecoverKind::Rollback, vec![OpId(1), OpId(3)]),
    )
    .unwrap();
    assert_eq!(v.instruction, r#"Roll the cleanup of "Vendor App" back?"#);
    assert_eq!(v.button, "Roll the cleanup back");
    assert_eq!(ids(&v.attention), ["c"]);
    assert!(v.attention[0].text.contains("Put back:"));
    assert!(
        v.summary
            .iter()
            .any(|l| l == "Rolling it back puts back 2 items:")
    );
    // A rollback of an item that has no inverse is refused.
    assert_eq!(
        view_recover(&p, &recover_facts(RecoverKind::Rollback, vec![OpId(4)])),
        Err(ViewError::NotRestorable(OpId(4)))
    );

    let v = view_recover(&p, &recover_facts(RecoverKind::RetryHeld, vec![OpId(1)])).unwrap();
    assert_eq!(
        v.instruction,
        r#"Try the held items of "Vendor App" again?"#
    );
    assert_eq!(v.button, "Try the held items again");
    assert!(v.attention.is_empty() && v.verification.is_none());
    for kind in [
        RecoverKind::Resume,
        RecoverKind::Rollback,
        RecoverKind::RetryHeld,
    ] {
        assert_eq!(
            view_recover(&p, &recover_facts(kind, vec![])),
            Err(ViewError::NothingToRun)
        );
    }
}

// ---------------------------------------------------------------------------------------------------
// Purge
// ---------------------------------------------------------------------------------------------------

const SESSION: &str = "20261115T101502Z-9f3a6c1d2b7e4a50";

fn expiry(op: u32) -> ExpiryId {
    ExpiryId {
        session: SESSION.parse().unwrap(),
        op: OpId(op),
    }
}

fn expiring_item(op: u32, original: &str, user_data: bool) -> ExpiringItem {
    ExpiringItem {
        id: expiry(op),
        item: cid(&format!("c-{op}")),
        original_path: original.into(),
        quarantine_path: format!(r"C:\ProgramData\Purge\quarantine\{SESSION}\{op}\item"),
        expires: FileTime(0),
        bytes: 2048 * u64::from(op),
        is_dir: op % 2 == 0,
        user_data,
        unfinished: false,
    }
}

fn expiring_backup(op: u32, files: &[&str], user_data: bool) -> ExpiringBackup {
    ExpiringBackup {
        id: expiry(op),
        item: cid(&format!("c-{op}")),
        target: Target::RegKey {
            path: format!(r"HKLM\SOFTWARE\Vendor\Key{op}"),
        },
        files: files.iter().map(|f| (*f).to_owned()).collect(),
        expires: FileTime(0),
        bytes: 4096,
        user_data,
        unfinished: false,
    }
}

#[test]
fn purge_names_every_item_and_every_file_in_pages_never_cut() {
    let items: Vec<ExpiringItem> = (1..=90)
        .map(|op| expiring_item(op, &format!(r"C:\Program Files\Vendor\part{op}"), false))
        .collect();
    let backups = vec![
        expiring_backup(
            91,
            &[r"reg\000091.regbackup.json", r"reg\000091.regbackup.1.json"],
            false,
        ),
        expiring_backup(92, &[r"pkg\000092.definition.json"], false),
    ];
    let (bulk, user) = split_purge(&items, &backups);
    assert!(user.is_empty());
    let v = view_purge(&bulk).unwrap();
    assert_eq!(v.variant, Variant::Purge);
    assert_eq!(v.icon, super::view::Icon::Warning);
    assert_eq!(
        v.instruction,
        "Delete 92 expired items for good? This cannot be undone."
    );
    assert_eq!(v.button, "Delete 92 items for good");
    assert_eq!((v.counts.items, v.counts.files), (92, 3));
    // Every item and every file is an attention entry; there is no "and N more".
    assert_eq!(v.attention.len(), 90 + 3);
    assert!(v.others.is_empty() && v.others_more.is_none());
    assert!(v.verification.is_some());
    for (op, entry) in (1..=90).zip(&v.attention) {
        assert!(
            entry
                .text
                .contains(&format!(r#"was "C:\Program Files\Vendor\part{op}""#)),
            "{}",
            entry.text
        );
        assert!(entry.text.contains(&format!("{SESSION}\\{op}\\item")));
        assert!(entry.reasons.contains(&Reason::Irreversible));
    }
    let files: Vec<&str> = v.attention[90..].iter().map(|e| e.text.as_str()).collect();
    assert!(
        files[0].contains(r#"Delete backup file: "reg\000091.regbackup.json""#),
        "{}",
        files[0]
    );
    assert!(files[1].contains(r#""reg\000091.regbackup.1.json""#));
    assert!(files[2].contains(r#""pkg\000092.definition.json""#));
    let pages = dialog::pages(&v);
    assert_eq!(page_counts(&v), [40, 40, 13]);
    assert_eq!(pages.len(), 3);
    taskdialog::check(&pages, PRIMARY).unwrap();
    assert!(pages[2].verification.is_some() && pages[2].buttons[0].id == PRIMARY);
    assert!(pages[0].buttons.is_empty());
    assert!(v.summary[0].starts_with("92 expired items and 3 backup files"));
    let want = {
        let ids: Vec<CandidateId> = (1..=92).map(|op| cid(&expiry(op).to_string())).collect();
        ConfirmCode::of(&selection_hash(&ids))
    };
    assert_eq!(v.code, want);
}

#[test]
fn user_data_gets_a_dialog_of_its_own() {
    let items = vec![
        expiring_item(1, r"C:\Program Files\Vendor\a", false),
        expiring_item(2, r"C:\Users\u\Documents\Vendor", true),
    ];
    let backups = vec![expiring_backup(3, &[r"reg\000003.regbackup.json"], true)];
    let (bulk, user) = split_purge(&items, &backups);
    assert_eq!(bulk.len(), 1);
    assert_eq!(user.len(), 2);
    // The bulk dialog refuses user data, and the user-data dialog refuses anything else.
    assert_eq!(
        view_purge(&[PurgeUnit::Item(&items[0]), PurgeUnit::Item(&items[1])]),
        Err(ViewError::UserDataMisplaced(expiry(2).to_string()))
    );
    assert_eq!(
        view_purge_user_data(PurgeUnit::Item(&items[0])),
        Err(ViewError::UserDataMisplaced(expiry(1).to_string()))
    );
    let v = view_purge_user_data(user[0]).unwrap();
    assert_eq!(
        v.instruction,
        "Delete this user data for good? This cannot be undone."
    );
    assert_eq!(v.button, "Delete 1 item for good");
    assert_eq!(v.attention.len(), 1);
    assert!(v.attention[0].reasons.contains(&Reason::UserData));
    assert!(
        v.attention[0]
            .text
            .contains(r#"was "C:\Users\u\Documents\Vendor""#)
    );
    assert_eq!(
        v.verification.as_deref(),
        Some("I reviewed the item marked \u{26A0}")
    );
    let v = view_purge_user_data(user[1]).unwrap();
    assert_eq!(v.attention.len(), 1);
    assert!(v.attention[0].text.contains("Delete backup file"));
    taskdialog::check(&dialog::pages(&v), PRIMARY).unwrap();
}

#[test]
fn purge_refuses_duplicates_empty_sets_and_backups_without_files() {
    let item = expiring_item(1, r"C:\a", false);
    assert_eq!(view_purge(&[]), Err(ViewError::NothingToRun));
    assert_eq!(
        view_purge(&[PurgeUnit::Item(&item), PurgeUnit::Item(&item)]),
        Err(ViewError::DuplicateUnit(expiry(1).to_string()))
    );
    let empty = expiring_backup(2, &[], false);
    assert_eq!(
        view_purge(&[PurgeUnit::Backup(&empty)]),
        Err(ViewError::NoFiles(expiry(2).to_string()))
    );
}

#[test]
fn purge_names_cannot_mislead_either() {
    let item = expiring_item(1, "C:\\Users\\u\\evil\u{202e}gpj.exe\nSafe", false);
    let backup = expiring_backup(2, &["reg\\a\u{200b}b\n.json"], false);
    let v = view_purge(&[PurgeUnit::Item(&item), PurgeUnit::Backup(&backup)]).unwrap();
    for line in every_line(&v) {
        assert_clean(line);
    }
    assert!(
        v.attention[0]
            .text
            .contains(r"evil\u{202e}gpj.exe\u{a}Safe")
    );
    assert!(v.attention[1].text.contains(r"a\u{200b}b\u{a}.json"));
    assert!(v.summary.iter().any(|l| l.contains("look-alike")));
}

// ---------------------------------------------------------------------------------------------------
// Uninstall (review M3-R2 M1)
// ---------------------------------------------------------------------------------------------------

fn quiet_command(exe: &str, args: &str) -> QuietCommand {
    QuietCommand {
        exe: exe.to_owned(),
        args: args.to_owned(),
        generated: false,
        kind: InstallerKind::Inno,
    }
}

fn uninstall_facts(command: QuietCommand, quiet: bool) -> UninstallFacts {
    UninstallFacts {
        app_name: "Vendor App".to_owned(),
        program_id: "HKLM|64|VendorApp".to_owned(),
        command,
        quiet,
        signer: Some("Vendor Ltd".to_owned()),
        restore_point: Some(RestorePoint::HighRisk),
    }
}

const VENDOR_EXE: &str = r"C:\Program Files\Vendor\unins000.exe";

#[test]
fn uninstall_shows_name_command_signer_mode_and_restore_point() {
    let command = quiet_command(VENDOR_EXE, "/VERYSILENT /NORESTART");
    let v = view_uninstall(&uninstall_facts(command.clone(), true)).unwrap();
    assert_eq!(v.variant, Variant::Uninstall);
    assert_eq!(v.icon, super::view::Icon::Warning);
    assert_eq!(
        v.instruction,
        "Run the uninstaller of \"Vendor App\" as administrator?"
    );
    assert_eq!(v.button, "Run the uninstaller");
    assert_eq!(
        v.summary[..4],
        [
            format!("Starts: \"{VENDOR_EXE}\""),
            "Arguments: \"/VERYSILENT /NORESTART\"".to_owned(),
            "Signed by: \"Vendor Ltd\"".to_owned(),
            "Mode: quiet. The uninstaller shows no window of its own.".to_owned(),
        ]
    );
    assert!(
        v.summary[4].contains("only when it is high-risk"),
        "{:?}",
        v.summary
    );
    assert!(v.attention.is_empty() && v.verification.is_none());
    assert!(v.footer.contains(&v.code.to_string()));
    assert!(v.describes_uninstall(&command, true));
    for line in every_line(&v) {
        assert_clean(line);
    }
    let pages = dialog::pages(&v);
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].buttons.len(), 1);
    assert_eq!(pages[0].buttons[0].id, PRIMARY);
    assert_eq!(pages[0].default_button, None, "Cancel is the default");
    assert_eq!(pages[0].gated_button, None);
    taskdialog::check(&pages, PRIMARY).unwrap();
}

#[test]
fn uninstall_says_when_it_is_interactive_has_no_arguments_and_no_signer() {
    let command = quiet_command(VENDOR_EXE, "");
    let facts = UninstallFacts {
        signer: None,
        restore_point: None,
        ..uninstall_facts(command.clone(), false)
    };
    let v = view_uninstall(&facts).unwrap();
    assert!(v.summary.iter().any(|l| l == "Arguments: none"));
    assert!(v.summary.iter().any(|l| l == "Signed by: no signer known"));
    assert!(v.summary.iter().any(|l| l.starts_with("Mode: interactive")));
    assert!(
        v.summary
            .iter()
            .any(|l| l.starts_with("Restore point: not asked for here"))
    );
    assert!(v.describes_uninstall(&command, false));
    assert!(
        !v.describes_uninstall(&command, true),
        "the mode is part of what was drawn"
    );
}

#[test]
fn uninstall_dialog_describes_only_the_command_it_was_drawn_from() {
    let command = quiet_command(VENDOR_EXE, "/S");
    let v = view_uninstall(&uninstall_facts(command.clone(), true)).unwrap();
    assert!(v.describes_uninstall(&command, true));
    for other in [
        quiet_command(r"C:\Program Files\Vendor\unins001.exe", "/S"),
        quiet_command(VENDOR_EXE, "/S /X"),
        QuietCommand {
            generated: true,
            ..command.clone()
        },
        QuietCommand {
            kind: InstallerKind::Msi,
            ..command.clone()
        },
    ] {
        assert!(!v.describes_uninstall(&other, true), "{other:?}");
    }
    let other_variant = view_purge_user_data(PurgeUnit::Item(&expiring_item(1, r"C:\a", true)));
    assert!(!other_variant.unwrap().describes_uninstall(&command, true));
}

#[test]
fn uninstall_code_follows_the_program_mode_and_command() {
    let command = quiet_command(VENDOR_EXE, "/S");
    let base = view_uninstall(&uninstall_facts(command.clone(), true)).unwrap();
    assert_eq!(
        base.code,
        view_uninstall(&uninstall_facts(command.clone(), true))
            .unwrap()
            .code
    );
    let other_mode = view_uninstall(&uninstall_facts(command.clone(), false)).unwrap();
    let other_args =
        view_uninstall(&uninstall_facts(quiet_command(VENDOR_EXE, "/Q"), true)).unwrap();
    let other_program = view_uninstall(&UninstallFacts {
        program_id: "HKLM|64|Other".to_owned(),
        ..uninstall_facts(command, true)
    })
    .unwrap();
    for other in [other_mode, other_args, other_program] {
        assert_ne!(base.code, other.code);
    }
}

#[test]
fn uninstall_names_that_could_mislead_are_escaped_and_need_the_box() {
    let command = quiet_command(
        "C:\\Program Files\\Vendor\\unins\u{202e}gpj.exe",
        "/S \"C:\\x\"\n/Y",
    );
    let facts = UninstallFacts {
        app_name: "Mozill\u{430} Firefox".to_owned(),
        signer: Some("Vendor\u{200b} Ltd".to_owned()),
        ..uninstall_facts(command, true)
    };
    let v = view_uninstall(&facts).unwrap();
    for line in every_line(&v) {
        assert_clean(line);
    }
    assert!(
        v.instruction.contains(r"Mozill\u{430}"),
        "{}",
        v.instruction
    );
    assert_eq!(ids(&v.attention), ["program", "exe", "args", "signer"]);
    assert!(v.attention[1].text.contains(r"unins\u{202e}gpj.exe"));
    assert!(v.attention[2].text.contains(r"\u{22}C:\x\u{22}\u{a}/Y"));
    assert!(v.summary.iter().any(|l| l.contains("hidden or look-alike")));
    assert!(v.verification.is_some());
    let pages = dialog::pages(&v);
    let last = pages.last().unwrap();
    assert_eq!(last.gated_button, Some(PRIMARY));
    taskdialog::check(&pages, PRIMARY).unwrap();
}

#[test]
fn uninstall_cut_command_is_attention_not_quietly_shortened() {
    let args = format!("/S {}", "x".repeat(900));
    let v = view_uninstall(&uninstall_facts(quiet_command(VENDOR_EXE, &args), true)).unwrap();
    assert_eq!(ids(&v.attention), ["args"]);
    assert!(v.attention[0].reasons.contains(&Reason::ShortenedName));
    assert!(v.verification.is_some());
}

#[test]
fn uninstall_refuses_a_command_without_a_program() {
    for exe in ["", "   "] {
        assert_eq!(
            view_uninstall(&uninstall_facts(quiet_command(exe, "/S"), true)),
            Err(ViewError::NoCommand)
        );
    }
}

// ---------------------------------------------------------------------------------------------------
// Backups before their retention ends (DECISIONS 2026-11-24).
// ---------------------------------------------------------------------------------------------------

#[test]
fn delete_backups_now_names_every_backup_with_its_change_and_says_what_is_given_up() {
    let backups: Vec<ExpiringBackup> = (1..=44)
        .map(|op| expiring_backup(op, &[&format!(r"reg\{op:06}.regbackup.json")], false))
        .chain(std::iter::once(ExpiringBackup {
            target: Target::Service {
                name: "VendorSvc".into(),
            },
            ..expiring_backup(
                45,
                &[r"reg\000045.regbackup.json", r"def\000045.json"],
                false,
            )
        }))
        .collect();
    let (bulk, user) = split_purge(&[], &backups);
    assert!(user.is_empty());
    let v = view_delete_backups_now(&bulk).unwrap();
    assert_eq!(v.variant, Variant::DeleteBackupsNow);
    assert_eq!(v.icon, super::view::Icon::Warning);
    assert_eq!(
        v.instruction,
        "Delete 45 registry backups now, before their retention ends? Undo can then no longer \
         restore these registry changes. This cannot be undone."
    );
    assert_eq!(v.button, "Delete 45 registry backups now, for good");
    assert_eq!((v.counts.items, v.counts.files), (45, 46));
    assert!(
        v.summary[0].starts_with("45 registry backups (46 backup files), "),
        "{}",
        v.summary[0]
    );
    // Its own sentence: what the backups are for, that this is early, and what Undo loses.
    assert_eq!(v.summary[1], DELETE_BACKUPS_NOW_WARNING);
    assert!(DELETE_BACKUPS_NOW_WARNING.contains("before their retention date"));
    assert!(
        DELETE_BACKUPS_NOW_WARNING.contains("Undo and History can no longer undo these changes")
    );
    assert!(DELETE_BACKUPS_NOW_WARNING.contains("stays removed"));
    assert_ne!(DELETE_BACKUPS_NOW_WARNING, DELETE_NOW_WARNING);
    for line in every_line(&v) {
        assert!(!line.contains("expired"), "not an expiry: {line}");
        assert!(
            !line.contains("Undo can put"),
            "not the sentence of quarantined items: {line}"
        );
    }
    // Every file of every backup is an attention entry that names the change; no "and N more".
    assert_eq!(v.attention.len(), 46);
    assert!(v.others.is_empty() && v.others_more.is_none());
    for (op, entry) in (1..=44).zip(&v.attention) {
        assert!(
            entry.text.contains(&format!(
                r#"Delete the backup of: "HKLM\SOFTWARE\Vendor\Key{op}""#
            )),
            "{}",
            entry.text
        );
        assert!(
            entry
                .text
                .contains(&format!(r#"backup file "reg\{op:06}.regbackup.json""#)),
            "{}",
            entry.text
        );
        assert!(entry.reasons.contains(&Reason::Irreversible));
    }
    assert!(
        v.attention[44]
            .text
            .contains(r#"Delete the backup of: service "VendorSvc""#),
        "{}",
        v.attention[44].text
    );
    assert!(v.attention[45].text.contains(r#""def\000045.json""#));
    assert_eq!(
        v.verification.as_deref(),
        Some("I reviewed the backups marked \u{26A0}")
    );
    let pages = dialog::pages(&v);
    assert_eq!(page_counts(&v), [40, 6]);
    taskdialog::check(&pages, PRIMARY).unwrap();
    assert!(pages[1].verification.is_some() && pages[1].buttons[0].id == PRIMARY);
    assert!(pages[0].buttons.is_empty());

    // Never the code of the purge dialog over the same units, nor a Delete now code over the same
    // ids.
    assert_ne!(v.code, view_purge(&bulk).unwrap().code);
    let same_ids: Vec<ExpiringItem> = (1..=45)
        .map(|op| expiring_item(op, r"C:\x", false))
        .collect();
    let (as_items, _) = split_purge(&same_ids, &[]);
    assert_ne!(v.code, view_delete_now(&as_items).unwrap().code);

    let one = view_delete_backups_now(&bulk[..1]).unwrap();
    assert_eq!(
        one.instruction,
        "Delete 1 registry backup now, before its retention ends? Undo can then no longer \
         restore this registry change. This cannot be undone."
    );
    assert_eq!(one.button, "Delete 1 registry backup now, for good");
    assert_eq!(one.summary[1], DELETE_BACKUPS_NOW_WARNING_ONE);
    assert_eq!(
        one.verification.as_deref(),
        Some("I reviewed the backup marked \u{26A0}")
    );
}

#[test]
fn delete_backups_now_keeps_user_data_apart_and_refuses_quarantined_items() {
    let backups = [
        expiring_backup(1, &[r"reg\000001.regbackup.json"], false),
        expiring_backup(2, &[r"reg\000002.regbackup.json"], true),
    ];
    let item = expiring_item(3, r"C:\Program Files\Vendor\a", false);
    assert_eq!(
        view_delete_backups_now(&[
            PurgeUnit::Backup(&backups[0]),
            PurgeUnit::Backup(&backups[1])
        ]),
        Err(ViewError::UserDataMisplaced(expiry(2).to_string()))
    );
    assert_eq!(
        view_delete_backups_now_user_data(PurgeUnit::Backup(&backups[0])),
        Err(ViewError::UserDataMisplaced(expiry(1).to_string()))
    );
    // A quarantined item is deleted early through the Delete now dialog, never through this one.
    assert_eq!(
        view_delete_backups_now(&[PurgeUnit::Backup(&backups[0]), PurgeUnit::Item(&item)]),
        Err(ViewError::NotABackup(expiry(3).to_string()))
    );
    let personal_item = expiring_item(4, r"C:\Users\u\Documents\Vendor", true);
    assert_eq!(
        view_delete_backups_now_user_data(PurgeUnit::Item(&personal_item)),
        Err(ViewError::NotABackup(expiry(4).to_string()))
    );
    assert_eq!(view_delete_backups_now(&[]), Err(ViewError::NothingToRun));
    assert_eq!(
        view_delete_backups_now(&[
            PurgeUnit::Backup(&backups[0]),
            PurgeUnit::Backup(&backups[0])
        ]),
        Err(ViewError::DuplicateUnit(expiry(1).to_string()))
    );
    let empty = expiring_backup(5, &[], false);
    assert_eq!(
        view_delete_backups_now(&[PurgeUnit::Backup(&empty)]),
        Err(ViewError::NoFiles(expiry(5).to_string()))
    );

    let v = view_delete_backups_now_user_data(PurgeUnit::Backup(&backups[1])).unwrap();
    assert_eq!(
        v.instruction,
        "Delete this registry backup of user data now, before its retention ends? Undo can then \
         no longer restore this registry change. This cannot be undone."
    );
    assert_eq!(v.button, "Delete 1 registry backup now, for good");
    assert_eq!(v.summary[1], DELETE_BACKUPS_NOW_WARNING_ONE);
    assert!(
        DELETE_BACKUPS_NOW_WARNING_ONE.contains("this change")
            && !DELETE_BACKUPS_NOW_WARNING_ONE.contains("these")
    );
    assert_eq!(v.attention.len(), 1);
    assert!(v.attention[0].reasons.contains(&Reason::UserData));
    taskdialog::check(&dialog::pages(&v), PRIMARY).unwrap();

    // Names cannot mislead here either: neither the change's nor the file's.
    let odd = ExpiringBackup {
        target: Target::RegKey {
            path: "HKLM\\SOFTWARE\\evil\u{202e}gpj\nSafe".into(),
        },
        ..expiring_backup(6, &["reg\\a\u{200b}b\n.json"], false)
    };
    let v = view_delete_backups_now(&[PurgeUnit::Backup(&odd)]).unwrap();
    for line in every_line(&v) {
        assert_clean(line);
    }
}

// ---------------------------------------------------------------------------------------------------
// Delete now: quarantined items before their retention ends.
// ---------------------------------------------------------------------------------------------------

#[test]
fn delete_now_names_every_item_and_says_what_is_given_up() {
    let items: Vec<ExpiringItem> = (1..=45)
        .map(|op| expiring_item(op, &format!(r"C:\Program Files\Vendor\part{op}"), false))
        .collect();
    let (bulk, user) = split_purge(&items, &[]);
    assert!(user.is_empty());
    let v = view_delete_now(&bulk).unwrap();
    assert_eq!(v.variant, Variant::DeleteNow);
    assert_eq!(v.icon, super::view::Icon::Warning);
    assert_eq!(
        v.instruction,
        "Delete 45 quarantined items now, before their retention ends? This cannot be undone."
    );
    assert_eq!(v.button, "Delete 45 items now, for good");
    assert_eq!((v.counts.items, v.counts.files), (45, 0));
    assert!(
        v.summary[0].starts_with("45 quarantined items, "),
        "{}",
        v.summary[0]
    );
    // Plainly: before the retention date, and Undo will no longer restore them.
    assert_eq!(v.summary[1], DELETE_NOW_WARNING);
    assert!(DELETE_NOW_WARNING.contains("before the retention date"));
    assert!(DELETE_NOW_WARNING.contains("Undo and History can no longer restore them"));
    for line in every_line(&v) {
        assert!(!line.contains("expired"), "not an expiry: {line}");
    }
    // Every item is an attention entry; there is no "and N more".
    assert_eq!(v.attention.len(), 45);
    assert!(v.others.is_empty() && v.others_more.is_none());
    for (op, entry) in (1..=45).zip(&v.attention) {
        assert!(
            entry
                .text
                .contains(&format!(r#"was "C:\Program Files\Vendor\part{op}""#)),
            "{}",
            entry.text
        );
        assert!(entry.reasons.contains(&Reason::Irreversible));
    }
    assert_eq!(
        v.verification.as_deref(),
        Some("I reviewed the items marked \u{26A0}")
    );
    let pages = dialog::pages(&v);
    assert_eq!(page_counts(&v), [40, 5]);
    taskdialog::check(&pages, PRIMARY).unwrap();
    assert!(pages[1].verification.is_some() && pages[1].buttons[0].id == PRIMARY);
    assert!(pages[0].buttons.is_empty());

    // Never the code of the purge dialog over the same units.
    assert_ne!(v.code, view_purge(&bulk).unwrap().code);

    let one = view_delete_now(&bulk[..1]).unwrap();
    assert_eq!(
        one.instruction,
        "Delete 1 quarantined item now, before its retention ends? This cannot be undone."
    );
    assert_eq!(one.button, "Delete 1 item now, for good");
}

#[test]
fn delete_now_keeps_user_data_apart_and_refuses_backups() {
    let items = [
        expiring_item(1, r"C:\Program Files\Vendor\a", false),
        expiring_item(2, r"C:\Users\u\Documents\Vendor", true),
    ];
    let backup = expiring_backup(3, &[r"reg\000003.regbackup.json"], false);
    let personal_backup = expiring_backup(4, &[r"reg\000004.regbackup.json"], true);
    assert_eq!(
        view_delete_now(&[PurgeUnit::Item(&items[0]), PurgeUnit::Item(&items[1])]),
        Err(ViewError::UserDataMisplaced(expiry(2).to_string()))
    );
    assert_eq!(
        view_delete_now_user_data(PurgeUnit::Item(&items[0])),
        Err(ViewError::UserDataMisplaced(expiry(1).to_string()))
    );
    // A backup is never deleted before its class is due: no "Delete now" dialog can name one.
    assert_eq!(
        view_delete_now(&[PurgeUnit::Item(&items[0]), PurgeUnit::Backup(&backup)]),
        Err(ViewError::BackupNotDue(expiry(3).to_string()))
    );
    assert_eq!(
        view_delete_now_user_data(PurgeUnit::Backup(&personal_backup)),
        Err(ViewError::BackupNotDue(expiry(4).to_string()))
    );
    assert_eq!(view_delete_now(&[]), Err(ViewError::NothingToRun));
    assert_eq!(
        view_delete_now(&[PurgeUnit::Item(&items[0]), PurgeUnit::Item(&items[0])]),
        Err(ViewError::DuplicateUnit(expiry(1).to_string()))
    );

    let v = view_delete_now_user_data(PurgeUnit::Item(&items[1])).unwrap();
    assert_eq!(
        v.instruction,
        "Delete this user data now, before its retention ends? This cannot be undone."
    );
    assert_eq!(v.button, "Delete 1 item now, for good");
    assert_eq!(v.summary[1], DELETE_NOW_WARNING_ONE);
    assert!(
        DELETE_NOW_WARNING_ONE.contains("this item") && !DELETE_NOW_WARNING_ONE.contains("them")
    );
    assert_eq!(v.attention.len(), 1);
    assert!(v.attention[0].reasons.contains(&Reason::UserData));
    assert_eq!(
        v.verification.as_deref(),
        Some("I reviewed the item marked \u{26A0}")
    );
    taskdialog::check(&dialog::pages(&v), PRIMARY).unwrap();

    // Names cannot mislead here either.
    let odd = expiring_item(5, "C:\\Users\\u\\evil\u{202e}gpj.exe\nSafe", false);
    let v = view_delete_now(&[PurgeUnit::Item(&odd)]).unwrap();
    for line in every_line(&v) {
        assert_clean(line);
    }
}
