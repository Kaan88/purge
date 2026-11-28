//! Sample consent views, one per variant of design 8, built by the real view functions from made-up
//! plans: what the preview harness (`examples/consent_preview.rs`, which includes this file by path)
//! and the tests of the toolkit dialog draw. Nothing here is in the broker binary: the module is
//! compiled for tests and for the example only, and no sample is ever run as a plan.

use purge_exec::expiry::{ExpiringBackup, ExpiringItem, ExpiryId};
use purge_exec::plan_in::{
    BoundPlan, ExecRequest, ExecSettings, Selection, bind, confirm_hash, selection_hash,
};
use purge_inventory::quiet::QuietCommand;
use purge_model::exec::op::OpId;
use purge_model::{
    Action, AppRef, Band, Candidate, CandidateId, Category, Decision, FileTime, Harm,
    InstallerKind, Origin, Reversibility, ScanMode, Target, Tool,
};
use purge_plan::emit::{ScanDoc, ScanSchema};
use purge_rpc::methods::RestorePoint;

use super::text::Stamp;
use super::view::{
    ConflictKind, ConsentView, Facts, PurgeUnit, RecoverFacts, RecoverKind, RestoreFacts,
    UninstallFacts, view, view_delete_backups_now, view_delete_now, view_delete_now_user_data,
    view_purge, view_purge_user_data, view_recover, view_restore, view_uninstall,
};

/// One sample: the name the harness takes on its command line, and the view.
pub struct Sample {
    /// The variant's name, lower case with hyphens.
    pub name: &'static str,
    /// What the dialog says.
    pub view: ConsentView,
}

const SESSION: &str = "20261115T101502Z-9f3a6c1d2b7e4a50";

struct Spec {
    id: String,
    target: Target,
    action: Action,
    band: Band,
    preselected: bool,
    category: Category,
    size: Option<u64>,
}

fn safe(id: &str, target: Target, action: Action, category: Category) -> Spec {
    Spec {
        id: id.to_owned(),
        target,
        action,
        band: Band::Safe,
        preselected: true,
        category,
        size: None,
    }
}

fn file(id: &str, path: &str) -> Spec {
    safe(
        id,
        Target::Path {
            path: path.to_owned(),
        },
        Action::Quarantine,
        Category::AppFiles,
    )
}

fn key(id: &str, path: &str, category: Category) -> Spec {
    safe(
        id,
        Target::RegKey {
            path: path.to_owned(),
        },
        Action::DeleteKey,
        category,
    )
}

fn user_data(id: &str, path: &str) -> Spec {
    Spec {
        band: Band::Likely,
        preselected: false,
        category: Category::UserData,
        ..file(id, path)
    }
}

impl Spec {
    fn size(mut self, bytes: u64) -> Spec {
        self.size = Some(bytes);
        self
    }

    fn build(self) -> Candidate {
        Candidate {
            id: CandidateId(self.id),
            target: self.target,
            action: self.action,
            owner: AppRef {
                program_id: "HKLM|64|VendorApp".parse().expect("a program id"),
                display_name: "Vendor App".into(),
            },
            origin: Origin::Scanner,
            scanner: "SAMPLE".into(),
            category: self.category,
            evidence: Vec::new(),
            blockers: Vec::new(),
            harm: Harm::Low,
            reversibility: Reversibility::Full,
            children: Vec::new(),
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
                explanation: "sample".into(),
            }),
        }
    }
}

fn plan(specs: Vec<Spec>) -> BoundPlan {
    let items: Vec<Candidate> = specs.into_iter().map(Spec::build).collect();
    let ids: Vec<CandidateId> = items.iter().map(|c| c.id.clone()).collect();
    let policy_version = "m1a.6".to_owned();
    let mode = ScanMode::Post;
    let scan = ScanDoc {
        schema: ScanSchema,
        app: "vendor-app".into(),
        tool: Tool::Purge,
        mode,
        plan_hash: purge_plan::hash::plan_hash(&items, &policy_version, mode),
        policy_version,
        items,
        absorbed: Vec::new(),
    };
    let confirm = confirm_hash(
        scan.plan_hash.parse().expect("a plan hash"),
        selection_hash(&ids),
    )
    .to_string();
    bind(&ExecRequest {
        scan,
        confirm,
        selection: Selection::Ids(ids),
        allow_irreversible: true,
        settings: ExecSettings::default(),
    })
    .expect("the sample plan binds")
}

fn facts(delete_after: bool, restore_point: bool) -> Facts {
    Facts {
        delete_after,
        app_name: "Mozilla Firefox".into(),
        restorable_until: Some(Stamp {
            year: 2026,
            month: 12,
            day: 21,
            hour: 0,
            minute: 0,
        }),
        restore_point,
    }
}

/// Files, registry, a package, one user-data folder, one large cache and one item the user ticked.
fn mixed() -> BoundPlan {
    plan(vec![
        file("c1", r"C:\Program Files\Mozilla Firefox").size(212 << 20),
        key(
            "c2",
            r"HKLM\SOFTWARE\Mozilla\Mozilla Firefox",
            Category::Registration,
        ),
        user_data("c3", r"C:\Users\kaan\Documents\Firefox exports").size(3 << 20),
        file(
            "c4",
            r"C:\Users\kaan\AppData\Local\Mozilla\Firefox\Profiles\x1.default\cache2",
        )
        .size(2 << 30),
        key(
            "c5",
            r"HKLM\SOFTWARE\Classes\FirefoxHTML-308046B0AF4A39CB",
            Category::Association,
        ),
        safe(
            "c6",
            Target::RegValue {
                path: r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run"
                    .into(),
                name: "Mozilla-Firefox-Updater".into(),
            },
            Action::DeleteValue,
            Category::Startup,
        ),
        Spec {
            band: Band::Weak,
            preselected: false,
            ..file("c7", r"C:\Tools\firefox-portable")
        },
    ])
}

/// Only what Purge chose as safe: no attention entry, so no box.
fn plain() -> BoundPlan {
    plan(vec![
        file("p1", r"C:\Program Files\Vendor").size(48 << 20),
        key("p2", r"HKLM\SOFTWARE\Vendor", Category::Registration),
        file("p3", r"C:\ProgramData\Vendor\logs").size(1 << 20),
    ])
}

/// `n` user-data values: a list that scrolls far.
fn long(n: usize) -> BoundPlan {
    plan(
        (0..n)
            .map(|i| {
                safe(
                    &format!("u-{i:04}"),
                    Target::RegValue {
                        path: r"HKLM\SOFTWARE\Vendor\Profiles".into(),
                        name: format!("Profile {i:04}"),
                    },
                    Action::DeleteValue,
                    Category::UserData,
                )
            })
            .collect(),
    )
}

/// Names that try to mislead: a right-to-left override, a line break, a look-alike and a name
/// longer than the cut. And one that does not: a folder named wholly in another script, which the
/// view shows as it is and a renderer with a fixed set of fonts may have no glyphs for (review B1;
/// `Sheet::drawable`). It is the only text of any sample outside ASCII that reaches a sheet.
fn hostile() -> BoundPlan {
    plan(vec![
        file("h1", "C:\\Users\\kaan\\Documents\\invoice\u{202E}fdp.exe"),
        file("h2", "C:\\Program Files\\Vendor\\safe\nUser data: none"),
        file("h3", "C:\\Program Files\\Micr\u{43E}soft\\Edge"),
        file(
            "h4",
            &format!(r"C:\Program Files\Vendor\{}", "long-name-".repeat(30)),
        ),
        file(
            "h5",
            "C:\\Users\\kaan\\Documents\\\u{65e5}\u{672c}\u{8a9e}\u{306e}\u{30e1}\u{30e2}",
        ),
    ])
}

fn session() -> BoundPlan {
    plan(vec![
        file("a", r"C:\Program Files\Vendor"),
        key("b", r"HKLM\SOFTWARE\Vendor", Category::Registration),
        user_data("c", r"C:\Users\kaan\Documents\Vendor"),
        safe(
            "d",
            Target::AppxPackage {
                full_name: "Vendor.App_1.0.0.0_x64__abcdefghijklm".into(),
            },
            Action::RemovePackage,
            Category::Package,
        ),
    ])
}

fn recover(kind: RecoverKind, ops: &[u32]) -> ConsentView {
    view_recover(
        &session(),
        &RecoverFacts {
            kind,
            app_name: "Vendor App".into(),
            session: SESSION.into(),
            started: Some(Stamp {
                year: 2026,
                month: 11,
                day: 15,
                hour: 10,
                minute: 15,
            }),
            done: 1,
            total: 4,
            ops: ops.iter().copied().map(OpId).collect(),
        },
    )
    .expect("the recover sample")
}

fn expiry(op: u32) -> ExpiryId {
    ExpiryId {
        session: SESSION.parse().expect("a session id"),
        op: OpId(op),
    }
}

fn item(op: u32, original: &str, user_data: bool) -> ExpiringItem {
    ExpiringItem {
        id: expiry(op),
        item: CandidateId(format!("c-{op}")),
        original_path: original.into(),
        quarantine_path: format!(r"C:\ProgramData\Purge\quarantine\{SESSION}\{op}\item"),
        expires: FileTime(0),
        bytes: 2048 * u64::from(op),
        is_dir: op % 2 == 0,
        user_data,
        unfinished: false,
    }
}

fn backup(op: u32, files: &[&str], user_data: bool) -> ExpiringBackup {
    ExpiringBackup {
        id: expiry(op),
        item: CandidateId(format!("c-{op}")),
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

fn uninstall(quiet: bool, signer: Option<&str>) -> ConsentView {
    view_uninstall(&UninstallFacts {
        app_name: "Mozilla Firefox".to_owned(),
        program_id: "HKLM|64|Mozilla Firefox 132.0 (x64 en-US)".to_owned(),
        command: QuietCommand {
            exe: r"C:\Program Files\Mozilla Firefox\uninstall\helper.exe".to_owned(),
            args: if quiet {
                "/S".to_owned()
            } else {
                String::new()
            },
            generated: false,
            kind: InstallerKind::Nsis,
        },
        quiet,
        signer: signer.map(str::to_owned),
        restore_point: Some(RestorePoint::HighRisk),
    })
    .expect("the uninstall sample")
}

/// Every sample, in the order of design 8.
pub fn all() -> Vec<Sample> {
    let s = |name, view| Sample { name, view };
    let items: Vec<ExpiringItem> = (1..=90)
        .map(|op| item(op, &format!(r"C:\Program Files\Vendor\part{op}"), false))
        .collect();
    let backups = [
        backup(
            91,
            &[r"reg\000091.regbackup.json", r"reg\000091.regbackup.1.json"],
            false,
        ),
        backup(92, &[r"pkg\000092.definition.json"], false),
    ];
    let expired: Vec<PurgeUnit<'_>> = items
        .iter()
        .map(PurgeUnit::Item)
        .chain(backups.iter().map(PurgeUnit::Backup))
        .collect();
    let private = item(7, r"C:\Users\kaan\Documents\Vendor projects", true);
    let quarantined: Vec<ExpiringItem> = (1..=3)
        .map(|op| item(op, &format!(r"C:\Program Files\Vendor\bin{op}"), false))
        .collect();
    let quarantined_units: Vec<PurgeUnit<'_>> = quarantined.iter().map(PurgeUnit::Item).collect();
    let early: Vec<ExpiringBackup> = (1..=3)
        .map(|op| backup(op, &[&format!(r"reg\{op:06}.regbackup.json")], false))
        .collect();
    let early_units: Vec<PurgeUnit<'_>> = early.iter().map(PurgeUnit::Backup).collect();
    vec![
        s("uninstall", uninstall(true, Some("Mozilla Corporation"))),
        s("uninstall-interactive", uninstall(false, None)),
        s(
            "quarantine",
            view(&mixed(), &facts(false, true)).expect("the quarantine sample"),
        ),
        s(
            "quarantine-plain",
            view(&plain(), &facts(false, false)).expect("the plain sample"),
        ),
        s(
            "quarantine-delete-after",
            view(&mixed(), &facts(true, false)).expect("the delete-after sample"),
        ),
        s(
            "quarantine-long",
            view(&long(200), &facts(false, false)).expect("the long sample"),
        ),
        s(
            "hostile",
            view(&hostile(), &facts(false, false)).expect("the hostile sample"),
        ),
        s(
            "restore",
            view_restore(
                &session(),
                &RestoreFacts {
                    app_name: "Vendor App".into(),
                    ops: vec![OpId(1), OpId(2), OpId(3)],
                    conflicts: vec![
                        (OpId(1), ConflictKind::WillOverwrite),
                        (OpId(3), ConflictKind::PlaceTaken),
                    ],
                },
            )
            .expect("the restore sample"),
        ),
        s("recover-resume", recover(RecoverKind::Resume, &[2, 3, 4])),
        s("recover-rollback", recover(RecoverKind::Rollback, &[1, 3])),
        s("recover-retry-held", recover(RecoverKind::RetryHeld, &[1])),
        s("purge", view_purge(&expired).expect("the purge sample")),
        s(
            "purge-user-data",
            view_purge_user_data(PurgeUnit::Item(&private)).expect("the user-data sample"),
        ),
        s(
            "delete-now",
            view_delete_now(&quarantined_units).expect("the delete-now sample"),
        ),
        s(
            "delete-now-user-data",
            view_delete_now_user_data(PurgeUnit::Item(&private))
                .expect("the delete-now user-data sample"),
        ),
        s(
            "delete-backups-now",
            view_delete_backups_now(&early_units).expect("the delete-backups sample"),
        ),
    ]
}
