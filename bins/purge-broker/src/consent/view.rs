//! The consent view model (design 8): what the dialog says, built from the frozen [`BoundPlan`] (or, for
//! a purge, the broker's own expiry listing) and the broker's own facts, and from nothing else. Pure:
//! it reads nothing and changes nothing; [`super::dialog`] only draws it.
//!
//! Five variants: [`view`] (quarantine, `plan.execute`), [`view_restore`] (`undo.run`),
//! [`view_recover`] (`journal.resume`, `.rollback`, `.retry_held`), [`view_purge`] with
//! [`view_purge_user_data`] (`quarantine.purge`) and [`view_uninstall`] (`uninstall.run`).
//!
//! # What the dialog shows is what will run
//!
//! Each selected item is drawn from the executor op it resolved to ([`BoundItem::exec_op`]): its verb
//! and its target are the op's, not a second reading of the scan. An item without an op (the run
//! journals it as skipped) is shown as "Leave alone". Counts, groups and the button count only items
//! with an op. The code is the short code of the confirm hash of the plan and the shown selection, so it
//! is the one `plan.create` gave the UI. [`ConsentView::describes_plan`] lets the handler check, right
//! before it runs, that the view was drawn from the very plan it is about to run.
//!
//! # Attention
//!
//! An entry is an attention entry, listed in full, never cut and never folded into "and N more", when
//! it is user data, was ticked by the user (not chosen by Purge as Safe), is over 1 GB, cannot be put
//! back, has an absorbed item inside it that needs attention (those are listed as entries of their own,
//! because they go with it), will conflict on restore, or when its name is shown with escapes, with
//! something left out, or is a path whose last component is wholly in a look-alike script
//! ([`super::text`]). Which of these apply depends on the variant ([`Rules`]).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use purge_exec::expiry::{ExpiringBackup, ExpiringItem, ExpiryId};
use purge_exec::plan_in::{BoundItem, BoundPlan, confirm_hash, selection_hash};
use purge_inventory::quiet::QuietCommand;
use purge_model::exec::op::{ExecOp, OpId, Sha256Hex};
use purge_model::{Band, Candidate, CandidateId, Category, Target};
use purge_rpc::methods::{ConfirmCode, RestorePoint};

use super::text::{
    BULLET, Flags, MARK, SEP, Shown, Stamp, count, grouped, quote, quote_line, shown, size,
};

/// Entries on one page of the attention list.
pub const PAGE_ENTRIES: usize = 40;
/// Characters on one page of the attention list: a page closes early rather than grow beyond this.
pub const PAGE_CHARS: usize = 12_000;
/// Other (not attention) items named in the expanded information.
pub const OTHER_SHOWN: usize = 100;
/// Characters of the expanded information.
pub const OTHER_CHARS: usize = 12_000;
/// An item over this many bytes needs attention.
pub const LARGE_BYTES: u64 = 1 << 30;

/// Which dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// `plan.execute`: move the selected leftovers to quarantine.
    Quarantine,
    /// `undo.run`: put items back.
    Restore,
    /// `journal.resume`, `journal.rollback`, `journal.retry_held`.
    Recover(RecoverKind),
    /// `quarantine.purge`: delete expired items for good.
    Purge,
    /// `quarantine.purge` of quarantined items whose retention has not ended: delete them now, for
    /// good, because the user asked.
    DeleteNow,
    /// `uninstall.run`: start a program's own uninstaller as administrator.
    Uninstall,
}

/// What a recovery does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverKind {
    /// Finish the interrupted cleanup.
    Resume,
    /// Put back what the interrupted cleanup already did.
    Rollback,
    /// Try the items that were held (locked) again.
    RetryHeld,
}

/// What restoring finds in an item's place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    /// Something is there now and the restore replaces it.
    WillOverwrite,
    /// Something is there now and the restore skips the item.
    PlaceTaken,
}

/// Why an entry needs attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The plan item is user data.
    UserData,
    /// An item absorbed into it, which goes with it, needs attention.
    Inside,
    /// The user ticked it; Purge did not choose it as Safe.
    NotChosen,
    /// Over 1 GB.
    Large,
    /// It cannot be put back.
    Irreversible,
    /// Restore: something is in its place.
    Conflict(ConflictKind),
    /// Its name is shown with `\u{...}` escapes.
    EscapedName,
    /// Its last path component is wholly in a script that borrows Latin shapes.
    LookAlikeName,
    /// Part of its name is left out.
    ShortenedName,
}

impl Reason {
    /// The words the dialog uses.
    pub fn label(self) -> &'static str {
        match self {
            Reason::UserData => "user data",
            Reason::Inside => "contains items that need attention, listed separately",
            Reason::NotChosen => "ticked by you, not chosen by Purge",
            Reason::Large => "over 1 GB",
            Reason::Irreversible => "cannot be put back",
            Reason::Conflict(ConflictKind::WillOverwrite) => {
                "something is there now, it will be replaced"
            }
            Reason::Conflict(ConflictKind::PlaceTaken) => {
                "something is there now, this item will be skipped"
            }
            Reason::EscapedName => "name has hidden or look-alike characters",
            Reason::LookAlikeName => "name is written in a look-alike script",
            Reason::ShortenedName => "name is shortened",
        }
    }
}

/// A kind of thing, for the counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    /// Files and folders.
    Files,
    /// Registry keys and values.
    Registry,
    /// File and protocol associations.
    Associations,
    /// Shell extensions and COM registrations.
    ShellCom,
    /// Services and scheduled tasks.
    ServicesTasks,
    /// Firewall rules.
    Firewall,
    /// Packages.
    Packages,
    /// Usage traces.
    Privacy,
}

impl Group {
    /// The words the dialog uses.
    pub fn label(self) -> &'static str {
        match self {
            Group::Files => "files and folders",
            Group::Registry => "registry keys and values",
            Group::Associations => "file and protocol associations",
            Group::ShellCom => "shell and COM entries",
            Group::ServicesTasks => "services and scheduled tasks",
            Group::Firewall => "firewall rules",
            Group::Packages => "packages",
            Group::Privacy => "privacy traces",
        }
    }

    fn of(target: &Target, category: Category) -> Group {
        match target {
            Target::Service { .. } | Target::Task { .. } => Group::ServicesTasks,
            Target::FirewallRule { .. } => Group::Firewall,
            Target::AppxPackage { .. } => Group::Packages,
            _ if category == Category::Privacy => Group::Privacy,
            Target::Path { .. } => Group::Files,
            _ => match category {
                Category::Association => Group::Associations,
                Category::ShellCom => Group::ShellCom,
                _ => Group::Registry,
            },
        }
    }
}

/// Items and bytes of one [`Group`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupCount {
    /// The group.
    pub group: Group,
    /// Items with an op in it.
    pub items: u32,
    /// Bytes the scan measured for them.
    pub bytes: u64,
}

/// Counts of what the dialog is about. Only items that will act are counted in `items`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counts {
    /// Items that will act (the number on the button).
    pub items: u32,
    /// Selected items the run will leave alone (no scan-time identity).
    pub skipped: u32,
    /// Of `items`, chosen by Purge as Safe.
    pub chosen: u32,
    /// Of `items`, ticked by the user.
    pub ticked: u32,
    /// Of `items`, without an undo.
    pub irreversible: u32,
    /// Absorbed items that go with the items.
    pub inside: u32,
    /// Bytes the scan measured for `items` (a purge: the bytes the journal recorded).
    pub bytes: u64,
    /// Per group, in a fixed order, only groups with items.
    pub groups: Vec<GroupCount>,
    /// A purge: backup files.
    pub files: u32,
}

/// One line of the attention list or of the expanded information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The candidate id (a purge: the expiry id), for tests and logs; never shown.
    pub id: String,
    /// The line.
    pub text: String,
    /// Why it needs attention; empty for the other items.
    pub reasons: Vec<Reason>,
}

/// The icon of the dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    /// The shield.
    Shield,
    /// The warning triangle.
    Warning,
}

/// Everything the dialog says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentView {
    /// Which dialog.
    pub variant: Variant,
    /// The code the footer shows and `consent.shown` carries.
    pub code: ConfirmCode,
    /// The icon.
    pub icon: Icon,
    /// The main instruction.
    pub instruction: String,
    /// The lines at the top of the first page.
    pub summary: Vec<String>,
    /// Every attention entry, never cut and never summarised.
    pub attention: Vec<Entry>,
    /// The first [`OTHER_SHOWN`] other items.
    pub others: Vec<Entry>,
    /// "and N more of the same kinds ...", when `others` is not all of them.
    pub others_more: Option<String>,
    /// The text of the verification box; the box is there when there is an attention entry.
    pub verification: Option<String>,
    /// The label of the button that approves.
    pub button: String,
    /// The footer.
    pub footer: String,
    /// The counts.
    pub counts: Counts,
    /// The plan hash of the plan the view was drawn from (the plan variants).
    pub plan_hash: Option<Sha256Hex>,
    /// The hash of the selection that is shown.
    pub selection_hash: Option<Sha256Hex>,
    /// The command an uninstall dialog was drawn from (`uninstall.run`).
    pub uninstall: Option<UninstallDrawn>,
}

/// What an uninstall dialog was drawn from: the command exactly as the session froze it, and the mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallDrawn {
    /// The frozen command; the dialog shows its program and its arguments.
    pub command: QuietCommand,
    /// Whether the quiet command was asked for.
    pub quiet: bool,
}

impl ConsentView {
    /// Whether this is an uninstall dialog drawn from exactly `command` and `quiet`. The handler asks
    /// right before it starts the command it is about to run, and again after the answer.
    pub fn describes_uninstall(&self, command: &QuietCommand, quiet: bool) -> bool {
        self.variant == Variant::Uninstall
            && self
                .uninstall
                .as_ref()
                .is_some_and(|d| d.quiet == quiet && d.command == *command)
    }

    /// The attention entries in pages: at most [`PAGE_ENTRIES`] each and at most [`PAGE_CHARS`]
    /// characters (an entry always fits a page alone). No entry is left out.
    pub fn attention_pages(&self) -> Vec<&[Entry]> {
        let mut pages = Vec::new();
        let mut start = 0;
        let mut chars = 0;
        for (i, e) in self.attention.iter().enumerate() {
            let len = e.text.chars().count() + 1;
            if i > start && (i - start >= PAGE_ENTRIES || chars + len > PAGE_CHARS) {
                pages.push(&self.attention[start..i]);
                start = i;
                chars = 0;
            }
            chars += len;
        }
        if start < self.attention.len() {
            pages.push(&self.attention[start..]);
        }
        pages
    }

    /// Whether the view was drawn from exactly this plan and its whole selection (not for a partial
    /// restore). The handler asks before it runs the plan it is about to execute.
    pub fn describes_plan(&self, plan: &BoundPlan) -> bool {
        self.plan_hash == Some(plan.plan_hash())
            && self.selection_hash == Some(plan.selection_hash())
            && self.counts.items + self.counts.skipped == plan.items().len() as u32
    }
}

/// Why no view could be built. The handler declines without showing anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewError {
    /// No selected item has an op: nothing would change.
    NothingToRun,
    /// An op id the plan does not hold.
    UnknownOp(OpId),
    /// An op named twice.
    DuplicateOp(OpId),
    /// An op that cannot be put back (no op was run for it, or it has no inverse).
    NotRestorable(OpId),
    /// A bound item whose candidate is missing from the scan document.
    Inconsistent(OpId),
    /// A purge dialog over user data with other items, or a user-data dialog over something else.
    UserDataMisplaced(String),
    /// A purge unit named twice.
    DuplicateUnit(String),
    /// A backup unit that names no file.
    NoFiles(String),
    /// A backup unit in a "Delete now" dialog: a backup is never deleted before its class is due.
    BackupNotDue(String),
    /// An uninstall command that names no program.
    NoCommand,
}

impl fmt::Display for ViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ViewError::NothingToRun => f.write_str("no selected item would change anything"),
            ViewError::UnknownOp(op) => write!(f, "op {op} is not an item of the plan"),
            ViewError::DuplicateOp(op) => write!(f, "op {op} is named twice"),
            ViewError::NotRestorable(op) => write!(f, "op {op} cannot be put back"),
            ViewError::Inconsistent(op) => write!(f, "op {op} has no candidate in the scan"),
            ViewError::UserDataMisplaced(id) => {
                write!(f, "{id}: user data belongs in a dialog of its own")
            }
            ViewError::DuplicateUnit(id) => write!(f, "{id} is named twice"),
            ViewError::NoFiles(id) => write!(f, "{id} names no backup file"),
            ViewError::BackupNotDue(id) => {
                write!(f, "{id}: a backup is not deleted before its retention ends")
            }
            ViewError::NoCommand => f.write_str("the uninstall command names no program"),
        }
    }
}

impl std::error::Error for ViewError {}

// ---------------------------------------------------------------------------------------------------
// Facts of the broker
// ---------------------------------------------------------------------------------------------------

/// What the broker knows for a quarantine dialog besides the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The program the leftovers belong to, as the broker's own inventory names it.
    pub app_name: String,
    /// When the quarantine ends; `None` makes no promise.
    pub restorable_until: Option<Stamp>,
    /// Whether the run will ask for a restore point first.
    pub restore_point: bool,
}

/// What the broker knows for a restore dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreFacts {
    /// The program, as the broker's own inventory names it.
    pub app_name: String,
    /// The ops to put back, in the order they will be put back.
    pub ops: Vec<OpId>,
    /// Ops whose place is taken now, with what the restore does about it. Each must be in `ops`.
    pub conflicts: Vec<(OpId, ConflictKind)>,
}

/// What the broker knows for a recovery dialog, from the session's journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverFacts {
    /// What is asked.
    pub kind: RecoverKind,
    /// The program, as the broker's own inventory names it.
    pub app_name: String,
    /// The interrupted session.
    pub session: String,
    /// When it started.
    pub started: Option<Stamp>,
    /// Items the journal says are done.
    pub done: u32,
    /// Items in all.
    pub total: u32,
    /// The ops this request will change, in order: for a resume the ones still to do, for a rollback
    /// the ones to put back, for a retry the held ones.
    pub ops: Vec<OpId>,
}

// ---------------------------------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Verb {
    Exec,
    PutBack,
}

/// Which attention reasons a variant applies.
#[derive(Clone, Copy)]
struct Rules {
    verb: Verb,
    not_chosen: bool,
    irreversible: bool,
    user_data: bool,
    large: bool,
}

struct Row {
    plain: Entry,
    attention: Option<Entry>,
    children: Vec<Entry>,
    group: Option<(Group, u64)>,
    chosen: bool,
    irreversible: bool,
    inside: u32,
    flags: Flags,
}

fn verb_of(op: &ExecOp) -> &'static str {
    match op {
        ExecOp::QuarantineMove { .. } => "Move to quarantine",
        ExecOp::RemoveDirIfEmpty { .. } => "Remove folder if it is empty",
        ExecOp::DeleteKeyTree { .. } => "Delete registry key and everything below it",
        ExecOp::DeleteKeyIfEmpty { .. } => "Delete registry key if it is empty",
        ExecOp::DeleteValue { .. } => "Delete registry value",
        ExecOp::EditSegment { .. } => "Remove one entry from a registry value",
        ExecOp::RemovePackage { .. } => "Remove package for good",
        ExecOp::DeleteService { .. } => "Delete service",
        ExecOp::DeleteTask { .. } => "Delete scheduled task",
        ExecOp::DeleteFirewallRule { .. } => "Delete firewall rule",
    }
}

const VERB_SKIPPED: &str = "Leave alone (changed since the scan)";
const VERB_NOT_ACKNOWLEDGED: &str = "Leave alone (a removal without undo was not confirmed)";
const VERB_PUT_BACK: &str = "Put back";
const VERB_WITH_PARENT: &str = "Taken with its parent";
const VERB_BACK_WITH_PARENT: &str = "Put back with its parent";

fn band_name(band: Option<Band>) -> &'static str {
    match band {
        Some(Band::Safe) => "Safe",
        Some(Band::Likely) => "Likely",
        Some(Band::Weak) => "Weak",
        Some(Band::Blocked) => "Blocked",
        None => "not rated",
    }
}

fn value_name(name: &str) -> Shown {
    if name.is_empty() {
        Shown {
            text: "(default)".to_owned(),
            flags: Flags::default(),
        }
    } else {
        quote(name)
    }
}

/// How the dialog names a target: always from the target's own fields, every piece through
/// [`quote`].
fn target_text(target: &Target) -> Shown {
    let join = |parts: Vec<(&str, Shown)>| {
        let mut flags = Flags::default();
        let mut out = String::new();
        for (label, s) in parts {
            if !out.is_empty() {
                out.push(' ');
            }
            if !label.is_empty() {
                out.push_str(label);
                out.push(' ');
            }
            out.push_str(&s.text);
            flags.merge(s.flags);
        }
        Shown { text: out, flags }
    };
    match target {
        Target::Path { path } | Target::RegKey { path } => quote(path),
        Target::RegValue { path, name } | Target::RegValueChanged { path, name, .. } => {
            join(vec![("", quote(path)), ("value", value_name(name))])
        }
        Target::RegMultiSzSegment {
            path,
            name,
            segment,
            index,
        } => {
            let mut parts = vec![
                ("", quote(path)),
                ("value", value_name(name)),
                ("entry", quote(segment)),
            ];
            if let Some(index) = index {
                parts.push((
                    "at position",
                    Shown {
                        text: index.to_string(),
                        flags: Flags::default(),
                    },
                ));
            }
            join(parts)
        }
        Target::Service { name } => join(vec![("service", quote(name))]),
        Target::Task { path } => join(vec![("task", quote(path))]),
        Target::FirewallRule { id } => join(vec![("rule", quote(id))]),
        Target::AppxPackage { full_name } => join(vec![("package", quote(full_name))]),
    }
}

fn name_reasons(flags: Flags, reasons: &mut Vec<Reason>) {
    if flags.escaped {
        reasons.push(Reason::EscapedName);
    }
    if flags.look_alike {
        reasons.push(Reason::LookAlikeName);
    }
    if flags.shortened {
        reasons.push(Reason::ShortenedName);
    }
}

/// `mark verb: target | size | band | n inside | reason; reason` (the bars are the middle-dot separators).
fn line(
    mark: &str,
    verb: &str,
    target: &str,
    bytes: Option<u64>,
    band: Option<&str>,
    inside: usize,
    reasons: &[Reason],
) -> String {
    let mut out = format!("{mark} {verb}: {target}");
    if let Some(bytes) = bytes {
        out.push_str(SEP);
        out.push_str(&size(bytes));
    }
    if let Some(band) = band {
        out.push_str(SEP);
        out.push_str(band);
    }
    if inside > 0 {
        out.push_str(SEP);
        out.push_str(&count(inside as u64, "item inside it", "items inside it"));
    }
    if !reasons.is_empty() {
        out.push_str(SEP);
        let labels: Vec<&str> = reasons.iter().map(|r| r.label()).collect();
        out.push_str(&labels.join("; "));
    }
    out
}

/// The absorbed candidates that go with `candidate`, nested ones included, each once, nearest first.
fn descendants<'a>(plan: &'a BoundPlan, candidate: &'a Candidate) -> Vec<&'a Candidate> {
    let mut seen: HashSet<&CandidateId> = HashSet::new();
    seen.insert(&candidate.id);
    let mut out = Vec::new();
    let mut queue = VecDeque::from([candidate]);
    while let Some(c) = queue.pop_front() {
        for child in plan.children(c) {
            if seen.insert(&child.id) {
                out.push(child);
                queue.push_back(child);
            }
        }
    }
    out
}

/// The entry for a candidate that goes with `parent` (absorbed into it or merely nested in it), and
/// the flags of its shown target (review M4).
fn child_row(child: &Candidate, rules: Rules) -> (Option<Entry>, Flags) {
    let child_target = target_text(&child.target);
    let mut reasons = Vec::new();
    if rules.user_data && purge_plan::collapse::is_user_data(child) {
        reasons.push(Reason::UserData);
    }
    if rules.large && child.size_bytes.is_some_and(|b| b > LARGE_BYTES) {
        reasons.push(Reason::Large);
    }
    name_reasons(child_target.flags, &mut reasons);
    let verb = match rules.verb {
        Verb::Exec => VERB_WITH_PARENT,
        Verb::PutBack => VERB_BACK_WITH_PARENT,
    };
    let entry = (!reasons.is_empty()).then(|| Entry {
        id: child.id.0.clone(),
        text: line(
            MARK,
            verb,
            &child_target.text,
            child.size_bytes,
            None,
            0,
            &reasons,
        ),
        reasons,
    });
    (entry, child_target.flags)
}

fn build_rows(
    plan: &BoundPlan,
    items: &[&BoundItem],
    rules: Rules,
    conflicts: &HashMap<OpId, ConflictKind>,
) -> Result<Vec<Row>, ViewError> {
    let selected: HashSet<&CandidateId> = plan
        .items()
        .iter()
        .filter_map(|item| plan.candidate(item))
        .map(|candidate| &candidate.id)
        .collect();
    let mut rows = Vec::with_capacity(items.len());
    for item in items {
        let candidate = plan
            .candidate(item)
            .ok_or(ViewError::Inconsistent(item.op))?;
        let op = item.exec_op.as_ref();
        let target = op.map_or_else(|| candidate.target.clone(), ExecOp::target);
        let shown_target = target_text(&target);
        let mut flags = shown_target.flags;
        // A removal without an undo runs only when the plan carries the user's acknowledgement
        // (`BoundPlan::allow_irreversible`); without it the executor decides the item as not done.
        let acts = match (rules.verb, op) {
            (Verb::PutBack, op) => op.is_some(),
            (Verb::Exec, Some(op)) => !op.is_irreversible() || plan.allow_irreversible(),
            (Verb::Exec, None) => false,
        };
        let verb = match (rules.verb, op) {
            (Verb::PutBack, _) => VERB_PUT_BACK,
            (Verb::Exec, Some(op)) if acts => verb_of(op),
            (Verb::Exec, Some(_)) => VERB_NOT_ACKNOWLEDGED,
            (Verb::Exec, None) => VERB_SKIPPED,
        };
        let decision = candidate.decision.as_ref();
        let chosen = decision.is_some_and(|d| d.band == Band::Safe && d.preselected);
        let irreversible = acts && op.is_some_and(ExecOp::is_irreversible);

        // What goes with the item: the absorbed children, and every other candidate of the document
        // that nests in it without having been absorbed (review M4; `collapse` rule 3 keeps a
        // user-data descendant as an item of its own, so `children` does not name it).
        let below = descendants(plan, candidate);
        let listed: HashSet<&CandidateId> = below.iter().map(|child| &child.id).collect();
        let mut nested_extra: Vec<&Candidate> = Vec::new();
        for child in purge_plan::collapse::nested_candidates(
            candidate,
            &plan.scan().items,
            &plan.scan().absorbed,
        ) {
            // A selected item has a line of its own and an op of its own: it does not also ride here.
            if listed.contains(&child.id) || selected.contains(&child.id) {
                continue;
            }
            nested_extra.push(child);
        }
        let mut child_entries = Vec::new();
        let mut sees_user_data = false;
        for child in below.iter().copied().chain(nested_extra.iter().copied()) {
            sees_user_data |= rules.user_data && purge_plan::collapse::is_user_data(child);
            let (entry, child_flags) = child_row(child, rules);
            flags.merge(child_flags);
            if let Some(entry) = entry {
                child_entries.push(entry);
            }
        }

        let mut reasons = Vec::new();
        if rules.user_data && (purge_plan::collapse::is_user_data(candidate) || sees_user_data) {
            reasons.push(Reason::UserData);
        }
        if rules.not_chosen && !chosen {
            reasons.push(Reason::NotChosen);
        }
        if rules.large && candidate.size_bytes.is_some_and(|b| b > LARGE_BYTES) {
            reasons.push(Reason::Large);
        }
        if rules.irreversible && irreversible {
            reasons.push(Reason::Irreversible);
        }
        if let Some(kind) = conflicts.get(&item.op) {
            reasons.push(Reason::Conflict(*kind));
        }
        if !child_entries.is_empty() {
            reasons.push(Reason::Inside);
        }
        name_reasons(shown_target.flags, &mut reasons);

        let id = candidate.id.0.clone();
        let inside = below.len() + nested_extra.len();
        let plain = Entry {
            id: id.clone(),
            text: line(
                BULLET,
                verb,
                &shown_target.text,
                candidate.size_bytes,
                None,
                inside,
                &[],
            ),
            reasons: Vec::new(),
        };
        let attention = (!reasons.is_empty()).then(|| Entry {
            id,
            text: line(
                MARK,
                verb,
                &shown_target.text,
                candidate.size_bytes,
                Some(band_name(decision.map(|d| d.band))),
                inside,
                &reasons,
            ),
            reasons,
        });
        rows.push(Row {
            plain,
            attention,
            children: child_entries,
            group: acts.then(|| {
                (
                    Group::of(&target, candidate.category),
                    candidate.size_bytes.unwrap_or(0),
                )
            }),
            chosen,
            irreversible: rules.irreversible && irreversible,
            inside: inside as u32,
            flags,
        });
    }
    Ok(rows)
}

fn add_group(groups: &mut Vec<GroupCount>, group: Group, bytes: u64) {
    match groups.iter_mut().find(|g| g.group == group) {
        Some(g) => {
            g.items += 1;
            g.bytes += bytes;
        }
        None => groups.push(GroupCount {
            group,
            items: 1,
            bytes,
        }),
    }
}

fn counts_of(rows: &[Row]) -> Counts {
    let mut counts = Counts::default();
    for row in rows {
        match row.group {
            Some((group, bytes)) => {
                counts.items += 1;
                counts.bytes += bytes;
                if row.chosen {
                    counts.chosen += 1;
                } else {
                    counts.ticked += 1;
                }
                if row.irreversible {
                    counts.irreversible += 1;
                }
                add_group(&mut counts.groups, group, bytes);
            }
            None => counts.skipped += 1,
        }
        counts.inside += row.inside;
    }
    counts.groups.sort_by_key(|g| g.group);
    counts
}

/// The attention entries (each followed by the entries of what goes with it) and the others.
struct Split {
    attention: Vec<Entry>,
    others: Vec<Entry>,
    more: Option<String>,
    any_flags: Flags,
}

fn split(rows: Vec<Row>) -> Split {
    let mut attention = Vec::new();
    let mut plain: Vec<(Entry, Option<Group>)> = Vec::new();
    let mut any_flags = Flags::default();
    for row in rows {
        any_flags.merge(row.flags);
        match row.attention {
            Some(entry) => {
                attention.push(entry);
                attention.extend(row.children);
            }
            None => plain.push((row.plain, row.group.map(|g| g.0))),
        }
    }
    let mut others = Vec::new();
    let mut chars = 0;
    let mut shown_n = 0;
    for (entry, _) in &plain {
        let len = entry.text.chars().count() + 1;
        if shown_n >= OTHER_SHOWN || (shown_n > 0 && chars + len > OTHER_CHARS) {
            break;
        }
        chars += len;
        shown_n += 1;
        others.push(entry.clone());
    }
    let rest = &plain[shown_n..];
    let more = (!rest.is_empty()).then(|| {
        let mut per: Vec<GroupCount> = Vec::new();
        let mut unnamed = 0u32;
        for (_, group) in rest {
            match group {
                Some(g) => add_group(&mut per, *g, 0),
                None => unnamed += 1,
            }
        }
        per.sort_by_key(|g| g.group);
        let mut parts: Vec<String> = per
            .iter()
            .map(|g| format!("{} {}", grouped(u64::from(g.items)), g.group.label()))
            .collect();
        if unnamed > 0 {
            parts.push(count(
                u64::from(unnamed),
                "item left alone",
                "items left alone",
            ));
        }
        format!(
            "and {} more of the same kinds: {}.",
            grouped(rest.len() as u64),
            parts.join(", ")
        )
    });
    Split {
        attention,
        others,
        more,
        any_flags,
    }
}

fn group_lines(counts: &Counts, out: &mut Vec<String>) {
    for g in &counts.groups {
        let mut line = format!(
            "{}: {}",
            capitalised(g.group.label()),
            grouped(u64::from(g.items))
        );
        if g.bytes > 0 {
            line.push_str(&format!(" ({})", size(g.bytes)));
        }
        out.push(line);
    }
}

fn capitalised(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

const LEGEND: &str = "Names with hidden or look-alike characters show them as \\u{...}. A name \
                      longer than 80 characters keeps its start and end and says how much it leaves out.";

fn footer(code: ConfirmCode) -> String {
    format!("Shown by the administrator part of Purge. Code {code}.")
}

fn verification(attention: usize) -> Option<String> {
    match attention {
        0 => None,
        1 => Some(format!("I reviewed the item marked {MARK}")),
        _ => Some(format!("I reviewed the items marked {MARK}")),
    }
}

fn app(name: &str, summary: &mut Vec<String>) -> String {
    let q = quote(name);
    if !q.flags.is_plain() {
        summary.push(
            "The program name below has hidden or look-alike characters or is shortened; see the legend."
                .to_owned(),
        );
    }
    q.text
}

fn leftovers(n: u32) -> String {
    count(u64::from(n), "leftover", "leftovers")
}

fn items(n: u32) -> String {
    count(u64::from(n), "item", "items")
}

fn plan_code(plan: &BoundPlan, selection: Sha256Hex) -> ConfirmCode {
    ConfirmCode::of(&confirm_hash(plan.plan_hash(), selection))
}

/// The parts of a view that are not the entries.
struct Head {
    variant: Variant,
    code: ConfirmCode,
    icon: Icon,
    instruction: String,
    summary: Vec<String>,
    button: String,
    hashes: Option<(Sha256Hex, Sha256Hex)>,
}

fn assemble(head: Head, counts: Counts, rows: Vec<Row>) -> ConsentView {
    let split = split(rows);
    let mut summary = head.summary;
    if !split.any_flags.is_plain() {
        summary.push(LEGEND.to_owned());
    }
    ConsentView {
        variant: head.variant,
        code: head.code,
        icon: head.icon,
        instruction: head.instruction,
        summary,
        verification: verification(split.attention.len()),
        attention: split.attention,
        others: split.others,
        others_more: split.more,
        button: head.button,
        footer: footer(head.code),
        counts,
        plan_hash: head.hashes.map(|h| h.0),
        selection_hash: head.hashes.map(|h| h.1),
        uninstall: None,
    }
}

// ---------------------------------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------------------------------

/// The quarantine dialog of `plan.execute` (design 8.1), drawn from the frozen plan.
pub fn view(plan: &BoundPlan, facts: &Facts) -> Result<ConsentView, ViewError> {
    let all: Vec<&BoundItem> = plan.items().iter().collect();
    let rules = Rules {
        verb: Verb::Exec,
        not_chosen: true,
        irreversible: true,
        user_data: true,
        large: true,
    };
    let rows = build_rows(plan, &all, rules, &HashMap::new())?;
    let counts = counts_of(&rows);
    if counts.items == 0 {
        return Err(ViewError::NothingToRun);
    }
    let mut summary = Vec::new();
    let name = app(&facts.app_name, &mut summary);
    let n = counts.items;
    let (instruction, button, icon) = if counts.irreversible > 0 {
        (
            format!(
                "Remove {} of {name}? {} cannot be put back.",
                leftovers(n),
                grouped(u64::from(counts.irreversible))
            ),
            format!("Remove {}", items(n)),
            Icon::Warning,
        )
    } else {
        (
            format!("Move {} of {name} to quarantine?", leftovers(n)),
            format!("Move {} to quarantine", items(n)),
            Icon::Shield,
        )
    };
    if counts.ticked == 0 {
        summary.push(format!(
            "All {} chosen by Purge as safe.",
            grouped(u64::from(n))
        ));
    } else {
        summary.push(format!(
            "{} chosen by Purge as safe, {} ticked by you.",
            grouped(u64::from(counts.chosen)),
            grouped(u64::from(counts.ticked))
        ));
    }
    group_lines(&counts, &mut summary);
    if counts.inside > 0 {
        summary.push(format!(
            "{} more inside them go with them.",
            count(u64::from(counts.inside), "item", "items")
        ));
    }
    if counts.skipped > 0 {
        summary.push(format!(
            "Left alone: {}. Each line says why.",
            count(u64::from(counts.skipped), "listed item", "listed items")
        ));
    }
    if counts.irreversible > 0 {
        summary.push(format!(
            "{} cannot be put back after this; {} marked {MARK}.",
            count(u64::from(counts.irreversible), "item", "items"),
            if counts.irreversible == 1 {
                "it is"
            } else {
                "they are"
            }
        ));
    }
    if let Some(until) = facts.restorable_until {
        summary.push(if counts.irreversible > 0 {
            format!(
                "You can restore the rest from History & undo until {}.",
                until.date()
            )
        } else {
            format!(
                "You can restore everything from History & undo until {}.",
                until.date()
            )
        });
    }
    if facts.restore_point {
        summary.push("Windows is asked for a restore point first.".to_owned());
    }
    let code = plan_code(plan, plan.selection_hash());
    let head = Head {
        variant: Variant::Quarantine,
        code,
        icon,
        instruction,
        summary,
        button,
        hashes: Some((plan.plan_hash(), plan.selection_hash())),
    };
    Ok(assemble(head, counts, rows))
}

// ---------------------------------------------------------------------------------------------------
// Restore and recover
// ---------------------------------------------------------------------------------------------------

fn pick<'a>(
    plan: &'a BoundPlan,
    ops: &[OpId],
    need_restorable: bool,
) -> Result<Vec<&'a BoundItem>, ViewError> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(ops.len());
    for op in ops {
        if !seen.insert(*op) {
            return Err(ViewError::DuplicateOp(*op));
        }
        let item = plan.item(*op).ok_or(ViewError::UnknownOp(*op))?;
        if need_restorable && !item.exec_op.as_ref().is_some_and(|o| !o.is_irreversible()) {
            return Err(ViewError::NotRestorable(*op));
        }
        out.push(item);
    }
    Ok(out)
}

fn selection_of(plan: &BoundPlan, picked: &[&BoundItem]) -> Result<Sha256Hex, ViewError> {
    let mut ids = Vec::with_capacity(picked.len());
    for item in picked {
        ids.push(
            plan.candidate(item)
                .ok_or(ViewError::Inconsistent(item.op))?
                .id
                .clone(),
        );
    }
    Ok(selection_hash(&ids))
}

/// The restore dialog of `undo.run` (design 8.2): the ops that will be put back, those whose place is
/// taken as attention entries.
pub fn view_restore(plan: &BoundPlan, facts: &RestoreFacts) -> Result<ConsentView, ViewError> {
    let picked = pick(plan, &facts.ops, true)?;
    if picked.is_empty() {
        return Err(ViewError::NothingToRun);
    }
    let mut conflicts = HashMap::new();
    for (op, kind) in &facts.conflicts {
        if !facts.ops.contains(op) {
            return Err(ViewError::UnknownOp(*op));
        }
        conflicts.insert(*op, *kind);
    }
    let rules = Rules {
        verb: Verb::PutBack,
        not_chosen: false,
        irreversible: false,
        user_data: false,
        large: false,
    };
    let rows = build_rows(plan, &picked, rules, &conflicts)?;
    let counts = counts_of(&rows);
    let mut summary = Vec::new();
    let name = app(&facts.app_name, &mut summary);
    summary.push("Purge puts each item back where it was.".to_owned());
    group_lines(&counts, &mut summary);
    let replaced = conflicts
        .values()
        .filter(|k| **k == ConflictKind::WillOverwrite)
        .count();
    let skipped = conflicts.len() - replaced;
    if replaced > 0 {
        summary.push(format!(
            "{} will replace something that is there now.",
            count(replaced as u64, "item", "items")
        ));
    }
    if skipped > 0 {
        summary.push(format!(
            "{} will be skipped because something is in its place.",
            count(skipped as u64, "item", "items")
        ));
    }
    let n = counts.items;
    let selection = selection_of(plan, &picked)?;
    let head = Head {
        variant: Variant::Restore,
        code: plan_code(plan, selection),
        icon: Icon::Shield,
        instruction: format!("Restore {} of {name}?", items(n)),
        summary,
        button: format!("Restore {}", items(n)),
        hashes: Some((plan.plan_hash(), selection)),
    };
    Ok(assemble(head, counts, rows))
}

/// The recovery dialog of `journal.resume`, `.rollback` and `.retry_held` (design 8.2), drawn from the
/// bound plan of the interrupted session and the journal's facts.
pub fn view_recover(plan: &BoundPlan, facts: &RecoverFacts) -> Result<ConsentView, ViewError> {
    let rollback = facts.kind == RecoverKind::Rollback;
    let picked = pick(plan, &facts.ops, rollback)?;
    if picked.is_empty() {
        return Err(ViewError::NothingToRun);
    }
    let rules = Rules {
        verb: if rollback { Verb::PutBack } else { Verb::Exec },
        not_chosen: false,
        irreversible: !rollback,
        user_data: true,
        large: false,
    };
    let rows = build_rows(plan, &picked, rules, &HashMap::new())?;
    let counts = counts_of(&rows);
    if counts.items == 0 {
        return Err(ViewError::NothingToRun);
    }
    let mut summary = Vec::new();
    let name = app(&facts.app_name, &mut summary);
    let when = facts
        .started
        .map(|s| format!(", started {}", s.date_time()))
        .unwrap_or_default();
    summary.push(format!(
        "An earlier cleanup was interrupted (session {}{when}): {} of {} items are done.",
        shown(&facts.session).text,
        grouped(u64::from(facts.done)),
        grouped(u64::from(facts.total)),
    ));
    let n = counts.items;
    let (instruction, button) = match facts.kind {
        RecoverKind::Resume => {
            summary.push(format!("Finishing it changes {}:", items(n)));
            (
                format!("Finish the cleanup of {name}?"),
                "Finish the cleanup".to_owned(),
            )
        }
        RecoverKind::Rollback => {
            summary.push(format!("Rolling it back puts back {}:", items(n)));
            (
                format!("Roll the cleanup of {name} back?"),
                "Roll the cleanup back".to_owned(),
            )
        }
        RecoverKind::RetryHeld => {
            summary.push(format!("Trying again changes {}:", items(n)));
            (
                format!("Try the held items of {name} again?"),
                "Try the held items again".to_owned(),
            )
        }
    };
    group_lines(&counts, &mut summary);
    if counts.irreversible > 0 {
        summary.push(format!(
            "{} cannot be put back after this; {} marked {MARK}.",
            count(u64::from(counts.irreversible), "item", "items"),
            if counts.irreversible == 1 {
                "it is"
            } else {
                "they are"
            }
        ));
    }
    let selection = selection_of(plan, &picked)?;
    let head = Head {
        variant: Variant::Recover(facts.kind),
        code: plan_code(plan, selection),
        icon: Icon::Shield,
        instruction,
        summary,
        button,
        hashes: Some((plan.plan_hash(), selection)),
    };
    Ok(assemble(head, counts, rows))
}

// ---------------------------------------------------------------------------------------------------
// Purge
// ---------------------------------------------------------------------------------------------------

/// One purgeable unit of the broker's own expiry listing.
#[derive(Debug, Clone, Copy)]
pub enum PurgeUnit<'a> {
    /// A quarantined item.
    Item(&'a ExpiringItem),
    /// The backup files of one op.
    Backup(&'a ExpiringBackup),
}

impl PurgeUnit<'_> {
    /// The unit's expiry id.
    pub fn id(&self) -> &ExpiryId {
        match self {
            PurgeUnit::Item(i) => &i.id,
            PurgeUnit::Backup(b) => &b.id,
        }
    }

    /// Whether it is user data (or could not be told apart from it).
    pub fn user_data(&self) -> bool {
        match self {
            PurgeUnit::Item(i) => i.user_data,
            PurgeUnit::Backup(b) => b.user_data,
        }
    }
}

fn purge_entries(units: &[PurgeUnit<'_>]) -> Result<(Vec<Entry>, Counts, Flags), ViewError> {
    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    let mut counts = Counts::default();
    let mut flags = Flags::default();
    for unit in units {
        let id = unit.id().to_string();
        if !seen.insert(unit.id().clone()) {
            return Err(ViewError::DuplicateUnit(id));
        }
        let shown_id = shown(&id).text;
        counts.items += 1;
        match unit {
            PurgeUnit::Item(item) => {
                let now = quote(&item.quarantine_path);
                let was = quote(&item.original_path);
                flags.merge(now.flags);
                flags.merge(was.flags);
                let mut reasons = vec![Reason::Irreversible];
                if item.user_data {
                    reasons.push(Reason::UserData);
                }
                name_reasons(now.flags, &mut reasons);
                name_reasons(was.flags, &mut reasons);
                counts.bytes += item.bytes;
                entries.push(Entry {
                    id: id.clone(),
                    text: format!(
                        "{MARK} Delete for good: {}{SEP}was {}{SEP}{}{SEP}{}{SEP}{}",
                        now.text,
                        was.text,
                        if item.is_dir { "folder" } else { "file" },
                        size(item.bytes),
                        reasons
                            .iter()
                            .map(|r| r.label())
                            .collect::<Vec<_>>()
                            .join("; "),
                    ),
                    reasons,
                });
            }
            PurgeUnit::Backup(backup) => {
                if backup.files.is_empty() {
                    return Err(ViewError::NoFiles(id));
                }
                counts.bytes += backup.bytes;
                for file in &backup.files {
                    let q = quote(file);
                    flags.merge(q.flags);
                    let mut reasons = vec![Reason::Irreversible];
                    if backup.user_data {
                        reasons.push(Reason::UserData);
                    }
                    name_reasons(q.flags, &mut reasons);
                    counts.files += 1;
                    entries.push(Entry {
                        id: id.clone(),
                        text: format!(
                            "{MARK} Delete backup file: {}{SEP}of {shown_id}{SEP}{}",
                            q.text,
                            reasons
                                .iter()
                                .map(|r| r.label())
                                .collect::<Vec<_>>()
                                .join("; "),
                        ),
                        reasons,
                    });
                }
            }
        }
    }
    Ok((entries, counts, flags))
}

fn purge_code(units: &[PurgeUnit<'_>]) -> ConfirmCode {
    let ids: Vec<CandidateId> = units
        .iter()
        .map(|u| CandidateId(u.id().to_string()))
        .collect();
    ConfirmCode::of(&selection_hash(&ids))
}

fn purge_view(
    units: &[PurgeUnit<'_>],
    instruction: String,
    button: String,
    single: bool,
) -> Result<ConsentView, ViewError> {
    if units.is_empty() {
        return Err(ViewError::NothingToRun);
    }
    let (entries, counts, flags) = purge_entries(units)?;
    let mut summary = vec![format!(
        "{} and {}, {} in all. Every item and file is listed; nothing else is deleted.",
        count(u64::from(counts.items), "expired item", "expired items"),
        count(u64::from(counts.files), "backup file", "backup files"),
        size(counts.bytes),
    )];
    if !flags.is_plain() {
        summary.push(LEGEND.to_owned());
    }
    let code = purge_code(units);
    let box_text = if single {
        format!("I reviewed the item marked {MARK}")
    } else {
        format!("I reviewed the items and files marked {MARK}")
    };
    Ok(ConsentView {
        variant: Variant::Purge,
        code,
        icon: Icon::Warning,
        instruction,
        summary,
        attention: entries,
        others: Vec::new(),
        others_more: None,
        verification: Some(box_text),
        button,
        footer: footer(code),
        counts,
        plan_hash: None,
        selection_hash: None,
        uninstall: None,
    })
}

/// The purge dialog of `quarantine.purge` (design 8.2) for expired items that are not user data. Every
/// item and every backup file is named, in pages, never cut. User data belongs in
/// [`view_purge_user_data`], one item per dialog.
pub fn view_purge(units: &[PurgeUnit<'_>]) -> Result<ConsentView, ViewError> {
    if let Some(u) = units.iter().find(|u| u.user_data()) {
        return Err(ViewError::UserDataMisplaced(u.id().to_string()));
    }
    purge_view(
        units,
        format!(
            "Delete {} for good? This cannot be undone.",
            count(units.len() as u64, "expired item", "expired items")
        ),
        format!("Delete {} for good", items(units.len() as u32)),
        false,
    )
}

/// The purge dialog for one user-data item (DECISIONS 2026-11-16): the item and its backup files, in a
/// dialog of its own.
pub fn view_purge_user_data(unit: PurgeUnit<'_>) -> Result<ConsentView, ViewError> {
    if !unit.user_data() {
        return Err(ViewError::UserDataMisplaced(unit.id().to_string()));
    }
    purge_view(
        &[unit],
        "Delete this user data for good? This cannot be undone.".to_owned(),
        "Delete 1 item for good".to_owned(),
        true,
    )
}

/// What every "Delete now" dialog says below its count: the delete comes before the retention date,
/// and what that takes away.
pub const DELETE_NOW_WARNING: &str = "This is before the retention date. Until then Purge keeps \
    these items, and Undo can put them back. Once they are deleted here, Undo and History can no \
    longer restore them.";

/// The confirmation code of a "Delete now" dialog: over the same ids as the purge dialog's, and
/// never the same code, so the two cannot be taken for each other.
fn delete_now_code(units: &[PurgeUnit<'_>]) -> ConfirmCode {
    let ids: Vec<CandidateId> = std::iter::once(CandidateId("delete-now".to_owned()))
        .chain(units.iter().map(|u| CandidateId(u.id().to_string())))
        .collect();
    ConfirmCode::of(&selection_hash(&ids))
}

fn delete_now_view(
    units: &[PurgeUnit<'_>],
    instruction: String,
    button: String,
    single: bool,
) -> Result<ConsentView, ViewError> {
    if units.is_empty() {
        return Err(ViewError::NothingToRun);
    }
    // Only quarantined items are ever deleted before their retention ends.
    if let Some(u) = units.iter().find(|u| matches!(u, PurgeUnit::Backup(_))) {
        return Err(ViewError::BackupNotDue(u.id().to_string()));
    }
    let (entries, counts, flags) = purge_entries(units)?;
    let mut summary = vec![
        format!(
            "{}, {} in all. Every item is listed; nothing else is deleted.",
            count(
                u64::from(counts.items),
                "quarantined item",
                "quarantined items"
            ),
            size(counts.bytes),
        ),
        DELETE_NOW_WARNING.to_owned(),
    ];
    if !flags.is_plain() {
        summary.push(LEGEND.to_owned());
    }
    let code = delete_now_code(units);
    let box_text = if single {
        format!("I reviewed the item marked {MARK}")
    } else {
        format!("I reviewed the items marked {MARK}")
    };
    Ok(ConsentView {
        variant: Variant::DeleteNow,
        code,
        icon: Icon::Warning,
        instruction,
        summary,
        attention: entries,
        others: Vec::new(),
        others_more: None,
        verification: Some(box_text),
        button,
        footer: footer(code),
        counts,
        plan_hash: None,
        selection_hash: None,
        uninstall: None,
    })
}

/// The "Delete now" dialog of `quarantine.purge` for quarantined items whose retention has **not**
/// ended and that are not user data: every item is named, in pages, never cut, and the dialog says
/// that this is before the retention date, that it cannot be undone, and that Undo will no longer
/// restore the items. A backup is refused ([`ViewError::BackupNotDue`]); user data belongs in
/// [`view_delete_now_user_data`], one item per dialog.
pub fn view_delete_now(units: &[PurgeUnit<'_>]) -> Result<ConsentView, ViewError> {
    if let Some(u) = units.iter().find(|u| u.user_data()) {
        return Err(ViewError::UserDataMisplaced(u.id().to_string()));
    }
    let n = units.len() as u64;
    delete_now_view(
        units,
        format!(
            "Delete {} now, before {} retention ends? This cannot be undone.",
            count(n, "quarantined item", "quarantined items"),
            if n == 1 { "its" } else { "their" },
        ),
        format!("Delete {} now, for good", items(units.len() as u32)),
        false,
    )
}

/// The "Delete now" dialog for one user-data item whose retention has not ended, in a dialog of its
/// own.
pub fn view_delete_now_user_data(unit: PurgeUnit<'_>) -> Result<ConsentView, ViewError> {
    if !unit.user_data() {
        return Err(ViewError::UserDataMisplaced(unit.id().to_string()));
    }
    delete_now_view(
        &[unit],
        "Delete this user data now, before its retention ends? This cannot be undone.".to_owned(),
        "Delete 1 item now, for good".to_owned(),
        true,
    )
}

/// What the broker knows for an uninstall dialog (`uninstall.run`, review M3-R2 M1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallFacts {
    /// The program, as the broker's own inventory names it.
    pub app_name: String,
    /// The program id, text of the session's key; only the code reads it.
    pub program_id: String,
    /// The command the session froze at `uninstall.prepare` and the run will start, unchanged.
    pub command: QuietCommand,
    /// Whether this is the session's quiet command.
    pub quiet: bool,
    /// The signer of the program file, when the broker read one.
    pub signer: Option<String>,
    /// The restore-point choice the client reports for the leftover cleanup that follows; `None` when
    /// it did not say.
    pub restore_point: Option<RestorePoint>,
}

/// The uninstall dialog of `uninstall.run`: the program, the exact command (program file and
/// arguments, each through [`shown`]), its signer, quiet or interactive, and the restore-point choice.
/// A program, command or signer that is shown with escapes or a cut is an attention entry, and brings the
/// verification box.
pub fn view_uninstall(facts: &UninstallFacts) -> Result<ConsentView, ViewError> {
    let command = &facts.command;
    if command.exe.trim().is_empty() {
        return Err(ViewError::NoCommand);
    }
    let name = quote(&facts.app_name);
    let mut summary = Vec::new();
    let mut attention = Vec::new();
    let mut flags = Flags::default();
    let mut field = |id: &str, label: &str, text: Shown| {
        flags.merge(text.flags);
        if text.flags.is_plain() && !text.flags.look_alike {
            summary.push(format!("{label}: {}", text.text));
        } else {
            let mut reasons = Vec::new();
            name_reasons(text.flags, &mut reasons);
            attention.push(Entry {
                id: id.to_owned(),
                text: line(MARK, label, &text.text, None, None, 0, &reasons),
                reasons,
            });
        }
    };
    if !name.flags.is_plain() || name.flags.look_alike {
        field("program", "Program", name.clone());
    }
    field("exe", "Starts", quote(&command.exe));
    if command.args.is_empty() {
        field(
            "args",
            "Arguments",
            Shown {
                text: "none".to_owned(),
                flags: Flags::default(),
            },
        );
    } else {
        field("args", "Arguments", quote_line(&command.args));
    }
    match &facts.signer {
        Some(signer) => field("signer", "Signed by", quote_line(signer)),
        None => field(
            "signer",
            "Signed by",
            Shown {
                text: "no signer known".to_owned(),
                flags: Flags::default(),
            },
        ),
    }
    summary.push(if facts.quiet {
        "Mode: quiet. The uninstaller shows no window of its own.".to_owned()
    } else {
        "Mode: interactive. The uninstaller may show windows and ask questions.".to_owned()
    });
    summary.push(match facts.restore_point {
        Some(RestorePoint::Off) => {
            "Restore point for the leftover cleanup that follows: off.".to_owned()
        }
        Some(RestorePoint::HighRisk) => {
            "Restore point for the leftover cleanup that follows: only when it is high-risk."
                .to_owned()
        }
        Some(RestorePoint::Always) => {
            "Restore point for the leftover cleanup that follows: always.".to_owned()
        }
        None => "Restore point: not asked for here; the leftover cleanup asks for it.".to_owned(),
    });
    summary.push(
        "The program's own uninstaller runs as administrator. Purge cannot undo what it does. \
         Nothing has been started yet."
            .to_owned(),
    );
    if !flags.is_plain() || flags.look_alike {
        summary.push(LEGEND.to_owned());
    }
    let code = ConfirmCode::of(&selection_hash(&[CandidateId(format!(
        "uninstall\n{}\n{}\n{}\n{}",
        facts.program_id, facts.quiet, command.exe, command.args
    ))]));
    Ok(ConsentView {
        variant: Variant::Uninstall,
        code,
        icon: Icon::Warning,
        instruction: format!("Run the uninstaller of {} as administrator?", name.text),
        summary,
        verification: verification(attention.len()),
        attention,
        others: Vec::new(),
        others_more: None,
        button: "Run the uninstaller".to_owned(),
        footer: footer(code),
        counts: Counts::default(),
        plan_hash: None,
        selection_hash: None,
        uninstall: Some(UninstallDrawn {
            command: command.clone(),
            quiet: facts.quiet,
        }),
    })
}

/// Splits an expiry listing into the units one bulk dialog may name and the user-data units that each
/// need a dialog of their own, both in the listing's order.
pub fn split_purge<'a>(
    items: &'a [ExpiringItem],
    backups: &'a [ExpiringBackup],
) -> (Vec<PurgeUnit<'a>>, Vec<PurgeUnit<'a>>) {
    let units = items
        .iter()
        .map(PurgeUnit::Item)
        .chain(backups.iter().map(PurgeUnit::Backup));
    units.partition(|u| !u.user_data())
}
