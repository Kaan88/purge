//! The residue of a scan (`purge.residue/1`) and advice about it (`purge.advice/1`)
//! (BASELINE_LOCAL_DESIGN.md §7): **interface only** until M6.
//!
//! # The residue
//!
//! Every item that carries [`Blocker::BaselineInferred`](crate::Blocker::BaselineInferred), plus every
//! key an A site answered `Unknown` for, is listed with why the view could not answer and a shape the
//! scan could read. No value data and no file content is part of it: the model never needs either.
//!
//! The list is capped at [`MAX_RESIDUE_ITEMS`]; [`ResidueDoc::omitted`] says how many items the cap left
//! out. Item ids are candidate ids (`c-…`), so an item that is also a candidate keeps the id the plan
//! uses, and [`item_fp_text`] spells a candidate's [`ItemFp`] the way advice binds to it.
//!
//! # Advice
//!
//! Advice is read as untrusted input: every object refuses unknown fields, lengths and enums are checked
//! by [`AdviceDoc::validate`], and it never becomes a candidate. [`bind`] drops advice whose `scan_id`,
//! id or `item_fp` do not match the scan it names, and [`apply`] only ever appends an
//! [`EvidenceKind::Ai`] note to a candidate that already exists:
//!
//! - `windows` is negative evidence and moves the item down one band (policy rule 7);
//! - `app` and `unknown` add one collapsed note and change nothing else.
//!
//! It cannot remove a blocker (including `BaselineInferred`), raise a band, preselect an item or create
//! a candidate: the code has no access path to those fields.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::schema_id;
use crate::{
    BaselineTrust, Blocker, Candidate, Evidence, EvidenceKind, Facts, ItemFp, Scope, SourceId,
    SourceTrust, Target, Tier,
};

schema_id!(
    /// The `schema` field of a residue document: always `purge.residue/1`.
    ResidueSchema = "purge.residue/1"
);
schema_id!(
    /// The `schema` field of an advice document: always `purge.advice/1`.
    AdviceSchema = "purge.advice/1"
);

/// Most items a residue document lists; the rest is counted in [`ResidueDoc::omitted`].
pub const MAX_RESIDUE_ITEMS: usize = 1_000;
/// Most advice items one advice document may carry.
pub const MAX_ADVICE_ITEMS: usize = 1_000;
/// Most characters of a scan id (residue or advice).
pub const MAX_SCAN_ID_CHARS: usize = 128;
/// Most characters of a model name.
pub const MAX_MODEL_CHARS: usize = 200;
/// Most characters of a residue or advice item id.
pub const MAX_ID_CHARS: usize = 64;
/// Most characters of a registry key in a residue item.
pub const MAX_KEY_CHARS: usize = 1_024;
/// Most characters of a scanner id.
pub const MAX_SITE_CHARS: usize = 64;
/// Most characters of an `item_fp`, and of an advice item's spelling of one.
pub const MAX_ITEM_FP_CHARS: usize = 80;
/// Most characters of an advice note (design §7: at most 200).
pub const MAX_NOTE_CHARS: usize = 200;
/// Most characters of an area id copied from `view.json`.
pub const MAX_AREA_CHARS: usize = 128;
/// Most neighbour flags a shape may carry.
pub const MAX_NEIGHBOURS: usize = 16;

// -----------------------------------------------------------------------------------------------------------
// Residue
// -----------------------------------------------------------------------------------------------------------

/// Why a key is in the residue.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ResidueWhy {
    /// The view inferred absence, which the presence-only cap handed to the site as `Unknown`.
    InferredAbsent,
    /// The view holds the sets but `view.json` does not mark the key's area for its trust (or the key is
    /// in no area, or the builder could not read it).
    AreaNotAccepted,
    /// The key is outside the capture scope, or its spelling names no bound hive.
    OutOfScope,
    /// There is no usable view: trust None, or an exact baseline of another Windows.
    NoView,
}

/// Who owns a key, as far as the scan can tell. Only TrustedInstaller ownership is read today; every
/// other key is `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ResidueOwner {
    /// Administrators.
    Admins,
    /// The system account.
    System,
    /// TrustedInstaller.
    Ti,
    /// A user account.
    User,
    /// Not known, or another principal.
    Other,
}

/// When the key was last written, against the uninstall window of the fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResidueWritten {
    /// Before the install.
    BeforeInstall,
    /// Between the install and the end of the uninstall.
    InWindow,
    /// After the uninstall ended.
    AfterUninstall,
    /// Unknown, because the key or the window could not be read.
    Unknown,
}

/// What the scan could read about a residue key, without its values or their data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidueShape {
    /// Number of values.
    pub values: u32,
    /// Number of direct subkeys.
    pub subkeys: u32,
    /// Owner of the key, as far as it is known.
    pub owner: ResidueOwner,
    /// When the key was last written.
    pub written: ResidueWritten,
    /// Whether the parent key is Windows' own in any set of the view.
    pub parent_in_view: bool,
    /// How many of the direct subkeys are Windows' own in any set of the view.
    pub siblings_in_view: u32,
    /// Number of direct subkeys (`subkeys`, repeated for the model's convenience).
    pub siblings: u32,
    /// Whether the local set of the view has the key. Always false for a residue key: a set that had it
    /// would have answered `Present`, not `Unknown`.
    pub in_local: bool,
    /// Whether each neighbour set of the view has the key, in view order. All false for a residue key.
    pub in_neighbours: Vec<bool>,
}

/// The view the residue was made against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidueBaselineView {
    /// The view's short name (`Professional-26340.9882`, `local-…+2`, `none`).
    pub name: String,
    /// Its trust.
    pub trust: BaselineTrust,
}

/// One residue item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidueItem {
    /// Candidate id (`c-…`), or the id the scan gave the residue item.
    pub id: String,
    /// The item's `item_fp` in [`item_fp_text`] form; empty for a key without a file identity.
    pub item_fp: String,
    /// The registry key.
    pub key: String,
    /// The `view.json` area of the key, when it is in one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub area: Option<String>,
    /// Why the site could not answer, or that absence was inferred.
    pub why: ResidueWhy,
    /// The id of the scanner that asked.
    pub site: String,
    /// What the scan could read about the key.
    pub shape: ResidueShape,
}

/// The residue of one scan (`purge.residue/1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidueDoc {
    /// Always `purge.residue/1`.
    pub schema: ResidueSchema,
    /// The scan the items belong to; advice binds to it.
    pub scan_id: String,
    /// The baseline view the scan worked with.
    pub baseline_view: ResidueBaselineView,
    /// At most [`MAX_RESIDUE_ITEMS`] items.
    pub items: Vec<ResidueItem>,
    /// How many items the cap left out.
    #[serde(default)]
    pub omitted: u32,
}

impl ResidueDoc {
    /// Checks lengths and the `item_fp` spelling of every item. Enums and unknown fields are refused by
    /// `serde` when the document is read.
    ///
    /// # Errors
    ///
    /// The first field that is empty, too long, not printable or a malformed `item_fp`.
    pub fn validate(&self) -> Result<(), ResidueError> {
        check_text("scan_id", &self.scan_id, MAX_SCAN_ID_CHARS)?;
        check_text(
            "baseline_view.name",
            &self.baseline_view.name,
            MAX_MODEL_CHARS,
        )?;
        if self.items.len() > MAX_RESIDUE_ITEMS {
            return Err(ResidueError::TooMany {
                field: "items",
                max: MAX_RESIDUE_ITEMS,
                got: self.items.len(),
            });
        }
        for item in &self.items {
            check_text("id", &item.id, MAX_ID_CHARS)?;
            check_item_fp(&item.item_fp)?;
            check_text("key", &item.key, MAX_KEY_CHARS)?;
            if let Some(area) = &item.area {
                check_text("area", area, MAX_AREA_CHARS)?;
            }
            check_text("site", &item.site, MAX_SITE_CHARS)?;
            if item.shape.in_neighbours.len() > MAX_NEIGHBOURS {
                return Err(ResidueError::TooMany {
                    field: "shape.in_neighbours",
                    max: MAX_NEIGHBOURS,
                    got: item.shape.in_neighbours.len(),
                });
            }
        }
        Ok(())
    }
}

/// The canonical text of a candidate's file identity for residues and advice:
/// `<32 lower-case hex digits>@<volume serial>`; the empty string when there is none.
#[must_use]
pub fn item_fp_text(item_fp: Option<&ItemFp>) -> String {
    item_fp.map_or_else(String::new, |fp| {
        format!("{}@{}", fp.file_id, fp.volume_serial)
    })
}

/// Why a residue or advice document is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResidueError {
    /// A required text is empty after trimming.
    Empty(&'static str),
    /// A text is longer than the limit.
    TooLong {
        /// The field's name.
        field: &'static str,
        /// The limit, in characters.
        max: usize,
        /// What the document holds.
        got: usize,
    },
    /// A text holds a control character.
    Control(&'static str),
    /// More items than the cap.
    TooMany {
        /// The field's name.
        field: &'static str,
        /// The limit.
        max: usize,
        /// What the document holds.
        got: usize,
    },
    /// An `item_fp` is neither empty nor `<32 hex>@<serial>`.
    BadItemFp,
    /// A confidence is not a finite number in `0.0..=1.0`.
    BadConfidence,
}

impl std::fmt::Display for ResidueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty(field) => write!(f, "{field} is empty"),
            Self::TooLong { field, max, got } => {
                write!(f, "{field} is {got} characters, at most {max} are allowed")
            }
            Self::Control(field) => write!(f, "{field} holds a control character"),
            Self::TooMany { field, max, got } => {
                write!(f, "{field} has {got} entries, at most {max} are allowed")
            }
            Self::BadItemFp => f.write_str(
                "item_fp is neither empty nor 32 lower-case hex digits, `@`, and a volume serial",
            ),
            Self::BadConfidence => f.write_str("confidence is not a finite number from 0.0 to 1.0"),
        }
    }
}

impl std::error::Error for ResidueError {}

/// Checks one text field: non-empty after trimming, at most `max` characters, printable.
fn check_text(field: &'static str, text: &str, max: usize) -> Result<(), ResidueError> {
    if text.trim().is_empty() {
        return Err(ResidueError::Empty(field));
    }
    let len = text.chars().count();
    if len > max {
        return Err(ResidueError::TooLong {
            field,
            max,
            got: len,
        });
    }
    if text.chars().any(char::is_control) {
        return Err(ResidueError::Control(field));
    }
    Ok(())
}

/// Checks an `item_fp`: empty, or `<32 lower-case hex>@<decimal volume serial>`.
fn check_item_fp(text: &str) -> Result<(), ResidueError> {
    if text.is_empty() {
        return Ok(());
    }
    let len = text.chars().count();
    if len > MAX_ITEM_FP_CHARS {
        return Err(ResidueError::TooLong {
            field: "item_fp",
            max: MAX_ITEM_FP_CHARS,
            got: len,
        });
    }
    let Some((id, serial)) = text.split_once('@') else {
        return Err(ResidueError::BadItemFp);
    };
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || serial.is_empty()
        || !serial.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(ResidueError::BadItemFp);
    }
    Ok(())
}

// -----------------------------------------------------------------------------------------------------------
// Advice
// -----------------------------------------------------------------------------------------------------------

/// What an advisor says about an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdviceVerdict {
    /// A Windows component: negative evidence, one band down.
    Windows,
    /// Belongs to an application (this one or another): a note that changes nothing.
    App,
    /// No opinion: a note that changes nothing.
    Unknown,
}

/// The category of an advisor's reason. Kept small; M6 may widen it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdviceReason {
    /// The item is part of Windows.
    WindowsComponent,
    /// The item belongs to another application.
    AnotherApp,
    /// Matched by name.
    NameMatch,
    /// Matched by path or registry reference.
    PathMatch,
    /// Matched by the shape of the key.
    Structure,
    /// The advisor is not sure.
    Uncertain,
    /// Anything else.
    Other,
}

impl AdviceReason {
    /// The stable JSON spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WindowsComponent => "windows_component",
            Self::AnotherApp => "another_app",
            Self::NameMatch => "name_match",
            Self::PathMatch => "path_match",
            Self::Structure => "structure",
            Self::Uncertain => "uncertain",
            Self::Other => "other",
        }
    }
}

/// One advice item. Binds to a residue item by `id` and `item_fp`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdviceItem {
    /// The residue item's id.
    pub id: String,
    /// The residue item's `item_fp` (empty for a key).
    pub item_fp: String,
    /// What the advisor says.
    pub verdict: AdviceVerdict,
    /// How sure the advisor is, `0.0..=1.0`.
    pub confidence: f64,
    /// Why it says so.
    pub reason: AdviceReason,
    /// A short note, at most [`MAX_NOTE_CHARS`] characters.
    pub note: String,
}

/// An advice document (`purge.advice/1`), read as untrusted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdviceDoc {
    /// Always `purge.advice/1`.
    pub schema: AdviceSchema,
    /// The scan the advice is about; a scan of another id drops every item.
    pub scan_id: String,
    /// The advisor's name, e.g. a model id.
    pub model: String,
    /// The advice items.
    #[serde(default)]
    pub items: Vec<AdviceItem>,
}

impl AdviceDoc {
    /// Checks lengths, enums (through `serde`), the confidence range and the `item_fp` spelling.
    ///
    /// # Errors
    ///
    /// The first item or field that breaks a limit.
    pub fn validate(&self) -> Result<(), ResidueError> {
        check_text("scan_id", &self.scan_id, MAX_SCAN_ID_CHARS)?;
        check_text("model", &self.model, MAX_MODEL_CHARS)?;
        if self.items.len() > MAX_ADVICE_ITEMS {
            return Err(ResidueError::TooMany {
                field: "items",
                max: MAX_ADVICE_ITEMS,
                got: self.items.len(),
            });
        }
        for item in &self.items {
            check_text("id", &item.id, MAX_ID_CHARS)?;
            check_item_fp(&item.item_fp)?;
            if !item.confidence.is_finite() || !(0.0..=1.0).contains(&item.confidence) {
                return Err(ResidueError::BadConfidence);
            }
            if item.note.chars().count() > MAX_NOTE_CHARS {
                return Err(ResidueError::TooLong {
                    field: "note",
                    max: MAX_NOTE_CHARS,
                    got: item.note.chars().count(),
                });
            }
            if item.note.chars().any(char::is_control) {
                return Err(ResidueError::Control("note"));
            }
        }
        Ok(())
    }
}

/// Advice that matches a residue item and a candidate of the scan.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BoundAdvice<'a> {
    /// The advice item.
    pub advice: &'a AdviceItem,
    /// The candidate it may annotate.
    pub candidate: &'a Candidate,
}

/// Binds `advice` to the candidates of `residue`'s scan: the scan id, the item id and the `item_fp` must
/// all match, and a residue item without a candidate is dropped (advice never creates one).
///
/// # Examples
///
/// ```
/// # use purge_model::{AdviceDoc, AdviceSchema, ResidueDoc, ResidueSchema, AdviceVerdict, AdviceReason,
/// #     ResidueBaselineView, BaselineTrust, bind};
/// let residue = ResidueDoc {
///     schema: ResidueSchema,
///     scan_id: "s".into(),
///     baseline_view: ResidueBaselineView { name: "none".into(), trust: BaselineTrust::None },
///     items: Vec::new(),
///     omitted: 0,
/// };
/// let advice = AdviceDoc {
///     schema: AdviceSchema,
///     scan_id: "other".into(),
///     model: "m".into(),
///     items: Vec::new(),
/// };
/// assert!(bind(&advice, &residue, &[]).is_empty());
/// ```
#[must_use]
pub fn bind<'a>(
    advice: &'a AdviceDoc,
    residue: &'a ResidueDoc,
    candidates: &'a [Candidate],
) -> Vec<BoundAdvice<'a>> {
    if advice.scan_id != residue.scan_id {
        return Vec::new();
    }
    let mut out = Vec::new();
    for item in &advice.items {
        let Some(residue_item) = residue.items.iter().find(|r| r.id == item.id) else {
            continue;
        };
        if item.item_fp != residue_item.item_fp {
            continue;
        }
        let Some(candidate) = candidates.iter().find(|c| c.id.0 == item.id) else {
            continue;
        };
        if item.item_fp != item_fp_text(candidate.item_fp.as_ref()) {
            continue;
        }
        out.push(BoundAdvice {
            advice: item,
            candidate,
        });
    }
    out
}

/// Applies every bound advice item to its candidate and returns how many were added.
///
/// Only `Candidate::evidence` is touched: no blocker is removed, no decision is written, no candidate is
/// created. A `windows` item appends an [`EvidenceKind::Ai`] note with a negative weight; `app` and
/// `unknown` append one zero-weight note, collapsed by (`reason`, `note`) when it is already there.
pub fn apply(advice: &AdviceDoc, residue: &ResidueDoc, candidates: &mut [Candidate]) -> usize {
    if advice.scan_id != residue.scan_id {
        return 0;
    }
    let mut planned = Vec::new();
    for item in &advice.items {
        let Some(residue_item) = residue.items.iter().find(|r| r.id == item.id) else {
            continue;
        };
        if item.item_fp != residue_item.item_fp {
            continue;
        }
        let Some(index) = candidates.iter().position(|c| c.id.0 == item.id) else {
            continue;
        };
        if item.item_fp != item_fp_text(candidates[index].item_fp.as_ref()) {
            continue;
        }
        planned.push((index, item));
    }
    let mut applied = 0;
    for (index, item) in planned {
        if add_note(&mut candidates[index], item, &advice.model) {
            applied += 1;
        }
    }
    applied
}

/// Appends one AI note to `candidate`; see [`apply`].
fn add_note(candidate: &mut Candidate, item: &AdviceItem, model: &str) -> bool {
    let weight = match item.verdict {
        AdviceVerdict::Windows => -1,
        AdviceVerdict::App | AdviceVerdict::Unknown => 0,
    };
    let mut detail = Facts::new()
        .with("verdict", verdict_text(item.verdict))
        .with("reason", item.reason.as_str())
        .with("confidence", format!("{:.2}", item.confidence));
    if !item.note.is_empty() {
        detail = detail.with("note", &item.note);
    }
    if weight == 0 {
        let collapsed = candidate.evidence.iter().any(|e| {
            e.kind == EvidenceKind::Ai
                && e.tier == Tier::Ai
                && e.weight == 0
                && e.detail.get("reason") == Some(item.reason.as_str())
                && e.detail.get("note") == Some(item.note.as_str())
        });
        if collapsed {
            return false;
        }
    }
    let Some(mut evidence) = Evidence::new(
        EvidenceKind::Ai,
        scope_of(&candidate.target),
        SourceTrust::UserWritable,
        SourceId::from(format!("ai:{model}")),
    ) else {
        return false;
    };
    evidence.weight = weight;
    evidence.detail = detail;
    candidate.evidence.push(evidence);
    true
}

/// The stable JSON spelling of a verdict, for the evidence detail.
fn verdict_text(verdict: AdviceVerdict) -> &'static str {
    match verdict {
        AdviceVerdict::Windows => "windows",
        AdviceVerdict::App => "app",
        AdviceVerdict::Unknown => "unknown",
    }
}

/// The [`Scope`] of a target, for the AI evidence.
fn scope_of(target: &Target) -> Scope {
    match target {
        Target::Path { .. } => Scope::Path,
        Target::RegKey { .. } => Scope::Key,
        Target::RegValue { .. }
        | Target::RegValueChanged { .. }
        | Target::RegMultiSzSegment { .. } => Scope::Value,
        Target::Service { .. } | Target::Task { .. } | Target::FirewallRule { .. } => Scope::Object,
        Target::AppxPackage { .. } => Scope::Package,
    }
}

/// Whether `candidate` carries the soft baseline cap.
#[must_use]
pub fn carries_baseline_inferred(candidate: &Candidate) -> bool {
    candidate
        .blockers
        .iter()
        .any(|b| matches!(b, Blocker::BaselineInferred))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, AppRef, Band, CandidateId, Category, Decision, Origin, Reversibility};

    fn residue() -> ResidueDoc {
        ResidueDoc {
            schema: ResidueSchema,
            scan_id: "scan-1".into(),
            baseline_view: ResidueBaselineView {
                name: "none".into(),
                trust: BaselineTrust::None,
            },
            items: vec![ResidueItem {
                id: "c-0123456789abcdef".into(),
                item_fp: String::new(),
                key: r"HKLM\SOFTWARE\Vendor".into(),
                area: Some("software-vendor".into()),
                why: ResidueWhy::NoView,
                site: "REG-SOFTWARE".into(),
                shape: ResidueShape {
                    values: 2,
                    subkeys: 1,
                    owner: ResidueOwner::Other,
                    written: ResidueWritten::Unknown,
                    parent_in_view: true,
                    siblings_in_view: 3,
                    siblings: 4,
                    in_local: false,
                    in_neighbours: vec![false, false],
                },
            }],
            omitted: 0,
        }
    }

    fn candidate(id: &str, band: Band, preselected: bool, blockers: Vec<Blocker>) -> Candidate {
        Candidate {
            id: CandidateId(id.into()),
            target: Target::RegKey {
                path: r"HKLM\SOFTWARE\Vendor".into(),
            },
            action: Action::DeleteKey,
            owner: AppRef {
                program_id: "HKLM|64|App".parse().unwrap(),
                display_name: "App".into(),
            },
            origin: Origin::Scanner,
            scanner: "TEST".into(),
            category: Category::Registration,
            evidence: Vec::new(),
            blockers,
            harm: crate::Harm::Low,
            reversibility: Reversibility::Full,
            children: Vec::new(),
            size_bytes: None,
            child_count: None,
            decision: Some(Decision {
                band,
                preselected,
                score: 1,
                explanation: "because".into(),
            }),
            item_fp: None,
            object_fp: None,
        }
    }

    fn advice(verdict: AdviceVerdict) -> AdviceDoc {
        AdviceDoc {
            schema: AdviceSchema,
            scan_id: "scan-1".into(),
            model: "test-model".into(),
            items: vec![AdviceItem {
                id: "c-0123456789abcdef".into(),
                item_fp: String::new(),
                verdict,
                confidence: 0.9,
                reason: AdviceReason::NameMatch,
                note: "looks like a leftover".into(),
            }],
        }
    }

    #[test]
    fn documents_round_trip_and_refuse_unknown_fields() {
        let doc = residue();
        doc.validate().unwrap();
        let text = serde_json::to_string(&doc).unwrap();
        let back: ResidueDoc = serde_json::from_str(&text).unwrap();
        assert_eq!(back, doc);
        assert!(text.contains(r#""schema":"purge.residue/1""#), "{text}");

        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        value["unexpected"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ResidueDoc>(value).is_err());
        let mut value = serde_json::to_value(residue()).unwrap();
        value["items"][0]["shape"]["files"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ResidueDoc>(value).is_err());

        let adv = advice(AdviceVerdict::App);
        adv.validate().unwrap();
        let text = serde_json::to_string(&adv).unwrap();
        assert!(text.contains(r#""schema":"purge.advice/1""#), "{text}");
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        value["items"][0]["weight"] = serde_json::json!(4);
        assert!(serde_json::from_value::<AdviceDoc>(value.clone()).is_err());
        value["schema"] = serde_json::json!("purge.advice/0");
        assert!(serde_json::from_value::<AdviceDoc>(value).is_err());
    }

    #[test]
    fn validation_rejects_oversize_and_bad_values() {
        let mut doc = residue();
        doc.items.truncate(1);
        doc.validate().unwrap();
        let mut too_many = residue();
        let item = too_many.items[0].clone();
        too_many.items = vec![item; MAX_RESIDUE_ITEMS + 1];
        assert!(matches!(
            too_many.validate(),
            Err(ResidueError::TooMany { field: "items", .. })
        ));

        let mut bad_fp = residue();
        bad_fp.items[0].item_fp = "not-a-fingerprint".into();
        assert_eq!(bad_fp.validate(), Err(ResidueError::BadItemFp));

        let mut adv = advice(AdviceVerdict::App);
        adv.items[0].note = "x".repeat(MAX_NOTE_CHARS + 1);
        assert!(matches!(
            adv.validate(),
            Err(ResidueError::TooLong { field: "note", .. })
        ));
        adv.items[0].note = "x".repeat(MAX_NOTE_CHARS);
        adv.items[0].confidence = 1.5;
        assert_eq!(adv.validate(), Err(ResidueError::BadConfidence));
        adv.items[0].confidence = f64::NAN;
        assert_eq!(adv.validate(), Err(ResidueError::BadConfidence));
        adv.items[0].confidence = 0.5;
        adv.items[0].id.clear();
        assert_eq!(adv.validate(), Err(ResidueError::Empty("id")));

        let mut many = advice(AdviceVerdict::App);
        let item = many.items[0].clone();
        many.items = vec![item; MAX_ADVICE_ITEMS + 1];
        assert!(matches!(
            many.validate(),
            Err(ResidueError::TooMany { field: "items", .. })
        ));
    }

    #[test]
    fn the_mapping_never_creates_a_candidate_or_touches_blockers_or_decisions() {
        for band in [Band::Safe, Band::Likely, Band::Weak, Band::Blocked] {
            for preselected in [true, false] {
                for verdict in [
                    AdviceVerdict::Windows,
                    AdviceVerdict::App,
                    AdviceVerdict::Unknown,
                ] {
                    let mut candidates = vec![candidate(
                        "c-0123456789abcdef",
                        band,
                        preselected,
                        vec![Blocker::BaselineInferred],
                    )];
                    let before = candidates[0].clone();
                    let applied = apply(&advice(verdict), &residue(), &mut candidates);
                    assert_eq!(applied, 1, "{band:?} {verdict:?}");
                    let after = &candidates[0];
                    assert_eq!(after.blockers, before.blockers, "{band:?} {verdict:?}");
                    assert!(carries_baseline_inferred(after));
                    assert_eq!(after.decision, before.decision, "{band:?} {verdict:?}");
                    assert_eq!(after.children, before.children);
                    assert_eq!(after.target, before.target);
                    let ai = after.evidence.last().expect("the note was appended");
                    assert_eq!(ai.kind, EvidenceKind::Ai);
                    assert_eq!(ai.tier, Tier::Ai);
                    assert_eq!(
                        ai.weight,
                        if verdict == AdviceVerdict::Windows {
                            -1
                        } else {
                            0
                        }
                    );
                }
            }
        }
        // An empty scan stays empty: advice never adds a candidate.
        let mut none: Vec<Candidate> = Vec::new();
        assert_eq!(
            apply(&advice(AdviceVerdict::Windows), &residue(), &mut none),
            0
        );
        assert!(none.is_empty());
    }

    #[test]
    fn stale_or_foreign_advice_is_dropped() {
        let candidates = vec![candidate(
            "c-0123456789abcdef",
            Band::Likely,
            false,
            Vec::new(),
        )];
        assert_eq!(
            bind(&advice(AdviceVerdict::App), &residue(), &candidates).len(),
            1
        );

        let mut stale = advice(AdviceVerdict::App);
        stale.items[0].item_fp = "00000000000000000000000000000000@1".into();
        assert!(bind(&stale, &residue(), &candidates).is_empty());

        let mut other_scan = advice(AdviceVerdict::App);
        other_scan.scan_id = "another".into();
        assert!(bind(&other_scan, &residue(), &candidates).is_empty());

        let mut unknown_id = advice(AdviceVerdict::App);
        unknown_id.items[0].id = "c-ffffffffffffffff".into();
        assert!(bind(&unknown_id, &residue(), &candidates).is_empty());
    }

    #[test]
    fn path_candidates_bind_their_item_fp() {
        let fp = ItemFp {
            file_id: crate::exec::op::FileIdHex([7; 16]),
            volume_serial: 9,
        };
        let mut c = candidate("c-0123456789abcdef", Band::Likely, false, Vec::new());
        c.target = Target::Path {
            path: r"C:\Program Files\App".into(),
        };
        c.item_fp = Some(fp);
        let text = item_fp_text(Some(&fp));
        let mut residue = residue();
        residue.items[0].item_fp = text.clone();
        let mut advice = advice(AdviceVerdict::Windows);
        advice.items[0].item_fp = text;
        assert_eq!(bind(&advice, &residue, &[c.clone()]).len(), 1);
        advice.items[0].item_fp = "00000000000000000000000000000000@1".into();
        assert!(bind(&advice, &residue, &[c]).is_empty());
    }

    #[test]
    fn app_and_unknown_notes_collapse() {
        let mut candidates = vec![candidate(
            "c-0123456789abcdef",
            Band::Likely,
            false,
            Vec::new(),
        )];
        assert_eq!(
            apply(&advice(AdviceVerdict::App), &residue(), &mut candidates),
            1
        );
        assert_eq!(
            apply(&advice(AdviceVerdict::App), &residue(), &mut candidates),
            0
        );
        assert_eq!(candidates[0].evidence.len(), 1);
        assert_eq!(
            apply(&advice(AdviceVerdict::Windows), &residue(), &mut candidates),
            1
        );
        assert_eq!(candidates[0].evidence.len(), 2);
    }

    #[test]
    fn json_schemas_are_generated() {
        let text = serde_json::to_string(&schemars::schema_for!(ResidueDoc)).unwrap();
        for name in [
            r#""const":"purge.residue/1""#,
            "inferred_absent",
            "area_not_accepted",
            "out_of_scope",
            "no_view",
            "in_neighbours",
            "siblings_in_view",
            "omitted",
            "additionalProperties",
        ] {
            assert!(text.contains(name), "schema lacks {name}");
        }
        let text = serde_json::to_string(&schemars::schema_for!(AdviceDoc)).unwrap();
        for name in [
            r#""const":"purge.advice/1""#,
            "windows",
            "app",
            "unknown",
            "confidence",
            "reason",
            "note",
            "additionalProperties",
        ] {
            assert!(text.contains(name), "schema lacks {name}");
        }
    }

    #[test]
    fn empty_details_are_not_collapsed() {
        let mut candidates = vec![candidate(
            "c-0123456789abcdef",
            Band::Likely,
            false,
            Vec::new(),
        )];
        let mut first = advice(AdviceVerdict::Unknown);
        first.items[0].note.clear();
        assert_eq!(apply(&first, &residue(), &mut candidates), 1);
        let mut second = advice(AdviceVerdict::Unknown);
        second.items[0].reason = AdviceReason::Other;
        second.items[0].note.clear();
        assert_eq!(apply(&second, &residue(), &mut candidates), 1);
    }
}
