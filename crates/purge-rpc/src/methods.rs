//! Request, result and notification types of every method (M3_DESIGN.md §6.3, §6.5), the ids the broker
//! hands out, and the two call sets [`StdioCall`] and [`PipeCall`].
//!
//! Rules for request (params) types:
//!
//! - Every one has `deny_unknown_fields`: an unknown member is `-32602`.
//! - A broker request holds only ids, enums, booleans and integers (B1, threat T3). No field can
//!   carry a path, a target, a fingerprint, a scan or a plan: the broker works from its own inventory,
//!   harvest and scan, and an id only looks up what the broker made. The ids the broker makes are of a
//!   fixed form (`s-<16 hex>` and so on), checked when read, so a path does not read as one.
//!   `ProgramId` is the one free-text id: it may hold any key name without a backslash or control
//!   character, and is only ever compared with the ids of the broker's own inventory and stored-fingerprint
//!   index, never turned into a registry path or a file name. The test
//!   `broker_requests_hold_only_ids_enums_booleans_and_integers` walks the schema of every one.
//!
//! Result and notification types do not refuse unknown members, so a newer server can add one.
//!
//! [`dtos`] lists every type with a fixture under `crates/purge-rpc/fixtures/` and its JSON Schema, for
//! `xtask gen-dto` and the fixture round trip.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use purge_model::exec::journal::UndoConflict;
use purge_model::exec::op::{ItemOutcome, OpId, OutcomeCounts, Sha256Hex};
use purge_model::exec::session::{
    Locker, RestorePointOutcome, RetentionClass, SessionId, SessionState, SessionSummary,
};
use purge_model::{
    Band, BaselineTrust, CandidateId, Category, FileTime, InstallScope, InstallerKind, ProgramId,
    RunOutcome, ScanMode, VerifyGone, WritableBy,
};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use serde_json::value::RawValue;

use crate::error::ErrorObject;
use crate::frame::{NotificationLine, RequestId};
use crate::sets::Transport;
use crate::table::{CallSet, Method, Notice};
use crate::{BaselineBuild, EngineHello};

// ---------------------------------------------------------------------------------------------------
// Ids the broker hands out.
// ---------------------------------------------------------------------------------------------------

/// Why a string is not an id of the expected kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdFormError {
    /// The id's prefix.
    pub prefix: &'static str,
}

impl fmt::Display for IdFormError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "an id of the form {}-<16 lower-case hex digits>",
            self.prefix
        )
    }
}

impl std::error::Error for IdFormError {}

macro_rules! broker_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal, $pattern:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(u64);

        impl $name {
            /// The prefix of the text form.
            pub const PREFIX: &'static str = $prefix;

            /// The id with these 64 bits (from the system's random source, or a stable hash).
            pub const fn from_bits(bits: u64) -> Self {
                Self(bits)
            }

            /// The 64 bits of the id.
            pub const fn bits(self) -> u64 {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($prefix, "-{:016x}"), self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdFormError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let error = IdFormError { prefix: $prefix };
                let hex = s
                    .strip_prefix(concat!($prefix, "-"))
                    .ok_or(error)?;
                if hex.len() != 16 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                    return Err(error);
                }
                u64::from_str_radix(hex, 16).map(Self).map_err(|_| error)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = Cow::<str>::deserialize(deserializer)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }

            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({ "type": "string", "pattern": $pattern })
            }
        }
    };
}

broker_id!(
    /// One harvest and uninstall of one program in the broker (`session_id`), e.g. `u-9f3a6c1d2b7e4a50`.
    /// Not the executor's [`SessionId`].
    UninstallSessionId,
    "u",
    "^u-[0-9a-f]{16}$"
);

broker_id!(
    /// One scan in the broker's memory, e.g. `s-9f3a6c1d2b7e4a50`.
    ScanId,
    "s",
    "^s-[0-9a-f]{16}$"
);

broker_id!(
    /// One plan in the broker's memory, e.g. `p-9f3a6c1d2b7e4a50`.
    PlanId,
    "p",
    "^p-[0-9a-f]{16}$"
);

broker_id!(
    /// One expired quarantine entry offered by `quarantine.expiring`, e.g. `e-9f3a6c1d2b7e4a50`.
    ExpiryId,
    "e",
    "^e-[0-9a-f]{16}$"
);

broker_id!(
    /// A candidate of a scan on the wire: the form `purge-scan` gives every candidate id
    /// (`c-<16 hex>`, a stable hash of the target). The client sends it back to select or explain a
    /// candidate; the broker looks it up in its own scan.
    CandidateRef,
    "c",
    "^c-[0-9a-f]{16}$"
);

impl TryFrom<&CandidateId> for CandidateRef {
    type Error = IdFormError;

    fn try_from(id: &CandidateId) -> Result<Self, Self::Error> {
        id.0.parse()
    }
}

impl From<CandidateRef> for CandidateId {
    fn from(id: CandidateRef) -> Self {
        CandidateId(id.to_string())
    }
}

/// The short code of a plan's confirm hash, `A1B2-C3D4`: its first eight hex digits, upper case. The UI
/// shows it while it waits; the consent dialog shows it in its footer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConfirmCode(u32);

impl ConfirmCode {
    /// The code of a confirm hash.
    pub fn of(confirm: &Sha256Hex) -> Self {
        let b = confirm.as_bytes();
        Self(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

impl fmt::Display for ConfirmCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04X}-{:04X}", self.0 >> 16, self.0 & 0xffff)
    }
}

impl FromStr for ConfirmCode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let error = "a code of the form XXXX-XXXX in upper-case hex";
        let b = s.as_bytes();
        let hex = |c: &u8| matches!(c, b'0'..=b'9' | b'A'..=b'F');
        if b.len() != 9 || b[4] != b'-' || !b[..4].iter().chain(&b[5..]).all(hex) {
            return Err(error);
        }
        let hi = u32::from_str_radix(&s[..4], 16).map_err(|_| error)?;
        let lo = u32::from_str_radix(&s[5..], 16).map_err(|_| error)?;
        Ok(Self(hi << 16 | lo))
    }
}

impl Serialize for ConfirmCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ConfirmCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = Cow::<str>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for ConfirmCode {
    fn schema_name() -> Cow<'static, str> {
        "ConfirmCode".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "string", "pattern": "^[0-9A-F]{4}-[0-9A-F]{4}$" })
    }
}

// ---------------------------------------------------------------------------------------------------
// Small request field types.
// ---------------------------------------------------------------------------------------------------

/// A list with at least one element.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct NonEmpty<T>(Vec<T>);

impl<T> NonEmpty<T> {
    /// The list, or `None` when it is empty.
    pub fn new(items: Vec<T>) -> Option<Self> {
        (!items.is_empty()).then_some(Self(items))
    }

    /// The elements.
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// The list.
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for NonEmpty<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = Vec::<T>::deserialize(deserializer)?;
        Self::new(items).ok_or_else(|| serde::de::Error::custom("the list is empty"))
    }
}

impl<T: JsonSchema> JsonSchema for NonEmpty<T> {
    fn schema_name() -> Cow<'static, str> {
        format!("NonEmpty_{}", T::schema_name()).into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "array",
            "items": generator.subschema_for::<T>(),
            "minItems": 1
        })
    }
}

/// The page size of `scan.candidates`: 1 to [`PageLimit::MAX`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct PageLimit(u16);

impl PageLimit {
    /// The largest page.
    pub const MAX: u16 = 500;

    /// The limit, or `None` outside 1 to [`PageLimit::MAX`].
    pub const fn new(limit: u16) -> Option<Self> {
        if limit >= 1 && limit <= Self::MAX {
            Some(Self(limit))
        } else {
            None
        }
    }

    /// The limit.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for PageLimit {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let limit = u16::deserialize(deserializer)?;
        Self::new(limit).ok_or_else(|| serde::de::Error::custom("limit is 1 to 500"))
    }
}

impl JsonSchema for PageLimit {
    fn schema_name() -> Cow<'static, str> {
        "PageLimit".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "integer", "minimum": 1, "maximum": 500 })
    }
}

/// The literal `true`; any other value fails when read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct True;

impl Serialize for True {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for True {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if bool::deserialize(deserializer)? {
            Ok(True)
        } else {
            Err(serde::de::Error::custom("only true is taken here"))
        }
    }
}

impl JsonSchema for True {
    fn schema_name() -> Cow<'static, str> {
        "True".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "boolean", "const": true })
    }
}

// ---------------------------------------------------------------------------------------------------
// Shared enums and records.
// ---------------------------------------------------------------------------------------------------

/// Where a program's uninstaller runs (design 3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    /// In the broker: a machine-scope entry whose uninstaller path has admin-only ancestors.
    Broker,
    /// In the medium engine, at the user's level: a per-user entry, or a path a user can write.
    Medium,
}

/// The engine token's `TokenElevationType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ElevationType {
    /// No split token (UAC off, or not an administrator).
    Default,
    /// The elevated half of an administrator token.
    Full,
    /// The limited half of an administrator token.
    Limited,
}

/// When `plan.execute` asks for a restore point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RestorePoint {
    /// Never.
    Off,
    /// Only for a high-risk run.
    HighRisk,
    /// For every run.
    Always,
}

/// What kind of thing an item is, for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    /// A file.
    File,
    /// A folder.
    Folder,
    /// A registry key.
    RegistryKey,
    /// A registry value.
    RegistryValue,
    /// Data inside a registry value (a changed value, a multi-string segment).
    RegistryData,
    /// A service.
    Service,
    /// A scheduled task.
    Task,
    /// A firewall rule.
    FirewallRule,
    /// An AppX package.
    Package,
}

/// Why an item is in a plan's attention list (design 8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttentionReason {
    /// The item is user data.
    UserData,
    /// The user ticked it; Purge did not preselect it.
    NotPreselected,
    /// The item is over 1 GB.
    Large,
    /// The removal cannot be put back (a package, or an item its op cannot undo).
    NoUndo,
    /// An item absorbed into it needs attention; that item is listed on its own.
    Inside,
    /// The item's name needs escapes for hidden or look-alike characters, or was shortened in the dialog.
    Name,
}

/// A warning for the user. `code` is stable for the client to switch on; `message` is shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Warning {
    /// A stable machine code, e.g. `baseline_inferred`.
    pub code: String,
    /// The text shown.
    pub message: String,
}

/// A running process that matters for an uninstall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunningProcess {
    /// Process id.
    pub pid: u32,
    /// Image name.
    pub name: String,
}

/// A program by id, with its display name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramRef {
    /// The program.
    pub program_id: ProgramId,
    /// Its display name.
    pub name: String,
}

/// Progress of a long request (`*.progress`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Progress {
    /// The request this belongs to.
    pub request: RequestId,
    /// The program, when the request covers several.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program_id: Option<ProgramId>,
    /// What runs now, e.g. `harvest`, `wait`, `verify`.
    pub phase: String,
    /// Steps done.
    pub done: u64,
    /// Steps in all, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

// ---------------------------------------------------------------------------------------------------
// Requests (params).
// ---------------------------------------------------------------------------------------------------

/// The params of a method that takes none: absent, `null` or `{}`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoParams {}

/// `{program_id}`: `programs.get`, `uninstall.route`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProgramParams {
    /// The program.
    pub program_id: ProgramId,
}

/// `{program_ids[]}`: `programs.sizes`, `uninstall.prepare`, `leftovers.stored`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProgramsParams {
    /// The programs, at least one.
    pub program_ids: NonEmpty<ProgramId>,
}

/// `programs.icons {program_ids[], px}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IconsParams {
    /// The programs, viewport first.
    pub program_ids: NonEmpty<ProgramId>,
    /// Edge length in pixels.
    pub px: u16,
}

/// `uninstall.run_user {program_id, quiet}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunUserParams {
    /// The program.
    pub program_id: ProgramId,
    /// Run the quiet uninstall command.
    pub quiet: bool,
}

/// `uninstall.run {session_id, quiet}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunParams {
    /// The uninstall session from `uninstall.prepare`.
    pub session_id: UninstallSessionId,
    /// Run the quiet uninstall command.
    pub quiet: bool,
}

/// `uninstall.observed {session_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservedParams {
    /// The uninstall session from `uninstall.prepare`.
    pub session_id: UninstallSessionId,
    /// How the medium engine's run ended, when it reports it. A failure (or a cancel, or a time-out)
    /// makes the scan `forced` with nothing preselected even when the program is gone; a success is
    /// never believed on its own: the broker's own verify-gone still decides. It can only make the
    /// scan safer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<RunOutcome>,
}

/// `leftovers.scan` after an uninstall of this broker: `{session_id, forced?}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanSessionParams {
    /// The uninstall session.
    pub session_id: UninstallSessionId,
    /// Ask for the forced mode. The client can lower the mode this way; it can never raise it.
    #[serde(default)]
    pub forced: bool,
}

/// `leftovers.scan` of a program removed outside Purge, from its stored fingerprint: `{program_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanStoredParams {
    /// The program whose stored fingerprint is scanned.
    pub program_id: ProgramId,
}

/// `leftovers.scan`: one of two forms.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum LeftoversScanParams {
    /// After an uninstall in this broker.
    Session(ScanSessionParams),
    /// From a stored fingerprint.
    Stored(ScanStoredParams),
}

/// `scan.candidates {scan_id, offset, limit}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidatesParams {
    /// The scan.
    pub scan_id: ScanId,
    /// Index of the first item.
    pub offset: u32,
    /// Items in the page, at most 500.
    pub limit: PageLimit,
}

/// `candidate.explain {scan_id, candidate_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExplainParams {
    /// The scan.
    pub scan_id: ScanId,
    /// The candidate.
    pub candidate_id: CandidateRef,
}

/// `plan.create` with the user's selection: `{scan_id, selected[]}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanSelectedParams {
    /// The scan.
    pub scan_id: ScanId,
    /// The selected candidates, at least one.
    pub selected: NonEmpty<CandidateRef>,
    /// Offer the removals that cannot be put back (packages) to the consent dialog. Off (the default),
    /// the dialog lists them as "Leave alone". On, the dialog names each of them, warns that it cannot
    /// be put back and gates its button behind the verification box: the dialog is the acknowledgement,
    /// this flag only lets it be asked.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_irreversible: bool,
}

/// `plan.create` with the scan's preselection: `{scan_id, preselected: true}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanPreselectedParams {
    /// The scan.
    pub scan_id: ScanId,
    /// Always `true`.
    pub preselected: True,
}

/// `plan.create`: one of two forms.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum PlanCreateParams {
    /// The user's selection.
    Selected(PlanSelectedParams),
    /// The scan's preselection.
    Preselected(PlanPreselectedParams),
}

/// `plan.execute {plan_id, restore_point}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanExecuteParams {
    /// The plan from `plan.create`.
    pub plan_id: PlanId,
    /// When to ask for a restore point.
    pub restore_point: RestorePoint,
}

/// `{session}`: `history.get`, `journal.resume`, `journal.rollback`, `journal.retry_held`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionParams {
    /// The executor session.
    pub session: SessionId,
}

/// `undo.run {session, item_ids?}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UndoParams {
    /// The executor session.
    pub session: SessionId,
    /// The ops to undo; absent for all of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_ids: Option<NonEmpty<OpId>>,
}

/// `quarantine.purge {expiry_ids[]}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PurgeParams {
    /// The expired entries from `quarantine.expiring`, at least one.
    pub expiry_ids: NonEmpty<ExpiryId>,
}

/// `$/cancel {request}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CancelParams {
    /// The request to stop.
    pub request: RequestId,
}

/// Reads params of type `T`: absent and `null` read as `{}`; anything but an object is `-32602`.
pub(crate) fn decode_params<T: DeserializeOwned>(
    params: Option<&RawValue>,
) -> Result<T, ErrorObject> {
    let text = params.map_or("{}", RawValue::get);
    if !text.starts_with('{') {
        return Err(ErrorObject::invalid_params("params are a JSON object"));
    }
    serde_json::from_str(text).map_err(|e| ErrorObject::invalid_params(e.to_string()))
}

// ---------------------------------------------------------------------------------------------------
// Results, medium engine.
// ---------------------------------------------------------------------------------------------------

/// `engine.hello` of the medium engine: [`EngineHello`] and the token facts of design 3.5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MediumHello {
    /// The common fields.
    #[serde(flatten)]
    pub hello: EngineHello,
    /// The engine token's elevation type.
    pub elevation_type: ElevationType,
    /// Whether the engine's token has the user and the elevation of the shell's token, so it may run a
    /// medium-route uninstaller.
    pub shell_matches: bool,
}

/// The result of a request whose data follows in notifications: how many items will follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Started {
    /// Items that will follow.
    pub count: u32,
}

/// One raw ARP row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramRow {
    /// The entry.
    pub program_id: ProgramId,
    /// `DisplayName`, or the key name.
    pub name: String,
    /// `Publisher`.
    #[serde(default)]
    pub publisher: Option<String>,
    /// `DisplayVersion`.
    #[serde(default)]
    pub version: Option<String>,
    /// Machine-wide or per-user.
    pub scope: InstallScope,
    /// `EstimatedSize` in bytes, when the entry states one.
    #[serde(default)]
    pub size_bytes: Option<u64>,
    /// The install time the entry suggests.
    #[serde(default)]
    pub install_time: Option<FileTime>,
}

/// Details for a row already sent; only the members that are present change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramPatch {
    /// The entry.
    pub program_id: ProgramId,
    /// The installer technology.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installer: Option<InstallerKind>,
    /// The MSI ProductCode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_code: Option<String>,
    /// The Burn bundle the entry belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<ProgramId>,
    /// Whether the entry is an AppX package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appx: Option<bool>,
    /// Whether the entry has `SystemComponent` set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_component: Option<bool>,
    /// Whether the entry has no `DisplayName` (the row's `name` is then its key name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unnamed: Option<bool>,
    /// The name of the parent Uninstall key (`ParentKeyName`), for entries that hang under another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_key: Option<String>,
}

/// `programs.get`: the details pane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramDetails {
    /// The row.
    #[serde(flatten)]
    pub row: ProgramRow,
    /// The installer technology.
    pub installer: InstallerKind,
    /// Who can write the Uninstall key.
    pub writable_by: WritableBy,
    /// `InstallLocation`, as written.
    #[serde(default)]
    pub install_location: Option<String>,
    /// `UninstallString`, as written.
    #[serde(default)]
    pub uninstall_command: Option<String>,
    /// `QuietUninstallString`, as written.
    #[serde(default)]
    pub quiet_uninstall_command: Option<String>,
    /// The MSI ProductCode.
    #[serde(default)]
    pub product_code: Option<String>,
}

/// One icon of an `icon.batch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Icon {
    /// The program.
    pub program_id: ProgramId,
    /// Edge length in pixels.
    pub px: u16,
    /// `px * px` BGRA pixels, base64; `None` when no icon could be read (the UI shows a placeholder).
    #[serde(default)]
    pub bgra: Option<String>,
}

/// One size of a `size.ready`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramSize {
    /// The program.
    pub program_id: ProgramId,
    /// Bytes on disk; `None` when they could not be measured.
    #[serde(default)]
    pub bytes: Option<u64>,
}

/// `inventory.changes`, against the last list stored in `%LOCALAPPDATA%\Purge` (display only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InventoryChanges {
    /// Programs in the stored list that are gone.
    pub disappeared: Vec<ProgramRef>,
    /// Programs that are new.
    pub appeared: Vec<ProgramRef>,
}

/// Quarantine usage and cap of one volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VolumeCap {
    /// The volume serial.
    pub serial: u64,
    /// Its root, for display.
    pub root: String,
    /// Bytes the quarantine holds on it.
    pub used: u64,
    /// The cap.
    pub cap: u64,
}

/// `history.index`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HistoryIndex {
    /// The sessions of `sessions\index.json`.
    pub sessions: Vec<SessionSummary>,
    /// Usage and cap per volume.
    pub volumes: Vec<VolumeCap>,
}

/// `uninstall.route`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RouteInfo {
    /// Where the uninstaller runs.
    pub route: Route,
    /// The command that will run.
    pub command: String,
    /// The quiet command, when there is one.
    #[serde(default)]
    pub quiet_command: Option<String>,
    /// The uninstaller's signer, when it is signed.
    #[serde(default)]
    pub signer: Option<String>,
    /// Processes of the program that run now.
    pub running: Vec<RunningProcess>,
}

/// `uninstall.run_user`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunUserResult {
    /// The exit code, when the process ended.
    #[serde(default)]
    pub exit_code: Option<u32>,
    /// What the run came to.
    pub outcome: RunOutcome,
}

// ---------------------------------------------------------------------------------------------------
// Results, broker.
// ---------------------------------------------------------------------------------------------------

/// A product removed together with the program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CoProduct {
    /// Its display name.
    pub name: String,
    /// Its entry, when it has one.
    #[serde(default)]
    pub program_id: Option<ProgramId>,
}

/// What a harvest found, in counts (display only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FingerprintSummary {
    /// Install roots.
    pub roots: u32,
    /// Files and folders recorded.
    pub files: u32,
    /// Registry keys and values recorded.
    pub registry: u32,
    /// Services, tasks and firewall rules recorded.
    pub objects: u32,
}

/// One program of `uninstall.prepare`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Prepared {
    /// The program.
    pub program_id: ProgramId,
    /// The uninstall session for the next steps.
    pub session_id: UninstallSessionId,
    /// Where its uninstaller runs.
    pub route: Route,
    /// The command that will run.
    pub command: String,
    /// The quiet command, when there is one.
    #[serde(default)]
    pub quiet_command: Option<String>,
    /// The uninstaller's signer, when it is signed.
    #[serde(default)]
    pub signer: Option<String>,
    /// Products removed with it.
    pub co_products: Vec<CoProduct>,
    /// Processes of the program that run now.
    pub running: Vec<RunningProcess>,
    /// What the harvest found.
    pub fingerprint_summary: FingerprintSummary,
    /// Warnings.
    pub warnings: Vec<Warning>,
}

/// `uninstall.prepare`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PrepareResult {
    /// One entry per program, in request order.
    pub programs: Vec<Prepared>,
}

/// `uninstall.run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunResult {
    /// The exit code, when the process ended.
    #[serde(default)]
    pub exit_code: Option<u32>,
    /// What the run came to.
    pub outcome: RunOutcome,
    /// The broker's own check that the program is gone.
    pub verify_gone: VerifyGone,
}

/// `uninstall.observed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ObservedResult {
    /// The broker's own check that the program is gone.
    pub verify_gone: VerifyGone,
}

/// `leftovers.stored`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StoredResult {
    /// The asked programs that have a stored fingerprint.
    pub stored: Vec<ProgramId>,
}

/// Candidates per band.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BandCounts {
    /// Band Safe.
    pub safe: u32,
    /// Band Likely.
    pub likely: u32,
    /// Band Weak.
    pub weak: u32,
    /// Band Blocked.
    pub blocked: u32,
    /// Preselected, over all bands.
    pub preselected: u32,
}

/// `leftovers.scan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScanResult {
    /// The scan, for the next requests.
    pub scan_id: ScanId,
    /// The mode the broker scanned in.
    pub mode: ScanMode,
    /// Candidates per band.
    pub counts: BandCounts,
    /// How far absence answers of the baseline view were trusted.
    pub baseline_trust: BaselineTrust,
    /// Warnings.
    pub warnings: Vec<Warning>,
}

/// One candidate of a `scan.candidates` page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CandidateRow {
    /// The candidate.
    pub candidate_id: CandidateRef,
    /// Its band.
    pub band: Band,
    /// What kind of thing it is.
    pub kind: ItemKind,
    /// Its category.
    pub category: Category,
    /// The name shown: a path, a key, a service name.
    pub display_name: String,
    /// The program it belongs to, when known.
    #[serde(default)]
    pub owner_program: Option<String>,
    /// Bytes, for files and folders.
    #[serde(default)]
    pub size_bytes: Option<u64>,
    /// Warnings about the item.
    pub warnings: Vec<Warning>,
    /// Whether Purge preselected it.
    pub preselected: bool,
}

/// `scan.candidates`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CandidatesPage {
    /// Candidates of the scan in all.
    pub total: u32,
    /// Index of the first item of the page.
    pub offset: u32,
    /// The page.
    pub items: Vec<CandidateRow>,
}

/// `candidate.explain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Explanation {
    /// The candidate.
    pub candidate_id: CandidateRef,
    /// The evidence, one line each.
    pub evidence: Vec<String>,
    /// What blocks it, one line each.
    pub blockers: Vec<String>,
}

/// An item of a plan's attention list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AttentionItem {
    /// The candidate.
    pub candidate_id: CandidateRef,
    /// The name shown.
    pub display_name: String,
    /// What kind of thing it is.
    pub kind: ItemKind,
    /// Its band.
    pub band: Band,
    /// Bytes, for files and folders.
    #[serde(default)]
    pub size_bytes: Option<u64>,
    /// Why it needs attention, at least one.
    pub reasons: Vec<AttentionReason>,
}

/// Item counts of a plan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PlanCounts {
    /// Selected items.
    pub items: u32,
    /// Of them, preselected by Purge.
    pub preselected: u32,
    /// Of them, ticked by the user.
    pub ticked: u32,
}

/// `plan.create`. A refused plan is the error `plan_refused`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PlanCreated {
    /// The plan, for `plan.execute`.
    pub plan_id: PlanId,
    /// The plan hash.
    pub plan_hash: Sha256Hex,
    /// The short code of the confirm hash; the consent dialog shows the same.
    pub code: ConfirmCode,
    /// Item counts.
    pub counts: PlanCounts,
    /// Bytes the plan moves to quarantine.
    pub bytes: u64,
    /// Items that need attention; never cut.
    pub attention: Vec<AttentionItem>,
    /// Warnings.
    pub warnings: Vec<Warning>,
}

/// An item left in place because it is locked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HeldItem {
    /// Its op.
    pub op: OpId,
    /// The name shown.
    pub display_name: String,
    /// The processes that hold it.
    pub lockers: Vec<Locker>,
}

/// `plan.execute`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExecResult {
    /// What the run did.
    pub outcome: crate::error::Outcome,
    /// The executor session.
    pub session: SessionId,
    /// Items per outcome.
    pub counts: OutcomeCounts,
    /// Items held by a lock.
    pub held: Vec<HeldItem>,
    /// What became of the restore point.
    pub restore_point: RestorePointOutcome,
}

/// One item of `history.get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HistoryItem {
    /// Its op.
    pub op: OpId,
    /// The name shown.
    pub display_name: String,
    /// What kind of thing it is.
    pub kind: ItemKind,
    /// How it ended.
    pub outcome: ItemOutcome,
    /// Whether it has been undone.
    pub undone: bool,
}

/// `history.get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HistoryDetail {
    /// The session.
    pub session: SessionId,
    /// Where it stands.
    pub state: SessionState,
    /// Its items.
    pub items: Vec<HistoryItem>,
}

/// One conflict of an undo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConflictRow {
    /// The op.
    pub op: OpId,
    /// The name shown.
    pub display_name: String,
    /// The conflict.
    pub conflict: UndoConflict,
}

/// `undo.run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UndoResult {
    /// What the undo did.
    pub outcome: crate::error::Outcome,
    /// The conflicts.
    pub conflicts: Vec<ConflictRow>,
}

/// An interrupted session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PendingSession {
    /// The session.
    pub session: SessionId,
    /// The app of its plan.
    pub app: String,
    /// When it started.
    pub started: FileTime,
    /// Items done.
    pub done: u32,
    /// Items in all.
    pub total: u32,
}

/// `journal.pending`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PendingList {
    /// The interrupted sessions.
    pub sessions: Vec<PendingSession>,
}

/// `journal.resume`, `journal.rollback`, `journal.retry_held`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OutcomeResult {
    /// What the run did.
    pub outcome: crate::error::Outcome,
}

/// One entry past retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExpiringItem {
    /// The id to purge it by.
    pub expiry_id: ExpiryId,
    /// Its session.
    pub session: SessionId,
    /// The app of the session.
    pub app: String,
    /// Which retention class expired.
    pub class: RetentionClass,
    /// When it expired.
    pub expired: FileTime,
    /// The files and backup files it holds, for display.
    pub files: Vec<String>,
    /// Bytes.
    pub bytes: u64,
    /// Whether it holds user data (each such item gets a dialog of its own).
    pub user_data: bool,
}

/// `quarantine.expiring`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExpiringList {
    /// The entries.
    pub items: Vec<ExpiringItem>,
}

/// `quarantine.purge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PurgeResult {
    /// What the purge did.
    pub outcome: crate::error::Outcome,
    /// Entries deleted.
    pub purged: u32,
    /// Entries kept.
    pub kept: u32,
}

/// `broker.shutdown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShutdownResult {
    /// Whether the broker exits now; `false` while something runs.
    pub exiting: bool,
}

// ---------------------------------------------------------------------------------------------------
// Notifications.
// ---------------------------------------------------------------------------------------------------

/// `programs.batch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramsBatch {
    /// The `programs.list` request.
    pub request: RequestId,
    /// The rows.
    pub rows: Vec<ProgramRow>,
}

/// `programs.patch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramsPatch {
    /// The `programs.list` request.
    pub request: RequestId,
    /// The patches.
    pub patches: Vec<ProgramPatch>,
}

/// Most icons in one `icon.batch` line.
pub const ICONS_PER_LINE: usize = 32;

/// `icon.batch`: at most [`ICONS_PER_LINE`] icons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IconBatch {
    /// The `programs.icons` request.
    pub request: RequestId,
    /// The icons.
    pub icons: Vec<Icon>,
}

/// `size.ready`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SizeReady {
    /// The `programs.sizes` request.
    pub request: RequestId,
    /// The sizes.
    pub sizes: Vec<ProgramSize>,
}

/// `baseline.changed`: the build state, and the scans worth making again when a build completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BaselineChanged {
    /// The build state.
    #[serde(flatten)]
    pub build: BaselineBuild,
    /// Scans made before the build ended.
    #[serde(default)]
    pub rescan_offered: Vec<ScanId>,
}

/// `consent.shown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConsentShown {
    /// The request that opened the dialog.
    pub request: RequestId,
    /// The code the dialog shows.
    pub code: ConfirmCode,
}

macro_rules! server_notifications {
    ($($variant:ident($payload:ty)),* $(,)?) => {
        /// A notification a server sends, with its params.
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum ServerNotification {
            $(
                #[doc = concat!("See [`Notice::", stringify!($variant), "`].")]
                $variant($payload),
            )*
        }

        impl ServerNotification {
            /// Which notification it is.
            pub fn notice(&self) -> Notice {
                match self {
                    $(ServerNotification::$variant(_) => Notice::$variant,)*
                }
            }

            /// Reads a notification a client received.
            pub fn decode(method: &str, params: Value) -> Result<Self, String> {
                $(
                    if method == Notice::$variant.name() {
                        return serde_json::from_value(params)
                            .map(ServerNotification::$variant)
                            .map_err(|e| e.to_string());
                    }
                )*
                Err(format!("unknown notification {method}"))
            }
        }

        impl Serialize for ServerNotification {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                match self {
                    $(ServerNotification::$variant(params) => NotificationLine {
                        method: Notice::$variant.name(),
                        params,
                    }
                    .serialize(serializer),)*
                }
            }
        }

        fn notification_dtos() -> Vec<Dto> {
            vec![$(Dto::of::<$payload>(
                format!("notification.{}", Notice::$variant.name()),
                Direction::Notification,
            ),)*]
        }
    };
}

server_notifications! {
    ProgramsBatch(ProgramsBatch),
    ProgramsPatch(ProgramsPatch),
    IconBatch(IconBatch),
    SizeReady(SizeReady),
    UninstallProgress(Progress),
    BaselineChanged(BaselineChanged),
    PrepareProgress(Progress),
    ScanProgress(Progress),
    ConsentShown(ConsentShown),
    ExecProgress(Progress),
    UndoProgress(Progress),
}

// ---------------------------------------------------------------------------------------------------
// Call sets.
// ---------------------------------------------------------------------------------------------------

macro_rules! call_set {
    ($(#[$meta:meta])* $name:ident, $transport:expr, $prefix:literal,
        { $($variant:ident($params:ty) -> $result:ty),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $name {
            $(
                #[doc = concat!("See [`Method::", stringify!($variant), "`]; result [`", stringify!($result), "`].")]
                $variant($params),
            )*
        }

        impl crate::table::sealed::Sealed for $name {}

        impl CallSet for $name {
            const TRANSPORT: Transport = $transport;

            fn decode(method: Method, params: Option<&RawValue>) -> Result<Self, ErrorObject> {
                match method {
                    $(Method::$variant => decode_params::<$params>(params).map($name::$variant),)*
                    #[allow(unreachable_patterns)]
                    _ => Err(ErrorObject::method_not_found()),
                }
            }

            fn method(&self) -> Method {
                match self {
                    $($name::$variant(_) => Method::$variant,)*
                }
            }
        }

        impl $name {
            /// The methods this set has a variant for.
            pub const METHODS: &[Method] = &[$(Method::$variant,)*];

            /// The params and result types of every method, with their fixture stems.
            pub fn dtos() -> Vec<Dto> {
                let mut out = Vec::new();
                $(
                    out.push(Dto::of::<$params>(
                        format!("{}.{}.params", $prefix, Method::$variant.name()),
                        Direction::Request($transport),
                    ));
                    out.push(Dto::of::<$result>(
                        format!("{}.{}.result", $prefix, Method::$variant.name()),
                        Direction::Result,
                    ));
                )*
                out
            }
        }
    };
}

call_set!(
    /// A request to the medium engine over stdio. There is no variant for an `Execute` or `Propose`
    /// method.
    StdioCall, Transport::Stdio, "stdio", {
        EngineHello(NoParams) -> MediumHello,
        ProgramsList(NoParams) -> Started,
        ProgramsGet(ProgramParams) -> ProgramDetails,
        ProgramsIcons(IconsParams) -> Started,
        ProgramsSizes(ProgramsParams) -> Started,
        InventoryChanges(NoParams) -> InventoryChanges,
        HistoryIndex(NoParams) -> HistoryIndex,
        UninstallRoute(ProgramParams) -> RouteInfo,
        UninstallRunUser(RunUserParams) -> RunUserResult,
    }
);

call_set!(
    /// A request to the broker over its pipe. There is no variant for a `UserRun` method.
    PipeCall, Transport::Pipe, "pipe", {
        EngineHello(NoParams) -> EngineHello,
        UninstallPrepare(ProgramsParams) -> PrepareResult,
        UninstallRun(RunParams) -> RunResult,
        UninstallObserved(ObservedParams) -> ObservedResult,
        LeftoversStored(ProgramsParams) -> StoredResult,
        LeftoversScan(LeftoversScanParams) -> ScanResult,
        ScanCandidates(CandidatesParams) -> CandidatesPage,
        CandidateExplain(ExplainParams) -> Explanation,
        PlanCreate(PlanCreateParams) -> PlanCreated,
        PlanExecute(PlanExecuteParams) -> ExecResult,
        HistoryGet(SessionParams) -> HistoryDetail,
        UndoRun(UndoParams) -> UndoResult,
        JournalPending(NoParams) -> PendingList,
        JournalResume(SessionParams) -> OutcomeResult,
        JournalRollback(SessionParams) -> OutcomeResult,
        JournalRetryHeld(SessionParams) -> OutcomeResult,
        QuarantineExpiring(NoParams) -> ExpiringList,
        QuarantinePurge(PurgeParams) -> PurgeResult,
        BrokerShutdown(NoParams) -> ShutdownResult,
    }
);

// ---------------------------------------------------------------------------------------------------
// The DTO registry.
// ---------------------------------------------------------------------------------------------------

/// Which way a DTO travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Params of a request (or the client's `$/cancel`) to a server of this transport.
    Request(Transport),
    /// A result.
    Result,
    /// A server notification's params.
    Notification,
    /// An error object.
    Error,
}

/// One type with a fixture file `fixtures/<stem>.json`.
#[derive(Debug, Clone)]
pub struct Dto {
    /// The fixture's file stem, e.g. `pipe.plan.execute.params`.
    pub stem: String,
    /// The Rust type's schema name.
    pub type_name: Cow<'static, str>,
    /// Which way it travels.
    pub direction: Direction,
    /// Its JSON Schema.
    pub schema: fn() -> Schema,
    /// Reads JSON text as the type and writes it back.
    pub round_trip: fn(&str) -> Result<Value, String>,
}

fn round_trip<T: Serialize + DeserializeOwned>(text: &str) -> Result<Value, String> {
    let value: T = serde_json::from_str(text).map_err(|e| e.to_string())?;
    serde_json::to_value(&value).map_err(|e| e.to_string())
}

fn schema_of<T: JsonSchema>() -> Schema {
    schemars::schema_for!(T)
}

impl Dto {
    fn of<T: Serialize + DeserializeOwned + JsonSchema>(
        stem: String,
        direction: Direction,
    ) -> Self {
        Self {
            stem,
            type_name: T::schema_name(),
            direction,
            schema: schema_of::<T>,
            round_trip: round_trip::<T>,
        }
    }
}

/// Every type of the engine API with a fixture: the params and result of every method of both call sets,
/// the second form of the two untagged params, `$/cancel`, every server notification, and one error
/// object per error kind.
pub fn dtos() -> Vec<Dto> {
    let mut out = StdioCall::dtos();
    out.extend(PipeCall::dtos());
    out.push(Dto::of::<LeftoversScanParams>(
        "pipe.leftovers.scan.params.stored".into(),
        Direction::Request(Transport::Pipe),
    ));
    out.push(Dto::of::<PlanCreateParams>(
        "pipe.plan.create.params.preselected".into(),
        Direction::Request(Transport::Pipe),
    ));
    for transport in Transport::ALL {
        let prefix = match transport {
            Transport::Stdio => "stdio",
            Transport::Pipe => "pipe",
        };
        out.push(Dto::of::<CancelParams>(
            format!("{prefix}.cancel.params"),
            Direction::Request(transport),
        ));
    }
    out.extend(notification_dtos());
    for kind in ERROR_KINDS {
        out.push(Dto::of::<ErrorObject>(
            format!("error.{kind}"),
            Direction::Error,
        ));
    }
    out
}

/// One type's schema, once per type, for `xtask gen-dto` (M3_DESIGN.md §6.5).
#[derive(Debug, Clone)]
pub struct SchemaExport {
    /// The schema name, which is also the schema file's stem (`EngineHello.json`).
    pub name: String,
    /// Its JSON Schema.
    pub schema: Schema,
}

/// The schema of every distinct type in [`dtos`], sorted by name. A type used by several DTOs (a shared
/// result, `ErrorObject`) appears once.
pub fn schemas() -> Vec<SchemaExport> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for dto in dtos() {
        if seen.insert(dto.type_name.clone()) {
            out.push(SchemaExport {
                name: dto.type_name.into_owned(),
                schema: (dto.schema)(),
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The `kind` of every [`ErrorData`] variant, one fixture each.
pub const ERROR_KINDS: [&str; 13] = [
    "consent_declined",
    "plan_refused",
    "needs_recovery",
    "store_integrity",
    "uninstall_failed",
    "other_account",
    "not_elevated",
    "install_untrusted",
    "wrong_route",
    "busy",
    "gone",
    "cap_exceeded",
    "runtime",
];
