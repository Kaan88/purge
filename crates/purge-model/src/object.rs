//! Identities and fingerprints of system objects: services, scheduled tasks and firewall rules
//! (contract C-OBJECT, M1b).
//!
//! # The object digest
//!
//! The scan, the harvest and the executor bind an act to the object the scan saw through one digest,
//! [`ObjectFp`]. Its input is defined here and nowhere else ([`ServiceIdentity::digest_input`],
//! [`TaskIdentity::digest_input`], [`FirewallIdentity::digest_input`]):
//!
//! ```text
//! purge.objfp/1 LF <kind> LF
//! then per field, in the order of the kind:  <field> '=' ( '-' | <decimal byte length> ':' <UTF-8 bytes> ) LF
//! ```
//!
//! `-` marks an absent field, so an absent value never equals an empty one, and every value carries its
//! length, so no value can spell a field boundary. The fields are:
//!
//! - service: `name` (folded with [`fold`]), `image_path` (as stored, `REG_EXPAND_SZ` not expanded),
//!   `service_dll`, `type`, `start` (decimal), `object_name`;
//! - task: `path` (folded), `count` (decimal number of actions), then per action `i` (from 0)
//!   `a<i>.kind`, `a<i>.path`, `a<i>.args`, `a<i>.dir`, `a<i>.clsid`, `a<i>.data` (see
//!   [`TaskAction`] for which are present);
//! - firewall rule: `id` and `rule`, both as stored.
//!
//! Only the service name and the task path are folded: Windows treats them case-insensitively. Every
//! other string is compared as stored, so a service whose `ImagePath` changed only in letter case has
//! another digest.
//!
//! # Firewall rule strings
//!
//! [`parse_firewall_rule`] splits the raw registry string of a rule
//! (`v2.33|Action=Allow|Dir=In|App=C:\x\a.exe|Name=X|`) into [`FirewallRuleFields`].
//!
//! # Re-creation (M1B-SPIKE)
//!
//! `vm/spikes/m1b/RESULT.json` measured a delete and re-create of each kind on Windows 11 26100. All three
//! re-create exactly: a firewall rule under its own id ([`FIREWALL_RESTORE_EXACT`]), a task from its XML
//! alone, a service from its key backup with the values written back. The two things that cannot come back
//! are a task's stored password (its re-registration is refused without it) and a service account's stored
//! password (the service re-creates, but without the secret). The scan states the second from the
//! definition ([`ServiceIdentity::account_builtin`]), because no comparison after the restore can see it.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Category, Target};

/// Whether a deleted firewall rule comes back exactly: same value name (= WMI `InstanceID`) and a
/// byte-equal rule string. Set from `vm/spikes/m1b/RESULT.json` (`firewall.exact`): the spike re-created
/// six rules with `IWbemServices::PutInstance(WBEM_FLAG_CREATE_ONLY)` and every one came back with its id
/// and string, stable across a reboot. So a firewall delete is reversible in full and undo re-creates the
/// rule under its own id; no re-create-under-a-new-id fallback exists.
pub const FIREWALL_RESTORE_EXACT: bool = true;

/// A form of firewall rule field whose exact re-creation the spike did not measure. The six spike rules
/// (`vm/spikes/m1b/RESULT.json`, `firewall.cases`) came back byte for byte with `Action` (Allow, Block),
/// `Active`, `Dir`, `Protocol` 6 and 17, `App`, `Svc`, `Name`, `Desc`, `EmbedCtxt`, `Defer=User`,
/// `LPort`, `LPort2_10`, `RPort`, `RA4`/`RA6` (literal addresses, subnets, ranges, `LocalSubnet` in both
/// families), `Profile` Private and Public, `IFType` Wireless and RemoteAccess. The mapping of the forms
/// below (`purge_win::firewall::map_rule`) is inferred from the provider's value tables only (M1b
/// reviews R1 S3, R2b S2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FirewallShape {
    /// `Edge=TRUE` (edge traversal), alone or with `Defer=App`.
    EdgeTraversal,
    /// `Defer=App`.
    DeferApp,
    /// `LSM` (loose source mapping).
    LooseSourceMapping,
    /// `LOM` (local only mapping).
    LocalOnlyMapping,
    /// `ICMP4` / `ICMP6` type and code entries.
    IcmpTypes,
    /// `LA4` / `LA6` (local addresses).
    LocalAddresses,
    /// `Profile=Domain`.
    DomainProfile,
    /// `RPort2_10` (a remote port range).
    RemotePortRange,
    /// `IFType=Lan`.
    LanInterface,
    /// `Protocol` other than 6 (TCP) or 17 (UDP).
    OtherProtocol,
}

/// The [`FirewallShape`]s not yet proven by a VM round trip (`create_with_instance_id` and a byte-equal
/// read back). A rule that uses one is not deleted: the executor's gate and the scanner both refuse it
/// (`CannotBackUp`), because a wrong mapping shows only at undo, when the half-made rule is deleted again
/// and the original is lost. The one list both read: when M1B-RIG-EXEC proves a shape on the VM, its
/// line is removed here.
pub const FIREWALL_UNPROVEN_SHAPES: &[FirewallShape] = &[
    FirewallShape::EdgeTraversal,
    FirewallShape::DeferApp,
    FirewallShape::LooseSourceMapping,
    FirewallShape::LocalOnlyMapping,
    FirewallShape::IcmpTypes,
    FirewallShape::LocalAddresses,
    FirewallShape::DomainProfile,
    FirewallShape::RemotePortRange,
    FirewallShape::LanInterface,
    FirewallShape::OtherProtocol,
];

impl FirewallShape {
    /// Every shape, in declaration order.
    pub const ALL: [FirewallShape; 10] = [
        FirewallShape::EdgeTraversal,
        FirewallShape::DeferApp,
        FirewallShape::LooseSourceMapping,
        FirewallShape::LocalOnlyMapping,
        FirewallShape::IcmpTypes,
        FirewallShape::LocalAddresses,
        FirewallShape::DomainProfile,
        FirewallShape::RemotePortRange,
        FirewallShape::LanInterface,
        FirewallShape::OtherProtocol,
    ];

    /// A short name for messages; the same text as `purge_win::firewall::RuleShape::name`.
    pub fn name(self) -> &'static str {
        match self {
            FirewallShape::EdgeTraversal => "Edge",
            FirewallShape::DeferApp => "Defer=App",
            FirewallShape::LooseSourceMapping => "LSM",
            FirewallShape::LocalOnlyMapping => "LOM",
            FirewallShape::IcmpTypes => "ICMP",
            FirewallShape::LocalAddresses => "local addresses",
            FirewallShape::DomainProfile => "Profile=Domain",
            FirewallShape::RemotePortRange => "RPort2_10",
            FirewallShape::LanInterface => "IFType=Lan",
            FirewallShape::OtherProtocol => "Protocol other than 6 or 17",
        }
    }

    /// Whether a VM round trip proved the shape (it is not in [`FIREWALL_UNPROVEN_SHAPES`]).
    pub fn is_proven(self) -> bool {
        !FIREWALL_UNPROVEN_SHAPES.contains(&self)
    }

    /// Whether `fields` use this shape. Keys compare ASCII case-insensitively, values exactly as stored
    /// (as `map_rule` reads them).
    pub fn used_by(self, fields: &[(String, String)]) -> bool {
        fields.iter().any(|(key, value)| {
            let k = key.to_ascii_uppercase();
            let v = value.as_str();
            match self {
                FirewallShape::EdgeTraversal => k == "EDGE",
                FirewallShape::DeferApp => k == "DEFER" && v == "App",
                FirewallShape::LooseSourceMapping => k == "LSM",
                FirewallShape::LocalOnlyMapping => k == "LOM",
                FirewallShape::IcmpTypes => k == "ICMP4" || k == "ICMP6",
                FirewallShape::LocalAddresses => k == "LA4" || k == "LA6",
                FirewallShape::DomainProfile => k == "PROFILE" && v == "Domain",
                FirewallShape::RemotePortRange => k == "RPORT2_10",
                FirewallShape::LanInterface => k == "IFTYPE" && v == "Lan",
                FirewallShape::OtherProtocol => k == "PROTOCOL" && v != "6" && v != "17",
            }
        })
    }

    /// The shapes `fields` use, each once, in declaration order.
    pub fn of(fields: &[(String, String)]) -> Vec<FirewallShape> {
        FirewallShape::ALL
            .into_iter()
            .filter(|s| s.used_by(fields))
            .collect()
    }

    /// The shapes `fields` use that are not proven: a rule with any is not deleted.
    pub fn unproven_in(fields: &[(String, String)]) -> Vec<FirewallShape> {
        FirewallShape::of(fields)
            .into_iter()
            .filter(|s| !s.is_proven())
            .collect()
    }
}

/// The first line of every object digest input.
const DIGEST_SCHEMA: &str = "purge.objfp/1";

/// The kind of a system object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum ObjectKind {
    /// A Windows service.
    #[serde(rename = "service")]
    Service,
    /// A scheduled task.
    #[serde(rename = "task")]
    Task,
    /// A Windows Firewall rule.
    #[serde(rename = "firewall_rule")]
    FirewallRule,
}

impl ObjectKind {
    /// Every kind, in declaration order.
    pub const ALL: [ObjectKind; 3] = [
        ObjectKind::Service,
        ObjectKind::Task,
        ObjectKind::FirewallRule,
    ];

    /// The kind's name as serialised, which is also the kind line of the digest input.
    pub fn name(self) -> &'static str {
        match self {
            ObjectKind::Service => "service",
            ObjectKind::Task => "task",
            ObjectKind::FirewallRule => "firewall_rule",
        }
    }

    /// The kind of object a target addresses; `None` for every target that is not a system object.
    pub fn of(target: &Target) -> Option<ObjectKind> {
        match target {
            Target::Service { .. } => Some(ObjectKind::Service),
            Target::Task { .. } => Some(ObjectKind::Task),
            Target::FirewallRule { .. } => Some(ObjectKind::FirewallRule),
            Target::Path { .. }
            | Target::RegKey { .. }
            | Target::RegValue { .. }
            | Target::RegValueChanged { .. }
            | Target::RegMultiSzSegment { .. }
            | Target::AppxPackage { .. } => None,
        }
    }

    /// The category a candidate for an object of this kind has (C-MODEL-SCOPE): services and firewall
    /// rules are [`Category::System`], tasks [`Category::Startup`].
    pub fn category(self) -> Category {
        match self {
            ObjectKind::Service | ObjectKind::FirewallRule => Category::System,
            ObjectKind::Task => Category::Startup,
        }
    }
}

/// Scan-time fingerprint of a system object: its kind and the SHA-256 of its identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObjectFp {
    /// What kind of object the digest covers.
    pub kind: ObjectKind,
    /// 64 lower-case hex digits.
    pub sha256: String,
}

impl ObjectFp {
    /// Whether `sha256` is exactly 64 lower-case hex digits. A digest in any other spelling matches no
    /// object; the executor treats it as absent.
    pub fn is_well_formed(&self) -> bool {
        self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    /// The fingerprint of a digest input.
    fn of(kind: ObjectKind, input: &[u8]) -> ObjectFp {
        let digest = Sha256::digest(input);
        let mut sha256 = String::with_capacity(64);
        for byte in digest {
            sha256.push(hex_digit(byte >> 4));
            sha256.push(hex_digit(byte & 0xf));
        }
        ObjectFp { kind, sha256 }
    }
}

/// One lower-case hex digit.
fn hex_digit(nibble: u8) -> char {
    char::from(b"0123456789abcdef"[usize::from(nibble & 0xf)])
}

/// Writes the digest input; see the module docs.
struct DigestInput(Vec<u8>);

impl DigestInput {
    fn new(kind: ObjectKind) -> Self {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(DIGEST_SCHEMA.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(kind.name().as_bytes());
        out.push(b'\n');
        DigestInput(out)
    }

    fn field(&mut self, name: &str, value: Option<&str>) {
        self.0.extend_from_slice(name.as_bytes());
        self.0.push(b'=');
        match value {
            None => self.0.push(b'-'),
            Some(value) => {
                self.0.extend_from_slice(value.len().to_string().as_bytes());
                self.0.push(b':');
                self.0.extend_from_slice(value.as_bytes());
            }
        }
        self.0.push(b'\n');
    }
}

/// What identifies a Windows service.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceIdentity {
    /// Service key name.
    pub name: String,
    /// `ImagePath` as stored (`REG_EXPAND_SZ` not expanded). The spike showed that
    /// `QueryServiceConfigW` returns it expanded; this is the raw registry string.
    pub image_path: Option<String>,
    /// `Parameters\ServiceDll`, else the top-level `ServiceDll`.
    pub service_dll: Option<String>,
    /// `Type`.
    pub service_type: u32,
    /// `Start`.
    pub start: u32,
    /// `ObjectName`.
    pub object_name: Option<String>,
}

impl ServiceIdentity {
    /// The exact bytes [`ServiceIdentity::fp`] hashes (see the module docs).
    pub fn digest_input(&self) -> Vec<u8> {
        let mut input = DigestInput::new(ObjectKind::Service);
        input.field("name", Some(&fold(&self.name)));
        input.field("image_path", self.image_path.as_deref());
        input.field("service_dll", self.service_dll.as_deref());
        input.field("type", Some(&self.service_type.to_string()));
        input.field("start", Some(&self.start.to_string()));
        input.field("object_name", self.object_name.as_deref());
        input.0
    }

    /// The service's fingerprint.
    pub fn fp(&self) -> ObjectFp {
        ObjectFp::of(ObjectKind::Service, &self.digest_input())
    }

    /// Whether the service runs under an account Windows holds no password for: no `ObjectName`,
    /// `LocalSystem`, `NT AUTHORITY\LocalService`, `NT AUTHORITY\NetworkService`, or a virtual account
    /// `NT SERVICE\...` (compared ignoring ASCII case).
    ///
    /// Any other account has a stored password. The spike showed that deleting the service deletes the
    /// password and that a re-created service starts without it, and that no comparison after the
    /// restore can see the loss. A delete of such a service is therefore `Reversibility::Partial` from
    /// this definition alone (C-DEF `account_builtin`), never from a restore comparison.
    pub fn account_builtin(&self) -> bool {
        let Some(account) = self.object_name.as_deref() else {
            return true;
        };
        [
            "LocalSystem",
            r"NT AUTHORITY\LocalService",
            r"NT AUTHORITY\NetworkService",
        ]
        .iter()
        .any(|builtin| account.eq_ignore_ascii_case(builtin))
            || account
                .get(..r"NT SERVICE\".len())
                .is_some_and(|head| head.eq_ignore_ascii_case(r"NT SERVICE\"))
    }
}

/// One action of a scheduled task. Serialised as an object tagged by `"kind"`:
/// `{"kind":"exec","path":...,"arguments":...,"working_dir":...}`,
/// `{"kind":"com_handler","clsid":...,"data":...}`, `{"kind":"other","other_kind":...}`.
///
/// In the digest input an exec action has `a<i>.kind` `exec` and its `path`, `args` and `dir`; a COM
/// handler has `com_handler` and its `clsid` and `data`; any other action has `other:<kind>` (so two
/// other actions of different kinds differ). The fields an action does not have are absent (`-`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum TaskAction {
    /// Run a program.
    #[serde(rename = "exec")]
    Exec {
        /// Program path, as stored.
        path: String,
        /// Command-line arguments.
        arguments: Option<String>,
        /// Working directory.
        working_dir: Option<String>,
    },
    /// Call a COM handler.
    #[serde(rename = "com_handler")]
    ComHandler {
        /// CLSID of the handler, as stored.
        clsid: String,
        /// Handler data.
        data: Option<String>,
    },
    /// Any other action type (send e-mail, show message).
    #[serde(rename = "other")]
    Other {
        /// Name of the action kind. Serialised as `other_kind`: the tag already uses `kind`, and serde
        /// refuses a field named like the tag.
        #[serde(rename = "other_kind")]
        kind: String,
    },
}

/// What identifies a scheduled task.
///
/// The spike re-registered tasks from their XML alone and got the XML and the security descriptor back
/// byte for byte. Task Scheduler regenerates the TaskCache values `Tree\Id` (a new task GUID),
/// `Tree\SD`, `DynamicInfo`, `Hash` and `Triggers` on every registration; none of them is part of this
/// identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskIdentity {
    /// Task path; starts with a backslash, as Task Scheduler returns it.
    pub path: String,
    /// The task's actions, in order. The order is part of the identity.
    pub actions: Vec<TaskAction>,
}

impl TaskIdentity {
    /// The exact bytes [`TaskIdentity::fp`] hashes (see the module docs).
    pub fn digest_input(&self) -> Vec<u8> {
        let mut input = DigestInput::new(ObjectKind::Task);
        input.field("path", Some(&fold(&self.path)));
        input.field("count", Some(&self.actions.len().to_string()));
        for (i, action) in self.actions.iter().enumerate() {
            let (kind, path, args, dir, clsid, data) = match action {
                TaskAction::Exec {
                    path,
                    arguments,
                    working_dir,
                } => (
                    "exec".to_owned(),
                    Some(path.as_str()),
                    arguments.as_deref(),
                    working_dir.as_deref(),
                    None,
                    None,
                ),
                TaskAction::ComHandler { clsid, data } => (
                    "com_handler".to_owned(),
                    None,
                    None,
                    None,
                    Some(clsid.as_str()),
                    data.as_deref(),
                ),
                TaskAction::Other { kind } => {
                    (format!("other:{kind}"), None, None, None, None, None)
                }
            };
            input.field(&format!("a{i}.kind"), Some(&kind));
            input.field(&format!("a{i}.path"), path);
            input.field(&format!("a{i}.args"), args);
            input.field(&format!("a{i}.dir"), dir);
            input.field(&format!("a{i}.clsid"), clsid);
            input.field(&format!("a{i}.data"), data);
        }
        input.0
    }

    /// The task's fingerprint.
    pub fn fp(&self) -> ObjectFp {
        ObjectFp::of(ObjectKind::Task, &self.digest_input())
    }
}

/// What identifies a firewall rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallIdentity {
    /// Registry value name, equal to the WMI `InstanceID`.
    pub id: String,
    /// The raw registry string, byte for byte.
    pub rule: String,
}

impl FirewallIdentity {
    /// The exact bytes [`FirewallIdentity::fp`] hashes (see the module docs).
    pub fn digest_input(&self) -> Vec<u8> {
        let mut input = DigestInput::new(ObjectKind::FirewallRule);
        input.field("id", Some(&self.id));
        input.field("rule", Some(&self.rule));
        input.0
    }

    /// The rule's fingerprint.
    pub fn fp(&self) -> ObjectFp {
        ObjectFp::of(ObjectKind::FirewallRule, &self.digest_input())
    }
}

/// The longest rule string [`parse_firewall_rule`] reads, in bytes.
pub const FIREWALL_RULE_MAX_BYTES: usize = 32 * 1024;

/// The fields of a firewall rule string, in stored order. A key that occurs several times (`RA4`,
/// `LPort`) keeps every occurrence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallRuleFields {
    /// The version segment, e.g. `v2.33`.
    pub version: String,
    /// `(key, value)` pairs in stored order, repeated keys kept. Serialised as `[[key, value], ...]`.
    pub fields: Vec<(String, String)>,
}

impl FirewallRuleFields {
    /// The value of the first field named `key` (ASCII case-insensitive).
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    /// The values of every field named `key` (ASCII case-insensitive), in stored order.
    pub fn get_all(&self, key: &str) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Whether `other` describes the same rule: the same multiset of (upper-cased key, value) pairs.
    /// The order of the fields and the version prefix do not count; how often a pair occurs does.
    pub fn same_rule(&self, other: &Self) -> bool {
        fn pairs(fields: &FirewallRuleFields) -> Vec<(String, &str)> {
            let mut out: Vec<(String, &str)> = fields
                .fields
                .iter()
                .map(|(k, v)| (k.to_ascii_uppercase(), v.as_str()))
                .collect();
            out.sort_unstable();
            out
        }
        self.fields.len() == other.fields.len() && pairs(self) == pairs(other)
    }
}

/// Why a firewall rule string does not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FwParseError {
    /// The string is empty.
    Empty,
    /// The first segment is not a version (`v<digits>.<digits>`).
    NoVersion,
    /// A non-empty segment after the version has no `=`. `index` counts the `|`-separated segments from
    /// 0 (the version).
    SegmentWithoutEquals {
        /// Position of the segment.
        index: usize,
    },
    /// The string is longer than [`FIREWALL_RULE_MAX_BYTES`].
    TooLong,
}

impl fmt::Display for FwParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the firewall rule string is empty"),
            Self::NoVersion => {
                f.write_str("the firewall rule string does not start with a version")
            }
            Self::SegmentWithoutEquals { index } => {
                write!(f, "segment {index} of the firewall rule string has no '='")
            }
            Self::TooLong => write!(
                f,
                "the firewall rule string is longer than {FIREWALL_RULE_MAX_BYTES} bytes"
            ),
        }
    }
}

impl std::error::Error for FwParseError {}

/// Whether `segment` is a rule version: `v`, digits, `.`, digits.
fn is_version(segment: &str) -> bool {
    let Some(rest) = segment.strip_prefix('v') else {
        return false;
    };
    let Some((major, minor)) = rest.split_once('.') else {
        return false;
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    digits(major) && digits(minor)
}

/// Parses the raw registry string of a firewall rule, e.g.
/// `v2.31|Action=Allow|Active=TRUE|Dir=In|App=C:\x\a.exe|Name=X|`.
///
/// The first `|`-separated segment is the version; every other non-empty segment must hold `=`, and its
/// key is what comes before the first `=`, its value everything after it. Empty segments (the trailing
/// `|`) are skipped. Windows cannot store a `|` inside a value, so a value holding one is read as two
/// segments. Never panics.
pub fn parse_firewall_rule(raw: &str) -> Result<FirewallRuleFields, FwParseError> {
    if raw.len() > FIREWALL_RULE_MAX_BYTES {
        return Err(FwParseError::TooLong);
    }
    if raw.is_empty() {
        return Err(FwParseError::Empty);
    }
    let mut segments = raw.split('|');
    let version = segments.next().unwrap_or_default();
    if !is_version(version) {
        return Err(FwParseError::NoVersion);
    }
    let mut fields = Vec::new();
    for (index, segment) in segments.enumerate() {
        if segment.is_empty() {
            continue;
        }
        let Some((key, value)) = segment.split_once('=') else {
            return Err(FwParseError::SegmentWithoutEquals { index: index + 1 });
        };
        fields.push((key.to_owned(), value.to_owned()));
    }
    Ok(FirewallRuleFields {
        version: version.to_owned(),
        fields,
    })
}

/// Ranges of letters that Unicode gives a lower-case form and Windows does not fold: the name with
/// the capital and the name with the small letter are two folders and two keys (letters cased
/// after the Windows table was drawn up: Georgian Mtavruli, Cherokee, late Latin and Cyrillic
/// additions, the title-case digraphs). Measured on Windows 11 build 26300, on an NTFS volume and
/// in a registry hive, for every pair below U+10000 that the rule of [`fold_char`] would join;
/// both gave the same 194 letters. The small letters inside a range fold to themselves anyway.
const WINDOWS_KEEPS_APART: &[(u32, u32)] = &[
    (0x01C5, 0x01C5),
    (0x01C8, 0x01C8),
    (0x01CB, 0x01CB),
    (0x01F2, 0x01F2),
    (0x037F, 0x037F),
    (0x0524, 0x052F),
    (0x10C7, 0x10CD),
    (0x13A0, 0x13F5),
    (0x1C90, 0x1CBF),
    (0x2C2F, 0x2C2F),
    (0x2C70, 0x2C70),
    (0x2C7E, 0x2C7F),
    (0x2CEB, 0x2CF2),
    (0xA660, 0xA660),
    (0xA698, 0xA69A),
    (0xA78D, 0xA7F5),
];

/// One character folded for case-insensitive comparison: its lower-case form when that is the same
/// letter (upper-casing the lower-case form gives what upper-casing the character gives), else the
/// character itself. `K` and `k` fold to `k`; the Kelvin sign, whose lower-case form is the `k` of
/// another letter, stays the Kelvin sign.
///
/// Windows folds less than Unicode does, and folding more than Windows calls two different names
/// one. A character outside the Basic Multilingual Plane is never folded (NTFS and the registry
/// compare UTF-16 units and cannot join a surrogate pair), and neither is a letter of
/// [`WINDOWS_KEEPS_APART`].
///
/// This is the engine's one fold: `purge_guard::prefix` re-exports it, and the object digest folds
/// service names and task paths with it.
pub fn fold_char(c: char) -> impl Iterator<Item = char> {
    let code = u32::from(c);
    let apart = code > 0xFFFF
        || WINDOWS_KEEPS_APART
            .iter()
            .any(|(first, last)| (*first..=*last).contains(&code));
    let (lower, keep) = if c.is_ascii() {
        (None, Some(c.to_ascii_lowercase()))
    } else if !apart
        && c.to_lowercase()
            .flat_map(char::to_uppercase)
            .eq(c.to_uppercase())
    {
        (Some(c.to_lowercase()), None)
    } else {
        (None, Some(c))
    };
    lower.into_iter().flatten().chain(keep)
}

/// Folds a string for case-insensitive comparison or use as a map key ([`fold_char`] per character).
pub fn fold(s: &str) -> String {
    s.chars().flat_map(fold_char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn service() -> ServiceIdentity {
        ServiceIdentity {
            name: "PurgeSpikeS1".into(),
            image_path: Some(r#""C:\Program Files\PurgeSpike\svc.exe" -run"#.into()),
            service_dll: None,
            service_type: 16,
            start: 3,
            object_name: Some("LocalSystem".into()),
        }
    }

    fn exec(path: &str, arguments: Option<&str>) -> TaskAction {
        TaskAction::Exec {
            path: path.into(),
            arguments: arguments.map(Into::into),
            working_dir: None,
        }
    }

    fn task() -> TaskIdentity {
        TaskIdentity {
            path: r"\PurgeSpikeVendor\T5".into(),
            actions: vec![
                exec(r"C:\Program Files\PurgeSpike\app.exe", Some("--update")),
                TaskAction::ComHandler {
                    clsid: "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}".into(),
                    data: Some(String::new()),
                },
            ],
        }
    }

    const FW1: &str = r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=C:\Program Files\PurgeSpike\app1.exe|Name=PurgeSpike F1 program|Defer=User|";

    fn firewall() -> FirewallIdentity {
        FirewallIdentity {
            id: "{dee51bba-69c3-4c90-9f22-faf95c857815}".into(),
            rule: FW1.into(),
        }
    }

    /// The golden digests were computed outside Rust (Python `hashlib` over the byte sequence the module
    /// docs define), so scan, harvest and executor can never drift apart unnoticed.
    #[test]
    fn objfp_golden_service() {
        let s = service();
        assert_eq!(
            String::from_utf8(s.digest_input()).unwrap(),
            concat!(
                "purge.objfp/1\nservice\n",
                "name=12:purgespikes1\n",
                "image_path=42:\"C:\\Program Files\\PurgeSpike\\svc.exe\" -run\n",
                "service_dll=-\n",
                "type=2:16\n",
                "start=1:3\n",
                "object_name=11:LocalSystem\n",
            )
        );
        assert_eq!(
            s.fp(),
            ObjectFp {
                kind: ObjectKind::Service,
                sha256: "971eccc7bd4d8e319d26b61e8ce5a2862f44e7653ed48e8d922dea80bb81575c".into()
            }
        );
        assert!(s.fp().is_well_formed());
    }

    #[test]
    fn objfp_golden_task() {
        let t = task();
        assert_eq!(
            String::from_utf8(t.digest_input()).unwrap(),
            concat!(
                "purge.objfp/1\ntask\n",
                "path=20:\\purgespikevendor\\t5\n",
                "count=1:2\n",
                "a0.kind=4:exec\n",
                "a0.path=35:C:\\Program Files\\PurgeSpike\\app.exe\n",
                "a0.args=8:--update\n",
                "a0.dir=-\n",
                "a0.clsid=-\n",
                "a0.data=-\n",
                "a1.kind=11:com_handler\n",
                "a1.path=-\n",
                "a1.args=-\n",
                "a1.dir=-\n",
                "a1.clsid=38:{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}\n",
                "a1.data=0:\n",
            )
        );
        assert_eq!(
            t.fp().sha256,
            "50a506e7e356369130d1802404b96f3ce43b9a37c9ccb144b9fc3091f90fee85"
        );
        assert_eq!(t.fp().kind, ObjectKind::Task);
    }

    #[test]
    fn objfp_golden_firewall() {
        let f = firewall();
        assert_eq!(
            String::from_utf8(f.digest_input()).unwrap(),
            format!(
                "purge.objfp/1\nfirewall_rule\nid=38:{{dee51bba-69c3-4c90-9f22-faf95c857815}}\nrule={}:{FW1}\n",
                FW1.len()
            )
        );
        assert_eq!(
            f.fp().sha256,
            "41ea393dd324a9da054d885894844c1c771387577047888e02edc691bed8426b"
        );
        assert_eq!(f.fp().kind, ObjectKind::FirewallRule);
    }

    /// Hostile: an absent field and an empty one are different objects.
    #[test]
    fn objfp_absent_field_differs_from_empty_string() {
        let absent = service();
        for field in 0..3 {
            let mut empty = absent.clone();
            let mut absent = absent.clone();
            match field {
                0 => (absent.image_path, empty.image_path) = (None, Some(String::new())),
                1 => (absent.service_dll, empty.service_dll) = (None, Some(String::new())),
                _ => (absent.object_name, empty.object_name) = (None, Some(String::new())),
            }
            assert_ne!(absent.fp(), empty.fp(), "field {field}");
        }
        let with = |arguments: Option<&str>| TaskIdentity {
            path: r"\T".into(),
            actions: vec![exec("a.exe", arguments)],
        };
        assert_ne!(with(None).fp(), with(Some("")).fp());
        let handler = |data: Option<&str>| TaskIdentity {
            path: r"\T".into(),
            actions: vec![TaskAction::ComHandler {
                clsid: "{1}".into(),
                data: data.map(Into::into),
            }],
        };
        assert_ne!(handler(None).fp(), handler(Some("")).fp());
        // No actions at all against one empty action.
        assert_ne!(
            TaskIdentity {
                path: r"\T".into(),
                actions: vec![]
            }
            .fp(),
            with(None).fp()
        );
    }

    /// Hostile: a value that spells a field boundary cannot pass for two fields.
    #[test]
    fn objfp_field_boundary_cannot_be_forged() {
        let forged = ServiceIdentity {
            name: "a\nimage_path=1:x".into(),
            image_path: None,
            ..service()
        };
        let honest = ServiceIdentity {
            name: "a".into(),
            image_path: Some("x".into()),
            ..service()
        };
        assert_ne!(forged.fp(), honest.fp());
        assert_ne!(forged.digest_input(), honest.digest_input());
        // The same with the length the forger would have to guess, and through the task actions.
        let forged = ServiceIdentity {
            name: "a\nimage_path=1:x\nservice_dll=-".into(),
            image_path: None,
            service_dll: None,
            ..service()
        };
        assert_ne!(forged.fp(), honest.fp());
        let one = TaskIdentity {
            path: r"\T".into(),
            actions: vec![exec("a.exe\na0.args=1:b", None)],
        };
        let two = TaskIdentity {
            path: r"\T".into(),
            actions: vec![exec("a.exe", Some("b"))],
        };
        assert_ne!(one.fp(), two.fp());
        // An `other` action cannot pass for an exec one.
        let other = TaskIdentity {
            path: r"\T".into(),
            actions: vec![TaskAction::Other {
                kind: "exec".into(),
            }],
        };
        let email = TaskIdentity {
            path: r"\T".into(),
            actions: vec![TaskAction::Other {
                kind: "email".into(),
            }],
        };
        let plain = TaskIdentity {
            path: r"\T".into(),
            actions: vec![TaskAction::Exec {
                path: String::new(),
                arguments: None,
                working_dir: None,
            }],
        };
        assert_ne!(other.fp(), email.fp());
        assert_ne!(other.fp(), plain.fp());
        // The kind line is hashed: equal text under another kind is another digest.
        let fw = FirewallIdentity {
            id: "x".into(),
            rule: "y".into(),
        };
        let mut as_service = fw.digest_input();
        let at = as_service.iter().position(|b| *b == b'\n').unwrap() + 1;
        as_service.splice(at..at + "firewall_rule".len(), b"service".iter().copied());
        assert_ne!(
            fw.fp().sha256,
            ObjectFp::of(ObjectKind::Service, &as_service).sha256
        );
    }

    #[test]
    fn objfp_service_name_case_folded_imagepath_not() {
        let base = service();
        let upper = ServiceIdentity {
            name: "PURGESPIKES1".into(),
            ..base.clone()
        };
        assert_eq!(base.fp(), upper.fp());
        let image = ServiceIdentity {
            image_path: Some(r#""C:\PROGRAM FILES\PurgeSpike\svc.exe" -run"#.into()),
            ..base.clone()
        };
        assert_ne!(base.fp(), image.fp());
        let dll = ServiceIdentity {
            service_dll: Some(r"C:\X\a.dll".into()),
            ..base.clone()
        };
        let dll_upper = ServiceIdentity {
            service_dll: Some(r"C:\X\A.dll".into()),
            ..base.clone()
        };
        assert_ne!(dll.fp(), dll_upper.fp());
        let account = ServiceIdentity {
            object_name: Some("localsystem".into()),
            ..base.clone()
        };
        assert_ne!(base.fp(), account.fp());
        // Type and start are part of it.
        assert_ne!(
            base.fp(),
            ServiceIdentity {
                start: 2,
                ..base.clone()
            }
            .fp()
        );
        assert_ne!(
            base.fp(),
            ServiceIdentity {
                service_type: 32,
                ..base.clone()
            }
            .fp()
        );
        // The fold is the engine's: the Kelvin sign is not `K`.
        let kelvin = ServiceIdentity {
            name: "\u{212A}odi".into(),
            ..base.clone()
        };
        let k = ServiceIdentity {
            name: "Kodi".into(),
            ..base.clone()
        };
        assert_ne!(kelvin.fp(), k.fp());
        assert_eq!(
            k.fp(),
            ServiceIdentity {
                name: "kODI".into(),
                ..base
            }
            .fp()
        );
        // Task paths fold too; the actions do not.
        let mut t = task();
        t.path = t.path.to_uppercase();
        assert_eq!(t.fp(), task().fp());
        if let TaskAction::Exec { path, .. } = &mut t.actions[0] {
            *path = path.to_uppercase();
        }
        assert_ne!(t.fp(), task().fp());
        // Firewall ids are compared as stored.
        let mut f = firewall();
        f.id = f.id.to_uppercase();
        assert_ne!(f.fp(), firewall().fp());
    }

    #[test]
    fn objfp_task_action_order_matters() {
        let t = task();
        let mut reversed = t.clone();
        reversed.actions.reverse();
        assert_ne!(t.fp(), reversed.fp());
        let a = TaskIdentity {
            path: r"\T".into(),
            actions: vec![exec("a.exe", None), exec("b.exe", None)],
        };
        let b = TaskIdentity {
            path: r"\T".into(),
            actions: vec![exec("b.exe", None), exec("a.exe", None)],
        };
        assert_ne!(a.fp(), b.fp());
        let mut once = a.clone();
        once.actions.pop();
        assert_ne!(a.fp(), once.fp());
    }

    #[test]
    fn object_fp_shape_and_kind_of_targets() {
        assert!(
            !ObjectFp {
                kind: ObjectKind::Task,
                sha256: "971ECCC7BD4D8E319D26B61E8CE5A2862F44E7653ED48E8D922DEA80BB81575C".into()
            }
            .is_well_formed()
        );
        for bad in ["", "abc", &"g".repeat(64), &"a".repeat(65), &"é".repeat(32)] {
            assert!(
                !ObjectFp {
                    kind: ObjectKind::Task,
                    sha256: bad.to_owned()
                }
                .is_well_formed(),
                "{bad}"
            );
        }
        let fp = service().fp();
        let v = serde_json::to_value(&fp).unwrap();
        assert_eq!(v, json!({"kind": "service", "sha256": fp.sha256}));
        assert_eq!(serde_json::from_value::<ObjectFp>(v).unwrap(), fp);
        assert!(
            serde_json::from_value::<ObjectFp>(
                json!({"kind": "service", "sha256": fp.sha256, "x": 1})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<ObjectFp>(json!({"kind": "Service", "sha256": "a"})).is_err()
        );
        for kind in ObjectKind::ALL {
            assert_eq!(serde_json::to_value(kind).unwrap(), json!(kind.name()));
        }
        let p = || "x".to_owned();
        assert_eq!(
            ObjectKind::of(&Target::Service { name: p() }),
            Some(ObjectKind::Service)
        );
        assert_eq!(
            ObjectKind::of(&Target::Task { path: p() }),
            Some(ObjectKind::Task)
        );
        assert_eq!(
            ObjectKind::of(&Target::FirewallRule { id: p() }),
            Some(ObjectKind::FirewallRule)
        );
        assert_eq!(ObjectKind::of(&Target::RegKey { path: p() }), None);
        assert_eq!(ObjectKind::Service.category(), Category::System);
        assert_eq!(ObjectKind::FirewallRule.category(), Category::System);
        assert_eq!(ObjectKind::Task.category(), Category::Startup);
    }

    #[test]
    fn identities_are_strict_json() {
        let t: TaskIdentity = serde_json::from_value(json!({
            "path": "\\V\\T",
            "actions": [
                {"kind": "exec", "path": "a.exe", "arguments": null, "working_dir": "C:\\"},
                {"kind": "com_handler", "clsid": "{1}", "data": null},
                {"kind": "other", "other_kind": "email"}
            ]
        }))
        .unwrap();
        assert_eq!(
            t.actions[2],
            TaskAction::Other {
                kind: "email".into()
            }
        );
        assert_eq!(
            serde_json::to_value(&t.actions[2]).unwrap(),
            json!({"kind": "other", "other_kind": "email"})
        );
        for bad in [
            json!({"path": "\\T", "actions": [], "x": 1}),
            json!({"path": "\\T", "actions": [{"kind": "exec", "path": "a", "arguments": null,
                   "working_dir": null, "extra": 1}]}),
            json!({"path": "\\T", "actions": [{"kind": "other", "kind2": "x"}]}),
            json!({"path": "\\T", "actions": [{"kind": "show_message"}]}),
        ] {
            assert!(
                serde_json::from_value::<TaskIdentity>(bad.clone()).is_err(),
                "{bad}"
            );
        }
        let s = serde_json::to_value(service()).unwrap();
        assert_eq!(
            serde_json::from_value::<ServiceIdentity>(s.clone()).unwrap(),
            service()
        );
        let mut extra = s;
        extra["display_name"] = json!("x");
        assert!(serde_json::from_value::<ServiceIdentity>(extra).is_err());
        assert!(
            serde_json::from_value::<FirewallIdentity>(json!({"id": "a", "rule": "b", "c": 1}))
                .is_err()
        );
        assert_eq!(TaskIdentity::default().actions.len(), 0);
        assert!(schemars::schema_for!(TaskIdentity).as_object().is_some());
    }

    /// The C-DEF rule, which decides `Reversibility::Partial` for a service delete (the spike: the stored
    /// password is gone after the delete, and no restore comparison can see it).
    #[test]
    fn account_builtin_follows_the_definition() {
        let with = |account: Option<&str>| ServiceIdentity {
            object_name: account.map(Into::into),
            ..service()
        };
        for builtin in [
            None,
            Some("LocalSystem"),
            Some("localsystem"),
            Some(r"NT AUTHORITY\LocalService"),
            Some(r"NT Authority\NetworkService"),
            Some(r"NT SERVICE\MSSQLSERVER"),
            Some(r"nt service\x"),
        ] {
            assert!(with(builtin).account_builtin(), "{builtin:?}");
        }
        for stored in [
            Some(r".\purgespike"),
            Some(r"DOMAIN\svc"),
            Some("svc@example.test"),
            Some(""),
            Some(r"NT SERVICE"),
            Some(r"NT AUTHORITY\SYSTEM2"),
            Some("LocalSystem "),
            Some("\u{e9}"),
        ] {
            assert!(!with(stored).account_builtin(), "{stored:?}");
        }
    }

    /// Ten rule strings as Windows 11 stores them: the spike's own rules (vm/spikes/m1b/RESULT.json) and
    /// stock rules of a Windows 11 26300 host. The `LUOwn` SID of the last one is replaced.
    const REAL_RULES: [&str; 10] = [
        r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=8080|LPort2_10=8090-8095|Name=PurgeSpike F2 port|",
        r"v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|RPort=53|RA4=LocalSubnet|RA6=LocalSubnet|RA4=192.168.1.0/255.255.255.0|RA4=10.0.0.1|RA4=10.1.1.1-10.1.1.9|RA6=fe80::1|Name=PurgeSpike F3 remote|",
        r"v2.33|Action=Allow|Active=FALSE|Dir=In|Profile=Private|Profile=Public|IFType=Wireless|IFType=RemoteAccess|App=C:\Program Files\PurgeSpike\app5.exe|Name=PurgeSpike F5 iftype|",
        r"v2.33|Action=Allow|Active=TRUE|Dir=Out|App=C:\Program Files\PurgeSpike\app6.exe|Name=PurgeSpike F6 group|Desc=Purge spike rule 6: a=b, c|EmbedCtxt=PurgeSpike Group|",
        r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort2_10=5000-5020|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\system32\svchost.exe|Svc=FrameServer|Name=@FirewallAPI.dll,-54006|Desc=@FirewallAPI.dll,-54007|EmbedCtxt=@FirewallAPI.dll,-54001|",
        r"v2.33|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|LPort2_10=49152-65535|App=%SystemRoot%\system32\svchost.exe|Svc=DmEnrollmentSvc|Name=@FirewallAPI.dll,-37505|Desc=@FirewallAPI.dll,-37506|EmbedCtxt=@FirewallAPI.dll,-37502|",
        r"v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\system32\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32765|Desc=@FirewallAPI.dll,-32768|EmbedCtxt=@FirewallAPI.dll,-32752|",
        r"v2.33|Action=Allow|Active=TRUE|Dir=Out|Profile=Public|App=%SystemRoot%\system32\spoolsv.exe|Svc=Spooler|Name=@FirewallAPI.dll,-36858|Desc=@FirewallAPI.dll,-36859|EmbedCtxt=@FirewallAPI.dll,-36851|TTK2_22=WFDPrint|",
        r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=1|ICMP4=3:4|App=System|Name=@FirewallAPI.dll,-25251|Desc=@FirewallAPI.dll,-25257|EmbedCtxt=@FirewallAPI.dll,-25000|",
        r"v2.33|Action=Allow|Active=TRUE|Dir=Out|Name=@{Microsoft.Edge.GameAssist_1.0.4019.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.Edge.GameAssist/Resources/EdgeGameBarPackageDisplayName}|Desc=@{Microsoft.Edge.GameAssist_1.0.4019.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.Edge.GameAssist/Resources/EdgeGameBarPackageDisplayName}|PFN=Microsoft.Edge.GameAssist_8wekyb3d8bbwe|LUOwn=S-1-5-21-1-2-3-1001|EmbedCtxt=@{Microsoft.Edge.GameAssist_1.0.4019.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.Edge.GameAssist/Resources/EdgeGameBarPackageDisplayName}|Platform=2:6:2|Platform2=GTEQ|",
    ];

    #[test]
    fn fw_parse_real_rules() {
        let parsed: Vec<FirewallRuleFields> = REAL_RULES
            .iter()
            .map(|raw| parse_firewall_rule(raw).unwrap_or_else(|e| panic!("{raw}: {e}")))
            .collect();
        for (fields, raw) in parsed.iter().zip(REAL_RULES) {
            assert_eq!(fields.version, "v2.33");
            // Every segment between the version and the trailing `|` is one field.
            assert_eq!(fields.fields.len(), raw.matches('|').count() - 1, "{raw}");
            assert!(
                fields.get("Name").is_some() && fields.get("action").is_some(),
                "{raw}"
            );
        }
        // Port lists and ranges.
        assert_eq!(parsed[0].get("LPort"), Some("8080"));
        assert_eq!(parsed[0].get("lport2_10"), Some("8090-8095"));
        // Repeated RA4, in stored order.
        assert_eq!(
            parsed[1].get_all("RA4"),
            [
                "LocalSubnet",
                "192.168.1.0/255.255.255.0",
                "10.0.0.1",
                "10.1.1.1-10.1.1.9"
            ]
        );
        assert_eq!(parsed[1].get_all("ra6"), ["LocalSubnet", "fe80::1"]);
        assert_eq!(parsed[2].get_all("Profile"), ["Private", "Public"]);
        // A value holding `=` and `,` keeps everything after the first `=`.
        assert_eq!(parsed[3].get("Desc"), Some("Purge spike rule 6: a=b, c"));
        assert_eq!(parsed[3].get("EmbedCtxt"), Some("PurgeSpike Group"));
        // Resource names.
        assert_eq!(parsed[4].get("Name"), Some("@FirewallAPI.dll,-54006"));
        assert_eq!(parsed[4].get("EmbedCtxt"), Some("@FirewallAPI.dll,-54001"));
        assert_eq!(parsed[4].get("Svc"), Some("FrameServer"));
        assert_eq!(parsed[8].get("ICMP4"), Some("3:4"));
        assert!(
            parsed[9]
                .get("Name")
                .unwrap()
                .starts_with("@{Microsoft.Edge.GameAssist")
        );
        assert_eq!(
            parsed[9].get("PFN"),
            Some("Microsoft.Edge.GameAssist_8wekyb3d8bbwe")
        );
        assert_eq!(parsed[9].get("Missing"), None);
        assert!(parsed[9].get_all("Missing").is_empty());
        // Round trip through JSON as `[[key, value], ...]`.
        let v = serde_json::to_value(&parsed[0]).unwrap();
        assert_eq!(v["fields"][0], json!(["Action", "Allow"]));
        assert_eq!(
            serde_json::from_value::<FirewallRuleFields>(v).unwrap(),
            parsed[0]
        );
    }

    #[test]
    fn fw_parse_rejects_empty_noversion_segment_without_equals_toolong() {
        assert_eq!(parse_firewall_rule(""), Err(FwParseError::Empty));
        for no_version in [
            "|",
            "Action=Allow|",
            "|v2.33|Action=Allow|",
            "2.33|Action=Allow|",
            "v2|Action=Allow|",
            "v2.|Action=Allow|",
            "v.33|",
            "V2.33|Action=Allow|",
            "v2.33x|",
            " v2.33|",
        ] {
            assert_eq!(
                parse_firewall_rule(no_version),
                Err(FwParseError::NoVersion),
                "{no_version}"
            );
        }
        assert_eq!(
            parse_firewall_rule("v2.33|Action=Allow|Active|"),
            Err(FwParseError::SegmentWithoutEquals { index: 2 })
        );
        // Hostile: a `|` inside a value cannot be stored by Windows; it reads as two segments.
        assert_eq!(
            parse_firewall_rule(r"v2.33|App=C:\a|b.exe|Name=X|"),
            Err(FwParseError::SegmentWithoutEquals { index: 2 })
        );
        let split = parse_firewall_rule(r"v2.33|Desc=a|b=c|Name=X|").unwrap();
        assert_eq!(split.get("Desc"), Some("a"));
        assert_eq!(split.get("b"), Some("c"));
        // Empty segments are skipped; a version alone is a rule without fields.
        assert_eq!(
            parse_firewall_rule("v2.33||Action=Allow||").unwrap().fields,
            [("Action".to_owned(), "Allow".to_owned())]
        );
        assert!(parse_firewall_rule("v2.33").unwrap().fields.is_empty());
        // Length: 32 KiB is read, one byte more is not.
        let fill = |len: usize| {
            let head = "v2.33|Desc=";
            format!("{head}{}", "x".repeat(len - head.len()))
        };
        assert!(parse_firewall_rule(&fill(FIREWALL_RULE_MAX_BYTES)).is_ok());
        assert_eq!(
            parse_firewall_rule(&fill(FIREWALL_RULE_MAX_BYTES + 1)),
            Err(FwParseError::TooLong)
        );
        for e in [
            FwParseError::Empty,
            FwParseError::NoVersion,
            FwParseError::SegmentWithoutEquals { index: 3 },
            FwParseError::TooLong,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn fw_same_rule_ignores_order_and_version_keeps_multiplicity() {
        let a = parse_firewall_rule(REAL_RULES[1]).unwrap();
        // Other order, other version, other key case.
        let mut reordered: Vec<&str> = REAL_RULES[1].split('|').skip(1).collect();
        reordered.reverse();
        let b = parse_firewall_rule(&format!("v2.31|{}", reordered.join("|"))).unwrap();
        assert!(a.same_rule(&b) && b.same_rule(&a));
        let c = parse_firewall_rule(&REAL_RULES[1].replace("RPort=", "rport=")).unwrap();
        assert!(a.same_rule(&c));
        // A value differing in case is another rule.
        let d = parse_firewall_rule(&REAL_RULES[1].replace("LocalSubnet", "localsubnet")).unwrap();
        assert!(!a.same_rule(&d));
        // Multiplicity counts: one RA4 more, or one less.
        let more = parse_firewall_rule(&format!("{}RA4=10.0.0.1|", REAL_RULES[1])).unwrap();
        assert!(!a.same_rule(&more) && !more.same_rule(&a));
        let x = parse_firewall_rule("v2.33|RA4=1|RA4=1|RA4=2|").unwrap();
        let y = parse_firewall_rule("v2.33|RA4=1|RA4=2|RA4=2|").unwrap();
        assert!(!x.same_rule(&y));
        assert!(x.same_rule(&x));
    }

    /// A small deterministic generator (xorshift64*), so the property runs the same inputs every time.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % (n as u64)).unwrap()
        }
    }

    /// Hostile property: `parse_firewall_rule` never panics, whatever the string, and what it returns
    /// is consistent with the input. Strings are built from the characters that matter to the parser
    /// (`|`, `=`, `v`, digits, `.`) mixed with arbitrary scalar values, plus lengths around the limit.
    #[test]
    fn fw_parse_never_panics() {
        const ALPHABET: [char; 12] = [
            '|',
            '=',
            'v',
            '2',
            '.',
            '3',
            'A',
            ' ',
            '\0',
            'é',
            '\u{1F600}',
            '\\',
        ];
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for round in 0..60_000 {
            let len = match round % 500 {
                0 => FIREWALL_RULE_MAX_BYTES - 2 + rng.below(4),
                _ => rng.below(48),
            };
            let mut raw = String::new();
            if rng.below(2) == 0 {
                raw.push_str("v2.33|");
            }
            while raw.len() < len {
                let c = if rng.below(4) == 0 {
                    char::from_u32(u32::try_from(rng.below(0x11_0000)).unwrap()).unwrap_or('?')
                } else {
                    ALPHABET[rng.below(ALPHABET.len())]
                };
                raw.push(c);
            }
            match parse_firewall_rule(&raw) {
                Ok(fields) => {
                    assert!(raw.len() <= FIREWALL_RULE_MAX_BYTES);
                    assert!(
                        raw.starts_with(&format!("{}|", fields.version)) || raw == fields.version
                    );
                    for (key, value) in &fields.fields {
                        assert!(!key.contains(['|', '=']) && !value.contains('|'), "{raw:?}");
                    }
                    // The fields written back read as the same rule.
                    let again: String = std::iter::once(fields.version.clone())
                        .chain(fields.fields.iter().map(|(k, v)| format!("{k}={v}")))
                        .collect::<Vec<_>>()
                        .join("|");
                    if again.len() <= FIREWALL_RULE_MAX_BYTES {
                        assert_eq!(parse_firewall_rule(&again).unwrap(), fields, "{raw:?}");
                    }
                }
                Err(FwParseError::TooLong) => assert!(raw.len() > FIREWALL_RULE_MAX_BYTES),
                Err(FwParseError::Empty) => assert!(raw.is_empty()),
                Err(FwParseError::NoVersion | FwParseError::SegmentWithoutEquals { .. }) => {}
            }
        }
    }

    /// FIREWALL_RESTORE_EXACT is the spike's measurement, not a guess: this reads the result file.
    #[test]
    fn firewall_restore_exact_matches_spike_result() {
        let text = include_str!("../../../vm/spikes/m1b/RESULT.json");
        let result: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).expect("RESULT.json parses");
        assert_eq!(result["schema"], json!("purge.m1b.spike/1"));
        assert_eq!(
            result["firewall"]["exact"].as_bool(),
            Some(FIREWALL_RESTORE_EXACT),
            "FIREWALL_RESTORE_EXACT disagrees with vm/spikes/m1b/RESULT.json"
        );
        // The other two facts the model relies on: tasks and services re-create exactly.
        assert_eq!(result["task"]["exact"].as_bool(), Some(true));
        assert_eq!(result["service"]["exact"].as_bool(), Some(true));
    }

    /// The rules the spike re-created use only proven shapes, and every unproven shape is told apart.
    #[test]
    fn firewall_shapes_spike_rules_are_proven_and_each_shape_is_found() {
        let text = include_str!("../../../vm/spikes/m1b/RESULT.json");
        let result: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).expect("RESULT.json parses");
        let cases = result["firewall"]["cases"].as_array().expect("cases");
        assert_eq!(cases.len(), 6);
        for case in cases {
            let raw = case["original"].as_str().expect("original");
            let fields = parse_firewall_rule(raw).expect("spike rule parses");
            assert_eq!(FirewallShape::of(&fields.fields), [], "{raw}");
        }
        for (raw, want) in [
            ("v2.33|Edge=TRUE|", FirewallShape::EdgeTraversal),
            ("v2.33|edge=TRUE|Defer=App|", FirewallShape::DeferApp),
            ("v2.33|LSM=TRUE|", FirewallShape::LooseSourceMapping),
            ("v2.33|LOM=TRUE|", FirewallShape::LocalOnlyMapping),
            ("v2.33|ICMP6=128:*|", FirewallShape::IcmpTypes),
            ("v2.33|LA4=10.0.0.1|", FirewallShape::LocalAddresses),
            ("v2.33|Profile=Domain|", FirewallShape::DomainProfile),
            ("v2.33|RPort2_10=1-2|", FirewallShape::RemotePortRange),
            ("v2.33|IFType=Lan|", FirewallShape::LanInterface),
            ("v2.33|Protocol=47|", FirewallShape::OtherProtocol),
        ] {
            let fields = parse_firewall_rule(raw).unwrap().fields;
            assert!(FirewallShape::of(&fields).contains(&want), "{raw}");
            assert!(!want.is_proven());
            assert!(FirewallShape::unproven_in(&fields).contains(&want), "{raw}");
        }
        // Defer=User, Profile=Private, IFType=Wireless, Protocol 6 and 17: proven forms.
        let fields =
            parse_firewall_rule("v2.33|Defer=User|Profile=Private|IFType=Wireless|Protocol=17|")
                .unwrap()
                .fields;
        assert_eq!(FirewallShape::of(&fields), []);
        assert_eq!(FIREWALL_UNPROVEN_SHAPES.len(), FirewallShape::ALL.len());
    }

    #[test]
    fn fold_is_the_windows_fold() {
        assert_eq!(fold("A\u{C4}B\u{416}"), "a\u{E4}b\u{436}");
        assert_eq!(fold("\u{212A}"), "\u{212A}");
        assert_eq!(fold("\u{10400}"), "\u{10400}");
        assert_eq!(fold("\u{13A0}"), "\u{13A0}");
    }
}
