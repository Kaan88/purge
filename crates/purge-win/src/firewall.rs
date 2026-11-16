//! Windows Firewall rules: delete one rule by its `InstanceID` and re-create it under the same id, over
//! WMI (features `write` + `com`, M1B-WIN-FW). With `write` alone the module holds only the pure parts
//! (id checks, WQL literal, rule string parsing and field mapping).
//!
//! ENGINE_PLAN.md §5.7.2, contract C-WIN (firewall) and decision D14 of docs/M1B_DESIGN.json, with the
//! method the M1B-SPIKE run proved on the rig VM (vm/spikes/m1b/RESULT.json, firewall `cim_create`,
//! `exact: true`). Rules are read elsewhere, from the registry through `RegistrySource`; this module only
//! removes and restores.
//!
//! - [`delete_by_instance_id`]: connects to `ROOT\StandardCimv2`, runs
//!   `SELECT * FROM MSFT_NetFirewallRule WHERE InstanceID = '<id>'` with an `IWbemContext` holding
//!   `PolicyStore = PersistentStore`, and calls `DeleteInstance` on the one match. The id is the only
//!   selector: no display name, group or program path is ever used to select a rule. Nothing is deleted
//!   when more than one instance matches ([`WinError::Ambiguous`]) or when the instance WMI returns does
//!   not carry exactly the id asked for ([`WinError::IdMismatch`]; WQL compares strings without regard to
//!   case). No match is `Ok(0)`.
//! - [`create_with_instance_id`]: `PutInstance(WBEM_FLAG_CREATE_ONLY)` of a spawned `MSFT_NetFirewallRule`
//!   carrying `InstanceID` and the rule properties, with the filter values (program, service, protocol,
//!   ports, addresses, interface types, ICMP types) passed as `IWbemContext` values beside `PolicyStore`
//!   ([`map_rule`] builds both from the stored rule string's fields). An id that already exists gives
//!   [`WinError::ObjectExists`] and the existing rule is left as it is. Creating the rule first and setting
//!   its filter instances afterwards is not used: the provider refuses a `Defer=User` rule until its
//!   protocol is set.
//!
//! Ids are checked before any WMI call ([`check_instance_id`]): empty ids, ids longer than
//! [`MAX_ID_UNITS`] UTF-16 units and ids with a control character are refused. The id enters the query
//! only as a WQL string literal built by [`wql_string_literal`] (backslash and single quote escaped), which
//! is parsed back and compared with the id before it is used.
//!
//! Fields [`map_rule`] cannot map exactly make [`create_with_instance_id`] fail with
//! [`WinError::Unmapped`] before WMI is touched, so a rule is either re-created with the same fields or not
//! at all. A caller that must know in advance whether a rule can come back calls [`map_rule`] itself.
//! The spike re-created six rule shapes byte for byte (program with `Defer=User`, local ports with a
//! `LPort2_10` range, remote address list with `LocalSubnet`, service, profiles with interface types,
//! group with description); the other mappings (`Edge`, `Defer=App`, ICMP types, `LSM`, `LOM`, local
//! addresses, `Profile=Domain`) are checked by the `#[ignore]`d rig tests in tests/firewall.rs.
//!
//! What this module never does: it writes no registry value, starts no process, never uses the
//! `INetFw*` COM objects, never removes a rule by name, and never addresses any policy store other than
//! `PersistentStore` (no group-policy store, no dynamic store). Rules are never enabled, disabled or
//! edited in place.
//!
//! COM: every public call that touches WMI initialises COM on the calling thread with
//! `CoInitializeEx(COINIT_MULTITHREADED)` through a guard that calls `CoUninitialize` on drop
//! (`RPC_E_CHANGED_MODE`, a thread already in an apartment, is used as it is and not uninitialised). No
//! process-wide COM security is set; the WMI proxy gets `RPC_C_IMP_LEVEL_IMPERSONATE` through
//! `CoSetProxyBlanket`. Deleting and creating need an elevated administrator.
//!
//! [`parse_rule`] is this crate's copy of C-OBJECT `parse_firewall_rule` (purge-win does not depend on
//! purge-model); callers holding a `purge_model::object::FirewallRuleFields` pass its `fields` directly.

use std::fmt;

/// Longest id accepted, in UTF-16 units.
pub const MAX_ID_UNITS: usize = 260;

/// Longest rule string [`parse_rule`] accepts, in bytes (C-OBJECT: 32 KiB).
pub const MAX_RULE_BYTES: usize = 32 * 1024;

/// The WMI namespace of the firewall provider.
pub const NAMESPACE: &str = r"ROOT\StandardCimv2";

/// The WMI class of a firewall rule.
pub const RULE_CLASS: &str = "MSFT_NetFirewallRule";

/// The only policy store this module addresses (`PolicyStore` context value).
pub const POLICY_STORE: &str = "PersistentStore";

/// Why [`check_instance_id`] refused an id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    /// The id is empty.
    Empty,
    /// The id is longer than [`MAX_ID_UNITS`] UTF-16 units.
    TooLong {
        /// Its length in UTF-16 units.
        units: usize,
    },
    /// The id contains a control character (C0, DEL or C1), which a WQL literal cannot carry.
    ControlChar {
        /// Byte offset of the first one.
        index: usize,
    },
    /// The escaped WQL literal did not parse back to the id.
    NotRoundTrip,
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdError::Empty => write!(f, "empty id"),
            IdError::TooLong { units } => {
                write!(f, "id of {units} UTF-16 units (limit {MAX_ID_UNITS})")
            }
            IdError::ControlChar { index } => write!(f, "control character at byte {index}"),
            IdError::NotRoundTrip => write!(f, "WQL literal does not parse back to the id"),
        }
    }
}

/// Why a firewall call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WinError {
    /// The id was refused before any WMI call.
    #[error("firewall rule id refused: {0}")]
    InvalidId(IdError),
    /// Rule fields without an exact WMI mapping (each entry names the field and why); nothing was
    /// created.
    #[error("firewall rule fields without an exact mapping: {}", .0.join("; "))]
    Unmapped(Vec<String>),
    /// More than one rule instance matched the id; nothing was deleted.
    #[error("{matched} firewall rule instances matched the id; nothing deleted")]
    Ambiguous {
        /// How many matched.
        matched: u32,
    },
    /// The one instance WMI returned carries another `InstanceID` (WQL compares without regard to
    /// case); nothing was deleted.
    #[error(
        "the matching firewall rule has InstanceID {found:?}, not the id asked for; nothing deleted"
    )]
    IdMismatch {
        /// The `InstanceID` WMI returned.
        found: String,
    },
    /// A rule with this id already exists (`WBEM_E_ALREADY_EXISTS`); it was left unchanged.
    #[error("a firewall rule with this id already exists; nothing changed")]
    ObjectExists,
    /// A COM or WMI call failed.
    #[error("{step} failed: HRESULT {hresult:#010x}")]
    Com {
        /// The call.
        step: &'static str,
        /// Its HRESULT.
        hresult: u32,
    },
}

// ---------------------------------------------------------------------------------------------
// Ids and WQL
// ---------------------------------------------------------------------------------------------

/// Checks an id before it is used: non-empty, at most [`MAX_ID_UNITS`] UTF-16 units, no control
/// character.
pub fn check_instance_id(id: &str) -> Result<(), IdError> {
    if id.is_empty() {
        return Err(IdError::Empty);
    }
    if let Some((index, _)) = id.char_indices().find(|(_, c)| c.is_control()) {
        return Err(IdError::ControlChar { index });
    }
    let units = id.encode_utf16().count();
    if units > MAX_ID_UNITS {
        return Err(IdError::TooLong { units });
    }
    Ok(())
}

/// The id as a single-quoted WQL string literal: checked with [`check_instance_id`], backslash and single
/// quote escaped with a backslash, then parsed back and compared with the id.
pub fn wql_string_literal(id: &str) -> Result<String, IdError> {
    check_instance_id(id)?;
    let mut lit = String::with_capacity(id.len() + 8);
    lit.push('\'');
    for c in id.chars() {
        if c == '\\' || c == '\'' {
            lit.push('\\');
        }
        lit.push(c);
    }
    lit.push('\'');
    if wql_unquote(&lit).as_deref() != Some(id) {
        return Err(IdError::NotRoundTrip);
    }
    Ok(lit)
}

/// Parses a whole single-quoted WQL literal (backslash escapes the next character). `None` unless the
/// input is exactly one literal: an unescaped quote before the end or a dangling backslash fails.
fn wql_unquote(lit: &str) -> Option<String> {
    let body = lit.strip_prefix('\'')?.strip_suffix('\'')?;
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push(chars.next()?),
            '\'' => return None,
            c => out.push(c),
        }
    }
    Some(out)
}

/// The WQL query [`delete_by_instance_id`] runs for `id`.
pub fn instance_query(id: &str) -> Result<String, IdError> {
    Ok(format!(
        "SELECT * FROM {RULE_CLASS} WHERE InstanceID = {}",
        wql_string_literal(id)?
    ))
}

// ---------------------------------------------------------------------------------------------
// Rule strings (C-OBJECT parse_firewall_rule)
// ---------------------------------------------------------------------------------------------

/// A stored rule string split into its version and fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleString {
    /// The first segment (`v2.33`).
    pub version: String,
    /// Every other non-empty segment as (key, value); order and repeated keys kept.
    pub fields: Vec<(String, String)>,
}

impl RuleString {
    /// The rule string again: version, then `|key=value` per field, then a closing `|`. Equal to the
    /// parsed input whenever that input had no empty segment other than the final one.
    pub fn to_rule(&self) -> String {
        let mut s = self.version.clone();
        for (k, v) in &self.fields {
            s.push('|');
            s.push_str(k);
            s.push('=');
            s.push_str(v);
        }
        s.push('|');
        s
    }
}

/// Why [`parse_rule`] refused a rule string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleParseError {
    /// The string is empty.
    #[error("empty rule string")]
    Empty,
    /// The first segment is empty.
    #[error("rule string without a version")]
    NoVersion,
    /// A non-empty segment after the version has no `=`.
    #[error("rule string segment {index} has no '='")]
    SegmentWithoutEquals {
        /// Index of the segment in the `|`-split string (the version is 0).
        index: usize,
    },
    /// The string is longer than [`MAX_RULE_BYTES`].
    #[error("rule string longer than {MAX_RULE_BYTES} bytes")]
    TooLong,
}

/// Splits a stored rule string (`v2.31|Action=Allow|Active=TRUE|Dir=In|Name=X|`): the first segment is
/// the version; every other non-empty segment must contain `=`, the key is what precedes the first `=`
/// and the value everything after it.
pub fn parse_rule(raw: &str) -> Result<RuleString, RuleParseError> {
    if raw.is_empty() {
        return Err(RuleParseError::Empty);
    }
    if raw.len() > MAX_RULE_BYTES {
        return Err(RuleParseError::TooLong);
    }
    let mut segs = raw.split('|');
    let version = segs.next().unwrap_or_default();
    if version.is_empty() {
        return Err(RuleParseError::NoVersion);
    }
    let mut fields = Vec::new();
    for (i, seg) in segs.enumerate() {
        if seg.is_empty() {
            continue;
        }
        let (k, v) = seg
            .split_once('=')
            .ok_or(RuleParseError::SegmentWithoutEquals { index: i + 1 })?;
        fields.push((k.to_owned(), v.to_owned()));
    }
    Ok(RuleString {
        version: version.to_owned(),
        fields,
    })
}

// ---------------------------------------------------------------------------------------------
// Rule fields -> MSFT_NetFirewallRule properties and context values
// ---------------------------------------------------------------------------------------------

/// A property of the spawned `MSFT_NetFirewallRule` instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropValue {
    /// A string property (`VT_BSTR`).
    Str(String),
    /// A `uint16` property (`VT_I4`, as WMI carries it).
    U16(u16),
    /// A boolean property (`VT_BOOL`).
    Bool(bool),
}

/// An `IWbemContext` value passed beside `PolicyStore`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextValue {
    /// A string (`VT_BSTR`).
    Str(String),
    /// A string list (`VT_ARRAY | VT_BSTR`), in field order.
    StrList(Vec<String>),
    /// An unsigned 32-bit value (`VT_UI4`).
    U32(u32),
}

/// What [`create_with_instance_id`] passes to WMI for one rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleMap {
    /// Instance properties, in a fixed order (`InstanceID` is added by the caller).
    pub properties: Vec<(&'static str, PropValue)>,
    /// Filter values for the `IWbemContext`, in a fixed order (`PolicyStore` is added by the caller).
    pub context: Vec<(&'static str, ContextValue)>,
}

/// One address family of an address field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// The values of one address list (local or remote) collected from `LA4`/`LA6` or `RA4`/`RA6`.
#[derive(Default)]
struct AddrList {
    /// Distinct values in order of first appearance (the `LocalSubnet` keyword once).
    values: Vec<String>,
    /// Families `LocalSubnet` was seen in.
    local_subnet: Vec<Family>,
}

/// Single-valued keys: a second occurrence is refused.
const SINGLE: &[&str] = &[
    "ACTION",
    "ACTIVE",
    "DIR",
    "NAME",
    "DESC",
    "EMBEDCTXT",
    "EDGE",
    "DEFER",
    "LSM",
    "LOM",
    "PROTOCOL",
    "APP",
    "SVC",
];

/// Maps a stored rule's fields to the instance properties and context values that re-create it with
/// the same fields (C-OBJECT `same_rule`). Keys compare ASCII case-insensitively; values compare exactly
/// as stored.
///
/// Mapped: `Action` (Allow, Block), `Active`, `Dir`, `Profile` (Domain, Private, Public), `Name`,
/// `Desc`, `EmbedCtxt`, `Edge` / `Defer` (`Edge=TRUE` alone, `Defer=User` alone, `Edge=TRUE` with
/// `Defer=App`), `LSM=TRUE`, `LOM=TRUE`, `Protocol` (decimal), `LPort` / `RPort` (decimal) and
/// `LPort2_10` / `RPort2_10` (decimal ranges) into `LocalPort` / `RemotePort`, `LA4`/`LA6`/`RA4`/`RA6`
/// (literal addresses in their family's key, and `LocalSubnet` present in both families), `App`, `Svc`,
/// `IFType` (Lan, Wireless, RemoteAccess), `ICMP4` (with `Protocol=1`) and `ICMP6` (with `Protocol=58`).
///
/// Everything else is refused, and so are repeats of a single-valued key or of a list value, empty
/// values, values with a NUL, port keywords (`RPC`, `IPHTTPSIn`, ...), address keywords other than
/// `LocalSubnet`, and a missing `Name`. The error lists every refused field with the reason.
pub fn map_rule(fields: &[(String, String)]) -> Result<RuleMap, Vec<String>> {
    let mut bad: Vec<String> = Vec::new();
    let mut seen_single: Vec<&'static str> = Vec::new();

    let mut action = None;
    let mut enabled = None;
    let mut direction = None;
    let mut profiles: u16 = 0;
    let mut name = None;
    let mut desc = None;
    let mut group = None;
    let mut edge = false;
    let mut defer: Option<&str> = None;
    let mut lsm = false;
    let mut lom = false;
    let mut protocol: Option<&str> = None;
    let mut program = None;
    let mut service = None;
    let mut iftype: u32 = 0;
    let mut lport: Vec<String> = Vec::new();
    let mut rport: Vec<String> = Vec::new();
    let mut laddr = AddrList::default();
    let mut raddr = AddrList::default();
    let mut icmp: Vec<String> = Vec::new();
    let mut icmp_families: Vec<Family> = Vec::new();

    for (key, value) in fields {
        let k = key.to_ascii_uppercase();
        let v = value.as_str();
        let seg = || format!("{key}={value}");
        if v.is_empty() {
            bad.push(format!("{} (empty value)", seg()));
            continue;
        }
        if v.contains('\0') {
            bad.push(format!("{key} (value contains NUL)"));
            continue;
        }
        if let Some(single) = SINGLE.iter().find(|s| **s == k) {
            if seen_single.contains(single) {
                bad.push(format!("{} (repeated key)", seg()));
                continue;
            }
            seen_single.push(single);
        }
        match k.as_str() {
            "ACTION" => match v {
                "Allow" => action = Some(2),
                "Block" => action = Some(4),
                _ => bad.push(format!("{} (unknown action)", seg())),
            },
            "ACTIVE" => match v {
                "TRUE" => enabled = Some(1),
                "FALSE" => enabled = Some(2),
                _ => bad.push(format!("{} (not TRUE or FALSE)", seg())),
            },
            "DIR" => match v {
                "In" => direction = Some(1),
                "Out" => direction = Some(2),
                _ => bad.push(format!("{} (unknown direction)", seg())),
            },
            "PROFILE" => {
                let bit = match v {
                    "Domain" => 1,
                    "Private" => 2,
                    "Public" => 4,
                    _ => 0,
                };
                if bit == 0 {
                    bad.push(format!("{} (unknown profile)", seg()));
                } else if profiles & bit != 0 {
                    bad.push(format!("{} (repeated value)", seg()));
                } else {
                    profiles |= bit;
                }
            }
            "NAME" => name = Some(v),
            "DESC" => desc = Some(v),
            "EMBEDCTXT" => group = Some(v),
            "EDGE" => {
                if v == "TRUE" {
                    edge = true;
                } else {
                    bad.push(format!("{} (only Edge=TRUE is mapped)", seg()));
                }
            }
            "DEFER" => {
                if v == "User" || v == "App" {
                    defer = Some(v);
                } else {
                    bad.push(format!("{} (unknown defer)", seg()));
                }
            }
            "LSM" | "LOM" => {
                if v != "TRUE" {
                    bad.push(format!("{} (only TRUE is mapped)", seg()));
                } else if k == "LSM" {
                    lsm = true;
                } else {
                    lom = true;
                }
            }
            "PROTOCOL" => {
                if canonical_decimal(v, 255) {
                    protocol = Some(v);
                } else {
                    bad.push(format!("{} (not a protocol number)", seg()));
                }
            }
            "LPORT" | "RPORT" | "LPORT2_10" | "RPORT2_10" => {
                let ok = if k.ends_with("2_10") {
                    v.split_once('-').is_some_and(|(a, b)| {
                        canonical_decimal(a, 65535)
                            && canonical_decimal(b, 65535)
                            && a.parse::<u32>().ok() <= b.parse::<u32>().ok()
                    })
                } else {
                    canonical_decimal(v, 65535)
                };
                let list = if k.starts_with('L') {
                    &mut lport
                } else {
                    &mut rport
                };
                if !ok {
                    bad.push(format!("{} (not a port number or range)", seg()));
                } else if list.iter().any(|p| p == v) {
                    bad.push(format!("{} (repeated value)", seg()));
                } else {
                    list.push(v.to_owned());
                }
            }
            "LA4" | "LA6" | "RA4" | "RA6" => {
                let family = if k.ends_with('4') {
                    Family::V4
                } else {
                    Family::V6
                };
                let list = if k.starts_with('L') {
                    &mut laddr
                } else {
                    &mut raddr
                };
                if let Err(why) = add_address(list, family, v) {
                    bad.push(format!("{} ({why})", seg()));
                }
            }
            "APP" => program = Some(v),
            "SVC" => service = Some(v),
            "IFTYPE" => {
                let bit = match v {
                    "Lan" => 1,
                    "Wireless" => 2,
                    "RemoteAccess" => 4,
                    _ => 0,
                };
                if bit == 0 {
                    bad.push(format!("{} (unknown interface type)", seg()));
                } else if iftype & bit != 0 {
                    bad.push(format!("{} (repeated value)", seg()));
                } else {
                    iftype |= bit;
                }
            }
            "ICMP4" | "ICMP6" => {
                if !icmp_type_code(v) {
                    bad.push(format!("{} (not type:code)", seg()));
                } else if icmp.iter().any(|t| t == v) {
                    bad.push(format!("{} (repeated value)", seg()));
                } else {
                    icmp.push(v.to_owned());
                    let fam = if k == "ICMP4" { Family::V4 } else { Family::V6 };
                    if !icmp_families.contains(&fam) {
                        icmp_families.push(fam);
                    }
                }
            }
            _ => bad.push(format!("{} (no mapping)", seg())),
        }
    }

    if name.is_none() {
        bad.push("Name (missing)".to_owned());
    }
    let edge_policy = match (edge, defer) {
        (false, None) => None,
        (true, None) => Some(1),
        (false, Some("User")) => Some(2),
        (true, Some("App")) => Some(3),
        (e, d) => {
            bad.push(format!(
                "Edge={} with Defer={} (no mapping)",
                if e { "TRUE" } else { "-" },
                d.unwrap_or("-")
            ));
            None
        }
    };
    // The keyword covers both families: the provider writes it under both keys, so a rule holding it
    // in one family only cannot come back as it was.
    for (list, key) in [(&laddr, "LA"), (&raddr, "RA")] {
        if let [only] = list.local_subnet.as_slice() {
            bad.push(format!(
                "{key}{}=LocalSubnet (LocalSubnet not present in both families)",
                if *only == Family::V4 { '4' } else { '6' }
            ));
        }
    }
    if !icmp.is_empty() {
        let want = match icmp_families.as_slice() {
            [Family::V4] => Some("1"),
            [Family::V6] => Some("58"),
            _ => None,
        };
        if want.is_none() || protocol != want {
            bad.push(format!(
                "ICMP types with Protocol={} (ICMP4 needs 1, ICMP6 needs 58, not both)",
                protocol.unwrap_or("-")
            ));
        }
    }
    if !bad.is_empty() {
        return Err(bad);
    }

    let mut properties: Vec<(&'static str, PropValue)> = Vec::new();
    let mut context: Vec<(&'static str, ContextValue)> = Vec::new();
    let s = |v: &str| PropValue::Str(v.to_owned());
    if let Some(v) = name {
        properties.push(("ElementName", s(v)));
    }
    if let Some(v) = desc {
        properties.push(("Description", s(v)));
    }
    if let Some(v) = group {
        properties.push(("RuleGroup", s(v)));
    }
    if let Some(v) = enabled {
        properties.push(("Enabled", PropValue::U16(v)));
    }
    if profiles != 0 {
        properties.push(("Profiles", PropValue::U16(profiles)));
    }
    if let Some(v) = direction {
        properties.push(("Direction", PropValue::U16(v)));
    }
    if let Some(v) = action {
        properties.push(("Action", PropValue::U16(v)));
    }
    if let Some(v) = edge_policy {
        properties.push(("EdgeTraversalPolicy", PropValue::U16(v)));
    }
    if lsm {
        properties.push(("LooseSourceMapping", PropValue::Bool(true)));
    }
    if lom {
        properties.push(("LocalOnlyMapping", PropValue::Bool(true)));
    }

    let c = |v: &str| ContextValue::Str(v.to_owned());
    if let Some(v) = program {
        context.push(("Program", c(v)));
    }
    if let Some(v) = service {
        context.push(("Service", c(v)));
    }
    if let Some(v) = protocol {
        context.push(("Protocol", c(v)));
    }
    if !lport.is_empty() {
        context.push(("LocalPort", ContextValue::StrList(lport)));
    }
    if !rport.is_empty() {
        context.push(("RemotePort", ContextValue::StrList(rport)));
    }
    if !laddr.values.is_empty() {
        context.push(("LocalAddress", ContextValue::StrList(laddr.values)));
    }
    if !raddr.values.is_empty() {
        context.push(("RemoteAddress", ContextValue::StrList(raddr.values)));
    }
    if iftype != 0 {
        context.push(("InterfaceType", ContextValue::U32(iftype)));
    }
    if !icmp.is_empty() {
        context.push(("IcmpType", ContextValue::StrList(icmp)));
    }
    Ok(RuleMap {
        properties,
        context,
    })
}

/// A decimal number without sign or leading zero (except `0` itself), at most `max`.
fn canonical_decimal(s: &str, max: u32) -> bool {
    !s.is_empty()
        && s.len() <= 5
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'))
        && s.parse::<u32>().is_ok_and(|n| n <= max)
}

/// An ICMP `type:code` entry as stored: decimal type, `:`, decimal code or `*`.
fn icmp_type_code(s: &str) -> bool {
    s.split_once(':')
        .is_some_and(|(t, c)| canonical_decimal(t, 255) && (c == "*" || canonical_decimal(c, 255)))
}

/// Adds one address entry of `family` to `list`: `LocalSubnet` (once per family) or a literal address,
/// subnet or range whose family matches the key.
fn add_address(list: &mut AddrList, family: Family, v: &str) -> Result<(), &'static str> {
    if v == "LocalSubnet" {
        if list.local_subnet.contains(&family) {
            return Err("repeated value");
        }
        list.local_subnet.push(family);
        if !list.values.iter().any(|x| x == v) {
            list.values.push(v.to_owned());
        }
        return Ok(());
    }
    // A literal IPv6 address, subnet or range has a colon and only hex digits and `.:/-`; an IPv4 one
    // has a dot and only decimal digits and `./-`. Anything else is a keyword.
    let literal_family = if v.contains(':')
        && v.bytes()
            .all(|b| b.is_ascii_hexdigit() || matches!(b, b'.' | b':' | b'/' | b'-'))
    {
        Family::V6
    } else if v.contains('.')
        && v.bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'/' | b'-'))
    {
        Family::V4
    } else {
        return Err("address keyword other than LocalSubnet");
    };
    if literal_family != family {
        return Err("address in the other family's key");
    }
    if list.values.iter().any(|x| x == v) {
        return Err("repeated value");
    }
    list.values.push(v.to_owned());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// WMI
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "com")]
pub use wmi::{create_with_instance_id, delete_by_instance_id};

#[cfg(feature = "com")]
mod wmi {
    use std::ffi::c_void;
    use std::marker::PhantomData;
    use std::mem::ManuallyDrop;

    use windows::Win32::Foundation::{RPC_E_CHANGED_MODE, VARIANT_FALSE, VARIANT_TRUE};
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Ole::{
        SafeArrayCreateVector, SafeArrayDestroy, SafeArrayPutElement,
    };
    use windows::Win32::System::Variant::{
        VARIANT, VT_ARRAY, VT_BOOL, VT_BSTR, VT_I4, VT_UI4, VariantClear,
    };
    use windows::Win32::System::Wmi::{
        IEnumWbemClassObject, IWbemClassObject, IWbemContext, IWbemLocator, IWbemServices,
        WBEM_E_ALREADY_EXISTS, WBEM_FLAG_CREATE_ONLY, WBEM_FLAG_FORWARD_ONLY,
        WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_FLAG_RETURN_WBEM_COMPLETE, WBEM_GENERIC_FLAG_TYPE,
        WBEM_INFINITE, WBEM_S_FALSE, WbemContext, WbemLocator,
    };
    use windows::core::{BSTR, PCWSTR};

    use super::{
        ContextValue, NAMESPACE, POLICY_STORE, PropValue, RULE_CLASS, WinError, check_instance_id,
        instance_query, map_rule,
    };
    use crate::os::wide;

    /// `RPC_C_AUTHN_WINNT` (the `Win32_System_Rpc` feature is not enabled).
    const RPC_C_AUTHN_WINNT: u32 = 10;
    /// `RPC_C_AUTHZ_NONE`.
    const RPC_C_AUTHZ_NONE: u32 = 0;

    fn com_err(step: &'static str) -> impl Fn(windows::core::Error) -> WinError {
        move |e| WinError::Com {
            step,
            hresult: e.code().0 as u32,
        }
    }

    /// COM on the calling thread for the guard's lifetime. Declared before every interface pointer so it
    /// is dropped after them. Not `Send`: `CoUninitialize` must run on the initialising thread.
    struct ComInit {
        uninit: bool,
        _thread: PhantomData<*const ()>,
    }

    impl ComInit {
        fn new() -> Result<ComInit, WinError> {
            // SAFETY: no reserved pointer; balanced by `CoUninitialize` in `drop` when it succeeded.
            let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            if hr == RPC_E_CHANGED_MODE {
                // The thread is already in a single-threaded apartment; COM is usable and is not ours
                // to uninitialise.
                return Ok(ComInit {
                    uninit: false,
                    _thread: PhantomData,
                });
            }
            if hr.is_err() {
                return Err(WinError::Com {
                    step: "CoInitializeEx",
                    hresult: hr.0 as u32,
                });
            }
            // S_OK or S_FALSE (already initialised): both need one `CoUninitialize`.
            Ok(ComInit {
                uninit: true,
                _thread: PhantomData,
            })
        }
    }

    impl Drop for ComInit {
        fn drop(&mut self) {
            if self.uninit {
                // SAFETY: balances the successful `CoInitializeEx` of `new` on this thread (the guard is
                // not `Send`); every interface pointer of the call was dropped before the guard.
                unsafe { CoUninitialize() };
            }
        }
    }

    /// An owned `VARIANT`, cleared on drop.
    struct Var(VARIANT);

    impl Var {
        fn empty() -> Var {
            Var(VARIANT::default())
        }

        fn bstr(s: &str) -> Var {
            let mut v = VARIANT::default();
            // SAFETY: `v` is a zeroed (VT_EMPTY) VARIANT; setting the tag and the matching member makes
            // it a valid VT_BSTR that owns the BSTR until `VariantClear`.
            unsafe {
                let inner = &mut *v.Anonymous.Anonymous;
                inner.vt = VT_BSTR;
                inner.Anonymous.bstrVal = ManuallyDrop::new(BSTR::from(s));
            }
            Var(v)
        }

        fn i4(n: i32) -> Var {
            let mut v = VARIANT::default();
            // SAFETY: as in `bstr`, for VT_I4.
            unsafe {
                let inner = &mut *v.Anonymous.Anonymous;
                inner.vt = VT_I4;
                inner.Anonymous.lVal = n;
            }
            Var(v)
        }

        fn ui4(n: u32) -> Var {
            let mut v = VARIANT::default();
            // SAFETY: as in `bstr`, for VT_UI4.
            unsafe {
                let inner = &mut *v.Anonymous.Anonymous;
                inner.vt = VT_UI4;
                inner.Anonymous.ulVal = n;
            }
            Var(v)
        }

        fn boolean(b: bool) -> Var {
            let mut v = VARIANT::default();
            // SAFETY: as in `bstr`, for VT_BOOL.
            unsafe {
                let inner = &mut *v.Anonymous.Anonymous;
                inner.vt = VT_BOOL;
                inner.Anonymous.boolVal = if b { VARIANT_TRUE } else { VARIANT_FALSE };
            }
            Var(v)
        }

        fn bstr_list(items: &[String]) -> Result<Var, WinError> {
            let fail = |step| WinError::Com {
                step,
                hresult: 0x8007_000E, // E_OUTOFMEMORY
            };
            let n = u32::try_from(items.len()).map_err(|_| fail("SafeArrayCreateVector"))?;
            // SAFETY: plain allocation of a one-dimensional BSTR array; null on failure.
            let sa = unsafe { SafeArrayCreateVector(VT_BSTR, 0, n) };
            if sa.is_null() {
                return Err(fail("SafeArrayCreateVector"));
            }
            for (i, item) in items.iter().enumerate() {
                let b = BSTR::from(item.as_str());
                // An empty `BSTR` derefs to a static empty slice, not to an allocated string: pass the
                // null BSTR for it instead.
                let raw: *const u16 = if b.is_empty() {
                    std::ptr::null()
                } else {
                    b.as_ptr()
                };
                let index = i32::try_from(i).map_err(|_| fail("SafeArrayPutElement"));
                // SAFETY: `sa` is a live VT_BSTR vector of `n` elements and `index` < `n`; for VT_BSTR
                // the element pointer is the BSTR itself (`b` is alive), which SafeArrayPutElement
                // copies.
                let put = index.and_then(|ix| unsafe {
                    SafeArrayPutElement(sa, &ix, raw as *const c_void)
                        .map_err(com_err("SafeArrayPutElement"))
                });
                if let Err(e) = put {
                    // SAFETY: `sa` was created above and is not referenced anywhere else.
                    let _ = unsafe { SafeArrayDestroy(sa) };
                    return Err(e);
                }
            }
            let mut v = VARIANT::default();
            // SAFETY: as in `bstr`; the VARIANT takes ownership of `sa`, which `VariantClear` destroys.
            unsafe {
                let inner = &mut *v.Anonymous.Anonymous;
                inner.vt = VT_ARRAY | VT_BSTR;
                inner.Anonymous.parray = sa;
            }
            Ok(Var(v))
        }

        /// The string of a VT_BSTR variant; `None` for any other type (VT_NULL included).
        fn as_string(&self) -> Option<String> {
            // SAFETY: the tag is read first and the member read only when it says VT_BSTR.
            unsafe {
                let inner = &*self.0.Anonymous.Anonymous;
                (inner.vt == VT_BSTR).then(|| inner.Anonymous.bstrVal.to_string())
            }
        }
    }

    impl Drop for Var {
        fn drop(&mut self) {
            // SAFETY: the VARIANT is valid (built above or filled by WMI) and owned by this guard.
            let _ = unsafe { VariantClear(&mut self.0) };
        }
    }

    /// A WMI connection to the firewall namespace and the context sent with every call.
    struct Wmi {
        svc: IWbemServices,
        ctx: IWbemContext,
    }

    impl Wmi {
        /// Connects to [`NAMESPACE`] and builds a context with `PolicyStore` = [`POLICY_STORE`] followed
        /// by `extra`.
        fn connect(extra: &[(&'static str, ContextValue)]) -> Result<Wmi, WinError> {
            // SAFETY: COM is initialised on this thread by the caller's `ComInit`.
            let locator: IWbemLocator =
                unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }
                    .map_err(com_err("CoCreateInstance(WbemLocator)"))?;
            let empty = BSTR::new();
            // SAFETY: valid BSTR arguments; local connection with the caller's credentials.
            let svc = unsafe {
                locator.ConnectServer(
                    &BSTR::from(NAMESPACE),
                    &empty,
                    &empty,
                    &empty,
                    0,
                    &empty,
                    None,
                )
            }
            .map_err(com_err("IWbemLocator::ConnectServer"))?;
            // SAFETY: `svc` is a live proxy; the blanket only sets authentication on it.
            unsafe {
                CoSetProxyBlanket(
                    &svc,
                    RPC_C_AUTHN_WINNT,
                    RPC_C_AUTHZ_NONE,
                    PCWSTR::null(),
                    RPC_C_AUTHN_LEVEL_CALL,
                    RPC_C_IMP_LEVEL_IMPERSONATE,
                    None,
                    EOAC_NONE,
                )
            }
            .map_err(com_err("CoSetProxyBlanket"))?;
            // SAFETY: as for the locator.
            let ctx: IWbemContext =
                unsafe { CoCreateInstance(&WbemContext, None, CLSCTX_INPROC_SERVER) }
                    .map_err(com_err("CoCreateInstance(WbemContext)"))?;
            set_context(&ctx, "PolicyStore", &Var::bstr(POLICY_STORE))?;
            for (name, value) in extra {
                let var = match value {
                    ContextValue::Str(s) => Var::bstr(s),
                    ContextValue::StrList(list) => Var::bstr_list(list)?,
                    ContextValue::U32(n) => Var::ui4(*n),
                };
                set_context(&ctx, name, &var)?;
            }
            Ok(Wmi { svc, ctx })
        }
    }

    fn set_context(ctx: &IWbemContext, name: &str, value: &Var) -> Result<(), WinError> {
        let n = wide(name);
        // SAFETY: `n` is NUL-terminated and outlives the call; the context copies the value.
        unsafe { ctx.SetValue(PCWSTR(n.as_ptr()), 0, &value.0) }
            .map_err(com_err("IWbemContext::SetValue"))
    }

    fn get_string(obj: &IWbemClassObject, name: &str) -> Result<Option<String>, WinError> {
        let n = wide(name);
        let mut v = Var::empty();
        // SAFETY: `n` is NUL-terminated; `v.0` is an empty VARIANT WMI fills and the guard clears.
        unsafe { obj.Get(PCWSTR(n.as_ptr()), 0, &mut v.0, None, None) }
            .map_err(com_err("IWbemClassObject::Get"))?;
        Ok(v.as_string())
    }

    fn put(obj: &IWbemClassObject, name: &str, value: &Var) -> Result<(), WinError> {
        let n = wide(name);
        // SAFETY: `n` is NUL-terminated; WMI copies the value; type 0 lets the class define it.
        unsafe { obj.Put(PCWSTR(n.as_ptr()), 0, &value.0, 0) }
            .map_err(com_err("IWbemClassObject::Put"))
    }

    /// Deletes the persistent-store firewall rule whose `InstanceID` is `id`, and only that rule.
    ///
    /// Returns `Ok(1)` when it was deleted and `Ok(0)` when no rule matched. Fails without deleting when
    /// the id is refused ([`WinError::InvalidId`], before any WMI call), when more than one instance
    /// matched ([`WinError::Ambiguous`]), or when the single match carries a different `InstanceID`
    /// ([`WinError::IdMismatch`]). Needs an elevated administrator.
    pub fn delete_by_instance_id(id: &str) -> Result<u32, WinError> {
        let query = instance_query(id).map_err(WinError::InvalidId)?;
        let _com = ComInit::new()?;
        let wmi = Wmi::connect(&[])?;
        // SAFETY: valid BSTRs and a live context; the enumerator is forward-only.
        let rows: IEnumWbemClassObject = unsafe {
            wmi.svc.ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from(query.as_str()),
                WBEM_GENERIC_FLAG_TYPE(WBEM_FLAG_FORWARD_ONLY.0 | WBEM_FLAG_RETURN_IMMEDIATELY.0),
                &wmi.ctx,
            )
        }
        .map_err(com_err("IWbemServices::ExecQuery"))?;
        // Every match is counted; only the first is kept.
        let mut first: Option<IWbemClassObject> = None;
        let mut matched: u32 = 0;
        loop {
            let mut slot: [Option<IWbemClassObject>; 1] = [None];
            let mut returned: u32 = 0;
            // SAFETY: one output slot and a valid count pointer.
            let hr = unsafe { rows.Next(WBEM_INFINITE, &mut slot, &mut returned) };
            if hr.is_err() {
                return Err(WinError::Com {
                    step: "IEnumWbemClassObject::Next",
                    hresult: hr.0 as u32,
                });
            }
            if let [Some(obj)] = slot {
                matched = matched.saturating_add(1);
                first.get_or_insert(obj);
            }
            // WBEM_S_FALSE: fewer objects than asked for, the end of the result set.
            if returned == 0 || hr.0 == WBEM_S_FALSE.0 {
                break;
            }
        }
        let obj = match (matched, first) {
            (0, _) | (_, None) => return Ok(0),
            (1, Some(obj)) => obj,
            (n, Some(_)) => return Err(WinError::Ambiguous { matched: n }),
        };
        let found = get_string(&obj, "InstanceID")?.unwrap_or_default();
        if found != id {
            return Err(WinError::IdMismatch { found });
        }
        let Some(path) = get_string(&obj, "__RELPATH")? else {
            return Err(WinError::Com {
                step: "IWbemClassObject::Get(__RELPATH)",
                hresult: 0x8004_1002, // WBEM_E_NOT_FOUND
            });
        };
        // SAFETY: the object path WMI returned for this instance, with the same context.
        unsafe {
            wmi.svc.DeleteInstance(
                &BSTR::from(path.as_str()),
                WBEM_FLAG_RETURN_WBEM_COMPLETE,
                &wmi.ctx,
                None,
            )
        }
        .map_err(com_err("IWbemServices::DeleteInstance"))?;
        Ok(1)
    }

    /// Creates a persistent-store firewall rule with `InstanceID` = `id` from a stored rule's fields
    /// (the version segment left out), by the method the M1B spike proved exact (`cim_create`).
    ///
    /// Fails before any WMI call when the id is refused ([`WinError::InvalidId`]) or a field has no
    /// exact mapping ([`WinError::Unmapped`], see [`map_rule`]); fails with [`WinError::ObjectExists`],
    /// changing nothing, when a rule with that id exists. Needs an elevated administrator.
    pub fn create_with_instance_id(id: &str, fields: &[(String, String)]) -> Result<(), WinError> {
        check_instance_id(id).map_err(WinError::InvalidId)?;
        let map = map_rule(fields).map_err(WinError::Unmapped)?;
        let _com = ComInit::new()?;
        let wmi = Wmi::connect(&map.context)?;
        let mut class: Option<IWbemClassObject> = None;
        // SAFETY: valid BSTR, live context, one output pointer.
        unsafe {
            wmi.svc.GetObject(
                &BSTR::from(RULE_CLASS),
                WBEM_FLAG_RETURN_WBEM_COMPLETE,
                &wmi.ctx,
                Some(&mut class as *mut Option<IWbemClassObject>),
                None,
            )
        }
        .map_err(com_err("IWbemServices::GetObject"))?;
        let Some(class) = class else {
            return Err(WinError::Com {
                step: "IWbemServices::GetObject",
                hresult: 0x8004_1002, // WBEM_E_NOT_FOUND
            });
        };
        // SAFETY: `class` is the live class object.
        let inst = unsafe { class.SpawnInstance(0) }.map_err(com_err("SpawnInstance"))?;
        put(&inst, "InstanceID", &Var::bstr(id))?;
        for (name, value) in &map.properties {
            let var = match value {
                PropValue::Str(s) => Var::bstr(s),
                PropValue::U16(n) => Var::i4(i32::from(*n)),
                PropValue::Bool(b) => Var::boolean(*b),
            };
            put(&inst, name, &var)?;
        }
        // SAFETY: live instance and context; synchronous call without a call-result object.
        unsafe {
            wmi.svc.PutInstance(
                &inst,
                WBEM_GENERIC_FLAG_TYPE(WBEM_FLAG_CREATE_ONLY.0),
                &wmi.ctx,
                None,
            )
        }
        .map_err(|e| {
            if e.code().0 == WBEM_E_ALREADY_EXISTS.0 {
                WinError::ObjectExists
            } else {
                com_err("IWbemServices::PutInstance")(e)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn fields_of(raw: &str) -> Vec<(String, String)> {
        parse_rule(raw).map(|r| r.fields).unwrap_or_default()
    }

    // ---- ids and WQL ------------------------------------------------------------------------

    #[test]
    fn id_with_control_char_or_too_long_rejected() {
        assert_eq!(check_instance_id(""), Err(IdError::Empty));
        for bad in [
            "a\0b", "a\nb", "\tx", "x\u{7f}", "x\u{85}y", "x\u{9b}", "\r",
        ] {
            assert!(
                matches!(check_instance_id(bad), Err(IdError::ControlChar { .. })),
                "{bad:?}"
            );
            assert!(matches!(
                wql_string_literal(bad),
                Err(IdError::ControlChar { .. })
            ));
            assert!(instance_query(bad).is_err());
        }
        assert_eq!(
            check_instance_id("a\nb"),
            Err(IdError::ControlChar { index: 1 })
        );
        let max = "x".repeat(MAX_ID_UNITS);
        assert_eq!(check_instance_id(&max), Ok(()));
        let long = "x".repeat(MAX_ID_UNITS + 1);
        assert_eq!(
            check_instance_id(&long),
            Err(IdError::TooLong {
                units: MAX_ID_UNITS + 1
            })
        );
        // UTF-16 units, not chars: 131 non-BMP chars are 262 units.
        let astral = "\u{1F600}".repeat(131);
        assert!(matches!(
            check_instance_id(&astral),
            Err(IdError::TooLong { units: 262 })
        ));
        assert!(instance_query(&long).is_err());
    }

    #[test]
    fn id_with_quote_escaped_or_rejected() {
        let hostile = "x' OR InstanceID LIKE '%";
        let q = instance_query(hostile).unwrap();
        assert_eq!(
            q,
            r"SELECT * FROM MSFT_NetFirewallRule WHERE InstanceID = 'x\' OR InstanceID LIKE \'%'"
        );
        // The literal is exactly one string token holding the whole id.
        let lit = wql_string_literal(hostile).unwrap();
        assert_eq!(wql_unquote(&lit).as_deref(), Some(hostile));
        // Every unescaped quote of the query is one of the literal's two delimiters.
        let tail = &q[q.find('\'').unwrap()..];
        assert_eq!(tail, lit);
        let mut unescaped = 0;
        let mut it = tail.chars();
        while let Some(c) = it.next() {
            match c {
                '\\' => {
                    it.next();
                }
                '\'' => unescaped += 1,
                _ => {}
            }
        }
        assert_eq!(unescaped, 2);
    }

    #[test]
    fn wql_literal_escapes_backslash_and_quote_and_round_trips() {
        let cases = [
            (
                "{dee51bba-69c3-4c90-9f22-faf95c857815}",
                "'{dee51bba-69c3-4c90-9f22-faf95c857815}'",
            ),
            (
                r"TCP Query User{1}C:\program files\a.exe",
                r"'TCP Query User{1}C:\\program files\\a.exe'",
            ),
            (r"a\'b", r"'a\\\'b'"),
            (r"trailing\", r"'trailing\\'"),
            ("'", r"'\''"),
            ("\"double\" %_[]", "'\"double\" %_[]'"),
            ("ünïcödé \u{1F600}", "'ünïcödé \u{1F600}'"),
        ];
        for (id, want) in cases {
            let lit = wql_string_literal(id).unwrap();
            assert_eq!(lit, want, "{id:?}");
            assert_eq!(wql_unquote(&lit).as_deref(), Some(id));
        }
    }

    #[test]
    fn wql_unquote_refuses_broken_literals() {
        for bad in ["", "'", "abc", "'a'b'", r"'a\'", "'a", "a'"] {
            assert_eq!(wql_unquote(bad), None, "{bad:?}");
        }
        assert_eq!(wql_unquote("''").as_deref(), Some(""));
    }

    // ---- parse_rule -------------------------------------------------------------------------

    #[test]
    fn parse_rule_splits_version_and_fields() {
        let raw = r"v2.31|Action=Allow|Active=TRUE|Dir=In|App=C:\x\a.exe|Name=X|";
        let r = parse_rule(raw).unwrap();
        assert_eq!(r.version, "v2.31");
        assert_eq!(
            r.fields,
            f(&[
                ("Action", "Allow"),
                ("Active", "TRUE"),
                ("Dir", "In"),
                ("App", r"C:\x\a.exe"),
                ("Name", "X")
            ])
        );
        assert_eq!(r.to_rule(), raw);
    }

    #[test]
    fn parse_rule_keeps_order_repeats_and_first_equals() {
        let raw = "v2.33|RA4=1.1.1.1|RA4=LocalSubnet|Desc=a=b, c|Name=|";
        let r = parse_rule(raw).unwrap();
        assert_eq!(
            r.fields,
            f(&[
                ("RA4", "1.1.1.1"),
                ("RA4", "LocalSubnet"),
                ("Desc", "a=b, c"),
                ("Name", "")
            ])
        );
        assert_eq!(r.to_rule(), raw);
        // Empty segments are skipped; no trailing bar is accepted.
        let r = parse_rule("v2.10||Name=X||Dir=In").unwrap();
        assert_eq!(r.fields, f(&[("Name", "X"), ("Dir", "In")]));
        assert_eq!(parse_rule("v2.10").unwrap().fields, Vec::new());
    }

    #[test]
    fn parse_rule_errors() {
        assert_eq!(parse_rule(""), Err(RuleParseError::Empty));
        assert_eq!(parse_rule("|Name=X|"), Err(RuleParseError::NoVersion));
        assert_eq!(
            parse_rule("v2.33|Name=X|bogus|"),
            Err(RuleParseError::SegmentWithoutEquals { index: 2 })
        );
        let long = format!("v2.33|Name={}|", "x".repeat(MAX_RULE_BYTES));
        assert_eq!(parse_rule(&long), Err(RuleParseError::TooLong));
    }

    // ---- map_rule ---------------------------------------------------------------------------

    fn prop<'a>(m: &'a RuleMap, name: &str) -> Option<&'a PropValue> {
        m.properties
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v)
    }

    fn ctx<'a>(m: &'a RuleMap, name: &str) -> Option<&'a ContextValue> {
        m.context.iter().find(|(n, _)| *n == name).map(|(_, v)| v)
    }

    fn list(v: &[&str]) -> ContextValue {
        ContextValue::StrList(v.iter().map(|s| (*s).to_owned()).collect())
    }

    /// The six rule strings the M1B spike re-created exactly on the VM (RESULT.json firewall cases).
    const SPIKE_RULES: [&str; 6] = [
        r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=C:\Program Files\PurgeSpike\app1.exe|Name=PurgeSpike F1 program|Defer=User|",
        "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=8080|LPort2_10=8090-8095|Name=PurgeSpike F2 port|",
        "v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|RPort=53|RA4=LocalSubnet|RA6=LocalSubnet|RA4=192.168.1.0/255.255.255.0|RA4=10.0.0.1|RA4=10.1.1.1-10.1.1.9|RA6=fe80::1|Name=PurgeSpike F3 remote|",
        r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=9000|App=%SystemRoot%\System32\svchost.exe|Svc=PurgeSpikeS1|Name=PurgeSpike F4 service|",
        r"v2.33|Action=Allow|Active=FALSE|Dir=In|Profile=Private|Profile=Public|IFType=Wireless|IFType=RemoteAccess|App=C:\Program Files\PurgeSpike\app5.exe|Name=PurgeSpike F5 iftype|",
        r"v2.33|Action=Allow|Active=TRUE|Dir=Out|App=C:\Program Files\PurgeSpike\app6.exe|Name=PurgeSpike F6 group|Desc=Purge spike rule 6: a=b, c|EmbedCtxt=PurgeSpike Group|",
    ];

    #[test]
    fn map_rule_maps_every_spike_rule() {
        for raw in SPIKE_RULES {
            let m = map_rule(&fields_of(raw));
            assert!(m.is_ok(), "{raw}: {m:?}");
        }
    }

    #[test]
    fn map_rule_spike_program_rule() {
        let m = map_rule(&fields_of(SPIKE_RULES[0])).unwrap();
        assert_eq!(
            m.properties,
            vec![
                (
                    "ElementName",
                    PropValue::Str("PurgeSpike F1 program".into())
                ),
                ("Enabled", PropValue::U16(1)),
                ("Direction", PropValue::U16(1)),
                ("Action", PropValue::U16(2)),
                ("EdgeTraversalPolicy", PropValue::U16(2)),
            ]
        );
        assert_eq!(
            m.context,
            vec![
                (
                    "Program",
                    ContextValue::Str(r"C:\Program Files\PurgeSpike\app1.exe".into())
                ),
                ("Protocol", ContextValue::Str("6".into())),
            ]
        );
    }

    #[test]
    fn map_rule_folds_port_ranges_into_local_and_remote_port() {
        let m = map_rule(&fields_of(SPIKE_RULES[1])).unwrap();
        assert_eq!(ctx(&m, "LocalPort"), Some(&list(&["8080", "8090-8095"])));
        assert_eq!(ctx(&m, "RemotePort"), None);
        let m = map_rule(&f(&[
            ("Name", "r"),
            ("Protocol", "17"),
            ("RPort", "53"),
            ("RPort2_10", "1-65535"),
        ]))
        .unwrap();
        assert_eq!(ctx(&m, "RemotePort"), Some(&list(&["53", "1-65535"])));
        assert_eq!(ctx(&m, "LocalPort"), None);
    }

    #[test]
    fn map_rule_addresses_keep_order_and_merge_local_subnet() {
        let m = map_rule(&fields_of(SPIKE_RULES[2])).unwrap();
        assert_eq!(
            ctx(&m, "RemoteAddress"),
            Some(&list(&[
                "LocalSubnet",
                "192.168.1.0/255.255.255.0",
                "10.0.0.1",
                "10.1.1.1-10.1.1.9",
                "fe80::1"
            ]))
        );
        assert_eq!(prop(&m, "Action"), Some(&PropValue::U16(4)));
        assert_eq!(prop(&m, "Direction"), Some(&PropValue::U16(2)));
    }

    #[test]
    fn map_rule_service_profiles_iftype_group() {
        let m = map_rule(&fields_of(SPIKE_RULES[3])).unwrap();
        assert_eq!(
            ctx(&m, "Service"),
            Some(&ContextValue::Str("PurgeSpikeS1".into()))
        );
        let m = map_rule(&fields_of(SPIKE_RULES[4])).unwrap();
        assert_eq!(prop(&m, "Profiles"), Some(&PropValue::U16(6)));
        assert_eq!(prop(&m, "Enabled"), Some(&PropValue::U16(2)));
        assert_eq!(ctx(&m, "InterfaceType"), Some(&ContextValue::U32(6)));
        let m = map_rule(&fields_of(SPIKE_RULES[5])).unwrap();
        assert_eq!(
            prop(&m, "Description"),
            Some(&PropValue::Str("Purge spike rule 6: a=b, c".into()))
        );
        assert_eq!(
            prop(&m, "RuleGroup"),
            Some(&PropValue::Str("PurgeSpike Group".into()))
        );
    }

    #[test]
    fn map_rule_keys_are_case_insensitive_values_exact() {
        let m = map_rule(&f(&[("name", "x"), ("ACTION", "Block"), ("dIr", "Out")])).unwrap();
        assert_eq!(prop(&m, "Action"), Some(&PropValue::U16(4)));
        let e = map_rule(&f(&[("Name", "x"), ("Action", "allow")])).unwrap_err();
        assert!(e[0].starts_with("Action=allow"), "{e:?}");
        let e = map_rule(&f(&[("Name", "x"), ("Active", "true")])).unwrap_err();
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn map_rule_edge_and_defer() {
        let edge = |pairs: &[(&str, &str)]| {
            let mut v = vec![("Name", "x")];
            v.extend_from_slice(pairs);
            map_rule(&f(&v)).map(|m| prop(&m, "EdgeTraversalPolicy").cloned())
        };
        assert_eq!(edge(&[]), Ok(None));
        assert_eq!(edge(&[("Edge", "TRUE")]), Ok(Some(PropValue::U16(1))));
        assert_eq!(edge(&[("Defer", "User")]), Ok(Some(PropValue::U16(2))));
        assert_eq!(
            edge(&[("Edge", "TRUE"), ("Defer", "App")]),
            Ok(Some(PropValue::U16(3)))
        );
        assert!(edge(&[("Defer", "App")]).is_err());
        assert!(edge(&[("Edge", "TRUE"), ("Defer", "User")]).is_err());
        assert!(edge(&[("Edge", "FALSE")]).is_err());
        assert!(edge(&[("Defer", "Other")]).is_err());
    }

    #[test]
    fn map_rule_icmp_needs_matching_protocol() {
        let m = map_rule(&f(&[
            ("Name", "x"),
            ("Protocol", "1"),
            ("ICMP4", "8:*"),
            ("ICMP4", "3:4"),
        ]))
        .unwrap();
        assert_eq!(ctx(&m, "IcmpType"), Some(&list(&["8:*", "3:4"])));
        assert!(map_rule(&f(&[("Name", "x"), ("Protocol", "58"), ("ICMP6", "128:*")])).is_ok());
        assert!(map_rule(&f(&[("Name", "x"), ("Protocol", "58"), ("ICMP4", "8:*")])).is_err());
        assert!(map_rule(&f(&[("Name", "x"), ("ICMP4", "8:*")])).is_err());
        assert!(
            map_rule(&f(&[
                ("Name", "x"),
                ("Protocol", "1"),
                ("ICMP4", "8:*"),
                ("ICMP6", "128:*")
            ]))
            .is_err()
        );
        assert!(map_rule(&f(&[("Name", "x"), ("Protocol", "1"), ("ICMP4", "8")])).is_err());
    }

    #[test]
    fn map_rule_refuses_what_it_cannot_recreate_exactly() {
        let refused = [
            // Unknown or unproven keys.
            vec![("Name", "x"), ("PFN", "Microsoft.App_8wekyb3d8bbwe")],
            vec![("Name", "x"), ("LUOwn", "S-1-5-21-1")],
            vec![("Name", "x"), ("RA42", "IntrAnet")],
            vec![
                ("Name", "x"),
                ("IF", "{487881FE-C517-4D54-BF9C-4B84CA1092BD}"),
            ],
            vec![("Name", "x"), ("Protocol", "6"), ("LPort2_20", "Ply2Disc")],
            // Port keywords and non-canonical numbers.
            vec![("Name", "x"), ("Protocol", "6"), ("LPort", "RPC")],
            vec![("Name", "x"), ("Protocol", "6"), ("LPort", "RPC-EPMap")],
            vec![("Name", "x"), ("Protocol", "6"), ("LPort2_10", "IPHTTPSIn")],
            vec![("Name", "x"), ("Protocol", "6"), ("LPort", "080")],
            vec![("Name", "x"), ("Protocol", "6"), ("LPort", "65536")],
            vec![("Name", "x"), ("Protocol", "6"), ("LPort", "1-2")],
            vec![("Name", "x"), ("Protocol", "6"), ("LPort2_10", "9-1")],
            vec![
                ("Name", "x"),
                ("Protocol", "6"),
                ("LPort", "80"),
                ("LPort", "80"),
            ],
            vec![("Name", "x"), ("Protocol", "256")],
            vec![("Name", "x"), ("Protocol", "TCP")],
            // Addresses.
            vec![("Name", "x"), ("RA4", "LocalSubnet")],
            vec![("Name", "x"), ("RA6", "LocalSubnet")],
            vec![("Name", "x"), ("RA4", "DNS"), ("RA6", "DNS")],
            vec![("Name", "x"), ("RA4", "DEAD")],
            vec![("Name", "x"), ("RA6", "Ply2Renders")],
            vec![("Name", "x"), ("RA4", "fe80::1")],
            vec![("Name", "x"), ("LA6", "10.0.0.1")],
            vec![("Name", "x"), ("RA4", "10.0.0.1"), ("RA4", "10.0.0.1")],
            vec![
                ("Name", "x"),
                ("RA4", "LocalSubnet"),
                ("RA4", "LocalSubnet"),
                ("RA6", "LocalSubnet"),
            ],
            // Repeats, empties, missing name.
            vec![("Name", "x"), ("Name", "y")],
            vec![("Name", "x"), ("Action", "Allow"), ("Action", "Allow")],
            vec![("Name", "x"), ("App", "a"), ("App", "b")],
            vec![("Name", "x"), ("Profile", "Public"), ("Profile", "Public")],
            vec![("Name", "x"), ("IFType", "Lan"), ("IFType", "Lan")],
            vec![("Name", "x"), ("Desc", "")],
            vec![("Name", "x"), ("App", "a\0b")],
            vec![("Action", "Allow")],
            // Values outside the mapped set.
            vec![("Name", "x"), ("Action", "ByPass")],
            vec![("Name", "x"), ("Dir", "Both")],
            vec![("Name", "x"), ("Profile", "Any")],
            vec![("Name", "x"), ("IFType", "All")],
            vec![("Name", "x"), ("LSM", "FALSE")],
        ];
        for pairs in refused {
            let r = map_rule(&f(&pairs));
            assert!(r.is_err(), "{pairs:?} mapped to {r:?}");
        }
    }

    #[test]
    fn map_rule_lists_every_refused_field() {
        let e = map_rule(&f(&[("PFN", "p"), ("LPort", "RPC"), ("Platform", "2:6:2")])).unwrap_err();
        assert_eq!(e.len(), 4, "{e:?}");
        assert!(e[0].starts_with("PFN=p"));
        assert!(e[1].starts_with("LPort=RPC"));
        assert!(e[2].starts_with("Platform=2:6:2"));
        assert_eq!(e[3], "Name (missing)");
    }

    #[test]
    fn map_rule_lsm_lom_and_domain_profile() {
        let m = map_rule(&f(&[
            ("Name", "x"),
            ("LSM", "TRUE"),
            ("LOM", "TRUE"),
            ("Profile", "Domain"),
            ("LA6", "fe80::/64"),
        ]))
        .unwrap();
        assert_eq!(prop(&m, "LooseSourceMapping"), Some(&PropValue::Bool(true)));
        assert_eq!(prop(&m, "LocalOnlyMapping"), Some(&PropValue::Bool(true)));
        assert_eq!(prop(&m, "Profiles"), Some(&PropValue::U16(1)));
        assert_eq!(ctx(&m, "LocalAddress"), Some(&list(&["fe80::/64"])));
    }
}
