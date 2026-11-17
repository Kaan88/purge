//! Scanner SYS-FIREWALL: leftover firewall rules (M1b, ENGINE_PLAN.md §5.6, §5.7.2).
//!
//! An uninstaller often leaves the rules it (or Windows' "allow this program" prompt) added for the
//! app's programs. This scanner offers each rule of the local store whose program was the app's.
//!
//! # Input
//!
//! Only what the pipeline read once for every scanner ([`ScanCtx::ext`]): the firewall rules of the
//! local (persistent) store in `ctx.ext.sysobj.firewall` (one `values()` of `FirewallRules`, C-SYSOBJ),
//! and the rules the harvest recorded as the app's (`fp.sys.firewall_rules`). The scanner opens no
//! registry key of its own (budget: 0 key opens); the group-policy store is never read. The only other
//! source call is one `exists` per candidate's program file.
//!
//! When the rule list could not be read (`NotCaptured`, `AccessDenied`, anything else) the index carries
//! one line in its errors (the scan's warning) and an empty list, and this scanner emits nothing.
//!
//! # Which rules
//!
//! A rule is considered only when
//!
//! - its `App=` resolves to one file ([`purge_index::sysobj::ProgramRef::File`]) that
//!   [`ScanCtx::object_owner`] says is the app's (inside an InstallRoot, or one of the app's exe or
//!   outside-root files), or
//! - its id is one the harvest recorded for the app (`fp.sys.firewall_rules`).
//!
//! Display name, group, description and `EmbedCtxt` are never a reason: a rule named like the app for
//! another program is not the app's, and two rules sharing a display name are two candidates (or one,
//! or none), never a group. A rule without a program (port-only, `App=System`) is never a candidate,
//! even when its `Svc=` names a service of the app, and even when a (hostile) fingerprint records its
//! id. A rule whose program is an interpreter or host (`svchost.exe`, ...) has no file program and is
//! not the app's; the harvest never records one either.
//!
//! The guard's object check comes first ([`DenyList::check_object`]: `fw.package-bound`,
//! `fw.resource-name` on `Name` or `EmbedCtxt`, a rule of the Windows baseline): such rules are never
//! emitted.
//!
//! # The candidate
//!
//! `Target::FirewallRule { id }` with the registry value name exactly as stored, `Action::DeleteKey`,
//! `Category::System`, harm Low, `object_fp` = the digest of (id, raw rule string). Then:
//!
//! - **recorded** with an equal digest: [`CandidateBuilder::owned_system_object`] with the harvest
//!   record, which can make the rule Safe (D10) only when the program file is gone now (the source
//!   says `Absent`); a program still present (or whose state is unknown) leaves the rule Likely
//!   (evidence capped at Tier B);
//! - **recorded** with another digest: `ObjectChangedSinceHarvest` (hard). A rule whose program is no
//!   longer the app's is not offered at all: the id was reused for something else;
//! - **not recorded**: the program alone, which is never Tier A for an object (at most Likely).
//!
//! # What undo can do
//!
//! The executor deletes a rule only when it can re-create it exactly (`purge_win::firewall::map_rule`,
//! mirrored here by [`recreate_refusal`] because this crate does not depend on `purge-win`), when the
//! rule uses no field form a VM round trip has not proven yet (`purge_model::FirewallShape`, the one
//! list both read) and when it names no service (`Svc`, refused in M1b: its program is the service
//! host, which no undo would re-create); a rule it would refuse gets `CannotBackUp` (hard,
//! report-only). Undo re-creates a rule only when its `App`,
//! expanded with the machine environment the way the executor expands it, is a file inside a root of
//! the run; a rule whose `App` is not ([`undo_program_in_root`]) can be deleted but never brought back,
//! so it carries `Reversibility::None` with the `ReversibilityNone` soft blocker and is never
//! preselected. When `purge_model::object::FIREWALL_RESTORE_EXACT` is false every candidate is
//! `Reversibility::Partial` with `ReversibilityPartial` (the rule would come back under a new id).
//!
//! The rule's program also takes the blockers a path target would get from the MSI ownership index
//! ([`ScanCtx::msi_blockers`]: a file another installed MSI product owns) and from the other installed
//! apps (`InsideOtherApp`, `ReferencedByOtherApp`): a rule for another product's program is not the
//! app's to remove.

use std::collections::BTreeMap;

use purge_guard::canon::{GuardEnv, canon_path};
use purge_guard::deny::{DenyList, ObjectGuardFacts};
use purge_guard::prefix::{self, expand_env};
use purge_index::sysobj::{self, FIREWALL_RULES_KEY, FirewallFacts, ProgramRef};
use purge_model::{
    Action, Blocker, Candidate, Category, FIREWALL_RESTORE_EXACT, FirewallRuleFields,
    FirewallShape, Harm, ObjectKind, ObjectWhy, Reversibility, SysFirewallRule, Target,
};

use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "SYS-FIREWALL";

/// The local store's rules, read by the pipeline (`purge_index::sysobj::read_firewall`), values only.
const ROOTS: &[RootSpec] = &[RootSpec::reg(
    r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
    Some(0),
)];

/// The error line prefix `purge_index::sysobj::build` writes when the rule list cannot be read.
const LIST_UNREADABLE: &str = "sysobj: firewall rules:";

/// The SYS-FIREWALL scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysFirewall {
    /// Whether an undo re-creates a rule under its own id (`FIREWALL_RESTORE_EXACT`).
    restore_exact: bool,
}

impl Default for SysFirewall {
    fn default() -> Self {
        Self {
            restore_exact: FIREWALL_RESTORE_EXACT,
        }
    }
}

impl SysFirewall {
    /// The scanner as it would run were `FIREWALL_RESTORE_EXACT` equal to `restore_exact` (tests).
    pub fn with_restore_exact(restore_exact: bool) -> Self {
        Self { restore_exact }
    }
}

impl Scanner for SysFirewall {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        let sysobj = &ctx.ext.sysobj;
        // Unknown is never "none": an unreadable list offers nothing (its warning is the index's).
        if sysobj.errors.iter().any(|e| e.starts_with(LIST_UNREADABLE)) {
            return Vec::new();
        }
        if sysobj.firewall.is_empty() {
            return Vec::new();
        }
        let deny = DenyList::compile(ctx.guard);
        let mut out: Vec<Candidate> = Vec::new();
        for rule in &sysobj.firewall {
            let Some(candidate) = self.rule_candidate(ctx, &deny, rule) else {
                continue;
            };
            if !out.iter().any(|c| c.id == candidate.id) {
                out.push(candidate);
            }
        }
        out
    }
}

impl SysFirewall {
    /// The candidate for one rule, or `None` when the rule is not the app's or is never offered.
    fn rule_candidate(
        &self,
        ctx: &ScanCtx<'_>,
        deny: &DenyList,
        rule: &FirewallFacts,
    ) -> Option<Candidate> {
        let id = rule.identity.id.as_str();
        // A rule without a program is never the app's, whatever records its id.
        if matches!(rule.program, ProgramRef::None) {
            return None;
        }
        let recorded = recorded(ctx, id);
        let current_owner = ctx.object_owner(&rule.program);
        let digest = rule.identity.fp();
        let unchanged = recorded.is_some_and(|r| r.identity.fp() == digest);

        // Why the rule is the app's.
        let why: ObjectWhy = match (current_owner, recorded) {
            (Some(why), _) => why,
            // Recorded with the same string, and the program cannot be resolved now (an environment
            // reference the scan cannot expand): the harvest's attribution stands, flagged below, but
            // only for what a harvest can have recorded: one program file that is the app's, and an
            // `App=` that is no interpreter or host (a `svchost.exe` service rule is never the app's).
            (None, Some(r))
                if unchanged
                    && matches!(rule.program, ProgramRef::Unresolved { .. })
                    && !rule
                        .fields
                        .get_all("App")
                        .iter()
                        .any(|a| sysobj::is_host(a))
                    && r.program
                        .as_ref()
                        .and_then(|p| ctx.object_owner(&ProgramRef::File(p.clone())))
                        .is_some() =>
            {
                r.why
            }
            // Not the app's program now: another program, or a recorded id reused for one.
            _ => return None,
        };

        // The guard first: package-bound, resource-named and baseline rules are never emitted.
        let facts = ObjectGuardFacts {
            name_or_path_or_id: id,
            program: rule.program.file(),
            package_bound: rule.package_bound,
            resource_name: rule.resource_name || resource_named(&rule.fields),
            in_baseline: ctx
                .baseline
                .is_some_and(|b| b.has_value(FIREWALL_RULES_KEY, id)),
            ..ObjectGuardFacts::default()
        };
        if deny
            .check_object(ObjectKind::FirewallRule, &facts)
            .is_some()
        {
            return None;
        }

        let mut b = ctx.candidate(
            ID,
            Target::FirewallRule { id: id.to_owned() },
            Action::DeleteKey,
            Category::System,
        );
        b = b.object_fp(digest);
        b.harm(Harm::Low);

        // The program file the attribution rests on: the rule's now, else the one recorded.
        let program: Option<&str> = rule
            .program
            .file()
            .or_else(|| recorded.and_then(|r| r.program.as_deref()));

        if unchanged {
            b = b.owned_system_object(why, true);
            let gone = program.is_some_and(|p| ctx.fs.exists(p).is_absent());
            if !gone {
                b.cap_at_tier_b("the rule's program file is still present");
            }
        } else {
            b = b.owned_system_object(why, false);
            if recorded.is_some() {
                b.blocker(Blocker::ObjectChangedSinceHarvest);
            }
        }
        if !matches!(rule.program, ProgramRef::File(_)) {
            b.blocker(Blocker::ProgramUnresolved);
        }

        // The program's other owners: another MSI product's file, another app's root or file.
        if let Some(program) = program {
            for blocker in ctx.msi_blockers(&Target::Path {
                path: program.to_owned(),
            }) {
                b.blocker(blocker);
            }
            for blocker in ctx.other_apps.path_blockers(program) {
                if matches!(
                    blocker,
                    Blocker::InsideOtherApp { .. } | Blocker::ReferencedByOtherApp { .. }
                ) {
                    b.blocker(blocker);
                }
            }
        }

        // What the executor and its undo can do with this rule.
        if recreate_refusal(&rule.fields).is_some() {
            b.blocker(Blocker::CannotBackUp);
        }
        if !self.restore_exact {
            b.reversibility(Reversibility::Partial)
                .blocker(Blocker::ReversibilityPartial);
        } else if !undo_program_in_root(ctx, &rule.fields) {
            b.reversibility(Reversibility::None)
                .blocker(Blocker::ReversibilityNone);
        }

        b.common_blockers();
        Some(b.build())
    }
}

/// The harvest's record of the rule with exactly this id.
fn recorded<'a>(ctx: &ScanCtx<'a>, id: &str) -> Option<&'a SysFirewallRule> {
    let fp = ctx.fp;
    fp.sys.firewall_rules.iter().find(|r| r.identity.id == id)
}

/// Whether any `Name` or `EmbedCtxt` of the rule is a resource reference (`@...`): Windows' own rule
/// groups. The index looks at `Name` only; the executor's gate at both.
fn resource_named(fields: &FirewallRuleFields) -> bool {
    ["Name", "EmbedCtxt"].iter().any(|key| {
        fields
            .get_all(key)
            .iter()
            .any(|v| v.trim_start().starts_with('@'))
    })
}

// ---------------------------------------------------------------------------------------------------------
// Undo's program check
// ---------------------------------------------------------------------------------------------------------

/// The machine environment the executor expands a rule's `App` with (`purge_exec::act_firewall`):
/// `SystemRoot`, `windir`, `SystemDrive`, the Program Files forms, `ProgramData`, `ALLUSERSPROFILE`.
fn machine_vars(env: &GuardEnv) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    let mut put = |name: &str, value: &str| {
        let value = value.trim().trim_end_matches(['\\', '/']);
        if !value.is_empty() {
            vars.insert(name.to_owned(), value.to_owned());
        }
    };
    put("SYSTEMROOT", &env.windir);
    put("WINDIR", &env.windir);
    put("SYSTEMDRIVE", &env.system_drive);
    put("PROGRAMFILES", &env.program_files);
    put("PROGRAMW6432", &env.program_files);
    if let Some(x86) = env.program_files_x86.as_deref() {
        put("PROGRAMFILES(X86)", x86);
    }
    put("PROGRAMDATA", &env.program_data);
    put("ALLUSERSPROFILE", &env.program_data);
    vars
}

/// Whether undo could re-create the rule: its one `App`, expanded with the machine environment the way
/// the executor expands it and canonicalised, is a file strictly inside an InstallRoot of the app (the
/// roots the journal header records). A rule without `App` would pass undo's check, but is never a
/// candidate.
pub fn undo_program_in_root(ctx: &ScanCtx<'_>, fields: &FirewallRuleFields) -> bool {
    let apps = fields.get_all("App");
    let [raw] = apps.as_slice() else {
        return false;
    };
    let expanded = expand_env(raw.trim(), &machine_vars(ctx.guard));
    if expanded.contains('%') || expanded.trim().is_empty() {
        return false;
    }
    let Ok(canon) = canon_path(expanded.trim(), &GuardEnv::default(), None) else {
        return false;
    };
    if canon.needs_long_name || prefix::depth(&canon.path) < 2 {
        return false;
    }
    ctx.inside_install_root(&canon.path)
        .is_some_and(|root| !prefix::is_same(&canon.path, &root.path))
}

// ---------------------------------------------------------------------------------------------------------
// Exact re-create (mirror of purge_win::firewall::map_rule)
// ---------------------------------------------------------------------------------------------------------

/// Single-valued keys of `map_rule`: a second occurrence is refused.
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

#[derive(Default)]
struct AddrList {
    values: Vec<String>,
    local_subnet: Vec<Family>,
}

/// Why the executor would refuse to delete the rule because it could not re-create it exactly, or
/// `None` when it can. The same acceptance as `purge_win::firewall::map_rule` (which this crate cannot
/// call): every field must have an exact mapping, single-valued keys and list values must not repeat,
/// no value may be empty or hold a NUL, and `Name`, `Action`, `Active` and `Dir` must be present. Then
/// the executor's own refusals: a field form not proven by a VM round trip
/// ([`FirewallShape::unproven_in`]) and a service's rule (`Svc`). Any disagreement only costs a
/// cleanup, never safety: the executor's gate runs `map_rule` and the same refusals itself before every
/// delete.
pub fn recreate_refusal(fields: &FirewallRuleFields) -> Option<String> {
    let mut bad: Vec<String> = Vec::new();
    let mut seen_single: Vec<&'static str> = Vec::new();
    let mut name = false;
    let mut edge = false;
    let mut defer: Option<&str> = None;
    let mut protocol: Option<&str> = None;
    let mut profiles: u16 = 0;
    let mut iftype: u32 = 0;
    let mut lport: Vec<&str> = Vec::new();
    let mut rport: Vec<&str> = Vec::new();
    let mut laddr = AddrList::default();
    let mut raddr = AddrList::default();
    let mut icmp: Vec<&str> = Vec::new();
    let mut icmp_families: Vec<Family> = Vec::new();

    for (key, value) in &fields.fields {
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
            "ACTION" if !matches!(v, "Allow" | "Block") => {
                bad.push(format!("{} (unknown action)", seg()));
            }
            "ACTIVE" if !matches!(v, "TRUE" | "FALSE") => {
                bad.push(format!("{} (not TRUE or FALSE)", seg()));
            }
            "DIR" if !matches!(v, "In" | "Out") => {
                bad.push(format!("{} (unknown direction)", seg()));
            }
            "ACTION" | "ACTIVE" | "DIR" | "DESC" | "EMBEDCTXT" | "APP" | "SVC" => {}
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
            "NAME" => name = true,
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
                } else if list.contains(&v) {
                    bad.push(format!("{} (repeated value)", seg()));
                } else {
                    list.push(v);
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
                } else if icmp.contains(&v) {
                    bad.push(format!("{} (repeated value)", seg()));
                } else {
                    icmp.push(v);
                    let fam = if k == "ICMP4" { Family::V4 } else { Family::V6 };
                    if !icmp_families.contains(&fam) {
                        icmp_families.push(fam);
                    }
                }
            }
            _ => bad.push(format!("{} (no mapping)", seg())),
        }
    }

    if !name {
        bad.push("Name (missing)".to_owned());
    }
    for (key, shown) in [("ACTION", "Action"), ("ACTIVE", "Active"), ("DIR", "Dir")] {
        if !seen_single.contains(&key) {
            bad.push(format!("{shown} (missing)"));
        }
    }
    let unproven = FirewallShape::unproven_in(&fields.fields);
    if !unproven.is_empty() {
        let names: Vec<&str> = unproven.iter().map(|s| s.name()).collect();
        bad.push(format!(
            "{} (not yet proven to come back exactly)",
            names.join(", ")
        ));
    }
    if fields.get("Svc").is_some() {
        bad.push("Svc (a service's rule is not deleted in M1b)".to_owned());
    }
    match (edge, defer) {
        (false, None) | (true, None) | (false, Some("User")) | (true, Some("App")) => {}
        (e, d) => bad.push(format!(
            "Edge={} with Defer={} (no mapping)",
            if e { "TRUE" } else { "-" },
            d.unwrap_or("-")
        )),
    }
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
    (!bad.is_empty()).then(|| bad.join("; "))
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

#[cfg(test)]
mod tests {
    use super::*;
    use purge_model::parse_firewall_rule;

    fn refusal(raw: &str) -> Option<String> {
        recreate_refusal(&parse_firewall_rule(raw).expect("rule parses"))
    }

    /// The spike's rule shapes (apart from its service rule) are accepted.
    #[test]
    fn mapped_rules_are_accepted() {
        for raw in [
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=C:\x\a.exe|Name=A|Defer=User|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=8080|LPort2_10=8090-8095|Name=B|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=Out|App=C:\x\b.exe|Name=C|Desc=d, e|EmbedCtxt=G|",
            r"v2.33|Action=Block|Active=FALSE|Dir=In|Profile=Private|Profile=Public|IFType=Wireless|IFType=RemoteAccess|Name=D|",
            r"v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|RPort=53|RA4=LocalSubnet|RA6=LocalSubnet|RA4=10.0.0.1|RA6=fe80::1|Name=E|",
        ] {
            assert_eq!(refusal(raw), None, "{raw}");
        }
    }

    /// Mapped, but not proven by a VM round trip (purge_model::FIREWALL_UNPROVEN_SHAPES), a service's
    /// rule, and a rule without Action, Active or Dir: refused, as the executor's gate refuses them.
    #[test]
    fn unproven_service_and_incomplete_rules_are_refused() {
        for raw in [
            r"v2.33|Action=Block|Active=FALSE|Dir=In|Profile=Domain|Profile=Public|Name=D|",
            r"v2.33|Action=Block|Active=FALSE|Dir=In|Name=D|Edge=TRUE|",
            r"v2.33|Action=Block|Active=FALSE|Dir=In|Name=D|Edge=TRUE|Defer=App|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=1|ICMP4=8:*|Name=E|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Name=E|LA4=10.0.0.1|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|IFType=Lan|Name=F|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|LSM=TRUE|Name=F|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|LOM=TRUE|Name=F|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|RPort2_10=1-9|Name=F|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=47|Name=F|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=9000|App=%SystemRoot%\System32\svchost.exe|Svc=S1|Name=G|",
            r"v2.33|Action=Allow|Dir=In|Name=H|",
            r"v2.33|Active=TRUE|Dir=In|Name=H|",
            r"v2.33|Action=Allow|Active=TRUE|Name=H|",
        ] {
            assert!(refusal(raw).is_some(), "{raw}");
        }
    }

    /// What map_rule refuses is refused here too.
    #[test]
    fn unmapped_rules_are_refused() {
        for raw in [
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|LPort=RPC|Name=A|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|App=C:\x\a.exe|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Name=A|Name=B|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Name=A|RA4=LocalSubnet|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Name=A|RA4=DNS|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Name=A|LA4=fe80::1|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Name=A|Protocol=6|ICMP4=8:*|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Name=A|Edge=FALSE|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Name=A|Defer=App|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Name=A|LPort=080|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Name=A|LPort=80|LPort=80|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Name=A|Profile=Any|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Name=A|AppPkgId=S-1-15-2-1|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|Name=A|Desc=|",
            r"v2.33|Action=Bypass|Active=TRUE|Dir=In|Name=A|",
        ] {
            assert!(refusal(raw).is_some(), "{raw}");
        }
    }
}
