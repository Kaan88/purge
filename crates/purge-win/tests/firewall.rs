//! Firewall wrapper tests.
//!
//! Two tests run anywhere: a source scan of `src/firewall.rs` (no removal by name, no spawned tools, no
//! registry writes, no other policy store) and a read-only parse round trip over the stored rule strings
//! of the machine the tests run on. Every test that creates or deletes a rule is `#[ignore]`d: it runs on
//! the rig VM only, elevated (`<exe> --ignored --exact <name> --test-threads=1`). Rules those tests
//! create carry ids starting with `PurgeTest-fw-` and are deleted by id when the test ends.
#![cfg(feature = "write")]

use purge_win::firewall::{map_rule, parse_rule};
use purge_win::reg::{Key, RegRoot, RegView, current_control_set};

/// The stored rules of the persistent store, below `HKLM\SYSTEM\<ControlSet00N>`.
const RULES_SUBKEY: &str = r"Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

fn rules_key() -> Key {
    let cs = current_control_set().expect("current control set");
    Key::open(
        RegRoot::Hklm,
        &format!(r"SYSTEM\{cs}\{RULES_SUBKEY}"),
        RegView::K64,
    )
    .expect("open the FirewallRules key")
}

/// Every stored rule as (value name, rule string), sorted by name. Non-string values are skipped.
fn all_rules() -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = rules_key()
        .values()
        .expect("enumerate rule values")
        .into_iter()
        .filter_map(|v| v.as_string().map(|s| (v.name, s)))
        .collect();
    v.sort();
    v
}

#[test]
fn no_remove_by_name_symbols() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/firewall.rs");
    let src = std::fs::read_to_string(path).expect("read src/firewall.rs");
    let lower = src.to_ascii_lowercase();
    for word in [
        // No removal by name and no INetFw* COM objects.
        "inetfwrules",
        "inetfwrule",
        "inetfwpolicy",
        "inetfwmgr",
        ".remove(",
        // No spawned tool.
        "netsh",
        "powershell",
        "std::process",
        "command::new",
        "createprocess",
        "shellexecute",
        // No registry write, to the rule key or anywhere.
        "firewallpolicy",
        "reg_write",
        "regsetvalue",
        "regsetkeyvalue",
        "regdeletevalue",
        "regdeletekey",
        // No policy store other than the persistent one.
        "activestore",
        "rsop",
        "systemdefaults",
        "staticservicestore",
        "configurableservicestore",
        "localhost",
    ] {
        assert!(!lower.contains(word), "src/firewall.rs contains {word:?}");
    }
    // The store is named once, as the one constant every context is built from.
    assert_eq!(src.matches("\"PersistentStore\"").count(), 1);
    assert_eq!(src.matches("\"PolicyStore\"").count(), 1);
    // The only WMI calls that change anything are DeleteInstance and PutInstance(CREATE_ONLY).
    for call in [
        "ExecMethod",
        "PutClass",
        "DeleteClass",
        "WBEM_FLAG_UPDATE_ONLY",
        "WBEM_FLAG_CREATE_OR_UPDATE",
    ] {
        assert!(!src.contains(call), "src/firewall.rs contains {call:?}");
    }
    assert_eq!(src.matches(".DeleteInstance(").count(), 1);
    assert_eq!(src.matches(".PutInstance(").count(), 1);
    assert!(src.contains("WBEM_GENERIC_FLAG_TYPE(WBEM_FLAG_CREATE_ONLY.0)"));
}

/// Read-only: every stored rule string of this machine parses, and the parsed fields put back together
/// give the stored string again. Prints how many rules [`map_rule`] could re-create.
#[test]
fn host_rule_strings_parse_round_trip() {
    let rules = all_rules();
    assert!(!rules.is_empty(), "no stored firewall rules");
    let mut parse_failures = Vec::new();
    let mut rebuild_failures = Vec::new();
    let mut mapped = 0usize;
    let mut refused: std::collections::BTreeMap<String, usize> = Default::default();
    for (id, raw) in &rules {
        match parse_rule(raw) {
            Err(e) => parse_failures.push(format!("{id}: {e}")),
            Ok(r) => {
                if r.to_rule() != *raw {
                    rebuild_failures.push(id.clone());
                }
                match map_rule(&r.fields) {
                    Ok(_) => mapped += 1,
                    Err(why) => {
                        for w in why {
                            let key = w.split(['=', ' ']).next().unwrap_or_default().to_owned();
                            *refused.entry(key).or_default() += 1;
                        }
                    }
                }
            }
        }
    }
    eprintln!(
        "host rules: {} stored, {} parse failures, {} rebuild mismatches, {} mappable for exact re-create",
        rules.len(),
        parse_failures.len(),
        rebuild_failures.len(),
        mapped
    );
    eprintln!("refused field kinds: {refused:?}");
    assert!(parse_failures.is_empty(), "{parse_failures:?}");
    assert!(rebuild_failures.is_empty(), "{rebuild_failures:?}");
}

#[cfg(feature = "com")]
mod rig {
    //! Rig VM only, elevated. Each test creates its own rules and deletes them by id at the end.

    use std::collections::BTreeMap;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use purge_win::firewall::{
        IdError, MAX_ID_UNITS, WinError, create_with_instance_id, delete_by_instance_id, map_rule,
        parse_rule,
    };

    use super::{all_rules, rules_key};

    fn unique_id(tag: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("PurgeTest-fw-{tag}-{}-{nanos}", std::process::id())
    }

    fn read_rule(id: &str) -> Option<String> {
        rules_key()
            .value(id)
            .expect("read rule value")
            .and_then(|v| v.as_string())
    }

    /// Polls the stored rule for up to 5 s until it is present (`Some`) or gone (`None`).
    fn wait_rule(id: &str, present: bool) -> Option<String> {
        let start = Instant::now();
        loop {
            let r = read_rule(id);
            if r.is_some() == present || start.elapsed() > Duration::from_secs(5) {
                return r;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn fields(raw: &str) -> Vec<(String, String)> {
        parse_rule(raw).expect("parse rule").fields
    }

    /// C-OBJECT `same_rule`: equal multisets of (upper-cased key, value); the version is ignored.
    fn same_rule(a: &[(String, String)], b: &[(String, String)]) -> bool {
        let bag = |f: &[(String, String)]| {
            let mut m: BTreeMap<(String, String), usize> = BTreeMap::new();
            for (k, v) in f {
                *m.entry((k.to_ascii_uppercase(), v.clone())).or_default() += 1;
            }
            m
        };
        bag(a) == bag(b)
    }

    /// Asserts every rule of `before` except `gone` is still stored with the same string.
    fn assert_untouched(before: &[(String, String)], gone: &[&str]) {
        let after: BTreeMap<String, String> = all_rules().into_iter().collect();
        for (id, rule) in before {
            if gone.contains(&id.as_str()) {
                assert!(!after.contains_key(id), "{id} still present");
            } else {
                assert_eq!(after.get(id), Some(rule), "rule {id} changed or vanished");
            }
        }
    }

    /// Deletes the listed ids on drop, pass or fail.
    struct Cleanup(Vec<String>);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            for id in &self.0 {
                let _ = delete_by_instance_id(id);
            }
        }
    }

    fn create(id: &str, raw: &str) -> String {
        create_with_instance_id(id, &fields(raw)).unwrap_or_else(|e| panic!("create {id}: {e}"));
        wait_rule(id, true).unwrap_or_else(|| panic!("no stored rule for {id} after create"))
    }

    const DISABLED_RULE: &str = r"v2.33|Action=Allow|Active=FALSE|Dir=In|App=C:\Program Files\PurgeTest\same.exe|Name=PurgeTest|";

    #[test]
    #[ignore = "rig VM only, elevated: creates and deletes firewall rules"]
    fn delete_unknown_id_is_zero() {
        let before = all_rules();
        assert_eq!(delete_by_instance_id(&unique_id("unknown")), Ok(0));
        assert_eq!(
            delete_by_instance_id("{00000000-0000-0000-0000-000000000000}"),
            Ok(0)
        );
        assert_untouched(&before, &[]);
    }

    #[test]
    #[ignore = "rig VM only, elevated: creates and deletes firewall rules"]
    fn delete_exactly_one_of_two_rules_with_same_display_name() {
        let a = unique_id("same-a");
        let b = unique_id("same-b");
        let _clean = Cleanup(vec![a.clone(), b.clone()]);
        create(&a, DISABLED_RULE);
        let rule_b = create(&b, DISABLED_RULE);
        let before = all_rules();
        assert_eq!(delete_by_instance_id(&a), Ok(1));
        assert_eq!(wait_rule(&a, false), None, "{a} not deleted");
        assert_eq!(read_rule(&b).as_deref(), Some(rule_b.as_str()));
        assert_untouched(&before, &[a.as_str()]);
    }

    #[test]
    #[ignore = "rig VM only, elevated: creates and deletes firewall rules"]
    fn id_with_quote_escaped_or_rejected() {
        // A rule the injected LIKE '%' would match, besides every other rule on the machine.
        let victim = unique_id("victim");
        let _clean = Cleanup(vec![victim.clone()]);
        create(&victim, DISABLED_RULE);
        let before = all_rules();
        for hostile in [
            "x' OR InstanceID LIKE '%",
            "x\\' OR InstanceID LIKE '%",
            "%",
            "PurgeTest-fw-%",
            "' OR 1=1 OR InstanceID='",
        ] {
            let r = delete_by_instance_id(hostile);
            assert!(
                matches!(r, Ok(0) | Err(WinError::InvalidId(_))),
                "{hostile:?}: {r:?}"
            );
        }
        assert_untouched(&before, &[]);
    }

    #[test]
    #[ignore = "rig VM only, elevated: creates and deletes firewall rules"]
    fn id_with_control_char_or_too_long_rejected() {
        let before = all_rules();
        let long = "x".repeat(MAX_ID_UNITS + 1);
        let fields = fields(DISABLED_RULE);
        for bad in [
            "PurgeTest\nfw",
            "PurgeTest\0fw",
            "\u{7f}",
            long.as_str(),
            "",
        ] {
            assert!(
                matches!(delete_by_instance_id(bad), Err(WinError::InvalidId(_))),
                "{bad:?}"
            );
            assert!(
                matches!(
                    create_with_instance_id(bad, &fields),
                    Err(WinError::InvalidId(_))
                ),
                "{bad:?}"
            );
        }
        assert_eq!(
            delete_by_instance_id(&long),
            Err(WinError::InvalidId(IdError::TooLong {
                units: MAX_ID_UNITS + 1
            }))
        );
        assert_untouched(&before, &[]);
    }

    /// Create from fields, read the stored string, delete by id, re-create from the stored string's
    /// fields: the second stored string is the same rule (C-OBJECT `same_rule`) as the first, and the
    /// first is the same rule as the input.
    fn round_trip(tag: &str, raw: &str) -> Result<bool, String> {
        let id = unique_id(tag);
        let _clean = Cleanup(vec![id.clone()]);
        let input = fields(raw);
        create_with_instance_id(&id, &input).map_err(|e| format!("{tag}: create: {e}"))?;
        let s1 = wait_rule(&id, true).ok_or(format!("{tag}: no rule after create"))?;
        let f1 = fields(&s1);
        if !same_rule(&input, &f1) {
            return Err(format!("{tag}: created {s1:?} from {raw:?}"));
        }
        match delete_by_instance_id(&id) {
            Ok(1) => {}
            other => return Err(format!("{tag}: delete: {other:?}")),
        }
        if wait_rule(&id, false).is_some() {
            return Err(format!("{tag}: rule still stored after delete"));
        }
        create_with_instance_id(&id, &f1).map_err(|e| format!("{tag}: re-create: {e}"))?;
        let s2 = wait_rule(&id, true).ok_or(format!("{tag}: no rule after re-create"))?;
        if !same_rule(&f1, &fields(&s2)) {
            return Err(format!("{tag}: re-created {s2:?}, stored before {s1:?}"));
        }
        eprintln!("{tag}: same_rule, raw_equal={}", s1 == s2);
        Ok(s1 == s2)
    }

    fn round_trip_all(cases: &[(&str, &str)]) {
        let failures: Vec<String> = cases
            .iter()
            .filter_map(|(tag, raw)| round_trip(tag, raw).err())
            .collect();
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    #[ignore = "rig VM only, elevated: creates and deletes firewall rules"]
    fn create_with_instance_id_round_trips_registry_string() {
        // The six rule shapes the M1B spike re-created exactly (vm/spikes/m1b/RESULT.json).
        round_trip_all(&[
            (
                "fw1-program",
                r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=C:\Program Files\PurgeTest\app1.exe|Name=PurgeTest F1 program|Defer=User|",
            ),
            (
                "fw2-port",
                "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=8080|LPort2_10=8090-8095|Name=PurgeTest F2 port|",
            ),
            (
                "fw3-remote",
                "v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|RPort=53|RA4=LocalSubnet|RA6=LocalSubnet|RA4=192.168.1.0/255.255.255.0|RA4=10.0.0.1|RA4=10.1.1.1-10.1.1.9|RA6=fe80::1|Name=PurgeTest F3 remote|",
            ),
            (
                "fw4-service",
                r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=9000|App=%SystemRoot%\System32\svchost.exe|Svc=PurgeTestS1|Name=PurgeTest F4 service|",
            ),
            (
                "fw5-iftype",
                r"v2.33|Action=Allow|Active=FALSE|Dir=In|Profile=Private|Profile=Public|IFType=Wireless|IFType=RemoteAccess|App=C:\Program Files\PurgeTest\app5.exe|Name=PurgeTest F5 iftype|",
            ),
            (
                "fw6-group",
                r"v2.33|Action=Allow|Active=TRUE|Dir=Out|App=C:\Program Files\PurgeTest\app6.exe|Name=PurgeTest F6 group|Desc=Purge test rule 6: a=b, c|EmbedCtxt=PurgeTest Group|",
            ),
        ]);
    }

    #[test]
    #[ignore = "rig VM only, elevated: creates and deletes firewall rules"]
    fn create_with_instance_id_round_trips_unproven_fields() {
        // Mappings map_rule has that the spike did not exercise.
        round_trip_all(&[
            (
                "icmp4",
                "v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=1|ICMP4=8:*|ICMP4=3:4|Name=PurgeTest icmp4|",
            ),
            (
                "icmp6",
                "v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=58|ICMP6=128:*|Name=PurgeTest icmp6|",
            ),
            (
                "edge",
                r"v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|App=C:\Program Files\PurgeTest\edge.exe|Name=PurgeTest edge|Edge=TRUE|",
            ),
            (
                "defer-app",
                r"v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|App=C:\Program Files\PurgeTest\defer.exe|Name=PurgeTest defer app|Edge=TRUE|Defer=App|",
            ),
            (
                "lsm-domain",
                r"v2.33|Action=Allow|Active=FALSE|Dir=In|Profile=Domain|Protocol=17|App=C:\Program Files\PurgeTest\lsm.exe|Name=PurgeTest lsm|LSM=TRUE|",
            ),
            (
                "local-address",
                "v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=7000|LA4=10.0.0.5|LA6=fe80::/64|Name=PurgeTest local address|",
            ),
            (
                "remote-range",
                "v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort2_10=8554-8558|Name=PurgeTest remote range|",
            ),
            (
                "lsm-out",
                r"v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|App=C:\Program Files\PurgeTest\lsmout.exe|Name=PurgeTest lsm out|LSM=TRUE|",
            ),
            (
                "lom",
                r"v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|App=C:\Program Files\PurgeTest\lom.exe|Name=PurgeTest lom|LOM=TRUE|",
            ),
            (
                "domain",
                r"v2.33|Action=Allow|Active=FALSE|Dir=In|Profile=Domain|App=C:\Program Files\PurgeTest\domain.exe|Name=PurgeTest domain|",
            ),
            (
                "iftype-lan",
                r"v2.33|Action=Allow|Active=FALSE|Dir=In|IFType=Lan|App=C:\Program Files\PurgeTest\lan.exe|Name=PurgeTest lan|",
            ),
            (
                "proto-47",
                "v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=47|Name=PurgeTest proto 47|",
            ),
        ]);
    }

    #[test]
    #[ignore = "rig VM only, elevated: creates and deletes firewall rules"]
    fn create_over_existing_id_is_object_exists_and_changes_nothing() {
        let id = unique_id("exists");
        let _clean = Cleanup(vec![id.clone()]);
        let stored = create(&id, DISABLED_RULE);
        let before = all_rules();
        let other = r"v2.33|Action=Block|Active=FALSE|Dir=Out|App=C:\Program Files\PurgeTest\other.exe|Name=PurgeTest other|";
        assert_eq!(
            create_with_instance_id(&id, &fields(other)),
            Err(WinError::ObjectExists)
        );
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(read_rule(&id).as_deref(), Some(stored.as_str()));
        assert_untouched(&before, &[]);
    }

    #[test]
    #[ignore = "rig VM only, elevated: creates and deletes firewall rules"]
    fn delete_by_case_variant_of_id_deletes_nothing() {
        let id = unique_id("case");
        let _clean = Cleanup(vec![id.clone()]);
        let stored = create(&id, DISABLED_RULE);
        let before = all_rules();
        let variant = id.to_ascii_uppercase();
        let r = delete_by_instance_id(&variant);
        assert!(
            matches!(r, Ok(0) | Err(WinError::IdMismatch { .. })),
            "{r:?}"
        );
        assert_eq!(read_rule(&id).as_deref(), Some(stored.as_str()));
        assert_untouched(&before, &[]);
    }

    #[test]
    #[ignore = "rig VM only, elevated: creates and deletes firewall rules"]
    fn delete_id_with_backslash_and_quote_matches_exactly() {
        // Shaped like the "TCP Query User{...}C:\path" ids Windows creates, plus a quote.
        let base = unique_id("path");
        let id = format!(r"{base}{{1}}C:\Users\O'Brien\app.exe");
        let near = format!(r"{base}{{1}}C:\Users\O'Brien\app.ex");
        let _clean = Cleanup(vec![id.clone(), near.clone()]);
        create(&id, DISABLED_RULE);
        let near_rule = create(&near, DISABLED_RULE);
        let before = all_rules();
        assert_eq!(delete_by_instance_id(&id), Ok(1));
        assert_eq!(wait_rule(&id, false), None);
        assert_eq!(read_rule(&near).as_deref(), Some(near_rule.as_str()));
        assert_untouched(&before, &[id.as_str()]);
    }
    /// One shape per rule, created natively by `New-NetFirewallRule` (as a vendor installer would), then
    /// deleted and re-created through `create_with_instance_id` from the stored string's fields. Prints one
    /// `SHAPE` line per case; passes only when every re-created string is byte-equal to the native one.
    #[test]
    #[ignore = "rig VM only, elevated: creates and deletes firewall rules (spawns New-NetFirewallRule)"]
    fn native_rules_recreate_byte_equal() {
        let app = r"C:\Program Files\PurgeTest\native.exe";
        let cases: Vec<(&str, String)> = vec![
            ("edge", format!("-Direction Inbound -Protocol UDP -Program '{app}' -EdgeTraversalPolicy Allow")),
            ("defer-app", format!("-Direction Inbound -Protocol UDP -Program '{app}' -EdgeTraversalPolicy DeferToApp")),
            ("lsm-out", format!("-Direction Outbound -Protocol UDP -Program '{app}' -LooseSourceMapping $true")),
            ("lom", format!("-Direction Inbound -Protocol UDP -Program '{app}' -LocalOnlyMapping $true")),
            ("icmp4", "-Direction Inbound -Protocol ICMPv4 -IcmpType 8,'3:4'".to_owned()),
            ("icmp6", "-Direction Inbound -Protocol ICMPv6 -IcmpType 128".to_owned()),
            ("local-address", "-Direction Inbound -Protocol TCP -LocalPort 7000 -LocalAddress 10.0.0.5,'fe80::/64'".to_owned()),
            ("domain", format!("-Direction Inbound -Profile Domain -Program '{app}'")),
            ("remote-range", "-Direction Outbound -Protocol TCP -RemotePort '8554-8558'".to_owned()),
            ("iftype-lan", format!("-Direction Inbound -InterfaceType Wired -Program '{app}'")),
            ("proto-47", "-Direction Inbound -Protocol 47".to_owned()),
        ];
        let mut failures = Vec::new();
        for (tag, params) in &cases {
            let id = unique_id(&format!("native-{tag}"));
            let _clean = Cleanup(vec![id.clone()]);
            let cmd = format!(
                "$ErrorActionPreference='Stop'; New-NetFirewallRule -Name '{id}' -DisplayName 'PurgeTest native {tag}' -Enabled False -Action Allow {params} | Out-Null"
            );
            let out = std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", &cmd])
                .output()
                .expect("spawn powershell");
            if !out.status.success() {
                let e = format!(
                    "{tag}: New-NetFirewallRule failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
                eprintln!("SHAPE {e}");
                failures.push(e);
                continue;
            }
            let Some(s0) = wait_rule(&id, true) else {
                failures.push(format!("{tag}: no stored rule after New-NetFirewallRule"));
                continue;
            };
            let f0 = fields(&s0);
            let shapes = match map_rule(&f0) {
                Ok(m) => m
                    .shapes
                    .iter()
                    .map(|s| s.name())
                    .collect::<Vec<_>>()
                    .join(","),
                Err(why) => {
                    let e = format!("{tag}: map_rule refused {s0:?}: {why:?}");
                    eprintln!("SHAPE {e}");
                    failures.push(e);
                    continue;
                }
            };
            match delete_by_instance_id(&id) {
                Ok(1) => {}
                other => {
                    failures.push(format!("{tag}: delete: {other:?}"));
                    continue;
                }
            }
            if wait_rule(&id, false).is_some() {
                failures.push(format!("{tag}: still stored after delete"));
                continue;
            }
            let s1 = match create_with_instance_id(&id, &f0) {
                Ok(()) => wait_rule(&id, true),
                Err(e) => {
                    let e = format!("{tag}: re-create: {e}");
                    eprintln!("SHAPE {e} (native {s0:?})");
                    failures.push(e);
                    continue;
                }
            };
            let s1 = s1.unwrap_or_default();
            let same = same_rule(&f0, &fields(&s1));
            eprintln!(
                "SHAPE {tag}: shapes=[{shapes}] exact={} same_rule={same}\n  native   {s0}\n  recreate {s1}",
                s0 == s1
            );
            if s0 != s1 {
                failures.push(format!("{tag}: native {s0:?} re-created {s1:?}"));
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }
}
