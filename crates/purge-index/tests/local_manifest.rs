//! BL-MANIFEST: component manifests to local baseline records (docs/BASELINE_LOCAL_DESIGN.md §3.2).
//!
//! The fixtures in `tests/fixtures/manifests` are hand-written in the shape of WinSxS component
//! manifests; no Microsoft manifest is committed.

use std::path::{Path, PathBuf};

use purge_index::baseline::{Baseline, PathKind};
use purge_index::local_baseline::Records;
use purge_index::local_baseline::macros::{MACROS, View};
use purge_index::local_baseline::manifest::{self, HKCU_SID, ManifestError, ManifestStats};

const CLSID: &str = "{0D7A1F64-3C2B-4E5A-9F10-0000000000A1}";
const CLSID32: &str = "{0D7A1F64-3C2B-4E5A-9F10-0000000000B2}";

const FIXTURES: [&str; 9] = [
    "clsid",
    "asm-prefix",
    "hkcu",
    "wow64",
    "key-macros",
    "paths",
    "paths-wow64",
    "no-registry",
    "malformed",
];

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/manifests")
        .join(format!("{name}.manifest"))
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn parse(name: &str) -> (Records, ManifestStats) {
    let mut r = Records::new();
    let stats = manifest::parse(&fixture(name), &mut r).unwrap_or_else(|e| panic!("{name}: {e}"));
    (r, stats)
}

/// Every fixture but the malformed one, parsed into one set of records.
fn all_records() -> Records {
    let mut r = Records::new();
    for name in FIXTURES.iter().filter(|n| **n != "malformed") {
        manifest::parse(&fixture(name), &mut r).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    r
}

/// The records behind a baseline header, loaded through the shipped loader and its normaliser.
fn load(records: &Records) -> Baseline {
    let mut text = b"#purge-baseline 1\t2026-11-21T00:00:00Z\tTEST-PC\tLocalTest\t1.2\n".to_vec();
    records.write_records(&mut text).unwrap();
    Baseline::from_bytes(&text).expect("the records load")
}

// ---------------------------------------------------------------------------------------------------
// Fixtures

#[test]
fn hkcr_clsid_with_subkeys() {
    let (r, s) = parse("clsid");
    assert_eq!(s.architecture.as_deref(), Some("amd64"));
    assert_eq!(s.public_key_token.as_deref(), Some("31bf3856ad364e35"));
    assert_eq!(s.view, View::Native);
    assert_eq!((s.registry_keys, s.registry_values), (5, 7));
    assert_eq!(s.skipped.total(), 0);
    let clsid = format!(r"HKLM\SOFTWARE\Classes\CLSID\{CLSID}");
    for key in [
        r"HKLM\SOFTWARE".to_owned(),
        r"HKLM\SOFTWARE\Classes".to_owned(),
        r"HKLM\SOFTWARE\Classes\CLSID".to_owned(),
        clsid.clone(),
        format!(r"{clsid}\InProcServer32"),
        format!(r"{clsid}\ShellFolder"),
        r"HKLM\SOFTWARE\Classes\PurgeTest.Object.1".to_owned(),
        r"HKLM\SOFTWARE\Classes\PurgeTest.Object.1\CLSID".to_owned(),
        r"HKLM\SOFTWARE\Classes\.purgetest\OpenWithProgids".to_owned(),
    ] {
        assert!(r.contains_key(&key), "{key}");
    }
    assert_eq!(r.counts().keys, 10);
    assert!(r.contains_value(&clsid, ""));
    assert!(r.contains_value(&clsid, "LocalizedString"));
    assert!(r.contains_value(&format!(r"{clsid}\InProcServer32"), "ThreadingModel"));
    assert!(r.contains_value(
        r"HKLM\SOFTWARE\Classes\.purgetest\OpenWithProgids",
        "PurgeTest.Object.1"
    ));
    let types: Vec<u32> = r.values().map(|v| v.ty()).collect();
    assert!(types.contains(&4) && types.contains(&2) && types.contains(&0));
    // The file goes to System32; the dependency's x86 identity does not make this a 32-bit manifest.
    assert!(r.contains_file(r"C:\Windows\System32\purgetest.dll"));
    assert!(r.contains_dir(r"C:\Windows\System32"));
    assert!(!r.keys().any(|k| k.contains("wow6432node")));
}

#[test]
fn asm_prefixed_elements() {
    let (r, s) = parse("asm-prefix");
    assert_eq!(s.architecture.as_deref(), Some("amd64"));
    assert_eq!(
        (s.registry_keys, s.registry_values, s.directories),
        (2, 3, 1)
    );
    let key = r"HKLM\SOFTWARE\Microsoft\PurgeTest\Prefixed";
    assert!(r.contains_key(key));
    assert!(r.contains_value(key, "Enabled"));
    assert!(
        r.contains_value(key, "Mode"),
        "a prefixed attribute is matched by its local name"
    );
    assert!(r.contains_value(r"HKLM\SOFTWARE\Microsoft\PurgeTest\Unprefixed", "Level"));
    assert!(r.contains_dir(r"C:\ProgramData\Microsoft\PurgeTest"));
    assert_eq!(s.unknown_value_types, 0);
}

#[test]
fn hkey_current_user_is_recorded_both_ways() {
    let (r, s) = parse("hkcu");
    assert_eq!(s.skipped.total(), 0);
    for user in [format!(r"HKU\{HKCU_SID}"), r"HKU\.DEFAULT".to_owned()] {
        let key = format!(r"{user}\Software\Microsoft\PurgeTest\Settings");
        assert!(r.contains_key(&key), "{key}");
        assert!(r.contains_value(&key, "Theme"), "{key}");
        assert!(r.contains_key(&format!(r"{user}\Software\Classes\.purgeuser")));
        assert!(r.contains_key(&user), "the hive root of {user}");
    }
    assert!(r.contains_value(r"HKU\.DEFAULT\Control Panel\PurgeTest", "Delay"));
    assert!(!r.contains_key(&format!(r"HKU\{HKCU_SID}\Control Panel\PurgeTest")));
}

#[test]
fn wow64_manifest_records_both_views() {
    let (r, s) = parse("wow64");
    assert_eq!(s.view, View::Wow64);
    for clsid in [
        format!(r"HKLM\SOFTWARE\Classes\CLSID\{CLSID32}"),
        format!(r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{CLSID32}"),
    ] {
        assert!(r.contains_key(&clsid), "{clsid}");
        assert!(r.contains_value(&clsid, ""), "{clsid}");
        assert!(
            r.contains_value(&format!(r"{clsid}\InProcServer32"), ""),
            "{clsid}"
        );
    }
    assert!(r.contains_value(r"HKLM\SOFTWARE\Microsoft\PurgeTest32", "Version"));
    assert!(r.contains_value(
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\PurgeTest32",
        "Version"
    ));
    // Already in the 32-bit view: not doubled again; outside HKLM\SOFTWARE: not doubled at all.
    assert!(r.contains_key(r"HKLM\SOFTWARE\Wow6432Node\PurgeVendor32"));
    assert!(!r.keys().any(|k| k.contains(r"wow6432node\wow6432node")));
    assert!(r.contains_key(r"HKLM\SYSTEM\CurrentControlSet\Services\PurgeTest32"));
    assert!(
        !r.keys()
            .any(|k| k.starts_with(r"hklm\system") && k.contains("wow6432node"))
    );
    // 32-bit destinations.
    assert!(r.contains_file(r"C:\Windows\SysWOW64\purgetest32.dll"));
    assert!(!r.contains_file(r"C:\Windows\System32\purgetest32.dll"));
    assert!(r.contains_dir(r"C:\Program Files (x86)\PurgeTest"));
    assert!(!r.contains_dir(r"C:\Program Files\PurgeTest"));
}

#[test]
fn key_names_with_known_and_unknown_macros() {
    let (r, s) = parse("key-macros");
    let shared = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDlls";
    assert!(r.contains_value(shared, r"C:\Windows\System32\purgeshared.dll"));
    assert_eq!(
        r.values()
            .filter(|v| v.key() == shared.to_lowercase())
            .count(),
        1
    );
    // A known macro in a key name is expanded where it stands.
    let known = r"HKLM\SOFTWARE\Microsoft\PurgeTest\Known\C:\ProgramData\Sub";
    assert!(r.contains_key(known));
    assert!(r.contains_value(known, "Kept"));
    // An unknown or unclosed one skips the key and its values, and is counted and named.
    assert!(
        !r.keys()
            .any(|k| k.contains("unknown") || k.contains("unclosed") || k.contains("$("))
    );
    assert!(
        !r.values()
            .any(|v| v.name() == "dropped" || v.name().contains("$("))
    );
    assert_eq!(s.skipped.key_unknown_macro, 2);
    assert_eq!(s.skipped.value_unknown_macro, 1);
    assert_eq!(s.skipped.values_of_skipped_keys, 1);
    assert_eq!(s.unknown_macros.get("build.arch"), Some(&1));
    assert_eq!(s.unknown_macros.get("runtime.nope"), Some(&1));
    assert_eq!(s.unknown_macros.get(r"runtime.system32\Unclosed"), Some(&1));
}

/// The expected expansion of each macro, in the order of [`MACROS`], native and 32-bit.
fn expected_roots(view: View) -> Vec<Vec<&'static str>> {
    let wow = view == View::Wow64;
    MACROS
        .iter()
        .map(|m| match *m {
            "runtime.windows" | "runtime.systemRoot" => vec![r"C:\Windows"],
            "runtime.system32" if wow => vec![r"C:\Windows\SysWOW64"],
            "runtime.system32" => vec![r"C:\Windows\System32"],
            "runtime.drivers" => vec![r"C:\Windows\System32\drivers"],
            "runtime.fonts" => vec![r"C:\Windows\Fonts"],
            "runtime.inf" => vec![r"C:\Windows\INF"],
            "runtime.wbem" if wow => vec![r"C:\Windows\SysWOW64\wbem"],
            "runtime.wbem" => vec![r"C:\Windows\System32\wbem"],
            "runtime.programFiles" if wow => vec![r"C:\Program Files (x86)"],
            "runtime.programFiles" => vec![r"C:\Program Files"],
            "runtime.programFilesX86" => vec![r"C:\Program Files (x86)"],
            "runtime.commonFiles" if wow => vec![r"C:\Program Files (x86)\Common Files"],
            "runtime.commonFiles" => vec![r"C:\Program Files\Common Files"],
            "runtime.commonFilesX86" => vec![r"C:\Program Files (x86)\Common Files"],
            "runtime.programData" => vec![r"C:\ProgramData"],
            "runtime.bootDrive" => vec!["C:"],
            "runtime.help" => vec![r"C:\Windows\Help"],
            "runtime.userProfile" => vec![r"C:\Users\Default", r"C:\Users\<user>"],
            "runtime.public" => vec![r"C:\Users\Public"],
            "runtime.startMenu" => vec![r"C:\ProgramData\Microsoft\Windows\Start Menu"],
            "runtime.documentsSettings" => vec![r"C:\Users"],
            other => panic!("no expectation for {other}"),
        })
        .collect()
}

fn check_paths(name: &str, view: View) {
    let (r, s) = parse(name);
    assert_eq!(s.view, view);
    assert_eq!(s.files, MACROS.len() as u64 + 3);
    assert_eq!(s.directories, MACROS.len() as u64 + 1);
    assert_eq!(s.files_without_destination, 1);
    assert_eq!(s.skipped.path_unknown_macro, 1);
    assert_eq!(
        s.skipped.not_absolute, 2,
        "a relative path and a `..` segment"
    );
    assert_eq!(s.unknown_macros.get("runtime.nope"), Some(&1));
    for (m, roots) in MACROS.iter().zip(expected_roots(view)) {
        for root in roots {
            let file = format!(r"{root}\PurgeTestFile\purgetest.txt");
            let dir = format!(r"{root}\PurgeTestDir");
            assert!(r.contains_file(&file), "{m}: {file}");
            assert!(
                r.contains_dir(&format!(r"{root}\PurgeTestFile")),
                "{m}: {file}"
            );
            assert!(r.contains_dir(&dir), "{m}: {dir}");
        }
    }
    assert!(
        !r.files()
            .chain(r.dirs())
            .any(|p| p.contains("$(") || p.contains(".."))
    );
    // Every directory above a recorded path is recorded too.
    assert!(r.contains_dir(r"C:\ProgramData\Microsoft\Windows"));
    // A file directly below the drive (bootDrive) has no directory to record but itself.
    assert!(r.contains_file(r"C:\PurgeTestFile\purgetest.txt"));
}

#[test]
fn file_and_directory_destinations_for_every_macro() {
    check_paths("paths", View::Native);
    check_paths("paths-wow64", View::Wow64);
}

#[test]
fn manifest_without_registry_keys() {
    let (r, s) = parse("no-registry");
    assert_eq!(s.registry_keys, 0);
    assert_eq!(r.counts().keys, 0);
    assert_eq!(r.counts().values, 0);
    assert_eq!(
        s.view,
        View::Native,
        "the dependency's wow64 identity is not this manifest's"
    );
    assert!(r.contains_file(r"C:\Windows\System32\purgeonly.exe"));
    assert_eq!(s.files_without_destination, 1);
    assert_eq!(r.counts().files, 1);
}

#[test]
fn malformed_xml_adds_nothing() {
    let before = all_records();
    let mut r = before.clone();
    let err = manifest::parse(&fixture("malformed"), &mut r).unwrap_err();
    assert!(matches!(err, ManifestError::Xml { .. }), "{err:?}");
    assert_eq!(r, before);
    assert!(!r.contains_key(r"HKLM\SOFTWARE\Microsoft\PurgeTest\Broken"));
    assert!(!r.contains_file(r"C:\Windows\System32\purgebroken.dll"));
    // Truncated at any point, a good manifest is an error and adds nothing either.
    let good = fixture("clsid");
    for cut in (0..good.len() - 1).step_by(7) {
        let mut r = Records::new();
        assert!(
            manifest::parse(&good[..cut], &mut r).is_err(),
            "cut at {cut}"
        );
        assert!(r.is_empty(), "cut at {cut}");
    }
}

// ---------------------------------------------------------------------------------------------------
// Properties

/// A small deterministic generator (xorshift64*), so the property tests need no new dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

const ROOTS: [&str; 10] = [
    r"HKEY_LOCAL_MACHINE\SOFTWARE",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Classes",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node",
    r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",
    r"HKEY_CLASSES_ROOT",
    r"HKEY_CLASSES_ROOT\Wow6432Node",
    r"HKEY_CURRENT_USER\Software",
    r"HKEY_USERS\.DEFAULT",
    r"HKCR",
    r"HKEY_CURRENT_CONFIG",
];
const SEGMENTS: [&str; 12] = [
    "CLSID",
    "{0D7A1F64-3C2B-4E5A-9F10-0000000000C3}",
    "Microsoft",
    "Classes",
    "WOW6432Node",
    "shell",
    "open",
    "",
    "Ünïcode",
    "$(runtime.system32)",
    "$(runtime.unknownMacro)",
    "a&amp;b",
];
const PATH_HEADS: [&str; 6] = [
    "$(runtime.system32)",
    "$(runtime.programFiles)",
    "$(runtime.userProfile)",
    "$(runtime.bootDrive)",
    "$(runtime.unknownMacro)",
    r"C:\Windows",
];

fn random_manifest(rng: &mut Rng) -> String {
    let arch = rng.pick(&["amd64", "wow64", "x86", "msil", "arm64"]);
    let mut body = String::new();
    for _ in 0..rng.below(12) {
        let mut key = rng.pick(&ROOTS).to_owned();
        for _ in 0..rng.below(5) {
            key.push('\\');
            key.push_str(rng.pick(&SEGMENTS));
        }
        if rng.below(3) == 0 {
            key.push('\\');
        }
        body.push_str(&format!(r#"<registryKey keyName="{key}">"#));
        for _ in 0..rng.below(4) {
            let name = rng.pick(&["", "Name", "$(runtime.windows)\\x.dll", "$(runtime.nope)"]);
            let ty = rng.pick(&["REG_SZ", "REG_DWORD", "REG_BINARY", "REG_ODD"]);
            body.push_str(&format!(
                r#"<registryValue name="{name}" valueType="{ty}" value="1"/>"#
            ));
        }
        body.push_str("</registryKey>");
    }
    for _ in 0..rng.below(4) {
        let head = rng.pick(&PATH_HEADS);
        let tail = rng.pick(&["", r"PurgeTest", r"PurgeTest\Sub\Deep", r"..\x"]);
        if rng.below(2) == 0 {
            body.push_str(&format!(r#"<directory destinationPath="{head}\{tail}"/>"#));
        } else {
            body.push_str(&format!(
                r#"<file name="f{}.dll" destinationPath="{head}\{tail}\"/>"#,
                rng.below(5)
            ));
        }
    }
    format!(
        r#"<?xml version="1.0"?><assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="R" processorArchitecture="{arch}" publicKeyToken="31bf3856ad364e35"/><registryKeys>{body}</registryKeys></assembly>"#
    )
}

fn segments(text: &str) -> usize {
    text.split('\\').count()
}

fn parent(text: &str) -> &str {
    text.rsplit_once('\\').map_or(text, |(head, _)| head)
}

/// Every recorded key's and directory's parent is recorded (down to the first segment below the
/// root or drive), so is every file's directory and every value's key.
fn assert_closed(r: &Records) {
    for key in r.keys() {
        assert!(segments(key) >= 2, "{key}");
        if segments(key) > 2 {
            assert!(r.contains_key(parent(key)), "parent of {key}");
        }
    }
    for dir in r.dirs() {
        if segments(dir) > 2 {
            assert!(r.contains_dir(parent(dir)), "parent of {dir}");
        }
    }
    for file in r.files() {
        if segments(file) > 2 {
            assert!(r.contains_dir(parent(file)), "directory of {file}");
        }
    }
    for value in r.values() {
        assert!(r.contains_key(value.key()), "key of {value:?}");
    }
}

fn assert_superset(big: &Records, small: &Records) {
    for key in small.keys() {
        assert!(big.contains_key(key), "{key}");
    }
    for value in small.values() {
        assert!(big.values().any(|v| v == value), "{value:?}");
    }
    for dir in small.dirs() {
        assert!(big.contains_dir(dir), "{dir}");
    }
    for file in small.files() {
        assert!(big.contains_file(file), "{file}");
    }
}

#[test]
fn property_every_parent_is_recorded() {
    let all = all_records();
    assert_closed(&all);
    let mut rng = Rng(0x5eed_0000_b1a5_e001);
    for _ in 0..400 {
        let xml = random_manifest(&mut rng);
        let mut r = Records::new();
        manifest::parse(xml.as_bytes(), &mut r).unwrap_or_else(|e| panic!("{e}: {xml}"));
        assert_closed(&r);
        assert!(!r.keys().any(|k| k.contains("$(")), "{xml}");
    }
}

#[test]
fn property_adding_a_manifest_only_adds() {
    let mut rng = Rng(0x5eed_0000_b1a5_e002);
    for _ in 0..300 {
        let (a, b) = (random_manifest(&mut rng), random_manifest(&mut rng));
        let mut first = Records::new();
        manifest::parse(a.as_bytes(), &mut first).unwrap();
        let mut both = first.clone();
        manifest::parse(b.as_bytes(), &mut both).unwrap();
        assert_superset(&both, &first);
        let mut second = Records::new();
        manifest::parse(b.as_bytes(), &mut second).unwrap();
        assert_superset(&both, &second);
        // The union does not depend on the order the manifests are read in.
        let mut other_order = second.clone();
        manifest::parse(a.as_bytes(), &mut other_order).unwrap();
        assert_eq!(both, other_order);
        // Merging per-manifest records gives the same union.
        let mut merged = first.clone();
        merged.merge(second);
        assert_eq!(merged, both);
    }
    // The real-shaped fixtures, added one by one.
    let mut acc = Records::new();
    for name in FIXTURES.iter().filter(|n| **n != "malformed") {
        let before = acc.clone();
        manifest::parse(&fixture(name), &mut acc).unwrap();
        assert_superset(&acc, &before);
    }
}

/// Mutated fixtures never panic, and a mutation that is refused adds nothing.
#[test]
fn property_hostile_input_never_panics() {
    let mut rng = Rng(0x5eed_0000_b1a5_e003);
    let base = all_records();
    let inputs: Vec<Vec<u8>> = FIXTURES.iter().map(|n| fixture(n)).collect();
    const INSERTS: [&[u8]; 10] = [
        b"<",
        b">",
        b"\"",
        b"&",
        b"&#0;",
        b"$(",
        b"<registryKey keyName=\"HKCU\">",
        b"</registryKey>",
        b"\xff\xfe",
        b"<!DOCTYPE a [<!ENTITY e \"&e;&e;\">]>",
    ];
    let (mut accepted, mut refused) = (0, 0);
    for round in 0..3000 {
        let mut bytes = inputs[rng.below(inputs.len())].clone();
        for _ in 0..1 + rng.below(4) {
            let at = rng.below(bytes.len() + 1);
            match rng.below(4) {
                0 => bytes.truncate(at),
                1 if at < bytes.len() => bytes[at] = rng.next() as u8,
                2 => {
                    let insert = INSERTS[rng.below(INSERTS.len())];
                    bytes.splice(at..at, insert.iter().copied());
                }
                _ => {
                    let end = (at + rng.below(64)).min(bytes.len());
                    bytes.drain(at..end);
                }
            }
        }
        let mut r = base.clone();
        match manifest::parse(&bytes, &mut r) {
            Ok(_) => {
                accepted += 1;
                assert_superset(&r, &base);
            }
            Err(_) => {
                refused += 1;
                assert_eq!(r, base, "round {round}");
            }
        }
    }
    assert!(
        accepted > 100 && refused > 100,
        "{accepted} accepted, {refused} refused"
    );
}

// ---------------------------------------------------------------------------------------------------
// Round trip through the shipped loader

#[test]
fn round_trip_through_the_baseline_loader() {
    let records = all_records();
    let b = load(&records);
    assert_eq!(b.counts(), records.counts());

    // HKCR, the machine classes, and the 32-bit view of a native CLSID (shared twin rule).
    for key in [
        format!(r"HKCR\CLSID\{CLSID}"),
        format!(r"HKEY_CLASSES_ROOT\CLSID\{CLSID}\InProcServer32"),
        format!(r"HKLM\SOFTWARE\Classes\CLSID\{CLSID}\ShellFolder"),
        format!(r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{CLSID}"),
        r"HKCR\.purgetest\OpenWithProgids".to_owned(),
    ] {
        assert!(b.has_key(&key), "{key}");
    }
    assert!(b.has_value(
        &format!(r"HKCR\CLSID\{CLSID}\InProcServer32"),
        "ThreadingModel"
    ));
    assert!(b.has_value(r"HKCR\.purgetest\OpenWithProgids", "PurgeTest.Object.1"));

    // The WOW6432Node link and the recorded 32-bit twin of a wow64 manifest.
    for key in [
        format!(r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{CLSID32}"),
        format!(r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{CLSID32}\InProcServer32"),
        format!(r"HKCR\WOW6432Node\CLSID\{CLSID32}"),
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\PurgeTest32".to_owned(),
    ] {
        assert!(b.has_key(&key), "{key}");
        assert!(b.has_key_exact_view(&key), "{key}");
    }
    assert!(b.has_value(
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\PurgeTest32",
        "Version"
    ));
    assert!(b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node\PurgeVendor32"));
    assert!(!b.has_key(r"HKLM\SOFTWARE\PurgeVendor32"));

    // HKCU: the baseline user stands for any user, the classes link is folded, LocalSystem's hive has
    // two names.
    let sid = "S-1-5-21-1004336348-1177238915-682003330-1001";
    for key in [
        r"HKCU\Software\Microsoft\PurgeTest\Settings".to_owned(),
        r"HKEY_CURRENT_USER\Software\Microsoft\PurgeTest".to_owned(),
        format!(r"HKU\{sid}\Software\Microsoft\PurgeTest\Settings"),
        format!(r"HKU\{sid}_Classes\.purgeuser"),
        format!(r"HKU\{sid}\Software\Classes\.purgeuser"),
        r"HKCR\.purgeuser".to_owned(),
        r"HKU\.DEFAULT\Software\Microsoft\PurgeTest\Settings".to_owned(),
        r"HKU\S-1-5-18\Software\Microsoft\PurgeTest\Settings".to_owned(),
        r"HKU\S-1-5-18\Control Panel\PurgeTest".to_owned(),
    ] {
        assert!(b.has_key(&key), "{key}");
    }
    assert!(b.has_value(r"HKCU\Software\Microsoft\PurgeTest\Settings", "Theme"));
    assert!(!b.has_key(&format!(r"HKU\{sid}\Control Panel\PurgeTest")));

    // Control sets, values with expanded names.
    assert!(b.has_key(r"HKLM\SYSTEM\ControlSet001\Services\PurgeTest32"));
    assert!(b.has_value(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDlls",
        r"c:\windows\system32\purgeshared.dll"
    ));
    let v = b
        .value(
            r"HKLM\SYSTEM\CurrentControlSet\Services\PurgeTest32",
            "Start",
        )
        .unwrap();
    assert_eq!((v.ty, v.data_hash), (4, 0));

    // Paths, the profile placeholder, tokens and segments.
    assert_eq!(
        b.path_kind(r"C:\Windows\System32\purgetest.dll"),
        Some(PathKind::File)
    );
    assert_eq!(b.path_kind(r"C:\Windows\System32"), Some(PathKind::Dir));
    assert!(b.has_path(r"C:\Windows\SysWOW64\purgetest32.dll"));
    assert!(b.has_path(r"C:\Users\Default\PurgeTestDir"));
    assert!(b.has_path(r"C:\Users\someone\PurgeTestFile\purgetest.txt"));
    assert!(b.has_token("0D7A1F64-3C2B-4E5A-9F10-0000000000A1"));
    assert!(b.has_segment("PurgeTest.Object.1"));

    // Nothing that no fixture names.
    assert!(!b.has_key(r"HKCR\CLSID\{0D7A1F64-3C2B-4E5A-9F10-0000000000FF}"));
    assert!(!b.has_key(r"HKLM\SOFTWARE\Microsoft\PurgeTest\Broken"));
    assert!(!b.has_path(r"C:\Windows\System32\purgestore.dll"));
}
