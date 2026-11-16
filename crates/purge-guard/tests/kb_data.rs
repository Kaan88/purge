//! Tests of the guard knowledge-base data files (M1B-KB): `kb/shared-iids.json`, `kb/shared-components.json`
//! and `kb/hosts.json`.
//!
//! The snap test reads the dirty-base rig snap (`vm/runs/dirty-base/snap-dirty-base-0.tsv.gz`, format in
//! vm/RIG.md §2). The snap is not in git: the test looks at `PURGE_DIRTY_BASE_SNAP`, then at the default path
//! below the workspace, and skips with a printed reason when neither exists.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;
use std::path::PathBuf;
use std::sync::OnceLock;

use purge_guard::canon::GuardEnv;
use purge_guard::deny::{SharedComponent, SharedComponents, shared_components};
use purge_model::Target;
use serde::Deserialize;

const SHARED_IIDS: &str = include_str!("../../../kb/shared-iids.json");
const HOSTS: &str = include_str!("../../../kb/hosts.json");
const KB_README: &str = include_str!("../../../kb/README.md");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedIids {
    iids: Vec<SharedIid>,
    shared_proxy_clsids: Vec<ProxyClsid>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedIid {
    iid: String,
    name: String,
    why: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyClsid {
    clsid: String,
    name: String,
    why: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hosts {
    interpreters: Vec<String>,
}

fn shared_iids() -> SharedIids {
    serde_json::from_str(SHARED_IIDS).expect("kb/shared-iids.json parses")
}

/// The Gecko interfaces M1B-KB requires, with the IIDs the design names.
const GECKO: [(&str, &str); 3] = [
    ("{1814CEEB-49E2-407F-AF99-FA755A7D2607}", "ISimpleDOMNode"),
    (
        "{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}",
        "ISimpleDOMDocument",
    ),
    ("{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}", "ISimpleDOMText"),
];

/// The IAccessible2 interfaces M1B-KB requires, by name.
const IA2: [&str; 19] = [
    "IAccessible2",
    "IAccessible2_2",
    "IAccessible2_3",
    "IAccessibleAction",
    "IAccessibleApplication",
    "IAccessibleComponent",
    "IAccessibleEditableText",
    "IAccessibleHyperlink",
    "IAccessibleHypertext",
    "IAccessibleHypertext2",
    "IAccessibleImage",
    "IAccessibleRelation",
    "IAccessibleTable",
    "IAccessibleTable2",
    "IAccessibleTableCell",
    "IAccessibleText",
    "IAccessibleText2",
    "IAccessibleValue",
    "IAccessibleDocument",
];

/// Required interfaces that no rig capture registers, so they have no snap-checked IID yet. Each is listed
/// under "Gaps" in kb/README.md with the capture that fills it; remove it here when it is filled.
const IA2_GAPS: [&str; 2] = ["IAccessible2_3", "IAccessibleDocument"];

/// The proxy CLSIDs M1B-KB requires.
const PROXIES: [&str; 6] = [
    "{00020424-0000-0000-C000-000000000046}",
    "{00020420-0000-0000-C000-000000000046}",
    "{00020421-0000-0000-C000-000000000046}",
    "{00020422-0000-0000-C000-000000000046}",
    "{00020423-0000-0000-C000-000000000046}",
    "{00020425-0000-0000-C000-000000000046}",
];

/// The interpreters and hosts of C-SYSOBJ `resolve_program` (docs/M1B_DESIGN.json).
const INTERPRETERS: [&str; 16] = [
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "svchost.exe",
    "dllhost.exe",
    "conhost.exe",
    "java.exe",
    "javaw.exe",
    "python.exe",
    "pythonw.exe",
    "node.exe",
];

/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` in upper case.
fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && b[1..37].iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'A'..=b'F').contains(c),
        })
}

#[test]
fn guid_check_cases() {
    assert!(is_guid("{1814CEEB-49E2-407F-AF99-FA755A7D2607}"));
    for bad in [
        "1814CEEB-49E2-407F-AF99-FA755A7D2607",
        "{1814ceeb-49E2-407F-AF99-FA755A7D2607}",
        "{1814CEEB-49E2-407F-AF99-FA755A7D260}",
        "{1814CEEB-49E2-407F-AF99-FA755A7D26077}",
        "{1814CEEB_49E2-407F-AF99-FA755A7D2607}",
        "{1814CEEG-49E2-407F-AF99-FA755A7D2607}",
        "(1814CEEB-49E2-407F-AF99-FA755A7D2607)",
    ] {
        assert!(!is_guid(bad), "{bad}");
    }
}

#[test]
fn shared_iids_parse_and_are_valid_guids_no_duplicates() {
    let data = shared_iids();
    assert!(!data.iids.is_empty());

    let mut seen = BTreeSet::new();
    for entry in &data.iids {
        assert!(is_guid(&entry.iid), "not an upper-case GUID: {}", entry.iid);
        assert!(
            seen.insert(entry.iid.to_ascii_uppercase()),
            "duplicate {}",
            entry.iid
        );
        assert!(!entry.name.trim().is_empty(), "{} has no name", entry.iid);
        assert!(!entry.why.trim().is_empty(), "{} has no why", entry.iid);
    }
    let by_iid: BTreeMap<&str, &str> = data
        .iids
        .iter()
        .map(|e| (e.iid.as_str(), e.name.as_str()))
        .collect();
    for (iid, name) in GECKO {
        assert_eq!(by_iid.get(iid), Some(&name), "{name} {iid} is listed");
    }
    let names: BTreeSet<&str> = data.iids.iter().map(|e| e.name.as_str()).collect();
    let gaps_section = KB_README
        .split_once("### Gaps")
        .map(|(_, rest)| rest)
        .expect("kb/README.md has a Gaps section");
    for name in IA2 {
        if IA2_GAPS.contains(&name) {
            assert!(
                !names.contains(name),
                "{name} is listed now: remove it from IA2_GAPS and from the kb/README.md gaps"
            );
            assert!(
                gaps_section.contains(name),
                "{name} is a gap but the kb/README.md Gaps section does not name it"
            );
        } else {
            assert!(names.contains(name), "{name} is listed");
        }
    }

    let mut seen = BTreeSet::new();
    for entry in &data.shared_proxy_clsids {
        assert!(
            is_guid(&entry.clsid),
            "not an upper-case GUID: {}",
            entry.clsid
        );
        assert!(
            seen.insert(entry.clsid.to_ascii_uppercase()),
            "duplicate {}",
            entry.clsid
        );
        assert!(!entry.name.trim().is_empty(), "{} has no name", entry.clsid);
        assert!(!entry.why.trim().is_empty(), "{} has no why", entry.clsid);
    }
    for clsid in PROXIES {
        assert!(seen.contains(clsid), "{clsid} is a shared proxy CLSID");
    }
}

// ---------------------------------------------------------------------------------------------------
// The dirty-base rig snap.

/// Default values of `Interface\{IID}` and `CLSID\{CLSID}` keys in any Classes view of the snap.
#[derive(Debug, Default)]
struct SnapNames {
    /// Upper-case IID -> every name registered for it.
    interfaces: BTreeMap<String, BTreeSet<String>>,
    /// Upper-case CLSID -> every name registered for it.
    classes: BTreeMap<String, BTreeSet<String>>,
}

fn snap_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PURGE_DIRTY_BASE_SNAP") {
        return Some(PathBuf::from(path));
    }
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vm/runs/dirty-base/snap-dirty-base-0.tsv.gz");
    path.exists().then_some(path)
}

/// Undoes the snap's text escapes (`\\`, `\t`, `\n`, `\r`, `\0`).
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// The `{GUID}` of `<classes view>\<kind>\{GUID}`, where the classes view is `HKLM\SOFTWARE\Classes` or a
/// user's `_Classes` hive, either with `\WOW6432Node`.
fn classes_child(key: &str, kind: &str) -> Option<String> {
    let segs: Vec<&str> = key.split('\\').collect();
    let (guid, rest) = segs.split_last()?;
    let (kind_seg, view) = rest.split_last()?;
    if !kind_seg.eq_ignore_ascii_case(kind) {
        return None;
    }
    let view = match view.split_last() {
        Some((last, base)) if last.eq_ignore_ascii_case("WOW6432Node") => base,
        _ => view,
    };
    let is_classes = match view {
        [hklm, software, classes] => {
            hklm.eq_ignore_ascii_case("HKLM")
                && software.eq_ignore_ascii_case("SOFTWARE")
                && classes.eq_ignore_ascii_case("Classes")
        }
        [hku, hive] => {
            hku.eq_ignore_ascii_case("HKU") && hive.to_ascii_lowercase().ends_with("_classes")
        }
        _ => false,
    };
    (is_classes && guid.starts_with('{') && guid.ends_with('}')).then(|| guid.to_ascii_uppercase())
}

fn read_snap(path: &PathBuf) -> SnapNames {
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let reader: Box<dyn BufRead> = if path.extension().is_some_and(|x| x == "gz") {
        Box::new(std::io::BufReader::new(flate2::read::GzDecoder::new(file)))
    } else {
        Box::new(std::io::BufReader::new(file))
    };
    let mut names = SnapNames::default();
    let mut header = false;
    for line in reader.lines() {
        let line = line.unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        header |= line.starts_with("#purge-snap ");
        // V: key, name, type, len, hash, preview. Only default values of Interface or CLSID keys.
        let Some(rest) = line.strip_prefix("V\t") else {
            continue;
        };
        if !(rest.contains("Interface") || rest.contains("CLSID")) {
            continue;
        }
        let fields: Vec<&str> = rest.split('\t').collect();
        if fields.len() < 6 || !fields[1].is_empty() {
            continue;
        }
        let key = unescape(fields[0]);
        let value = unescape(fields[5]);
        if let Some(iid) = classes_child(&key, "Interface") {
            names.interfaces.entry(iid).or_default().insert(value);
        } else if let Some(clsid) = classes_child(&key, "CLSID") {
            names.classes.entry(clsid).or_default().insert(value);
        }
    }
    assert!(header, "{} is not a purge snap", path.display());
    names
}

/// The dirty-base snap's names, or `None` (with the reason printed) when the snap is not on this machine.
fn dirty_base() -> Option<&'static SnapNames> {
    static SNAP: OnceLock<Option<SnapNames>> = OnceLock::new();
    SNAP.get_or_init(|| snap_path().map(|path| read_snap(&path)))
        .as_ref()
        .or_else(|| {
            println!(
                "skipped: the dirty-base snap is not present (set PURGE_DIRTY_BASE_SNAP to \
             vm/runs/dirty-base/snap-dirty-base-0.tsv.gz of the main checkout)"
            );
            None
        })
}

#[test]
fn snap_key_shapes() {
    assert_eq!(
        classes_child(
            r"HKLM\SOFTWARE\Classes\Interface\{1814ceeb-49E2-407F-AF99-FA755A7D2607}",
            "Interface"
        )
        .as_deref(),
        Some("{1814CEEB-49E2-407F-AF99-FA755A7D2607}")
    );
    assert!(
        classes_child(
            r"HKLM\SOFTWARE\Classes\WOW6432Node\Interface\{X}",
            "Interface"
        )
        .is_some()
    );
    assert!(
        classes_child(
            r"HKU\S-1-5-21-1-2-3-1000_Classes\Interface\{X}",
            "Interface"
        )
        .is_some()
    );
    assert!(
        classes_child(
            r"HKU\S-1-5-21-1-2-3-1000_Classes\WOW6432Node\CLSID\{X}",
            "CLSID"
        )
        .is_some()
    );
    assert!(
        classes_child(
            r"HKLM\SOFTWARE\Classes\Interface\{X}\ProxyStubClsid32",
            "Interface"
        )
        .is_none()
    );
    assert!(classes_child(r"HKLM\SOFTWARE\Vendor\Interface\{X}", "Interface").is_none());
    assert!(classes_child(r"HKLM\SOFTWARE\Classes\CLSID\{X}", "Interface").is_none());
    assert!(classes_child(r"HKU\S-1-5-21-1-2-3-1000\Interface\{X}", "Interface").is_none());
    assert_eq!(unescape(r"a\\b\tc"), "a\\b\tc");
}

#[test]
fn shared_iids_match_dirty_base_snap() {
    let Some(snap) = dirty_base() else {
        return;
    };
    for entry in shared_iids().iids {
        let names = snap.interfaces.get(&entry.iid);
        assert!(
            names.is_some_and(|n| n.contains(&entry.name)),
            "{} {}: the dirty-base snap has no Interface key with that name (it has {names:?})",
            entry.iid,
            entry.name
        );
    }
}

#[test]
fn shared_proxy_clsids_match_dirty_base_snap() {
    let Some(snap) = dirty_base() else {
        return;
    };
    for entry in shared_iids().shared_proxy_clsids {
        let names = snap.classes.get(&entry.clsid);
        assert!(
            names.is_some_and(|n| n.contains(&entry.name)),
            "{} {}: the dirty-base snap has no CLSID key with that name (it has {names:?})",
            entry.clsid,
            entry.name
        );
    }
}

// ---------------------------------------------------------------------------------------------------
// Shared components.

/// `kb/shared-components.json` as M1a shipped it (commit 55a077b). M1b only appends.
const M1A_COMPONENTS: &str = r#"[
  {
    "id": "webview2",
    "name": "Microsoft Edge WebView2 Runtime",
    "paths": [
      "%ProgramFiles%\\Microsoft\\EdgeWebView",
      "%LOCALAPPDATA%\\Microsoft\\EdgeWebView"
    ],
    "keys": [
      "*\\SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
      "*\\SOFTWARE\\Microsoft\\EdgeUpdate\\ClientState\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
      "*\\SOFTWARE\\Microsoft\\EdgeWebView",
      "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft EdgeWebView"
    ],
    "packages": [
      "Microsoft.WebView2Runtime*",
      "Microsoft.Win32WebViewHost*"
    ]
  },
  {
    "id": "edge",
    "name": "Microsoft Edge",
    "paths": [
      "%ProgramFiles%\\Microsoft\\Edge",
      "%ProgramFiles%\\Microsoft\\EdgeCore",
      "%ProgramFiles%\\Microsoft\\EdgeUpdate",
      "%LOCALAPPDATA%\\Microsoft\\Edge",
      "%LOCALAPPDATA%\\Microsoft\\EdgeUpdate"
    ],
    "keys": [
      "*\\SOFTWARE\\Microsoft\\Edge",
      "*\\SOFTWARE\\Microsoft\\EdgeUpdate",
      "*\\SOFTWARE\\Clients\\StartMenuInternet\\Microsoft Edge",
      "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Edge",
      "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Edge Update",
      "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe",
      "HKCR\\MSEdgeHTM",
      "HKCR\\MSEdgePDF",
      "HKCR\\MSEdgeMHT",
      "HKCR\\microsoft-edge"
    ],
    "packages": [
      "Microsoft.MicrosoftEdge*"
    ]
  },
  {
    "id": "vcredist",
    "name": "Microsoft Visual C++ Redistributable",
    "paths": [],
    "keys": [
      "HKLM\\SOFTWARE\\Microsoft\\VisualStudio\\*\\VC\\Runtimes",
      "HKLM\\SOFTWARE\\Microsoft\\DevDiv\\VC",
      "HKCR\\Installer\\Dependencies\\Microsoft.VS.VC_Runtime*",
      "HKCR\\Installer\\Dependencies\\VC,redist.*"
    ],
    "packages": []
  },
  {
    "id": "dotnet",
    "name": "Microsoft .NET",
    "paths": [
      "%ProgramFiles%\\dotnet",
      "%ProgramFiles%\\Reference Assemblies",
      "%ProgramFiles%\\Microsoft.NET",
      "%WINDIR%\\Microsoft.NET",
      "%WINDIR%\\assembly"
    ],
    "keys": [
      "HKLM\\SOFTWARE\\dotnet",
      "HKLM\\SOFTWARE\\Microsoft\\.NETFramework",
      "HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup",
      "HKLM\\SOFTWARE\\Microsoft\\ASP.NET",
      "HKCR\\Installer\\Dependencies\\dotnet_*"
    ],
    "packages": [
      "Microsoft.NET.Native.*",
      "Microsoft.DotNet.*"
    ]
  },
  {
    "id": "directx",
    "name": "Microsoft DirectX",
    "paths": [
      "%WINDIR%\\System32\\DirectX",
      "%WINDIR%\\SysWOW64\\DirectX"
    ],
    "keys": [
      "HKLM\\SOFTWARE\\Microsoft\\DirectX",
      "HKLM\\SOFTWARE\\Microsoft\\Direct3D",
      "HKLM\\SOFTWARE\\Microsoft\\DirectDraw",
      "HKLM\\SOFTWARE\\Microsoft\\DirectInput",
      "HKLM\\SOFTWARE\\Microsoft\\DirectPlay",
      "HKLM\\SOFTWARE\\Microsoft\\DirectSound"
    ],
    "packages": [
      "Microsoft.DirectXRuntime*"
    ]
  },
  {
    "id": "vclibs",
    "name": "Microsoft Visual C++ Runtime Package",
    "paths": [],
    "keys": [],
    "packages": [
      "Microsoft.VCLibs.*"
    ]
  },
  {
    "id": "windowsappruntime",
    "name": "Windows App Runtime",
    "paths": [],
    "keys": [],
    "packages": [
      "Microsoft.WindowsAppRuntime.*",
      "MicrosoftCorporationII.WinAppRuntime.*",
      "Microsoft.WinAppRuntime.*"
    ]
  },
  {
    "id": "ui-xaml",
    "name": "Microsoft UI XAML",
    "paths": [],
    "keys": [],
    "packages": [
      "Microsoft.UI.Xaml.*"
    ]
  }
]"#;

#[test]
fn shared_components_schema_unchanged_for_existing_entries() {
    // The shipped loader parses with deny_unknown_fields: every entry, old and new, has the M1a shape.
    let all = shared_components().expect("kb/shared-components.json parses with the M1a schema");
    let m1a: Vec<SharedComponent> = serde_json::from_str(M1A_COMPONENTS).unwrap();
    assert!(all.len() > m1a.len(), "M1b appends entries");
    assert_eq!(
        all[..m1a.len()],
        m1a[..],
        "the M1a entries are unchanged, in place"
    );

    let mut ids = BTreeSet::new();
    for c in &all {
        assert!(ids.insert(c.id.as_str()), "duplicate id {}", c.id);
        assert!(!c.name.trim().is_empty(), "{} has no name", c.id);
        assert!(
            !(c.paths.is_empty() && c.keys.is_empty() && c.packages.is_empty()),
            "{} names nothing",
            c.id
        );
    }

    // Every pattern of every entry compiles, and the new entries cover what the rig captured.
    let env = GuardEnv::sample();
    let shared = SharedComponents::compile(&env).expect("every pattern compiles");
    let p = |path: &str| Target::Path { path: path.into() };
    let k = |path: &str| Target::RegKey { path: path.into() };
    let user_classes = |rest: &str| format!(r"HKU\{}_Classes\{rest}", GuardEnv::SAMPLE_SID);
    let wasdk = "Microsoft.WindowsAppRuntime.2_2.6.5.0_x64__8wekyb3d8bbwe";
    let wasdk_cbs = "Microsoft.WindowsAppRuntime.CBS_5001.184.1607.0_x64__8wekyb3d8bbwe";
    let launcher = Some("python-launcher");
    let rows: Vec<(Target, Option<&str>)> = vec![
        (p(r"C:\Windows\py.exe"), launcher),
        (p(r"C:\WINDOWS\pyw.exe"), launcher),
        (p(r"C:\Windows\pyshellext.amd64.dll"), launcher),
        (
            p(
                r"C:\ProgramData\Package Cache\{7102CAE5-270C-4E81-AC25-27699156D8AE}v3.13.1150.0\launcher.msi",
            ),
            launcher,
        ),
        (
            p(r"C:\ProgramData\Package Cache\{73831AC2-F0E1-4173-9FDB-D07463D7EB80}v3.12.7150.0"),
            launcher,
        ),
        (k(r"HKLM\SOFTWARE\Classes\.py"), launcher),
        (k(r"HKLM\SOFTWARE\Classes\.pyzw"), launcher),
        (
            k(r"HKLM\SOFTWARE\Classes\Python.File\Shell\open\command"),
            launcher,
        ),
        (
            k(r"HKLM\SOFTWARE\Classes\CLSID\{BEA218D2-6950-497B-9434-61683EC065FE}\InprocServer32"),
            launcher,
        ),
        (k(r"HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher"), launcher),
        (
            k(
                r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{73831AC2-F0E1-4173-9FDB-D07463D7EB80}",
            ),
            launcher,
        ),
        // A Python version's own registration and cache are not the launcher's.
        (k(r"HKLM\SOFTWARE\Python\PythonCore\3.12"), None),
        (
            p(r"C:\ProgramData\Package Cache\{1BB43BDF-D9E8-487A-B743-CA10AAE7B25F}v3.12.7150.0"),
            None,
        ),
        (
            p(r"C:\Windows\System32\vcruntime140.dll"),
            Some("vcredist-files"),
        ),
        (
            p(r"C:\Windows\System32\mfc140u.dll"),
            Some("vcredist-files"),
        ),
        (
            p(r"C:\Windows\System32\msvcp140_codecvt_ids.dll"),
            Some("vcredist-files"),
        ),
        // The .NET Framework's private copy is not the redistributable's.
        (p(r"C:\Windows\System32\vcruntime140_clr0400.dll"), None),
        (
            k(&format!(
                r"HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\{wasdk}"
            )),
            Some("windowsappruntime-registration"),
        ),
        (
            k(&user_classes(&format!(
                r"Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\{wasdk_cbs}"
            ))),
            Some("windowsappruntime-registration"),
        ),
        (
            k(&format!(
                r"HKLM\SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\{wasdk}"
            )),
            Some("windowsappruntime-registration"),
        ),
        (
            k(&format!(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications\{wasdk_cbs}"
            )),
            Some("windowsappruntime-registration"),
        ),
        (
            Target::AppxPackage {
                full_name: wasdk.into(),
            },
            Some("windowsappruntime"),
        ),
    ];
    for (target, want) in &rows {
        assert_eq!(
            shared.find(target).map(|c| c.id.as_str()),
            *want,
            "{target:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------------
// Hosts.

#[test]
fn hosts_list_lowercase_unique() {
    let hosts: Hosts = serde_json::from_str(HOSTS).expect("kb/hosts.json parses");
    let mut seen = BTreeSet::new();
    for name in &hosts.interpreters {
        assert_eq!(*name, name.to_lowercase(), "{name} is lower case");
        assert_eq!(name.trim(), name, "{name:?} has no surrounding space");
        assert!(
            !name.contains(['\\', '/', ':', '"']),
            "{name} is a bare file name"
        );
        assert!(
            name.ends_with(".exe") && name.len() > 4,
            "{name} is an .exe"
        );
        assert!(seen.insert(name.as_str()), "duplicate {name}");
    }
    for name in INTERPRETERS {
        assert!(
            seen.contains(name),
            "{name} (C-SYSOBJ resolve_program) is listed"
        );
    }
}
