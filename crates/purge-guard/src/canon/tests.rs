//! Tests for canonicalisation: tables per rule of gate G1, and a deterministic property test over the
//! spellings one location can have (ENGINE_PLAN.md §10.1).

use super::*;

const SID: &str = GuardEnv::SAMPLE_SID;

fn env() -> GuardEnv {
    GuardEnv::sample()
}

fn path(input: &str) -> Result<String, CanonError> {
    canon_path(input, &env(), Some(SID)).map(|c| c.path)
}

fn key(input: &str) -> Result<String, CanonError> {
    canon_key(input, None, &env(), Some(SID)).map(|k| k.key_path())
}

/// xorshift64*: small, deterministic, good enough to pick spellings.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Rng {
        Rng(seed.max(1))
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub(crate) fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    pub(crate) fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }

    pub(crate) fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    /// Flips the case of random ASCII letters.
    pub(crate) fn recase(&mut self, s: &str) -> String {
        s.chars()
            .map(|c| match self.below(3) {
                0 => c.to_ascii_uppercase(),
                1 => c.to_ascii_lowercase(),
                _ => c,
            })
            .collect()
    }
}

/// Another spelling of a canonical file path: separators, doubled and trailing separators, a `\\?\`
/// prefix, drive-letter case. Segment case is kept (canonical form preserves it).
pub(crate) fn respell_path(rng: &mut Rng, canonical: &str) -> String {
    let (drive, rest) = canonical.split_at(2);
    let drive = if rng.coin() {
        drive.to_ascii_lowercase()
    } else {
        drive.to_owned()
    };
    let mut out = String::new();
    let long_prefix = rng.below(4) == 0;
    if long_prefix {
        out.push_str(if rng.coin() { r"\\?\" } else { r"\??\" });
    }
    out.push_str(&drive);
    for segment in rest.split('\\').filter(|s| !s.is_empty()) {
        let sep = if rng.below(3) == 0 { "/" } else { "\\" };
        out.push_str(sep);
        if rng.below(5) == 0 {
            out.push_str(sep);
        }
        out.push_str(segment);
    }
    if rng.below(3) == 0 || out.ends_with(':') {
        out.push('\\');
    }
    out
}

#[test]
fn path_forms_table() {
    let rows: &[(&str, &str)] = &[
        (r"C:\Program Files\Git", r"C:\Program Files\Git"),
        (r"c:\Program Files\Git\", r"C:\Program Files\Git"),
        (r"C:/Program Files//Git/", r"C:\Program Files\Git"),
        (r"\\?\C:\Program Files\Git", r"C:\Program Files\Git"),
        (r"\??\c:\Program Files\Git", r"C:\Program Files\Git"),
        (r"//?/C:/Program Files/Git", r"C:\Program Files\Git"),
        (r"C:\", r"C:\"),
        (r"d:\\", r"D:\"),
        (
            r"C:\a.b\.config\ x\100% done",
            r"C:\a.b\.config\ x\100% done",
        ),
        (r"C:\data\%APPDATA%\x", r"C:\data\%APPDATA%\x"),
        (r"%WINDIR%\System32", r"C:\Windows\System32"),
        (r"%SystemRoot%", r"C:\Windows"),
        (r"%windir%/Fonts/", r"C:\Windows\Fonts"),
        (r"%ProgramFiles%\Git", r"C:\Program Files\Git"),
        (r"%ProgramW6432%\Git", r"C:\Program Files\Git"),
        (
            r"%ProgramFiles(x86)%\Steam",
            r"C:\Program Files (x86)\Steam",
        ),
        (
            r"%CommonProgramFiles%\X",
            r"C:\Program Files\Common Files\X",
        ),
        (
            r"%CommonProgramFiles(x86)%\X",
            r"C:\Program Files (x86)\Common Files\X",
        ),
        (r"%ProgramData%\X", r"C:\ProgramData\X"),
        (r"%ALLUSERSPROFILE%\X", r"C:\ProgramData\X"),
        (r"%SystemDrive%\X", r"C:\X"),
        (r"%PUBLIC%\Desktop", r"C:\Users\Public\Desktop"),
        (r"%USERPROFILE%\.app", r"C:\Users\tester\.app"),
        (r"%APPDATA%\App", r"C:\Users\tester\AppData\Roaming\App"),
        (r"%LocalAppData%\App", r"C:\Users\tester\AppData\Local\App"),
    ];
    for (input, want) in rows {
        assert_eq!(path(input).as_deref(), Ok(*want), "{input}");
    }
}

#[test]
fn path_rejections_table() {
    use CanonError::*;
    let rows: &[(&str, CanonError)] = &[
        ("", Empty),
        (r"Program Files\Git", Relative),
        (r"\Windows\System32", Relative),
        ("C:", Relative),
        (r"C:Windows", Relative),
        (r"C:\a\..\Windows", DotSegment),
        (r"C:\a\..", DotSegment),
        (r"C:\a\.\b", DotSegment),
        (r"C:\a\...\b", DotSegment),
        (r"C:/a/../b", DotSegment),
        (r"\\?\GLOBALROOT\Device\HarddiskVolume1\x", GlobalRoot),
        (r"\\?\globalroot\Device\x", GlobalRoot),
        (r"C:\x\GLOBALROOT\y", GlobalRoot),
        (r"\\server\share\x", Unc),
        (r"//server/share/x", Unc),
        (r"\\?\UNC\server\share\x", Unc),
        (r"\\.\C:\x", DeviceNamespace),
        (r"\\.\PhysicalDrive0", DeviceNamespace),
        (
            r"\\?\Volume{6f2e4b0a-0000-0000-0000-100000000000}\x",
            DeviceNamespace,
        ),
        (r"\\?\%WINDIR%\x", DeviceNamespace),
        (r"C:\x\file.txt:stream", Ads),
        (r"C:\x\file.txt::$DATA", Ads),
        (r"C:\x:y\z", Ads),
        (r"C:\x\NUL", DeviceName("NUL".into())),
        (r"C:\x\nul.txt", DeviceName("nul.txt".into())),
        (r"C:\con\x", DeviceName("con".into())),
        (r"C:\x\COM1", DeviceName("COM1".into())),
        (r"C:\x\lpt9.log", DeviceName("lpt9.log".into())),
        (r"C:\x\CONIN$", DeviceName("CONIN$".into())),
        (r"C:\x\aux .txt", DeviceName("aux .txt".into())),
        (r"C:\x\trailing.", TrailingDotOrSpace),
        (r"C:\x\trailing \y", TrailingDotOrSpace),
        (r"C:\x\a?b", InvalidChar),
        (r"C:\x\*.tmp", InvalidChar),
        (r#"C:\x\a"b"#, InvalidChar),
        (r"C:\x\a|b", InvalidChar),
        ("C:\\x\\a\u{0}b", InvalidChar),
        ("C:\\x\\a\nb", InvalidChar),
        (r"%TEMP%\x", EnvToken("%TEMP%".into())),
        (r"%PATH%", EnvToken("%PATH%".into())),
        (r"%WINDIR", EnvToken("%WINDIR".into())),
        (r"%WINDIR%32\x", EnvToken("%WINDIR%32".into())),
    ];
    for (input, want) in rows {
        assert_eq!(path(input), Err(want.clone()), "{input:?}");
    }
}

#[test]
fn names_that_only_resemble_devices_pass() {
    for ok in [
        r"C:\x\COM10",
        r"C:\x\console",
        r"C:\x\nullable.txt",
        r"C:\x\COM",
        r"C:\x\LPT0x",
    ] {
        assert!(path(ok).is_ok(), "{ok}");
    }
}

#[test]
fn per_user_tokens_need_a_known_profile() {
    let env = env();
    assert_eq!(
        canon_path(r"%APPDATA%\X", &env, None),
        Err(CanonError::NoProfile)
    );
    assert_eq!(
        canon_path(r"%USERPROFILE%\X", &env, Some("S-1-5-21-1-2-3-9999")),
        Err(CanonError::NoProfile)
    );
    let mut no_x86 = env.clone();
    no_x86.program_files_x86 = None;
    assert!(matches!(
        canon_path(r"%ProgramFiles(x86)%\X", &no_x86, None),
        Err(CanonError::EnvToken(_))
    ));
    assert!(matches!(
        canon_path(r"%WINDIR%\X", &GuardEnv::default(), None),
        Err(CanonError::EnvToken(_))
    ));
}

#[test]
fn short_names_are_flagged_not_resolved() {
    let flagged = [
        r"C:\PROGRA~1\Git",
        r"C:\Users\TESTER~1\AppData",
        r"C:\x\LONGFI~2.TXT",
        r"C:\x\A~1",
        r"C:\x\AB~12.C",
    ];
    for input in flagged {
        let canon = canon_path(input, &env(), None).unwrap();
        assert!(canon.needs_long_name, "{input}");
        assert_eq!(canon.path, input, "the name itself is left alone");
    }
    let plain = [
        r"C:\Program Files\Git",
        r"C:\x\~temp",
        r"C:\x\file~",
        r"C:\x\~1",
        r"C:\x\backup~1 copy",
        r"C:\x\averylongname~1.txt",
        r"C:\x\name~1.html",
        r"C:\x\a~b",
    ];
    for input in plain {
        assert!(
            !canon_path(input, &env(), None).unwrap().needs_long_name,
            "{input}"
        );
    }
}

#[test]
fn key_forms_table() {
    let s = SID;
    let rows: Vec<(String, String)> = [
        (r"HKLM\SOFTWARE\Vendor\App", r"HKLM\SOFTWARE\Vendor\App"),
        (
            r"HKEY_LOCAL_MACHINE\Software\Vendor\App\",
            r"HKLM\SOFTWARE\Vendor\App",
        ),
        (r"hklm\software\\Vendor", r"HKLM\SOFTWARE\Vendor"),
        (
            r"Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Vendor",
            r"HKLM\SOFTWARE\Vendor",
        ),
        (
            r"\REGISTRY\MACHINE\SOFTWARE\Vendor",
            r"HKLM\SOFTWARE\Vendor",
        ),
        (r"HKLM", r"HKLM"),
        (r"HKLM\SOFTWARE", r"HKLM\SOFTWARE"),
        // WOW64 views.
        (
            r"HKLM\SOFTWARE\WOW6432Node\Vendor",
            r"HKLM\SOFTWARE\WOW6432Node\Vendor",
        ),
        (
            r"HKLM\Software\Wow6432Node\Vendor",
            r"HKLM\SOFTWARE\WOW6432Node\Vendor",
        ),
        (r"HKLM\SOFTWARE\WOW6432Node", r"HKLM\SOFTWARE\WOW6432Node"),
        (
            r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{X}",
            r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{X}",
        ),
        (
            r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{X}",
            r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{X}",
        ),
        (r"HKLM\SOFTWARE\classes\.txt", r"HKLM\SOFTWARE\Classes\.txt"),
        // Control sets.
        (
            r"HKLM\SYSTEM\CurrentControlSet\Services\X",
            r"HKLM\SYSTEM\ControlSet001\Services\X",
        ),
        (
            r"HKLM\System\currentcontrolset",
            r"HKLM\SYSTEM\ControlSet001",
        ),
        (
            r"HKLM\SYSTEM\controlset002\Services",
            r"HKLM\SYSTEM\ControlSet002\Services",
        ),
        (r"HKLM\SYSTEM\Select", r"HKLM\SYSTEM\Select"),
        (
            r"HKLM\SYSTEM\CurrentControlSetX",
            r"HKLM\SYSTEM\CurrentControlSetX",
        ),
        (
            r"HKLM\SOFTWARE\CurrentControlSet",
            r"HKLM\SOFTWARE\CurrentControlSet",
        ),
        // Key names may contain a forward slash.
        (
            r"HKLM\SOFTWARE\Classes\MIME\Database\Content Type\application/pdf",
            r"HKLM\SOFTWARE\Classes\MIME\Database\Content Type\application/pdf",
        ),
    ]
    .into_iter()
    .map(|(a, b)| (a.to_owned(), b.to_owned()))
    .chain([
        (
            format!(r"HKU\{s}\Software\Vendor"),
            format!(r"HKU\{s}\Software\Vendor"),
        ),
        (
            format!(r"HKEY_USERS\{}\SOFTWARE\Vendor", s.to_lowercase()),
            format!(r"HKU\{s}\Software\Vendor"),
        ),
        (
            r"HKCU\Software\Vendor".to_owned(),
            format!(r"HKU\{s}\Software\Vendor"),
        ),
        (r"HKEY_CURRENT_USER".to_owned(), format!(r"HKU\{s}")),
        (
            r"hkcu\Environment".to_owned(),
            format!(r"HKU\{s}\Environment"),
        ),
        (
            format!(r"\Registry\User\{s}\Software\X"),
            format!(r"HKU\{s}\Software\X"),
        ),
        // The Classes link.
        (
            format!(r"HKU\{s}\Software\Classes\.txt"),
            format!(r"HKU\{s}_Classes\.txt"),
        ),
        (
            format!(r"HKU\{s}\SOFTWARE\CLASSES"),
            format!(r"HKU\{s}_Classes"),
        ),
        (
            r"HKCU\Software\Classes\Applications\a.exe".to_owned(),
            format!(r"HKU\{s}_Classes\Applications\a.exe"),
        ),
        (
            format!(r"HKU\{s}_classes\.txt"),
            format!(r"HKU\{s}_Classes\.txt"),
        ),
        (
            format!(r"HKU\{s}_Classes\WOW6432Node\CLSID\{{X}}"),
            format!(r"HKU\{s}_Classes\WOW6432Node\CLSID\{{X}}"),
        ),
        (
            format!(r"HKU\{s}\Software\Classes\Wow6432Node\CLSID\{{X}}"),
            format!(r"HKU\{s}_Classes\WOW6432Node\CLSID\{{X}}"),
        ),
        (
            format!(r"HKU\{s}\Software\ClassesX"),
            format!(r"HKU\{s}\Software\ClassesX"),
        ),
        // No redirection of a user's Software key.
        (
            format!(r"HKU\{s}\Software\WOW6432Node\Vendor"),
            format!(r"HKU\{s}\Software\WOW6432Node\Vendor"),
        ),
        (
            r"HKU\.default\Software\X".to_owned(),
            r"HKU\.DEFAULT\Software\X".to_owned(),
        ),
        (r"HKU\s-1-5-18".to_owned(), r"HKU\S-1-5-18".to_owned()),
    ])
    .collect();
    for (input, want) in &rows {
        assert_eq!(key(input).as_ref(), Ok(want), "{input}");
        // Canonical output is a fixed point.
        assert_eq!(key(want).as_ref(), Ok(want), "fixed point of {want}");
    }
}

#[test]
fn key_rejections_table() {
    use CanonError::*;
    let rows: &[(&str, CanonError)] = &[
        ("", Empty),
        (r"\\", Empty),
        (r"HKCR\.txt", Hkcr),
        (r"HKEY_CLASSES_ROOT\CLSID\{X}", Hkcr),
        (r"hkcr", Hkcr),
        (r"HKCC\System", UnknownRoot("HKCC".into())),
        (
            r"HKEY_CURRENT_CONFIG\System",
            UnknownRoot("HKEY_CURRENT_CONFIG".into()),
        ),
        (
            r"HKEY_PERFORMANCE_DATA",
            UnknownRoot("HKEY_PERFORMANCE_DATA".into()),
        ),
        (r"SOFTWARE\Vendor", UnknownRoot("SOFTWARE".into())),
        (r"\REGISTRY\A\{guid}\Root", UnknownRoot("REGISTRY".into())),
        (r"REGISTRY\MACHINE\SOFTWARE", UnknownRoot("REGISTRY".into())),
        (r"HKU", MissingSid),
        (r"HKEY_USERS\", MissingSid),
        (r"HKU\Software\Vendor", BadSid("Software".into())),
        (r"HKU\S-1-5-21-x\Software", BadSid("S-1-5-21-x".into())),
        (r"HKU\S-1-\Software", BadSid("S-1-".into())),
        (r"HKU\_Classes\X", BadSid("_Classes".into())),
        ("HKLM\\SOFTWARE\\a\u{0}b", InvalidChar),
    ];
    for (input, want) in rows {
        assert_eq!(key(input), Err(want.clone()), "{input:?}");
    }
    assert_eq!(
        canon_key(r"HKCU\Software\X", None, &env(), None),
        Err(NoProfile),
        "an unbound HKCU is rejected"
    );
    let mut unknown_set = env();
    unknown_set.current_control_set = 0;
    assert_eq!(
        canon_key(
            r"HKLM\SYSTEM\CurrentControlSet\Services",
            None,
            &unknown_set,
            None
        ),
        Err(NoControlSet)
    );
    assert!(
        canon_key(
            r"HKLM\SYSTEM\ControlSet001\Services",
            None,
            &unknown_set,
            None
        )
        .is_ok()
    );
}

#[test]
fn views_are_explicit() {
    let env = env();
    let k = |input: &str, view| canon_key(input, view, &env, Some(SID)).unwrap();

    let plain = k(r"HKLM\SOFTWARE\Vendor", None);
    assert_eq!(
        (plain.view, plain.path.as_str()),
        (View::K64, r"SOFTWARE\Vendor")
    );

    let spelled = k(r"HKLM\SOFTWARE\WOW6432Node\Vendor", None);
    assert_eq!(
        (spelled.view, spelled.path.as_str()),
        (View::K32, r"SOFTWARE\Vendor")
    );

    // A caller that read `SOFTWARE\Vendor` through the 32-bit view says so; the result is the same key.
    assert_eq!(k(r"HKLM\SOFTWARE\Vendor", Some(View::K32)), spelled);
    // The spelling wins over a 64-bit claim: that path only exists as 32-bit data.
    assert_eq!(
        k(r"HKLM\SOFTWARE\WOW6432Node\Vendor", Some(View::K64)),
        spelled
    );

    let alias = k(r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{X}", None);
    assert_eq!(
        alias,
        k(r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{X}", None)
    );
    assert_eq!(
        (alias.view, alias.path.as_str()),
        (View::K32, r"SOFTWARE\Classes\CLSID\{X}")
    );

    // No view outside SOFTWARE and Classes.
    assert_eq!(
        k(r"HKLM\SYSTEM\CurrentControlSet", Some(View::K32)).view,
        View::K64
    );
    assert_eq!(k(r"HKCU\Software\Vendor", Some(View::K32)).view, View::K64);

    let user_classes = k(r"HKCU\Software\Classes\CLSID\{X}", Some(View::K32));
    assert_eq!(user_classes.hive, Hive::HkuClasses(SID.into()));
    assert_eq!(user_classes.view, View::K32);
    assert_eq!(
        user_classes.key_path(),
        format!(r"HKU\{SID}_Classes\WOW6432Node\CLSID\{{X}}")
    );
}

#[test]
fn canon_key_agrees_with_typed_target() {
    let env = env();
    for input in [
        r"HKLM\SOFTWARE\WOW6432Node\Vendor\App",
        r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{X}",
        r"HKCU\Software\Classes\.txt",
        r"HKCU\Software\Vendor",
        r"HKLM\SYSTEM\CurrentControlSet\Services\X",
        r"HKLM",
    ] {
        let k = canon_key(input, None, &env, Some(SID)).unwrap();
        let typed = k.typed(RegKind::Key);
        assert_eq!(
            (typed.hive(), typed.view(), typed.path()),
            (&k.hive, k.view, k.path.as_str()),
            "{input}"
        );
        let reparsed = TypedTarget::parse_key_path(&k.key_path()).unwrap();
        assert_eq!(
            reparsed,
            (k.hive.clone(), k.view, k.path.clone()),
            "{input}"
        );
    }
}

#[test]
fn canon_target_rewrites_only_the_location() {
    let env = env();
    let t = Target::RegMultiSzSegment {
        path: r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment"
            .into(),
        name: "Path".into(),
        segment: r"C:\Program Files\Git\cmd".into(),
        index: Some(3),
    };
    let canon = canon_target(&t, &env, None).unwrap();
    assert_eq!(
        canon.target,
        Target::RegMultiSzSegment {
            path: r"HKLM\SYSTEM\ControlSet001\Control\Session Manager\Environment".into(),
            name: "Path".into(),
            segment: r"C:\Program Files\Git\cmd".into(),
            index: Some(3),
        }
    );
    assert!(!canon.needs_long_name);

    let value = Target::RegValue {
        path: r"HKCU\Software\Classes\.txt\OpenWithProgids".into(),
        name: "App.txt".into(),
    };
    assert_eq!(
        canon_target(&value, &env, Some(SID)).unwrap().target,
        Target::RegValue {
            path: format!(r"HKU\{SID}_Classes\.txt\OpenWithProgids"),
            name: "App.txt".into()
        }
    );
    assert_eq!(canon_target(&value, &env, None), Err(CanonError::NoProfile));

    let short = canon_target(
        &Target::Path {
            path: r"c:/PROGRA~1/App/".into(),
        },
        &env,
        None,
    )
    .unwrap();
    assert_eq!(
        short.target,
        Target::Path {
            path: r"C:\PROGRA~1\App".into()
        }
    );
    assert!(short.needs_long_name);

    let service = Target::Service {
        name: "..\\x".into(),
    };
    assert_eq!(canon_target(&service, &env, None).unwrap().target, service);
    assert!(
        canon_target(
            &Target::Path {
                path: r"C:\a\..\b".into()
            },
            &env,
            None
        )
        .is_err()
    );
    assert!(
        canon_target(
            &Target::RegKey {
                path: r"HKCR\.txt".into()
            },
            &env,
            None
        )
        .is_err()
    );
}

#[test]
fn guard_env_helpers() {
    let env = env();
    assert!(env.missing().is_empty());
    assert_eq!(
        GuardEnv::default().missing(),
        [
            "system_drive",
            "windir",
            "program_files",
            "program_data",
            "profiles_dir"
        ]
    );
    assert_eq!(env.control_set_name().as_deref(), Some("ControlSet001"));
    assert_eq!(
        env.profile(&SID.to_lowercase()).map(|p| p.root.as_str()),
        Some(r"C:\Users\tester")
    );
    assert_eq!(env.program_files_dirs().count(), 2);
    let json = serde_json::to_string(&env).unwrap();
    assert_eq!(serde_json::from_str::<GuardEnv>(&json).unwrap(), env);
    // Every field is optional on the wire; what is missing is reported, not guessed.
    let partial: GuardEnv = serde_json::from_str(r#"{"windir":"C:\\Windows"}"#).unwrap();
    assert_eq!(partial.missing().len(), 4);
}

const SEGMENTS: &[&str] = &[
    "Program Files",
    "Git",
    "bin",
    "My App",
    ".config",
    "a.b.c",
    "Übung",
    "x64",
    "data (1)",
    "100%",
    "v1.2",
    "node_modules",
    "~cache",
    "$Recycle",
    "名前",
];

fn random_canonical_path(rng: &mut Rng) -> String {
    let mut out = format!("{}:", rng.pick(&['C', 'D', 'E']));
    for _ in 0..rng.below(6) {
        out.push('\\');
        out.push_str(rng.pick(SEGMENTS));
    }
    if out.len() == 2 {
        out.push('\\');
    }
    out
}

/// Every spelling of a path canonicalises to the same string, the result is a fixed point, and one
/// poisoned segment anywhere is always refused with the matching error.
#[test]
fn property_path_spellings() {
    let env = env();
    let mut rng = Rng::new(0x5EED_0001);
    let poisons: &[(&str, CanonError)] = &[
        ("..", CanonError::DotSegment),
        (".", CanonError::DotSegment),
        ("file:ads", CanonError::Ads),
        ("NUL", CanonError::DeviceName("NUL".into())),
        ("com3.txt", CanonError::DeviceName("com3.txt".into())),
        ("dot.", CanonError::TrailingDotOrSpace),
        ("space ", CanonError::TrailingDotOrSpace),
        ("GlobalRoot", CanonError::GlobalRoot),
        ("a*b", CanonError::InvalidChar),
    ];
    for round in 0..3000 {
        let canonical = random_canonical_path(&mut rng);
        assert_eq!(
            canon_path(&canonical, &env, None)
                .map(|c| c.path)
                .as_deref(),
            Ok(canonical.as_str()),
            "fixed point, round {round}"
        );
        let spelled = respell_path(&mut rng, &canonical);
        let got = canon_path(&spelled, &env, None).unwrap_or_else(|e| panic!("{spelled:?}: {e}"));
        assert_eq!(got.path, canonical, "{spelled:?}");
        assert!(!got.needs_long_name, "{spelled:?}");

        // Poison one position.
        let mut segments: Vec<&str> = canonical[2..]
            .split('\\')
            .filter(|s| !s.is_empty())
            .collect();
        let (poison, want) = rng.pick(poisons);
        segments.insert(rng.below(segments.len() + 1), poison);
        let poisoned = format!("{}\\{}", &canonical[..2], segments.join("\\"));
        let poisoned = respell_path(&mut rng, &poisoned);
        // A trailing separator after "space " or "dot." does not rescue it; nothing else changes it.
        assert_eq!(
            canon_path(&poisoned, &env, None),
            Err(want.clone()),
            "{poisoned:?}"
        );

        // A short-name marker is flagged and never rejected.
        let mut with_short: Vec<&str> = canonical[2..]
            .split('\\')
            .filter(|s| !s.is_empty())
            .collect();
        with_short.insert(rng.below(with_short.len() + 1), "PROGRA~1");
        let short = format!("{}\\{}", &canonical[..2], with_short.join("\\"));
        assert!(
            canon_path(&respell_path(&mut rng, &short), &env, None)
                .unwrap()
                .needs_long_name
        );

        // Whole-path poisons.
        let tail = &canonical[2..];
        assert_eq!(
            canon_path(&format!(r"\\server\share{tail}"), &env, None),
            Err(CanonError::Unc)
        );
        assert_eq!(
            canon_path(&format!(r"\\?\UNC\server{tail}"), &env, None),
            Err(CanonError::Unc)
        );
        assert_eq!(
            canon_path(&format!(r"\\?\GLOBALROOT\Device\X{tail}"), &env, None),
            Err(CanonError::GlobalRoot)
        );
        assert_eq!(
            canon_path(&format!(r"\\.\{canonical}"), &env, None),
            Err(CanonError::DeviceNamespace)
        );
    }
}

/// One registry location, many spellings: root names, case of the rewritten segments, the three links
/// (WOW6432Node placement, CurrentControlSet, Software\Classes), doubled and trailing separators.
#[test]
fn property_key_spellings() {
    let env = env();
    let mut rng = Rng::new(0x5EED_0002);
    let tails: &[&str] = &[
        "",
        r"Vendor",
        r"Vendor\App",
        r"CLSID\{0A1B}\InprocServer32",
        r".txt\OpenWithProgids",
        r"a/b\c",
    ];
    let join = |parts: &[&str]| -> String {
        parts
            .iter()
            .filter(|p| !p.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join("\\")
    };
    for round in 0..3000 {
        let tail = *rng.pick(tails);
        let hklm = *rng.pick(&["HKLM", "HKEY_LOCAL_MACHINE", "hklm", "Hkey_Local_Machine"]);
        let hku = *rng.pick(&["HKU", "HKEY_USERS", "hku"]);
        let hkcu = *rng.pick(&["HKCU", "HKEY_CURRENT_USER", "hkcu"]);
        let software = rng.recase("SOFTWARE");
        let classes = rng.recase("Classes");
        let wow = rng.recase("WOW6432Node");
        let sid = if rng.coin() {
            SID.to_owned()
        } else {
            SID.to_lowercase()
        };

        // (spelling, canonical)
        let (mut spelled, want): (String, String) = match rng.below(7) {
            0 => (
                join(&[hklm, &software, tail]),
                join(&["HKLM", "SOFTWARE", tail]),
            ),
            1 => (
                join(&[hklm, &software, &wow, tail]),
                join(&["HKLM", "SOFTWARE", "WOW6432Node", tail]),
            ),
            2 => {
                // The Classes alias of the 32-bit view, either placement of the node.
                let spelled = if rng.coin() {
                    join(&[hklm, &software, &classes, &wow, tail])
                } else {
                    join(&[hklm, &software, &wow, &classes, tail])
                };
                (
                    spelled,
                    join(&["HKLM", "SOFTWARE", "WOW6432Node", "Classes", tail]),
                )
            }
            3 => {
                let set = rng.recase("CurrentControlSet");
                let set = if rng.coin() {
                    set
                } else {
                    rng.recase("ControlSet001")
                };
                (
                    join(&[hklm, &rng.recase("SYSTEM"), &set, tail]),
                    join(&["HKLM", "SYSTEM", "ControlSet001", tail]),
                )
            }
            4 => {
                let spelled = if rng.coin() {
                    join(&[hku, &sid, &software, tail])
                } else {
                    join(&[hkcu, &software, tail])
                };
                (spelled, join(&["HKU", SID, "Software", tail]))
            }
            5 => {
                // HKU\<SID>\Software\Classes == HKU\<SID>_Classes.
                let spelled = match rng.below(3) {
                    0 => join(&[hku, &sid, &software, &classes, tail]),
                    1 => join(&[hkcu, &software, &classes, tail]),
                    _ => join(&[hku, &format!("{sid}{}", rng.recase("_Classes")), tail]),
                };
                (spelled, join(&["HKU", &format!("{SID}_Classes"), tail]))
            }
            _ => {
                let spelled = if rng.coin() {
                    join(&[hkcu, &software, &classes, &wow, tail])
                } else {
                    join(&[hku, &format!("{sid}_Classes"), &wow, tail])
                };
                (
                    spelled,
                    join(&["HKU", &format!("{SID}_Classes"), "WOW6432Node", tail]),
                )
            }
        };
        if rng.below(4) == 0 {
            spelled = spelled.replacen('\\', r"\\", 1);
        }
        if rng.below(4) == 0 {
            spelled.push('\\');
        }
        if rng.below(6) == 0 {
            spelled = format!(r"Computer\{spelled}");
        }
        let got = canon_key(&spelled, None, &env, Some(SID))
            .unwrap_or_else(|e| panic!("round {round}: {spelled:?}: {e}"));
        assert_eq!(got.key_path(), want, "{spelled:?}");
        assert_eq!(
            key(&want).as_deref(),
            Ok(want.as_str()),
            "fixed point of {want}"
        );

        // HKCR is never accepted, whatever follows.
        let hkcr = *rng.pick(&["HKCR", "HKEY_CLASSES_ROOT", "hkcr"]);
        assert_eq!(key(&join(&[hkcr, tail])), Err(CanonError::Hkcr));
    }
}
