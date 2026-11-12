// Copyright (c) 2017 Marcin Szeniak
// Modified by Purge
// Ported from BCU: source/UninstallTools/Factory/InfoAdders/UninstallerTypeAdder.cs (Apache-2.0)

//! Installer-kind detection for one Uninstall key (ENGINE_PLAN.md §4.1 `installer_kind`, §4.3).
//!
//! Written from Microsoft's documented Uninstall-key semantics, the Inno Setup and NSIS documentation and
//! BCU's uninstaller-kind detection as a starting point. The signals, strongest first:
//!
//! | Kind | Signal ([`KindBasis`]) |
//! |---|---|
//! | Burn | `BundleProviderKey`, `BundleCachePath` or `BundleUpgradeCode` values ([`KindBasis::BundleValues`]); children are not linked in M1a |
//! | MSI | `WindowsInstaller` = 1 ([`KindBasis::WindowsInstallerFlag`]), or a `{GUID}` key name whose uninstall command is `msiexec` ([`KindBasis::GuidKeyWithMsiexec`]) |
//! | Inno | the `_is1` key-name suffix Inno gives its `<AppId>_is1` keys ([`KindBasis::InnoKeySuffix`]), or `Inno Setup: …` values ([`KindBasis::InnoValues`]) |
//! | NSIS / Inno | the uninstaller's bytes carry the installer's own manifest name (`Nullsoft…`, `JR.Inno.Setup`) ([`KindBasis::ExeMarker`]) |
//! | NSIS | `_?=` in the uninstall arguments, which only NSIS uninstallers take ([`KindBasis::NsisInstdirArg`]) |
//! | NSIS / Inno | the uninstaller's file name (`uninst.exe`, `uninstall.exe`, Mozilla's `uninstall\helper.exe`; `unins000.exe`) ([`KindBasis::UninstallerName`]), the weakest signal, used when the bytes say nothing |
//!
//! Detection is pure: the caller hands in the key's facts and a probe that returns the first bytes of the
//! uninstaller (or `None` when they cannot be read, e.g. a snapshot fixture), so it runs the same on Live
//! and Fixture sources.

use purge_model::InstallerKind;
use purge_win::cmdline::{self, CommandKind, SplitCommand};

/// How many leading bytes of an uninstaller the marker scan reads. The manifest of an NSIS or Inno stub
/// sits in the stub's resources, well inside this window.
pub const EXE_SCAN_BYTES: usize = 512 * 1024;

/// Value names whose presence marks a WiX Burn bundle entry.
pub const BUNDLE_VALUES: [&str; 3] = ["BundleProviderKey", "BundleCachePath", "BundleUpgradeCode"];

/// Prefix of the values Inno Setup writes into its Uninstall key (`Inno Setup: App Path`, …).
pub const INNO_VALUE_PREFIX: &str = "Inno Setup:";

/// Suffix of an Inno Setup Uninstall key name (`<AppId>_is1`).
pub const INNO_KEY_SUFFIX: &str = "_is1";

/// Byte markers of an NSIS stub (its manifest names `Nullsoft.NSIS.exehead`).
const NSIS_MARKERS: [&[u8]; 1] = [b"Nullsoft"];
/// Byte markers of an Inno Setup uninstaller (its manifest names `JR.Inno.Setup`).
const INNO_MARKERS: [&[u8]; 2] = [b"JR.Inno.Setup", b"Inno Setup"];

/// The facts of an Uninstall key that kind detection reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KindFacts<'a> {
    /// The key's name under `…\Uninstall`.
    pub key_name: &'a str,
    /// `WindowsInstaller` is set to 1.
    pub windows_installer: bool,
    /// `UninstallString`, when non-empty.
    pub uninstall_string: Option<&'a str>,
    /// `QuietUninstallString`, when non-empty.
    pub quiet_uninstall_string: Option<&'a str>,
    /// The key has at least one `Inno Setup: …` value.
    pub has_inno_values: bool,
    /// The key has at least one of [`BUNDLE_VALUES`].
    pub has_bundle_values: bool,
}

/// Which signal decided the kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KindBasis {
    /// Burn bundle values.
    BundleValues,
    /// `WindowsInstaller` = 1.
    WindowsInstallerFlag,
    /// A `{GUID}` key name with an `msiexec` uninstall command.
    GuidKeyWithMsiexec,
    /// The `_is1` key-name suffix.
    InnoKeySuffix,
    /// `Inno Setup: …` values.
    InnoValues,
    /// A marker in the uninstaller's bytes.
    ExeMarker,
    /// `_?=` in the uninstall arguments.
    NsisInstdirArg,
    /// The uninstaller's file name only (weakest).
    UninstallerName,
    /// Nothing matched; the kind is [`InstallerKind::Unknown`].
    Nothing,
}

/// The outcome of kind detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KindDetection {
    /// The installer technology.
    pub kind: InstallerKind,
    /// The signal that decided it.
    pub basis: KindBasis,
    /// The MSI ProductCode, `{GUID}` upper case: the key name when it is a GUID, otherwise the GUID of an
    /// `msiexec` uninstall command. Only for [`InstallerKind::Msi`].
    pub product_code: Option<String>,
    /// The Inno Setup AppId: the key name without `_is1`. Only for [`InstallerKind::Inno`] keys that have
    /// the suffix.
    pub inno_app_id: Option<String>,
}

/// Whether `s` is exactly a braced GUID (`{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`, any case).
pub fn is_braced_guid(s: &str) -> bool {
    s.len() == 38 && s.starts_with('{') && cmdline::find_braced_guid(s).is_some()
}

/// The command an uninstall string runs, split into executable and arguments; `None` when it is empty or
/// cannot be split.
pub fn uninstaller(uninstall_string: &str) -> Option<SplitCommand> {
    cmdline::split(uninstall_string).ok()
}

/// The ProductCode an `msiexec` command names (any action, any spacing: `/I{…}`, `/X {…}`), upper case.
pub fn msiexec_product_code(command: &str) -> Option<String> {
    match uninstaller(command)?.kind() {
        CommandKind::Msiexec(m) => m.product_code,
        _ => None,
    }
}

/// Whether the command runs `msiexec`.
pub fn is_msiexec(command: &str) -> bool {
    uninstaller(command).is_some_and(|c| matches!(c.kind(), CommandKind::Msiexec(_)))
}

/// The key name without a trailing `_is1` (ASCII case-insensitive), when it has one.
pub fn strip_inno_suffix(key_name: &str) -> Option<&str> {
    let cut = key_name.len().checked_sub(INNO_KEY_SUFFIX.len())?;
    (cut > 0
        && key_name.is_char_boundary(cut)
        && key_name[cut..].eq_ignore_ascii_case(INNO_KEY_SUFFIX))
    .then(|| &key_name[..cut])
}

/// Whether the arguments carry NSIS's `_?=<dir>` switch (at the start or after whitespace).
pub fn has_nsis_instdir(args: &str) -> bool {
    nsis_instdir_pos(args).is_some()
}

/// Byte offset of NSIS's `_?=` switch in `args`, at the start or after whitespace.
pub(crate) fn nsis_instdir_pos(args: &str) -> Option<usize> {
    args.match_indices("_?=")
        .map(|(i, _)| i)
        .find(|&i| i == 0 || args[..i].ends_with(char::is_whitespace))
}

/// What the uninstaller's bytes say.
fn marker_kind(bytes: &[u8]) -> Option<InstallerKind> {
    let has = |m: &[u8]| bytes.windows(m.len()).any(|w| w == m);
    if NSIS_MARKERS.iter().any(|m| has(m)) {
        Some(InstallerKind::Nsis)
    } else if INNO_MARKERS.iter().any(|m| has(m)) {
        Some(InstallerKind::Inno)
    } else {
        None
    }
}

/// What the uninstaller's file name (and its folder) suggest.
fn name_kind(cmd: &SplitCommand) -> Option<InstallerKind> {
    let name = cmd.file_name().to_ascii_lowercase();
    let is_inno_name = name.len() == "unins000.exe".len()
        && name.starts_with("unins")
        && name.ends_with(".exe")
        && name[5..8].bytes().all(|b| b.is_ascii_digit());
    if is_inno_name {
        return Some(InstallerKind::Inno);
    }
    if name == "uninst.exe" || name == "uninstall.exe" {
        return Some(InstallerKind::Nsis);
    }
    // Mozilla's NSIS uninstaller: `<install dir>\uninstall\helper.exe`.
    let parent = cmd.exe[..cmd.exe.len() - cmd.file_name().len()]
        .trim_end_matches(['\\', '/'])
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("");
    (name == "helper.exe" && parent.eq_ignore_ascii_case("uninstall"))
        .then_some(InstallerKind::Nsis)
}

/// Detects the installer kind of one Uninstall key.
///
/// `exe_bytes` is called at most once, with the uninstaller's path as written in the key (environment
/// variables unexpanded), and returns up to [`EXE_SCAN_BYTES`] leading bytes or `None` when they cannot be
/// read. It is not called for Burn, MSI or Inno-keyed entries.
pub fn detect(
    facts: &KindFacts<'_>,
    exe_bytes: impl FnOnce(&str) -> Option<Vec<u8>>,
) -> KindDetection {
    let done = |kind, basis| KindDetection {
        kind,
        basis,
        product_code: None,
        inno_app_id: None,
    };
    let command = facts.uninstall_string.or(facts.quiet_uninstall_string);

    if facts.has_bundle_values {
        return done(InstallerKind::Burn, KindBasis::BundleValues);
    }

    let guid_key = is_braced_guid(facts.key_name);
    let msi_basis = if facts.windows_installer {
        Some(KindBasis::WindowsInstallerFlag)
    } else if guid_key && command.is_some_and(is_msiexec) {
        Some(KindBasis::GuidKeyWithMsiexec)
    } else {
        None
    };
    if let Some(basis) = msi_basis {
        let product_code = if guid_key {
            Some(facts.key_name.to_ascii_uppercase())
        } else {
            command.and_then(msiexec_product_code)
        };
        return KindDetection {
            product_code,
            ..done(InstallerKind::Msi, basis)
        };
    }

    if let Some(app_id) = strip_inno_suffix(facts.key_name) {
        return KindDetection {
            inno_app_id: Some(app_id.to_owned()),
            ..done(InstallerKind::Inno, KindBasis::InnoKeySuffix)
        };
    }
    if facts.has_inno_values {
        return done(InstallerKind::Inno, KindBasis::InnoValues);
    }

    let Some(cmd) = command.and_then(uninstaller) else {
        return done(InstallerKind::Unknown, KindBasis::Nothing);
    };
    if matches!(cmd.kind(), CommandKind::Other) {
        if let Some(kind) = exe_bytes(&cmd.exe).as_deref().and_then(marker_kind) {
            return done(kind, KindBasis::ExeMarker);
        }
        if has_nsis_instdir(&cmd.args) {
            return done(InstallerKind::Nsis, KindBasis::NsisInstdirArg);
        }
        if let Some(kind) = name_kind(&cmd) {
            return done(kind, KindBasis::UninstallerName);
        }
    }
    done(InstallerKind::Unknown, KindBasis::Nothing)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PC: &str = "{23170F69-40C1-2702-2408-000001000000}";

    fn facts(key: &str, us: Option<&'static str>) -> KindFacts<'static> {
        KindFacts {
            key_name: Box::leak(key.to_owned().into_boxed_str()),
            uninstall_string: us,
            ..KindFacts::default()
        }
    }

    fn no_bytes(_: &str) -> Option<Vec<u8>> {
        None
    }

    #[test]
    fn kind_detection_table() {
        use InstallerKind::*;
        use KindBasis::*;
        let rows: Vec<(KindFacts<'static>, InstallerKind, KindBasis)> = vec![
            // Burn wins over everything else.
            (
                KindFacts {
                    has_bundle_values: true,
                    windows_installer: true,
                    ..facts(
                        "{e9b7c837-5066-4f10-851a-69179f987b18}",
                        Some("\"C:\\pc\\py.exe\" /uninstall"),
                    )
                },
                Burn,
                BundleValues,
            ),
            (
                KindFacts {
                    windows_installer: true,
                    ..facts(
                        "Office16",
                        Some("MsiExec.exe /X{90160000-008C-0000-1000-0000000FF1CE}"),
                    )
                },
                Msi,
                WindowsInstallerFlag,
            ),
            (
                facts(
                    PC,
                    Some("MsiExec.exe /I{23170F69-40C1-2702-2408-000001000000}"),
                ),
                Msi,
                GuidKeyWithMsiexec,
            ),
            // A GUID key without msiexec is not MSI.
            (
                facts(
                    "{0b5169e3-39da-4313-808e-1f9c0407f3bf}",
                    Some("\"C:\\x\\setup.exe\" /uninstall"),
                ),
                Unknown,
                Nothing,
            ),
            (
                facts("Git_is1", Some("\"C:\\Program Files\\Git\\unins000.exe\"")),
                Inno,
                InnoKeySuffix,
            ),
            (
                facts(
                    "{EA457B21-F73E-494C-ACAB-524FDE069978}_IS1",
                    Some("\"C:\\VS Code\\unins000.exe\""),
                ),
                Inno,
                InnoKeySuffix,
            ),
            (
                KindFacts {
                    has_inno_values: true,
                    ..facts("SomeApp", Some("\"C:\\A\\unins000.exe\""))
                },
                Inno,
                InnoValues,
            ),
            (
                facts("Thing", Some("\"C:\\T\\remove.exe\" _?=C:\\T")),
                Nsis,
                NsisInstdirArg,
            ),
            (
                facts(
                    "Mozilla Firefox",
                    Some("\"C:\\Program Files\\Mozilla Firefox\\uninstall\\helper.exe\""),
                ),
                Nsis,
                UninstallerName,
            ),
            (
                facts(
                    "Notepad++",
                    Some("\"C:\\Program Files\\Notepad++\\uninstall.exe\""),
                ),
                Nsis,
                UninstallerName,
            ),
            (
                facts(
                    "VBox",
                    Some("C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\uninst.exe"),
                ),
                Nsis,
                UninstallerName,
            ),
            (
                facts("OldInno", Some("\"C:\\Old\\unins001.exe\"")),
                Inno,
                UninstallerName,
            ),
            // `helper.exe` outside an `uninstall` folder says nothing.
            (
                facts("Other", Some("\"C:\\Other\\helper.exe\"")),
                Unknown,
                Nothing,
            ),
            (
                facts(
                    "Edge",
                    Some("\"C:\\Edge\\setup.exe\" --uninstall --system-level"),
                ),
                Unknown,
                Nothing,
            ),
            (facts("NoCommand", None), Unknown, Nothing),
            // `_is1` alone is not an AppId.
            (facts("_is1", Some("x.exe")), Unknown, Nothing),
        ];
        for (f, kind, basis) in rows {
            let d = detect(&f, no_bytes);
            assert_eq!((d.kind, d.basis), (kind, basis), "{f:?}");
        }
    }

    #[test]
    fn product_code_and_app_id() {
        let d = detect(
            &facts(
                &PC.to_ascii_lowercase(),
                Some("msiexec /x {23170f69-40c1-2702-2408-000001000000}"),
            ),
            no_bytes,
        );
        assert_eq!(d.product_code.as_deref(), Some(PC));
        // A non-GUID key takes the code from the msiexec command, whatever the spacing.
        let f = KindFacts {
            windows_installer: true,
            ..facts(
                "Product",
                Some("MsiExec.exe   /I   {23170f69-40c1-2702-2408-000001000000}"),
            )
        };
        assert_eq!(detect(&f, no_bytes).product_code.as_deref(), Some(PC));
        let d = detect(&facts("Git_is1", Some("unins000.exe")), no_bytes);
        assert_eq!(d.inno_app_id.as_deref(), Some("Git"));
        assert_eq!(d.product_code, None);
        let d = detect(
            &facts("{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1", None),
            no_bytes,
        );
        assert_eq!(
            d.inno_app_id.as_deref(),
            Some("{771FD6B0-FA20-440A-A002-3B3BAC16DC50}")
        );
    }

    #[test]
    fn exe_markers_beat_names() {
        let mut nsis = vec![0u8; 100];
        nsis.extend_from_slice(b"<assemblyIdentity name=\"Nullsoft.NSIS.exehead\"/>");
        let mut inno = vec![1u8; 10];
        inno.extend_from_slice(b"name=\"JR.Inno.Setup\"");
        let f = facts("App", Some("\"C:\\App\\remove.exe\" /x"));
        let mut seen = None;
        let d = detect(&f, |p| {
            seen = Some(p.to_owned());
            Some(nsis.clone())
        });
        assert_eq!(
            (d.kind, d.basis),
            (InstallerKind::Nsis, KindBasis::ExeMarker)
        );
        assert_eq!(seen.as_deref(), Some("C:\\App\\remove.exe"));
        // Bytes win over a misleading name.
        let f = facts("App", Some("\"C:\\App\\uninstall.exe\""));
        let d = detect(&f, |_| Some(inno.clone()));
        assert_eq!(
            (d.kind, d.basis),
            (InstallerKind::Inno, KindBasis::ExeMarker)
        );
        // Readable bytes without a marker fall back to the name.
        let d = detect(&f, |_| Some(vec![0; 64]));
        assert_eq!(
            (d.kind, d.basis),
            (InstallerKind::Nsis, KindBasis::UninstallerName)
        );
        // MSI keys never read the uninstaller.
        let d = detect(
            &facts(
                PC,
                Some("MsiExec.exe /X{23170F69-40C1-2702-2408-000001000000}"),
            ),
            |_| panic!("probe called"),
        );
        assert_eq!(d.kind, InstallerKind::Msi);
    }

    #[test]
    fn helpers() {
        assert!(is_braced_guid(PC));
        assert!(!is_braced_guid(&PC[1..]));
        assert!(!is_braced_guid(
            "{23170F69-40C1-2702-2408-000001000000}_is1"
        ));
        assert_eq!(strip_inno_suffix("A_IS1"), Some("A"));
        assert_eq!(strip_inno_suffix("A"), None);
        assert_eq!(strip_inno_suffix("é_is1"), Some("é"));
        assert!(has_nsis_instdir("_?=C:\\x"));
        assert!(has_nsis_instdir("/S _?=C:\\x"));
        assert!(!has_nsis_instdir("/D=a_?=b"));
        assert_eq!(
            msiexec_product_code("notmsi.exe {23170F69-40C1-2702-2408-000001000000}"),
            None
        );
    }
}
