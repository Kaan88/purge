//! Canonical key path → (physical root, subpath, WOW64 view), the registry half of gate G1 (ENGINE_PLAN.md
//! §5.10) as the Live source applies it.
//!
//! Input is a canonical key string (`HKLM\…`, `HKU\<SID>\…`, `HKU\<SID>_Classes\…`; the long root names
//! `HKEY_LOCAL_MACHINE` / `HKEY_USERS` are accepted too). The rules, in order:
//!
//! 1. `HKLM\SYSTEM\CurrentControlSet\…` → `HKLM\SYSTEM\ControlSet00N\…` (`N` from `SYSTEM\Select\Current`).
//!    `CurrentControlSet` is a registry link that `purge-win` refuses to traverse.
//! 2. `HKU\<SID>\Software\Classes\<more>` → `HKU\<SID>_Classes\<more>`: the physical classes hive.
//!    `HKU\<SID>\Software\Classes` itself is left alone, so it is opened (and reported) as the link it is.
//! 3. The `WOW6432Node` segment is read the way [`TypedTarget`] reads it, i.e. only where Windows redirects:
//!    `HKLM\SOFTWARE\WOW6432Node\X` → `SOFTWARE\X` opened with `KEY_WOW64_32KEY`, and
//!    `HKU\<SID>_Classes\WOW6432Node\X` → `<SID>_Classes\X` with `KEY_WOW64_32KEY`. The redirector then
//!    resolves redirected keys to their `WOW6432Node` storage and shared keys (`SOFTWARE\Classes\.txt`,
//!    the `Policies` link, …) to the 64-bit key, exactly as a 32-bit process would see them. The bare
//!    redirection node (`HKLM\SOFTWARE\WOW6432Node`, `HKU\<SID>_Classes\WOW6432Node`) is opened physically
//!    in the 64-bit view, because a 32-bit open of a hive root or of `SOFTWARE\Classes` is not redirected.
//!    Elsewhere (`HKU\<SID>\Software\WOW6432Node`, `HKLM\SOFTWARE\Classes\WOW6432Node`) the segment is an
//!    ordinary key read in the 64-bit view.
//!
//! `HKCU`, `HKCR` and `HKCC` are not canonical (they are per-process aliases or merged views) and are
//! refused with [`SourceError::InvalidPath`].

use purge_model::{Hive, TypedTarget, View};
use purge_win::reg::{RegRoot, RegView};

use crate::registry::{map_current_control_set, split_key};
use crate::types::{SourceError, SourceResult};

/// The spelling of the redirection node.
const WOW_NODE: &str = "WOW6432Node";
/// Suffix of a user's classes hive under `HKEY_USERS`.
const CLASSES_SUFFIX: &str = "_Classes";

/// Where a canonical key path is opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegLocation {
    /// The physical root.
    pub root: RegRoot,
    /// The path below the root (empty for the root itself).
    pub path: String,
    /// The view passed on every open.
    pub view: RegView,
}

impl RegLocation {
    fn new(root: RegRoot, path: impl Into<String>, view: RegView) -> Self {
        Self {
            root,
            path: path.into(),
            view,
        }
    }
}

fn eq_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn ends_with_ci(s: &str, suffix: &str) -> bool {
    let cut = s.len().saturating_sub(suffix.len());
    s.len() > suffix.len() && s.is_char_boundary(cut) && s[cut..].eq_ignore_ascii_case(suffix)
}

fn invalid(key: &str, why: &str) -> SourceError {
    SourceError::InvalidPath(format!("{key}: {why}"))
}

/// Translates a canonical key path. `control_set` is asked for `N` of `ControlSet00N` only when the path
/// goes through `HKLM\SYSTEM\CurrentControlSet`.
pub(crate) fn translate_key(
    key: &str,
    control_set: impl FnOnce() -> SourceResult<u32>,
) -> SourceResult<RegLocation> {
    if key.chars().any(char::is_control) {
        return Err(invalid(key, "control character in key path"));
    }
    let mut segs: Vec<String> = split_key(key).into_iter().map(String::from).collect();
    let Some(first) = segs.first() else {
        return Err(invalid(key, "empty key path"));
    };
    let machine = match first.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => true,
        "HKU" | "HKEY_USERS" => false,
        "HKCU"
        | "HKEY_CURRENT_USER"
        | "HKCR"
        | "HKEY_CLASSES_ROOT"
        | "HKCC"
        | "HKEY_CURRENT_CONFIG" => {
            return Err(invalid(
                key,
                "not a canonical root (use HKLM, HKU\\<SID> or HKU\\<SID>_Classes)",
            ));
        }
        _ => return Err(invalid(key, "unknown registry root")),
    };
    segs[0] = if machine { "HKLM" } else { "HKU" }.to_owned();

    if machine {
        if segs.len() >= 3 && eq_ci(&segs[1], "SYSTEM") && eq_ci(&segs[2], "CurrentControlSet") {
            map_current_control_set(&mut segs, control_set()?);
        }
    } else {
        if segs.len() == 1 {
            return Ok(RegLocation::new(RegRoot::Hku, "", RegView::K64));
        }
        if segs.len() > 4
            && !ends_with_ci(&segs[1], CLASSES_SUFFIX)
            && eq_ci(&segs[2], "Software")
            && eq_ci(&segs[3], "Classes")
        {
            let hive = format!("{}{CLASSES_SUFFIX}", segs[1]);
            segs.splice(1..4, [hive]);
        }
    }

    let joined = segs.join("\\");
    let (hive, view, path) =
        TypedTarget::parse_key_path(&joined).map_err(|e| invalid(key, &e.to_string()))?;
    Ok(match (hive, view) {
        (Hive::Hklm, View::K64) => RegLocation::new(RegRoot::Hklm, path, RegView::K64),
        // `path` is `SOFTWARE` or `SOFTWARE\…`; the bare node is opened physically.
        (Hive::Hklm, View::K32) if eq_ci(&path, "SOFTWARE") => {
            RegLocation::new(RegRoot::Hklm, format!("{path}\\{WOW_NODE}"), RegView::K64)
        }
        (Hive::Hklm, View::K32) => RegLocation::new(RegRoot::Hklm, path, RegView::K32),
        (Hive::Hku(sid), _) => RegLocation::new(RegRoot::Hku, join(&sid, &path), RegView::K64),
        (Hive::HkuClasses(sid), View::K64) => RegLocation::new(
            RegRoot::Hku,
            join(&format!("{sid}{CLASSES_SUFFIX}"), &path),
            RegView::K64,
        ),
        (Hive::HkuClasses(sid), View::K32) if path.is_empty() => RegLocation::new(
            RegRoot::Hku,
            format!("{sid}{CLASSES_SUFFIX}\\{WOW_NODE}"),
            RegView::K64,
        ),
        (Hive::HkuClasses(sid), View::K32) => RegLocation::new(
            RegRoot::Hku,
            join(&format!("{sid}{CLASSES_SUFFIX}"), &path),
            RegView::K32,
        ),
    })
}

fn join(head: &str, tail: &str) -> String {
    if tail.is_empty() {
        head.to_owned()
    } else {
        format!("{head}\\{tail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "S-1-5-21-1-2-3-1001";

    fn t(key: &str) -> SourceResult<RegLocation> {
        translate_key(key, || Ok(2))
    }

    fn loc(root: RegRoot, path: &str, view: RegView) -> RegLocation {
        RegLocation::new(root, path, view)
    }

    /// The canonical path translation table.
    #[test]
    fn translation_table() {
        use RegRoot::{Hklm, Hku};
        use RegView::{K32, K64};
        let cases: Vec<(String, RegLocation)> = vec![
            ("HKLM".into(), loc(Hklm, "", K64)),
            ("HKU".into(), loc(Hku, "", K64)),
            (
                r"HKLM\SOFTWARE\Vendor\App".into(),
                loc(Hklm, r"SOFTWARE\Vendor\App", K64),
            ),
            (
                r"HKEY_LOCAL_MACHINE\SOFTWARE\X\".into(),
                loc(Hklm, r"SOFTWARE\X", K64),
            ),
            // Redirected 32-bit view.
            (
                r"HKLM\SOFTWARE\WOW6432Node\Vendor\App".into(),
                loc(Hklm, r"SOFTWARE\Vendor\App", K32),
            ),
            (
                r"hklm\software\wow6432node\Microsoft\Windows\CurrentVersion\Uninstall".into(),
                loc(
                    Hklm,
                    r"software\Microsoft\Windows\CurrentVersion\Uninstall",
                    K32,
                ),
            ),
            (
                r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{X}".into(),
                loc(Hklm, r"SOFTWARE\Classes\CLSID\{X}", K32),
            ),
            // The node itself is physical.
            (
                r"HKLM\SOFTWARE\WOW6432Node".into(),
                loc(Hklm, r"SOFTWARE\WOW6432Node", K64),
            ),
            // The Classes alias is an ordinary physical key.
            (
                r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID".into(),
                loc(Hklm, r"SOFTWARE\Classes\WOW6432Node\CLSID", K64),
            ),
            // Not redirected outside SOFTWARE.
            (
                r"HKLM\SYSTEM\WOW6432Node".into(),
                loc(Hklm, r"SYSTEM\WOW6432Node", K64),
            ),
            // CurrentControlSet.
            (
                r"HKLM\SYSTEM\CurrentControlSet\Services\x".into(),
                loc(Hklm, r"SYSTEM\ControlSet002\Services\x", K64),
            ),
            (
                r"HKLM\SYSTEM\ControlSet001\Services".into(),
                loc(Hklm, r"SYSTEM\ControlSet001\Services", K64),
            ),
            (
                r"HKLM\SOFTWARE\CurrentControlSet".into(),
                loc(Hklm, r"SOFTWARE\CurrentControlSet", K64),
            ),
            // User hives.
            (
                format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Run"),
                loc(
                    Hku,
                    &format!(r"{SID}\Software\Microsoft\Windows\CurrentVersion\Run"),
                    K64,
                ),
            ),
            (
                format!(r"HKEY_USERS\{SID}\Software\WOW6432Node\Vendor"),
                loc(Hku, &format!(r"{SID}\Software\WOW6432Node\Vendor"), K64),
            ),
            (format!(r"HKU\{SID}"), loc(Hku, SID, K64)),
            // Software\Classes: the link key itself, then the physical hive below it.
            (
                format!(r"HKU\{SID}\Software\Classes"),
                loc(Hku, &format!(r"{SID}\Software\Classes"), K64),
            ),
            (
                format!(r"HKU\{SID}\Software\Classes\.txt"),
                loc(Hku, &format!(r"{SID}_Classes\.txt"), K64),
            ),
            (
                format!(r"HKU\{SID}\software\classes\Wow6432Node\CLSID\{{X}}"),
                loc(Hku, &format!(r"{SID}_Classes\CLSID\{{X}}"), K32),
            ),
            (
                format!(r"HKU\{SID}_Classes\CLSID\{{X}}"),
                loc(Hku, &format!(r"{SID}_Classes\CLSID\{{X}}"), K64),
            ),
            (
                format!(r"HKU\{SID}_Classes\WOW6432Node\CLSID\{{X}}"),
                loc(Hku, &format!(r"{SID}_Classes\CLSID\{{X}}"), K32),
            ),
            (
                format!(r"HKU\{SID}_Classes\WOW6432Node"),
                loc(Hku, &format!(r"{SID}_Classes\WOW6432Node"), K64),
            ),
            (
                format!(r"HKU\{SID}_Classes"),
                loc(Hku, &format!("{SID}_Classes"), K64),
            ),
            // A `_Classes` hive is not rewritten again.
            (
                format!(r"HKU\{SID}_Classes\Software\Classes\x"),
                loc(Hku, &format!(r"{SID}_Classes\Software\Classes\x"), K64),
            ),
            (
                r"HKU\.DEFAULT\Software".into(),
                loc(Hku, r".DEFAULT\Software", K64),
            ),
        ];
        for (key, want) in cases {
            assert_eq!(t(&key).as_ref(), Ok(&want), "{key}");
        }
    }

    #[test]
    fn rejected_roots_and_forms() {
        for key in [
            "",
            "\\",
            r"HKCU\Software\X",
            r"HKEY_CURRENT_USER\Software",
            r"HKCR\.txt",
            r"HKCC\System",
            r"C:\Program Files",
            "HKLMX\\a",
            "HKLM\\a\u{0}b",
        ] {
            assert!(
                matches!(t(key), Err(SourceError::InvalidPath(_))),
                "{key:?} -> {:?}",
                t(key)
            );
        }
    }

    #[test]
    fn control_set_is_asked_only_when_needed() {
        let never = || -> SourceResult<u32> { panic!("control set asked") };
        assert!(translate_key(r"HKLM\SOFTWARE\X", never).is_ok());
        assert_eq!(
            translate_key(r"HKLM\SYSTEM\CurrentControlSet", || Err(
                SourceError::AccessDenied
            )),
            Err(SourceError::AccessDenied)
        );
    }
}
