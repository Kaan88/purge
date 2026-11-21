//! The `$(…)` macros of component manifests, expanded for drive `C:` (BASELINE_LOCAL_DESIGN.md §3.2).
//!
//! Component manifests name file and directory destinations, and now and then a key or value name,
//! with macros such as `$(runtime.system32)`. The baselines record paths on drive `C:` (the capture's
//! convention, [`crate::baseline::Baseline::path_in_scope`]), so the table expands every macro for `C:`.
//!
//! # The table
//!
//! [`MACROS`] holds the eighteen macros the design lists. Names compare ASCII case-insensitively
//! (`$(runtime.programFiles)` and `$(runtime.ProgramFiles)` are one macro). A manifest of the 32-bit
//! view ([`View::Wow64`]: `processorArchitecture` `wow64` or `x86`) reads `system32` as `SysWOW64` and
//! `programFiles` as `Program Files (x86)`, as the design says; the two macros that are spelled below
//! those directories follow them (`wbem` is `SysWOW64\wbem`, `commonFiles` is
//! `Program Files (x86)\Common Files`). Every other macro has one meaning in both views.
//!
//! `runtime.userProfile` has two expansions: the default profile `C:\Users\Default`, which is where
//! servicing puts profile content, and the profile of any user (`C:\Users\<user>`, the
//! [`USER_PLACEHOLDER`] the baseline normaliser also writes), because every profile is copied from the
//! default one. Both only add to what counts as Windows' own (L1).
//!
//! Anything else in `$(…)`, including a `$(` that is never closed, is an unknown macro: the caller
//! skips that name and counts it ([`Unknown`]). The local baseline's measurement (BL-MEASURE) lists
//! every macro found on the rig machines; the table grows from that list.

use std::borrow::Cow;

use crate::baseline::USER_PLACEHOLDER;

/// Which registry and file-system view a manifest is installed in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum View {
    /// The native (64-bit) view: `amd64`, `msil`, `neutral`, … manifests.
    #[default]
    Native,
    /// The 32-bit view of a 64-bit Windows: `wow64` and `x86` manifests.
    Wow64,
}

impl View {
    /// The view of a manifest whose `assemblyIdentity` has this `processorArchitecture`.
    pub fn of_architecture(architecture: &str) -> View {
        if architecture.eq_ignore_ascii_case("wow64") || architecture.eq_ignore_ascii_case("x86") {
            View::Wow64
        } else {
            View::Native
        }
    }
}

const WINDOWS: &str = r"C:\Windows";
const SYSTEM32: &str = r"C:\Windows\System32";
const SYSWOW64: &str = r"C:\Windows\SysWOW64";
const PROGRAM_FILES: &str = r"C:\Program Files";
const PROGRAM_FILES_X86: &str = r"C:\Program Files (x86)";

/// The macro names of the table, as the design spells them (without `$(` and `)`).
pub const MACROS: [&str; 18] = [
    "runtime.windows",
    "runtime.system32",
    "runtime.drivers",
    "runtime.fonts",
    "runtime.inf",
    "runtime.wbem",
    "runtime.programFiles",
    "runtime.programFilesX86",
    "runtime.commonFiles",
    "runtime.commonFilesX86",
    "runtime.programData",
    "runtime.bootDrive",
    "runtime.systemRoot",
    "runtime.help",
    "runtime.userProfile",
    "runtime.public",
    "runtime.startMenu",
    "runtime.documentsSettings",
];

/// The expansions of one macro in one view, or `None` when the macro is not in the table.
///
/// Every expansion is an absolute path on drive `C:` without a trailing separator.
pub fn lookup(name: &str, view: View) -> Option<Vec<Cow<'static, str>>> {
    let index = MACROS.iter().position(|m| m.eq_ignore_ascii_case(name))?;
    let wow = view == View::Wow64;
    let one = |s: &'static str| Some(vec![Cow::Borrowed(s)]);
    let joined = |base: &str, rest: &str| Some(vec![Cow::Owned(format!(r"{base}\{rest}"))]);
    let system32 = if wow { SYSWOW64 } else { SYSTEM32 };
    let program_files = if wow {
        PROGRAM_FILES_X86
    } else {
        PROGRAM_FILES
    };
    match MACROS[index] {
        "runtime.windows" | "runtime.systemRoot" => one(WINDOWS),
        "runtime.system32" => one(system32),
        "runtime.drivers" => one(r"C:\Windows\System32\drivers"),
        "runtime.fonts" => one(r"C:\Windows\Fonts"),
        "runtime.inf" => one(r"C:\Windows\INF"),
        "runtime.wbem" => joined(system32, "wbem"),
        "runtime.programFiles" => one(program_files),
        "runtime.programFilesX86" => one(PROGRAM_FILES_X86),
        "runtime.commonFiles" => joined(program_files, "Common Files"),
        "runtime.commonFilesX86" => one(r"C:\Program Files (x86)\Common Files"),
        "runtime.programData" => one(r"C:\ProgramData"),
        "runtime.bootDrive" => one("C:"),
        "runtime.help" => one(r"C:\Windows\Help"),
        "runtime.userProfile" => Some(vec![
            Cow::Borrowed(r"C:\Users\Default"),
            Cow::Owned(format!(r"C:\Users\{USER_PLACEHOLDER}")),
        ]),
        "runtime.public" => one(r"C:\Users\Public"),
        "runtime.startMenu" => one(r"C:\ProgramData\Microsoft\Windows\Start Menu"),
        "runtime.documentsSettings" => one(r"C:\Users"),
        _ => None,
    }
}

/// A `$(…)` that is not in the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unknown {
    /// The text between `$(` and `)`, or everything after a `$(` that is never closed; at most
    /// [`MAX_MACRO_NAME`] bytes (cut on a character boundary).
    pub name: String,
}

/// The longest unknown macro name kept in [`Unknown::name`].
pub const MAX_MACRO_NAME: usize = 64;

/// The most expansions [`expand`] returns for one text; more is reported as [`Unknown`]
/// (`runtime.userProfile` is the only macro with two, so this is a bound, never met by a real name).
pub const MAX_EXPANSIONS: usize = 8;

/// Whether `text` holds a `$(`.
pub fn has_macro(text: &str) -> bool {
    text.contains("$(")
}

/// Expands every macro of `text` in `view`.
///
/// A text without `$(` comes back unchanged as its only expansion. A text with a macro that has two
/// expansions comes back twice, once with each (and so on for several; at most [`MAX_EXPANSIONS`]).
/// The first macro that is not in the table makes the whole text [`Unknown`].
pub fn expand(text: &str, view: View) -> Result<Vec<String>, Unknown> {
    let mut out = vec![String::with_capacity(text.len())];
    let mut rest = text;
    while let Some(at) = rest.find("$(") {
        let literal = &rest[..at];
        for o in &mut out {
            o.push_str(literal);
        }
        let after = &rest[at + 2..];
        let Some(close) = after.find(')') else {
            return Err(unknown(after));
        };
        let name = &after[..close];
        let Some(values) = lookup(name, view) else {
            return Err(unknown(name));
        };
        if out.len() * values.len() > MAX_EXPANSIONS {
            return Err(unknown(name));
        }
        out = out
            .iter()
            .flat_map(|o| values.iter().map(move |v| format!("{o}{v}")))
            .collect();
        rest = &after[close + 1..];
    }
    for o in &mut out {
        o.push_str(rest);
    }
    Ok(out)
}

fn unknown(name: &str) -> Unknown {
    let mut end = name.len().min(MAX_MACRO_NAME);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    Unknown {
        name: name[..end].to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_macro_expands_in_both_views() {
        for name in MACROS {
            for view in [View::Native, View::Wow64] {
                let values = lookup(name, view).unwrap_or_else(|| panic!("{name}"));
                assert!(!values.is_empty());
                for v in values {
                    assert!(v.starts_with("C:"), "{name}: {v}");
                    assert!(!v.ends_with('\\'), "{name}: {v}");
                }
            }
        }
        assert!(lookup("runtime.nope", View::Native).is_none());
        assert!(lookup("", View::Native).is_none());
    }

    #[test]
    fn the_32_bit_view_moves_system32_and_program_files_only() {
        let one = |name: &str, view| {
            let v = lookup(name, view).unwrap();
            assert_eq!(v.len(), 1);
            v[0].clone().into_owned()
        };
        assert_eq!(
            one("runtime.system32", View::Native),
            r"C:\Windows\System32"
        );
        assert_eq!(one("runtime.system32", View::Wow64), r"C:\Windows\SysWOW64");
        assert_eq!(
            one("runtime.wbem", View::Wow64),
            r"C:\Windows\SysWOW64\wbem"
        );
        assert_eq!(
            one("runtime.programFiles", View::Native),
            r"C:\Program Files"
        );
        assert_eq!(
            one("runtime.programFiles", View::Wow64),
            r"C:\Program Files (x86)"
        );
        assert_eq!(
            one("runtime.commonFiles", View::Wow64),
            r"C:\Program Files (x86)\Common Files"
        );
        for name in MACROS {
            if matches!(
                name,
                "runtime.system32"
                    | "runtime.wbem"
                    | "runtime.programFiles"
                    | "runtime.commonFiles"
            ) {
                continue;
            }
            assert_eq!(
                lookup(name, View::Native),
                lookup(name, View::Wow64),
                "{name}"
            );
        }
    }

    #[test]
    fn expansion() {
        let n = View::Native;
        assert_eq!(expand(r"a\b", n).unwrap(), vec![r"a\b"]);
        assert_eq!(
            expand(r"$(runtime.system32)\drivers\x.sys", n).unwrap(),
            vec![r"C:\Windows\System32\drivers\x.sys"]
        );
        assert_eq!(
            expand(r"$(RUNTIME.SYSTEM32)\x", View::Wow64).unwrap(),
            vec![r"C:\Windows\SysWOW64\x"]
        );
        assert_eq!(
            expand(r"$(runtime.bootDrive)\bootmgr", n).unwrap(),
            vec![r"C:\bootmgr"]
        );
        assert_eq!(
            expand(r"$(runtime.userProfile)\Favorites", n).unwrap(),
            vec![
                r"C:\Users\Default\Favorites".to_owned(),
                format!(r"C:\Users\{USER_PLACEHOLDER}\Favorites")
            ]
        );
        assert_eq!(
            expand(r"x$(runtime.windows)y$(runtime.inf)z", n).unwrap(),
            vec![r"xC:\WindowsyC:\Windows\INFz"]
        );
        assert_eq!(
            expand(r"$(runtime.nope)\x", n),
            Err(Unknown {
                name: "runtime.nope".into()
            })
        );
        assert_eq!(
            expand(r"$(runtime.system32\x", n),
            Err(Unknown {
                name: r"runtime.system32\x".into()
            })
        );
        assert_eq!(
            expand("$(", n),
            Err(Unknown {
                name: String::new()
            })
        );
        // `$` alone and `(` alone are text.
        assert_eq!(expand("a$b(c)", n).unwrap(), vec!["a$b(c)"]);
    }

    #[test]
    fn expansion_is_bounded() {
        let many = r"$(runtime.userProfile)".repeat(4);
        assert_eq!(
            expand(&many, View::Native).unwrap_err().name,
            "runtime.userProfile"
        );
        let three = r"$(runtime.userProfile)".repeat(3);
        assert_eq!(expand(&three, View::Native).unwrap().len(), 8);
        let long = format!("$({})", "é".repeat(100));
        let e = expand(&long, View::Native).unwrap_err();
        assert!(e.name.len() <= MAX_MACRO_NAME && e.name.starts_with('é'));
    }

    #[test]
    fn architectures() {
        assert_eq!(View::of_architecture("wow64"), View::Wow64);
        assert_eq!(View::of_architecture("X86"), View::Wow64);
        for a in ["amd64", "msil", "arm64", "neutral", "*", "", "x86_64"] {
            assert_eq!(View::of_architecture(a), View::Native, "{a}");
        }
    }
}
