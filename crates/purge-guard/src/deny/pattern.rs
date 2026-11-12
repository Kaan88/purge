//! Segment patterns shared by the deny-list, the shared-component rules and the container table.
//!
//! A pattern is a list of segments. A segment is a literal name, or a glob in which `*` matches any run
//! of characters inside one segment (never a separator). `[*]` is the literal name `*` (the
//! `HKCR\*` key). Matching is case-insensitive: both sides are folded with [`crate::prefix::fold`].
//!
//! File patterns start with a drive (`C:`, `*:` for any drive) or one whitelisted token that expands from
//! the [`GuardEnv`], several ways when it names several directories:
//! `%WINDIR%`, `%SystemDrive%`, `%ProgramFiles%` (native and x86), `%CommonProgramFiles%` (both),
//! `%ProgramData%`, `%PROFILES%` (the profiles directory), and the per-profile `%USERPROFILE%`,
//! `%APPDATA%`, `%LOCALAPPDATA%` (the default layout of any profile directory, plus the actual folders of
//! every profile in the `GuardEnv`).
//!
//! Key patterns start with `HKLM\`, `HKU\*\` (any user hive), `*\` (either) or `HKCR\` (the Classes root
//! of the machine or of any user). They are view-agnostic and never spell `WOW6432Node`; a
//! `CurrentControlSet` segment matches every control set. A user's `Software\Classes` matches both
//! `HKU\*\SOFTWARE\Classes\...` and `HKCR\...` patterns.

use crate::canon::{GuardEnv, ProfileEnv};
use crate::prefix::{SEP, fold};

/// One pattern segment (already folded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Seg {
    Lit(String),
    Glob(String),
}

impl Seg {
    pub(crate) fn parse(s: &str) -> Seg {
        if s == "[*]" {
            Seg::Lit("*".into())
        } else if s.contains('*') {
            Seg::Glob(fold(s))
        } else {
            Seg::Lit(fold(s))
        }
    }

    pub(crate) fn any() -> Seg {
        Seg::Glob("*".into())
    }

    fn matches(&self, folded: &str) -> bool {
        match self {
            Seg::Lit(lit) => lit == folded,
            Seg::Glob(glob) => glob_match(glob, folded),
        }
    }
}

/// `*` matches any run of characters; everything else is literal.
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let mut backtrack: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            backtrack = Some((pi, ti));
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some((star, at)) = backtrack {
            pi = star + 1;
            ti = at + 1;
            backtrack = Some((star, at + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// How a target relates to a pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rel {
    /// The target is the pattern's item.
    Exact,
    /// The target is below it.
    Inside,
    /// The target is above it. `literal`: every pattern segment the target matched is a literal, so the
    /// target is an ancestor of every item the pattern can name.
    Ancestor { literal: bool },
}

pub(crate) fn relate(pattern: &[Seg], target: &[String]) -> Option<Rel> {
    let shared = pattern.len().min(target.len());
    if !pattern[..shared]
        .iter()
        .zip(target)
        .all(|(p, t)| p.matches(t))
    {
        return None;
    }
    Some(match target.len().cmp(&pattern.len()) {
        std::cmp::Ordering::Equal => Rel::Exact,
        std::cmp::Ordering::Greater => Rel::Inside,
        std::cmp::Ordering::Less => Rel::Ancestor {
            literal: pattern[..shared].iter().all(|p| matches!(p, Seg::Lit(_))),
        },
    })
}

/// The folded segments of a canonical path or key.
pub(crate) fn split_fold(path: &str) -> Vec<String> {
    path.split(SEP)
        .filter(|s| !s.is_empty())
        .map(fold)
        .collect()
}

/// A concrete path from the `GuardEnv` as an all-literal pattern.
pub(crate) fn literal(path: &str) -> Vec<Seg> {
    split_fold(path).into_iter().map(Seg::Lit).collect()
}

/// Which registry locations a key pattern applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyBase {
    Hklm,
    Hku,
    Any,
    Classes,
}

pub(crate) fn parse_key_pattern(pattern: &str) -> Result<(KeyBase, Vec<Seg>), String> {
    let segs: Vec<&str> = pattern.split(SEP).filter(|s| !s.is_empty()).collect();
    let bad = |why: &str| Err(format!("key pattern {pattern:?}: {why}"));
    let (base, rest) = match segs.split_first() {
        Some((root, rest)) if root.eq_ignore_ascii_case("HKLM") => (KeyBase::Hklm, rest),
        Some((root, rest)) if root.eq_ignore_ascii_case("HKCR") => (KeyBase::Classes, rest),
        Some((root, rest)) if *root == "*" => (KeyBase::Any, rest),
        Some((root, rest)) if root.eq_ignore_ascii_case("HKU") => match rest.split_first() {
            Some((sid, rest)) if *sid == "*" => (KeyBase::Hku, rest),
            _ => return bad("HKU must be followed by `*`"),
        },
        _ => return bad("must start with HKLM, HKU\\*, * or HKCR"),
    };
    if base != KeyBase::Hku && rest.iter().any(|s| s.eq_ignore_ascii_case("WOW6432Node")) {
        return bad("patterns are view-agnostic and must not spell WOW6432Node");
    }
    let segs = rest
        .iter()
        .map(|s| {
            if s.eq_ignore_ascii_case("CurrentControlSet") {
                Seg::Glob("controlset*".into())
            } else {
                Seg::parse(s)
            }
        })
        .collect();
    Ok((base, segs))
}

/// Expands a file pattern into one segment list per directory its leading token names.
pub(crate) fn parse_fs_pattern(pattern: &str, env: &GuardEnv) -> Result<Vec<Vec<Seg>>, String> {
    let (head, tail) = pattern.split_once(SEP).unwrap_or((pattern, ""));
    let tail: Vec<Seg> = tail
        .split(SEP)
        .filter(|s| !s.is_empty())
        .map(Seg::parse)
        .collect();
    let bases: Vec<Vec<Seg>> = if head.starts_with('%') {
        token_bases(head, env).ok_or_else(|| format!("file pattern {pattern:?}: unknown token"))?
    } else if head.chars().count() == 2 && head.ends_with(':') {
        vec![vec![Seg::parse(head)]]
    } else {
        return Err(format!(
            "file pattern {pattern:?}: must start with a drive or a token"
        ));
    };
    Ok(bases
        .into_iter()
        .map(|mut base| {
            base.extend(tail.iter().cloned());
            base
        })
        .collect())
}

fn token_bases(token: &str, env: &GuardEnv) -> Option<Vec<Vec<Seg>>> {
    fn one(path: &str) -> Vec<Vec<Seg>> {
        if path.trim().is_empty() {
            Vec::new()
        } else {
            vec![literal(path)]
        }
    }
    // The default layout below any directory of the profiles folder, then each profile's real folder.
    let per_profile = |default_tail: &[&str], pick: fn(&ProfileEnv) -> &str| {
        let mut out = Vec::new();
        if !env.profiles_dir.trim().is_empty() {
            let mut segs = literal(&env.profiles_dir);
            segs.push(Seg::any());
            segs.extend(default_tail.iter().map(|s| Seg::parse(s)));
            out.push(segs);
        }
        out.extend(env.profiles.iter().flat_map(|p| one(pick(p))));
        out
    };
    Some(match token.to_ascii_uppercase().as_str() {
        "%WINDIR%" => one(&env.windir),
        "%SYSTEMDRIVE%" => one(&env.system_drive),
        "%PROGRAMDATA%" => one(&env.program_data),
        "%PROFILES%" => one(&env.profiles_dir),
        "%PROGRAMFILES%" => env.program_files_dirs().flat_map(one).collect(),
        "%COMMONPROGRAMFILES%" => env
            .program_files_dirs()
            .flat_map(|pf| one(&format!("{pf}\\Common Files")))
            .collect(),
        "%USERPROFILE%" => per_profile(&[], |p| &p.root),
        "%APPDATA%" => per_profile(&["AppData", "Roaming"], |p| &p.appdata),
        "%LOCALAPPDATA%" => per_profile(&["AppData", "Local"], |p| &p.local_appdata),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(path: &str) -> Vec<String> {
        split_fold(path)
    }

    #[test]
    fn glob_cases() {
        for (p, s, want) in [
            ("*", "", true),
            ("*", "anything", true),
            ("*:", "c:", true),
            ("*:", "c", false),
            ("jdk*", "jdk-21", true),
            ("jdk*", "openjdk", false),
            ("*.lnk", "notepad.lnk", true),
            ("*.lnk", "notepad.lnk.bak", false),
            ("a*b*c", "axxbyyc", true),
            ("a*b*c", "axxbyy", false),
            (
                "microsoft.vclibs.*",
                "microsoft.vclibs.140.00_14.0_x64",
                true,
            ),
            ("", "", true),
            ("", "x", false),
        ] {
            assert_eq!(glob_match(p, s), want, "{p:?} vs {s:?}");
        }
    }

    #[test]
    fn relate_cases() {
        let (_, p) = parse_key_pattern(
            r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\*\UserChoice",
        )
        .unwrap();
        let base = r"software\microsoft\windows\currentversion\explorer\fileexts";
        assert_eq!(
            relate(&p, &t(&format!(r"{base}\.txt\UserChoice"))),
            Some(Rel::Exact)
        );
        assert_eq!(
            relate(&p, &t(&format!(r"{base}\.txt\UserChoice\x"))),
            Some(Rel::Inside)
        );
        assert_eq!(relate(&p, &t(base)), Some(Rel::Ancestor { literal: true }));
        assert_eq!(
            relate(&p, &t(&format!(r"{base}\.txt"))),
            Some(Rel::Ancestor { literal: false })
        );
        assert_eq!(relate(&p, &t(&format!(r"{base}\.txt\OpenWithList"))), None);
        assert_eq!(relate(&[], &t("")), Some(Rel::Exact));
    }

    #[test]
    fn key_pattern_roots() {
        assert_eq!(
            parse_key_pattern(r"HKLM\SOFTWARE\X").unwrap().0,
            KeyBase::Hklm
        );
        assert_eq!(
            parse_key_pattern(r"HKU\*\Environment").unwrap().0,
            KeyBase::Hku
        );
        assert_eq!(parse_key_pattern(r"*\SOFTWARE").unwrap().0, KeyBase::Any);
        let (base, segs) = parse_key_pattern(r"HKCR\[*]\shell").unwrap();
        assert_eq!(base, KeyBase::Classes);
        assert_eq!(segs, [Seg::Lit("*".into()), Seg::Lit("shell".into())]);
        assert!(parse_key_pattern(r"HKU\S-1-5-18\X").is_err());
        assert!(parse_key_pattern(r"HKCU\X").is_err());
        assert!(parse_key_pattern(r"HKLM\SOFTWARE\WOW6432Node\X").is_err());
        let (_, ccs) = parse_key_pattern(r"HKLM\SYSTEM\CurrentControlSet\Control").unwrap();
        assert_eq!(
            relate(&ccs, &t(r"system\controlset001\control")),
            Some(Rel::Exact)
        );
    }

    #[test]
    fn fs_pattern_tokens() {
        let env = GuardEnv::sample();
        assert_eq!(
            parse_fs_pattern(r"%ProgramFiles%\Java", &env)
                .unwrap()
                .len(),
            2
        );
        let local = parse_fs_pattern(r"%LOCALAPPDATA%\Packages", &env).unwrap();
        assert_eq!(local.len(), 2);
        assert_eq!(
            relate(&local[0], &t(r"c:\users\someone\appdata\local\packages\x")),
            Some(Rel::Inside)
        );
        assert_eq!(
            relate(
                &parse_fs_pattern(r"*:\Recovery", &env).unwrap()[0],
                &t(r"d:\recovery")
            ),
            Some(Rel::Exact)
        );
        assert!(parse_fs_pattern(r"%TEMP%\x", &env).is_err());
        assert!(parse_fs_pattern(r"relative\x", &env).is_err());
        assert!(
            parse_fs_pattern(r"%WINDIR%", &GuardEnv::default())
                .unwrap()
                .is_empty()
        );
    }
}
