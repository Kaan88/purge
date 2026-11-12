//! Environment-variable expansion.
//!
//! - [`expand`]: `ExpandEnvironmentStringsW` against the engine's own environment, with a buffer
//!   that grows to the size the API reports (ENGINE_PLAN.md §4.2: rewritten here, not copied).
//! - [`expand_with`] / [`EnvMap`]: the same `%NAME%` rules against a supplied variable map, used for
//!   another user's environment (`HKU\<SID>\Environment`, `Volatile Environment`) and for fixtures.
//!   Names match case-insensitively; an unknown or empty name is left intact, `%` signs included,
//!   and its closing `%` may open the next reference, as `ExpandEnvironmentStringsW` does (a test
//!   checks the two agree).
//!
//! The pure part is available without the `read` feature; [`expand`] and [`EnvMap::from_process`]
//! need it.

use std::collections::BTreeMap;

/// A case-insensitive variable map for [`expand_with`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvMap {
    /// Upper-cased name -> (name as given, value).
    vars: BTreeMap<String, (String, String)>,
}

impl EnvMap {
    /// An empty map.
    pub fn new() -> EnvMap {
        EnvMap::default()
    }

    /// Sets `name` (case-insensitive) to `value`, replacing any earlier value.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        self.vars.insert(name.to_uppercase(), (name, value.into()));
    }

    /// The value of `name`, case-insensitively.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars.get(&name.to_uppercase()).map(|(_, v)| v.as_str())
    }

    /// Number of variables.
    pub fn len(&self) -> usize {
        self.vars.len()
    }

    /// No variables.
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }

    /// `(name, value)` pairs in upper-cased-name order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.vars.values().map(|(n, v)| (n.as_str(), v.as_str()))
    }

    /// The current process environment (non-Unicode entries are skipped).
    #[cfg(feature = "read")]
    pub fn from_process() -> EnvMap {
        std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect()
    }
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for EnvMap {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut m = EnvMap::new();
        for (k, v) in iter {
            m.insert(k, v);
        }
        m
    }
}

/// Expands `%NAME%` references in `s` with `map`. Unknown and empty names stay as written.
pub fn expand_with(s: &str, map: &EnvMap) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(open) = rest.find('%') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('%') else {
            // Unterminated: the remainder is literal.
            out.push_str(&rest[open..]);
            return out;
        };
        let name = &after[..close];
        match (!name.is_empty()).then(|| map.get(name)).flatten() {
            Some(value) => {
                out.push_str(value);
                rest = &after[close + 1..];
            }
            None => {
                // Keep `%NAME` and rescan from the closing `%`, which may open the next reference.
                out.push('%');
                out.push_str(name);
                rest = &after[close..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Expands `s` with `ExpandEnvironmentStringsW` against this process's environment, growing the
/// buffer to the size the API reports until the result fits.
#[cfg(feature = "read")]
pub fn expand(s: &str) -> Result<String, crate::os::Win32Error> {
    use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;

    let src = crate::os::wide(s);
    let mut buf = vec![0u16; src.len().max(64) * 2];
    loop {
        // SAFETY: `src` is NUL-terminated; `buf` has `buf.len()` writable units.
        let n =
            unsafe { ExpandEnvironmentStringsW(src.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) }
                as usize;
        if n == 0 {
            return Err(crate::os::Win32Error::last());
        }
        // `n` counts the terminating NUL. When it exceeds the buffer the output was not written.
        if n <= buf.len() {
            return Ok(String::from_utf16_lossy(&buf[..n - 1]));
        }
        buf.resize(n, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> EnvMap {
        [
            ("SystemRoot", r"C:\Windows"),
            ("APPDATA", r"C:\Users\u\AppData\Roaming"),
            ("X", "1"),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn expansion_with_map() {
        let m = map();
        assert_eq!(
            expand_with(r"%systemroot%\System32", &m),
            r"C:\Windows\System32"
        );
        assert_eq!(
            expand_with(r"%APPDATA%\%X%%X%", &m),
            r"C:\Users\u\AppData\Roaming\11"
        );
        assert_eq!(expand_with("%NOPE%", &m), "%NOPE%");
        assert_eq!(expand_with("a%NOPE%X%b", &m), "a%NOPE1b");
        assert_eq!(expand_with("100%", &m), "100%");
        assert_eq!(expand_with("%%", &m), "%%");
        assert_eq!(expand_with("%%X%", &m), "%1");
        assert_eq!(expand_with("no refs", &m), "no refs");
        assert_eq!(expand_with("%X", &m), "%X");
        assert_eq!(expand_with("ü%X%ü", &m), "ü1ü");
        assert_eq!(m.get("appdata"), Some(r"C:\Users\u\AppData\Roaming"));
        assert_eq!(m.len(), 3);
    }

    #[cfg(feature = "read")]
    #[test]
    fn live_expansion_and_agreement_with_map() {
        let windir = std::env::var("SystemRoot").unwrap();
        assert_eq!(expand(r"%SystemRoot%\x").unwrap(), format!(r"{windir}\x"));
        assert_eq!(expand("").unwrap(), "");
        // Long output forces the retry path.
        let long = "%SystemRoot%".repeat(500);
        assert_eq!(expand(&long).unwrap(), windir.repeat(500));

        let m = EnvMap::from_process();
        for s in [
            r"%SystemRoot%\System32",
            "%PURGE_TEST_UNKNOWN_VAR_1%",
            "a%PURGE_TEST_UNKNOWN_VAR_1%SystemRoot%b",
            "%%",
            "%%SystemRoot%",
            "50%",
            "%SystemRoot",
            "%windir%%windir%",
            "%PURGE_TEST_UNKNOWN_VAR_1%%PURGE_TEST_UNKNOWN_VAR_2%",
        ] {
            assert_eq!(expand_with(s, &m), expand(s).unwrap(), "input {s:?}");
        }
    }
}
