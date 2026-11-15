//! What an item of a plan acts on: the wire type [`Target`] and its typed registry view [`TypedTarget`].
//!
//! [`Target`] is the wire format of `purge.plan/0` and of the rig's truth files (vm/RIG.md §5, §7): plain
//! string paths, byte-compatible with `vm/rigtool`. ENGINE_PLAN.md §5.2 describes registry targets as
//! (hive, view, path); that form exists here as [`TypedTarget`], an internal view of the registry variants
//! with a lossless conversion in both directions. Plans always carry [`Target`].

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

/// Reads a value name, where JSON `null` means the default value (as `""`). A missing field is still an
/// error. rigtool writes `""`, but older rig output and hand-written plans may use `null`.
fn value_name<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

/// A thing on the system that a candidate or plan item refers to.
///
/// Serialised as an object tagged by `"type"`, exactly as in vm/RIG.md §5 and §7, e.g.
/// `{"type":"RegValue","path":"HKLM\\SOFTWARE\\X","name":"Y"}`. A value `name` of `null` reads as `""`
/// (the default value); it is always written as a string.
///
/// This is the one vocabulary for both plans (§7) and the rig's `truth.json` items (§5).
/// [`Target::RegValueChanged`] is truth-only: a plan never offers it, because removing a changed value is
/// never right; the fix is a [`Target::RegMultiSzSegment`] edit.
///
/// Registry paths use canonical roots (`HKLM\SOFTWARE\…`, `HKU\<SID>\…`, `HKU\<SID>_Classes\…`); file
/// paths are absolute. Canonicalisation itself lives in `purge-guard`. Shortcuts are plain
/// [`Target::Path`] items.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum Target {
    /// A file or directory.
    Path {
        /// Absolute path, without a `\\?\` prefix.
        path: String,
    },
    /// A registry key and everything under it.
    RegKey {
        /// Canonical key path.
        path: String,
    },
    /// One named value of a registry key.
    RegValue {
        /// Canonical key path.
        path: String,
        /// Value name; empty for the key's default value.
        #[serde(deserialize_with = "value_name")]
        #[schemars(with = "Option<String>")]
        name: String,
    },
    /// A value that existed before the install and was changed by it (rig truth only, vm/RIG.md §5; e.g. a
    /// segment appended to `PATH`). Plans never contain it.
    RegValueChanged {
        /// Canonical key path.
        path: String,
        /// Value name; empty for the key's default value.
        #[serde(deserialize_with = "value_name")]
        #[schemars(with = "Option<String>")]
        name: String,
        /// Data before the install (preview, or hash when there is no preview).
        #[serde(default)]
        before: String,
        /// Data after the install (preview, or hash when there is no preview).
        #[serde(default)]
        after: String,
    },
    /// One segment of a list-like value (a `;`-separated `REG_SZ`/`REG_EXPAND_SZ` such as `PATH`, or one
    /// string of a `REG_MULTI_SZ`). Acting on it edits the value instead of deleting it.
    RegMultiSzSegment {
        /// Canonical key path.
        path: String,
        /// Value name; empty for the key's default value.
        #[serde(deserialize_with = "value_name")]
        #[schemars(with = "Option<String>")]
        name: String,
        /// The segment text.
        segment: String,
        /// Zero-based position of the segment in the value, when the producer knows it; it tells two
        /// equal segments apart. `None` means the first matching segment, and the field is then not
        /// written, which keeps the output identical to plans made before the field existed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        index: Option<u32>,
    },
    /// A Windows service.
    Service {
        /// Service (key) name, not the display name.
        name: String,
    },
    /// A Task Scheduler task.
    Task {
        /// Full task path, e.g. `\Vendor\Updater`.
        path: String,
    },
    /// A Windows Firewall rule.
    FirewallRule {
        /// Rule instance id. Rules are matched by id only, because display names are not unique.
        id: String,
    },
    /// An installed AppX/MSIX package.
    AppxPackage {
        /// Package full name.
        full_name: String,
    },
}

impl Target {
    /// Whether a value name is `MRUList` (compared without regard to case, as the registry does): the
    /// value of an MRU list (`…\OpenWithList`, and others) that holds the order of its entries as a string
    /// of one-letter value names, most recent first (`"cab"`).
    pub fn is_mru_list_name(name: &str) -> bool {
        name.eq_ignore_ascii_case("MRUList")
    }

    /// For an MRU-list edit (see the convention table on [`Action`](crate::Action)): the letter a
    /// [`Target::RegMultiSzSegment`] of an `MRUList` value removes. `Some` only when the value is named
    /// `MRUList` and the segment is exactly one letter `a`-`z`; `None` for any other target. The segment's
    /// `index` is the letter's position in the string, which undo restores.
    pub fn mru_list_letter(&self) -> Option<char> {
        let Target::RegMultiSzSegment { name, segment, .. } = self else {
            return None;
        };
        let mut chars = segment.chars();
        match (chars.next(), chars.next()) {
            (Some(letter), None) if Self::is_mru_list_name(name) && letter.is_ascii_lowercase() => {
                Some(letter)
            }
            _ => None,
        }
    }

    /// Whether this is one of the registry variants, i.e. whether a [`TypedTarget`] can describe it.
    pub fn is_registry(&self) -> bool {
        matches!(
            self,
            Target::RegKey { .. }
                | Target::RegValue { .. }
                | Target::RegValueChanged { .. }
                | Target::RegMultiSzSegment { .. }
        )
    }
}

/// A registry hive, in the canonical form the engine addresses keys by (ENGINE_PLAN.md §5.2).
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum Hive {
    /// `HKEY_LOCAL_MACHINE`.
    Hklm,
    /// `HKEY_USERS\<sid>`: one user's hive (`HKCU` of that user).
    Hku(String),
    /// `HKEY_USERS\<sid>_Classes`: one user's classes hive (`HKCU\Software\Classes` of that user).
    HkuClasses(String),
}

impl Hive {
    /// The SID of a per-user hive; `None` for `HKLM`.
    pub fn sid(&self) -> Option<&str> {
        match self {
            Hive::Hklm => None,
            Hive::Hku(sid) | Hive::HkuClasses(sid) => Some(sid),
        }
    }

    /// Whether the hive is machine-wide (`HKLM`).
    pub fn is_machine(&self) -> bool {
        matches!(self, Hive::Hklm)
    }
}

/// Which registry view a key is addressed through.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum View {
    /// The native 64-bit view (`KEY_WOW64_64KEY`).
    K64,
    /// The 32-bit view (`KEY_WOW64_32KEY`), i.e. the `WOW6432Node` subtree.
    K32,
}

impl View {
    /// `64` or `32`.
    pub fn bits(self) -> u8 {
        match self {
            View::K64 => 64,
            View::K32 => 32,
        }
    }
}

/// The spelling of the redirection node in canonical paths.
const WOW_NODE: &str = "WOW6432Node";
/// Suffix of a user's classes hive under `HKEY_USERS`.
const CLASSES_SUFFIX: &str = "_Classes";

/// What part of a key a [`TypedTarget`] refers to; mirrors the registry variants of [`Target`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum RegKind {
    /// The key and everything under it ([`Target::RegKey`]).
    Key,
    /// One named value ([`Target::RegValue`]).
    Value {
        /// Value name; empty for the default value.
        name: String,
    },
    /// A value changed by the install ([`Target::RegValueChanged`], rig truth only).
    ValueChanged {
        /// Value name; empty for the default value.
        name: String,
        /// Data before the install.
        before: String,
        /// Data after the install.
        after: String,
    },
    /// One segment of a list-like value ([`Target::RegMultiSzSegment`]).
    Segment {
        /// Value name; empty for the default value.
        name: String,
        /// The segment text.
        segment: String,
        /// Zero-based position of the segment, when known.
        index: Option<u32>,
    },
}

impl RegKind {
    /// The value name, for every kind but [`RegKind::Key`].
    pub fn value_name(&self) -> Option<&str> {
        match self {
            RegKind::Key => None,
            RegKind::Value { name }
            | RegKind::ValueChanged { name, .. }
            | RegKind::Segment { name, .. } => Some(name),
        }
    }
}

/// Why a [`Target`] has no [`TypedTarget`] form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedTargetError {
    /// The target is not a registry key, value or segment.
    NotRegistry,
    /// The path does not start with a canonical root (`HKLM` or `HKU`); holds the root found.
    UnknownRoot(String),
    /// The path is `HKU` without a SID.
    MissingSid,
}

impl fmt::Display for TypedTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRegistry => f.write_str("target is not a registry target"),
            Self::UnknownRoot(root) => {
                write!(
                    f,
                    "registry path root {root:?} is not canonical (HKLM or HKU)"
                )
            }
            Self::MissingSid => f.write_str("registry path under HKU has no SID"),
        }
    }
}

impl std::error::Error for TypedTargetError {}

/// The typed view of a registry [`Target`]: hive, view and the path below the hive (ENGINE_PLAN.md §5.2).
///
/// Internal to the engine; plans and truth files carry [`Target`]. Converting a canonical [`Target`] to a
/// `TypedTarget` and back gives the same target, and the other way round too. Root names, the `_Classes`
/// suffix and the `WOW6432Node` segment are matched without regard to case and written in their canonical
/// spelling.
///
/// # Registry view
///
/// On the wire the 32-bit registry view is spelled as a `WOW6432Node` path segment. [`TypedTarget`] reads
/// that segment as [`View::K32`] in exactly the two places where Windows redirects:
///
/// - `HKLM\SOFTWARE\WOW6432Node\…` → hive `Hklm`, view `K32`, path `SOFTWARE\…`;
/// - `HKU\<sid>_Classes\WOW6432Node\…` → hive `HkuClasses(sid)`, view `K32`, path `…`.
///
/// Anywhere else (`HKU\<sid>\Software\WOW6432Node`, `HKLM\SOFTWARE\Classes\WOW6432Node`, …) the segment is
/// an ordinary key name and stays in the path with view `K64`, so one wire string maps to one typed value
/// and back.
///
/// The fields are private so that a value is always in its one normal form: [`View::K32`] only where
/// Windows redirects, never a redirecting `WOW6432Node` segment left in the path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, JsonSchema)]
pub struct TypedTarget {
    hive: Hive,
    view: View,
    path: String,
    kind: RegKind,
}

/// Field-for-field copy of [`TypedTarget`], used to normalise on deserialisation.
#[derive(Deserialize)]
#[serde(rename = "TypedTarget")]
struct RawTypedTarget {
    hive: Hive,
    view: View,
    path: String,
    kind: RegKind,
}

impl<'de> Deserialize<'de> for TypedTarget {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawTypedTarget::deserialize(deserializer)?;
        Ok(TypedTarget::new(raw.hive, raw.view, raw.path, raw.kind))
    }
}

impl TypedTarget {
    /// Builds a typed target and brings it to normal form.
    ///
    /// `path` is the key path below the hive, without leading or trailing `\`. A `view` of
    /// [`View::K32`] is kept only where it has a meaning (`HKLM\SOFTWARE\…` and a user's classes hive);
    /// elsewhere it becomes [`View::K64`]. A path that spells the redirection node itself
    /// (`SOFTWARE\WOW6432Node\X` under `HKLM`) is turned into the 32-bit view of `SOFTWARE\X`.
    pub fn new(hive: Hive, view: View, path: impl Into<String>, kind: RegKind) -> Self {
        let path = path.into();
        let rendered = render(&hive, view, path.trim_matches('\\'));
        match parse(&rendered) {
            Ok((hive, view, path)) => Self {
                hive,
                view,
                path,
                kind,
            },
            // Cannot happen: `render` always writes a canonical root with a SID. Keep the input.
            Err(_) => Self {
                hive,
                view: View::K64,
                path,
                kind,
            },
        }
    }

    /// The hive.
    pub fn hive(&self) -> &Hive {
        &self.hive
    }

    /// The registry view.
    pub fn view(&self) -> View {
        self.view
    }

    /// The key path below the hive, without the `WOW6432Node` segment the view stands for. Empty for the
    /// hive root.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// What part of the key is meant.
    pub fn kind(&self) -> &RegKind {
        &self.kind
    }

    /// The canonical full key path as [`Target`] spells it, e.g. `HKLM\SOFTWARE\WOW6432Node\Notepad++`.
    pub fn key_path(&self) -> String {
        render(&self.hive, self.view, &self.path)
    }

    /// Splits a canonical key path into hive, view and path below the hive.
    pub fn parse_key_path(key_path: &str) -> Result<(Hive, View, String), TypedTargetError> {
        parse(key_path)
    }
}

/// Writes the wire form of (hive, view, path).
fn render(hive: &Hive, view: View, path: &str) -> String {
    let mut out = match hive {
        Hive::Hklm => "HKLM".to_owned(),
        Hive::Hku(sid) => format!("HKU\\{sid}"),
        Hive::HkuClasses(sid) => format!("HKU\\{sid}{CLASSES_SUFFIX}"),
    };
    let mut push = |segment: &str| {
        if !segment.is_empty() {
            out.push('\\');
            out.push_str(segment);
        }
    };
    match (hive, view) {
        (Hive::Hklm, View::K32) => {
            let (first, rest) = split_first(path);
            push(first);
            if first.eq_ignore_ascii_case("SOFTWARE") {
                push(WOW_NODE);
            }
            push(rest);
        }
        (Hive::HkuClasses(_), View::K32) => {
            push(WOW_NODE);
            push(path);
        }
        _ => push(path),
    }
    out
}

/// Splits at the first `\`: (first segment, rest without the separator).
fn split_first(path: &str) -> (&str, &str) {
    path.split_once('\\').unwrap_or((path, ""))
}

/// Reads the wire form of a key path.
fn parse(key_path: &str) -> Result<(Hive, View, String), TypedTargetError> {
    let (root, rest) = split_first(key_path.trim_end_matches('\\'));
    if root.eq_ignore_ascii_case("HKLM") {
        let (first, tail) = split_first(rest);
        let (node, below) = split_first(tail);
        if first.eq_ignore_ascii_case("SOFTWARE") && node.eq_ignore_ascii_case(WOW_NODE) {
            let path = if below.is_empty() {
                first.to_owned()
            } else {
                format!("{first}\\{below}")
            };
            return Ok((Hive::Hklm, View::K32, path));
        }
        return Ok((Hive::Hklm, View::K64, rest.to_owned()));
    }
    if root.eq_ignore_ascii_case("HKU") {
        let (sid, rest) = split_first(rest);
        if sid.is_empty() {
            return Err(TypedTargetError::MissingSid);
        }
        // `is_char_boundary` guards the slice: a SID is ASCII in practice, but the input is any string.
        let cut = sid.len().saturating_sub(CLASSES_SUFFIX.len());
        if cut > 0 && sid.is_char_boundary(cut) && sid[cut..].eq_ignore_ascii_case(CLASSES_SUFFIX) {
            let hive = Hive::HkuClasses(sid[..cut].to_owned());
            let (node, below) = split_first(rest);
            return Ok(if node.eq_ignore_ascii_case(WOW_NODE) {
                (hive, View::K32, below.to_owned())
            } else {
                (hive, View::K64, rest.to_owned())
            });
        }
        return Ok((Hive::Hku(sid.to_owned()), View::K64, rest.to_owned()));
    }
    Err(TypedTargetError::UnknownRoot(root.to_owned()))
}

impl TryFrom<&Target> for TypedTarget {
    type Error = TypedTargetError;

    fn try_from(target: &Target) -> Result<Self, Self::Error> {
        let (key_path, kind) = match target {
            Target::RegKey { path } => (path, RegKind::Key),
            Target::RegValue { path, name } => (path, RegKind::Value { name: name.clone() }),
            Target::RegValueChanged {
                path,
                name,
                before,
                after,
            } => (
                path,
                RegKind::ValueChanged {
                    name: name.clone(),
                    before: before.clone(),
                    after: after.clone(),
                },
            ),
            Target::RegMultiSzSegment {
                path,
                name,
                segment,
                index,
            } => (
                path,
                RegKind::Segment {
                    name: name.clone(),
                    segment: segment.clone(),
                    index: *index,
                },
            ),
            Target::Path { .. }
            | Target::Service { .. }
            | Target::Task { .. }
            | Target::FirewallRule { .. }
            | Target::AppxPackage { .. } => return Err(TypedTargetError::NotRegistry),
        };
        let (hive, view, path) = parse(key_path)?;
        Ok(TypedTarget {
            hive,
            view,
            path,
            kind,
        })
    }
}

impl TryFrom<Target> for TypedTarget {
    type Error = TypedTargetError;

    fn try_from(target: Target) -> Result<Self, Self::Error> {
        TypedTarget::try_from(&target)
    }
}

impl From<&TypedTarget> for Target {
    fn from(typed: &TypedTarget) -> Self {
        let path = typed.key_path();
        match typed.kind.clone() {
            RegKind::Key => Target::RegKey { path },
            RegKind::Value { name } => Target::RegValue { path, name },
            RegKind::ValueChanged {
                name,
                before,
                after,
            } => Target::RegValueChanged {
                path,
                name,
                before,
                after,
            },
            RegKind::Segment {
                name,
                segment,
                index,
            } => Target::RegMultiSzSegment {
                path,
                name,
                segment,
                index,
            },
        }
    }
}

impl From<TypedTarget> for Target {
    fn from(typed: TypedTarget) -> Self {
        Target::from(&typed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SID: &str = "S-1-5-21-1-2-3-1001";

    /// The registry part of `vm/rigtool/src/target.rs`, copied field for field: what the rig's scorer
    /// reads a plan item's target into.
    #[derive(Deserialize, Debug, PartialEq)]
    #[serde(tag = "type")]
    enum RigTarget {
        Path {
            path: String,
        },
        RegKey {
            path: String,
        },
        RegValue {
            path: String,
            #[serde(default)]
            name: Option<String>,
        },
        RegValueChanged {
            path: String,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            before: String,
            #[serde(default)]
            after: String,
        },
        RegMultiSzSegment {
            path: String,
            #[serde(default)]
            name: Option<String>,
            segment: String,
        },
        Service {
            name: String,
        },
        Task {
            path: String,
        },
        FirewallRule {
            #[serde(alias = "rule_id")]
            id: String,
        },
        AppxPackage {
            full_name: String,
        },
    }

    fn key(path: &str) -> Target {
        Target::RegKey { path: path.into() }
    }

    /// Target → typed → target is the identity, and the typed parts are as expected.
    fn check(path: &str, hive: Hive, view: View, below: &str) {
        let target = key(path);
        let typed = TypedTarget::try_from(&target).unwrap();
        assert_eq!(
            (typed.hive(), typed.view(), typed.path()),
            (&hive, view, below),
            "{path}"
        );
        assert_eq!(Target::from(&typed), target, "{path}");
        // Typed → target → typed is the identity as well, also when built through `new`.
        assert_eq!(
            TypedTarget::new(hive, view, below, RegKind::Key),
            typed,
            "{path}"
        );
    }

    #[test]
    fn typed_view_of_each_hive_and_view() {
        check(
            r"HKLM\SOFTWARE\Mozilla",
            Hive::Hklm,
            View::K64,
            r"SOFTWARE\Mozilla",
        );
        check(
            r"HKLM\SOFTWARE\WOW6432Node\Notepad++",
            Hive::Hklm,
            View::K32,
            r"SOFTWARE\Notepad++",
        );
        check(
            r"HKLM\SOFTWARE\WOW6432Node",
            Hive::Hklm,
            View::K32,
            "SOFTWARE",
        );
        check(r"HKLM\SOFTWARE", Hive::Hklm, View::K64, "SOFTWARE");
        check("HKLM", Hive::Hklm, View::K64, "");
        check(
            r"HKLM\SYSTEM\CurrentControlSet\Services\X",
            Hive::Hklm,
            View::K64,
            r"SYSTEM\CurrentControlSet\Services\X",
        );
        check(
            &format!(r"HKU\{SID}\Software\Vendor\App"),
            Hive::Hku(SID.into()),
            View::K64,
            r"Software\Vendor\App",
        );
        check(&format!(r"HKU\{SID}"), Hive::Hku(SID.into()), View::K64, "");
        check(
            &format!(r"HKU\{SID}_Classes\.txt\OpenWithProgids"),
            Hive::HkuClasses(SID.into()),
            View::K64,
            r".txt\OpenWithProgids",
        );
        check(
            &format!(r"HKU\{SID}_Classes\WOW6432Node\CLSID\{{A}}"),
            Hive::HkuClasses(SID.into()),
            View::K32,
            r"CLSID\{A}",
        );
        check(
            &format!(r"HKU\{SID}_Classes\WOW6432Node"),
            Hive::HkuClasses(SID.into()),
            View::K32,
            "",
        );
        check(
            r"HKU\.DEFAULT\Software\X",
            Hive::Hku(".DEFAULT".into()),
            View::K64,
            r"Software\X",
        );
    }

    /// `WOW6432Node` where Windows does not redirect is an ordinary key name.
    #[test]
    fn wow_node_elsewhere_stays_in_the_path() {
        check(
            &format!(r"HKU\{SID}\Software\WOW6432Node\X"),
            Hive::Hku(SID.into()),
            View::K64,
            r"Software\WOW6432Node\X",
        );
        check(
            r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID",
            Hive::Hklm,
            View::K64,
            r"SOFTWARE\Classes\WOW6432Node\CLSID",
        );
        check(
            r"HKLM\SYSTEM\WOW6432Node",
            Hive::Hklm,
            View::K64,
            r"SYSTEM\WOW6432Node",
        );
    }

    #[test]
    fn new_normalises_view_and_path() {
        // A 32-bit view outside the redirected areas has no meaning.
        let t = TypedTarget::new(Hive::Hklm, View::K32, r"SYSTEM\X", RegKind::Key);
        assert_eq!(t.view(), View::K64);
        let t = TypedTarget::new(
            Hive::Hku(SID.into()),
            View::K32,
            r"Software\X",
            RegKind::Key,
        );
        assert_eq!((t.view(), t.path()), (View::K64, r"Software\X"));
        // The node spelled in the path is the 32-bit view.
        let t = TypedTarget::new(
            Hive::Hklm,
            View::K64,
            r"SOFTWARE\Wow6432Node\X",
            RegKind::Key,
        );
        assert_eq!((t.view(), t.path()), (View::K32, r"SOFTWARE\X"));
        assert_eq!(t.key_path(), r"HKLM\SOFTWARE\WOW6432Node\X");
        // Stray separators are dropped.
        let t = TypedTarget::new(Hive::Hklm, View::K64, r"\SOFTWARE\X\", RegKind::Key);
        assert_eq!(t.path(), r"SOFTWARE\X");
        // Every normalised value survives the round trip through `Target`.
        for t in [
            TypedTarget::new(Hive::Hklm, View::K32, "SOFTWARE", RegKind::Key),
            TypedTarget::new(Hive::HkuClasses(SID.into()), View::K32, "", RegKind::Key),
            TypedTarget::new(Hive::Hklm, View::K32, "", RegKind::Key),
        ] {
            assert_eq!(TypedTarget::try_from(Target::from(&t)).unwrap(), t);
        }
    }

    #[test]
    fn roots_are_matched_without_case_and_written_canonically() {
        let typed =
            TypedTarget::try_from(&key(&format!(r"hku\{SID}_classes\wow6432node\CLSID"))).unwrap();
        assert_eq!(typed.hive(), &Hive::HkuClasses(SID.into()));
        assert_eq!(typed.view(), View::K32);
        assert_eq!(
            typed.key_path(),
            format!(r"HKU\{SID}_Classes\WOW6432Node\CLSID")
        );
        let typed = TypedTarget::try_from(&key(r"hklm\Software\Wow6432Node\X\")).unwrap();
        assert_eq!(typed.key_path(), r"HKLM\Software\WOW6432Node\X");
    }

    #[test]
    fn every_registry_kind_converts_both_ways() {
        let path = r"HKLM\SOFTWARE\WOW6432Node\Vendor".to_owned();
        let targets = [
            Target::RegKey { path: path.clone() },
            Target::RegValue {
                path: path.clone(),
                name: String::new(),
            },
            Target::RegValueChanged {
                path: path.clone(),
                name: "Path".into(),
                before: "a".into(),
                after: "a;b".into(),
            },
            Target::RegMultiSzSegment {
                path: path.clone(),
                name: "Path".into(),
                segment: r"C:\Tool\bin".into(),
                index: None,
            },
            Target::RegMultiSzSegment {
                path,
                name: "Path".into(),
                segment: r"C:\Tool\bin".into(),
                index: Some(3),
            },
        ];
        for target in targets {
            assert!(target.is_registry());
            let typed = TypedTarget::try_from(&target).unwrap();
            assert_eq!(typed.view(), View::K32);
            assert_eq!(
                typed.kind().value_name().is_none(),
                matches!(target, Target::RegKey { .. })
            );
            assert_eq!(Target::from(typed.clone()), target);
            // The typed form itself round-trips through JSON.
            let json = serde_json::to_value(&typed).unwrap();
            assert_eq!(serde_json::from_value::<TypedTarget>(json).unwrap(), typed);
        }
    }

    #[test]
    fn deserialising_a_typed_target_normalises_it() {
        let typed: TypedTarget = serde_json::from_value(json!({
            "hive": "Hklm", "view": "K64", "path": "SOFTWARE\\WOW6432Node\\X", "kind": "Key"
        }))
        .unwrap();
        assert_eq!((typed.view(), typed.path()), (View::K32, r"SOFTWARE\X"));
        let typed: TypedTarget = serde_json::from_value(json!({
            "hive": {"HkuClasses": SID}, "view": "K32", "path": "CLSID",
            "kind": {"Value": {"name": "n"}}
        }))
        .unwrap();
        assert_eq!(
            typed.key_path(),
            format!(r"HKU\{SID}_Classes\WOW6432Node\CLSID")
        );
    }

    #[test]
    fn non_registry_and_non_canonical_targets_have_no_typed_form() {
        for target in [
            Target::Path {
                path: r"C:\X".into(),
            },
            Target::Service { name: "S".into() },
            Target::Task { path: r"\T".into() },
            Target::FirewallRule { id: "R".into() },
            Target::AppxPackage {
                full_name: "P".into(),
            },
        ] {
            assert!(!target.is_registry());
            assert_eq!(
                TypedTarget::try_from(&target),
                Err(TypedTargetError::NotRegistry)
            );
        }
        assert_eq!(
            TypedTarget::try_from(&key(r"HKCU\Software\X")),
            Err(TypedTargetError::UnknownRoot("HKCU".into()))
        );
        assert_eq!(
            TypedTarget::try_from(&key(r"HKEY_LOCAL_MACHINE\SOFTWARE")),
            Err(TypedTargetError::UnknownRoot("HKEY_LOCAL_MACHINE".into()))
        );
        assert_eq!(
            TypedTarget::try_from(&key("HKU")),
            Err(TypedTargetError::MissingSid)
        );
        assert_eq!(
            TypedTarget::try_from(&key("")),
            Err(TypedTargetError::UnknownRoot(String::new()))
        );
        // A hive literally named `_Classes` has no SID part and is read as a plain user hive.
        let typed = TypedTarget::try_from(&key(r"HKU\_Classes\X")).unwrap();
        assert_eq!(typed.hive(), &Hive::Hku("_Classes".into()));
    }

    /// Every target a plan may contain, as this crate writes it, reads with rigtool's field names.
    #[test]
    fn plan_targets_read_with_rigtool_field_names() {
        let cases = [
            (
                Target::Path {
                    path: r"C:\Program Files\App".into(),
                },
                RigTarget::Path {
                    path: r"C:\Program Files\App".into(),
                },
            ),
            (
                key(r"HKLM\SOFTWARE\Mozilla"),
                RigTarget::RegKey {
                    path: r"HKLM\SOFTWARE\Mozilla".into(),
                },
            ),
            (
                Target::RegValue {
                    path: r"HKLM\SOFTWARE\X".into(),
                    name: "Y".into(),
                },
                RigTarget::RegValue {
                    path: r"HKLM\SOFTWARE\X".into(),
                    name: Some("Y".into()),
                },
            ),
            (
                Target::RegMultiSzSegment {
                    path: r"HKLM\SYSTEM\X".into(),
                    name: "Path".into(),
                    segment: r"C:\Tool\bin".into(),
                    index: None,
                },
                RigTarget::RegMultiSzSegment {
                    path: r"HKLM\SYSTEM\X".into(),
                    name: Some("Path".into()),
                    segment: r"C:\Tool\bin".into(),
                },
            ),
            (
                Target::RegMultiSzSegment {
                    path: r"HKLM\SYSTEM\X".into(),
                    name: "Path".into(),
                    segment: r"C:\Tool\bin".into(),
                    index: Some(2),
                },
                RigTarget::RegMultiSzSegment {
                    path: r"HKLM\SYSTEM\X".into(),
                    name: Some("Path".into()),
                    segment: r"C:\Tool\bin".into(),
                },
            ),
            (
                Target::Service {
                    name: "MozillaMaintenance".into(),
                },
                RigTarget::Service {
                    name: "MozillaMaintenance".into(),
                },
            ),
            (
                Target::Task {
                    path: r"\Mozilla\Agent".into(),
                },
                RigTarget::Task {
                    path: r"\Mozilla\Agent".into(),
                },
            ),
            (
                Target::FirewallRule {
                    id: "{6A3F2C1E-0000-4000-8000-000000000001}".into(),
                },
                RigTarget::FirewallRule {
                    id: "{6A3F2C1E-0000-4000-8000-000000000001}".into(),
                },
            ),
            (
                Target::AppxPackage {
                    full_name: "Vendor.App_1.0.0.0_x64__abcdefghijklm".into(),
                },
                RigTarget::AppxPackage {
                    full_name: "Vendor.App_1.0.0.0_x64__abcdefghijklm".into(),
                },
            ),
        ];
        for (ours, rig) in cases {
            let text = serde_json::to_string(&ours).unwrap();
            assert_eq!(
                serde_json::from_str::<RigTarget>(&text).unwrap(),
                rig,
                "{text}"
            );
        }
        // The firewall rule is written with the field name `id`, not §5.2's `rule_id`.
        assert_eq!(
            serde_json::to_string(&Target::FirewallRule { id: "R1".into() }).unwrap(),
            r#"{"type":"FirewallRule","id":"R1"}"#
        );
    }

    /// A segment without an index is written exactly as before the field existed.
    #[test]
    fn segment_index_is_written_only_when_known() {
        let without = Target::RegMultiSzSegment {
            path: "HKLM\\X".into(),
            name: "Path".into(),
            segment: "s".into(),
            index: None,
        };
        assert_eq!(
            serde_json::to_string(&without).unwrap(),
            r#"{"type":"RegMultiSzSegment","path":"HKLM\\X","name":"Path","segment":"s"}"#
        );
        let with = Target::RegMultiSzSegment {
            path: "HKLM\\X".into(),
            name: "Path".into(),
            segment: "s".into(),
            index: Some(4),
        };
        let v = serde_json::to_value(&with).unwrap();
        assert_eq!(v["index"], json!(4));
        assert_eq!(serde_json::from_value::<Target>(v).unwrap(), with);
    }
}
