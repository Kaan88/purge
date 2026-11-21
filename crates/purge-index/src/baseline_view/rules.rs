//! The rules of the baseline view, read from `kb/baselines/view.json` (BASELINE_LOCAL_DESIGN.md §4.1,
//! §4.2): the registry areas with their `merged` / `local` flags, and the neighbour selection limits.
//!
//! The file is data that gate M wrote from measurement; the reader is strict so that a damaged or
//! hand-edited file cannot widen what the view infers. Anything unexpected (another schema, an unknown
//! field, a prefix that is not a normalised key, a doubled id, a missing `neighbours` rule) refuses the
//! whole file, and the caller then works with [`ViewRules::closed`]: no area, so no inferred absence
//! anywhere.
//!
//! # Area of a key
//!
//! A key belongs to the first area, in file order, that has a prefix the normalised key is at or below
//! and whose shape matches ([`AreaShape`]). A key no area matches belongs to none and is never marked.
//! `vm/rigtool/src/baseline_diff.rs` (`Areas`) classifies the same way; gate M measured the areas with
//! it, so the two must agree: the matching rule here is the same three lines as `Area::matches` there,
//! and the test `areas_classify_as_the_rig_measured_them` pins one key or more per shipped area. No test
//! runs both over one corpus (`rigtool` is a separate Cargo project).

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

use serde::Deserialize;

use super::BaselineTrust;
use crate::baseline::normalised_key;

/// The schema this reader reads.
pub const VIEW_SCHEMA: &str = "purge.baseline-view/1";
/// The file's name in the baseline directory.
pub const VIEW_FILE_NAME: &str = "view.json";
/// The largest `view.json` read.
pub const MAX_VIEW_FILE_BYTES: u64 = 1 << 20;
/// The largest `neighbours.max_count` accepted: the load budget (§5) is set for two or three.
pub const MAX_NEIGHBOUR_COUNT: usize = 8;

/// The neighbour selection limits (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighbourRule {
    /// A shipped baseline qualifies only when its build is at most this far from the host's.
    pub max_build_distance: u32,
    /// At most this many neighbours are used.
    pub max_count: usize,
}

impl Default for NeighbourRule {
    /// The limits of design §4.1 (1000 builds, three neighbours), used when `view.json` is unusable:
    /// a neighbour only adds presence (L1), so keeping them costs no safety.
    fn default() -> Self {
        NeighbourRule {
            max_build_distance: 1000,
            max_count: 3,
        }
    }
}

/// What an area asks of the segments below its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AreaShape {
    /// Anything at or below the prefix.
    Any,
    /// The first segment below the prefix starts with `.`.
    Ext,
    /// A segment after the first below the prefix is `shell` or `shellex`.
    Shell,
}

/// One registry area of `view.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Area {
    id: String,
    title: String,
    prefixes: Vec<String>,
    shape: AreaShape,
    merged: bool,
    local: bool,
}

impl Area {
    /// The area's id (`classes-clsid`, …), as the residue output names it (§7).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The human title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// The normalised key prefixes.
    pub fn prefixes(&self) -> &[String] {
        &self.prefixes
    }

    /// The shape asked of a key below a prefix.
    pub fn shape(&self) -> AreaShape {
        self.shape
    }

    /// Whether inferred absence is accepted here at trust Merged.
    pub fn merged(&self) -> bool {
        self.merged
    }

    /// Whether inferred absence is accepted here at trust Local.
    pub fn local(&self) -> bool {
        self.local
    }

    /// Whether inferred absence is accepted here at this trust. Never at Exact (absence is proof
    /// there, and no area is asked) and never at None.
    pub fn accepts(&self, trust: BaselineTrust) -> bool {
        match trust {
            BaselineTrust::Merged => self.merged,
            BaselineTrust::Local => self.local,
            BaselineTrust::Exact | BaselineTrust::None => false,
        }
    }

    fn matches(&self, normalised: &str) -> bool {
        self.prefixes.iter().any(|prefix| {
            let Some(rest) = normalised.strip_prefix(prefix.as_str()) else {
                return false;
            };
            let mut below = match rest.strip_prefix('\\') {
                Some(below) => below.split('\\'),
                None if rest.is_empty() => "".split('\\'),
                None => return false,
            };
            // `"".split` yields one empty segment: a key that is the prefix itself has no segment
            // below it, which neither `.x` nor `shell` matches.
            match self.shape {
                AreaShape::Any => true,
                AreaShape::Ext => below.next().is_some_and(|s| s.starts_with('.')),
                AreaShape::Shell => below.skip(1).any(|s| s == "shell" || s == "shellex"),
            }
        })
    }
}

/// Why `view.json` is refused.
#[derive(Debug)]
pub enum ViewRulesError {
    /// The file could not be read, or is larger than [`MAX_VIEW_FILE_BYTES`].
    Io(io::Error),
    /// Not the JSON this reader expects (syntax, a missing or unknown field, a wrong type).
    Json(String),
    /// Another schema.
    Schema(String),
    /// A value the rules do not allow; the text says which.
    Invalid(String),
}

impl fmt::Display for ViewRulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read {VIEW_FILE_NAME}: {e}"),
            Self::Json(e) => write!(f, "{VIEW_FILE_NAME}: {e}"),
            Self::Schema(s) => {
                write!(
                    f,
                    "{VIEW_FILE_NAME}: schema {s:?}, expected {VIEW_SCHEMA:?}"
                )
            }
            Self::Invalid(e) => write!(f, "{VIEW_FILE_NAME}: {e}"),
        }
    }
}

impl std::error::Error for ViewRulesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewFile {
    schema: String,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
    neighbours: NeighbourDef,
    areas: Vec<AreaDef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NeighbourDef {
    max_build_distance: u32,
    max_count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AreaDef {
    id: String,
    #[serde(default)]
    title: String,
    prefixes: Vec<String>,
    #[serde(default)]
    shape: Option<String>,
    #[serde(default)]
    merged: bool,
    #[serde(default)]
    local: bool,
}

/// The rules of the view: areas and neighbour limits. Made only by [`ViewRules::parse`] (and
/// [`ViewRules::load`]) or [`ViewRules::closed`], so a flag is never set by code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewRules {
    neighbours: NeighbourRule,
    areas: Vec<Area>,
}

impl ViewRules {
    /// The rules when `view.json` is missing or refused: no area (so no inferred absence anywhere)
    /// and the default neighbour limits.
    pub fn closed() -> ViewRules {
        ViewRules {
            neighbours: NeighbourRule::default(),
            areas: Vec::new(),
        }
    }

    /// Parses the text of a `view.json`. See the module documentation for what is refused.
    pub fn parse(text: &str) -> Result<ViewRules, ViewRulesError> {
        let invalid = |m: String| Err(ViewRulesError::Invalid(m));
        let file: ViewFile =
            serde_json::from_str(text).map_err(|e| ViewRulesError::Json(e.to_string()))?;
        if file.schema != VIEW_SCHEMA {
            return Err(ViewRulesError::Schema(file.schema));
        }
        if file.neighbours.max_count > MAX_NEIGHBOUR_COUNT {
            return invalid(format!(
                "neighbours.max_count {} is above {MAX_NEIGHBOUR_COUNT}",
                file.neighbours.max_count
            ));
        }
        let mut seen = HashSet::new();
        let mut areas = Vec::with_capacity(file.areas.len());
        for a in file.areas {
            if a.id.is_empty() || !seen.insert(a.id.clone()) {
                return invalid(format!("area id {:?} is empty or not unique", a.id));
            }
            if a.prefixes.is_empty() {
                return invalid(format!("area {} has no prefix", a.id));
            }
            for p in &a.prefixes {
                let norm = normalised_key(p);
                if p.is_empty() || norm != *p {
                    return invalid(format!(
                        "area {}: prefix {p:?} is not a normalised key (it reads as {norm:?})",
                        a.id
                    ));
                }
                if !matches!(p.split('\\').next(), Some("hklm" | "hku")) {
                    return invalid(format!(
                        "area {}: prefix {p:?} is not under hklm or hku",
                        a.id
                    ));
                }
            }
            let shape = match a.shape.as_deref() {
                None | Some("any") => AreaShape::Any,
                Some("ext") => AreaShape::Ext,
                Some("shell") => AreaShape::Shell,
                Some(x) => {
                    return invalid(format!("area {}: shape {x:?} (any, ext or shell)", a.id));
                }
            };
            areas.push(Area {
                id: a.id,
                title: a.title,
                prefixes: a.prefixes,
                shape,
                merged: a.merged,
                local: a.local,
            });
        }
        Ok(ViewRules {
            neighbours: NeighbourRule {
                max_build_distance: file.neighbours.max_build_distance,
                max_count: file.neighbours.max_count,
            },
            areas,
        })
    }

    /// Reads `<dir>\view.json`.
    pub fn load(dir: &Path) -> Result<ViewRules, ViewRulesError> {
        let mut bytes = Vec::new();
        fs::File::open(dir.join(VIEW_FILE_NAME))
            .map_err(ViewRulesError::Io)?
            .take(MAX_VIEW_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(ViewRulesError::Io)?;
        if bytes.len() as u64 > MAX_VIEW_FILE_BYTES {
            return Err(ViewRulesError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("larger than {MAX_VIEW_FILE_BYTES} bytes"),
            )));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|e| ViewRulesError::Json(format!("not UTF-8: {e}")))?;
        Self::parse(text.strip_prefix('\u{feff}').unwrap_or(text))
    }

    /// [`ViewRules::load`], or [`ViewRules::closed`] with a line in `warnings` when the file is
    /// missing or refused (fail closed: no area is marked).
    pub fn load_or_closed(dir: &Path, warnings: &mut Vec<String>) -> ViewRules {
        match Self::load(dir) {
            Ok(rules) => rules,
            Err(e) => {
                warnings.push(format!(
                    "baseline: {e} (in {}); no registry area is marked, absence is never inferred",
                    dir.display()
                ));
                Self::closed()
            }
        }
    }

    /// The neighbour selection limits.
    pub fn neighbours(&self) -> NeighbourRule {
        self.neighbours
    }

    /// The areas, in file order.
    pub fn areas(&self) -> &[Area] {
        &self.areas
    }

    /// The area of a **normalised** key ([`normalised_key`]): the first one that matches, or `None`.
    pub fn area_of(&self, normalised: &str) -> Option<&Area> {
        self.areas.iter().find(|a| a.matches(normalised))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shipped_text() -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../kb/baselines/view.json");
        fs::read_to_string(path).expect("kb/baselines/view.json")
    }

    fn wrap(areas: &str) -> String {
        format!(
            "{{\"schema\":\"{VIEW_SCHEMA}\",\"neighbours\":{{\"max_build_distance\":1000,\"max_count\":3}},\
             \"areas\":[{areas}]}}"
        )
    }

    /// Gate M's result (DECISIONS 2026-11-21): seven areas `merged`, none `local`.
    #[test]
    fn the_shipped_file_marks_seven_merged_areas_and_no_local_one() {
        let rules =
            ViewRules::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../kb/baselines"))
                .expect("the shipped view.json is accepted");
        assert_eq!(
            rules.neighbours(),
            NeighbourRule {
                max_build_distance: 1000,
                max_count: 3
            }
        );
        assert_eq!(rules.neighbours(), NeighbourRule::default());
        assert_eq!(rules.areas().len(), 22);
        let merged: Vec<&str> = rules
            .areas()
            .iter()
            .filter(|a| a.merged())
            .map(Area::id)
            .collect();
        assert_eq!(
            merged,
            [
                "classes-wow6432node",
                "classes-clsid",
                "classes-interface",
                "classes-appid",
                "software-clients",
                "software-wow6432node",
                "software-vendor"
            ]
        );
        assert!(rules.areas().iter().all(|a| !a.local()));
        for a in rules.areas() {
            assert_eq!(a.accepts(BaselineTrust::Merged), a.merged(), "{}", a.id());
            assert!(!a.accepts(BaselineTrust::Local), "{}", a.id());
            assert!(!a.accepts(BaselineTrust::Exact), "{}", a.id());
            assert!(!a.accepts(BaselineTrust::None), "{}", a.id());
        }
    }

    /// One key or more per area of the shipped file, classified by hand from the rule `rigtool`
    /// measured the areas with (the first area in file order whose prefix and shape match).
    #[test]
    fn areas_classify_as_the_rig_measured_them() {
        let rules = ViewRules::parse(&shipped_text()).unwrap();
        let area = |key: &str| {
            rules
                .area_of(&normalised_key(key))
                .map_or("(unmatched)", Area::id)
        };
        for (key, want) in [
            (r"HKLM\SOFTWARE\Classes\CLSID\{A}", "classes-clsid"),
            (r"HKLM\SOFTWARE\Classes\CLSID", "classes-clsid"),
            (
                r"HKLM\SOFTWARE\Classes\Interface\{I}\ProxyStubClsid32",
                "classes-interface",
            ),
            (r"HKLM\SOFTWARE\Classes\TypeLib\{T}\1.0", "classes-typelib"),
            (r"HKLM\SOFTWARE\Classes\AppID\x.exe", "classes-appid"),
            (
                r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{A}",
                "classes-wow6432node",
            ),
            (
                r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{A}",
                "classes-wow6432node",
            ),
            (r"HKLM\SOFTWARE\Classes\.txt", "classes-ext"),
            (r"HKLM\SOFTWARE\Classes\.txt\OpenWithProgids", "classes-ext"),
            (r"HKLM\SOFTWARE\Classes\.txt\shell\open", "classes-shell"),
            (
                r"HKLM\SOFTWARE\Classes\txtfile\shell\open\command",
                "classes-shell",
            ),
            (r"HKLM\SOFTWARE\Classes\txtfile\ShellEx\X", "classes-shell"),
            (r"HKLM\SOFTWARE\Classes\txtfile", "classes-progid"),
            (r"HKLM\SOFTWARE\Classes\shell", "classes-progid"),
            (r"HKLM\SOFTWARE\Classes\CLSIDx", "classes-progid"),
            (r"HKLM\SOFTWARE\Classes", "classes-progid"),
            (
                r"HKLM\SOFTWARE\Clients\StartMenuInternet",
                "software-clients",
            ),
            (r"HKLM\SOFTWARE\RegisteredApplications", "software-clients"),
            (
                r"HKLM\SOFTWARE\WOW6432Node\Clients\Mail",
                "software-clients",
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\X",
                "software-ms-currentversion",
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "software-microsoft",
            ),
            (
                r"HKLM\SOFTWARE\WOW6432Node\Vendor\App",
                "software-wow6432node",
            ),
            (r"HKLM\SOFTWARE\WOW6432Node", "software-wow6432node"),
            (r"HKLM\SOFTWARE\Vendor\App", "software-vendor"),
            (r"HKLM\SOFTWARE\Policies\Microsoft", "software-vendor"),
            (r"HKLM\SOFTWARE", "software-vendor"),
            (
                r"HKLM\SYSTEM\ControlSet001\Services\Tcpip",
                "system-services",
            ),
            (
                r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                "system-control",
            ),
            (r"HKLM\SYSTEM\Setup", "system"),
            (r"HKU\S-1-5-21-1-2-3-1001_Classes\CLSID\{A}", "hku-classes"),
            (
                r"HKU\S-1-5-21-1-2-3-1001\Software\Classes\.x",
                "hku-classes",
            ),
            (r"HKCU\Software\Microsoft\Windows", "hku-software-microsoft"),
            (r"HKU\S-1-5-21-1-2-3-1001\Software\Vendor", "hku-software"),
            (r"HKU\S-1-5-21-1-2-3-1001\Environment", "hku-profile"),
            (r"HKU\.DEFAULT\Software\Vendor", "hku-default"),
            (r"HKU\S-1-5-18\Software\Vendor", "hku-default"),
            (r"HKU\S-1-5-19\Environment", "hku-other"),
            (r"HKU", "hku-other"),
            // Outside every area.
            (r"HKLM\SAM\SAM", "(unmatched)"),
            (r"HKLM\SOFTWAREX\Vendor", "(unmatched)"),
            (r"HKLM", "(unmatched)"),
            (r"HKCR\.txt", "(unmatched)"),
            (r"HKCC\Software", "(unmatched)"),
            ("", "(unmatched)"),
        ] {
            assert_eq!(area(key), want, "{key}");
        }
    }

    #[test]
    fn shapes() {
        let rules = ViewRules::parse(&wrap(
            r#"{"id":"s","prefixes":["hklm\\software\\classes"],"shape":"shell","merged":true},
               {"id":"e","prefixes":["hklm\\software\\classes"],"shape":"ext","merged":true},
               {"id":"a","prefixes":["hklm\\software\\classes\\clsid"],"shape":"any"}"#,
        ))
        .unwrap();
        let area = |k: &str| rules.area_of(k).map(Area::id);
        assert_eq!(area(r"hklm\software\classes\x\shell"), Some("s"));
        assert_eq!(area(r"hklm\software\classes\x\y\shellex\z"), Some("s"));
        // The first segment below the prefix is the class, not a verb container.
        assert_eq!(area(r"hklm\software\classes\shell"), None);
        assert_eq!(area(r"hklm\software\classes\shell\shell"), Some("s"));
        assert_eq!(area(r"hklm\software\classes\x\shells"), None);
        assert_eq!(area(r"hklm\software\classes\.x"), Some("e"));
        assert_eq!(area(r"hklm\software\classes\.x\y"), Some("e"));
        assert_eq!(area(r"hklm\software\classes\x\.y"), None);
        assert_eq!(area(r"hklm\software\classes"), None);
        assert_eq!(area(r"hklm\software\classes\clsid"), Some("a"));
        assert_eq!(area(r"hklm\software\classes\clsid\{a}"), Some("a"));
        // A prefix matches whole segments only.
        assert_eq!(area(r"hklm\software\classes\clsidx"), None);
        assert_eq!(area(r"hklm\software\classesx\.x"), None);
    }

    #[test]
    fn a_malformed_file_is_refused() {
        let ok = r#"{"id":"a","prefixes":["hklm\\software"],"merged":true}"#;
        assert!(ViewRules::parse(&wrap(ok)).is_ok());
        assert!(
            ViewRules::parse(&wrap("")).is_ok(),
            "no area is a valid file"
        );
        for (areas, why) in [
            (
                r#"{"id":"a","prefixes":["HKLM\\SOFTWARE"]}"#,
                "prefix not folded",
            ),
            (
                r#"{"id":"a","prefixes":["hklm\\software\\"]}"#,
                "trailing separator",
            ),
            (
                r#"{"id":"a","prefixes":["hkey_local_machine\\software"]}"#,
                "long root",
            ),
            (
                r#"{"id":"a","prefixes":["hklm\\system\\controlset001"]}"#,
                "control set",
            ),
            (
                r#"{"id":"a","prefixes":["hku\\s-1-5-21-1-2-3-4"]}"#,
                "a real SID",
            ),
            (
                r#"{"id":"a","prefixes":["hkcr\\clsid"]}"#,
                "an unbound root",
            ),
            (r#"{"id":"a","prefixes":["software"]}"#, "no root"),
            (r#"{"id":"a","prefixes":[""]}"#, "empty prefix"),
            (r#"{"id":"a","prefixes":[]}"#, "no prefix"),
            (r#"{"id":"a"}"#, "prefixes missing"),
            (r#"{"id":"","prefixes":["hklm"]}"#, "empty id"),
            (r#"{"prefixes":["hklm"]}"#, "id missing"),
            (
                r#"{"id":"a","prefixes":["hklm"],"shape":"odd"}"#,
                "unknown shape",
            ),
            (
                r#"{"id":"a","prefixes":["hklm"],"merged":"yes"}"#,
                "flag not a boolean",
            ),
            (
                r#"{"id":"a","prefixes":["hklm"],"merged":1}"#,
                "flag a number",
            ),
            (
                r#"{"id":"a","prefixes":["hklm"],"typo":true}"#,
                "unknown field",
            ),
            (
                r#"{"id":"a","prefixes":["hklm"],"Merged":true}"#,
                "flag in another case",
            ),
            (
                r#"{"id":"a","prefixes":["hklm"]},{"id":"a","prefixes":["hku"]}"#,
                "doubled id",
            ),
        ] {
            assert!(ViewRules::parse(&wrap(areas)).is_err(), "{why}");
        }
        let n = r#""neighbours":{"max_build_distance":1000,"max_count":3}"#;
        for (text, why) in [
            (String::new(), "empty"),
            ("[]".to_owned(), "not an object"),
            (
                format!(r#"{{"schema":"x",{n},"areas":[]}}"#),
                "another schema",
            ),
            (
                format!(r#"{{"schema":"purge.baseline-view/2",{n},"areas":[]}}"#),
                "a later schema",
            ),
            (format!(r#"{{{n},"areas":[]}}"#), "no schema"),
            (format!(r#"{{"schema":"{VIEW_SCHEMA}",{n}}}"#), "no areas"),
            (
                format!(r#"{{"schema":"{VIEW_SCHEMA}","areas":[]}}"#),
                "no neighbour rule",
            ),
            (
                format!(r#"{{"schema":"{VIEW_SCHEMA}",{n},"areas":[],"extra":1}}"#),
                "unknown top-level field",
            ),
            (
                format!(
                    r#"{{"schema":"{VIEW_SCHEMA}","neighbours":{{"max_build_distance":1000}},"areas":[]}}"#
                ),
                "no max_count",
            ),
            (
                format!(
                    r#"{{"schema":"{VIEW_SCHEMA}","neighbours":{{"max_build_distance":-1,"max_count":3}},"areas":[]}}"#
                ),
                "negative distance",
            ),
            (
                format!(
                    r#"{{"schema":"{VIEW_SCHEMA}","neighbours":{{"max_build_distance":1000,"max_count":9}},"areas":[]}}"#
                ),
                "too many neighbours",
            ),
            (
                format!(r#"{{"schema":"{VIEW_SCHEMA}",{n},"areas":[{ok}]"#),
                "truncated",
            ),
        ] {
            assert!(ViewRules::parse(&text).is_err(), "{why}");
        }
        // A truncated copy of the shipped file is refused at every cut.
        let shipped = shipped_text();
        for cut in (0..shipped.trim_end().len() - 1).step_by(97) {
            if shipped.is_char_boundary(cut) {
                assert!(ViewRules::parse(&shipped[..cut]).is_err(), "cut at {cut}");
            }
        }
    }

    #[test]
    fn a_missing_or_refused_file_closes_the_rules() {
        let dir = std::env::temp_dir().join(format!("purge-view-rules-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut warnings = Vec::new();
        let rules = ViewRules::load_or_closed(&dir, &mut warnings);
        assert_eq!(rules, ViewRules::closed());
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(rules.areas().is_empty());
        assert_eq!(rules.area_of(r"hklm\software\vendor"), None);

        fs::write(
            dir.join(VIEW_FILE_NAME),
            shipped_text().replace("\"merged\"", "\"merge\""),
        )
        .unwrap();
        let rules = ViewRules::load_or_closed(&dir, &mut warnings);
        assert_eq!(rules, ViewRules::closed());
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[1].contains("view.json"), "{warnings:?}");

        // A UTF-8 byte-order mark (a file saved by a Windows editor) is not a reason to refuse.
        fs::write(
            dir.join(VIEW_FILE_NAME),
            format!("\u{feff}{}", shipped_text()),
        )
        .unwrap();
        let rules = ViewRules::load_or_closed(&dir, &mut warnings);
        assert_eq!(rules.areas().len(), 22);
        assert_eq!(warnings.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }
}
