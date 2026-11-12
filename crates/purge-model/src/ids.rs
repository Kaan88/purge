//! Identifiers and small scalars shared by every document: [`ProgramId`], [`CandidateId`], [`SourceId`],
//! [`FileTime`], and the `schema_id!` macro behind the `schema` field of the versioned documents.
//!
//! The text form of a program id is documented on [`ProgramId`].

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::target::{Hive, View};

/// Defines the type of a document's `schema` field: a unit struct that serialises as one literal string and
/// refuses every other value when read, so a document of another version is rejected up front.
macro_rules! schema_id {
    ($(#[$meta:meta])* $name:ident = $id:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct $name;

        impl $name {
            /// The schema identifier this crate reads and writes.
            pub const ID: &'static str = $id;
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(Self::ID)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                let s = <::std::borrow::Cow<'de, str> as ::serde::Deserialize>::deserialize(
                    deserializer,
                )?;
                if s == Self::ID {
                    Ok($name)
                } else {
                    Err(::serde::de::Error::custom(format_args!(
                        "unsupported schema {s:?}, expected {:?}",
                        Self::ID
                    )))
                }
            }
        }

        impl ::schemars::JsonSchema for $name {
            fn schema_name() -> ::std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            fn inline_schema() -> bool {
                true
            }

            fn json_schema(_: &mut ::schemars::SchemaGenerator) -> ::schemars::Schema {
                ::schemars::json_schema!({ "type": "string", "const": $id })
            }
        }
    };
}
pub(crate) use schema_id;

/// Why a string is not a program id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramIdError {
    /// Fewer than three `|`-separated fields.
    MissingField,
    /// The hive tag is neither `HKLM` nor `HKU:<sid>` with a non-empty SID, or the SID contains `|`, `\`
    /// or `:` or names a classes hive (`<sid>_Classes`).
    BadHive,
    /// The view is neither `64` nor `32`.
    BadView,
    /// The key name is empty or contains `\`.
    BadKeyName,
}

impl fmt::Display for ProgramIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingField => "program id needs the form <hive>|<view>|<key name>",
            Self::BadHive => "program id hive must be HKLM or HKU:<sid>",
            Self::BadView => "program id view must be 64 or 32",
            Self::BadKeyName => "program id key name must be non-empty and contain no backslash",
        })
    }
}

impl std::error::Error for ProgramIdError {}

/// The stable identity of one Uninstall (ARP) key, serialised as its text form (a JSON string).
///
/// A program id names one Uninstall (ARP) key and is stable across runs on the same machine. Its text form
/// is `<hive tag>|<view>|<key name>`:
///
/// - hive tag: `HKLM`, or `HKU:<sid>` for a per-user entry;
/// - view: `64` or `32` (the registry view the key was read through);
/// - key name: the name of the key under `…\CurrentVersion\Uninstall`, verbatim. It may contain `|`, since
///   only the first two `|` separate fields.
///
/// Examples: `HKLM|64|Git_is1`, `HKU:S-1-5-21-1-2-3-1001|64|{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProgramId {
    sid: Option<String>,
    view: View,
    key_name: String,
}

/// Suffix of a user's classes hive under `HKEY_USERS`.
const CLASSES_SUFFIX: &str = "_Classes";
/// Path of the Uninstall key below `SOFTWARE`.
const UNINSTALL_TAIL: &str = r"Microsoft\Windows\CurrentVersion\Uninstall";

impl ProgramId {
    /// A machine-wide entry (`HKLM`).
    pub fn machine(view: View, key_name: impl Into<String>) -> Result<Self, ProgramIdError> {
        Self::build(None, view, key_name.into())
    }

    /// A per-user entry (`HKU\<sid>`).
    pub fn user(
        sid: impl Into<String>,
        view: View,
        key_name: impl Into<String>,
    ) -> Result<Self, ProgramIdError> {
        Self::build(Some(sid.into()), view, key_name.into())
    }

    fn build(sid: Option<String>, view: View, key_name: String) -> Result<Self, ProgramIdError> {
        // A `<sid>_Classes` name under `HKEY_USERS` is the user's classes hive, not a profile: it holds no
        // Uninstall key, and `Hive::Hku` of it would not be in `TypedTarget`'s normal form.
        let is_classes_hive = |sid: &str| {
            let cut = sid.len().saturating_sub(CLASSES_SUFFIX.len());
            sid.is_char_boundary(cut) && sid[cut..].eq_ignore_ascii_case(CLASSES_SUFFIX)
        };
        let bad_sid =
            |sid: &String| sid.is_empty() || sid.contains(['|', '\\', ':']) || is_classes_hive(sid);
        if sid.as_ref().is_some_and(bad_sid) {
            return Err(ProgramIdError::BadHive);
        }
        if key_name.is_empty() || key_name.contains('\\') {
            return Err(ProgramIdError::BadKeyName);
        }
        Ok(Self {
            sid,
            view,
            key_name,
        })
    }

    /// The hive the entry lives in: [`Hive::Hklm`] or [`Hive::Hku`].
    pub fn hive(&self) -> Hive {
        match &self.sid {
            None => Hive::Hklm,
            Some(sid) => Hive::Hku(sid.clone()),
        }
    }

    /// The SID of a per-user entry; `None` for a machine-wide one.
    pub fn hive_sid(&self) -> Option<&str> {
        self.sid.as_deref()
    }

    /// The registry view the key was read through.
    pub fn view(&self) -> View {
        self.view
    }

    /// The key's name under `…\Uninstall`.
    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    /// The canonical path of the Uninstall key, with `WOW6432Node` as a path segment for the 32-bit view,
    /// e.g. `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++`.
    pub fn key_path(&self) -> String {
        let wow = match self.view {
            View::K64 => "",
            View::K32 => "WOW6432Node\\",
        };
        match &self.sid {
            None => format!("HKLM\\SOFTWARE\\{wow}{UNINSTALL_TAIL}\\{}", self.key_name),
            Some(sid) => format!(
                "HKU\\{sid}\\Software\\{wow}{UNINSTALL_TAIL}\\{}",
                self.key_name
            ),
        }
    }
}

impl fmt::Display for ProgramId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.sid {
            None => f.write_str("HKLM")?,
            Some(sid) => write!(f, "HKU:{sid}")?,
        }
        write!(f, "|{}|{}", self.view.bits(), self.key_name)
    }
}

impl FromStr for ProgramId {
    type Err = ProgramIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(3, '|');
        let (Some(hive), Some(view), Some(key_name)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(ProgramIdError::MissingField);
        };
        let sid = match hive {
            "HKLM" => None,
            _ => Some(
                hive.strip_prefix("HKU:")
                    .ok_or(ProgramIdError::BadHive)?
                    .to_owned(),
            ),
        };
        let view = match view {
            "64" => View::K64,
            "32" => View::K32,
            _ => return Err(ProgramIdError::BadView),
        };
        Self::build(sid, view, key_name.to_owned())
    }
}

impl Serialize for ProgramId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ProgramId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = Cow::<str>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for ProgramId {
    fn schema_name() -> Cow<'static, str> {
        "ProgramId".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "description": "<hive tag>|<view>|<key name>, e.g. HKLM|64|Git_is1 or HKU:<sid>|64|{guid}",
            "pattern": "^(HKLM|HKU:[^|\\\\:]+)\\|(64|32)\\|[^\\\\]+$"
        })
    }
}

/// Id of a candidate within one scan: a stable hash of its target, assigned by `purge-scan`.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct CandidateId(pub String);

/// Where a piece of evidence came from, e.g. `inno:unins000.dat`, `arp:InstallLocation`,
/// `refsnap:HKLM\…`. Two pieces of evidence of the same kind count as independent (§5.8.1) only when their
/// source ids differ.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct SourceId(pub String);

impl From<&str> for SourceId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl From<String> for SourceId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// A point in time as a Windows `FILETIME`: 100-nanosecond intervals since 1601-01-01 UTC.
///
/// This is what registry key LastWriteTime, file times and process start times are in, so nothing is
/// converted on the way in. Serialised as a plain integer.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct FileTime(pub u64);

impl FileTime {
    /// Seconds between 1601-01-01 and 1970-01-01.
    const UNIX_EPOCH_SECS: i64 = 11_644_473_600;
    const TICKS_PER_SEC: u64 = 10_000_000;

    /// From seconds since the Unix epoch (UTC). Times before 1601 clamp to zero.
    pub fn from_unix_secs(secs: i64) -> Self {
        let since_1601 = secs.saturating_add(Self::UNIX_EPOCH_SECS);
        Self(
            u64::try_from(since_1601)
                .unwrap_or(0)
                .saturating_mul(Self::TICKS_PER_SEC),
        )
    }

    /// Whole seconds since the Unix epoch (UTC).
    pub fn to_unix_secs(self) -> i64 {
        // u64::MAX / 10^7 is far below i64::MAX, so the conversion cannot fail.
        let secs = i64::try_from(self.0 / Self::TICKS_PER_SEC).unwrap_or(i64::MAX);
        secs - Self::UNIX_EPOCH_SECS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    schema_id!(
        /// Test schema id.
        TestSchema = "purge.test/0"
    );

    #[test]
    fn program_id_formats_and_parses() {
        let m = ProgramId::machine(View::K64, "Git_is1").unwrap();
        assert_eq!(m.to_string(), "HKLM|64|Git_is1");
        assert_eq!(m.hive(), Hive::Hklm);
        assert_eq!(m.hive_sid(), None);
        assert_eq!(
            m.key_path(),
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Git_is1"
        );
        assert_eq!("HKLM|64|Git_is1".parse::<ProgramId>().unwrap(), m);

        let w = ProgramId::machine(View::K32, "Notepad++").unwrap();
        assert_eq!(w.to_string(), "HKLM|32|Notepad++");
        assert_eq!(
            w.key_path(),
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++"
        );

        let text = "HKU:S-1-5-21-1-2-3-1001|64|{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1";
        let u: ProgramId = text.parse().unwrap();
        assert_eq!(u.to_string(), text);
        assert_eq!(u.hive_sid(), Some("S-1-5-21-1-2-3-1001"));
        assert_eq!(u.hive(), Hive::Hku("S-1-5-21-1-2-3-1001".into()));
        assert_eq!(u.view(), View::K64);
        assert_eq!(u.key_name(), "{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1");
        assert_eq!(
            u.key_path(),
            r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Uninstall\{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1"
        );
        assert_eq!(
            ProgramId::user("S-1-5-21-1-2-3-1001", View::K64, u.key_name()).unwrap(),
            u
        );
    }

    #[test]
    fn program_id_key_name_may_contain_a_bar() {
        let p: ProgramId = "HKLM|32|A|B".parse().unwrap();
        assert_eq!(p.key_name(), "A|B");
        assert_eq!(p.to_string(), "HKLM|32|A|B");
    }

    #[test]
    fn program_id_rejects_malformed_text() {
        use ProgramIdError::*;
        for (text, err) in [
            ("", MissingField),
            ("HKLM|64", MissingField),
            ("HKCU|64|X", BadHive),
            ("HKU|64|X", BadHive),
            ("HKU:|64|X", BadHive),
            ("hklm|64|X", BadHive),
            ("HKLM|16|X", BadView),
            ("HKLM|64|", BadKeyName),
            ("HKLM|64|A\\B", BadKeyName),
        ] {
            assert_eq!(text.parse::<ProgramId>(), Err(err), "{text:?}");
        }
        assert!(ProgramId::user("S-1|5", View::K64, "X").is_err());
        // A classes hive is not a profile: `HKU\<sid>_Classes`, enumerated next to `HKU\<sid>`, is refused.
        for sid in [
            "S-1-5-21-1-2-3-1001_Classes",
            "S-1-5-21-1-2-3-1001_CLASSES",
            "_classes",
        ] {
            assert_eq!(ProgramId::user(sid, View::K64, "X"), Err(BadHive), "{sid}");
            assert_eq!(format!("HKU:{sid}|64|X").parse::<ProgramId>(), Err(BadHive));
        }
        // Non-ASCII input does not panic on the suffix check.
        assert!(ProgramId::user("é", View::K64, "X").is_ok());
        assert!(ProgramId::user("ééééé", View::K64, "X").is_ok());
    }

    #[test]
    fn program_id_is_a_json_string() {
        let p = ProgramId::machine(View::K64, "Git_is1").unwrap();
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v, json!("HKLM|64|Git_is1"));
        assert_eq!(serde_json::from_value::<ProgramId>(v).unwrap(), p);
        assert!(serde_json::from_value::<ProgramId>(json!("nope")).is_err());
        let schema = serde_json::to_value(schemars::schema_for!(ProgramId)).unwrap();
        assert_eq!(schema["type"], json!("string"));
    }

    #[test]
    fn schema_id_accepts_only_its_literal() {
        assert_eq!(
            serde_json::to_value(TestSchema).unwrap(),
            json!("purge.test/0")
        );
        assert!(serde_json::from_value::<TestSchema>(json!("purge.test/0")).is_ok());
        assert!(serde_json::from_value::<TestSchema>(json!("purge.test/1")).is_err());
        // An escaped string cannot be borrowed from the input; it must still be accepted.
        assert!(serde_json::from_str::<TestSchema>(r#""purge.test\/0""#).is_ok());
    }

    #[test]
    fn file_time_converts_to_unix_seconds() {
        assert_eq!(FileTime::from_unix_secs(0).0, 116_444_736_000_000_000);
        assert_eq!(
            FileTime::from_unix_secs(1_700_000_000).to_unix_secs(),
            1_700_000_000
        );
        assert_eq!(FileTime(0).to_unix_secs(), -11_644_473_600);
        assert_eq!(FileTime::from_unix_secs(i64::MIN).0, 0);
        assert_eq!(serde_json::to_value(FileTime(5)).unwrap(), json!(5));
    }
}
