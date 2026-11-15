//! The registry backup document `purge.regbackup/1` (ENGINE_PLAN.md §7.4).
//!
//! A backup holds what is needed to put a key tree or one value back exactly: raw value types, raw data
//! bytes, key classes, security as SDDL, and names that are not valid UTF-16 or contain NUL characters.
//! Names and data are therefore carried as base64 ([`WideB64`], [`BytesB64`]), never as JSON strings.
//!
//! A tree is stored flat: [`RegTree::keys`] lists the keys parent-first, and each key names its parent by
//! index. Registry trees can be several hundred keys deep, deeper than a JSON reader's nesting limit, so
//! the document must not nest once per key. The flat list also gives the two walks the executor needs for
//! free: restore goes front to back, delete goes back to front (deepest first).

use std::borrow::Cow;
use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::FileTime;
use crate::ids::schema_id;

schema_id!(
    /// The `schema` field of a registry backup: always the literal string `purge.regbackup/1`.
    /// Deserialising any other value fails.
    RegBackupSchema = "purge.regbackup/1"
);

/// Why a string is not canonical base64, or does not hold what the field needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// The length is not a multiple of four.
    BadLength,
    /// A character is outside the standard alphabet, or `=` stands anywhere but at the end.
    BadCharacter,
    /// The unused bits of the last group are not zero, so the text is not the one canonical spelling.
    NonCanonical,
    /// The bytes of a UTF-16 name are odd in number.
    OddLength,
}

impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadLength => "base64 length is not a multiple of four",
            Self::BadCharacter => "base64 text has a character outside the standard alphabet",
            Self::NonCanonical => "base64 text has non-zero padding bits",
            Self::OddLength => "a UTF-16 name needs an even number of bytes",
        })
    }
}

impl std::error::Error for Base64Error {}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes bytes as standard base64 (RFC 4648 §4) with `=` padding.
fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let sextet = |n: u32, shift: u32| char::from(ALPHABET[((n >> shift) & 63) as usize]);
    for chunk in bytes.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        out.push(sextet(n, 18));
        out.push(sextet(n, 12));
        out.push(if chunk.len() > 1 { sextet(n, 6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(n, 0) } else { '=' });
    }
    out
}

/// Decodes standard base64 with `=` padding. Only the one canonical spelling of each byte string is
/// accepted: no whitespace, no missing padding, no stray bits.
fn b64_decode(text: &str) -> Result<Vec<u8>, Base64Error> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(Base64Error::BadLength);
    }
    let value = |c: u8| -> Result<u32, Base64Error> {
        match c {
            b'A'..=b'Z' => Ok(u32::from(c - b'A')),
            b'a'..=b'z' => Ok(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Ok(u32::from(c - b'0') + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(Base64Error::BadCharacter),
        }
    };
    let groups = bytes.len() / 4;
    let mut out = Vec::with_capacity(groups * 3);
    for (i, group) in bytes.chunks_exact(4).enumerate() {
        // Padding may only close the last group: `xx==` or `xxx=`.
        let pad = match (i + 1 == groups, group[2], group[3]) {
            (true, b'=', b'=') => 2,
            (true, _, b'=') => 1,
            _ => 0,
        };
        let mut n = 0u32;
        for &c in &group[..4 - pad] {
            n = (n << 6) | value(c)?;
        }
        n <<= 6 * pad;
        let spare_bits = match pad {
            2 => n & 0xffff,
            1 => n & 0xff,
            _ => 0,
        };
        if spare_bits != 0 {
            return Err(Base64Error::NonCanonical);
        }
        let [_, b0, b1, b2] = n.to_be_bytes();
        out.push(b0);
        if pad < 2 {
            out.push(b1);
        }
        if pad < 1 {
            out.push(b2);
        }
    }
    Ok(out)
}

/// The JSON Schema of a base64 string field.
fn b64_schema(description: &str) -> Schema {
    json_schema!({
        "type": "string",
        "contentEncoding": "base64",
        "description": description,
        "pattern": "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
    })
}

/// Raw bytes, serialised as standard base64 with padding. Used for value data.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct BytesB64(pub Vec<u8>);

impl fmt::Debug for BytesB64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BytesB64({} bytes)", self.0.len())
    }
}

impl From<Vec<u8>> for BytesB64 {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Serialize for BytesB64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&b64_encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for BytesB64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Cow::<str>::deserialize(deserializer)?;
        b64_decode(&text)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for BytesB64 {
    fn schema_name() -> Cow<'static, str> {
        "BytesB64".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        b64_schema("Raw bytes as standard base64 with padding")
    }
}

/// A registry name or class as its UTF-16 code units, serialised as the base64 of their little-endian
/// bytes, without a terminator.
///
/// Registry names are counted strings: they may hold lone surrogates and NUL characters, which a JSON
/// string cannot carry faithfully. The code units are kept exactly as Windows returned them.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct WideB64(pub Vec<u16>);

impl WideB64 {
    /// The code units.
    pub fn units(&self) -> &[u16] {
        &self.0
    }

    /// The name as text for messages, with `U+FFFD` in place of each lone surrogate. Never use the result
    /// to address a key or value.
    pub fn to_string_lossy(&self) -> String {
        String::from_utf16_lossy(&self.0)
    }
}

impl fmt::Debug for WideB64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WideB64({:?})", self.to_string_lossy())
    }
}

impl From<&str> for WideB64 {
    fn from(text: &str) -> Self {
        Self(text.encode_utf16().collect())
    }
}

impl From<Vec<u16>> for WideB64 {
    fn from(units: Vec<u16>) -> Self {
        Self(units)
    }
}

impl Serialize for WideB64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes: Vec<u8> = self.0.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        serializer.serialize_str(&b64_encode(&bytes))
    }
}

impl<'de> Deserialize<'de> for WideB64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Cow::<str>::deserialize(deserializer)?;
        let bytes = b64_decode(&text).map_err(serde::de::Error::custom)?;
        if bytes.len() % 2 != 0 {
            return Err(serde::de::Error::custom(Base64Error::OddLength));
        }
        Ok(Self(
            bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect(),
        ))
    }
}

impl JsonSchema for WideB64 {
    fn schema_name() -> Cow<'static, str> {
        "WideB64".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        b64_schema("UTF-16LE code units as standard base64 with padding")
    }
}

/// One registry value: its name, raw type and raw data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ValueBackup {
    /// The value name; empty for the default value.
    pub name_b64: WideB64,
    /// The raw value type as Windows reports it. Any `u32` is kept, also types without a `REG_*` name.
    #[serde(rename = "type")]
    pub value_type: u32,
    /// The raw data bytes, exactly as stored (terminators included or missing as they were).
    pub data_b64: BytesB64,
}

/// One key of a backed-up tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct KeyNode {
    /// Index of the parent key in [`RegTree::keys`]; `None` for the root, which is always first.
    pub parent: Option<u32>,
    /// The key's own name (the last path component). For the root it is the leaf name of
    /// [`RegBackup::key`].
    pub name_b64: WideB64,
    /// The key's class string, when it has one.
    pub class_b64: Option<WideB64>,
    /// Owner, group and DACL of the key as one SDDL string (`O:…G:…D:…`).
    pub sddl: String,
    /// The key's last write time when it was captured. Restoring a key cannot set it; it is kept for the
    /// record.
    pub last_write_time: FileTime,
    /// Whether the key is a registry link. The capture walk refuses links, so a backup written by Purge
    /// always holds `false`; a reader refuses to restore from a tree that says otherwise.
    pub link: bool,
    /// The key's values, in enumeration order.
    pub values: Vec<ValueBackup>,
}

/// Why a [`RegTree`] is not well-formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegTreeError {
    /// The tree has no keys.
    Empty,
    /// The first key names a parent.
    RootHasParent,
    /// The key at this index has no parent, or a parent that does not come before it.
    BadParent(usize),
    /// The key at this index (not the root) has an empty name or a name with a `\`.
    BadName(usize),
}

impl fmt::Display for RegTreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the tree has no keys"),
            Self::RootHasParent => f.write_str("the root key names a parent"),
            Self::BadParent(i) => write!(f, "key {i} does not name an earlier key as its parent"),
            Self::BadName(i) => write!(f, "key {i} has an empty name or a name with a backslash"),
        }
    }
}

impl std::error::Error for RegTreeError {}

/// A key with everything under it, stored flat and parent-first.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct RegTree {
    /// The keys. The root is first; every other key comes after its parent.
    pub keys: Vec<KeyNode>,
}

impl RegTree {
    /// Checks the shape: a root without a parent comes first, every other key names an earlier key as its
    /// parent and has a usable name. Call it after reading a backup and before acting on it; the other
    /// methods assume it passed.
    pub fn validate(&self) -> Result<(), RegTreeError> {
        let root = self.keys.first().ok_or(RegTreeError::Empty)?;
        if root.parent.is_some() {
            return Err(RegTreeError::RootHasParent);
        }
        for (i, key) in self.keys.iter().enumerate().skip(1) {
            match key.parent {
                Some(parent) if (parent as usize) < i => {}
                _ => return Err(RegTreeError::BadParent(i)),
            }
            if key.name_b64.0.is_empty() || key.name_b64.0.contains(&u16::from(b'\\')) {
                return Err(RegTreeError::BadName(i));
            }
        }
        Ok(())
    }

    /// The number of values over all keys.
    pub fn value_count(&self) -> usize {
        self.keys.iter().map(|key| key.values.len()).sum()
    }

    /// Whether any key is flagged as a registry link.
    pub fn has_link(&self) -> bool {
        self.keys.iter().any(|key| key.link)
    }

    /// The names from just below the root down to the key at `index`; empty for the root. Returns `None`
    /// when the index or a parent link is out of range.
    pub fn rel_path(&self, index: usize) -> Option<Vec<&WideB64>> {
        let mut names = Vec::new();
        let mut at = index;
        loop {
            let key = self.keys.get(at)?;
            match key.parent {
                None => break,
                // A parent must come earlier; anything else would loop.
                Some(parent) if (parent as usize) < at => {
                    names.push(&key.name_b64);
                    at = parent as usize;
                }
                Some(_) => return None,
            }
        }
        names.reverse();
        Some(names)
    }

    /// The indexes of the direct subkeys of the key at `index`, in stored order.
    pub fn children(&self, index: usize) -> impl Iterator<Item = usize> + '_ {
        self.keys
            .iter()
            .enumerate()
            .filter(move |(_, key)| key.parent.is_some_and(|p| p as usize == index))
            .map(|(i, _)| i)
    }

    /// The key indexes in an order that visits every key after all keys below it: the order of a
    /// deepest-first delete. The reverse (plain index order) is the order of a restore.
    pub fn deepest_first(&self) -> impl Iterator<Item = usize> {
        (0..self.keys.len()).rev()
    }
}

/// What a backup holds. Serialised as an object tagged by `"kind"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum RegBackupBody {
    /// A key with its subtree (also a single empty key, for a delete-if-empty).
    Tree(RegTree),
    /// One value of the key.
    Value(ValueBackup),
}

/// A registry backup document, `purge.regbackup/1`: one file per op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RegBackup {
    /// Always `purge.regbackup/1`.
    pub schema: RegBackupSchema,
    /// Canonical path of the key the backup belongs to, as `Target` spells it (the 32-bit view as a
    /// `WOW6432Node` segment). For a tree it is the root key; for a value, the key holding the value.
    pub key: String,
    /// When the backup was captured.
    pub captured: FileTime,
    /// The tree or the value.
    pub body: RegBackupBody,
}

impl RegBackup {
    /// The tree, when the backup holds one.
    pub fn tree(&self) -> Option<&RegTree> {
        match &self.body {
            RegBackupBody::Tree(tree) => Some(tree),
            RegBackupBody::Value(_) => None,
        }
    }

    /// The single value, when the backup holds one.
    pub fn value(&self) -> Option<&ValueBackup> {
        match &self.body {
            RegBackupBody::Value(value) => Some(value),
            RegBackupBody::Tree(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> WideB64 {
        WideB64::from(text)
    }

    #[test]
    fn base64_matches_the_rfc_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64_encode(plain.as_bytes()), encoded);
            assert_eq!(b64_decode(encoded).unwrap(), plain.as_bytes());
        }
        assert_eq!(b64_encode(&[0xfb, 0xff, 0xfe]), "+//+");
        assert_eq!(b64_decode("+//+").unwrap(), [0xfb, 0xff, 0xfe]);
        let every_byte: Vec<u8> = (0..=255).collect();
        for len in 0..every_byte.len() {
            let text = b64_encode(&every_byte[..len]);
            assert_eq!(text.len(), len.div_ceil(3) * 4);
            assert_eq!(b64_decode(&text).unwrap(), &every_byte[..len]);
        }
    }

    #[test]
    fn base64_accepts_one_spelling_only() {
        use Base64Error::*;
        for (text, err) in [
            ("Zg", BadLength),
            ("Zg=", BadLength),
            ("Zm9vY", BadLength),
            ("Zg==\n", BadLength),
            ("Zm 9", BadCharacter),
            ("Zm9-", BadCharacter),
            ("Zm9_", BadCharacter),
            ("Zm9é", BadLength),
            ("Zé=", BadCharacter),
            ("====", BadCharacter),
            ("Z===", BadCharacter),
            ("=m9v", BadCharacter),
            ("Zg=v", BadCharacter),
            ("Zg==Zm9v", BadCharacter),
            ("Zm8=Zm9v", BadCharacter),
            // 'h' ends in non-zero bits that no byte produced.
            ("Zh==", NonCanonical),
            ("Zm9=", NonCanonical),
        ] {
            assert_eq!(b64_decode(text), Err(err), "{text:?}");
        }
        assert!(!NonCanonical.to_string().is_empty());
        assert!(serde_json::from_str::<BytesB64>(r#""Zh==""#).is_err());
        assert!(serde_json::from_str::<BytesB64>("12").is_err());
    }

    #[test]
    fn empty_name_is_the_empty_string() {
        let name = WideB64::default();
        assert_eq!(serde_json::to_string(&name).unwrap(), r#""""#);
        assert_eq!(serde_json::from_str::<WideB64>(r#""""#).unwrap(), name);
        assert_eq!(name.to_string_lossy(), "");
        assert_eq!(wide(""), name);
        let data = BytesB64::default();
        assert_eq!(serde_json::to_string(&data).unwrap(), r#""""#);
        assert_eq!(serde_json::from_str::<BytesB64>(r#""""#).unwrap(), data);
    }

    #[test]
    fn names_json_cannot_spell_survive() {
        // A lone high surrogate, a lone low surrogate, an embedded NUL, a trailing NUL, and a pair.
        let cases: [&[u16]; 6] = [
            &[0xd800],
            &[0x0041, 0xdc00, 0x0042],
            &[0x0041, 0x0000, 0x0042],
            &[0x0041, 0x0000],
            &[0xd83d, 0xde00],
            &[0xdc00, 0xd800],
        ];
        for units in cases {
            let name = WideB64(units.to_vec());
            let text = serde_json::to_string(&name).unwrap();
            let back: WideB64 = serde_json::from_str(&text).unwrap();
            assert_eq!(back.units(), units, "{text}");
            assert_eq!(serde_json::to_string(&back).unwrap(), text);
        }
        // The exact bytes: UTF-16LE of U+D800 is 00 D8.
        assert_eq!(
            serde_json::to_string(&WideB64(vec![0xd800])).unwrap(),
            r#""ANg=""#
        );
        assert_eq!(
            serde_json::to_string(&WideB64(vec![0x41, 0, 0x42])).unwrap(),
            r#""QQAAAEIA""#
        );
        assert_eq!(WideB64(vec![0xd800]).to_string_lossy(), "\u{fffd}");
        assert_eq!(format!("{:?}", wide("Run")), r#"WideB64("Run")"#);
        assert_eq!(WideB64::from(vec![0x52u16, 0x75, 0x6e]), wide("Run"));
        // An odd number of bytes is not a UTF-16 name.
        assert!(serde_json::from_str::<WideB64>(r#""Zg==""#).is_err());
        assert!(serde_json::from_str::<WideB64>(r#""Zm9v""#).is_err());
    }

    #[test]
    fn large_value_data_round_trips() {
        // 16 384 bytes with every byte value, NULs included.
        let data: Vec<u8> = (0..16_384u32)
            .map(|i| (i.wrapping_mul(31) >> 3) as u8)
            .collect();
        let value = ValueBackup {
            name_b64: wide("Blob"),
            value_type: 3,
            data_b64: BytesB64::from(data.clone()),
        };
        let text = serde_json::to_string(&value).unwrap();
        let back: ValueBackup = serde_json::from_str(&text).unwrap();
        assert_eq!(back, value);
        assert_eq!(back.data_b64.0, data);
        assert_eq!(serde_json::to_string(&back).unwrap(), text);
        assert_eq!(format!("{:?}", back.data_b64), "BytesB64(16384 bytes)");
        // 16 384 = 3 * 5461 + 1: the encoding ends in `==`.
        assert!(text.ends_with(r#"=="}"#));
        for len in [16_383usize, 16_385, 16_386] {
            let data = BytesB64(vec![0xa5; len]);
            let text = serde_json::to_string(&data).unwrap();
            assert_eq!(serde_json::from_str::<BytesB64>(&text).unwrap(), data);
        }
    }

    /// A tree backup as written to disk: `Vendor` with a default value and a `REG_DWORD`, one subkey with
    /// a class and a `REG_MULTI_SZ`, and below that a key whose name holds a NUL.
    const TREE: &str = concat!(
        r#"{"schema":"purge.regbackup/1","key":"HKLM\\SOFTWARE\\WOW6432Node\\Vendor","captured":134078121020000000,"#,
        r#""body":{"kind":"Tree","keys":["#,
        r#"{"parent":null,"name_b64":"VgBlAG4AZABvAHIA","class_b64":null,"sddl":"O:BAG:SYD:AI(A;CIID;KA;;;BA)(A;CIID;KR;;;BU)","#,
        r#""last_write_time":134078000000000000,"link":false,"values":["#,
        r#"{"name_b64":"","type":1,"data_b64":"aABpAAAA"},"#,
        r#"{"name_b64":"RgBsAGEAZwBzAA==","type":4,"data_b64":"AQAAAA=="}]},"#,
        r#"{"parent":0,"name_b64":"UwBlAHQAdABpAG4AZwBzAA==","class_b64":"QwBsAHMA","sddl":"O:BAG:SYD:AI(A;CIID;KA;;;BA)","#,
        r#""last_write_time":134078000000000001,"link":false,"values":["#,
        r#"{"name_b64":"TABpAHMAdAA=","type":7,"data_b64":"YQAAAGIAAAAAAA=="}]},"#,
        r#"{"parent":1,"name_b64":"QQAAAEIA","class_b64":null,"sddl":"O:BAG:SYD:","last_write_time":0,"link":false,"values":[]},"#,
        r#"{"parent":0,"name_b64":"RQBtAHAAdAB5AA==","class_b64":null,"sddl":"O:BAG:SYD:","last_write_time":5,"link":false,"values":[]}"#,
        r#"]}}"#
    );

    const VALUE: &str = concat!(
        r#"{"schema":"purge.regbackup/1","key":"HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","#,
        r#""captured":134078121020000000,"body":{"kind":"Value","name_b64":"VgBlAG4AZABvAHIA","type":2,"data_b64":"IgBDADoAXABWAFwAYQAuAGUAeABlACIAAAA="}}"#
    );

    #[test]
    fn tree_backup_round_trips_byte_for_byte() {
        let backup: RegBackup = serde_json::from_str(TREE).unwrap();
        assert_eq!(serde_json::to_string(&backup).unwrap(), TREE);
        assert!(backup.value().is_none());
        let tree = backup.tree().unwrap();
        tree.validate().unwrap();
        assert_eq!((tree.keys.len(), tree.value_count()), (4, 3));
        assert!(!tree.has_link());

        let root = &tree.keys[0];
        assert_eq!(root.name_b64, wide("Vendor"));
        assert_eq!(root.values[0].name_b64, wide(""));
        assert_eq!(root.values[0].data_b64.0, [b'h', 0, b'i', 0, 0, 0]);
        assert_eq!(
            (root.values[1].value_type, &root.values[1].data_b64.0[..]),
            (4, &[1, 0, 0, 0][..])
        );
        assert_eq!(tree.keys[1].class_b64, Some(wide("Cls")));
        assert_eq!(tree.keys[2].name_b64.units(), [0x41, 0, 0x42]);

        assert_eq!(tree.rel_path(0).unwrap(), Vec::<&WideB64>::new());
        assert_eq!(tree.rel_path(1).unwrap(), [&wide("Settings")]);
        assert_eq!(
            tree.rel_path(2).unwrap(),
            [&wide("Settings"), &WideB64(vec![0x41, 0, 0x42])]
        );
        assert!(tree.rel_path(4).is_none());
        assert_eq!(tree.children(0).collect::<Vec<_>>(), [1, 3]);
        assert_eq!(tree.children(1).collect::<Vec<_>>(), [2]);
        assert_eq!(tree.children(3).count(), 0);
        assert_eq!(tree.deepest_first().collect::<Vec<_>>(), [3, 2, 1, 0]);
        // Deepest first: every key comes before its parent.
        let order: Vec<usize> = tree.deepest_first().collect();
        for (pos, &i) in order.iter().enumerate() {
            if let Some(parent) = tree.keys[i].parent {
                assert!(order[pos..].contains(&(parent as usize)));
            }
        }
    }

    #[test]
    fn value_backup_round_trips_byte_for_byte() {
        let backup: RegBackup = serde_json::from_str(VALUE).unwrap();
        assert_eq!(serde_json::to_string(&backup).unwrap(), VALUE);
        assert!(backup.tree().is_none());
        let value = backup.value().unwrap();
        assert_eq!(value.name_b64, wide("Vendor"));
        assert_eq!(value.value_type, 2);
        let text: Vec<u16> = value
            .data_b64
            .0
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        assert_eq!(String::from_utf16(&text).unwrap(), "\"C:\\V\\a.exe\"\0");
    }

    #[test]
    fn other_schema_ids_are_refused() {
        for sample in [TREE, VALUE] {
            for other in [
                "purge.regbackup/0",
                "purge.regbackup/2",
                "purge.journal/1",
                "",
            ] {
                let changed = sample.replace("purge.regbackup/1", other);
                assert!(
                    serde_json::from_str::<RegBackup>(&changed).is_err(),
                    "{other}"
                );
            }
            let without = sample.replace(r#""schema":"purge.regbackup/1","#, "");
            assert!(serde_json::from_str::<RegBackup>(&without).is_err());
        }
        // One changed byte in a base64 field is either another value or no document at all; it never
        // reads as the same backup.
        let original: RegBackup = serde_json::from_str(TREE).unwrap();
        let tampered = TREE.replace("AQAAAA==", "AgAAAA==");
        assert_ne!(
            serde_json::from_str::<RegBackup>(&tampered).unwrap(),
            original
        );
        let broken = TREE.replace("AQAAAA==", "AQAAAB==");
        assert!(serde_json::from_str::<RegBackup>(&broken).is_err());
    }

    #[test]
    fn malformed_trees_are_refused() {
        let tree = || -> RegTree {
            serde_json::from_str::<RegBackup>(TREE)
                .unwrap()
                .tree()
                .unwrap()
                .clone()
        };
        assert_eq!(
            RegTree { keys: vec![] }.validate(),
            Err(RegTreeError::Empty)
        );

        let mut t = tree();
        t.keys[0].parent = Some(0);
        assert_eq!(t.validate(), Err(RegTreeError::RootHasParent));

        let mut t = tree();
        t.keys[2].parent = None;
        assert_eq!(t.validate(), Err(RegTreeError::BadParent(2)));

        // A key may not be its own parent or name a later key: either would make a cycle.
        for parent in [1, 2, 3, 99] {
            let mut t = tree();
            t.keys[1].parent = Some(parent);
            assert_eq!(t.validate(), Err(RegTreeError::BadParent(1)), "{parent}");
            assert!(t.rel_path(1).is_none());
        }

        let mut t = tree();
        t.keys[3].name_b64 = wide("");
        assert_eq!(t.validate(), Err(RegTreeError::BadName(3)));
        let mut t = tree();
        t.keys[3].name_b64 = wide(r"A\B");
        assert_eq!(t.validate(), Err(RegTreeError::BadName(3)));
        assert!(!RegTreeError::BadName(3).to_string().is_empty());

        // The root's name is not judged (a hive root has none), and a link flag is reported, not hidden.
        let mut t = tree();
        t.keys[0].name_b64 = wide("");
        t.keys[1].link = true;
        assert_eq!(t.validate(), Ok(()));
        assert!(t.has_link());
    }

    #[test]
    fn a_deep_tree_reads_back() {
        // 600 keys in one chain: deeper than a JSON reader's nesting limit, which a nested document would
        // hit.
        let keys: Vec<KeyNode> = (0..600u32)
            .map(|i| KeyNode {
                parent: i.checked_sub(1),
                name_b64: wide(&format!("k{i}")),
                class_b64: None,
                sddl: "O:BAG:SYD:".into(),
                last_write_time: FileTime(u64::from(i)),
                link: false,
                values: Vec::new(),
            })
            .collect();
        let backup = RegBackup {
            schema: RegBackupSchema,
            key: r"HKLM\SOFTWARE\k0".into(),
            captured: FileTime(1),
            body: RegBackupBody::Tree(RegTree { keys }),
        };
        let text = serde_json::to_string(&backup).unwrap();
        let back: RegBackup = serde_json::from_str(&text).unwrap();
        assert_eq!(back, backup);
        let tree = back.tree().unwrap();
        tree.validate().unwrap();
        assert_eq!(tree.rel_path(599).unwrap().len(), 599);
        assert_eq!(tree.deepest_first().next(), Some(599));
    }

    #[test]
    fn json_schema_is_generated() {
        let text = serde_json::to_string(&schemars::schema_for!(RegBackup)).unwrap();
        for name in [
            r#""const":"purge.regbackup/1""#,
            "name_b64",
            "data_b64",
            "class_b64",
            "last_write_time",
            "sddl",
            "contentEncoding",
            "WideB64",
            "BytesB64",
            "\"type\"",
            "\"link\"",
        ] {
            assert!(text.contains(name), "schema lacks {name}");
        }
    }
}
