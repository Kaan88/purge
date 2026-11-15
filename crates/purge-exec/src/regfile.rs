//! Generator of a `.reg` text from a registry backup, for the user (M2-X-REGBACKUP).
//!
//! ENGINE_PLAN.md §7.4, §10.1. The `purge.regbackup/1` JSON document is what undo restores from; this module
//! only renders it as a registry editor import file, on request, so that a person can read it or import it
//! by hand. It is a pure function of the document: no registry or file access.
//!
//! Format: UTF-16LE with a byte order mark, CRLF line ends, the header line [`HEADER`], then one `[key]`
//! block per key (parent before child) holding its values:
//!
//! - the default value as `@`, other names in double quotes with `\` and `"` escaped;
//! - `REG_SZ` data that is plain text with exactly one terminating NUL as a quoted string, otherwise as
//!   `hex(1):`;
//! - `REG_DWORD` with exactly four bytes as `dword:` and eight hex digits, otherwise as `hex(4):`;
//! - `REG_BINARY` as `hex:`, every other type `N` as `hex(N):` (`hex(2)` expandable string, `hex(7)` multi
//!   string, `hex(b)` QWORD, …) with the raw bytes, so any data, odd lengths included, is kept exactly;
//! - long byte lists wrapped with a trailing `\` and continued on lines indented by two spaces.
//!
//! A `.reg` file cannot carry key classes or security descriptors; they stay in the JSON backup only. Names
//! that a `.reg` line cannot hold (a NUL, a line break, not valid UTF-16) make the generator refuse.

use purge_model::exec::regbackup::{RegBackup, RegBackupBody, RegTree, ValueBackup, WideB64};

/// The first line of every file.
pub const HEADER: &str = "Windows Registry Editor Version 5.00";

/// Width at which byte lists are wrapped, including the continuation `\`.
const LINE_WIDTH: usize = 80;

/// `REG_SZ`.
const REG_SZ: u32 = 1;
/// `REG_BINARY`.
const REG_BINARY: u32 = 3;
/// `REG_DWORD`.
const REG_DWORD: u32 = 4;

/// Why a backup cannot be rendered as a `.reg` file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegFileError {
    /// The backup's key path does not start with `HKLM` or `HKU`.
    #[error("the key path {0:?} does not start with HKLM or HKU")]
    UnknownRoot(String),
    /// A key or value name holds a NUL or a line break, or is not valid UTF-16.
    #[error("a key or value name cannot be written to a .reg file: {0:?}")]
    NameNotRepresentable(String),
    /// The tree is flagged as holding a registry link.
    #[error("the backup holds a registry link")]
    Link,
    /// The tree's shape is broken.
    #[error("the backup tree is not well-formed: {0}")]
    Malformed(String),
}

/// A name as `.reg` text: valid UTF-16 without NUL, CR or LF.
fn reg_name(name: &WideB64) -> Result<String, RegFileError> {
    let text = String::from_utf16(&name.0)
        .map_err(|_| RegFileError::NameNotRepresentable(name.to_string_lossy()))?;
    if text.contains(['\0', '\r', '\n']) {
        return Err(RegFileError::NameNotRepresentable(name.to_string_lossy()));
    }
    Ok(text)
}

/// `text` between double quotes, with `\` and `"` escaped.
fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        if matches!(c, '\\' | '"') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// The long form of the backup's key path (`HKEY_LOCAL_MACHINE\…`, `HKEY_USERS\…`).
fn long_key_path(key: &str) -> Result<String, RegFileError> {
    let trimmed = key.trim_end_matches('\\');
    let (root, rest) = trimmed.split_once('\\').unwrap_or((trimmed, ""));
    let long =
        if root.eq_ignore_ascii_case("HKLM") || root.eq_ignore_ascii_case("HKEY_LOCAL_MACHINE") {
            "HKEY_LOCAL_MACHINE"
        } else if root.eq_ignore_ascii_case("HKU") || root.eq_ignore_ascii_case("HKEY_USERS") {
            "HKEY_USERS"
        } else {
            return Err(RegFileError::UnknownRoot(key.to_owned()));
        };
    if rest.contains(['\0', '\r', '\n']) {
        return Err(RegFileError::NameNotRepresentable(key.to_owned()));
    }
    Ok(if rest.is_empty() {
        long.to_owned()
    } else {
        format!("{long}\\{rest}")
    })
}

/// The data as a `.reg` string, when it is plain text with exactly one terminating NUL.
fn plain_string(data: &[u8]) -> Option<String> {
    if data.len() < 2 || data.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let (last, body) = units.split_last()?;
    if *last != 0 || body.contains(&0) {
        return None;
    }
    let text = String::from_utf16(body).ok()?;
    (!text.contains(['\r', '\n'])).then_some(text)
}

/// Appends `prefix` and the bytes as a comma-separated hex list, wrapped at [`LINE_WIDTH`].
fn push_hex(out: &mut String, prefix: &str, data: &[u8]) {
    let mut line = prefix.to_owned();
    let mut on_line = 0usize;
    for (i, byte) in data.iter().enumerate() {
        let piece = if i + 1 == data.len() {
            format!("{byte:02x}")
        } else {
            format!("{byte:02x},")
        };
        if on_line > 0 && line.chars().count() + piece.len() + 1 > LINE_WIDTH {
            out.push_str(&line);
            out.push_str("\\\r\n");
            line = "  ".to_owned();
            on_line = 0;
        }
        line.push_str(&piece);
        on_line += 1;
    }
    out.push_str(&line);
    out.push_str("\r\n");
}

/// Appends one value line.
fn push_value(out: &mut String, value: &ValueBackup) -> Result<(), RegFileError> {
    let name = if value.name_b64.0.is_empty() {
        "@".to_owned()
    } else {
        quoted(&reg_name(&value.name_b64)?)
    };
    let data = &value.data_b64.0;
    match value.value_type {
        REG_SZ => {
            if let Some(text) = plain_string(data) {
                out.push_str(&format!("{name}={}\r\n", quoted(&text)));
                return Ok(());
            }
        }
        REG_DWORD => {
            if let Ok(bytes) = <[u8; 4]>::try_from(data.as_slice()) {
                out.push_str(&format!(
                    "{name}=dword:{:08x}\r\n",
                    u32::from_le_bytes(bytes)
                ));
                return Ok(());
            }
        }
        _ => {}
    }
    let prefix = if value.value_type == REG_BINARY {
        format!("{name}=hex:")
    } else {
        format!("{name}=hex({:x}):", value.value_type)
    };
    push_hex(out, &prefix, data);
    Ok(())
}

/// The full path of every key of the tree, parent-first.
fn key_paths(root_path: &str, tree: &RegTree) -> Result<Vec<String>, RegFileError> {
    let mut paths: Vec<String> = Vec::with_capacity(tree.keys.len());
    for (i, key) in tree.keys.iter().enumerate() {
        let path = match key.parent {
            None if i == 0 => root_path.to_owned(),
            Some(parent) if (parent as usize) < i => {
                format!("{}\\{}", paths[parent as usize], reg_name(&key.name_b64)?)
            }
            _ => return Err(RegFileError::Malformed(format!("key {i} has a bad parent"))),
        };
        paths.push(path);
    }
    Ok(paths)
}

/// Renders a backup as `.reg` text (CRLF line ends, no byte order mark). [`reg_file_bytes`] gives the file
/// form.
pub fn reg_text(backup: &RegBackup) -> Result<String, RegFileError> {
    let root_path = long_key_path(&backup.key)?;
    let mut out = format!("{HEADER}\r\n\r\n");
    match &backup.body {
        RegBackupBody::Value(value) => {
            out.push_str(&format!("[{root_path}]\r\n"));
            push_value(&mut out, value)?;
            out.push_str("\r\n");
        }
        RegBackupBody::Tree(tree) => {
            tree.validate()
                .map_err(|e| RegFileError::Malformed(e.to_string()))?;
            if tree.has_link() {
                return Err(RegFileError::Link);
            }
            for (key, path) in tree.keys.iter().zip(key_paths(&root_path, tree)?) {
                out.push_str(&format!("[{path}]\r\n"));
                for value in &key.values {
                    push_value(&mut out, value)?;
                }
                out.push_str("\r\n");
            }
        }
    }
    Ok(out)
}

/// Renders a backup as the bytes of a `.reg` file: UTF-16LE with a byte order mark.
pub fn reg_file_bytes(backup: &RegBackup) -> Result<Vec<u8>, RegFileError> {
    let text = reg_text(backup)?;
    let mut bytes = vec![0xff, 0xfe];
    bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_model::FileTime;
    use purge_model::exec::regbackup::{BytesB64, KeyNode, RegBackupSchema};

    fn wide(text: &str) -> WideB64 {
        WideB64::from(text)
    }

    fn utf16z(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    fn value(name: &str, ty: u32, data: Vec<u8>) -> ValueBackup {
        ValueBackup {
            name_b64: wide(name),
            value_type: ty,
            data_b64: BytesB64(data),
        }
    }

    /// Built from JSON so that fields the model adds later (with serde defaults) need no change here.
    fn node(parent: Option<u32>, name: &str, values: Vec<ValueBackup>) -> KeyNode {
        serde_json::from_value(serde_json::json!({
            "parent": parent,
            "name_b64": wide(name),
            "class_b64": null,
            "sddl": "O:BAG:SYD:",
            "last_write_time": 0,
            "link": false,
            "values": values,
        }))
        .expect("key node")
    }

    fn sample() -> RegBackup {
        RegBackup {
            schema: RegBackupSchema,
            key: r"HKLM\SOFTWARE\WOW6432Node\Vendor".into(),
            captured: FileTime(1),
            body: RegBackupBody::Tree(RegTree {
                keys: vec![
                    node(
                        None,
                        "Vendor",
                        vec![
                            value("", REG_SZ, utf16z("Default")),
                            value(r#"Path "q" \x"#, REG_SZ, utf16z(r#"C:\A "b""#)),
                            value("Odd", REG_SZ, vec![0x41, 0x00, 0x42]),
                            value("NoNul", REG_SZ, vec![0x41, 0x00]),
                            value("Flags", REG_DWORD, 0x0102_0304u32.to_le_bytes().to_vec()),
                            value("Short", REG_DWORD, vec![1, 2, 3]),
                            value("Bin", REG_BINARY, vec![]),
                            value("Exp", 2, utf16z("%X%")),
                        ],
                    ),
                    node(
                        Some(0),
                        "Sub",
                        vec![
                            value("Multi", 7, utf16z("a\0b\0")),
                            value("Q", 11, 7u64.to_le_bytes().to_vec()),
                            value("Odd type", 0x1234_5678, vec![0xff]),
                            value("None", 0, vec![]),
                        ],
                    ),
                    node(
                        Some(1),
                        "Deep",
                        vec![value("Long", REG_BINARY, (0..40).collect())],
                    ),
                    node(Some(0), "Empty", vec![]),
                ],
            }),
        }
    }

    const GOLDEN: &str = concat!(
        "Windows Registry Editor Version 5.00\r\n",
        "\r\n",
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Vendor]\r\n",
        "@=\"Default\"\r\n",
        "\"Path \\\"q\\\" \\\\x\"=\"C:\\\\A \\\"b\\\"\"\r\n",
        "\"Odd\"=hex(1):41,00,42\r\n",
        "\"NoNul\"=hex(1):41,00\r\n",
        "\"Flags\"=dword:01020304\r\n",
        "\"Short\"=hex(4):01,02,03\r\n",
        "\"Bin\"=hex:\r\n",
        "\"Exp\"=hex(2):25,00,58,00,25,00,00,00\r\n",
        "\r\n",
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Vendor\\Sub]\r\n",
        "\"Multi\"=hex(7):61,00,00,00,62,00,00,00,00,00\r\n",
        "\"Q\"=hex(b):07,00,00,00,00,00,00,00\r\n",
        "\"Odd type\"=hex(12345678):ff\r\n",
        "\"None\"=hex(0):\r\n",
        "\r\n",
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Vendor\\Sub\\Deep]\r\n",
        "\"Long\"=hex:00,01,02,03,04,05,06,07,08,09,0a,0b,0c,0d,0e,0f,10,11,12,13,14,15,\\\r\n",
        "  16,17,18,19,1a,1b,1c,1d,1e,1f,20,21,22,23,24,25,26,27\r\n",
        "\r\n",
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Vendor\\Empty]\r\n",
        "\r\n",
    );

    #[test]
    fn golden_tree_text() {
        assert_eq!(reg_text(&sample()).unwrap(), GOLDEN);
    }

    #[test]
    fn value_backup_text_and_file_bytes() {
        let backup = RegBackup {
            schema: RegBackupSchema,
            key: r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run".into(),
            captured: FileTime(1),
            body: RegBackupBody::Value(value("Vendor", REG_SZ, utf16z(r#""C:\V\a.exe""#))),
        };
        let text = reg_text(&backup).unwrap();
        assert_eq!(
            text,
            concat!(
                "Windows Registry Editor Version 5.00\r\n\r\n",
                "[HKEY_USERS\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n",
                "\"Vendor\"=\"\\\"C:\\\\V\\\\a.exe\\\"\"\r\n\r\n"
            )
        );
        let bytes = reg_file_bytes(&backup).unwrap();
        assert_eq!(&bytes[..2], &[0xff, 0xfe]);
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        assert_eq!(String::from_utf16(&units).unwrap(), text);
    }

    #[test]
    fn long_lines_wrap_within_the_width() {
        let mut backup = sample();
        let RegBackupBody::Tree(tree) = &mut backup.body else {
            unreachable!()
        };
        tree.keys[3]
            .values
            .push(value(&"N".repeat(120), REG_BINARY, (0..=255).collect()));
        let text = reg_text(&backup).unwrap();
        for line in text.split("\r\n") {
            // Only a line that starts with a long name may exceed the width, and only by its prefix.
            if !line.starts_with("\"NNN") {
                assert!(line.chars().count() <= LINE_WIDTH, "{line:?}");
            }
        }
        assert_eq!(parse(&reg_file_bytes(&backup).unwrap()), expected(&backup));
    }

    #[test]
    fn unrepresentable_input_is_refused() {
        let mut backup = sample();
        backup.key = r"HKCR\x".into();
        assert!(matches!(
            reg_text(&backup),
            Err(RegFileError::UnknownRoot(_))
        ));

        for bad in [
            vec![0x41u16, 0, 0x42],
            vec![0xd800],
            "a\nb".encode_utf16().collect(),
        ] {
            let mut backup = sample();
            let RegBackupBody::Tree(tree) = &mut backup.body else {
                unreachable!()
            };
            tree.keys[1].values[0].name_b64 = WideB64(bad.clone());
            assert!(matches!(
                reg_text(&backup),
                Err(RegFileError::NameNotRepresentable(_))
            ));
            let mut backup = sample();
            let RegBackupBody::Tree(tree) = &mut backup.body else {
                unreachable!()
            };
            tree.keys[2].name_b64 = WideB64(bad);
            assert!(reg_text(&backup).is_err());
        }

        let mut backup = sample();
        let RegBackupBody::Tree(tree) = &mut backup.body else {
            unreachable!()
        };
        tree.keys[2].link = true;
        // Refused either by the model's own tree check or by this module's.
        assert!(matches!(
            reg_text(&backup),
            Err(RegFileError::Link | RegFileError::Malformed(_))
        ));
        let RegBackupBody::Tree(tree) = &mut backup.body else {
            unreachable!()
        };
        tree.keys[2].link = false;
        tree.keys[2].parent = Some(3);
        assert!(matches!(reg_text(&backup), Err(RegFileError::Malformed(_))));
    }

    /// One key of a parsed file: its path and its values as (name, type, data).
    type Parsed = Vec<(String, Vec<(String, u32, Vec<u8>)>)>;

    /// What [`parse`] must give for a backup.
    fn expected(backup: &RegBackup) -> Parsed {
        let root = long_key_path(&backup.key).unwrap();
        let entry = |v: &ValueBackup| {
            (
                v.name_b64.to_string_lossy(),
                v.value_type,
                v.data_b64.0.clone(),
            )
        };
        match &backup.body {
            RegBackupBody::Value(v) => vec![(root, vec![entry(v)])],
            RegBackupBody::Tree(tree) => key_paths(&root, tree)
                .unwrap()
                .into_iter()
                .zip(&tree.keys)
                .map(|(path, key)| (path, key.values.iter().map(entry).collect()))
                .collect(),
        }
    }

    /// Reads a quoted `.reg` string starting at `s[0] == '"'`; returns the text and the rest.
    fn unquote(s: &str) -> (String, &str) {
        assert!(s.starts_with('"'), "{s:?}");
        let mut out = String::new();
        let mut chars = s[1..].char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => out.push(chars.next().unwrap().1),
                '"' => return (out, &s[i + 2..]),
                c => out.push(c),
            }
        }
        panic!("unterminated string in {s:?}");
    }

    /// A small `.reg` reader, independent of the writer, for round trips.
    fn parse(bytes: &[u8]) -> Parsed {
        assert_eq!(&bytes[..2], &[0xff, 0xfe]);
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        let text = String::from_utf16(&units).unwrap();
        let mut lines = text.split("\r\n");
        assert_eq!(lines.next(), Some(HEADER));
        let mut out: Parsed = Vec::new();
        let mut logical = Vec::new();
        let mut pending = String::new();
        for line in lines {
            if let Some(head) = line.strip_suffix('\\') {
                pending.push_str(head.trim_start());
                continue;
            }
            pending.push_str(if pending.is_empty() {
                line
            } else {
                line.trim_start()
            });
            logical.push(std::mem::take(&mut pending));
        }
        for line in logical {
            if line.is_empty() {
                continue;
            }
            if let Some(path) = line.strip_prefix('[') {
                out.push((path.strip_suffix(']').unwrap().to_owned(), Vec::new()));
                continue;
            }
            let (name, rest) = if let Some(rest) = line.strip_prefix('@') {
                (String::new(), rest)
            } else {
                unquote(&line)
            };
            let data = rest.strip_prefix('=').unwrap();
            let (ty, bytes) = if data.starts_with('"') {
                let (text, tail) = unquote(data);
                assert!(tail.is_empty());
                (REG_SZ, utf16z(&text))
            } else if let Some(hex) = data.strip_prefix("dword:") {
                (
                    REG_DWORD,
                    u32::from_str_radix(hex, 16).unwrap().to_le_bytes().to_vec(),
                )
            } else {
                let (ty, list) = if let Some(list) = data.strip_prefix("hex:") {
                    (REG_BINARY, list)
                } else {
                    let inner = data.strip_prefix("hex(").unwrap();
                    let (ty, list) = inner.split_once("):").unwrap();
                    (u32::from_str_radix(ty, 16).unwrap(), list)
                };
                let bytes = if list.is_empty() {
                    Vec::new()
                } else {
                    list.split(',')
                        .map(|b| u8::from_str_radix(b, 16).unwrap())
                        .collect()
                };
                (ty, bytes)
            };
            out.last_mut().unwrap().1.push((name, ty, bytes));
        }
        out
    }

    #[test]
    fn generated_files_parse_back_to_the_backup() {
        let backup = sample();
        assert_eq!(parse(&reg_file_bytes(&backup).unwrap()), expected(&backup));

        // Every byte value, every length up to a few lines, several types.
        let mut keys = vec![node(None, "R", Vec::new())];
        for len in [0usize, 1, 2, 3, 4, 5, 25, 26, 27, 52, 53, 300] {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            for ty in [0u32, REG_SZ, 2, REG_BINARY, REG_DWORD, 7, 11, 0xffff_ffff] {
                keys[0]
                    .values
                    .push(value(&format!("v{len}-{ty}"), ty, data.clone()));
            }
        }
        keys.push(node(Some(0), "a\\b", Vec::new()));
        keys[1].name_b64 = wide("c d");
        let backup = RegBackup {
            schema: RegBackupSchema,
            key: r"HKU\S-1-5-21-9\Software\R".into(),
            captured: FileTime(0),
            body: RegBackupBody::Tree(RegTree { keys }),
        };
        assert_eq!(parse(&reg_file_bytes(&backup).unwrap()), expected(&backup));
    }
}
