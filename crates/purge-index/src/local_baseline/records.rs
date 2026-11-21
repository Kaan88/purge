//! The text records a local baseline is built from (BASELINE_LOCAL_DESIGN.md §3.2, §3.5).
//!
//! [`Records`] is the union of what every source says is Windows' own: registry keys, value names, and
//! file and directory paths, as the `K`, `V`, `D` and `F` records of the baseline format
//! (`kb/baselines/README.md`). It holds **text**, never hashes: hashing happens only in the loader
//! ([`crate::baseline::Baseline::from_reader`]), which also applies the normaliser (roots, views,
//! control sets, SIDs, profiles). The records only add (L1): nothing is ever removed.
//!
//! # Form
//!
//! - Text is case-folded with the engine's one fold (`purge_guard::prefix::fold`, the fold the loader
//!   applies too), so two spellings of one key are one record and the output does not depend on which
//!   manifest was read first.
//! - Registry keys use the canonical roots the caller gives (`HKLM\…`, `HKU\…`); empty segments (a
//!   trailing or doubled `\`) are dropped. Paths take `\` for `/` and drop empty segments.
//! - Both sets are **closed under ancestors**: recording a key records every key above it down to the
//!   first segment below the root (`HKLM\SOFTWARE`, `HKU\<sid>`), and recording a path records every
//!   directory above it down to the first segment below the drive (`C:\Windows`). A bare root (`HKLM`,
//!   `C:`) is never a record: no capture scope holds one.
//! - A value's key is always a key record as well.
//!
//! [`Records::write_records`] writes the records sorted (`K`, then `V`, `D`, `F`) and escaped as the
//! format says; the same records always give the same bytes.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::sync::Arc;

use purge_guard::prefix;

use crate::baseline::RecordCounts;

/// The hash a `V` record of a local baseline carries: none. Only the value's name is ever used
/// (BASELINE_LOCAL_DESIGN.md §3.3, §4.3).
pub const NO_DATA_HASH: &str = "0000000000000000";

/// One `V` record: a value name in a key, with its registry type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueRecord {
    key: Arc<str>,
    name: Arc<str>,
    ty: u32,
}

impl ValueRecord {
    /// The key (folded).
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The value name (folded); `""` is the default value.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The registry type (`REG_SZ` = 1, …).
    pub fn ty(&self) -> u32 {
        self.ty
    }
}

/// The records of a local baseline. See the module documentation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Records {
    keys: BTreeSet<Arc<str>>,
    values: BTreeSet<ValueRecord>,
    dirs: BTreeSet<Box<str>>,
    files: BTreeSet<Box<str>>,
    /// Every value name in `values`, once: the records share the text (most names repeat many
    /// thousand times, and one allocation each was a fifth of the build's memory).
    names: BTreeSet<Arc<str>>,
}

impl Records {
    /// No records.
    pub fn new() -> Records {
        Records::default()
    }

    /// Records a registry key and every key above it. `false` (and nothing recorded) when the key has
    /// no segment below its root.
    pub fn add_key(&mut self, key: &str) -> bool {
        self.intern_key(key).is_some()
    }

    /// Records a value name (`""` for the default value) of this type in `key`, and the key with its
    /// ancestors. `false` (and nothing recorded) when the key has no segment below its root.
    pub fn add_value(&mut self, key: &str, name: &str, ty: u32) -> bool {
        let Some(key) = self.intern_key(key) else {
            return false;
        };
        let name = self.intern_name(Arc::from(prefix::fold(name)));
        self.values.insert(ValueRecord { key, name, ty });
        true
    }

    /// Records a directory and every directory above it. `false` when the path has no segment below
    /// its first one (a bare drive).
    pub fn add_dir(&mut self, path: &str) -> bool {
        let Some(path) = clean(&prefix::fold(path).replace('/', "\\")) else {
            return false;
        };
        insert_closed(&mut self.dirs, &path, |s| s.into());
        true
    }

    /// Records a file and every directory above it. `false` when the path has no segment below its
    /// first one.
    pub fn add_file(&mut self, path: &str) -> bool {
        let Some(path) = clean(&prefix::fold(path).replace('/', "\\")) else {
            return false;
        };
        if let Some(parent) = parent(&path) {
            insert_closed(&mut self.dirs, parent, |s| s.into());
        }
        if !self.files.contains(path.as_str()) {
            self.files.insert(path.into_boxed_str());
        }
        true
    }

    /// Adds every record of `other`.
    pub fn merge(&mut self, other: Records) {
        for key in other.keys {
            if !self.keys.contains(&*key) {
                self.keys.insert(key);
            }
        }
        for value in other.values {
            // Share the key text with the key record.
            let key = self.keys.get(&*value.key).cloned().unwrap_or(value.key);
            let name = self.intern_name(value.name);
            self.values.insert(ValueRecord {
                key,
                name,
                ty: value.ty,
            });
        }
        self.dirs.extend(other.dirs);
        self.files.extend(other.files);
    }

    /// Whether this very key text (folded, empty segments dropped; no other normalisation) is recorded.
    pub fn contains_key(&self, key: &str) -> bool {
        clean(&prefix::fold(key)).is_some_and(|k| self.keys.contains(k.as_str()))
    }

    /// Whether this value name is recorded in this key text (any type).
    pub fn contains_value(&self, key: &str, name: &str) -> bool {
        let Some(key) = clean(&prefix::fold(key)) else {
            return false;
        };
        let bound = |ty| ValueRecord {
            key: Arc::from(key.as_str()),
            name: Arc::from(prefix::fold(name)),
            ty,
        };
        self.values
            .range(bound(0)..=bound(u32::MAX))
            .next()
            .is_some()
    }

    /// Whether this directory is recorded.
    pub fn contains_dir(&self, path: &str) -> bool {
        clean(&prefix::fold(path).replace('/', "\\"))
            .is_some_and(|p| self.dirs.contains(p.as_str()))
    }

    /// Whether this file is recorded.
    pub fn contains_file(&self, path: &str) -> bool {
        clean(&prefix::fold(path).replace('/', "\\"))
            .is_some_and(|p| self.files.contains(p.as_str()))
    }

    /// The key records, sorted.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|k| &**k)
    }

    /// The value records, sorted by key, name and type.
    pub fn values(&self) -> impl Iterator<Item = &ValueRecord> {
        self.values.iter()
    }

    /// The directory records, sorted.
    pub fn dirs(&self) -> impl Iterator<Item = &str> {
        self.dirs.iter().map(|d| &**d)
    }

    /// The file records, sorted.
    pub fn files(&self) -> impl Iterator<Item = &str> {
        self.files.iter().map(|f| &**f)
    }

    /// How many records of each type there are.
    pub fn counts(&self) -> RecordCounts {
        let n = |len: usize| u64::try_from(len).unwrap_or(u64::MAX);
        RecordCounts {
            keys: n(self.keys.len()),
            values: n(self.values.len()),
            dirs: n(self.dirs.len()),
            files: n(self.files.len()),
        }
    }

    /// Whether there are no records at all.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
            && self.values.is_empty()
            && self.dirs.is_empty()
            && self.files.is_empty()
    }

    /// Writes the record lines (no header, no trailer): `K`, then `V` with [`NO_DATA_HASH`], then `D`,
    /// then `F`, each sorted, fields escaped as `kb/baselines/README.md` says, LF line ends.
    pub fn write_records<W: Write>(&self, out: &mut W) -> io::Result<()> {
        let mut line = String::with_capacity(512);
        for key in &self.keys {
            record_line(&mut line, 'K', &[key]);
            out.write_all(line.as_bytes())?;
        }
        for v in &self.values {
            value_line(&mut line, v);
            out.write_all(line.as_bytes())?;
        }
        for dir in &self.dirs {
            record_line(&mut line, 'D', &[dir]);
            out.write_all(line.as_bytes())?;
        }
        for file in &self.files {
            record_line(&mut line, 'F', &[file]);
            out.write_all(line.as_bytes())?;
        }
        Ok(())
    }

    /// [`Records::write_records`], consuming the records: every record is freed once it is written,
    /// so the memory the sets hold goes down while the output grows. The same bytes.
    pub fn write_records_owned<W: Write>(self, out: &mut W) -> io::Result<()> {
        let Records {
            keys,
            values,
            dirs,
            files,
            names,
        } = self;
        drop(names);
        let mut line = String::with_capacity(512);
        // A key's text is shared with its value records; it is freed with the last of them.
        for key in keys {
            record_line(&mut line, 'K', &[&key]);
            out.write_all(line.as_bytes())?;
        }
        for v in values {
            value_line(&mut line, &v);
            out.write_all(line.as_bytes())?;
        }
        for dir in dirs {
            record_line(&mut line, 'D', &[&dir]);
            out.write_all(line.as_bytes())?;
        }
        for file in files {
            record_line(&mut line, 'F', &[&file]);
            out.write_all(line.as_bytes())?;
        }
        Ok(())
    }

    /// The shared text of a value name (folded), recorded on first use.
    fn intern_name(&mut self, name: Arc<str>) -> Arc<str> {
        match self.names.get(&*name) {
            Some(shared) => Arc::clone(shared),
            None => {
                self.names.insert(Arc::clone(&name));
                name
            }
        }
    }

    /// Records a key with its ancestors and returns the shared text of the key itself.
    fn intern_key(&mut self, key: &str) -> Option<Arc<str>> {
        let key = clean(&prefix::fold(key))?;
        insert_closed(&mut self.keys, &key, |s| Arc::from(s));
        self.keys.get(key.as_str()).cloned()
    }
}

/// Appends `s` escaped as the baseline format says: `\`, TAB, LF, CR and NUL become `\\`, `\t`, `\n`,
/// `\r` and `\0`.
pub fn escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\0' => out.push_str("\\0"),
            c => out.push(c),
        }
    }
}

fn value_line(line: &mut String, v: &ValueRecord) {
    line.clear();
    line.push_str("V\t");
    escape_into(&v.key, line);
    line.push('\t');
    escape_into(&v.name, line);
    line.push('\t');
    line.push_str(&v.ty.to_string());
    line.push('\t');
    line.push_str(NO_DATA_HASH);
    line.push('\n');
}

fn record_line(line: &mut String, tag: char, fields: &[&str]) {
    line.clear();
    line.push(tag);
    for field in fields {
        line.push('\t');
        escape_into(field, line);
    }
    line.push('\n');
}

/// The text with empty segments dropped, or `None` when fewer than two segments are left.
fn clean(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut segments = 0usize;
    for segment in text.split('\\').filter(|s| !s.is_empty()) {
        if segments > 0 {
            out.push('\\');
        }
        out.push_str(segment);
        segments += 1;
    }
    (segments >= 2).then_some(out)
}

/// The cleaned text without its last segment, when that leaves at least two segments.
fn parent(clean: &str) -> Option<&str> {
    let (head, _) = clean.rsplit_once('\\')?;
    head.contains('\\').then_some(head)
}

/// Inserts `text` (cleaned, at least two segments) and every prefix of it with at least two segments.
/// The set is closed under ancestors, so the walk upwards stops at the first prefix already there.
fn insert_closed<T>(set: &mut BTreeSet<T>, text: &str, make: impl Fn(&str) -> T)
where
    T: Ord + std::borrow::Borrow<str>,
{
    let mut end = text.len();
    loop {
        let prefix = &text[..end];
        if set.contains(prefix) {
            return;
        }
        set.insert(make(prefix));
        match parent(prefix) {
            Some(head) => end = head.len(),
            None => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(r: &Records) -> String {
        let mut out = Vec::new();
        r.write_records(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn keys_are_folded_cleaned_and_closed() {
        let mut r = Records::new();
        assert!(r.add_key(r"HKLM\SOFTWARE\Classes\CLSID\{A}\InProcServer32\"));
        assert!(r.add_key(r"HKLM\\SOFTWARE\CLASSES\clsid\{a}"));
        let keys: Vec<&str> = r.keys().collect();
        assert_eq!(
            keys,
            [
                r"hklm\software",
                r"hklm\software\classes",
                r"hklm\software\classes\clsid",
                r"hklm\software\classes\clsid\{a}",
                r"hklm\software\classes\clsid\{a}\inprocserver32",
            ]
        );
        assert!(!r.add_key("HKLM"));
        assert!(!r.add_key(r"\HKLM\"));
        assert!(!r.add_key(""));
        assert!(r.contains_key(r"HKLM\Software"));
        assert!(!r.contains_key("HKLM"));
    }

    #[test]
    fn values_share_and_record_their_key() {
        let mut r = Records::new();
        assert!(r.add_value(r"HKLM\SOFTWARE\X\Y", "Name", 1));
        assert!(r.add_value(r"hklm\software\x\y", "NAME", 1));
        assert!(r.add_value(r"HKLM\SOFTWARE\X\Y", "", 4));
        assert!(!r.add_value("HKLM", "x", 1));
        assert_eq!(r.counts().values, 2);
        assert!(r.contains_key(r"HKLM\SOFTWARE\X"));
        assert!(r.contains_value(r"HKLM\SOFTWARE\X\Y", "name"));
        assert!(r.contains_value(r"HKLM\SOFTWARE\X\Y", ""));
        assert!(!r.contains_value(r"HKLM\SOFTWARE\X", ""));
    }

    #[test]
    fn paths_record_their_directories() {
        let mut r = Records::new();
        assert!(r.add_file(r"C:\Windows\System32\drivers\x.sys"));
        assert!(r.add_dir("C:/Program Files/Common Files/"));
        assert!(!r.add_dir(r"C:\"));
        assert!(!r.add_file("C:"));
        assert_eq!(
            r.dirs().collect::<Vec<_>>(),
            [
                r"c:\program files",
                r"c:\program files\common files",
                r"c:\windows",
                r"c:\windows\system32",
                r"c:\windows\system32\drivers",
            ]
        );
        assert_eq!(
            r.files().collect::<Vec<_>>(),
            [r"c:\windows\system32\drivers\x.sys"]
        );
        // A file directly below the drive has no directory to record.
        let mut s = Records::new();
        assert!(s.add_file(r"C:\bootmgr"));
        assert_eq!(s.counts().dirs, 0);
        assert!(s.contains_file(r"c:\BOOTMGR"));
    }

    #[test]
    fn output_is_sorted_escaped_and_independent_of_order() {
        let mut a = Records::new();
        a.add_key(r"HKLM\SOFTWARE\B");
        a.add_value(r"HKLM\SOFTWARE\A", "x\ty", 1);
        a.add_file(r"C:\Windows\a.dll");
        let mut b = Records::new();
        b.add_file(r"C:\Windows\A.DLL");
        b.add_value(r"HKLM\SOFTWARE\A", "X\tY", 1);
        b.add_key(r"HKLM\SOFTWARE\b");
        assert_eq!(a, b);
        assert_eq!(
            lines(&a),
            "K\thklm\\\\software\nK\thklm\\\\software\\\\a\nK\thklm\\\\software\\\\b\n\
             V\thklm\\\\software\\\\a\tx\\ty\t1\t0000000000000000\n\
             D\tc:\\\\windows\nF\tc:\\\\windows\\\\a.dll\n"
        );
        let mut s = String::new();
        escape_into("a\\b\tc\nd\re\0f", &mut s);
        assert_eq!(s, r"a\\b\tc\nd\re\0f");
    }

    #[test]
    fn merge_is_a_union() {
        let mut a = Records::new();
        a.add_value(r"HKLM\SOFTWARE\A\B", "v", 1);
        let mut b = Records::new();
        b.add_value(r"HKLM\SOFTWARE\A\B", "w", 2);
        b.add_key(r"HKLM\SYSTEM\X");
        b.add_dir(r"C:\Windows\Fonts");
        let mut both = a.clone();
        both.merge(b.clone());
        for k in a.keys().chain(b.keys()) {
            assert!(both.contains_key(k), "{k}");
        }
        assert!(both.contains_value(r"HKLM\SOFTWARE\A\B", "v"));
        assert!(both.contains_value(r"HKLM\SOFTWARE\A\B", "w"));
        assert!(both.contains_dir(r"C:\Windows"));
        assert_eq!(both.counts().values, 2);
        assert!(Records::new().is_empty() && !both.is_empty());
    }
}
