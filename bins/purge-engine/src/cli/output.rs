//! Output and input files of the CLI.
//!
//! Every document is written as pretty-printed JSON, UTF-8 **without** a byte-order mark, with a final
//! newline. A file named with `-o` (and the fingerprint `uninstall --fp` updates in place) is written
//! atomically: the text goes to a temporary file in the same directory, which then replaces the target in
//! one rename, so a reader never sees half a document and a failed write leaves the old file alone.
//!
//! Documents are read leniently about encoding: a leading UTF-8 byte-order mark (PowerShell 5.1 writes
//! one) is skipped.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// A document as file text: pretty JSON plus a final newline.
pub fn json_text<T: Serialize>(doc: &T) -> String {
    let mut text = serde_json::to_string_pretty(doc).expect("engine documents serialise to JSON");
    text.push('\n');
    text
}

/// Writes `text` to `path` atomically (temporary file in the same directory, then rename).
///
/// # Errors
///
/// Any I/O error; the temporary file is removed when the rename fails.
pub fn write_atomic(path: &Path, text: &str) -> io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "the path names no file"))?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    let written = (|| {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()
    })();
    let result = written.and_then(|()| fs::rename(&tmp, path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// `FILE_FLAG_OPEN_REPARSE_POINT`: open a reparse point itself, never what it points to.
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Writes `text` to `path` atomically without following a reparse point: an existing reparse point at
/// `path` (a symbolic link, a junction) is refused and left alone; the temporary file is a new file
/// (`CREATE_NEW`, opened with `FILE_FLAG_OPEN_REPARSE_POINT`, so nothing planted under its name is
/// followed or reused); the rename then replaces the directory entry at `path`, never the object a link
/// there would name. The executor verbs write their documents this way.
///
/// # Errors
///
/// A reparse point at `path`, or any I/O error; the temporary file is removed when anything fails.
pub fn write_atomic_no_follow(path: &Path, text: &str) -> io::Result<()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "the path names no file"))?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a reparse point (link or junction) is at the output path; it is not followed or replaced",
            ));
        }
        Ok(meta) if meta.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a directory is at the output path",
            ));
        }
        _ => {}
    }
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = dir.join(format!(
        ".{}.{}.{nanos:x}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    // Only a file this call created is ever removed again.
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&tmp)?;
    let written = f.write_all(text.as_bytes()).and_then(|()| f.sync_all());
    drop(f);
    let result = written.and_then(|()| fs::rename(&tmp, path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// The sidecar of a plan file: `plan.json` -> `plan.scan.json`, `plan` -> `plan.scan.json`.
pub fn sidecar_path(plan: &Path) -> PathBuf {
    let name = plan
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = if name.len() > 5 && name[name.len() - 5..].eq_ignore_ascii_case(".json") {
        &name[..name.len() - 5]
    } else {
        name.as_str()
    };
    plan.with_file_name(format!("{stem}.scan.json"))
}

/// Reads a JSON document of type `T` from `path`.
///
/// # Errors
///
/// A one-line message naming the file and what was wrong.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes);
    serde_json::from_slice(text).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("purge-engine-output-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sidecar_sits_next_to_the_plan() {
        assert_eq!(
            sidecar_path(Path::new(r"C:\run\plan-purge.json")),
            PathBuf::from(r"C:\run\plan-purge.scan.json")
        );
        assert_eq!(
            sidecar_path(Path::new("plan.JSON")),
            PathBuf::from("plan.scan.json")
        );
        assert_eq!(
            sidecar_path(Path::new("out/plan")),
            PathBuf::from("out/plan.scan.json")
        );
    }

    #[test]
    fn atomic_write_replaces_the_file_without_bom_or_leftovers() {
        let dir = scratch("atomic");
        let path = dir.join("doc.json");
        write_atomic(&path, "{\"a\": 1}\n").unwrap();
        write_atomic(&path, &json_text(&serde_json::json!({"b": "ä"}))).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert!(!bytes.starts_with(b"\xEF\xBB\xBF"));
        assert_eq!(String::from_utf8(bytes).unwrap(), "{\n  \"b\": \"ä\"\n}\n");
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["doc.json"]);
        // A write into a missing directory fails and leaves nothing behind.
        assert!(write_atomic(&dir.join("missing").join("x.json"), "x").is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_follow_write_replaces_files_and_refuses_reparse_points() {
        let dir = scratch("nofollow");
        let path = dir.join("report.json");
        write_atomic_no_follow(&path, "one\n").unwrap();
        write_atomic_no_follow(&path, "two\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "two\n");
        // A junction at the output path is neither followed nor replaced.
        let target = dir.join("target");
        fs::create_dir(&target).unwrap();
        let link = dir.join("link.json");
        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if made {
            let e = write_atomic_no_follow(&link, "x").unwrap_err();
            assert!(e.to_string().contains("reparse point"), "{e}");
            assert!(fs::read_dir(&target).unwrap().next().is_none());
            fs::remove_dir(&link).unwrap();
        }
        // A directory at the output path is refused too.
        assert!(write_atomic_no_follow(&target, "x").is_err());
        let mut names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["report.json", "target"]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reading_skips_a_bom_and_names_the_file_on_errors() {
        let dir = scratch("read");
        let path = dir.join("bom.json");
        fs::write(&path, b"\xEF\xBB\xBF{\"x\": 2}").unwrap();
        let v: serde_json::Value = read_json(&path).unwrap();
        assert_eq!(v["x"], 2);
        fs::write(&path, b"{").unwrap();
        let e = read_json::<serde_json::Value>(&path).unwrap_err();
        assert!(e.contains("bom.json"), "{e}");
        assert!(read_json::<serde_json::Value>(&dir.join("none.json")).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
