//! Output and input files of the CLI.
//!
//! Every document is written as pretty-printed JSON, UTF-8 **without** a byte-order mark, with a final
//! newline. A file named with `-o` (and the fingerprint `uninstall --fp` updates in place) is written
//! atomically: the text goes to a temporary file in the same directory, which then replaces the target in
//! one rename, so a reader never sees half a document and a failed write leaves the old file alone.
//! No link on the path is followed ([`write_atomic_no_follow`]).
//!
//! Documents are read leniently about encoding: a leading UTF-8 byte-order mark (PowerShell 5.1 writes
//! one) is skipped.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

mod nofollow;

/// A document as file text: pretty JSON plus a final newline.
pub fn json_text<T: Serialize>(doc: &T) -> String {
    let mut text = serde_json::to_string_pretty(doc).expect("engine documents serialise to JSON");
    text.push('\n');
    text
}

/// Writes `text` to `path` atomically (temporary file in the same directory, then rename), as
/// [`write_atomic_no_follow`]: every file the CLI writes, elevated or not, is written that way (review
/// M2 S7).
///
/// # Errors
///
/// As [`write_atomic_no_follow`].
pub fn write_atomic(path: &Path, text: &str) -> io::Result<()> {
    write_atomic_no_follow(path, text)
}

/// Writes `text` to `path` atomically without following a reparse point anywhere on the path: the
/// directories down to the file are opened one by one, each relative to the handle of the one above
/// and never through a link (a junction, a symbolic link or a mount point on the path is refused); an
/// existing reparse point or directory at `path` is refused and left alone; the temporary file is a
/// new file created relative to the verified directory's handle, and the rename to `path` happens
/// relative to that same handle, replacing the directory entry at `path`, never the object a link
/// would name (`output::nofollow`). Only a drive or share path is accepted.
///
/// # Errors
///
/// A reparse point on the path, a path that is not a plain drive or share path, or any I/O error;
/// the temporary file is removed when anything fails.
pub fn write_atomic_no_follow(path: &Path, text: &str) -> io::Result<()> {
    nofollow::write(path, text.as_bytes())
}

/// [`write_atomic`] for a binary file (the gzip of `baseline build`): the same writer, the same rules.
///
/// # Errors
///
/// As [`write_atomic_no_follow`].
pub fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    nofollow::write(path, bytes)
}

/// The sidecar of a plan file: `plan.json` -> `plan.scan.json`, `plan` -> `plan.scan.json`.
pub fn sidecar_path(plan: &Path) -> PathBuf {
    let name = plan
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Sliced on a char boundary only: `planß.txt` has none five bytes before its end (review M2 M20).
    let stem = name
        .len()
        .checked_sub(5)
        .filter(|&at| at > 0)
        .and_then(|at| Some((name.get(..at)?, name.get(at..)?)))
        .filter(|(_, ext)| ext.eq_ignore_ascii_case(".json"))
        .map_or(name.as_str(), |(stem, _)| stem);
    plan.with_file_name(format!("{stem}.scan.json"))
}

/// The largest document [`read_json`] reads (review M2 M24): far above any plan, scan document or id
/// list the engine writes.
pub const MAX_INPUT_BYTES: u64 = 256 << 20;

/// Reads a JSON document of type `T` from `path`, of at most [`MAX_INPUT_BYTES`].
///
/// # Errors
///
/// A one-line message naming the file and what was wrong.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    read_json_capped(path, MAX_INPUT_BYTES)
}

/// [`read_json`] with a size cap of `cap` bytes.
fn read_json_capped<T: DeserializeOwned>(path: &Path, cap: u64) -> Result<T, String> {
    let fail = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|f| f.take(cap.saturating_add(1)).read_to_end(&mut bytes))
        .map_err(|e| fail(&e))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > cap {
        return Err(fail(&format!("the file is larger than {cap} bytes")));
    }
    let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes);
    serde_json::from_slice(text).map_err(|e| fail(&e))
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

    /// Review M2 M20: a name with a multi-byte character near its end does not panic.
    #[test]
    fn sidecar_of_a_name_with_multibyte_characters() {
        assert_eq!(
            sidecar_path(Path::new("planß.txt")),
            PathBuf::from("planß.txt.scan.json")
        );
        assert_eq!(
            sidecar_path(Path::new("aé.txt")),
            PathBuf::from("aé.txt.scan.json")
        );
        assert_eq!(
            sidecar_path(Path::new("ä.json")),
            PathBuf::from("ä.scan.json")
        );
    }

    /// Review M2 M24: a document larger than the cap is refused without reading it whole.
    #[test]
    fn reading_refuses_a_document_over_the_cap() {
        let dir = scratch("cap");
        let path = dir.join("big.json");
        fs::write(&path, b"[1, 2, 3]").unwrap();
        assert_eq!(read_json_capped::<Vec<u8>>(&path, 9).unwrap(), [1, 2, 3]);
        let e = read_json_capped::<Vec<u8>>(&path, 8).unwrap_err();
        assert!(
            e.contains("larger than 8 bytes") && e.contains("big.json"),
            "{e}"
        );
        fs::remove_dir_all(&dir).unwrap();
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

    /// Review M2 S7: a junction in a directory component of the path is not followed, for either
    /// writer; the same file written through the real directory works; nothing is left behind.
    #[test]
    fn no_write_goes_through_a_junction_on_the_path() {
        let dir = scratch("chain");
        let real = dir.join("real");
        fs::create_dir(&real).unwrap();
        let junction = dir.join("j");
        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&real)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        assert!(made, "mklink /J failed");
        for write in [write_atomic, write_atomic_no_follow] {
            let e = write(&junction.join("out.json"), "x").unwrap_err();
            assert!(e.to_string().contains("link or junction"), "{e}");
            fs::create_dir(real.join("sub")).unwrap();
            assert!(write(&junction.join(r"sub\out.json"), "x").is_err());
            fs::remove_dir(real.join("sub")).unwrap();
            assert!(fs::read_dir(&real).unwrap().next().is_none());
        }
        // An existing file reached only through the junction is not replaced either.
        fs::write(real.join("keep.json"), "old").unwrap();
        assert!(write_atomic(&junction.join("keep.json"), "new").is_err());
        assert_eq!(fs::read_to_string(real.join("keep.json")).unwrap(), "old");
        // A stream name is refused; the real path works.
        assert!(write_atomic(&real.join("keep.json:s"), "x").is_err());
        write_atomic(&real.join("keep.json"), "new").unwrap();
        assert_eq!(fs::read_to_string(real.join("keep.json")).unwrap(), "new");
        let names: Vec<String> = fs::read_dir(&real)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["keep.json"]);
        fs::remove_dir(&junction).unwrap();
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
