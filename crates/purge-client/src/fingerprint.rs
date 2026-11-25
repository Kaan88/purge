//! The UI's only look at the broker's fingerprint store, `%ProgramData%\Purge\fp` (port of
//! `Broker/FingerprintStore.cs`): whether a stored fingerprint may exist for a program, so the
//! Programs page offers "Check for leftovers" (and the Windows prompt it needs) only for a program
//! Purge recorded (M3 design 7a delta 5; DECISIONS 2026-11-23 "removed outside Purge").
//!
//! `fp` and its files are admin-only (SYSTEM and Administrators, no entry for Users), so this process
//! can never open or read a fingerprint. It asks Windows for the metadata of the one name the broker
//! would use (`fp-<SHA-256 of the program id, lower-case hex>.json`, as `fingerprint_name` in
//! `bins/purge-broker/src/uninstall.rs`): with "bypass traverse checking" the lookup answers "not
//! found" for a name that is not there and "access denied" for one that is. Only a definite "not
//! found" (of the file, or of `fp` itself) counts as no record; any other answer may be a record, and
//! the broker's `leftovers.stored` decides after the prompt. Nothing here reads content, and nothing
//! it says is trusted beyond showing or hiding a button.

use std::path::{Path, PathBuf};

use purge_model::ProgramId;
use purge_win::known_folders::{KnownFolder, known_folder};
use sha2::{Digest, Sha256};

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PATH_NOT_FOUND: i32 = 3;

/// `<FOLDERID_ProgramData>\Purge\fp`, or `None` when Windows names no ProgramData folder.
pub fn default_directory() -> Option<PathBuf> {
    known_folder(KnownFolder::ProgramData)
        .ok()
        .map(|p| p.join("Purge").join("fp"))
}

/// The broker's file name for `program`: `fp-`, SHA-256 of the UTF-8 of its id in lower-case hex,
/// `.json`.
pub fn file_name(program: &ProgramId) -> String {
    file_name_of(&program.to_string())
}

/// [`file_name`] of an id given as text.
pub fn file_name_of(program_id: &str) -> String {
    let digest = Sha256::digest(program_id.as_bytes());
    let mut name = String::with_capacity(3 + 64 + 5);
    name.push_str("fp-");
    for byte in digest {
        name.push_str(&format!("{byte:02x}"));
    }
    name.push_str(".json");
    name
}

/// False only when Windows says the fingerprint file (or the store directory) does not exist; true
/// otherwise, including when it exists but cannot be read, and on any error. `directory` is for the
/// tests; `None` is [`default_directory`].
pub fn may_have_record(program: &ProgramId, directory: Option<&Path>) -> bool {
    let dir = match directory {
        Some(d) => d.to_path_buf(),
        None => match default_directory() {
            Some(d) => d,
            None => return true,
        },
    };
    if dir.as_os_str().is_empty() {
        return true;
    }
    // Metadata of the name only (no follow, no open of content): the attributes lookup of the C#.
    match std::fs::symlink_metadata(dir.join(file_name(program))) {
        Ok(_) => true,
        Err(e) => !matches!(
            e.raw_os_error(),
            Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(text: &str) -> ProgramId {
        text.parse().unwrap()
    }

    #[test]
    fn the_name_is_the_brokers() {
        // SHA-256("abc"), the FIPS 180-2 example.
        assert_eq!(
            file_name_of("abc"),
            "fp-ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.json"
        );
        let program = id("HKLM|64|Git_is1");
        assert_eq!(file_name(&program), file_name_of(&program.to_string()));
    }

    #[test]
    fn the_names_match_the_shared_vector() {
        // The same file is checked against the broker's own `fingerprint_name`.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/fingerprint-names.json"
        );
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let names = v["names"].as_array().unwrap();
        assert!(!names.is_empty());
        for n in names {
            let program = id(n["program_id"].as_str().unwrap());
            assert_eq!(file_name(&program), n["file"].as_str().unwrap());
        }
    }

    #[test]
    fn only_a_definite_not_found_is_no_record() {
        let dir = std::env::temp_dir().join(format!("purge-client-fp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let program = id("HKLM|64|Git_is1");
        // The store directory is missing: path not found.
        assert!(!may_have_record(&program, Some(&dir)));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!may_have_record(&program, Some(&dir)));
        std::fs::write(dir.join(file_name(&program)), b"{}").unwrap();
        assert!(may_have_record(&program, Some(&dir)));
        // Another program's file says nothing about this one.
        assert!(!may_have_record(&id("HKLM|64|Other_is1"), Some(&dir)));
        // No directory known: maybe.
        assert!(may_have_record(&program, Some(Path::new(""))));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
