//! The Programs list's icons: the one icon atlas (the port of `Shell/IconAtlas.cs`) and what the
//! loader of `Shell/IconLoader.cs` decided about it (the atlas key and stamp of a program, the edge
//! length and the chunk size of `programs.icons`). The requests themselves go out from `link`.
//!
//! The atlas is a display cache and nothing else: a damaged, missing or read-only file starts
//! empty or refuses to save, and the list shows its placeholder tiles. A hit needs the key and the
//! stamp to match, so an updated program asks the engine again.
//!
//! Format (little-endian, the WinUI app's): the magic `PICA`, a `u16` version, a `u16` reserved
//! word and an `i32` entry count; each entry is an `i32` UTF-8 key length and its bytes, an `i64`
//! stamp, a `u16` edge length, an `i32` pixel length and its BGRA bytes. An unknown version starts
//! empty; reading stops at the first malformed entry and keeps the ones before it.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use purge_model::ProgramId;

/// Edge length asked of the engine; the atlas holds 24 px icons (M3_DESIGN.md A10).
pub const PX: u16 = 24;

/// Programs per `programs.icons` request: the engine answers one request at a time, so a details
/// request waits for at most one chunk.
pub const CHUNK: usize = 48;

const MAGIC: u32 = 0x4143_4950; // "PICA" little-endian
const VERSION: u16 = 1;
const MAX_ENTRIES: usize = 8192;
const MAX_KEY_BYTES: usize = 32 * 1024;
const MAX_PX: u16 = 256;

/// One cached icon: its edge length and its top-down, straight-alpha BGRA pixels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtlasIcon {
    pub px: u16,
    pub bgra: Vec<u8>,
}

/// The atlas key of a program's icon. `icon.batch` carries no source path or file time, so the key
/// is the program id with a prefix no file path has.
pub fn key_of(program_id: &ProgramId) -> String {
    format!("purge-program:{program_id}")
}

/// The atlas stamp of a program: FNV-1a (64-bit) over the UTF-16 units of `version|install time`,
/// as the WinUI app made it, so an unchanged program is served from the file.
pub fn stamp(version: Option<&str>, install_time: Option<u64>) -> i64 {
    let text = format!(
        "{}|{}",
        version.unwrap_or(""),
        install_time.map(|t| t.to_string()).unwrap_or_default()
    );
    let mut hash: u64 = 14_695_981_039_346_656_037;
    for unit in text.encode_utf16() {
        hash = (hash ^ u64::from(unit)).wrapping_mul(1_099_511_628_211);
    }
    hash as i64
}

/// The user's atlas, `%LOCALAPPDATA%\Purge\icons.atlas`; a launch bench run's own one when
/// `PURGE_BENCH_ICON_ATLAS` names it (bench only, as in the WinUI app).
pub fn default_file() -> Option<PathBuf> {
    if crate::markers::enabled()
        && let Some(file) = std::env::var_os("PURGE_BENCH_ICON_ATLAS").filter(|f| !f.is_empty())
    {
        return Some(PathBuf::from(file));
    }
    std::env::var_os("LOCALAPPDATA")
        .filter(|d| !d.is_empty())
        .map(|d| PathBuf::from(d).join("Purge").join("icons.atlas"))
}

/// The icon atlas: icons by key (case-insensitive, as Windows paths) and stamp.
pub struct Atlas {
    file: Option<PathBuf>,
    icons: HashMap<(String, i64), AtlasIcon>,
    dirty: bool,
}

fn fold(key: &str) -> String {
    key.to_lowercase()
}

impl Atlas {
    /// The atlas at `file`; a missing or damaged file starts empty. `None`: an atlas that is never
    /// saved.
    pub fn open(file: Option<PathBuf>) -> Atlas {
        let mut atlas = Atlas {
            file,
            icons: HashMap::new(),
            dirty: false,
        };
        if let Some(f) = atlas.file.clone() {
            atlas.load(&f);
        }
        atlas
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.icons.len()
    }

    /// The cached icon of `key` as last seen with `stamp`.
    pub fn get(&self, key: &str, stamp: i64) -> Option<&AtlasIcon> {
        self.icons.get(&(fold(key), stamp))
    }

    /// Records an icon; false (and nothing kept) when it is not `px * px * 4` BGRA bytes, 1 to 256
    /// px square. At the limit the atlas starts over rather than grow without end.
    pub fn put(&mut self, key: &str, stamp: i64, px: u16, bgra: &[u8]) -> bool {
        if !(1..=MAX_PX).contains(&px) || bgra.len() != usize::from(px) * usize::from(px) * 4 {
            return false;
        }
        let k = (fold(key), stamp);
        if self.icons.len() >= MAX_ENTRIES && !self.icons.contains_key(&k) {
            self.icons.clear();
        }
        self.icons.insert(
            k,
            AtlasIcon {
                px,
                bgra: bgra.to_vec(),
            },
        );
        self.dirty = true;
        true
    }

    /// Writes the atlas atomically (a temporary file, then a rename over the old one); false when
    /// it could not be saved, which leaves the old file as it was.
    pub fn save(&mut self) -> bool {
        let Some(file) = self.file.clone() else {
            return true;
        };
        if !self.dirty && file.is_file() {
            return true;
        }
        let tmp = PathBuf::from(format!("{}.tmp", file.display()));
        let written = (|| -> std::io::Result<()> {
            if let Some(dir) = file.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let mut out = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
            out.write_all(&MAGIC.to_le_bytes())?;
            out.write_all(&VERSION.to_le_bytes())?;
            out.write_all(&0u16.to_le_bytes())?;
            out.write_all(&(self.icons.len() as i32).to_le_bytes())?;
            for ((key, stamp), icon) in &self.icons {
                out.write_all(&(key.len() as i32).to_le_bytes())?;
                out.write_all(key.as_bytes())?;
                out.write_all(&stamp.to_le_bytes())?;
                out.write_all(&icon.px.to_le_bytes())?;
                out.write_all(&(icon.bgra.len() as i32).to_le_bytes())?;
                out.write_all(&icon.bgra)?;
            }
            out.flush()?;
            drop(out);
            std::fs::rename(&tmp, &file)
        })();
        match written {
            Ok(()) => {
                self.dirty = false;
                true
            }
            Err(_) => {
                let _ = std::fs::remove_file(&tmp);
                false
            }
        }
    }

    fn load(&mut self, file: &Path) {
        let Ok(mut f) = std::fs::File::open(file) else {
            return;
        };
        let mut bytes = Vec::new();
        // A file larger than the largest atlas can be is not one.
        let most = (MAX_ENTRIES as u64) * (4 + MAX_KEY_BYTES as u64 + 8 + 2 + 4) + 12;
        if Read::by_ref(&mut f)
            .take(most + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > most
        {
            return;
        }
        let mut r = Reader {
            bytes: &bytes,
            at: 0,
        };
        let (Some(magic), Some(version), Some(_), Some(count)) =
            (r.u32(), r.u16(), r.u16(), r.i32())
        else {
            return;
        };
        if magic != MAGIC || version != VERSION || count < 0 || count as usize > MAX_ENTRIES {
            return;
        }
        for _ in 0..count {
            let Some(entry) = r.entry() else { break };
            self.icons.insert((fold(&entry.0), entry.1), entry.2);
        }
        self.dirty = false;
    }
}

/// Reads the atlas file's little-endian fields; `None` past the end.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(s)
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn i32(&mut self) -> Option<i32> {
        self.u32().map(|v| v as i32)
    }
    fn i64(&mut self) -> Option<i64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Some(i64::from_le_bytes(a))
    }
    fn entry(&mut self) -> Option<(String, i64, AtlasIcon)> {
        let len = usize::try_from(self.i32()?).ok()?;
        if len > MAX_KEY_BYTES {
            return None;
        }
        let key = String::from_utf8(self.take(len)?.to_vec()).ok()?;
        let stamp = self.i64()?;
        let px = self.u16()?;
        let n = usize::try_from(self.i32()?).ok()?;
        if !(1..=MAX_PX).contains(&px) || n != usize::from(px) * usize::from(px) * 4 {
            return None;
        }
        let bgra = self.take(n)?.to_vec();
        Some((key, stamp, AtlasIcon { px, bgra }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("purge-ui-atlas-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir.join(name)
    }

    fn square(px: u16, v: u8) -> Vec<u8> {
        vec![v; usize::from(px) * usize::from(px) * 4]
    }

    #[test]
    fn an_icon_is_kept_by_key_and_stamp_and_survives_a_save() {
        let file = temp("round.atlas");
        let _ = std::fs::remove_file(&file);
        let mut a = Atlas::open(Some(file.clone()));
        assert_eq!(a.len(), 0);
        assert!(a.put("purge-program:HKLM|64|Git_is1", 7, 24, &square(24, 9)));
        assert!(
            !a.put("x", 1, 24, &square(23, 9)),
            "a wrong length is refused"
        );
        assert!(!a.put("x", 1, 0, &[]), "an empty icon is refused");
        assert!(a.save());
        let b = Atlas::open(Some(file.clone()));
        assert_eq!(b.len(), 1);
        let hit = b
            .get("PURGE-PROGRAM:hklm|64|git_is1", 7)
            .expect("case-insensitive key");
        assert_eq!(hit.px, 24);
        assert!(
            b.get("purge-program:HKLM|64|Git_is1", 8).is_none(),
            "another stamp"
        );
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn a_damaged_file_starts_empty_or_keeps_the_entries_before_the_damage() {
        let file = temp("damaged.atlas");
        std::fs::write(&file, b"not an atlas").unwrap();
        assert_eq!(Atlas::open(Some(file.clone())).len(), 0);

        let mut a = Atlas::open(None);
        a.file = Some(file.clone());
        a.put("one", 1, 2, &square(2, 1));
        a.put("two", 2, 2, &square(2, 2));
        assert!(a.save());
        let mut bytes = std::fs::read(&file).unwrap();
        // Cut into the second entry: the first is kept.
        bytes.truncate(bytes.len() - 5);
        std::fs::write(&file, &bytes).unwrap();
        assert_eq!(Atlas::open(Some(file.clone())).len(), 1);

        // An entry that claims a pixel length that is not px * px * 4 ends the reading.
        let mut bad = Vec::new();
        bad.extend_from_slice(&MAGIC.to_le_bytes());
        bad.extend_from_slice(&VERSION.to_le_bytes());
        bad.extend_from_slice(&0u16.to_le_bytes());
        bad.extend_from_slice(&1i32.to_le_bytes());
        bad.extend_from_slice(&1i32.to_le_bytes());
        bad.push(b'k');
        bad.extend_from_slice(&0i64.to_le_bytes());
        bad.extend_from_slice(&2u16.to_le_bytes());
        bad.extend_from_slice(&15i32.to_le_bytes());
        bad.extend_from_slice(&[0; 15]);
        std::fs::write(&file, &bad).unwrap();
        assert_eq!(Atlas::open(Some(file.clone())).len(), 0);

        // An unknown version, or a count past the limit, starts empty.
        bad[4] = 2;
        std::fs::write(&file, &bad).unwrap();
        assert_eq!(Atlas::open(Some(file.clone())).len(), 0);
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn the_stamp_is_the_winui_apps() {
        // FNV-1a of "|" alone, and a change of version or time is another stamp.
        let empty = stamp(None, None);
        assert_eq!(
            empty,
            ((14_695_981_039_346_656_037_u64 ^ u64::from(b'|')).wrapping_mul(1_099_511_628_211))
                as i64
        );
        assert_ne!(stamp(Some("1.0"), Some(5)), stamp(Some("1.1"), Some(5)));
        assert_ne!(stamp(Some("1.0"), Some(5)), stamp(Some("1.0"), Some(6)));
        assert_eq!(stamp(Some("1.0"), Some(5)), stamp(Some("1.0"), Some(5)));
    }
}
