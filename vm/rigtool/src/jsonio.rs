//! JSON helpers. Files written by Windows PowerShell 5.1 start with a UTF-8 BOM; it is stripped.

use crate::err::{Context, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::Path;

pub fn read_text(path: &Path) -> Result<String> {
    let b = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let b = b.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(&b[..]);
    // UTF-16LE with BOM (Out-File default in PS 5.1 is "Unicode").
    if b.len() >= 2 && b[0] == 0xFF && b[1] == 0xFE {
        let w: Vec<u16> = b[2..].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return Ok(String::from_utf16_lossy(&w));
    }
    String::from_utf8(b.to_vec()).with_context(|| format!("{} is not UTF-8", path.display()))
}

pub fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let t = read_text(path)?;
    serde_json::from_str(&t).with_context(|| format!("parse {}", path.display()))
}

pub fn write<T: Serialize>(path: &Path, v: &T) -> Result<()> {
    let s = serde_json::to_string_pretty(v)?;
    std::fs::write(path, s + "\n").with_context(|| format!("write {}", path.display()))
}
