//! Records the SHA-256 of rigtool's own sources in the binary (`rigtool version`), so `truth/m1b.sh` can refuse a
//! binary that was not built from the sources in the tree (review R5 S1).
//!
//! The hash: the files `Cargo.toml`, `Cargo.lock`, `build.rs` and every file under `src/`, sorted by their path
//! relative to this directory (`/` separators); for each, the line `<sha256 of its bytes with CRLF read as LF>  <path>\n`;
//! the SHA-256 of those lines. `truth/m1b.sh` (`rigtool_tree_sha256`) computes the same over the checkout.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir).expect("read src").map(|e| e.expect("dir entry").path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            walk(root, &p, out);
        } else {
            let rel = p.strip_prefix(root).expect("under root").to_string_lossy().replace('\\', "/");
            out.push((rel, p));
        }
    }
}

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let mut files: Vec<(String, PathBuf)> =
        ["Cargo.toml", "Cargo.lock", "build.rs"].iter().map(|f| (f.to_string(), root.join(f))).collect();
    walk(&root, &root.join("src"), &mut files);
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut lines = String::new();
    for (rel, p) in &files {
        let bytes = std::fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
        let mut lf = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
                i += 1;
                continue;
            }
            lf.push(bytes[i]);
            i += 1;
        }
        lines.push_str(&format!("{}  {rel}\n", hex(&Sha256::digest(&lf))));
    }
    println!("cargo:rustc-env=RIGTOOL_SOURCE_SHA256={}", hex(&Sha256::digest(lines.as_bytes())));
    for f in ["Cargo.toml", "Cargo.lock", "build.rs", "src"] {
        println!("cargo:rerun-if-changed={f}");
    }
}
