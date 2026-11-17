//! M1B-X-INTEG: every `// M1b: wired by M1B-X-INTEG` placeholder arm of the executor is gone.

use std::path::Path;

fn walk(dir: &Path, hits: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, hits);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).unwrap();
            for (n, line) in text.lines().enumerate() {
                // Spelled in two parts so this file does not match itself.
                if line.contains(concat!("wired by ", "M1B-X-INTEG")) {
                    hits.push(format!("{}:{}", path.display(), n + 1));
                }
            }
        }
    }
}

#[test]
fn no_wired_by_arms_left() {
    let mut hits = Vec::new();
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    walk(&crate_dir.join("src"), &mut hits);
    walk(&crate_dir.join("../../bins/purge-engine/src"), &mut hits);
    assert!(hits.is_empty(), "placeholder arms left: {hits:#?}");
}
