//! `no-new-walks`: no scanner walks the registry on its own (M1B_DESIGN.json `budgets`, R3a carry 4).
//!
//! The scan makes exactly one reference walk per app (C-SCANEXT): `ScanExt::build` runs it through
//! `ref_any::walk`, and every scanner reads its hits. A scanner that called `RegistrySource::walker` or
//! `refscan::scan` itself would add a walk the budget does not allow. This check fails when any `.rs`
//! file under `crates/purge-scan/src` other than the allow-list ([`ALLOWED`]) contains `.walker(` or
//! `refscan::scan`, in code or in a comment (the text is matched as it stands, so a doc example counts
//! too: name the allowed file instead).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The files that may walk, relative to `crates/purge-scan/src` with `/` separators: REF-ANY's own walk,
/// the framework, and `ScanExt::build`.
pub const ALLOWED: &[&str] = &["ref_any.rs", "framework.rs", "framework/m1b.rs"];

/// The texts that mean a walk.
pub const FORBIDDEN: &[&str] = &[".walker(", "refscan::scan"];

/// One forbidden text in a file outside the allow-list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walk {
    /// The file, relative to the scanned directory, `/`-separated.
    pub file: String,
    /// The 1-based line.
    pub line: usize,
    /// The forbidden text found.
    pub what: &'static str,
}

/// Every `.rs` file below `dir`, sorted, as (relative `/`-separated name, path).
fn rust_files(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).with_context(|| format!("listing {}", d.display()))? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                stack.push(path);
            } else if kind.is_file() && path.extension().is_some_and(|e| e == "rs") {
                let rel = path
                    .strip_prefix(dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, path));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// The walks in the `.rs` files below `src_dir` (a `purge-scan/src` directory).
pub fn find(src_dir: &Path) -> Result<Vec<Walk>> {
    let mut out = Vec::new();
    for (rel, path) in rust_files(src_dir)? {
        if ALLOWED.contains(&rel.as_str()) {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        for (i, line) in text.lines().enumerate() {
            for what in FORBIDDEN {
                if line.contains(what) {
                    out.push(Walk {
                        file: rel.clone(),
                        line: i + 1,
                        what,
                    });
                }
            }
        }
    }
    Ok(out)
}

/// Runs the check over the workspace's `crates/purge-scan/src`; `Ok(false)` on a walk.
pub fn run(root: &Path) -> Result<bool> {
    let src = root.join("crates").join("purge-scan").join("src");
    if !src.is_dir() {
        anyhow::bail!("no directory {}", src.display());
    }
    let found = find(&src)?;
    for w in &found {
        eprintln!(
            "no-new-walks: crates/purge-scan/src/{}:{}: `{}` outside {} (the scan makes one reference \
             walk, in ScanExt::build; read ScanCtx::ref_hits_under instead)",
            w.file,
            w.line,
            w.what,
            ALLOWED.join(", ")
        );
    }
    if found.is_empty() {
        println!(
            "no-new-walks: ok (no `.walker(` or `refscan::scan` in purge-scan outside {})",
            ALLOWED.join(", ")
        );
    }
    Ok(found.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A copy of purge-scan's sources in a fresh temporary directory, removed on drop.
    struct Copy {
        dir: PathBuf,
    }

    impl Copy {
        fn of_the_workspace(tag: &str) -> Copy {
            let src = crate::workspace_root()
                .join("crates")
                .join("purge-scan")
                .join("src");
            let dir = std::env::temp_dir().join(format!(
                "purge-xtask-no-new-walks-{tag}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            for (rel, path) in rust_files(&src).unwrap() {
                let to = dir.join(&rel);
                std::fs::create_dir_all(to.parent().unwrap()).unwrap();
                std::fs::copy(&path, &to).unwrap();
            }
            Copy { dir }
        }
    }

    impl Drop for Copy {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// The tree as committed passes; a scanner file that walks, planted next to the real ones, fails
    /// with its file and line; the allowed files may walk.
    #[test]
    fn xtask_no_new_walks_passes_and_catches_planted_walker() {
        let copy = Copy::of_the_workspace("planted");
        assert_eq!(find(&copy.dir).unwrap(), Vec::new());
        assert!(run(&crate::workspace_root()).unwrap());

        std::fs::write(
            copy.dir.join("reg_planted.rs"),
            "fn scan(ctx: &ScanCtx<'_>) {\n    let w = ctx.reg.walker(root, opts);\n}\n",
        )
        .unwrap();
        std::fs::create_dir_all(copy.dir.join("sub")).unwrap();
        std::fs::write(
            copy.dir.join("sub").join("deep.rs"),
            "use purge_index::refscan;\nfn f() { let _ = refscan::scan(reg, fp, refs); }\n",
        )
        .unwrap();
        let found = find(&copy.dir).unwrap();
        assert_eq!(
            found,
            vec![
                Walk {
                    file: "reg_planted.rs".into(),
                    line: 2,
                    what: ".walker(",
                },
                Walk {
                    file: "sub/deep.rs".into(),
                    line: 2,
                    what: "refscan::scan",
                },
            ]
        );

        // The allow-list is by exact relative name: `framework/m1b.rs` may, `other/framework.rs` may not.
        std::fs::remove_file(copy.dir.join("reg_planted.rs")).unwrap();
        std::fs::remove_dir_all(copy.dir.join("sub")).unwrap();
        let walk = "fn f() { ctx.reg.walker(r, o); }\n";
        std::fs::write(copy.dir.join("framework").join("m1b.rs"), walk).unwrap();
        assert_eq!(find(&copy.dir).unwrap(), Vec::new());
        std::fs::create_dir_all(copy.dir.join("other")).unwrap();
        std::fs::write(copy.dir.join("other").join("framework.rs"), walk).unwrap();
        assert_eq!(find(&copy.dir).unwrap().len(), 1);
    }
}
