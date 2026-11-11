//! `ui-strings`: none of our user-visible text may equal a string of the reference product
//! (ENGINE_PLAN.md §11.4).
//!
//! The reference language file is read from the path in `PURGE_UT_STRINGS`. It stays outside the repo; its
//! strings are only held in memory, and the only one ever printed is the literal of ours that matched.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::lex::{self, Literal};

/// Literals shorter than this many characters are not compared.
const MIN_CHARS: usize = 12;
const ENV: &str = "PURGE_UT_STRINGS";

/// Case-folds, collapses whitespace and strips trailing punctuation.
pub fn normalize(s: &str) -> String {
    let lower = s.to_lowercase();
    let collapsed = lower.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed
        .trim_end_matches(|c: char| {
            c.is_whitespace() || c.is_ascii_punctuation() || "…。、：；！？".contains(c)
        })
        .to_string()
}

fn long_enough(s: &str) -> bool {
    s.chars().count() >= MIN_CHARS
}

fn parse_xml(text: &str) -> Result<roxmltree::Document<'_>> {
    let opts = roxmltree::ParsingOptions {
        allow_dtd: true,
        ..Default::default()
    };
    Ok(roxmltree::Document::parse_with_options(text, opts)?)
}

/// Normalised text values (text and CDATA nodes) of 12+ characters from the reference file.
fn reference_strings(path: &Path) -> Result<HashSet<String>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading {ENV}={}", path.display()))?;
    let text = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
    let doc = parse_xml(text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(doc
        .descendants()
        .filter(|n| n.is_text())
        .filter_map(|n| n.text())
        .filter(|t| long_enough(t))
        .map(normalize)
        .filter(|n| !n.is_empty())
        .collect())
}

/// Attribute values and text of a XAML file, with the line of their element.
fn xaml_literals(src: &str) -> Result<Vec<Literal>> {
    let text = src.strip_prefix('\u{feff}').unwrap_or(src);
    let doc = parse_xml(text)?;
    let mut out = Vec::new();
    for node in doc.descendants() {
        let line = doc.text_pos_at(node.range().start).row as usize;
        if node.is_element() {
            out.extend(node.attributes().map(|a| Literal {
                line,
                text: a.value().to_string(),
            }));
        } else if let Some(t) = node.text().filter(|_| node.is_text()) {
            out.push(Literal {
                line,
                text: t.to_string(),
            });
        }
    }
    Ok(out)
}

/// Whether `dir` (a directory found while walking) is build output or tool state rather than source.
///
/// Only real build output is skipped, so `src/bin/*.rs` binaries and a module directory named `target`
/// are still checked:
/// - a Cargo target directory, recognised by the `CACHEDIR.TAG` Cargo writes into it;
/// - MSBuild `bin`/`obj`, only next to a project file (`*.csproj`, `*.wapproj`, …);
/// - `.git` and `.vs`.
fn is_build_output(dir: &Path) -> bool {
    let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let is = |s: &str| name.eq_ignore_ascii_case(s);
    if is(".git") || is(".vs") {
        return true;
    }
    if is("target") {
        return dir.join("CACHEDIR.TAG").is_file();
    }
    if is("bin") || is("obj") {
        return dir.parent().is_some_and(has_msbuild_project);
    }
    false
}

/// Whether `dir` directly holds an MSBuild project file (extension ending in `proj`).
fn has_msbuild_project(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries.flatten().any(|e| {
            e.file_type().is_ok_and(|t| t.is_file())
                && e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| x.to_ascii_lowercase().ends_with("proj"))
        })
    })
}

/// Files under `dir` whose extension is one of `exts`, skipping build output ([`is_build_output`]).
fn files(dir: &Path, exts: &[&str], out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            if !is_build_output(&path) {
                files(&path, exts, out)?;
            }
        } else if ft.is_file()
            && path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| exts.iter().any(|x| e.eq_ignore_ascii_case(x)))
        {
            out.push(path);
        }
    }
    Ok(())
}

/// Every literal of ours that ui-strings checks, by file.
fn our_literals(root: &Path) -> Result<Vec<(PathBuf, Vec<Literal>)>> {
    let mut rs = Vec::new();
    files(&root.join("crates"), &["rs"], &mut rs)?;
    files(&root.join("bins"), &["rs"], &mut rs)?;
    let mut ui = Vec::new();
    files(&root.join("ui"), &["cs", "xaml"], &mut ui)?;
    let mut out = Vec::new();
    for path in rs.into_iter().chain(ui) {
        let src = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let lits = match ext.as_str() {
            "rs" => lex::rust_literals(&src),
            "cs" => lex::csharp_literals(&src),
            _ => xaml_literals(&src).with_context(|| format!("parsing {}", path.display()))?,
        };
        out.push((path, lits));
    }
    Ok(out)
}

/// `(file, line, literal)` of every literal of ours whose normalised text is in `reference`.
fn find_matches(
    ours: &[(PathBuf, Vec<Literal>)],
    reference: &HashSet<String>,
) -> Vec<(PathBuf, usize, String)> {
    let mut hits = Vec::new();
    for (path, lits) in ours {
        for lit in lits.iter().filter(|l| long_enough(&l.text)) {
            if reference.contains(&normalize(&lit.text)) {
                hits.push((path.clone(), lit.line, lit.text.clone()));
            }
        }
    }
    hits
}

/// Runs the check; `Ok(false)` on any match.
pub fn run(root: &Path) -> Result<bool> {
    let Some(xml) = std::env::var_os(ENV).filter(|v| !v.is_empty()) else {
        println!("ui-strings: skipped ({ENV} not set)");
        return Ok(true);
    };
    let reference = reference_strings(Path::new(&xml))?;
    let ours = our_literals(root)?;
    let checked: usize = ours
        .iter()
        .map(|(_, l)| l.iter().filter(|l| long_enough(&l.text)).count())
        .sum();
    let hits = find_matches(&ours, &reference);
    for (path, line, text) in &hits {
        let rel = path.strip_prefix(root).unwrap_or(path);
        eprintln!(
            "ui-strings: {}:{line}: matches the reference product: {text:?}",
            rel.display()
        );
    }
    let mut per_kind: HashMap<&str, usize> = HashMap::new();
    for (path, _) in &ours {
        *per_kind
            .entry(path.extension().and_then(|e| e.to_str()).unwrap_or("?"))
            .or_default() += 1;
    }
    let mut kinds: Vec<_> = per_kind
        .into_iter()
        .map(|(k, n)| format!("{n} .{k}"))
        .collect();
    kinds.sort();
    println!(
        "ui-strings: {} match(es); {checked} literals of {MIN_CHARS}+ chars in {} files ({}) vs {} reference strings",
        hits.len(),
        ours.len(),
        if kinds.is_empty() {
            "none".to_string()
        } else {
            kinds.join(", ")
        },
        reference.len(),
    );
    Ok(hits.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalisation() {
        assert_eq!(normalize("  Hello\t\n  World...  "), "hello world");
        assert_eq!(normalize("Remove the item?!"), "remove the item");
        assert_eq!(normalize("Wait…"), "wait");
        assert_eq!(normalize("50%"), "50");
        assert_eq!(normalize("C:\\Path\\"), "c:\\path");
    }

    #[test]
    fn matches_after_normalisation_only_when_long_enough() {
        let reference: HashSet<String> = ["Some reference sentence.", "short one"]
            .iter()
            .map(|s| normalize(s))
            .collect();
        let ours = vec![(
            PathBuf::from("x.rs"),
            lex::rust_literals(
                "let a = \"some   REFERENCE sentence!\"; let b = \"short one\"; let c = \"unrelated text here\";",
            ),
        )];
        let hits = find_matches(&ours, &reference);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, 1);
    }

    /// A fresh, empty directory for one test.
    fn scratch_dir(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("purge-xtask-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn walks_src_bin_and_target_modules_but_not_build_output() {
        let root = scratch_dir("walk");
        let lit = "let s = \"A synthetic reference sentence\";";
        // Source: must all be checked.
        write(&root, "crates/demo/src/lib.rs", lit);
        write(&root, "crates/demo/src/bin/tool.rs", lit);
        write(&root, "crates/demo/src/target/mod.rs", lit);
        write(&root, "bins/app/src/bin/extra.rs", lit);
        write(
            &root,
            "ui/App/Views/bin/Page.cs",
            "var s = \"A synthetic reference sentence\";",
        );
        write(&root, "ui/App/App.csproj", "<Project/>");
        write(
            &root,
            "ui/App/Main.cs",
            "var s = \"A synthetic reference sentence\";",
        );
        // Build output: must be skipped.
        write(
            &root,
            "crates/demo/target/CACHEDIR.TAG",
            "Signature: 8a477f597d28d172789f06886806bc55",
        );
        write(&root, "crates/demo/target/debug/build/out/gen.rs", lit);
        write(
            &root,
            "ui/App/bin/Debug/Gen.cs",
            "var s = \"A synthetic reference sentence\";",
        );
        write(
            &root,
            "ui/App/obj/Debug/Gen.g.cs",
            "var s = \"A synthetic reference sentence\";",
        );
        write(&root, "crates/demo/.git/x.rs", lit);

        let reference: HashSet<String> = [normalize("A synthetic reference sentence")].into();
        let ours = our_literals(&root).unwrap();
        let mut hit_files: Vec<String> = find_matches(&ours, &reference)
            .into_iter()
            .map(|(p, _, _)| {
                p.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        hit_files.sort();
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(
            hit_files,
            [
                "bins/app/src/bin/extra.rs",
                "crates/demo/src/bin/tool.rs",
                "crates/demo/src/lib.rs",
                "crates/demo/src/target/mod.rs",
                "ui/App/Main.cs",
                "ui/App/Views/bin/Page.cs",
            ]
        );
    }

    #[test]
    fn xaml_attributes_and_text() {
        let src = "<Page xmlns=\"urn:x\">\n  <TextBlock Text=\"Attribute value text\"/>\n  <Run>Element body text</Run>\n</Page>";
        let lits = xaml_literals(src).unwrap();
        assert!(
            lits.iter()
                .any(|l| l.line == 2 && l.text == "Attribute value text")
        );
        assert!(lits.iter().any(|l| l.text == "Element body text"));
    }
}
