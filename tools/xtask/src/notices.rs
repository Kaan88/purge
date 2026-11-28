//! `notices`: writes `THIRD-PARTY-NOTICES.txt`, the licences of every third-party crate that the
//! shipped binaries link, from `Cargo.lock`; `notices --check` fails when the committed file is not
//! what this command would write now (a dependency bump without new notices).
//!
//! The crates are those reached from the shipped binaries ([`SHIPPED`], the exes of
//! `install/inno/purge.iss`) over normal dependency edges of `cargo metadata --filter-platform
//! x86_64-pc-windows-msvc`: dev-dependencies and build-dependencies (and so build scripts' own
//! tools) are left out, and so is the xtask. The metadata's resolve is the workspace's, with its
//! features unified, so the list can name a crate that one release build (`cargo build --release
//! -p <bin>`) does not link; it never misses one. Purge's own workspace crates are covered by
//! `LICENSE` and `NOTICE` and are not listed.
//!
//! For each crate: its name, version, licence expression and repository, and the full text of
//! every `LICENSE*`, `LICENCE*`, `COPYING*`, `NOTICE*` and `UNLICENSE*` file of its package
//! (verbatim, NOTICE files included, Apache-2.0 section 4(d)), deduplicated by text. A git
//! dependency without such files in its own folder takes them from its checkout's root. A crate
//! with none at all gets the SPDX standard text of each licence its expression names
//! ([`STANDARD`]), and its entry says so. A licence id outside [`PERMISSIVE`], or a crate that
//! declares no licence and is not in [`DECLARED_ELSEWHERE`], is an error: a person decides.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// The committed output, at the workspace root.
pub const OUTPUT: &str = "THIRD-PARTY-NOTICES.txt";

/// The only target Purge ships for.
const TARGET: &str = "x86_64-pc-windows-msvc";

/// The workspace packages whose binaries the installer installs, with each exe's file name.
const SHIPPED: &[(&str, &str)] = &[
    ("purge-engine", "purge-engine.exe"),
    ("purge-broker", "purge-broker.exe"),
    ("purge-ui", "Purge.exe"),
];

/// The installer script, read to check that [`SHIPPED`] names every exe it installs.
const ISS: &str = "install/inno/purge.iss";

/// SPDX ids (and exceptions) that need no one's judgement.
const PERMISSIVE: &[&str] = &[
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "ISC",
    "LLVM-exception",
    "MIT",
    "MIT-0",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "Unlicense",
    "Zlib",
];

/// The SPDX standard texts used for a crate that ships no licence file.
const STANDARD: &[(&str, &str)] = &[
    ("Apache-2.0", include_str!("notices/Apache-2.0.txt")),
    ("MIT", include_str!("notices/MIT.txt")),
];

/// Crates whose Cargo.toml declares no licence, with the licence their repository gives and where.
/// The owner's toolkit: its root `LICENSE` is MIT, and its README says "Licence: MIT".
const DECLARED_ELSEWHERE: &[(&str, &str, &str)] = &[
    (
        "mdshared-app",
        "MIT",
        "the toolkit repository's LICENSE and README",
    ),
    (
        "mdshared-text",
        "MIT",
        "the toolkit repository's LICENSE and README",
    ),
    (
        "mdshared-ui",
        "MIT",
        "the toolkit repository's LICENSE and README",
    ),
];

/// One listed crate.
struct Crate {
    name: String,
    version: String,
    licence: String,
    /// Where the licence came from when Cargo.toml has none.
    licence_note: Option<&'static str>,
    repository: String,
    authors: Vec<String>,
    /// `(file label, text index)`, in file-name order.
    texts: Vec<(String, usize)>,
    /// The texts are SPDX standard texts: the package has no licence file.
    standard: bool,
}

pub fn run(root: &Path, args: &[String]) -> Result<bool> {
    let mut check = false;
    for arg in args {
        match arg.as_str() {
            "--check" => check = true,
            other => bail!("notices: unknown argument {other}"),
        }
    }
    check_shipped(root)?;
    let output = crate::cargo()
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--filter-platform",
            TARGET,
        ])
        .current_dir(root)
        .output()
        .context("running cargo metadata")?;
    if !output.status.success() {
        bail!(
            "cargo metadata --locked failed (is Cargo.lock up to date?):\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let json = String::from_utf8(output.stdout).context("cargo metadata output is not UTF-8")?;
    let text = render(&json)?;
    let path = root.join(OUTPUT);
    if check {
        let committed = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let committed = normalise(&committed);
        if committed == text {
            println!("notices: {OUTPUT} matches Cargo.lock");
            return Ok(true);
        }
        let line = committed
            .lines()
            .zip(text.lines())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| committed.lines().count().min(text.lines().count()))
            + 1;
        eprintln!(
            "notices: {OUTPUT} does not match Cargo.lock (first difference at line {line}); \
             run `cargo xtask notices` and commit the file"
        );
        return Ok(false);
    }
    std::fs::write(&path, &text).with_context(|| format!("writing {}", path.display()))?;
    println!("notices: wrote {}", path.display());
    Ok(true)
}

/// Fails when the installer installs an exe from the cargo target folder that [`SHIPPED`] does not
/// name, or no longer installs one it names.
fn check_shipped(root: &Path) -> Result<()> {
    let iss = std::fs::read_to_string(root.join(ISS))
        .with_context(|| format!("reading {ISS}"))?
        .to_ascii_lowercase();
    let marker = "\\target\\release\\";
    let mut found = BTreeSet::new();
    for (at, _) in iss.match_indices(marker) {
        let rest = &iss[at + marker.len()..];
        if let Some(end) = rest.find(".exe") {
            found.insert(format!("{}.exe", &rest[..end]));
        }
    }
    let named: BTreeSet<String> = SHIPPED
        .iter()
        .map(|(_, exe)| exe.to_ascii_lowercase())
        .collect();
    if found != named {
        bail!(
            "notices: {ISS} installs {found:?} from target\\release, but notices.rs SHIPPED names \
             {named:?}; make them agree"
        );
    }
    Ok(())
}

/// LF line ends, no byte-order mark, no trailing blank lines, one final newline.
fn normalise(text: &str) -> String {
    let t = text.strip_prefix('\u{feff}').unwrap_or(text);
    let t = t.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = t.lines().map(str::trim_end).collect();
    let mut out = lines.join("\n");
    let trimmed = out.trim_end_matches('\n').len();
    out.truncate(trimmed);
    out.push('\n');
    out
}

/// The SPDX ids and exceptions an expression names (`AND`, `OR`, `WITH`, brackets and the old
/// `/` left out).
fn licence_ids(expr: &str) -> Vec<&str> {
    expr.split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == '/')
        .filter(|t| !t.is_empty() && !matches!(*t, "AND" | "OR" | "WITH"))
        .collect()
}

/// Whether a file name is a licence or notice file.
fn is_licence_name(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    ["LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE"]
        .iter()
        .any(|p| n.starts_with(p))
}

/// The licence files in `dir` (and in a licence-named folder in it, such as `LICENSES/`), as
/// `(label, path)` sorted by label.
fn licence_files(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for e in entries {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        if !is_licence_name(&name) {
            continue;
        }
        let ty = e.file_type()?;
        if ty.is_file() {
            out.push((name, e.path()));
        } else if ty.is_dir() {
            for f in std::fs::read_dir(e.path())? {
                let f = f?;
                if f.file_type()?.is_file() {
                    let sub = f.file_name().to_string_lossy().into_owned();
                    out.push((format!("{name}/{sub}"), f.path()));
                }
            }
        }
    }
    out.sort_by(|a, b| {
        a.0.to_ascii_lowercase()
            .cmp(&b.0.to_ascii_lowercase())
            .then(a.0.cmp(&b.0))
    });
    Ok(out)
}

/// A package's licence files: its own folder's, or for a git dependency without any, those of
/// the checkout's root (the nearest folder above that holds cargo's `.cargo-ok`).
fn package_licence_files(dir: &Path, git: bool) -> Result<Vec<(String, PathBuf)>> {
    let own = licence_files(dir)?;
    if !own.is_empty() || !git {
        return Ok(own);
    }
    for up in dir.ancestors().skip(1) {
        if up.join(".cargo-ok").exists() {
            let files = licence_files(up)?;
            return Ok(files
                .into_iter()
                .map(|(l, p)| (format!("{l} (repository root)"), p))
                .collect());
        }
    }
    Ok(Vec::new())
}

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// The repository of a package: Cargo.toml's `repository`, or a git source's URL.
fn repository_of(pkg: &Value) -> String {
    if let Some(r) = str_field(pkg, "repository") {
        return r.to_string();
    }
    if let Some(src) = str_field(pkg, "source").and_then(|s| s.strip_prefix("git+")) {
        let end = src.find(['?', '#']).unwrap_or(src.len());
        return src[..end].to_string();
    }
    "not declared".to_string()
}

/// The notices file for a `cargo metadata --format-version 1` output.
fn render(json: &str) -> Result<String> {
    let meta: Value = serde_json::from_str(json).context("cargo metadata output is not JSON")?;
    let packages = meta["packages"]
        .as_array()
        .context("cargo metadata has no packages")?;
    let by_id: BTreeMap<&str, &Value> = packages
        .iter()
        .filter_map(|p| Some((str_field(p, "id")?, p)))
        .collect();
    let members: BTreeSet<&str> = meta["workspace_members"]
        .as_array()
        .context("cargo metadata has no workspace_members")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let nodes: BTreeMap<&str, &Value> = meta["resolve"]["nodes"]
        .as_array()
        .context("cargo metadata has no resolve")?
        .iter()
        .filter_map(|n| Some((str_field(n, "id")?, n)))
        .collect();

    // The shipped packages, then everything they reach over normal edges.
    let mut stack = Vec::new();
    for (name, _) in SHIPPED {
        let id = members
            .iter()
            .find(|id| by_id.get(*id).and_then(|p| str_field(p, "name")) == Some(*name))
            .with_context(|| format!("the workspace has no member {name}"))?;
        stack.push(*id);
    }
    let mut reached = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !reached.insert(id) {
            continue;
        }
        let node = nodes
            .get(id)
            .with_context(|| format!("no resolve node for {id}"))?;
        for dep in node["deps"].as_array().into_iter().flatten() {
            let normal = dep["dep_kinds"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|k| k["kind"].is_null());
            if normal && let Some(pkg) = str_field(dep, "pkg") {
                stack.push(pkg);
            }
        }
    }

    let mut texts: Vec<String> = Vec::new();
    let mut text_index: BTreeMap<String, usize> = BTreeMap::new();
    let mut intern = |t: String| -> usize {
        *text_index.entry(t.clone()).or_insert_with(|| {
            texts.push(t);
            texts.len() - 1
        })
    };
    let mut crates: Vec<Crate> = Vec::new();
    let mut problems = Vec::new();
    let mut sorted: Vec<&Value> = reached
        .iter()
        .filter(|id| !members.contains(*id))
        .map(|id| by_id[id])
        .collect();
    sorted.sort_by(|a, b| {
        (str_field(a, "name"), str_field(a, "version"))
            .cmp(&(str_field(b, "name"), str_field(b, "version")))
    });
    for pkg in sorted {
        let name = str_field(pkg, "name").unwrap_or_default().to_string();
        let version = str_field(pkg, "version").unwrap_or_default().to_string();
        let source = str_field(pkg, "source").unwrap_or_default();
        if source.is_empty() {
            problems.push(format!(
                "{name} {version} is a path dependency outside the workspace"
            ));
            continue;
        }
        let (licence, licence_note) = match str_field(pkg, "license") {
            Some(l) => (l.to_string(), None),
            None => match DECLARED_ELSEWHERE.iter().find(|(n, _, _)| *n == name) {
                Some((_, l, why)) => (l.to_string(), Some(*why)),
                None => {
                    problems.push(format!(
                        "{name} {version} declares no licence in Cargo.toml (license_file: {:?})",
                        str_field(pkg, "license_file")
                    ));
                    continue;
                }
            },
        };
        for id in licence_ids(&licence) {
            if !PERMISSIVE.contains(&id) {
                problems.push(format!(
                    "{name} {version}: licence {id} (in '{licence}') is not on the permissive list"
                ));
            }
        }
        let manifest = str_field(pkg, "manifest_path").context("a package has no manifest_path")?;
        let dir = Path::new(manifest)
            .parent()
            .context("manifest_path has no parent")?;
        let mut files = package_licence_files(dir, source.starts_with("git+"))?;
        if let Some(lf) = str_field(pkg, "license_file") {
            let p = dir.join(lf);
            if !files.iter().any(|(_, f)| f == &p) {
                files.push((lf.replace('\\', "/"), p));
            }
        }
        let mut entry_texts = Vec::new();
        let standard = files.is_empty();
        if standard {
            for id in licence_ids(&licence) {
                match STANDARD.iter().find(|(s, _)| *s == id) {
                    Some((_, t)) => {
                        entry_texts.push((format!("SPDX {id}"), intern(normalise(t))));
                    }
                    None => problems.push(format!(
                        "{name} {version} ships no licence file and notices.rs has no SPDX text \
                         for {id}"
                    )),
                }
            }
        } else {
            for (label, path) in files {
                let bytes =
                    std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
                let text = String::from_utf8(bytes)
                    .with_context(|| format!("{} is not UTF-8", path.display()))?;
                entry_texts.push((label, intern(normalise(&text))));
            }
        }
        let authors = pkg["authors"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        crates.push(Crate {
            name,
            version,
            licence,
            licence_note,
            repository: repository_of(pkg),
            authors,
            texts: entry_texts,
            standard,
        });
    }
    if !problems.is_empty() {
        bail!(
            "notices: a person has to decide on these crates:\n  {}",
            problems.join("\n  ")
        );
    }
    Ok(format_notices(&crates, &texts))
}

fn format_notices(crates: &[Crate], texts: &[String]) -> String {
    let rule = "=".repeat(78);
    let thin = "-".repeat(78);
    let mut o = String::new();
    let shipped: Vec<&str> = SHIPPED.iter().map(|(_, exe)| *exe).collect();
    let _ = writeln!(o, "Third-party notices for Purge");
    let _ = writeln!(o, "{rule}");
    let _ = writeln!(o);
    wrap(
        &mut o,
        "",
        &format!(
            "Purge itself is under the MIT licence (LICENSE); NOTICE holds the notices of the code \
             it ports. {} link the {} Rust crates below. Each entry names the crate's licence and \
             the licence texts it ships; the texts follow the list, each given once. Where a crate \
             offers a choice of licences (\"OR\"), Purge uses it under any one of them; the texts \
             of all are reproduced.",
            shipped.join(", "),
            crates.len()
        ),
    );
    let _ = writeln!(o);
    wrap(
        &mut o,
        "",
        &format!(
            "Generated from Cargo.lock by `cargo xtask notices` (tools/xtask/src/notices.rs) for \
             the target {TARGET}; do not edit by hand. `cargo xtask notices --check` fails when \
             this file is out of date."
        ),
    );
    let _ = writeln!(o);
    let _ = writeln!(o, "Crates");
    let _ = writeln!(o, "{rule}");
    for c in crates {
        let _ = writeln!(o);
        let _ = writeln!(o, "{} {}", c.name, c.version);
        match c.licence_note {
            Some(why) => {
                let _ = writeln!(
                    o,
                    "  Licence:    {} (its Cargo.toml declares none; from {why})",
                    c.licence
                );
            }
            None => {
                let _ = writeln!(o, "  Licence:    {}", c.licence);
            }
        }
        let _ = writeln!(o, "  Repository: {}", c.repository);
        let list: Vec<String> = c
            .texts
            .iter()
            .map(|(label, i)| format!("[T{}] {label}", i + 1))
            .collect();
        let _ = writeln!(o, "  Texts:      {}", list.join(", "));
        if c.standard {
            let _ = writeln!(
                o,
                "  Note:       the crate's package ships no licence file; the SPDX standard text of"
            );
            let _ = writeln!(
                o,
                " \
             its licence is given instead, with the template's copyright line."
            );
            if !c.authors.is_empty() {
                let _ = writeln!(o, "  Authors:    {}", c.authors.join(", "));
            }
        }
    }
    let _ = writeln!(o);
    let _ = writeln!(o, "Licence texts");
    let _ = writeln!(o, "{rule}");
    for (i, text) in texts.iter().enumerate() {
        let users: Vec<String> = crates
            .iter()
            .filter(|c| c.texts.iter().any(|(_, t)| *t == i))
            .map(|c| format!("{} {}", c.name, c.version))
            .collect();
        let _ = writeln!(o);
        wrap(
            &mut o,
            "    ",
            &format!("[T{}] used by: {}", i + 1, users.join(", ")),
        );
        let _ = writeln!(o, "{thin}");
        o.push_str(text);
    }
    normalise(&o)
}

/// `text` wrapped at 78 columns, the lines after the first indented by `indent`.
fn wrap(o: &mut String, indent: &str, text: &str) {
    let mut line = String::new();
    for word in text.split(' ').filter(|w| !w.is_empty()) {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > 78 {
            o.push_str(&line);
            o.push('\n');
            line = indent.to_string();
        } else if !line.is_empty() && line != indent {
            line.push(' ');
        }
        line.push_str(word);
    }
    o.push_str(&line);
    o.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_of_expressions() {
        assert_eq!(licence_ids("MIT OR Apache-2.0"), ["MIT", "Apache-2.0"]);
        assert_eq!(
            licence_ids("(MIT OR Apache-2.0) AND Unicode-3.0"),
            ["MIT", "Apache-2.0", "Unicode-3.0"]
        );
        assert_eq!(licence_ids("Unlicense/MIT"), ["Unlicense", "MIT"]);
        assert_eq!(
            licence_ids("Apache-2.0 WITH LLVM-exception"),
            ["Apache-2.0", "LLVM-exception"]
        );
    }

    #[test]
    fn normalising() {
        assert_eq!(normalise("\u{feff}a \r\nb\r\n\r\n\n"), "a\nb\n");
    }

    #[test]
    fn licence_names() {
        for n in [
            "LICENSE",
            "LICENSE-MIT",
            "license-apache-2.0",
            "COPYING",
            "NOTICE",
            "UNLICENSE",
            "LICENCE.md",
        ] {
            assert!(is_licence_name(n), "{n}");
        }
        for n in ["README.md", "Cargo.toml", "src"] {
            assert!(!is_licence_name(n), "{n}");
        }
    }

    #[test]
    fn standard_texts_are_whole() {
        for (id, t) in STANDARD {
            assert!(t.len() > 900, "{id}");
        }
    }
}
