//! `notices`: writes `THIRD-PARTY-NOTICES.txt`, the licences of the third-party code the shipped
//! binaries contain, from `Cargo.lock` and the pinned toolchain; `notices --check` fails when the
//! committed file is not what this command would write now (a dependency or toolchain bump without
//! new notices).
//!
//! **Crates.** Those reached from the shipped binaries ([`SHIPPED`], the exes of
//! `install/inno/purge.iss`) over normal dependency edges of `cargo metadata --filter-platform
//! x86_64-pc-windows-msvc` ([`shipped_ids`]): dev-dependencies and build-dependencies (and so build
//! scripts' own tools) are left out, and so is the xtask. The metadata's resolve is the workspace's,
//! with its features unified, so the list can name a crate that one release build (`cargo build
//! --release -p <bin>`) does not link; it never misses one. Purge's own workspace crates are covered
//! by `LICENSE` and `NOTICE` and are not listed.
//!
//! For each crate: its name, version, licence expression and repository, and the full text of every
//! licence-like file of its package ([`is_licence_name`]: `LICENSE*`, `COPYING*`, `NOTICE*`,
//! `COPYRIGHT*`, `AUTHORS*`, ...) at its root and anywhere below `src/` (vendored code), NOTICE files
//! included (Apache-2.0 section 4(d)), deduplicated by text. A git dependency without such files in
//! its own folder takes them from its checkout's root. A crate with no such file at all must have an
//! entry in [`VENDORED`] (keyed by name and version, so a bump forces a fresh look): its upstream
//! repository's files at the matching tag, committed under `notices/`. A licence id outside
//! [`PERMISSIVE`], a crate that declares no licence and is not in [`DECLARED_ELSEWHERE`], a crate
//! with no licence file and no [`VENDORED`] entry, or a [`VENDORED`] entry no crate uses is an
//! error: a person decides.
//!
//! **The Rust standard library** ([`rust_std`]). Every exe links it statically. Its notices come
//! from the toolchain that builds the exes (`rustc --print sysroot`, run in the workspace so that
//! `rust-toolchain.toml` picks it): `share/doc/rust/COPYRIGHT-library.html` (the in-tree licences,
//! and the out-of-tree crates with their notices) and `share/doc/rust/licenses/<id>.txt`. Of the
//! out-of-tree crates, those the toolchain ships an rlib of for the target
//! (`lib/rustlib/x86_64-pc-windows-msvc/lib`) are listed, every version the file names.
//!
//! Not covered: the Microsoft C runtime (linked statically, `crt-static`), Microsoft's
//! redistributable runtime under its own terms, and the Windows system libraries.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

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

/// The file-name prefixes (any case) of the files collected from a package.
const LICENCE_PREFIXES: &[&str] = &[
    "LICENSE",
    "LICENCE",
    "COPYING",
    "NOTICE",
    "UNLICENSE",
    "COPYRIGHT",
    "AUTHORS",
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

/// The licence files of a crate whose package ships none, taken from its upstream repository.
struct Vendored {
    name: &'static str,
    version: &'static str,
    /// Where the files were taken from: the repository and the tag of this version.
    source: &'static str,
    files: &'static [(&'static str, &'static str)],
}

// AccessKit (github.com/AccessKit/accesskit): its crates' packages ship no licence file. The three
// files at the repository root are the same at the four tags below (commit f302622). Parts of
// accesskit, accesskit_consumer and accesskit_windows derive from Chromium (LICENSE.chromium).
const AK_MIT: (&str, &str) = ("LICENSE-MIT", include_str!("notices/accesskit/LICENSE-MIT"));
const AK_APACHE: (&str, &str) = (
    "LICENSE-APACHE",
    include_str!("notices/accesskit/LICENSE-APACHE"),
);
const AK_CHROMIUM: (&str, &str) = (
    "LICENSE.chromium",
    include_str!("notices/accesskit/LICENSE.chromium"),
);

/// Licence files for crates that ship none, keyed by name and version.
const VENDORED: &[Vendored] = &[
    Vendored {
        name: "accesskit",
        version: "0.25.2",
        source: "https://github.com/AccessKit/accesskit/tree/accesskit-v0.25.2",
        files: &[AK_MIT, AK_APACHE, AK_CHROMIUM],
    },
    Vendored {
        name: "accesskit_consumer",
        version: "0.39.2",
        source: "https://github.com/AccessKit/accesskit/tree/accesskit_consumer-v0.39.2",
        files: &[AK_MIT, AK_APACHE, AK_CHROMIUM],
    },
    Vendored {
        name: "accesskit_windows",
        version: "0.35.2",
        source: "https://github.com/AccessKit/accesskit/tree/accesskit_windows-v0.35.2",
        files: &[AK_MIT, AK_APACHE, AK_CHROMIUM],
    },
    // Apache-2.0 only, and no Chromium-derived source in this crate.
    Vendored {
        name: "accesskit_winit",
        version: "0.34.2",
        source: "https://github.com/AccessKit/accesskit/tree/accesskit_winit-v0.34.2",
        files: &[AK_APACHE],
    },
];

/// One entry of a list.
struct Crate {
    name: String,
    version: String,
    licence: String,
    /// Where the licence came from when Cargo.toml has none.
    licence_note: Option<&'static str>,
    repository: String,
    /// `(file label, text index)`.
    texts: Vec<(String, usize)>,
    /// Lines printed after the texts, as they are.
    extra: Vec<String>,
}

/// The licence texts, each kept once, numbered in the order they are first met.
#[derive(Default)]
struct Texts {
    list: Vec<String>,
    index: BTreeMap<String, usize>,
}

impl Texts {
    fn intern(&mut self, text: String) -> usize {
        if let Some(i) = self.index.get(&text) {
            return *i;
        }
        self.list.push(text.clone());
        self.index.insert(text, self.list.len() - 1);
        self.list.len() - 1
    }
}

/// What the toolchain says of the Rust standard library.
struct RustStd {
    /// `rustc -V`.
    rustc: String,
    /// The standard library itself, with its in-tree licences in `extra`.
    library: Crate,
    /// The out-of-tree crates it links.
    crates: Vec<Crate>,
}

pub fn run(root: &Path, args: &[String]) -> Result<bool> {
    let mut check = false;
    for arg in args {
        match arg.as_str() {
            "--check" => check = true,
            other => bail!("notices: unknown argument {other}"),
        }
    }
    check_shipped(
        &std::fs::read_to_string(root.join(ISS)).with_context(|| format!("reading {ISS}"))?,
    )?;
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
    let mut texts = Texts::default();
    let rust_std = rust_std(root, &mut texts)?;
    let crates = crates(&json, &mut texts)?;
    let text = format_notices(&rust_std, &crates, &texts.list);
    let path = root.join(OUTPUT);
    if check {
        let committed = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let committed = normalise(&committed);
        if committed == text {
            println!(
                "notices: {OUTPUT} matches Cargo.lock and {}",
                rust_std.rustc
            );
            return Ok(true);
        }
        let line = committed
            .lines()
            .zip(text.lines())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| committed.lines().count().min(text.lines().count()))
            + 1;
        eprintln!(
            "notices: {OUTPUT} does not match Cargo.lock and {} (first difference at line \
             {line}); run `cargo xtask notices` and commit the file",
            rust_std.rustc
        );
        return Ok(false);
    }
    std::fs::write(&path, &text).with_context(|| format!("writing {}", path.display()))?;
    println!("notices: wrote {}", path.display());
    Ok(true)
}

/// Fails when the installer installs an exe from the cargo target folder that [`SHIPPED`] does not
/// name, or no longer installs one it names. Comment lines (`;`) are skipped.
fn check_shipped(iss: &str) -> Result<()> {
    let marker = "\\target\\release\\";
    let mut found = BTreeSet::new();
    for line in iss.lines() {
        if line.trim_start().starts_with(';') {
            continue;
        }
        let line = line.to_ascii_lowercase();
        for (at, _) in line.match_indices(marker) {
            let rest = &line[at + marker.len()..];
            if let Some(end) = rest.find(".exe") {
                found.insert(format!("{}.exe", &rest[..end]));
            }
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

/// LF line ends, no byte-order mark, no trailing whitespace, no leading or trailing blank lines,
/// one final newline.
fn normalise(text: &str) -> String {
    let t = text.strip_prefix('\u{feff}').unwrap_or(text);
    let t = t.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = t.lines().map(str::trim_end).collect();
    let mut out = lines.join("\n");
    let trimmed = out.trim_end_matches('\n').len();
    out.truncate(trimmed);
    let out = out.trim_start_matches('\n');
    format!("{out}\n")
}

/// A file's text, normalised; it must be UTF-8.
fn read_text(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let text =
        String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))?;
    Ok(normalise(&text))
}

/// The SPDX ids and exceptions an expression names (`AND`, `OR`, `WITH`, brackets and the old
/// `/` left out).
fn licence_ids(expr: &str) -> Vec<&str> {
    expr.split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == '/')
        .filter(|t| !t.is_empty() && !matches!(*t, "AND" | "OR" | "WITH"))
        .collect()
}

/// The ids of `licence` outside [`PERMISSIVE`], as problems of `who`.
fn not_permissive(who: &str, licence: &str) -> Vec<String> {
    licence_ids(licence)
        .into_iter()
        .filter(|id| !PERMISSIVE.contains(id))
        .map(|id| format!("{who}: licence {id} (in '{licence}') is not on the permissive list"))
        .collect()
}

/// Whether a file name is a licence, notice or copyright file (never a `.rs` file).
fn is_licence_name(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    // Source files are code, whatever their name (the toolkit's src/notice.rs).
    !n.ends_with(".RS") && LICENCE_PREFIXES.iter().any(|p| n.starts_with(p))
}

/// The licence files in `dir` (and in a licence-named folder in it, such as `LICENSES/`), and with
/// `src`, every licence-named file anywhere below `dir/src` (vendored code), as `(label, path)`
/// sorted by label.
fn licence_files(dir: &Path, src: bool) -> Result<Vec<(String, PathBuf)>> {
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
    if src {
        let mut stack = vec![(dir.join("src"), "src".to_string())];
        while let Some((d, label)) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in entries {
                let e = e?;
                let name = e.file_name().to_string_lossy().into_owned();
                let ty = e.file_type()?;
                if ty.is_dir() {
                    stack.push((e.path(), format!("{label}/{name}")));
                } else if ty.is_file() && is_licence_name(&name) {
                    out.push((format!("{label}/{name}"), e.path()));
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
    let own = licence_files(dir, true)?;
    if !own.is_empty() || !git {
        return Ok(own);
    }
    for up in dir.ancestors().skip(1) {
        if up.join(".cargo-ok").exists() {
            let files = licence_files(up, false)?;
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

/// The package ids the shipped binaries reach over normal edges (a dependency that is also a
/// build- or dev-dependency counts; one that is only that does not), workspace members included.
fn shipped_ids(meta: &Value) -> Result<BTreeSet<String>> {
    let packages = meta["packages"]
        .as_array()
        .context("cargo metadata has no packages")?;
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
    let mut stack = Vec::new();
    for (name, _) in SHIPPED {
        let pkg = packages
            .iter()
            .find(|p| {
                str_field(p, "name") == Some(*name)
                    && str_field(p, "id").is_some_and(|id| members.contains(id))
            })
            .with_context(|| format!("the workspace has no member {name}"))?;
        stack.push(str_field(pkg, "id").unwrap_or_default());
    }
    let mut reached = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !reached.insert(id.to_string()) {
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
    Ok(reached)
}

/// The third-party crates of a `cargo metadata --format-version 1` output that the shipped
/// binaries reach, sorted by name and version.
fn crates(json: &str, texts: &mut Texts) -> Result<Vec<Crate>> {
    let meta: Value = serde_json::from_str(json).context("cargo metadata output is not JSON")?;
    let reached = shipped_ids(&meta)?;
    let members: BTreeSet<&str> = meta["workspace_members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let mut sorted: Vec<&Value> = meta["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| {
            str_field(p, "id").is_some_and(|id| reached.contains(id) && !members.contains(id))
        })
        .collect();
    sorted.sort_by(|a, b| {
        (str_field(a, "name"), str_field(a, "version"))
            .cmp(&(str_field(b, "name"), str_field(b, "version")))
    });

    let mut out = Vec::new();
    let mut problems = Vec::new();
    let mut used_vendored = BTreeSet::new();
    for pkg in sorted {
        let name = str_field(pkg, "name").unwrap_or_default().to_string();
        let version = str_field(pkg, "version").unwrap_or_default().to_string();
        let who = format!("{name} {version}");
        let source = str_field(pkg, "source").unwrap_or_default();
        if source.is_empty() {
            problems.push(format!("{who} is a path dependency outside the workspace"));
            continue;
        }
        let (licence, licence_note) = match str_field(pkg, "license") {
            Some(l) => (l.to_string(), None),
            None => match DECLARED_ELSEWHERE.iter().find(|(n, _, _)| *n == name) {
                Some((_, l, why)) => (l.to_string(), Some(*why)),
                None => {
                    problems.push(format!(
                        "{who} declares no licence in Cargo.toml (license_file: {:?})",
                        str_field(pkg, "license_file")
                    ));
                    continue;
                }
            },
        };
        problems.extend(not_permissive(&who, &licence));
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
        for (label, path) in files {
            entry_texts.push((label, texts.intern(read_text(&path)?)));
        }
        let mut extra = Vec::new();
        let vendored = VENDORED
            .iter()
            .position(|v| v.name == name && v.version == version);
        if let Some(i) = vendored {
            let v = &VENDORED[i];
            used_vendored.insert(i);
            for (label, text) in v.files {
                entry_texts.push((format!("{label} (upstream)"), texts.intern(normalise(text))));
            }
            extra.push(field(
                "  Note:       ",
                &format!(
                    "the package ships no licence file; the \"(upstream)\" texts are the files \
                     of {}.",
                    v.source
                ),
            ));
        } else if entry_texts.is_empty() {
            problems.push(format!(
                "{who} ships no licence file and notices.rs VENDORED has no entry for this version"
            ));
            continue;
        }
        out.push(Crate {
            name,
            version,
            licence,
            licence_note,
            repository: repository_of(pkg),
            texts: entry_texts,
            extra,
        });
    }
    for (i, v) in VENDORED.iter().enumerate() {
        if !used_vendored.contains(&i) {
            problems.push(format!(
                "notices.rs VENDORED has {} {}, which no shipped binary links (bumped? vendor the \
                 new version's files and look again)",
                v.name, v.version
            ));
        }
    }
    if !problems.is_empty() {
        bail!(
            "notices: a person has to decide on these crates:\n  {}",
            problems.join("\n  ")
        );
    }
    Ok(out)
}

/// The standard library's notices from the toolchain the workspace builds with.
fn rust_std(root: &Path, texts: &mut Texts) -> Result<RustStd> {
    let rustc = |arg: &str| -> Result<String> {
        let out = Command::new("rustc")
            .arg(arg)
            .current_dir(root)
            .output()
            .with_context(|| format!("running rustc {arg}"))?;
        if !out.status.success() {
            bail!("rustc {arg} failed");
        }
        Ok(String::from_utf8(out.stdout)
            .context("rustc output is not UTF-8")?
            .trim()
            .to_string())
    };
    let version_line = rustc("-V")?;
    let sysroot = PathBuf::from(rustc("--print=sysroot")?);
    let doc = sysroot.join("share").join("doc").join("rust");
    let html_path = doc.join("COPYRIGHT-library.html");
    let html = std::fs::read_to_string(&html_path)
        .with_context(|| format!("reading {}", html_path.display()))?;
    let lib = sysroot.join("lib").join("rustlib").join(TARGET).join("lib");
    let mut rlibs = BTreeSet::new();
    for e in std::fs::read_dir(&lib).with_context(|| format!("reading {}", lib.display()))? {
        let name = e?.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".rlib")
            && let Some(stem) = stem.strip_prefix("lib")
            && let Some(dash) = stem.rfind('-')
        {
            rlibs.insert(stem[..dash].to_string());
        }
    }
    if !rlibs.contains("std") {
        bail!("{} has no std rlib", lib.display());
    }
    let parsed = parse_copyright_library(&html)?;
    let mut problems = Vec::new();

    // The library itself and its in-tree licences.
    let mut ids = BTreeSet::new();
    let mut extra = vec![field(
        "  In-tree:    ",
        "the licences of the library's own files, from share/doc/rust/COPYRIGHT-library.html; \
         an indented entry is an exception inside the one above it:",
    )];
    for e in &parsed.in_tree {
        let pad = "  ".repeat(e.depth);
        extra.push(format!("    {pad}{}: {}\n", e.path, e.licence));
        for c in &e.copyrights {
            extra.push(format!("    {pad}  Copyright {c}\n"));
        }
        problems.extend(not_permissive(
            &format!("std in-tree {}", e.path),
            &e.licence,
        ));
        for id in licence_ids(&e.licence) {
            ids.insert(id.to_string());
        }
    }
    let mut lib_texts = Vec::new();
    for id in &ids {
        let path = doc.join("licenses").join(format!("{id}.txt"));
        if !path.is_file() {
            problems.push(format!(
                "the toolchain has no licence text {}",
                path.display()
            ));
            continue;
        }
        lib_texts.push((
            format!("share/doc/rust/licenses/{id}.txt"),
            texts.intern(read_text(&path)?),
        ));
    }
    extra.push(field(
        "  Note:       ",
        "the texts are the toolchain's licence files, templates whose copyright line the \
         in-tree list above gives.",
    ));
    let rust_version = version_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let library = Crate {
        name: "Rust standard library (core, alloc, std, ...)".to_string(),
        version: rust_version,
        licence: "Apache-2.0 OR MIT, with the in-tree exceptions below".to_string(),
        licence_note: None,
        repository: "https://github.com/rust-lang/rust".to_string(),
        texts: lib_texts,
        extra,
    };

    // The out-of-tree crates the toolchain ships an rlib of.
    let mut crates = Vec::new();
    for c in &parsed.out_of_tree {
        if !rlibs.contains(&c.name.replace('-', "_")) {
            continue;
        }
        let who = format!("std's {} {}", c.name, c.version);
        problems.extend(not_permissive(&who, &c.licence));
        if c.notices.is_empty() {
            problems.push(format!("{who} has no notices in COPYRIGHT-library.html"));
            continue;
        }
        let entry_texts = c
            .notices
            .iter()
            .map(|(label, text)| (label.clone(), texts.intern(normalise(text))))
            .collect();
        crates.push(Crate {
            name: c.name.clone(),
            version: c.version.clone(),
            licence: c.licence.clone(),
            licence_note: None,
            repository: c.url.clone(),
            texts: entry_texts,
            extra: Vec::new(),
        });
    }
    if !problems.is_empty() {
        bail!(
            "notices: a person has to decide on the standard library's notices:\n  {}",
            problems.join("\n  ")
        );
    }
    Ok(RustStd {
        rustc: version_line,
        library,
        crates,
    })
}

/// One in-tree entry of COPYRIGHT-library.html.
struct InTree {
    /// 0 for a top entry, 1 for an exception inside it, ...
    depth: usize,
    path: String,
    licence: String,
    copyrights: Vec<String>,
}

/// One out-of-tree crate of COPYRIGHT-library.html.
struct OutOfTree {
    name: String,
    version: String,
    url: String,
    licence: String,
    /// `(file name, text)`.
    notices: Vec<(String, String)>,
}

struct CopyrightLibrary {
    in_tree: Vec<InTree>,
    out_of_tree: Vec<OutOfTree>,
}

/// `&#34;`, `&#x22;`, `&lt;` and the like.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let Some(end) = tail.find(';').filter(|e| *e <= 10) else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let entity = &tail[1..end];
        let ch = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some('\u{a0}'),
            _ => entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &tail[end + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// `s` without its tags, unescaped and trimmed.
fn plain(s: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    unescape(&out).trim().to_string()
}

/// The text after `marker` in `s` up to `end`, and the rest after `end`.
fn between<'a>(s: &'a str, marker: &str, end: &str) -> Option<(&'a str, &'a str)> {
    let from = s.find(marker)? + marker.len();
    let len = s[from..].find(end)?;
    Some((&s[from..from + len], &s[from + len + end.len()..]))
}

/// The in-tree and out-of-tree parts of the toolchain's COPYRIGHT-library.html.
fn parse_copyright_library(html: &str) -> Result<CopyrightLibrary> {
    let in_at = html
        .find("id=\"in-tree-files\"")
        .context("COPYRIGHT-library.html has no in-tree-files section")?;
    let out_at = html
        .find("id=\"out-of-tree-dependencies\"")
        .context("COPYRIGHT-library.html has no out-of-tree-dependencies section")?;
    if out_at < in_at {
        bail!("COPYRIGHT-library.html: the sections are out of order");
    }

    // In-tree: the File/Directory, License and Copyright fields in order; the depth is how many
    // entry boxes (<div) are open at the entry.
    let part = &html[in_at..out_at];
    let markers = [
        "<b>File/Directory:</b>",
        "<b>License:</b>",
        "<b>Copyright:</b>",
    ];
    let mut in_tree: Vec<InTree> = Vec::new();
    let mut at = 0;
    loop {
        let next = markers
            .iter()
            .enumerate()
            .filter_map(|(k, m)| part[at..].find(m).map(|p| (at + p, k)))
            .min();
        let Some((pos, k)) = next else { break };
        let body_from = pos + markers[k].len();
        let body_len = part[body_from..]
            .find("</p>")
            .context("COPYRIGHT-library.html: a field has no </p>")?;
        let value = plain(&part[body_from..body_from + body_len]);
        at = body_from + body_len;
        match k {
            0 => {
                let before = &part[..pos];
                let open = before.matches("<div").count();
                let close = before.matches("</div>").count();
                in_tree.push(InTree {
                    depth: open.saturating_sub(close).saturating_sub(1),
                    path: value,
                    licence: String::new(),
                    copyrights: Vec::new(),
                });
            }
            1 => {
                let e = in_tree
                    .last_mut()
                    .context("COPYRIGHT-library.html: a licence before any file")?;
                e.licence = value;
            }
            _ => {
                let e = in_tree
                    .last_mut()
                    .context("COPYRIGHT-library.html: a copyright before any file")?;
                e.copyrights.push(value);
            }
        }
    }
    if in_tree.is_empty() || in_tree.iter().any(|e| e.licence.is_empty()) {
        bail!("COPYRIGHT-library.html: an in-tree entry without a licence, or none at all");
    }

    // Out-of-tree: one <h3> a crate.
    let mut out_of_tree = Vec::new();
    for block in html[out_at..].split("<h3>").skip(1) {
        let (head, rest) = block
            .split_once("</h3>")
            .context("COPYRIGHT-library.html: an <h3> without </h3>")?;
        let head = plain(head);
        let head = head.trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
        let dash = head
            .match_indices('-')
            .map(|(i, _)| i)
            .rfind(|i| head[i + 1..].starts_with(|c: char| c.is_ascii_digit()))
            .with_context(|| format!("COPYRIGHT-library.html: no version in '{head}'"))?;
        let (name, version) = (&head[..dash], &head[dash + 1..]);
        let url = between(rest, "<b>URL:</b>", "</p>")
            .map(|(u, _)| plain(u))
            .unwrap_or_default();
        let licence = between(rest, "<b>License:</b>", "</p>")
            .map(|(l, _)| plain(l))
            .with_context(|| format!("COPYRIGHT-library.html: {head} has no licence"))?;
        let mut notices = Vec::new();
        let mut r = rest;
        while let Some((file, after)) = between(r, "<summary><code>", "</code></summary>") {
            let (text, after) = between(after, "<pre>", "</pre>")
                .with_context(|| format!("COPYRIGHT-library.html: {head} {file} has no text"))?;
            notices.push((plain(file), unescape(text)));
            r = after;
        }
        out_of_tree.push(OutOfTree {
            name: name.to_string(),
            version: version.to_string(),
            url,
            licence,
            notices,
        });
    }
    Ok(CopyrightLibrary {
        in_tree,
        out_of_tree,
    })
}

fn format_notices(rust_std: &RustStd, crates: &[Crate], texts: &[String]) -> String {
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
             it ports. This file lists the other software that {} contain: (1) the Rust standard \
             library, which every Rust program links statically, with the {} crates of the \
             toolchain that it links ({}); (2) the {} third-party Rust crates of Cargo.lock that \
             the exes depend on.",
            shipped.join(", "),
            rust_std.crates.len(),
            rust_std.rustc,
            crates.len()
        ),
    );
    let _ = writeln!(o);
    wrap(
        &mut o,
        "",
        "Not listed here: the Microsoft C runtime, which the exes link statically (crt-static) as \
         Microsoft's redistributable runtime under Microsoft's own terms, and the Windows system \
         libraries they call.",
    );
    let _ = writeln!(o);
    wrap(
        &mut o,
        "",
        "Each entry names a licence and the licence texts that come with it; the texts follow the \
         lists, each given once. They are reproduced as their packages ship them, with line \
         endings, trailing whitespace and leading and trailing blank lines normalised. Where a \
         licence offers a choice (\"OR\"), the texts of every choice are reproduced. Both lists \
         may name a little more than is linked: the crates come from the workspace's resolve \
         with its features unified, and the standard library's crates are every version the \
         toolchain names of each crate it ships for the target.",
    );
    let _ = writeln!(o);
    wrap(
        &mut o,
        "",
        &format!(
            "Generated from Cargo.lock and the pinned toolchain by `cargo xtask notices` \
             (tools/xtask/src/notices.rs) for the target {TARGET}; do not edit by hand. `cargo \
             xtask notices --check` fails when this file is out of date."
        ),
    );
    let _ = writeln!(o);
    let _ = writeln!(o, "Rust standard library");
    let _ = writeln!(o, "{rule}");
    entry(&mut o, &rust_std.library);
    for c in &rust_std.crates {
        entry(&mut o, c);
    }
    let _ = writeln!(o);
    let _ = writeln!(o, "Crates");
    let _ = writeln!(o, "{rule}");
    for c in crates {
        entry(&mut o, c);
    }
    let _ = writeln!(o);
    let _ = writeln!(o, "Licence texts");
    let _ = writeln!(o, "{rule}");
    let all: Vec<(&Crate, &str)> = std::iter::once((&rust_std.library, "Rust standard library"))
        .chain(rust_std.crates.iter().map(|c| (c, "std's ")))
        .chain(crates.iter().map(|c| (c, "")))
        .collect();
    for (i, text) in texts.iter().enumerate() {
        let users: Vec<String> = all
            .iter()
            .filter(|(c, _)| c.texts.iter().any(|(_, t)| *t == i))
            .map(|(c, how)| match *how {
                "Rust standard library" => format!("Rust standard library {}", c.version),
                prefix => format!("{prefix}{} {}", c.name, c.version),
            })
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

/// One entry of a list.
fn entry(o: &mut String, c: &Crate) {
    let _ = writeln!(o);
    let _ = writeln!(o, "{} {}", c.name, c.version);
    match c.licence_note {
        Some(why) => o.push_str(&field(
            "  Licence:    ",
            &format!("{} (its Cargo.toml declares none; from {why})", c.licence),
        )),
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
    wrap_items(o, "  Texts:      ", FIELD_INDENT, &list, ", ");
    for line in &c.extra {
        o.push_str(line);
    }
}

/// Where a wrapped field's later lines start.
const FIELD_INDENT: &str = "              ";

/// A field of an entry (`"  Note:       "` and the like) with its text wrapped under it.
fn field(prefix: &str, text: &str) -> String {
    let mut o = String::new();
    let words: Vec<String> = text.split_whitespace().map(str::to_string).collect();
    wrap_items(&mut o, prefix, FIELD_INDENT, &words, " ");
    o
}

/// `text` wrapped at 78 columns, the lines after the first indented by `indent`.
fn wrap(o: &mut String, indent: &str, text: &str) {
    let words: Vec<String> = text.split_whitespace().map(str::to_string).collect();
    wrap_items(o, "", indent, &words, " ");
}

/// `prefix` and the `items` joined by `sep`, wrapped at 78 columns between items (an item is never
/// split), the lines after the first starting with `indent`.
fn wrap_items(o: &mut String, prefix: &str, indent: &str, items: &[String], sep: &str) {
    let mut line = prefix.to_string();
    let mut first = true;
    for item in items {
        if first {
            line.push_str(item);
            first = false;
            continue;
        }
        if line.chars().count() + sep.chars().count() + item.chars().count() > 78 {
            o.push_str(&line);
            o.push_str(sep.trim_end());
            o.push('\n');
            line = indent.to_string();
        } else {
            line.push_str(sep);
        }
        line.push_str(item);
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
        assert_eq!(not_permissive("x", "MIT OR GPL-3.0").len(), 1);
    }

    #[test]
    fn normalising() {
        assert_eq!(normalise("\u{feff}\r\na \r\nb\r\n\r\n\n"), "a\nb\n");
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
            "COPYRIGHT",
            "AUTHORS",
            "AUTHORS.md",
        ] {
            assert!(is_licence_name(n), "{n}");
        }
        for n in [
            "README.md",
            "Cargo.toml",
            "src",
            "author.rs",
            "notice.rs",
            "license.rs",
        ] {
            assert!(!is_licence_name(n), "{n}");
        }
    }

    #[test]
    fn vendored_files_are_whole() {
        for v in VENDORED {
            assert!(!v.files.is_empty(), "{}", v.name);
            assert!(v.source.contains(v.version), "{}", v.name);
            for (label, text) in v.files {
                assert!(text.len() > 900, "{} {label}", v.name);
            }
        }
    }

    #[test]
    fn shipped_exes_from_the_inno_script() {
        let iss = "; #define Old RepoRoot + \"\\target\\release\\old.exe\"\n\
                   #define EngineExe RepoRoot + \"\\target\\release\\purge-engine.exe\"\n\
                   #define BrokerExe RepoRoot + \"\\target\\release\\purge-broker.exe\"\n\
                   #define UiExe RepoRoot + \"\\target\\release\\Purge.exe\"\n";
        check_shipped(iss).unwrap();
        let more = format!("{iss}#define X RepoRoot + \"\\target\\release\\x.exe\"\n");
        assert!(check_shipped(&more).is_err());
    }

    /// The walk follows normal edges (also one that is a build edge too), not build-only or
    /// dev-only ones, and starts from the shipped members.
    #[test]
    fn normal_edges_only() {
        let kinds = |k: &[Option<&str>]| -> Value {
            Value::Array(
                k.iter()
                    .map(|k| serde_json::json!({ "kind": k, "target": null }))
                    .collect(),
            )
        };
        let dep = |pkg: &str, k: &[Option<&str>]| serde_json::json!({ "pkg": pkg, "dep_kinds": kinds(k) });
        let meta = serde_json::json!({
            "packages": [
                { "id": "e", "name": "purge-engine" },
                { "id": "b", "name": "purge-broker" },
                { "id": "u", "name": "purge-ui" },
                { "id": "x", "name": "xtask" },
                { "id": "normal", "name": "normal" },
                { "id": "mixed", "name": "mixed" },
                { "id": "build", "name": "build" },
                { "id": "dev", "name": "dev" },
                { "id": "deep", "name": "deep" },
                { "id": "xonly", "name": "xonly" },
            ],
            "workspace_members": ["e", "b", "u", "x"],
            "resolve": { "nodes": [
                { "id": "e", "deps": [dep("normal", &[None]), dep("build", &[Some("build")])] },
                { "id": "b", "deps": [dep("mixed", &[Some("build"), None]), dep("dev", &[Some("dev")])] },
                { "id": "u", "deps": [dep("e", &[None])] },
                { "id": "x", "deps": [dep("xonly", &[None])] },
                { "id": "normal", "deps": [dep("deep", &[None])] },
                { "id": "mixed", "deps": [] },
                { "id": "build", "deps": [] },
                { "id": "dev", "deps": [] },
                { "id": "deep", "deps": [] },
                { "id": "xonly", "deps": [] },
            ]},
        });
        let got = shipped_ids(&meta).unwrap();
        let want: BTreeSet<String> = ["e", "b", "u", "normal", "mixed", "deep"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn copyright_library_html() {
        let html = r#"<h2 id="in-tree-files">In-tree files</h2>
<div><p><b>File/Directory:</b> <code>.</code></p>
<p><b>License:</b> Apache-2.0 OR MIT</p>
<p><b>Copyright:</b> The Rust Project Developers</p>
<div><p><b>File/Directory:</b> <code>library/core/src/unicode</code></p>
<p><b>License:</b> Unicode-3.0</p>
<p><b>Copyright:</b> 1991-2024 Unicode, Inc</p>
</div></div>
<h2 id="out-of-tree-dependencies">Out-of-tree dependencies</h2>
<h3>&#x1F4E6; rustc-demangle-0.1.28</h3>
<p><b>URL:</b> <a href="u">https://crates.io/crates/rustc-demangle/0.1.28</a></p>
<p><b>License:</b> MIT/Apache-2.0</p>
<details><summary><code>LICENSE-MIT</code></summary><pre>
Copyright &#34;x&#34; &lt;y&gt; &amp; z
</pre></details>
"#;
        let p = parse_copyright_library(html).unwrap();
        assert_eq!(p.in_tree.len(), 2);
        assert_eq!((p.in_tree[0].depth, p.in_tree[0].path.as_str()), (0, "."));
        assert_eq!(p.in_tree[1].depth, 1);
        assert_eq!(p.in_tree[1].licence, "Unicode-3.0");
        assert_eq!(p.in_tree[1].copyrights, ["1991-2024 Unicode, Inc"]);
        let c = &p.out_of_tree[0];
        assert_eq!(
            (c.name.as_str(), c.version.as_str()),
            ("rustc-demangle", "0.1.28")
        );
        assert_eq!(c.licence, "MIT/Apache-2.0");
        assert_eq!(c.url, "https://crates.io/crates/rustc-demangle/0.1.28");
        assert_eq!(c.notices[0].0, "LICENSE-MIT");
        assert_eq!(normalise(&c.notices[0].1), "Copyright \"x\" <y> & z\n");
    }

    #[test]
    fn wrapping_between_items() {
        let mut o = String::new();
        let items: Vec<String> = (0..30).map(|i| format!("[T{i}] x")).collect();
        wrap_items(&mut o, "  Texts:      ", FIELD_INDENT, &items, ", ");
        assert!(o.starts_with("  Texts:      [T0] x, [T1] x,"));
        assert!(o.lines().all(|l| l.len() <= 78));
        assert!(o.lines().skip(1).all(|l| l.starts_with(FIELD_INDENT)));
        assert!(o.lines().all(|l| !l.ends_with(' ')));
    }
}
