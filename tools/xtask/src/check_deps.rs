//! `check-deps`: the MCP server must never link the executor (ENGINE_PLAN.md §3.2, §8.1).
//!
//! Three checks, all on normal and build edges:
//! 1. **Allowlist.** In purge-mcp's own tree (`cargo tree -p purge-mcp`), the only Purge crates are
//!    [`ALLOWED`]. That keeps purge-exec and purge-win out entirely, so no `write`-gated API is reachable.
//! 2. **Unified resolution.** A workspace build unifies features, so an optional dependency that another
//!    member switches on can pull a crate into purge-mcp that its own tree does not show. For every other
//!    Purge crate in the workspace graph, `cargo tree --workspace -i <crate>` must not list purge-mcp.
//! 3. `purge-win` must not have feature `write` in purge-mcp's own tree (kept as a direct statement of the
//!    rule; check 1 already implies it).
//! 4. **Executor.** Only purge-engine links purge-exec, only with its `rig-exec` feature, and `fault-inject`
//!    comes on only through `rig-exec` (see `exec_violations`). A default workspace build links purge-exec
//!    into nothing, and the engine's own tree has no `purge-win/write` (see `default_build_violations`;
//!    releases are built with `cargo build --release -p purge-engine`).
//! 5. **Relaxed store.** purge-exec's `test-support` comes on only through purge-engine's `sandbox-dev`
//!    (never a default, `rig-exec` or workspace build; see `test_support_violations`).
//! 6. **Forbidden identifiers** (M1b, C-WIN). purge-win's code (its `src`, test modules left out) never
//!    names an API that starts, stops or controls a service, opens, installs, configures or repairs an
//!    MSI product, or removes a firewall rule by name through `INetFwRules`, and never spawns `netsh` or
//!    PowerShell (see `identifier_violations`).
//!
//! `xtask ci` also builds purge-mcp on its own (`cargo clippy -p purge-mcp`), so code that only compiles
//! with features another member turns on fails CI.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, bail};

/// The checked binary.
const MCP: &str = "purge-mcp";
/// The only Purge crates purge-mcp may depend on, directly or not.
const ALLOWED: [&str; 2] = ["purge-model", "purge-rpc"];

/// One package line of `cargo tree --prefix none -f "{p} {f}"`.
#[derive(Debug, PartialEq, Eq)]
struct TreeLine<'a> {
    name: &'a str,
    features: Vec<&'a str>,
}

/// Parses `name vX.Y.Z [(source)] [feat1,feat2] [(*)]`.
fn parse_line(line: &str) -> Option<TreeLine<'_>> {
    let line = line.trim();
    let line = line.strip_suffix("(*)").unwrap_or(line).trim_end();
    let (name, rest) = line.split_once(' ')?;
    let feats = match rest.rfind(')') {
        Some(i) => &rest[i + 1..],
        None => rest.split_once(' ').map_or("", |(_version, f)| f),
    };
    let features = feats
        .split(',')
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .collect();
    Some(TreeLine { name, features })
}

fn is_purge(name: &str) -> bool {
    name.starts_with("purge-")
}

/// Violations in a `cargo tree -p purge-mcp` listing (checks 1 and 3).
fn own_tree_violations(tree: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for line in tree.lines().filter_map(parse_line) {
        if is_purge(line.name)
            && line.name != MCP
            && !ALLOWED.contains(&line.name)
            && seen.insert(line.name)
        {
            out.push(format!(
                "{} is in {MCP}'s dependency tree; only {} are allowed",
                line.name,
                ALLOWED.join(" and ")
            ));
        }
        if line.name == "purge-win" && line.features.contains(&"write") {
            out.push(format!("purge-win is built with feature `write` for {MCP}"));
        }
    }
    out
}

/// Purge crates in a workspace-wide tree listing that purge-mcp must not reach.
fn forbidden_in(tree: &str) -> BTreeSet<&str> {
    tree.lines()
        .filter_map(parse_line)
        .map(|l| l.name)
        .filter(|n| is_purge(n) && *n != MCP && !ALLOWED.contains(n))
        .collect()
}

/// Violations in `cargo tree --workspace -i <a> -i <b>...` output (check 2). Cargo prints one tree per
/// inverted crate, root first, separated by a blank line; a purge-mcp line in a tree means purge-mcp
/// depends on that root under unified features. If a tree's root is not recognised, every inverted crate
/// is named.
fn unified_violations(inverted: &str, forbidden: &BTreeSet<&str>) -> Vec<String> {
    let text = inverted.replace("\r\n", "\n");
    let mut out = Vec::new();
    for block in text.split("\n\n") {
        let mut lines = block.lines().filter_map(parse_line);
        let Some(root) = lines.next() else { continue };
        if root.name == MCP || lines.any(|l| l.name == MCP) {
            let what = if forbidden.contains(root.name) {
                root.name.to_string()
            } else {
                let all: Vec<&str> = forbidden.iter().copied().collect();
                format!("one of {}", all.join(", "))
            };
            out.push(format!(
                "with workspace feature unification, {MCP} depends on {what}"
            ));
        }
    }
    out
}

/// The executor crate: only [`ENGINE`] may link it, and with `fault-inject` only through `rig-exec`.
const EXEC: &str = "purge-exec";
/// The one crate that may depend on [`EXEC`].
const ENGINE: &str = "purge-engine";

/// The features purge-exec is built with in a `-f "{p} {f}"` listing, or `None` if it is absent.
fn exec_features(tree: &str) -> Option<BTreeSet<&str>> {
    let mut found: Option<BTreeSet<&str>> = None;
    for line in tree
        .lines()
        .filter_map(parse_line)
        .filter(|l| l.name == EXEC)
    {
        found
            .get_or_insert_with(BTreeSet::new)
            .extend(line.features);
    }
    found
}

/// Violations of the executor rules (M2-CLI). The listings are:
/// - `dependents`: `cargo tree --workspace --all-features -i purge-exec --depth 1 -f "{p}"`; the direct
///   dependents of purge-exec under every feature must be purge-engine alone;
/// - `engine_default`: `cargo tree -p purge-engine -f "{p}"`; a normal build has no executor;
/// - `engine_rig`: `cargo tree -p purge-engine --features rig-exec -f "{p} {f}"`; purge-exec with
///   `fault-inject` and without `test-support`;
/// - `workspace`: `cargo tree --workspace -f "{p} {f}"`; a default workspace build has neither feature.
fn exec_violations(
    dependents: &str,
    engine_default: &str,
    engine_rig: &str,
    workspace: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut deps = dependents.lines().filter_map(parse_line).map(|l| l.name);
    if deps.next() != Some(EXEC) {
        out.push(format!(
            "unexpected cargo tree -i {EXEC} output (first package is not {EXEC})"
        ));
    }
    for name in deps.filter(|n| *n != ENGINE).collect::<BTreeSet<_>>() {
        out.push(format!("{name} depends on {EXEC}; only {ENGINE} may"));
    }
    let mut default = engine_default
        .lines()
        .filter_map(parse_line)
        .map(|l| l.name);
    if default.next() != Some(ENGINE) {
        out.push(format!(
            "unexpected cargo tree -p {ENGINE} output (first package is not {ENGINE})"
        ));
    }
    if default.any(|n| n == EXEC) {
        out.push(format!("{ENGINE} links {EXEC} without feature rig-exec"));
    }
    match exec_features(engine_rig) {
        None => out.push(format!(
            "{ENGINE} with feature rig-exec does not link {EXEC}"
        )),
        Some(f) => {
            if !f.contains("fault-inject") {
                out.push(format!(
                    "{ENGINE} with feature rig-exec builds {EXEC} without fault-inject"
                ));
            }
            if f.contains("test-support") {
                out.push(format!(
                    "{ENGINE} with feature rig-exec builds {EXEC} with test-support"
                ));
            }
        }
    }
    for feature in ["fault-inject", "test-support"] {
        if exec_features(workspace).is_some_and(|f| f.contains(feature)) {
            out.push(format!(
                "a default workspace build turns on {EXEC} feature {feature}"
            ));
        }
    }
    out
}

/// The feature of [`ENGINE`] that is the one way to purge-exec's `test-support` outside tests.
const SANDBOX_DEV: &str = "sandbox-dev";

/// The names of the features in the `[features]` table of a manifest whose list turns on purge-exec's
/// `test-support` (`purge-exec/test-support` or `purge-exec?/test-support`), and whether a normal or build
/// dependency on purge-exec names `test-support` itself. A line-based reader of the plain TOML layout the
/// workspace uses (one feature per line, one dependency per line).
fn test_support_paths(manifest: &str) -> (Vec<&str>, bool) {
    let mut section = "";
    let mut features = Vec::new();
    let mut in_dependency = false;
    for line in manifest.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            section = line;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        let names_it =
            value.contains("purge-exec/test-support") || value.contains("purge-exec?/test-support");
        match section {
            "[features]" if names_it => features.push(key),
            "[dependencies]" | "[build-dependencies]"
                if key == EXEC && value.contains("test-support") =>
            {
                in_dependency = true;
            }
            _ => {}
        }
    }
    (features, in_dependency)
}

/// Violations of the `test-support` rule: only [`SANDBOX_DEV`] turns it on (never a normal dependency,
/// default or `rig-exec`), and `sandbox-dev` really builds purge-exec with it. The listings are
/// `manifest`, the text of purge-engine's Cargo.toml, and `engine_sandbox`: `cargo tree -p purge-engine
/// --features sandbox-dev -f "{p} {f}"`. The default and `rig-exec` builds are checked by
/// [`exec_violations`].
fn test_support_violations(manifest: &str, engine_sandbox: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (features, in_dependency) = test_support_paths(manifest);
    for feature in features.iter().filter(|f| **f != SANDBOX_DEV) {
        out.push(format!(
            "{ENGINE} feature {feature} turns on {EXEC} feature test-support; only {SANDBOX_DEV} may"
        ));
    }
    if !features.contains(&SANDBOX_DEV) {
        out.push(format!(
            "{ENGINE} has no feature {SANDBOX_DEV} that turns on {EXEC} feature test-support"
        ));
    }
    if in_dependency {
        out.push(format!(
            "{ENGINE} depends on {EXEC} with test-support outside a feature"
        ));
    }
    match exec_features(engine_sandbox) {
        Some(f) if f.contains("test-support") => {}
        _ => out.push(format!(
            "{ENGINE} with feature {SANDBOX_DEV} does not build {EXEC} with test-support"
        )),
    }
    out
}

/// Violations of the default build's rules (review M2 M22). The listings are:
/// - `default_dependents`: `cargo tree --workspace -i purge-exec -f "{p}"` with default features: a
///   default workspace build links purge-exec into nothing (a feature another member switches on in the
///   engine would show here, though `-p purge-engine` alone does not show it);
/// - `engine_default`: `cargo tree -p purge-engine -f "{p} {f}"`: purge-win without `write`.
///
/// Releases are built with `cargo build --release -p purge-engine`: a `--workspace` build unifies
/// `purge-win/write` (purge-exec's) into the engine, `-p purge-engine` does not.
fn default_build_violations(default_dependents: &str, engine_default: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut deps = default_dependents
        .lines()
        .filter_map(parse_line)
        .map(|l| l.name);
    if deps.next() != Some(EXEC) {
        out.push(format!(
            "unexpected cargo tree -i {EXEC} output (first package is not {EXEC})"
        ));
    }
    for name in deps.collect::<BTreeSet<_>>() {
        out.push(format!(
            "a default workspace build links {EXEC} into {name}"
        ));
    }
    if engine_default
        .lines()
        .filter_map(parse_line)
        .any(|l| l.name == "purge-win" && l.features.contains(&"write"))
    {
        out.push(format!(
            "{ENGINE} builds purge-win with feature `write` without rig-exec"
        ));
    }
    out
}

fn cargo_tree(root: &Path, args: &[&str]) -> Result<String> {
    let output = crate::cargo()
        .arg("tree")
        .args(args)
        .args(["-e", "normal,build", "--prefix", "none"])
        .current_dir(root)
        .output()
        .context("running cargo tree")?;
    if !output.status.success() {
        bail!(
            "cargo tree {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).context("cargo tree output is not UTF-8")
}

/// The text of [`ENGINE`]'s Cargo.toml, found through `cargo metadata` (the workspace may lay it out
/// anywhere: `bins/purge-engine` in the repository, `purge-engine` in the fixtures of the tests).
fn engine_manifest(root: &Path) -> Result<String> {
    let output = crate::cargo()
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()
        .context("running cargo metadata")?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let meta: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("cargo metadata output is not JSON")?;
    let path = meta["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["name"] == ENGINE)
        .and_then(|p| p["manifest_path"].as_str())
        .with_context(|| format!("cargo metadata lists no {ENGINE}"))?;
    std::fs::read_to_string(path).with_context(|| format!("reading {path}"))
}

/// Runs the check; `Ok(false)` on a violation.
pub fn run(root: &Path) -> Result<bool> {
    let own = cargo_tree(root, &["-p", MCP, "-f", "{p} {f}"])?;
    let names: Vec<&str> = own.lines().filter_map(parse_line).map(|l| l.name).collect();
    if names.first() != Some(&MCP) {
        bail!("unexpected cargo tree output (first package is not {MCP}):\n{own}");
    }
    let mut found = own_tree_violations(&own);

    let workspace = cargo_tree(root, &["--workspace", "-f", "{p}"])?;
    let forbidden = forbidden_in(&workspace);
    if !forbidden.contains("purge-exec") || !forbidden.contains("purge-win") {
        bail!("unexpected cargo tree output (purge-exec or purge-win missing):\n{workspace}");
    }
    let mut args = vec!["--workspace", "-f", "{p}"];
    for name in &forbidden {
        args.extend(["-i", name]);
    }
    let inverted = cargo_tree(root, &args)?;
    found.extend(unified_violations(&inverted, &forbidden));

    let dependents = cargo_tree(
        root,
        &[
            "--workspace",
            "--all-features",
            "-i",
            EXEC,
            "--depth",
            "1",
            "-f",
            "{p}",
        ],
    )?;
    let engine_default = cargo_tree(root, &["-p", ENGINE, "-f", "{p} {f}"])?;
    let engine_rig = cargo_tree(
        root,
        &["-p", ENGINE, "--features", "rig-exec", "-f", "{p} {f}"],
    )?;
    let workspace_features = cargo_tree(root, &["--workspace", "-f", "{p} {f}"])?;
    found.extend(exec_violations(
        &dependents,
        &engine_default,
        &engine_rig,
        &workspace_features,
    ));
    let default_dependents = cargo_tree(root, &["--workspace", "-i", EXEC, "-f", "{p}"])?;
    found.extend(default_build_violations(
        &default_dependents,
        &engine_default,
    ));
    let manifest = engine_manifest(root)?;
    let engine_sandbox = cargo_tree(
        root,
        &["-p", ENGINE, "--features", SANDBOX_DEV, "-f", "{p} {f}"],
    )?;
    found.extend(test_support_violations(&manifest, &engine_sandbox));

    found.extend(win_source_violations(root)?);

    for v in &found {
        eprintln!("check-deps: {v}");
    }
    if found.is_empty() {
        println!(
            "check-deps: ok ({MCP} tree has {} packages, Purge crates only {}; with unified workspace \
             features it reaches none of {} other Purge crates)",
            names.len(),
            ALLOWED.join(", "),
            forbidden.len()
        );
        println!(
            "check-deps: ok ({EXEC} is linked only by {ENGINE}, and with fault-inject only through rig-exec; \
             a default build links it into nothing and {ENGINE} has no purge-win/write)"
        );
        println!(
            "check-deps: ok ({EXEC} test-support only through {ENGINE} feature {SANDBOX_DEV})"
        );
        println!(
            "check-deps: ok (purge-win names none of {}, no `INetFwRules` removal, no {})",
            FORBIDDEN_WIN_IDENTS.join(", "),
            FORBIDDEN_WIN_WORDS.join(" or ")
        );
    }
    Ok(found.is_empty())
}

/// API names purge-win's code must not contain (case-sensitive; a longer name that starts with one,
/// such as `ControlServiceExW` or `MsiOpenPackageExW`, counts).
pub const FORBIDDEN_WIN_IDENTS: &[&str] = &[
    "ControlService",
    "StartServiceW",
    "MsiOpenPackage",
    "MsiOpenProduct",
    "MsiInstallProduct",
    "MsiConfigureProduct",
    "MsiReinstallProduct",
];

/// Tools purge-win's code must not name in any case (no spawned tool changes the machine).
pub const FORBIDDEN_WIN_WORDS: &[&str] = &["netsh", "powershell"];

/// `src` without its top-level `#[cfg(test)]` items: from an attribute line at column 0 through the
/// first line that is `}` at column 0 (the end of a top-level `mod tests { ... }`), or through the
/// attribute's item line when it ends in `;`. An indented `#[cfg(test)]` is kept, so its item is checked.
fn strip_test_modules(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut lines = src.lines();
    while let Some(line) = lines.next() {
        if line.trim_end() != "#[cfg(test)]" {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        for item in lines.by_ref() {
            let t = item.trim_end();
            if t == "}" || (!item.starts_with(' ') && t.ends_with(';')) {
                break;
            }
        }
        out.push('\n');
    }
    out
}

/// What one purge-win source file (`file`, for the message) names that it must not (rule 5).
pub fn identifier_violations(file: &str, src: &str) -> Vec<String> {
    let code = strip_test_modules(src);
    let lower = code.to_ascii_lowercase();
    let mut out = Vec::new();
    for ident in FORBIDDEN_WIN_IDENTS {
        if code.contains(ident) {
            out.push(format!("{file} names {ident}"));
        }
    }
    for word in FORBIDDEN_WIN_WORDS {
        if lower.contains(word) {
            out.push(format!("{file} names {word}"));
        }
    }
    if code.contains("INetFwRules") && code.contains("Remove(") {
        out.push(format!(
            "{file} removes a firewall rule through INetFwRules"
        ));
    }
    out
}

/// Rule 5 over every `.rs` file of `crates/purge-win/src` (none when the directory does not exist, as in
/// the fixture workspaces of the tests).
fn win_source_violations(root: &Path) -> Result<Vec<String>> {
    let src = root.join("crates").join("purge-win").join("src");
    let mut out = Vec::new();
    if !src.is_dir() {
        return Ok(out);
    }
    let mut stack = vec![src.clone()];
    let mut files = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("listing {}", dir.display()))?
        {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    for path in files {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let name = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        out.extend(identifier_violations(&name, &text));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rule 5: each forbidden name in code fails, in any spelling the rule covers; the same names in a
    /// test module, and an `INetFwRules` mention without a removal, pass. The real purge-win passes.
    #[test]
    fn xtask_check_deps_forbidden_identifiers() {
        assert!(identifier_violations("x.rs", "fn f() { let s = \"sc.exe\"; }\n").is_empty());
        for (code, what) in [
            (
                "unsafe { ControlService(h, 1, &mut st) };",
                "ControlService",
            ),
            (
                "unsafe { ControlServiceExW(h, 1, 0, p) };",
                "ControlService",
            ),
            ("StartServiceW(h, None)", "StartServiceW"),
            ("MsiOpenPackageExW(p, 0, &mut h)", "MsiOpenPackage"),
            ("MsiOpenProduct(code, &mut h)", "MsiOpenProduct"),
            ("MsiInstallProductW(p, c)", "MsiInstallProduct"),
            ("MsiConfigureProductEx(p, 0, 2, c)", "MsiConfigureProduct"),
            ("MsiReinstallProductW(p, 0)", "MsiReinstallProduct"),
            ("Command::new(\"NETSH.exe\")", "netsh"),
            (
                "let p = r\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\";",
                "powershell",
            ),
        ] {
            let src = format!("fn f() {{\n    {code}\n}}\n");
            let v = identifier_violations("purge-win/src/x.rs", &src);
            assert_eq!(v, [format!("purge-win/src/x.rs names {what}")], "{code}");
        }
        let fw = "fn f(rules: &INetFwRules) { unsafe { rules.Remove(&name) } }\n";
        assert_eq!(
            identifier_violations("fw.rs", fw),
            ["fw.rs removes a firewall rule through INetFwRules"]
        );
        assert!(identifier_violations("fw.rs", "// INetFwRules is never used\n").is_empty());

        // Test modules may name them (a test that checks a signer of powershell.exe, a list of the
        // names a grep test forbids).
        let tests = "fn real() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        \
                     let _ = \"powershell.exe\";\n        let _ = \"ControlService\";\n    }\n}\n";
        assert!(identifier_violations("x.rs", tests).is_empty());
        let after = format!("{tests}fn later() {{ StartServiceW(h); }}\n");
        assert_eq!(identifier_violations("x.rs", &after).len(), 1);

        assert_eq!(
            win_source_violations(&crate::workspace_root()).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn parses_path_and_registry_lines() {
        assert_eq!(
            parse_line(r"purge-win v0.1.0 (C:\a b\crates\purge-win) default,read,write"),
            Some(TreeLine {
                name: "purge-win",
                features: vec!["default", "read", "write"]
            })
        );
        assert_eq!(
            parse_line(r"purge-model v0.1.0 (C:\x\purge-model)"),
            Some(TreeLine {
                name: "purge-model",
                features: vec![]
            })
        );
        assert_eq!(
            parse_line("serde v1.0.228 default,derive,std (*)"),
            Some(TreeLine {
                name: "serde",
                features: vec!["default", "derive", "std"]
            })
        );
        assert_eq!(
            parse_line("itoa v1.0.15"),
            Some(TreeLine {
                name: "itoa",
                features: vec![]
            })
        );
    }

    #[test]
    fn own_tree_allows_only_model_and_rpc() {
        let clean = "purge-mcp v0.1.0 (C:\\p)\npurge-rpc v0.1.0 (C:\\r)\npurge-model v0.1.0 (C:\\m)\nserde v1 default\n";
        assert!(own_tree_violations(clean).is_empty());
        // purge-win with read only is still not allowed: a workspace build may unify `write` into it.
        let read_only = "purge-mcp v0.1.0 (C:\\p)\npurge-win v0.1.0 (C:\\w) default,read\n";
        assert_eq!(own_tree_violations(read_only).len(), 1);
        let exec = "purge-mcp v0.1.0 (C:\\p)\npurge-exec v0.1.0 (C:\\e)\n";
        assert_eq!(own_tree_violations(exec).len(), 1);
        let write = "purge-mcp v0.1.0 (C:\\p)\npurge-win v0.1.0 (C:\\w) read,write (*)\n";
        assert_eq!(own_tree_violations(write).len(), 2);
        let other = "purge-mcp v0.1.0 (C:\\p)\npurge-source v0.1.0 (C:\\s)\npurge-source v0.1.0 (C:\\s) (*)\n";
        assert_eq!(own_tree_violations(other).len(), 1, "reported once");
        let lookalike = "purge-mcp v0.1.0 (C:\\p)\nfoo-purge-exec v0.1.0\nfoo v1 write\n";
        assert!(own_tree_violations(lookalike).is_empty());
    }

    #[test]
    fn unified_check_flags_mcp_as_a_dependent() {
        let ws = "purge-engine v0.1.0 (C:\\e)\npurge-exec v0.1.0 (C:\\x)\npurge-win v0.1.0 (C:\\w)\n\
                  purge-model v0.1.0 (C:\\m)\npurge-mcp v0.1.0 (C:\\p)\npurge-rpc v0.1.0 (C:\\r)\n";
        let forbidden = forbidden_in(ws);
        assert_eq!(
            forbidden.iter().copied().collect::<Vec<_>>(),
            ["purge-engine", "purge-exec", "purge-win"]
        );
        let clean =
            "purge-win v0.1.0 (C:\\w)\npurge-exec v0.1.0 (C:\\x)\npurge-engine v0.1.0 (C:\\e)\n";
        assert!(unified_violations(clean, &forbidden).is_empty());
        let bad = "purge-exec v0.1.0 (C:\\x)\r\npurge-engine v0.1.0 (C:\\e)\r\n\r\n\
                   purge-win v0.1.0 (C:\\w)\r\npurge-rpc v0.1.0 (C:\\r)\r\npurge-mcp v0.1.0 (C:\\p)\r\n";
        let v = unified_violations(bad, &forbidden);
        assert_eq!(v.len(), 1);
        assert!(v[0].ends_with("depends on purge-win"), "{v:?}");
        let unknown_root = "purge-rpc v0.1.0 (C:\\r)\npurge-mcp v0.1.0 (C:\\p)\n";
        let v = unified_violations(unknown_root, &forbidden);
        assert!(
            v[0].contains("one of purge-engine, purge-exec, purge-win"),
            "{v:?}"
        );
    }

    #[test]
    fn executor_only_in_the_engine_and_fault_inject_only_through_rig_exec() {
        let deps = "purge-exec v0.1.0 (C:\\x)\npurge-engine v0.1.0 (C:\\e)\n";
        let default = "purge-engine v0.1.0 (C:\\e)\npurge-win v0.1.0 (C:\\w) read\n";
        let rig = "purge-engine v0.1.0 (C:\\e)\npurge-exec v0.1.0 (C:\\x) fault-inject\n";
        let ws = "purge-engine v0.1.0 (C:\\e)\npurge-exec v0.1.0 (C:\\x) \npurge-exec v0.1.0 (C:\\x) (*)\n";
        assert!(exec_violations(deps, default, rig, ws).is_empty());

        let other =
            "purge-exec v0.1.0 (C:\\x)\npurge-engine v0.1.0 (C:\\e)\npurge-mcp v0.1.0 (C:\\p)\n";
        let v = exec_violations(other, default, rig, ws);
        assert_eq!(
            v,
            ["purge-mcp depends on purge-exec; only purge-engine may"]
        );

        let linked = "purge-engine v0.1.0 (C:\\e)\npurge-exec v0.1.0 (C:\\x)\n";
        let v = exec_violations(deps, linked, rig, ws);
        assert_eq!(
            v,
            ["purge-engine links purge-exec without feature rig-exec"]
        );

        let no_fault = "purge-engine v0.1.0 (C:\\e)\npurge-exec v0.1.0 (C:\\x) test-support\n";
        assert_eq!(exec_violations(deps, default, no_fault, ws).len(), 2);
        assert_eq!(
            exec_violations(deps, default, default, ws).len(),
            1,
            "rig-exec without the executor"
        );

        let ws_bad = "purge-engine v0.1.0 (C:\\e)\npurge-exec v0.1.0 (C:\\x) fault-inject\n\
                      purge-exec v0.1.0 (C:\\x) test-support (*)\n";
        assert_eq!(exec_violations(deps, default, rig, ws_bad).len(), 2);

        let garbage = "error: nothing\n";
        assert_eq!(
            exec_violations(garbage, garbage, rig, ws).len(),
            2,
            "unrecognised roots are named"
        );
    }

    #[test]
    fn test_support_only_through_sandbox_dev() {
        let sbx = "purge-engine v0.1.0 (C:\\e) sandbox-dev\npurge-exec v0.1.0 (C:\\x) fault-inject,test-support\n";
        let good = "[features]\n\
                    # test-support is mentioned in a comment: purge-exec/test-support\n\
                    rig-exec = [\"dep:purge-exec\", \"purge-exec/fault-inject\"]\n\
                    sandbox-dev = [\"rig-exec\", \"purge-exec/test-support\"]\n\
                    \n[dependencies]\n\
                    purge-exec = { workspace = true, optional = true }\n\
                    \n[dev-dependencies]\n\
                    purge-exec = { workspace = true, features = [\"test-support\"] }\n";
        assert!(test_support_violations(good, sbx).is_empty());
        assert_eq!(test_support_paths(good), (vec!["sandbox-dev"], false));

        // rig-exec (or default) turning it on.
        let rig = good.replace(
            "\"purge-exec/fault-inject\"]",
            "\"purge-exec/fault-inject\", \"purge-exec?/test-support\"]",
        );
        assert_eq!(
            test_support_violations(&rig, sbx),
            [
                "purge-engine feature rig-exec turns on purge-exec feature test-support; only sandbox-dev may"
            ]
        );
        let default = good.replace(
            "[features]\n",
            "[features]\ndefault = [\"purge-exec/test-support\"]\n",
        );
        assert_eq!(test_support_violations(&default, sbx).len(), 1);

        // A normal dependency with the feature.
        let dep = good.replace(
            "purge-exec = { workspace = true, optional = true }",
            "purge-exec = { workspace = true, optional = true, features = [\"test-support\"] }",
        );
        assert_eq!(
            test_support_violations(&dep, sbx),
            ["purge-engine depends on purge-exec with test-support outside a feature"]
        );

        // No sandbox-dev feature, or one that does not reach purge-exec.
        let none = good.replace(
            "sandbox-dev = [\"rig-exec\", \"purge-exec/test-support\"]\n",
            "",
        );
        assert_eq!(test_support_violations(&none, sbx).len(), 1);
        let rig_only = "purge-engine v0.1.0 (C:\\e)\npurge-exec v0.1.0 (C:\\x) fault-inject\n";
        assert_eq!(
            test_support_violations(good, rig_only),
            ["purge-engine with feature sandbox-dev does not build purge-exec with test-support"]
        );
    }

    #[test]
    fn a_default_build_links_no_executor_and_no_write() {
        let none = "purge-exec v0.1.0 (C:\\x)\n";
        let engine = "purge-engine v0.1.0 (C:\\e)\npurge-win v0.1.0 (C:\\w) appx,read,run\n";
        assert!(default_build_violations(none, engine).is_empty());
        let linked = "purge-exec v0.1.0 (C:\\x)\npurge-engine v0.1.0 (C:\\e)\n\
                      purge-xtask v0.1.0 (C:\\t)\npurge-engine v0.1.0 (C:\\e) (*)\n";
        assert_eq!(
            default_build_violations(linked, engine),
            [
                "a default workspace build links purge-exec into purge-engine",
                "a default workspace build links purge-exec into purge-xtask",
            ]
        );
        let write = "purge-engine v0.1.0 (C:\\e)\npurge-win v0.1.0 (C:\\w) read,write\n";
        assert_eq!(
            default_build_violations(none, write),
            ["purge-engine builds purge-win with feature `write` without rig-exec"]
        );
        assert_eq!(default_build_violations("", engine).len(), 1);
    }

    /// A scratch Cargo workspace with the crates rule 4 names, removed on drop.
    struct FixtureWorkspace(std::path::PathBuf);

    impl FixtureWorkspace {
        /// Members `purge-mcp`, `purge-exec`, `purge-win`, `purge-engine` as the real ones relate
        /// (`engine_extra` is added to the engine's manifest), plus `purge-other` with `other_deps`.
        fn new(tag: &str, engine_extra: &str, other_deps: &str) -> FixtureWorkspace {
            let root =
                std::env::temp_dir().join(format!("purge-xtask-deps-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let krate = |name: &str, manifest: &str| {
                let dir = root.join(name);
                std::fs::create_dir_all(dir.join("src")).unwrap();
                std::fs::write(dir.join("src").join("lib.rs"), "").unwrap();
                std::fs::write(
                    dir.join("Cargo.toml"),
                    format!(
                        "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n{manifest}"
                    ),
                )
                .unwrap();
            };
            krate("purge-mcp", "");
            krate(
                "purge-win",
                "[features]\ndefault = [\"read\"]\nread = []\nwrite = [\"read\"]\n",
            );
            krate(
                "purge-exec",
                "[features]\nfault-inject = []\ntest-support = []\n\
                 [dependencies]\npurge-win = { path = \"../purge-win\", features = [\"write\"] }\n",
            );
            krate(
                "purge-engine",
                &format!(
                    "[features]\nrig-exec = [\"dep:purge-exec\", \"purge-exec/fault-inject\"]\n\
                     sandbox-dev = [\"rig-exec\", \"purge-exec/test-support\"]\n{engine_extra}\n\
                     [dependencies]\npurge-win = {{ path = \"../purge-win\", features = [\"read\"] }}\n\
                     purge-exec = {{ path = \"../purge-exec\", optional = true }}\n"
                ),
            );
            krate("purge-other", &format!("[dependencies]\n{other_deps}\n"));
            std::fs::write(
                root.join("Cargo.toml"),
                "[workspace]\nresolver = \"2\"\n\
                 members = [\"purge-mcp\", \"purge-win\", \"purge-exec\", \"purge-engine\", \"purge-other\"]\n",
            )
            .unwrap();
            FixtureWorkspace(root)
        }
    }

    impl Drop for FixtureWorkspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Review M2 M22: the rule run on real manifests. A clean workspace passes; an engine feature that
    /// another member switches on and links the executor fails, and so does an engine that asks for
    /// `purge-win/write` itself. Both broken manifests passed the checks before this rule.
    #[test]
    fn rule_4_fails_on_broken_manifests() {
        let clean = FixtureWorkspace::new("clean", "", "");
        assert!(run(&clean.0).unwrap());

        let unified = FixtureWorkspace::new(
            "unified",
            "exec-core = [\"dep:purge-exec\"]",
            "purge-engine = { path = \"../purge-engine\", features = [\"exec-core\"] }",
        );
        assert!(!run(&unified.0).unwrap());
        let tree = |root: &Path, args: &[&str]| cargo_tree(root, args).unwrap();
        assert_eq!(
            default_build_violations(
                &tree(&unified.0, &["--workspace", "-i", EXEC, "-f", "{p}"]),
                &tree(&unified.0, &["-p", ENGINE, "-f", "{p} {f}"]),
            ),
            [
                "a default workspace build links purge-exec into purge-engine",
                "a default workspace build links purge-exec into purge-other",
            ]
        );

        let write = FixtureWorkspace::new("write", "", "");
        let manifest = write.0.join("purge-engine").join("Cargo.toml");
        let text = std::fs::read_to_string(&manifest)
            .unwrap()
            .replace("features = [\"read\"]", "features = [\"read\", \"write\"]");
        std::fs::write(&manifest, text).unwrap();
        assert!(!run(&write.0).unwrap());
    }
}
