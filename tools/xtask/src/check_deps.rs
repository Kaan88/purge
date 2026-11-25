//! `check-deps`: the MCP server never links the executor, only the broker's release build does, and
//! one function enables a privilege (ENGINE_PLAN.md §3.2, §8.1; M3_DESIGN.md §3.1, §11.1).
//!
//! Every `cargo tree` listing is read with `--target all` and `--prefix none`, on normal and build
//! edges unless a rule names dev edges too. A listing whose first package is not the one asked for is a
//! violation, a failed cargo call an error. "Under any feature" means `--all-features`: a feature only
//! adds edges and features, so that listing holds every combination of them.
//!
//! 1. **Allowlist.** In purge-mcp's own tree under any feature, dev-dependencies included, the only
//!    Purge crates are [`ALLOWED`]. That keeps purge-exec and purge-win out entirely, so no
//!    `write`-gated API is reachable.
//! 2. **Unified resolution.** A workspace build unifies features, so an optional dependency that another
//!    member switches on can pull a crate into purge-mcp that its own tree does not show. For every other
//!    Purge crate in the workspace graph, `cargo tree --workspace --all-features -i <crate>` must not
//!    list purge-mcp.
//! 3. `purge-win` must not have feature `write` in purge-mcp's own tree (kept as a direct statement of the
//!    rule; check 1 already implies it).
//! 4. **Executor and broker** (M3-DEPS; the user's answer 2 of 2026-11-21: a separate broker binary
//!    holds the executor and the medium engine stays executor-free). A release is two builds,
//!    `cargo build --release -p purge-engine`, then `cargo build --release -p purge-broker`, never one
//!    build of both and never `--workspace` (install/README.md).
//!    - (a) purge-exec is linked by purge-broker, and by purge-engine only with `rig-exec`. Under any
//!      feature its direct dependents are those two, and as a dev-dependency only purge-engine (its
//!      tests). purge-engine with every feature but `rig-exec` has no purge-exec; with `rig-exec`
//!      purge-exec has `fault-inject`, and under no feature `test-support`. purge-exec reaches none of
//!      purge-engine, purge-broker and purge-mcp, not even as a dev-dependency (see `exec_violations`).
//!    - (b) purge-broker has no cargo feature. Its tree under any feature, dev-dependencies included,
//!      has purge-exec with no feature at all (so neither `fault-inject` nor `test-support`) and
//!      purge-engine with no feature the release engine lacks (so no `rig-exec`, no `inject-view`).
//!    - (c) purge-engine's release tree has neither purge-exec nor `purge-win/write`, and neither has
//!      the release tree of any other package with a binary target except purge-broker. A default
//!      workspace build links purge-exec into purge-broker alone and turns on neither executor feature.
//!    - (d) No package depends on purge-broker, under any feature, as any kind of dependency.
//!    - (e) **One privilege, one place** (B9; M3-WIN-PRIV's shape, coordinator decision 2026-11-21).
//!      In the production code of every member (its `src`, test items and comments left out):
//!      `SeRestorePrivilege` (as a string or as `SE_RESTORE_NAME`) is named in one function, of
//!      purge-win's `src/privilege.rs`, and no other privilege is named anywhere; the token-adjusting
//!      APIs ([`PRIVILEGE_APIS`]) are named only in that file, in the body of the write-gated
//!      `pub(crate)` enabler `with_restore_privilege` or in a write-gated plain `use`, so its
//!      read-only queries adjust nothing; the enabler is referenced only from `src/reg_write.rs`, once
//!      in each of `CreatedKey::set_security` and `CreatedKey::reopen_and_set_owner` (any other
//!      reference is a violation); `reopen_and_set_owner` has exactly one production reference, in
//!      purge-exec's `src/act_service.rs`. The callers of `set_security` are not limited (the M2 use).
//!      See `privilege_violations`.
//!    - (f) **Manifests and cfg.** Only purge-exec and purge-broker ask for `purge-win/write`, as a
//!      dependency feature or through a feature of their own (purge-engine also as a dev-dependency),
//!      and no other purge-win feature turns `write` on. No member's build script emits `rustc-cfg`
//!      and the workspace's cargo config passes no `--cfg`, so no feature is switched on outside
//!      Cargo's graph (see `manifest_violations`, `cfg_violations`).
//! 5. **Forbidden identifiers** (M1b, C-WIN). purge-win's code (its `src`, test modules left out) never
//!    names an API that starts, stops or controls a service, opens, installs, configures or repairs an
//!    MSI product, or removes a firewall rule by name through `INetFwRules`, never names an offreg call
//!    that creates, changes, saves or merges an offline hive, never mounts a hive (`RegLoadKey`,
//!    `RegLoadAppKey`), and never spawns `netsh` or PowerShell (see `identifier_violations`).
//!
//! 6. **The broker's outside crates** (BROKER-CONSENT-UI). The elevated binary links only what is
//!    listed. In purge-broker's tree for the shipped target, under any feature and with
//!    dev-dependencies, every crate that is not a Purge crate is in [`BROKER_OUTSIDE`] (what it linked
//!    before) or in [`BROKER_TOOLKIT`] (what drawing its consent dialog with Purge's own toolkit
//!    brings: the toolkit, the window loop, accessibility, text, and what the toolkit's crates link
//!    without the dialog using it). Every `mdshared-*` crate comes from the toolkit's repository at a
//!    pinned revision, and `mdshared-ui` is built with `host` and `a11y` only, in the broker's own
//!    tree and in a workspace build. Before this rule nothing limited what the broker links from
//!    outside; a crate a toolkit update starts to bring is now a violation until it is listed (see
//!    `broker_outside_violations`).
//!
//! `xtask ci` also builds purge-mcp on its own (`cargo clippy -p purge-mcp`), so code that only compiles
//! with features another member turns on fails CI.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::{baseline_sites, lex};

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

/// The executor crate.
const EXEC: &str = "purge-exec";
/// The medium engine; it links [`EXEC`] only with [`RIG_EXEC`].
const ENGINE: &str = "purge-engine";
/// The elevated broker: the one release binary that links [`EXEC`].
const BROKER: &str = "purge-broker";
/// The Win32 wrappers, whose `write` feature only the executor's builds have.
const WIN: &str = "purge-win";
/// The engine's rig feature (headless `exec`, fault points).
const RIG_EXEC: &str = "rig-exec";
/// The direct dependents [`EXEC`] may have under any feature (rule 4a).
const EXEC_DEPENDENTS: [&str; 2] = [BROKER, ENGINE];
/// The packages that may have [`EXEC`] as a dev-dependency (purge-engine's tests, rule 4a).
const EXEC_DEV_DEPENDENTS: [&str; 1] = [ENGINE];
/// What [`EXEC`] must not reach, as any kind of dependency (rule 4a).
const EXEC_MUST_NOT_REACH: [&str; 3] = [ENGINE, BROKER, MCP];
/// The executor features a release never has.
const EXEC_RIG_FEATURES: [&str; 2] = ["fault-inject", "test-support"];
/// The packages that may ask for `purge-win/write` (rule 4f).
const WRITE_ASKERS: [&str; 2] = [EXEC, BROKER];
/// The packages that may ask for `purge-win/write` as a dev-dependency (rule 4f).
const WRITE_DEV_ASKERS: [&str; 3] = [EXEC, BROKER, ENGINE];

/// The target a release is built for (`.cargo/config.toml`): rule 6 reads the broker's tree for it,
/// since a crate another system would link is not in the binary.
const SHIPPED_TARGET: &str = "x86_64-pc-windows-msvc";
/// The crates from outside the workspace the broker linked before its consent dialog could be drawn
/// with the toolkit (rule 6): serialisation, hashing, compression, the Windows bindings.
pub const BROKER_OUTSIDE: &[&str] = &[
    "adler2",
    "anyhow",
    "block-buffer",
    "cfg-if",
    "cpufeatures",
    "crc32fast",
    "crypto-common",
    "digest",
    "dyn-clone",
    "flate2",
    "generic-array",
    "itoa",
    "memchr",
    "miniz_oxide",
    "proc-macro2",
    "quick-xml",
    "quote",
    "ref-cast",
    "ref-cast-impl",
    "schemars",
    "schemars_derive",
    "serde",
    "serde_core",
    "serde_derive",
    "serde_derive_internals",
    "serde_json",
    "sha2",
    "simd-adler32",
    "syn",
    "thiserror",
    "thiserror-impl",
    "tinyvec",
    "typenum",
    "unicode-ident",
    "unicode-normalization",
    "version_check",
    "windows",
    "windows-collections",
    "windows-core",
    "windows-future",
    "windows-implement",
    "windows-interface",
    "windows-link",
    "windows-numerics",
    "windows-result",
    "windows-strings",
    "windows-sys",
    "windows-threading",
    "zmij",
];
/// The crates the toolkit dialog brings into the broker (rule 6; package BROKER-CONSENT-UI, the user's
/// decision of 2026-11-25: the elevated consent dialog is drawn with Purge's own toolkit so that it
/// looks like the application). Each group says why it is there. Nothing else from outside may be
/// added to the elevated binary without a line here.
pub const BROKER_TOOLKIT: &[&str] = &[
    // The toolkit itself, at the revision the workspace pins.
    "mdshared-ui",
    "mdshared-text",
    "mdshared-app",
    // The window, its loop and its present: winit (named by the broker too, for the window's handle
    // and size), softbuffer, and what they bring.
    "winit",
    "softbuffer",
    "raw-window-handle",
    "dpi",
    "cursor-icon",
    "smol_str",
    "cfg_aliases",
    "tracing",
    "tracing-core",
    "pin-project-lite",
    "bitflags",
    "windows-targets",
    "windows_x86_64_msvc",
    // Accessibility: the tree and its UI Automation provider.
    "accesskit",
    "accesskit_consumer",
    "accesskit_windows",
    "accesskit_winit",
    "hashbrown",
    "foldhash",
    "static_assertions",
    "uuid",
    // Text: layout (parley), shaping (harfrust), font lookup (fontique, which maps font files into
    // memory), font parsing and scaling (read-fonts, skrifa, swash, zeno), and the Unicode tables.
    "parley",
    "parley_data",
    "parley_emoji",
    "parley_engine",
    "parlance",
    "harfrust",
    "fontique",
    "memmap2",
    "linebender_resource_handle",
    "read-fonts",
    "font-types",
    "skrifa",
    "swash",
    "yazi",
    "zeno",
    "bytemuck",
    "bytemuck_derive",
    "once_cell",
    "smallvec",
    "unicode-segmentation",
    "utf8_iter",
    "utf_types",
    "icu_collections",
    "icu_locale_core",
    "icu_locale_fallback",
    "icu_locale_fallback_data",
    "icu_normalizer",
    "icu_normalizer_data",
    "icu_properties",
    "icu_properties_data",
    "icu_provider",
    "icu_segmenter",
    "icu_segmenter_data",
    "displaydoc",
    "litemap",
    "potential_utf",
    "stable_deref_trait",
    "synstructure",
    "tinystr",
    "writeable",
    "yoke",
    "yoke-derive",
    "zerofrom",
    "zerofrom-derive",
    "zerotrie",
    "zerovec",
    "zerovec-derive",
    // Linked because the toolkit's crates depend on them, and not used by the dialog: image decoding
    // (mdshared-text: png, JPEG), the file watcher of mdshared-app (notify), the file dialogs of
    // mdshared-ui (rfd).
    "png",
    "fdeflate",
    "zune-core",
    "zune-jpeg",
    "notify",
    "notify-types",
    "walkdir",
    "same-file",
    "winapi-util",
    "libc",
    "log",
    "rfd",
];
/// The toolkit crate, and the only features the broker (and any build that unifies with it) may
/// build it with: the window host and accessibility. Not `recycle`, `media-session` or `notify`.
const TOOLKIT: &str = "mdshared-ui";
/// See [`TOOLKIT`].
const TOOLKIT_FEATURES: [&str; 2] = ["a11y", "host"];
/// Where every `mdshared-*` crate must come from: the toolkit's repository at a pinned revision.
const TOOLKIT_SOURCE: &str = "(https://github.com/Kaan88/markdown-shared-rs?rev=";

/// The package names of a listing, root first.
fn names(listing: &str) -> Vec<&str> {
    listing
        .lines()
        .filter_map(parse_line)
        .map(|l| l.name)
        .collect()
}

/// Whether the listing's first package is `root`; pushes a violation naming `query` when it is not.
fn expect_root(listing: &str, root: &str, query: &str, out: &mut Vec<String>) -> bool {
    if names(listing).first() == Some(&root) {
        return true;
    }
    out.push(format!(
        "unexpected cargo tree {query} output (first package is not {root})"
    ));
    false
}

/// The features `name` is built with in a `-f "{p} {f}"` listing (over all its lines), or `None` if it
/// is absent.
fn features_of<'a>(listing: &'a str, name: &str) -> Option<BTreeSet<&'a str>> {
    let mut found: Option<BTreeSet<&str>> = None;
    for line in listing
        .lines()
        .filter_map(parse_line)
        .filter(|l| l.name == name)
    {
        found
            .get_or_insert_with(BTreeSet::new)
            .extend(line.features);
    }
    found
}

/// Whether purge-win is built with `write` in a `-f "{p} {f}"` listing.
fn has_win_write(listing: &str) -> bool {
    features_of(listing, WIN).is_some_and(|f| f.contains("write"))
}

/// The listings of rule 4a.
struct ExecListings<'a> {
    /// `cargo tree --workspace --all-features -i purge-exec --depth 1 -f "{p}"`.
    dependents: &'a str,
    /// The same with `-e dev`: the packages that have purge-exec as a dev-dependency.
    dev_dependents: &'a str,
    /// `cargo tree -p purge-exec --all-features -f "{p}"` with dev edges.
    exec_tree: &'a str,
    /// `cargo tree -p purge-engine --features <every feature but rig-exec> -f "{p} {f}"`.
    engine_no_rig: &'a str,
    /// The features `engine_no_rig` turned on (for the message).
    no_rig_features: &'a str,
    /// `cargo tree -p purge-engine --features rig-exec -f "{p} {f}"`.
    engine_rig: &'a str,
    /// `cargo tree -p purge-engine --all-features -f "{p} {f}"`.
    engine_all: &'a str,
}

/// Violations of rule 4a: who links the executor, and with which features.
fn exec_violations(l: &ExecListings<'_>) -> Vec<String> {
    let mut out = Vec::new();
    if expect_root(l.dependents, EXEC, "-i purge-exec", &mut out) {
        let deps: BTreeSet<&str> = names(l.dependents).into_iter().skip(1).collect();
        for name in deps.iter().filter(|n| !EXEC_DEPENDENTS.contains(*n)) {
            out.push(format!(
                "{name} depends on {EXEC}; only {BROKER}, and {ENGINE} with {RIG_EXEC}, may"
            ));
        }
        if !deps.contains(BROKER) {
            out.push(format!(
                "{BROKER} does not depend on {EXEC} (it is the release binary that links the executor)"
            ));
        }
    }
    if expect_root(l.dev_dependents, EXEC, "-i purge-exec -e dev", &mut out) {
        let deps: BTreeSet<&str> = names(l.dev_dependents).into_iter().skip(1).collect();
        for name in deps.iter().filter(|n| !EXEC_DEV_DEPENDENTS.contains(*n)) {
            out.push(format!(
                "{name} has {EXEC} as a dev-dependency; only {ENGINE}'s tests may"
            ));
        }
    }
    if expect_root(l.exec_tree, EXEC, "-p purge-exec", &mut out) {
        let reached: BTreeSet<&str> = names(l.exec_tree).into_iter().skip(1).collect();
        for name in EXEC_MUST_NOT_REACH.iter().filter(|n| reached.contains(*n)) {
            out.push(format!(
                "{EXEC} reaches {name} (under some feature, or as a dev-dependency)"
            ));
        }
    }
    let with = if l.no_rig_features.is_empty() {
        "its default features".to_string()
    } else {
        format!("features {}", l.no_rig_features)
    };
    if expect_root(
        l.engine_no_rig,
        ENGINE,
        "-p purge-engine (no rig-exec)",
        &mut out,
    ) {
        if names(l.engine_no_rig).contains(&EXEC) {
            out.push(format!(
                "{ENGINE} links {EXEC} without feature {RIG_EXEC} (with {with})"
            ));
        }
        if has_win_write(l.engine_no_rig) {
            out.push(format!(
                "{ENGINE} builds purge-win with feature `write` without {RIG_EXEC} (with {with})"
            ));
        }
    }
    if expect_root(
        l.engine_rig,
        ENGINE,
        "-p purge-engine --features rig-exec",
        &mut out,
    ) {
        match features_of(l.engine_rig, EXEC) {
            None => out.push(format!(
                "{ENGINE} with feature {RIG_EXEC} does not link {EXEC}"
            )),
            Some(f) => {
                if !f.contains("fault-inject") {
                    out.push(format!(
                        "{ENGINE} with feature {RIG_EXEC} builds {EXEC} without fault-inject"
                    ));
                }
                if f.contains("test-support") {
                    out.push(format!(
                        "{ENGINE} with feature {RIG_EXEC} builds {EXEC} with test-support"
                    ));
                }
            }
        }
    }
    if expect_root(
        l.engine_all,
        ENGINE,
        "-p purge-engine --all-features",
        &mut out,
    ) && features_of(l.engine_all, EXEC).is_some_and(|f| f.contains("test-support"))
    {
        out.push(format!(
            "{ENGINE} builds {EXEC} with test-support under some feature (only its tests may)"
        ));
    }
    out
}

/// Violations of rule 6. `tree` is `cargo tree -p purge-broker --all-features -f "{p} {f}"` for the
/// shipped target with dev edges; `workspace` the same for `--workspace`, which holds the features a
/// unified build gives the toolkit.
fn broker_outside_violations(tree: &str, workspace: &str) -> Vec<String> {
    let mut out = Vec::new();
    if !expect_root(tree, BROKER, "-p purge-broker (shipped target)", &mut out) {
        return out;
    }
    let mut seen = BTreeSet::new();
    for raw in tree.lines() {
        let Some(line) = parse_line(raw) else {
            continue;
        };
        if is_purge(line.name) || !seen.insert(line.name) {
            continue;
        }
        if !BROKER_OUTSIDE.contains(&line.name) && !BROKER_TOOLKIT.contains(&line.name) {
            out.push(format!(
                "{} is in {BROKER}'s dependency tree and in neither list of rule 6: the elevated \
                 binary links only what is listed, with the reason written down",
                line.name
            ));
        }
        if line.name.starts_with("mdshared-") && !raw.contains(TOOLKIT_SOURCE) {
            out.push(format!(
                "{} in {BROKER}'s tree does not come from the toolkit's repository at a pinned \
                 revision",
                line.name
            ));
        }
    }
    for (what, listing) in [(BROKER, tree), ("a workspace build", workspace)] {
        let Some(features) = features_of(listing, TOOLKIT) else {
            continue;
        };
        for extra in features.iter().filter(|f| !TOOLKIT_FEATURES.contains(*f)) {
            out.push(format!(
                "{what} builds {TOOLKIT} with feature {extra}; the broker links it with {} only",
                TOOLKIT_FEATURES.join(" and ")
            ));
        }
    }
    out
}

/// Violations of rule 4b. `broker` is `cargo tree -p purge-broker --all-features -f "{p} {f}"` with
/// dev edges; `release_engine` is `cargo tree -p purge-engine -f "{p} {f}"`, whose root line carries the
/// features a release engine has.
fn broker_violations(broker: &str, release_engine: &str) -> Vec<String> {
    let mut out = Vec::new();
    if !expect_root(broker, BROKER, "-p purge-broker", &mut out) {
        return out;
    }
    match features_of(broker, EXEC) {
        None => out.push(format!("{BROKER} does not link {EXEC}")),
        Some(f) => {
            for feature in f {
                out.push(format!(
                    "{BROKER} builds {EXEC} with feature {feature}; it takes {EXEC} with no feature"
                ));
            }
        }
    }
    let release: BTreeSet<&str> = release_engine
        .lines()
        .find_map(parse_line)
        .filter(|l| l.name == ENGINE)
        .map(|l| l.features.into_iter().collect())
        .unwrap_or_default();
    if let Some(f) = features_of(broker, ENGINE) {
        for feature in f.difference(&release) {
            out.push(format!(
                "{BROKER} builds {ENGINE} with feature {feature}, which the release engine does not have"
            ));
        }
    }
    out
}

/// Violations of rule 4c for one package with a binary target: `release` is `cargo tree -p <bin>
/// -f "{p} {f}"` (default features, as `cargo build --release -p <bin>` builds it).
fn release_violations(bin: &str, release: &str) -> Vec<String> {
    let mut out = Vec::new();
    if !expect_root(release, bin, &format!("-p {bin}"), &mut out) {
        return out;
    }
    if names(release).contains(&EXEC) {
        out.push(format!(
            "{bin}'s release build links {EXEC}; only {BROKER}'s may"
        ));
    }
    if has_win_write(release) {
        out.push(format!(
            "{bin}'s release build has purge-win with feature `write`; only {BROKER}'s may"
        ));
    }
    out
}

/// Violations of the default workspace build's rules (rule 4c; review M2 M22). The listings are:
/// - `default_dependents`: `cargo tree --workspace -i purge-exec -f "{p}"` with default features: a
///   default workspace build links purge-exec into purge-broker alone (a feature another member
///   switches on in the engine shows here, though `-p purge-engine` alone does not show it);
/// - `workspace`: `cargo tree --workspace -f "{p} {f}"`: neither executor feature is on.
fn default_build_violations(default_dependents: &str, workspace: &str) -> Vec<String> {
    let mut out = Vec::new();
    if expect_root(
        default_dependents,
        EXEC,
        "--workspace -i purge-exec",
        &mut out,
    ) {
        let deps: BTreeSet<&str> = names(default_dependents).into_iter().skip(1).collect();
        for name in deps.iter().filter(|n| **n != BROKER) {
            out.push(format!(
                "a default workspace build links {EXEC} into {name}"
            ));
        }
    }
    let on = features_of(workspace, EXEC).unwrap_or_default();
    for feature in EXEC_RIG_FEATURES.iter().filter(|f| on.contains(*f)) {
        out.push(format!(
            "a default workspace build turns on {EXEC} feature {feature}"
        ));
    }
    out
}

/// Violations of rule 4d: `dependents` is `cargo tree --workspace --all-features -i purge-broker
/// -f "{p}"` with dev edges.
fn broker_dependents_violations(dependents: &str) -> Vec<String> {
    let mut out = Vec::new();
    if expect_root(dependents, BROKER, "-i purge-broker", &mut out) {
        let deps: BTreeSet<&str> = names(dependents).into_iter().skip(1).collect();
        for name in deps {
            out.push(format!(
                "{name} depends on {BROKER}; nothing may (under any feature, as any kind of dependency)"
            ));
        }
    }
    out
}

/// A workspace member as `cargo metadata --no-deps` declares it.
#[derive(Debug, Default)]
struct Member {
    name: String,
    /// The directory of its manifest.
    dir: PathBuf,
    /// Its `[features]` table (implicit features of optional dependencies included).
    features: BTreeMap<String, Vec<String>>,
    deps: Vec<Dep>,
    /// Whether it has a binary target.
    bin: bool,
    /// Its build scripts (`custom-build` targets).
    build_scripts: Vec<PathBuf>,
}

/// One declared dependency of a [`Member`].
#[derive(Debug, Default)]
struct Dep {
    /// The package name.
    name: String,
    /// The name the manifest uses for it (its `rename`, else the package name).
    key: String,
    /// A `[dev-dependencies]` entry.
    dev: bool,
    /// The features it asks for.
    features: Vec<String>,
}

/// The members of `cargo metadata --no-deps --format-version 1` output; a field missing is an error.
fn parse_members(json: &str) -> Result<Vec<Member>> {
    let v: serde_json::Value =
        serde_json::from_str(json).context("cargo metadata output is not JSON")?;
    let str_of = |v: &serde_json::Value, what: &str| -> Result<String> {
        v.as_str()
            .map(str::to_owned)
            .with_context(|| format!("cargo metadata: {what} is not a string"))
    };
    let mut out = Vec::new();
    for p in v["packages"]
        .as_array()
        .context("cargo metadata has no packages")?
    {
        let name = str_of(&p["name"], "package name")?;
        let manifest = PathBuf::from(str_of(&p["manifest_path"], "manifest_path")?);
        let mut m = Member {
            dir: manifest
                .parent()
                .context("cargo metadata: manifest_path has no parent")?
                .to_path_buf(),
            ..Member::default()
        };
        for (feature, implied) in p["features"]
            .as_object()
            .with_context(|| format!("cargo metadata: {name} has no features table"))?
        {
            let implied = implied
                .as_array()
                .with_context(|| format!("cargo metadata: {name} feature {feature}"))?
                .iter()
                .map(|x| str_of(x, "feature value"))
                .collect::<Result<_>>()?;
            m.features.insert(feature.clone(), implied);
        }
        for d in p["dependencies"]
            .as_array()
            .with_context(|| format!("cargo metadata: {name} has no dependencies"))?
        {
            let dep_name = str_of(&d["name"], "dependency name")?;
            let key = match d["rename"].as_str() {
                Some(r) => r.to_owned(),
                None => dep_name.clone(),
            };
            m.deps.push(Dep {
                key,
                dev: d["kind"].as_str() == Some("dev"),
                features: d["features"]
                    .as_array()
                    .with_context(|| format!("cargo metadata: {name} dependency {dep_name}"))?
                    .iter()
                    .map(|x| str_of(x, "dependency feature"))
                    .collect::<Result<_>>()?,
                name: dep_name,
            });
        }
        for t in p["targets"]
            .as_array()
            .with_context(|| format!("cargo metadata: {name} has no targets"))?
        {
            let kinds = t["kind"]
                .as_array()
                .with_context(|| format!("cargo metadata: {name} target kind"))?;
            let is = |k: &str| kinds.iter().any(|x| x.as_str() == Some(k));
            if is("bin") {
                m.bin = true;
            }
            if is("custom-build") {
                m.build_scripts
                    .push(PathBuf::from(str_of(&t["src_path"], "src_path")?));
            }
        }
        m.name = name;
        out.push(m);
    }
    Ok(out)
}

/// Violations of rule 4f (and 4b's "no feature") in the members' manifests.
fn manifest_violations(members: &[Member]) -> Vec<String> {
    let mut out = Vec::new();
    for m in members {
        if m.name == BROKER && !m.features.is_empty() {
            let list: Vec<&str> = m.features.keys().map(String::as_str).collect();
            out.push(format!(
                "{BROKER} declares cargo features ({}); it may have none",
                list.join(", ")
            ));
        }
        if m.name == WIN {
            for (feature, implied) in &m.features {
                if feature != "write" && implied.iter().any(|x| x == "write") {
                    out.push(format!("purge-win feature `{feature}` turns on `write`"));
                }
            }
        }
        let win_keys: BTreeSet<&str> = m
            .deps
            .iter()
            .filter(|d| d.name == WIN)
            .map(|d| d.key.as_str())
            .collect();
        let (mut normal, mut dev) = (false, false);
        for d in m
            .deps
            .iter()
            .filter(|d| d.name == WIN && d.features.iter().any(|f| f == "write"))
        {
            if d.dev {
                dev = true;
            } else {
                normal = true;
            }
        }
        for implied in m.features.values().flatten() {
            if let Some((key, feature)) = implied.split_once('/')
                && feature == "write"
                && win_keys.contains(key.trim_end_matches('?'))
            {
                normal = true;
            }
        }
        if normal && !WRITE_ASKERS.contains(&m.name.as_str()) {
            out.push(format!(
                "{} asks for purge-win/write; only {} may",
                m.name,
                WRITE_ASKERS.join(" and ")
            ));
        }
        if dev && !WRITE_DEV_ASKERS.contains(&m.name.as_str()) {
            out.push(format!(
                "{} asks for purge-win/write as a dev-dependency; only {} may",
                m.name,
                WRITE_DEV_ASKERS.join(", ")
            ));
        }
    }
    out
}

/// Violations of rule 4f's cfg part: a member's build script that emits `rustc-cfg`, a workspace cargo
/// config (`<root>/.cargo/config[.toml]`) that passes `--cfg`. Either could turn on code behind
/// `#[cfg(feature = "...")]` without the feature in Cargo's graph.
fn cfg_violations(root: &Path, members: &[Member]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for m in members {
        for script in &m.build_scripts {
            let text = std::fs::read_to_string(script)
                .with_context(|| format!("reading {}", script.display()))?;
            if text.contains("rustc-cfg") {
                out.push(format!(
                    "{}'s build script {} emits rustc-cfg; no build script may set a cfg",
                    m.name,
                    script.strip_prefix(root).unwrap_or(script).display()
                ));
            }
        }
    }
    for name in ["config", "config.toml"] {
        let path = root.join(".cargo").join(name);
        if path.is_file() {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            if text.contains("--cfg") {
                out.push(format!(".cargo/{name} passes --cfg to rustc"));
            }
        }
    }
    Ok(out)
}

/// The privilege the broker enables, and only around undo's owner restore (B9). Built from two pieces
/// so that this file's own code does not name it (xtask is scanned like every member).
const RESTORE_PRIVILEGE: &str = concat!("SeRestore", "Privilege");
/// The middle of the windows-sys constants for it (`SE_RESTORE_NAME`).
const RESTORE_CONSTANT: &str = "RESTORE";
/// The APIs that enable a privilege on a token (rule 4e); built from pieces like
/// [`RESTORE_PRIVILEGE`].
pub const PRIVILEGE_APIS: [&str; 6] = [
    concat!("Adjust", "TokenPrivileges"),
    concat!("NtAdjust", "PrivilegesToken"),
    concat!("ZwAdjust", "PrivilegesToken"),
    concat!("RtlAdjust", "Privilege"),
    concat!("RtlAcquire", "Privilege"),
    concat!("RtlRelease", "Privilege"),
];
/// The one file that names the privilege and the adjusting APIs (purge-win's, M3-WIN-PRIV).
const PRIVILEGE_FILE: &str = "src/privilege.rs";
/// The attribute that makes an item of [`PRIVILEGE_FILE`] `write`-only.
const WRITE_GATE: &str = "#[cfg(feature = \"write\")]";
/// The scoped enabler: `pub(crate)`, write-gated, in [`PRIVILEGE_FILE`]; the only function that may
/// adjust a token.
const ENABLER: &str = "with_restore_privilege";
/// Where the enabler may be used: purge-win's file, the type, and exactly these methods of it, each
/// once (coordinator decision 2026-11-21, DECISIONS). `set_security` is the M2 use (an owner the token
/// may not assign, E1 SYSTEM-owned restores), `reopen_and_set_owner` the R8b M1 one.
const ENABLER_USERS: (&str, &str, [&str; 2]) = (
    "src/reg_write.rs",
    "CreatedKey",
    ["set_security", "reopen_and_set_owner"],
);
/// The enabler user with exactly one production caller, and where that caller must be.
const OWNER_RESTORE: &str = "reopen_and_set_owner";
/// The file of [`OWNER_RESTORE`]'s one caller (purge-exec's `set_recorded_security`).
const OWNER_RESTORE_CALLER: (&str, &str) = (EXEC, "src/act_service.rs");

/// The production code of one source file of a member (rule 4e).
struct Source {
    krate: String,
    /// Relative to the member's directory, `/`-separated (`src/reg_write.rs`).
    file: String,
    /// The file as written, by line.
    lines: Vec<String>,
    /// Comments removed, literals emptied, test items blanked; line breaks kept
    /// ([`baseline_sites::analyse`]).
    code: String,
    /// The offset in `code` where each line starts.
    starts: Vec<usize>,
    /// The string literals on production lines, as (offset of the line's first `"` in `code`, text).
    literals: Vec<(usize, String)>,
}

/// Whether the arguments of a `cfg(all(…))` name `test` as one of their own top-level arguments:
/// `all(test, feature = "x")` is test code, while `all(not(any(miri, test, doc)), feature = "x")` is
/// not (review M3-R1 S3: a plain `split(',')` read the nested `test` as an argument and blanked
/// production code). Parentheses nest; commas at depth 0 separate the arguments.
fn all_names_test(args: &str) -> bool {
    let mut depth = 0u32;
    let mut start = 0usize;
    for (i, ch) in args.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                if args[start..i].trim() == "test" {
                    return true;
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    args[start..].trim() == "test"
}

impl Source {
    /// The production view of `text`, and the out-of-line test modules it declares.
    fn new(krate: &str, file: &str, text: &str) -> (Source, Vec<String>) {
        // `#[cfg(all(test, …))]` is test code too (`baseline_sites::analyse` knows only
        // `#[cfg(test)]`); written as that, line for line. `any(test, …)` is not.
        let normalised: String = text
            .split_inclusive('\n')
            .map(|line| {
                let t = line.trim();
                let all_test = t
                    .strip_prefix("#[cfg(all(")
                    .and_then(|r| r.strip_suffix("))]"))
                    .is_some_and(all_names_test);
                if all_test {
                    let indent = &line[..line.len() - line.trim_start().len()];
                    let end = if line.ends_with("\r\n") {
                        "\r\n"
                    } else if line.ends_with('\n') {
                        "\n"
                    } else {
                        ""
                    };
                    format!("{indent}#[cfg(test)]{end}")
                } else {
                    line.to_owned()
                }
            })
            .collect();
        let (code, modules) = baseline_sites::analyse(&normalised);
        let mut starts = vec![0];
        starts.extend(code.match_indices('\n').map(|(i, _)| i + 1));
        let literals = lex::rust_literals(text)
            .into_iter()
            .filter_map(|lit| {
                let start = *starts.get(lit.line.checked_sub(1)?)?;
                let end = starts.get(lit.line).copied().unwrap_or(code.len());
                let quote = code[start..end].find('"')?;
                Some((start + quote, lit.text))
            })
            .collect();
        let source = Source {
            krate: krate.to_owned(),
            file: file.to_owned(),
            lines: text.lines().map(str::to_owned).collect(),
            code,
            starts,
            literals,
        };
        (source, modules)
    }

    /// The 0-based line of an offset in `code`.
    fn line_of(&self, at: usize) -> usize {
        self.starts.partition_point(|s| *s <= at).saturating_sub(1)
    }

    /// The line of an offset as written, trimmed.
    fn line_text(&self, at: usize) -> &str {
        self.lines.get(self.line_of(at)).map_or("", |l| l.trim())
    }

    /// Whether the item whose keyword (`fn`, `use`) is at `at` carries [`WRITE_GATE`] among the
    /// attribute and comment lines right above it.
    fn write_gated(&self, at: usize) -> bool {
        for line in self.lines[..self.line_of(at).min(self.lines.len())]
            .iter()
            .rev()
        {
            let t = line.trim();
            if t == WRITE_GATE {
                return true;
            }
            if !(t.starts_with("#[") || t.starts_with("//")) {
                return false;
            }
        }
        false
    }

    /// Whether this is purge-win's file `file`.
    fn is_win(&self, file: &str) -> bool {
        self.krate == WIN && self.file == file
    }
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

/// The production sources of every member's `src` ([`Source`]); files that are a `#[cfg(test)] mod x;`
/// as a whole are left out.
fn production_sources(members: &[Member]) -> Result<Vec<Source>> {
    let mut out = Vec::new();
    for m in members {
        let src = m.dir.join("src");
        if !src.is_dir() {
            continue;
        }
        let mut read = Vec::new();
        let mut test_files: Vec<String> = Vec::new();
        for (rel, path) in rust_files(&src)? {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let (source, modules) = Source::new(&m.name, &format!("src/{rel}"), &text);
            let (dir, stem) = match rel.rsplit_once('/') {
                Some((dir, name)) => (format!("{dir}/"), name),
                None => (String::new(), rel.as_str()),
            };
            // `a/b.rs` holds its modules in `a/b/`; `mod.rs`, `lib.rs` and `main.rs` beside themselves.
            let base = match stem.strip_suffix(".rs") {
                Some("mod" | "lib" | "main") | None => dir,
                Some(stem) => format!("{dir}{stem}/"),
            };
            for module in modules {
                test_files.push(format!("{base}{module}.rs"));
                test_files.push(format!("{base}{module}/"));
            }
            read.push((rel, source));
        }
        out.extend(
            read.into_iter()
                .filter(|(rel, _)| {
                    !test_files.iter().any(|t| match t.strip_suffix('/') {
                        Some(_) => rel.starts_with(t.as_str()),
                        None => rel == t,
                    })
                })
                .map(|(_, s)| s),
        );
    }
    Ok(out)
}

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c >= 0x80
}

/// The identifiers of `code` as (offset, text); numbers are left out.
fn idents(code: &str) -> Vec<(usize, &str)> {
    let b = code.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !is_ident_byte(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && is_ident_byte(b[i]) {
            i += 1;
        }
        if !b[start].is_ascii_digit() {
            out.push((start, &code[start..i]));
        }
    }
    out
}

/// A function with a body.
#[derive(Debug)]
struct FnSpan {
    name: String,
    /// The offset of the name in its definition.
    name_at: usize,
    /// From its `{` to its `}`.
    body: Range<usize>,
}

/// The functions with a body in `code` (`ids` is [`idents`] of it).
fn fn_spans(code: &str, ids: &[(usize, &str)]) -> Vec<FnSpan> {
    let b = code.as_bytes();
    let mut out = Vec::new();
    for (k, (at, word)) in ids.iter().enumerate() {
        if *word != "fn" {
            continue;
        }
        let Some((name_at, name)) = ids.get(k + 1) else {
            continue;
        };
        let gap = &code[at + 2..*name_at];
        if gap.is_empty() || !gap.chars().all(char::is_whitespace) {
            continue;
        }
        let mut depth = 0i32;
        let mut open = None;
        for (j, c) in b.iter().enumerate().skip(name_at + name.len()) {
            match c {
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth -= 1,
                b';' if depth <= 0 => break,
                b'{' if depth <= 0 => {
                    open = Some(j);
                    break;
                }
                _ => {}
            }
        }
        let Some(open) = open else { continue };
        let mut depth = 0usize;
        let mut close = b.len();
        for (j, c) in b.iter().enumerate().skip(open) {
            match c {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = j;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push(FnSpan {
            name: (*name).to_owned(),
            name_at: *name_at,
            body: open..close,
        });
    }
    out
}

/// The innermost function whose body holds `at`, as an index into `spans`.
fn enclosing(spans: &[FnSpan], at: usize) -> Option<usize> {
    spans
        .iter()
        .enumerate()
        .filter(|(_, s)| s.body.start < at && at < s.body.end)
        .min_by_key(|(_, s)| s.body.len())
        .map(|(i, _)| i)
}

/// Whether identifier `k` stands in a `use` declaration: a `use` comes before it with no `;` between.
fn in_use(code: &str, ids: &[(usize, &str)], k: usize) -> bool {
    let at = ids[k].0;
    ids[..k]
        .iter()
        .rev()
        .find(|(_, w)| *w == "use")
        .is_some_and(|(u, _)| !code[*u..at].contains(';'))
}

/// Whether identifier `k` is followed by `as` (an alias).
fn aliased(code: &str, ids: &[(usize, &str)], k: usize) -> bool {
    let end = ids[k].0 + ids[k].1.len();
    ids.get(k + 1)
        .is_some_and(|(next, w)| *w == "as" && code[end..*next].chars().all(char::is_whitespace))
}

/// A privilege name in a string: `Se<Letters>Privilege`.
fn is_privilege_name(text: &str) -> bool {
    text.strip_prefix("Se")
        .and_then(|t| t.strip_suffix("Privilege"))
        .is_some_and(|mid| !mid.is_empty() && mid.chars().all(|c| c.is_ascii_alphabetic()))
}

/// The middle of a privilege constant (`SE_RESTORE_NAME`, `SE_BACKUP_PRIVILEGE` give `RESTORE`,
/// `BACKUP`), or `None`.
fn privilege_constant(word: &str) -> Option<&str> {
    let t = word.strip_prefix("SE_")?;
    let mid = t
        .strip_suffix("_NAME")
        .or_else(|| t.strip_suffix("_PRIVILEGE"))?;
    (!mid.is_empty()
        && mid
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
    .then_some(mid)
}

/// The `impl` blocks of `code` as (self type, body); the type is the last identifier, outside `<…>`,
/// after `for` if there is one (`impl Deref for CreatedKey` and `impl CreatedKey` give `CreatedKey`).
fn impl_spans(code: &str, ids: &[(usize, &str)]) -> Vec<(String, Range<usize>)> {
    let b = code.as_bytes();
    let mut out = Vec::new();
    for (at, word) in ids {
        if *word != "impl" {
            continue;
        }
        // An item, not `impl Trait` in a type (`-> impl Fn()`, `x: impl Read`).
        let before = code[..*at].trim_end();
        let item = before.is_empty()
            || before.ends_with(['}', ';', ']', '{'])
            || before.ends_with("unsafe")
            || before.ends_with("default");
        if !item {
            continue;
        }
        let Some(open) = (at + 4..b.len()).find(|j| matches!(b[*j], b'{' | b';')) else {
            continue;
        };
        if b[open] == b';' {
            continue;
        }
        let header = &code[at + 4..open];
        let mut angle = 0i32;
        let mut top = String::new();
        let mut prev = ' ';
        for c in header.chars() {
            match c {
                '<' => angle += 1,
                '>' if prev != '-' => angle -= 1,
                _ if angle == 0 => top.push(c),
                _ => {}
            }
            prev = c;
        }
        let words: Vec<&str> = idents(&top).into_iter().map(|(_, w)| w).collect();
        let after_for = match words.iter().rposition(|w| *w == "for") {
            Some(i) => &words[i + 1..],
            None => &words[..],
        };
        let ty = after_for
            .iter()
            .take_while(|w| **w != "where")
            .last()
            .copied()
            .unwrap_or_default();
        let mut depth = 0usize;
        let mut close = b.len();
        for (j, c) in b.iter().enumerate().skip(open) {
            match c {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = j;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push((ty.to_owned(), open..close));
    }
    out
}

/// The offset of the `use` whose declaration holds identifier `k`, if one does.
fn use_at(code: &str, ids: &[(usize, &str)], k: usize) -> Option<usize> {
    in_use(code, ids, k)
        .then(|| {
            ids[..k]
                .iter()
                .rev()
                .find(|(_, w)| *w == "use")
                .map(|(u, _)| *u)
        })
        .flatten()
}

/// The identifiers, functions and impl blocks of one [`Source`].
struct Parsed<'a> {
    ids: Vec<(usize, &'a str)>,
    fns: Vec<FnSpan>,
    impls: Vec<(String, Range<usize>)>,
}

impl Parsed<'_> {
    /// `Type::method` (or `method`) of the innermost function around `at`, `(no function)` outside.
    fn place(&self, at: usize) -> String {
        let Some(f) = enclosing(&self.fns, at) else {
            return "(no function)".to_owned();
        };
        let name = &self.fns[f].name;
        match self.impl_of(at) {
            Some(ty) => format!("{ty}::{name}"),
            None => name.clone(),
        }
    }

    /// The self type of the innermost impl block around `at`.
    fn impl_of(&self, at: usize) -> Option<&str> {
        self.impls
            .iter()
            .filter(|(_, r)| r.start < at && at < r.end)
            .min_by_key(|(_, r)| r.len())
            .map(|(ty, _)| ty.as_str())
    }
}

/// Violations of rule 4e over the production sources of every member, and on success a line that names
/// where the privilege is named, enabled and used.
///
/// - `SeRestorePrivilege` (string or `SE_RESTORE_NAME`) is named in one function, of purge-win's
///   [`PRIVILEGE_FILE`] (the LUID lookup); no other privilege is named anywhere.
/// - The adjusting APIs ([`PRIVILEGE_APIS`]) are named only in [`PRIVILEGE_FILE`]: in the body of
///   [`ENABLER`] or in a plain `use` carrying [`WRITE_GATE`]. So the read-only queries of that file
///   (the LUID lookup, the state read-back) may use the lookup but adjust nothing.
/// - [`ENABLER`] is defined there, `pub(crate)` and write-gated. Besides plain `use`s in
///   [`ENABLER_USERS`]' file, it is referenced only in the methods [`ENABLER_USERS`] lists, once in
///   each of them.
/// - [`OWNER_RESTORE`] has exactly one production reference, in [`OWNER_RESTORE_CALLER`]. The callers
///   of `set_security` are not limited by this rule (the M2 use).
fn privilege_violations(sources: &[Source]) -> (Vec<String>, Option<String>) {
    let mut out = Vec::new();
    let parsed: Vec<Parsed<'_>> = sources
        .iter()
        .map(|s| {
            let ids = idents(&s.code);
            Parsed {
                fns: fn_spans(&s.code, &ids),
                impls: impl_spans(&s.code, &ids),
                ids,
            }
        })
        .collect();
    let at_place = |i: usize, at: usize| {
        format!(
            "{} {} {}",
            sources[i].krate,
            sources[i].file,
            parsed[i].place(at)
        )
    };

    // The privilege's name.
    let mut sites = Vec::new();
    for (i, s) in sources.iter().enumerate() {
        for (at, text) in &s.literals {
            if is_privilege_name(text) {
                if text == RESTORE_PRIVILEGE {
                    sites.push((i, *at));
                } else {
                    out.push(format!(
                        "{} {} names the privilege {text}; {RESTORE_PRIVILEGE} is the only one Purge \
                         may enable (B9)",
                        s.krate, s.file
                    ));
                }
            }
            for api in PRIVILEGE_APIS.iter().filter(|api| text.contains(*api)) {
                out.push(format!(
                    "{} {} has a string that names {api}",
                    s.krate, s.file
                ));
            }
        }
        for (at, word) in &parsed[i].ids {
            match privilege_constant(word) {
                Some(RESTORE_CONSTANT) => sites.push((i, *at)),
                Some(_) => out.push(format!(
                    "{} {} names the privilege constant {word}; {RESTORE_PRIVILEGE} is the only \
                     privilege Purge may enable (B9)",
                    s.krate, s.file
                )),
                None => {}
            }
        }
    }
    let mut owners = BTreeSet::new();
    for (i, at) in &sites {
        let s = &sources[*i];
        if !s.is_win(PRIVILEGE_FILE) {
            out.push(format!(
                "{} {} names {RESTORE_PRIVILEGE}; only purge-win {PRIVILEGE_FILE} may",
                s.krate, s.file
            ));
        } else if let Some(k) = enclosing(&parsed[*i].fns, *at) {
            owners.insert((*i, k));
        } else {
            out.push(format!(
                "{} {} names {RESTORE_PRIVILEGE} outside a function",
                s.krate, s.file
            ));
        }
    }
    let lookup = match owners.len() {
        0 => {
            if sites.is_empty() {
                out.push(format!(
                    "no function names {RESTORE_PRIVILEGE}; one function of purge-win {PRIVILEGE_FILE} \
                     must (the LUID lookup)"
                ));
            }
            None
        }
        1 => owners.first().map(|(i, k)| parsed[*i].fns[*k].name.clone()),
        n => {
            let all: Vec<String> = owners
                .iter()
                .map(|(i, k)| at_place(*i, parsed[*i].fns[*k].body.start + 1))
                .collect();
            out.push(format!(
                "{RESTORE_PRIVILEGE} is named in {n} functions ({}); only one may",
                all.join(", ")
            ));
            None
        }
    };

    // The enabler: defined once in the privilege file, pub(crate) and write-gated.
    let priv_file = sources.iter().position(|s| s.is_win(PRIVILEGE_FILE));
    let enabler = priv_file.and_then(|i| {
        parsed[i]
            .fns
            .iter()
            .position(|f| f.name == ENABLER)
            .map(|k| (i, k))
    });
    match enabler {
        None => out.push(format!(
            "purge-win {PRIVILEGE_FILE} has no fn {ENABLER} (the one function that may enable a privilege)"
        )),
        Some((i, k)) => {
            let s = &sources[i];
            let f = &parsed[i].fns[k];
            if !s
                .line_text(f.name_at)
                .starts_with(&format!("pub(crate) fn {ENABLER}"))
            {
                out.push(format!(
                    "purge-win {PRIVILEGE_FILE} {ENABLER} is not `pub(crate) fn`; it may not leave purge-win"
                ));
            }
            if !s.write_gated(f.name_at) {
                out.push(format!(
                    "purge-win {PRIVILEGE_FILE} {ENABLER} is not under {WRITE_GATE}"
                ));
            }
        }
    }

    // The adjusting APIs: in the enabler's body or a write-gated plain `use` of its file only.
    for (i, s) in sources.iter().enumerate() {
        let ids = &parsed[i].ids;
        for (k, (at, word)) in ids.iter().enumerate() {
            if !PRIVILEGE_APIS.contains(word) {
                continue;
            }
            let in_enabler =
                enabler.is_some_and(|(ei, ek)| ei == i && parsed[ei].fns[ek].body.contains(at));
            let gated_use = s.is_win(PRIVILEGE_FILE)
                && !aliased(&s.code, ids, k)
                && use_at(&s.code, ids, k).is_some_and(|u| s.write_gated(u));
            if !(in_enabler || gated_use) {
                out.push(format!(
                    "{} names {word}; only purge-win {PRIVILEGE_FILE} {ENABLER} (or a {WRITE_GATE} use \
                     of that file) may",
                    at_place(i, *at)
                ));
            }
        }
    }

    // The enabler's users, and the owner restore's one caller.
    let (users_file, users_type, users) = ENABLER_USERS;
    let mut uses: BTreeMap<&str, usize> = users.iter().map(|u| (*u, 0)).collect();
    let mut owner_restore_def = None;
    let mut owner_restore_refs = Vec::new();
    for (i, s) in sources.iter().enumerate() {
        let p = &parsed[i];
        for (k, (at, word)) in p.ids.iter().enumerate() {
            let is_enabler = *word == ENABLER;
            if !is_enabler && *word != OWNER_RESTORE {
                continue;
            }
            if is_enabler && enabler.is_some_and(|(ei, ek)| ei == i && p.fns[ek].name_at == *at) {
                continue;
            }
            let defines = p.fns.iter().any(|f| f.name_at == *at);
            if !is_enabler && defines {
                if s.is_win(users_file) && p.impl_of(*at) == Some(users_type) {
                    owner_restore_def = Some(i);
                    continue;
                }
                out.push(format!(
                    "{} defines another {OWNER_RESTORE}",
                    at_place(i, *at)
                ));
                continue;
            }
            if in_use(&s.code, p.ids.as_slice(), k) {
                if aliased(&s.code, &p.ids, k) {
                    out.push(format!(
                        "{} {} imports {word} under another name",
                        s.krate, s.file
                    ));
                } else if is_enabler && !s.is_win(users_file) {
                    out.push(format!(
                        "{} {} imports {ENABLER}; only purge-win {users_file} may",
                        s.krate, s.file
                    ));
                }
                continue;
            }
            if !is_enabler {
                owner_restore_refs.push((i, *at));
                continue;
            }
            let method = enclosing(&p.fns, *at).map(|f| p.fns[f].name.as_str());
            match method.and_then(|m| uses.get_mut(m)) {
                Some(n) if s.is_win(users_file) && p.impl_of(*at) == Some(users_type) => *n += 1,
                _ => out.push(format!(
                    "{} references {ENABLER}; only {} in purge-win {users_file} may",
                    at_place(i, *at),
                    users
                        .iter()
                        .map(|u| format!("{users_type}::{u}"))
                        .collect::<Vec<_>>()
                        .join(" and ")
                )),
            }
        }
    }
    for (user, n) in &uses {
        if *n != 1 {
            out.push(format!(
                "purge-win {users_file} {users_type}::{user} references {ENABLER} {n} times; the \
                 allowlist (ENABLER_USERS, DECISIONS) has it once"
            ));
        }
    }
    if owner_restore_def.is_none() {
        out.push(format!(
            "purge-win {users_file} has no {users_type}::{OWNER_RESTORE}"
        ));
    }
    let mut caller = None;
    match owner_restore_refs.as_slice() {
        [(i, at)]
            if sources[*i].krate == OWNER_RESTORE_CALLER.0
                && sources[*i].file == OWNER_RESTORE_CALLER.1 =>
        {
            caller = Some(at_place(*i, *at));
        }
        refs => {
            let all: Vec<String> = refs.iter().map(|(i, at)| at_place(*i, *at)).collect();
            out.push(format!(
                "{users_type}::{OWNER_RESTORE} has {} production references ({}); it must have exactly \
                 one, in {} {}",
                refs.len(),
                all.join(", "),
                OWNER_RESTORE_CALLER.0,
                OWNER_RESTORE_CALLER.1
            ));
        }
    }
    let summary = match (lookup, caller) {
        (Some(lookup), Some(caller)) if out.is_empty() => Some(format!(
            "{RESTORE_PRIVILEGE} is named only in purge-win {PRIVILEGE_FILE} {lookup}; tokens are \
             adjusted only in its write-gated pub(crate) {ENABLER}, used only by {} in {users_file}; \
             {users_type}::{OWNER_RESTORE} has one caller, {caller}",
            users
                .iter()
                .map(|u| format!("{users_type}::{u}"))
                .collect::<Vec<_>>()
                .join(" and ")
        )),
        _ => None,
    };
    (out, summary)
}

/// `cargo tree <args> -e <edges> --target all --prefix none` in `root`.
fn cargo_tree(root: &Path, args: &[&str], edges: &str) -> Result<String> {
    cargo_tree_for(root, args, edges, "all")
}

/// [`cargo_tree`] for one target.
fn cargo_tree_for(root: &Path, args: &[&str], edges: &str, target: &str) -> Result<String> {
    let output = crate::cargo()
        .arg("tree")
        .args(args)
        .args(["-e", edges, "--target", target, "--prefix", "none"])
        .current_dir(root)
        .output()
        .context("running cargo tree")?;
    if !output.status.success() {
        bail!(
            "cargo tree {} -e {edges} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).context("cargo tree output is not UTF-8")
}

/// `cargo metadata --no-deps` in `root`, parsed.
fn cargo_members(root: &Path) -> Result<Vec<Member>> {
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
    parse_members(&String::from_utf8(output.stdout).context("cargo metadata output is not UTF-8")?)
}

/// What the check found, and what it says on success.
struct Report {
    found: Vec<String>,
    ok: Vec<String>,
}

/// Normal and build edges.
const NORMAL: &str = "normal,build";
/// Normal, build and dev edges.
const WITH_DEV: &str = "normal,build,dev";

/// Rules 1 to 6 on the workspace at `root`.
fn check(root: &Path) -> Result<Report> {
    let tree = |args: &[&str], edges: &str| cargo_tree(root, args, edges);

    let own = tree(&["-p", MCP, "--all-features", "-f", "{p} {f}"], WITH_DEV)?;
    let mcp_names = names(&own);
    if mcp_names.first() != Some(&MCP) {
        bail!("unexpected cargo tree output (first package is not {MCP}):\n{own}");
    }
    let mut found = own_tree_violations(&own);

    let workspace = tree(&["--workspace", "--all-features", "-f", "{p}"], NORMAL)?;
    let forbidden = forbidden_in(&workspace);
    if !forbidden.contains(EXEC) || !forbidden.contains(WIN) {
        bail!("unexpected cargo tree output (purge-exec or purge-win missing):\n{workspace}");
    }
    let mut args = vec!["--workspace", "--all-features", "-f", "{p}"];
    for name in &forbidden {
        args.extend(["-i", name]);
    }
    found.extend(unified_violations(&tree(&args, NORMAL)?, &forbidden));

    let members = cargo_members(root)?;
    let engine = members
        .iter()
        .find(|m| m.name == ENGINE)
        .context("no purge-engine in the workspace")?;
    let no_rig: Vec<&str> = engine
        .features
        .keys()
        .map(String::as_str)
        .filter(|f| *f != RIG_EXEC)
        .collect();
    let no_rig = no_rig.join(",");
    let mut no_rig_args = vec!["-p", ENGINE, "-f", "{p} {f}"];
    if !no_rig.is_empty() {
        no_rig_args.extend(["--features", no_rig.as_str()]);
    }
    let dependents = [
        "--workspace",
        "--all-features",
        "-i",
        EXEC,
        "--depth",
        "1",
        "-f",
        "{p}",
    ];
    let release_engine = tree(&["-p", ENGINE, "-f", "{p} {f}"], NORMAL)?;
    found.extend(exec_violations(&ExecListings {
        dependents: &tree(&dependents, NORMAL)?,
        dev_dependents: &tree(&dependents, "dev")?,
        exec_tree: &tree(&["-p", EXEC, "--all-features", "-f", "{p}"], WITH_DEV)?,
        engine_no_rig: &tree(&no_rig_args, NORMAL)?,
        no_rig_features: &no_rig,
        engine_rig: &tree(
            &["-p", ENGINE, "--features", RIG_EXEC, "-f", "{p} {f}"],
            NORMAL,
        )?,
        engine_all: &tree(&["-p", ENGINE, "--all-features", "-f", "{p} {f}"], NORMAL)?,
    }));
    found.extend(broker_violations(
        &tree(&["-p", BROKER, "--all-features", "-f", "{p} {f}"], WITH_DEV)?,
        &release_engine,
    ));
    found.extend(release_violations(ENGINE, &release_engine));
    let mut bins = vec![ENGINE];
    for m in members
        .iter()
        .filter(|m| m.bin && m.name != BROKER && m.name != ENGINE)
    {
        bins.push(m.name.as_str());
        found.extend(release_violations(
            &m.name,
            &tree(&["-p", m.name.as_str(), "-f", "{p} {f}"], NORMAL)?,
        ));
    }
    found.extend(default_build_violations(
        &tree(&["--workspace", "-i", EXEC, "-f", "{p}"], NORMAL)?,
        &tree(&["--workspace", "-f", "{p} {f}"], NORMAL)?,
    ));
    found.extend(broker_dependents_violations(&tree(
        &["--workspace", "--all-features", "-i", BROKER, "-f", "{p}"],
        WITH_DEV,
    )?));
    let (privilege, privilege_ok) = privilege_violations(&production_sources(&members)?);
    found.extend(privilege);
    found.extend(manifest_violations(&members));
    found.extend(cfg_violations(root, &members)?);

    found.extend(win_source_violations(root)?);

    let shipped = |args: &[&str]| cargo_tree_for(root, args, WITH_DEV, SHIPPED_TARGET);
    let broker_shipped = shipped(&["-p", BROKER, "--all-features", "-f", "{p} {f}"])?;
    found.extend(broker_outside_violations(
        &broker_shipped,
        &shipped(&["--workspace", "--all-features", "-f", "{p} {f}"])?,
    ));
    let broker_outside = names(&broker_shipped)
        .into_iter()
        .filter(|n| !is_purge(n))
        .collect::<BTreeSet<_>>()
        .len();

    let ok = vec![
        format!(
            "{MCP} tree under any feature, dev-dependencies included, has {} packages, Purge crates \
             only {}; with unified workspace features it reaches none of {} other Purge crates",
            mcp_names.len(),
            ALLOWED.join(", "),
            forbidden.len()
        ),
        format!(
            "{EXEC} is linked only by {BROKER} and, with {RIG_EXEC}, {ENGINE} (fault-inject only \
             through {RIG_EXEC}, test-support only in {ENGINE}'s tests); {BROKER} has no feature, \
             builds {EXEC} with none and {ENGINE} as released, and nothing depends on it; the release \
             builds of {} have no {EXEC} and no purge-win/write",
            bins.join(", ")
        ),
        privilege_ok.unwrap_or_default(),
        format!(
            "only {} ask for purge-win/write; no build script or cargo config sets a cfg",
            WRITE_ASKERS.join(" and ")
        ),
        format!(
            "purge-win names none of {}, no `INetFwRules` removal, no {}",
            FORBIDDEN_WIN_IDENTS.join(", "),
            FORBIDDEN_WIN_WORDS.join(" or ")
        ),
        format!(
            "{BROKER} links {broker_outside} crates from outside the workspace for \
             {SHIPPED_TARGET}, each listed: {} it had before and {} the toolkit consent dialog \
             brings; {TOOLKIT} with {} only",
            BROKER_OUTSIDE.len(),
            BROKER_TOOLKIT.len(),
            TOOLKIT_FEATURES.join(" and ")
        ),
    ];
    Ok(Report { found, ok })
}

/// Runs the check; `Ok(false)` on a violation.
pub fn run(root: &Path) -> Result<bool> {
    let report = check(root)?;
    for v in &report.found {
        eprintln!("check-deps: {v}");
    }
    if report.found.is_empty() {
        for line in &report.ok {
            println!("check-deps: ok ({line})");
        }
    }
    Ok(report.found.is_empty())
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
    // Offline hives (BL-WIN-OFFREG): purge-win only opens, enumerates and closes them.
    "ORCreateHive",
    "ORCreateKey",
    "ORDeleteKey",
    "ORDeleteValue",
    "ORFlushHive",
    "ORMergeHives",
    "ORRenameKey",
    "ORSaveHive",
    "ORSetKeySecurity",
    "ORSetValue",
    "ORSetVirtualFlags",
    "RegLoadKey",
    "RegLoadAppKey",
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
            ("ORCreateHive(&mut h)", "ORCreateHive"),
            (
                "ORCreateKey(h, name, None, 0, None, &mut k, None)",
                "ORCreateKey",
            ),
            ("ORDeleteKey(h, name)", "ORDeleteKey"),
            ("ORDeleteValue(k, name)", "ORDeleteValue"),
            ("ORFlushHive(h)", "ORFlushHive"),
            ("ORMergeHives(hs, 2, &mut h)", "ORMergeHives"),
            ("ORRenameKey(k, name)", "ORRenameKey"),
            ("ORSaveHiveEx(h, path, 6, 1)", "ORSaveHive"),
            ("ORSetKeySecurity(k, 4, sd)", "ORSetKeySecurity"),
            ("ORSetValue(k, name, 1, data, n)", "ORSetValue"),
            ("ORSetVirtualFlags(k, 0)", "ORSetVirtualFlags"),
            ("RegLoadKeyW(HKEY_USERS, name, path)", "RegLoadKey"),
            (
                "RegLoadAppKeyW(path, &mut k, 0x20019, 0, 0)",
                "RegLoadAppKey",
            ),
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

    /// `name v0.1.0 (C:\x\name) features`, one line per (name, features).
    fn listing(lines: &[(&str, &str)]) -> String {
        lines
            .iter()
            .map(|(name, features)| format!("{name} v0.1.0 (C:\\x\\{name}) {features}\n"))
            .collect()
    }

    /// Rule 4a: clean listings pass; every way the executor gets linked elsewhere, or with the wrong
    /// features, is named.
    #[test]
    fn rule_4a_executor_only_in_the_broker_and_the_rig_engine() {
        let deps = listing(&[(EXEC, ""), (BROKER, ""), (ENGINE, "")]);
        let dev = listing(&[(EXEC, ""), (ENGINE, "")]);
        let exec_tree = listing(&[(EXEC, ""), (WIN, "read,write"), ("purge-model", "")]);
        let no_rig = listing(&[(ENGINE, "inject-view"), (WIN, "read")]);
        let rig = listing(&[(ENGINE, "rig-exec"), (EXEC, "fault-inject")]);
        let all = listing(&[(ENGINE, "inject-view,rig-exec"), (EXEC, "fault-inject")]);
        let clean = ExecListings {
            dependents: &deps,
            dev_dependents: &dev,
            exec_tree: &exec_tree,
            engine_no_rig: &no_rig,
            no_rig_features: "inject-view",
            engine_rig: &rig,
            engine_all: &all,
        };
        assert_eq!(exec_violations(&clean), Vec::<String>::new());

        let other = listing(&[(EXEC, ""), (BROKER, ""), ("purge-new", ""), (MCP, "")]);
        assert_eq!(
            exec_violations(&ExecListings {
                dependents: &other,
                ..clean
            }),
            [
                "purge-mcp depends on purge-exec; only purge-broker, and purge-engine with rig-exec, may",
                "purge-new depends on purge-exec; only purge-broker, and purge-engine with rig-exec, may",
            ]
        );
        let no_broker = listing(&[(EXEC, ""), (ENGINE, "")]);
        assert_eq!(
            exec_violations(&ExecListings {
                dependents: &no_broker,
                ..clean
            }),
            [
                "purge-broker does not depend on purge-exec (it is the release binary that links the executor)"
            ]
        );
        let dev_other = listing(&[(EXEC, ""), (ENGINE, ""), ("xtask", ""), (BROKER, "")]);
        assert_eq!(
            exec_violations(&ExecListings {
                dev_dependents: &dev_other,
                ..clean
            }),
            [
                "purge-broker has purge-exec as a dev-dependency; only purge-engine's tests may",
                "xtask has purge-exec as a dev-dependency; only purge-engine's tests may",
            ]
        );
        let reaches = listing(&[(EXEC, ""), (ENGINE, ""), (MCP, ""), (ENGINE, "(*)")]);
        assert_eq!(
            exec_violations(&ExecListings {
                exec_tree: &reaches,
                ..clean
            }),
            [
                "purge-exec reaches purge-engine (under some feature, or as a dev-dependency)",
                "purge-exec reaches purge-mcp (under some feature, or as a dev-dependency)",
            ]
        );
        let linked = listing(&[(ENGINE, "inject-view"), (EXEC, ""), (WIN, "read,write")]);
        assert_eq!(
            exec_violations(&ExecListings {
                engine_no_rig: &linked,
                ..clean
            }),
            [
                "purge-engine links purge-exec without feature rig-exec (with features inject-view)",
                "purge-engine builds purge-win with feature `write` without rig-exec (with features inject-view)",
            ]
        );
        let test_support = listing(&[(ENGINE, "rig-exec"), (EXEC, "test-support")]);
        assert_eq!(
            exec_violations(&ExecListings {
                engine_rig: &test_support,
                ..clean
            }),
            [
                "purge-engine with feature rig-exec builds purge-exec without fault-inject",
                "purge-engine with feature rig-exec builds purge-exec with test-support",
            ]
        );
        assert_eq!(
            exec_violations(&ExecListings {
                engine_rig: &no_rig,
                ..clean
            }),
            ["purge-engine with feature rig-exec does not link purge-exec"]
        );
        let all_bad = listing(&[(ENGINE, ""), (EXEC, "fault-inject,test-support")]);
        assert_eq!(
            exec_violations(&ExecListings {
                engine_all: &all_bad,
                ..clean
            }),
            [
                "purge-engine builds purge-exec with test-support under some feature (only its tests may)"
            ]
        );
        let garbage = "error: nothing\n";
        assert_eq!(
            exec_violations(&ExecListings {
                dependents: garbage,
                dev_dependents: garbage,
                exec_tree: garbage,
                engine_no_rig: garbage,
                no_rig_features: "",
                engine_rig: garbage,
                engine_all: garbage,
            })
            .len(),
            6,
            "every unrecognised listing is named"
        );
    }

    /// Rule 6: the broker links from outside only what the two lists name, the toolkit from its
    /// pinned repository and with the window host and accessibility only.
    #[test]
    fn rule_6_the_broker_links_only_the_listed_outside_crates() {
        let line = |name: &str, source: &str, features: &str| {
            format!("{name} v0.1.0 {source}{features}\n")
        };
        let toolkit_source = "(https://github.com/Kaan88/markdown-shared-rs?rev=294d330#294d330a) ";
        let mut clean = line(BROKER, "(C:\\x\\purge-broker) ", "");
        clean += &line("purge-win", "(C:\\x\\purge-win) ", "read,write");
        for name in BROKER_OUTSIDE.iter().chain(BROKER_TOOLKIT) {
            let (source, features) = match *name {
                "mdshared-ui" => (toolkit_source, "a11y,host"),
                n if n.starts_with("mdshared-") => (toolkit_source, ""),
                _ => ("", ""),
            };
            clean += &line(name, source, features);
        }
        assert_eq!(
            broker_outside_violations(&clean, &clean),
            Vec::<String>::new()
        );
        // The lists do not overlap, and name nothing twice.
        let all: Vec<&str> = BROKER_OUTSIDE
            .iter()
            .chain(BROKER_TOOLKIT)
            .copied()
            .collect();
        let unique: BTreeSet<&str> = all.iter().copied().collect();
        assert_eq!(all.len(), unique.len());

        // A crate nobody listed, once however often the tree repeats it.
        let more = format!(
            "{clean}{}{}",
            line("reqwest", "", ""),
            line("reqwest", "", "(*)")
        );
        assert_eq!(
            broker_outside_violations(&more, &clean),
            [
                "reqwest is in purge-broker's dependency tree and in neither list of rule 6: the \
                 elevated binary links only what is listed, with the reason written down"
            ]
        );
        // The toolkit from somewhere else: a path, a registry, another repository.
        let moved = clean.replace(
            &line("mdshared-text", toolkit_source, ""),
            &line("mdshared-text", "(C:\\src\\mdshared-text) ", ""),
        );
        assert_eq!(
            broker_outside_violations(&moved, &clean),
            [
                "mdshared-text in purge-broker's tree does not come from the toolkit's repository \
                 at a pinned revision"
            ]
        );
        // A feature beyond the window host and accessibility, in the broker's tree or switched on
        // by another member of a workspace build.
        let recycle = clean.replace("a11y,host", "a11y,host,recycle");
        assert_eq!(
            broker_outside_violations(&recycle, &clean),
            [
                "purge-broker builds mdshared-ui with feature recycle; the broker links it with \
                 a11y and host only"
            ]
        );
        assert_eq!(
            broker_outside_violations(&clean, &recycle),
            [
                "a workspace build builds mdshared-ui with feature recycle; the broker links it \
                 with a11y and host only"
            ]
        );
        // A listing of something else is not read as clean.
        assert_eq!(
            broker_outside_violations(&line(ENGINE, "", ""), &clean).len(),
            1
        );
    }

    /// Rule 4b: the broker builds the executor with no feature and the engine as released.
    #[test]
    fn rule_4b_broker_has_no_rig_features() {
        let release = listing(&[(ENGINE, ""), (WIN, "appx,read,run")]);
        let broker = listing(&[
            (BROKER, ""),
            (ENGINE, ""),
            (EXEC, ""),
            (WIN, "appx,com,read,run,write"),
            (EXEC, "(*)"),
        ]);
        assert_eq!(broker_violations(&broker, &release), Vec::<String>::new());
        let rig = listing(&[
            (BROKER, ""),
            (ENGINE, "inject-view,rig-exec"),
            (EXEC, "fault-inject"),
        ]);
        assert_eq!(
            broker_violations(&rig, &release),
            [
                "purge-broker builds purge-exec with feature fault-inject; it takes purge-exec with no feature",
                "purge-broker builds purge-engine with feature inject-view, which the release engine does not have",
                "purge-broker builds purge-engine with feature rig-exec, which the release engine does not have",
            ]
        );
        // A dev-dependency's feature shows on the same line (cargo tree -e dev unifies it).
        let dev = listing(&[(BROKER, ""), (EXEC, "test-support"), (ENGINE, "")]);
        assert_eq!(
            broker_violations(&dev, &release),
            [
                "purge-broker builds purge-exec with feature test-support; it takes purge-exec with no feature"
            ]
        );
        // A release engine with a default feature: the broker may have it too.
        let release_default = listing(&[(ENGINE, "default,fast")]);
        let broker_default = listing(&[(BROKER, ""), (ENGINE, "default,fast"), (EXEC, "")]);
        assert!(broker_violations(&broker_default, &release_default).is_empty());
        let without = listing(&[(BROKER, ""), (ENGINE, "")]);
        assert_eq!(
            broker_violations(&without, &release),
            ["purge-broker does not link purge-exec"]
        );
        assert_eq!(broker_violations("", &release).len(), 1);
    }

    /// Rule 4c: release builds of the other binaries, and the default workspace build.
    #[test]
    fn rule_4c_release_builds_have_no_executor_and_no_write() {
        let engine = listing(&[(ENGINE, ""), (WIN, "appx,read,run")]);
        assert!(release_violations(ENGINE, &engine).is_empty());
        let bad = listing(&[(ENGINE, ""), (EXEC, ""), (WIN, "read,write")]);
        assert_eq!(
            release_violations(ENGINE, &bad),
            [
                "purge-engine's release build links purge-exec; only purge-broker's may",
                "purge-engine's release build has purge-win with feature `write`; only purge-broker's may",
            ]
        );
        assert_eq!(release_violations(MCP, &engine).len(), 1, "wrong root");

        let none = listing(&[(EXEC, ""), (BROKER, "")]);
        let ws = listing(&[(ENGINE, ""), (EXEC, ""), (EXEC, "(*)")]);
        assert!(default_build_violations(&none, &ws).is_empty());
        let linked = listing(&[
            (EXEC, ""),
            (BROKER, ""),
            (ENGINE, ""),
            ("xtask", ""),
            (BROKER, "(*)"),
        ]);
        assert_eq!(
            default_build_violations(&linked, &ws),
            [
                "a default workspace build links purge-exec into purge-engine",
                "a default workspace build links purge-exec into xtask",
            ]
        );
        let ws_bad = listing(&[(EXEC, "fault-inject"), (EXEC, "test-support (*)")]);
        assert_eq!(
            default_build_violations(&none, &ws_bad),
            [
                "a default workspace build turns on purge-exec feature fault-inject",
                "a default workspace build turns on purge-exec feature test-support",
            ]
        );
        assert_eq!(default_build_violations("", &ws).len(), 1);
    }

    /// Rule 4d: nothing depends on the broker.
    #[test]
    fn rule_4d_nothing_depends_on_the_broker() {
        assert!(broker_dependents_violations(&listing(&[(BROKER, "")])).is_empty());
        assert_eq!(
            broker_dependents_violations(&listing(&[(BROKER, ""), ("purge-tool", "")])),
            [
                "purge-tool depends on purge-broker; nothing may (under any feature, as any kind of dependency)"
            ]
        );
        assert_eq!(broker_dependents_violations("").len(), 1);
    }

    /// A member with `deps` as (package, dev, features) and `features` as (name, implied).
    fn member(name: &str, deps: &[(&str, bool, &[&str])], features: &[(&str, &[&str])]) -> Member {
        Member {
            name: name.to_owned(),
            features: features
                .iter()
                .map(|(f, implied)| {
                    (
                        (*f).to_owned(),
                        implied.iter().map(|s| (*s).to_owned()).collect(),
                    )
                })
                .collect(),
            deps: deps
                .iter()
                .map(|(dep, dev, features)| Dep {
                    name: (*dep).to_owned(),
                    key: (*dep).to_owned(),
                    dev: *dev,
                    features: features.iter().map(|s| (*s).to_owned()).collect(),
                })
                .collect(),
            ..Member::default()
        }
    }

    /// Rule 4f (manifests) and 4b's "no feature".
    #[test]
    fn rule_4f_only_the_executor_and_the_broker_ask_for_write() {
        let clean = [
            member(
                WIN,
                &[],
                &[
                    ("default", &["read"]),
                    ("read", &[]),
                    ("write", &["read"]),
                    ("run", &["read"]),
                ],
            ),
            member(
                EXEC,
                &[(WIN, false, &["write", "appx"])],
                &[("fault-inject", &[])],
            ),
            member(BROKER, &[(WIN, false, &["write"]), (EXEC, false, &[])], &[]),
            member(
                ENGINE,
                &[(WIN, false, &["read"]), (WIN, true, &["read", "write"])],
                &[("rig-exec", &["dep:purge-exec", "purge-exec/fault-inject"])],
            ),
        ];
        assert_eq!(manifest_violations(&clean), Vec::<String>::new());
        let bad = [
            member(
                WIN,
                &[],
                &[("write", &["read"]), ("turbo", &["run", "write"])],
            ),
            member(BROKER, &[], &[("extra", &[])]),
            member("purge-scan", &[(WIN, true, &["write"])], &[]),
            member(
                ENGINE,
                &[(WIN, false, &["read"])],
                &[("fast", &["purge-win/write"])],
            ),
            member(MCP, &[(WIN, false, &[])], &[("w", &["purge-win?/write"])]),
            member("purge-new", &[(WIN, false, &["read", "write"])], &[]),
        ];
        assert_eq!(
            manifest_violations(&bad),
            [
                "purge-win feature `turbo` turns on `write`",
                "purge-broker declares cargo features (extra); it may have none",
                "purge-scan asks for purge-win/write as a dev-dependency; only purge-exec, purge-broker, purge-engine may",
                "purge-engine asks for purge-win/write; only purge-exec and purge-broker may",
                "purge-mcp asks for purge-win/write; only purge-exec and purge-broker may",
                "purge-new asks for purge-win/write; only purge-exec and purge-broker may",
            ]
        );
        // A renamed dependency is found by its key.
        let mut renamed = member("purge-x", &[(WIN, false, &[])], &[("f", &["win/write"])]);
        renamed.deps[0].key = "win".to_owned();
        assert_eq!(manifest_violations(&[renamed]).len(), 1);
    }

    /// The production sources of `files` as (crate, file, text).
    fn sources(files: &[(&str, &str, &str)]) -> Vec<Source> {
        files
            .iter()
            .map(|(krate, file, text)| Source::new(krate, file, text).0)
            .collect()
    }

    /// purge-win `src/privilege.rs` in the M3-WIN-PRIV shape.
    const WIN_PRIV: &str = "#[cfg(feature = \"write\")]\n\
        use windows_sys::Win32::Security::{AdjustTokenPrivileges, DuplicateTokenEx};\n\
        use windows_sys::Win32::Security::{GetTokenInformation, LookupPrivilegeValueW};\n\
        // SeRestorePrivilege, AdjustTokenPrivileges and with_restore_privilege() in a comment.\n\
        /// The LUID of `SeRestorePrivilege`.\n\
        fn restore_luid() -> Result<LUID, u32> {\n\
            let name = wide(\"SeRestorePrivilege\");\n\
            unsafe { LookupPrivilegeValueW(null(), name.as_ptr(), &mut l) };\n\
            Ok(l)\n\
        }\n\
        pub fn restore_privilege_enabled() -> Result<bool, u32> {\n\
            let luid = restore_luid()?;\n\
            unsafe { GetTokenInformation(t, 3, b, n, &mut n) };\n\
            Ok(true)\n\
        }\n\
        /// Runs `f` with the privilege on.\n\
        #[cfg(feature = \"write\")]\n\
        pub(crate) fn with_restore_privilege<T>(f: impl FnOnce() -> T) -> Result<T, u32> {\n\
            let p = TOKEN_PRIVILEGES { Luid: restore_luid()?, Attributes: 2 };\n\
            if unsafe { AdjustTokenPrivileges(t, 0, &p, 0, null(), null()) } == 0 { return Err(1); }\n\
            Ok(f())\n\
        }\n\
        #[cfg(all(test, feature = \"write\"))]\n\
        mod tests {\n\
            fn t() { super::with_restore_privilege(|| ()); let _ = \"SeBackupPrivilege\"; }\n\
        }\n";
    /// purge-win `src/reg_write.rs`: the two users of the enabler.
    const WIN_REG: &str = "use crate::privilege::with_restore_privilege;\n\
        impl Deref for CreatedKey { fn deref(&self) -> &WKey { &self.0 } }\n\
        impl CreatedKey {\n\
            pub fn set_security(&self, sddl: &str) -> Result<(), u32> {\n\
                let set = || nt(self.0);\n\
                match set() { Err(1307) => with_restore_privilege(set).unwrap_or(Err(1307)), o => o }\n\
            }\n\
            pub fn reopen_and_set_owner(&self, owner: &str) -> Result<(), u32> {\n\
                with_restore_privilege(|| self.reopen(owner)).and_then(|r| r)\n\
            }\n\
        }\n\
        #[cfg(test)]\n\
        mod tests {\n\
            fn t(k: &CreatedKey) { k.reopen_and_set_owner(\"O:SY\").unwrap(); }\n\
        }\n";
    /// purge-exec `src/act_service.rs`: the one owner-restore caller, and set_security used freely.
    const EXEC_CALL: &str = "fn set_recorded_security(key: &CreatedKey, sddl: &str, owner: &str) {\n\
            let _ = key.set_security(sddl);\n\
            if key.set_security(owner).is_err() && key.reopen_and_set_owner(owner).is_err() { note(); }\n\
        }\n\
        fn other(key: &CreatedKey) { let _ = key.set_security(\"D:\"); }\n";

    /// Rule 4e's production view: `#[cfg(all(test, …))]` is test code, but a `test` nested inside
    /// `not(any(…))` is not a top-level argument and must not blank the item (review M3-R1 S3).
    #[test]
    fn cfg_all_test_is_only_test_code_at_the_top_level() {
        let prod = "#[cfg(all(not(any(miri, test, doc)), feature = \"write\"))]\nfn f() {}\n";
        let (source, _) = Source::new(WIN, "src/x.rs", prod);
        assert!(source.code.contains("fn f"), "{}", source.code);
        let test = "#[cfg(all(test, feature = \"write\"))]\nfn t() {}\n";
        let (source, _) = Source::new(WIN, "src/x.rs", test);
        assert!(!source.code.contains("fn t"), "{}", source.code);
        let single = "#[cfg(all(test))]\nfn t() {}\n";
        let (source, _) = Source::new(WIN, "src/x.rs", single);
        assert!(!source.code.contains("fn t"), "{}", source.code);
    }

    /// Rule 4e as the coordinator stated it for the M3-WIN-PRIV shape: the name and the adjusting APIs
    /// only in purge-win's privilege.rs (the APIs write-gated, in the enabler); the enabler
    /// `pub(crate)` and used only by the two allowlisted methods, once each; `reopen_and_set_owner`
    /// with one caller, in purge-exec's act_service.rs. Comments and test items do not count.
    #[test]
    fn rule_4e_privilege_named_enabled_and_used_only_where_allowed() {
        let win = (WIN, "src/privilege.rs", WIN_PRIV);
        let reg = (WIN, "src/reg_write.rs", WIN_REG);
        let exec = (EXEC, "src/act_service.rs", EXEC_CALL);
        let (found, ok) = privilege_violations(&sources(&[win, reg, exec]));
        assert_eq!(found, Vec::<String>::new());
        assert_eq!(
            ok.unwrap(),
            "SeRestorePrivilege is named only in purge-win src/privilege.rs restore_luid; tokens are \
             adjusted only in its write-gated pub(crate) with_restore_privilege, used only by \
             CreatedKey::set_security and CreatedKey::reopen_and_set_owner in src/reg_write.rs; \
             CreatedKey::reopen_and_set_owner has one caller, purge-exec src/act_service.rs \
             set_recorded_security"
        );
        let check = |files: &[(&str, &str, &str)]| privilege_violations(&sources(files)).0;

        // reopen_and_set_owner: a second caller, a caller elsewhere, none.
        let second = format!(
            "{EXEC_CALL}fn again(k: &CreatedKey) {{ k.reopen_and_set_owner(\"O:SY\").ok(); }}\n"
        );
        assert_eq!(
            check(&[win, reg, (EXEC, "src/act_service.rs", &second)]),
            [
                "CreatedKey::reopen_and_set_owner has 2 production references (purge-exec src/act_service.rs \
              set_recorded_security, purge-exec src/act_service.rs again); it must have exactly one, in \
              purge-exec src/act_service.rs"
            ]
        );
        let broker = "fn run(k: &CreatedKey) { k.reopen_and_set_owner(\"O:SY\").ok(); }\n";
        assert_eq!(
            check(&[win, reg, exec, (BROKER, "src/start.rs", broker)]).len(),
            1
        );
        let moved = EXEC_CALL.replace("&& key.reopen_and_set_owner(owner).is_err()", "");
        assert_eq!(
            check(&[
                win,
                reg,
                (EXEC, "src/act_service.rs", &moved),
                (EXEC, "src/regbackup.rs", broker)
            ]),
            [
                "CreatedKey::reopen_and_set_owner has 1 production references (purge-exec src/regbackup.rs \
              run); it must have exactly one, in purge-exec src/act_service.rs"
            ]
        );

        // The enabler: another user in reg_write.rs, in another file, a re-export, an alias, a second
        // use inside an allowlisted method, its visibility and gate.
        let third = format!(
            "{WIN_REG}impl WKey {{ pub fn take_owner(&self) {{ with_restore_privilege(|| ()).ok(); }} }}\n"
        );
        assert_eq!(
            check(&[win, (WIN, "src/reg_write.rs", &third), exec]),
            [
                "purge-win src/reg_write.rs WKey::take_owner references with_restore_privilege; only \
              CreatedKey::set_security and CreatedKey::reopen_and_set_owner in purge-win src/reg_write.rs \
              may"
            ]
        );
        let fs = "use crate::privilege::with_restore_privilege;\n\
                  impl MoveHandle { pub fn set_security(&self) { with_restore_privilege(|| ()).ok(); } }\n";
        assert_eq!(
            check(&[win, reg, exec, (WIN, "src/fs_write.rs", fs)]),
            [
                "purge-win src/fs_write.rs imports with_restore_privilege; only purge-win src/reg_write.rs may",
                "purge-win src/fs_write.rs MoveHandle::set_security references with_restore_privilege; only \
                 CreatedKey::set_security and CreatedKey::reopen_and_set_owner in purge-win src/reg_write.rs \
                 may",
            ]
        );
        let reexport = "pub use privilege::with_restore_privilege;\n";
        assert_eq!(
            check(&[win, reg, exec, (WIN, "src/lib.rs", reexport)]),
            [
                "purge-win src/lib.rs imports with_restore_privilege; only purge-win src/reg_write.rs may"
            ]
        );
        let alias = WIN_REG.replace(
            "with_restore_privilege;\n",
            "with_restore_privilege as elevate;\n",
        );
        assert!(
            check(&[win, (WIN, "src/reg_write.rs", &alias), exec]).contains(
                &"purge-win src/reg_write.rs imports with_restore_privilege under another name"
                    .to_owned()
            )
        );
        let twice = WIN_REG.replace(
            "with_restore_privilege(|| self.reopen(owner))",
            "with_restore_privilege(|| ()).ok(); with_restore_privilege(|| self.reopen(owner))",
        );
        assert_eq!(
            check(&[win, (WIN, "src/reg_write.rs", &twice), exec]),
            [
                "purge-win src/reg_write.rs CreatedKey::reopen_and_set_owner references with_restore_privilege \
              2 times; the allowlist (ENABLER_USERS, DECISIONS) has it once"
            ]
        );
        let public = WIN_PRIV.replace(
            "pub(crate) fn with_restore_privilege",
            "pub fn with_restore_privilege",
        );
        assert_eq!(
            check(&[(WIN, "src/privilege.rs", &public), reg, exec]),
            [
                "purge-win src/privilege.rs with_restore_privilege is not `pub(crate) fn`; it may not leave \
              purge-win"
            ]
        );
        let ungated = WIN_PRIV.replace(
            "#[cfg(feature = \"write\")]\npub(crate) fn",
            "pub(crate) fn",
        );
        assert_eq!(
            check(&[(WIN, "src/privilege.rs", &ungated), reg, exec]),
            [
                "purge-win src/privilege.rs with_restore_privilege is not under #[cfg(feature = \"write\")]"
            ]
        );

        // The adjusting APIs: in a read-only query, in an ungated use, in another file, by string.
        let query = WIN_PRIV.replace(
            "let luid = restore_luid()?;",
            "let luid = restore_luid()?; unsafe { AdjustTokenPrivileges(t, 1, p, 0, n, n) };",
        );
        assert_eq!(
            check(&[(WIN, "src/privilege.rs", &query), reg, exec]),
            [
                "purge-win src/privilege.rs restore_privilege_enabled names AdjustTokenPrivileges; only \
              purge-win src/privilege.rs with_restore_privilege (or a #[cfg(feature = \"write\")] use of \
              that file) may"
            ]
        );
        let ungated_use = WIN_PRIV.replacen("#[cfg(feature = \"write\")]\n", "", 1);
        assert_eq!(
            check(&[(WIN, "src/privilege.rs", &ungated_use), reg, exec]).len(),
            1
        );
        let elsewhere = "use windows_sys::Win32::Security::AdjustTokenPrivileges;\n\
                         extern \"system\" { fn RtlAdjustPrivilege(p: u32, e: u8, t: u8, w: *mut u8) -> i32; }\n\
                         fn g() { let p = GetProcAddress(h, s!(\"NtAdjustPrivilegesToken\")); }\n";
        assert_eq!(
            check(&[win, reg, exec, (EXEC, "src/y.rs", elsewhere)]),
            [
                "purge-exec src/y.rs has a string that names NtAdjustPrivilegesToken",
                "purge-exec src/y.rs (no function) names AdjustTokenPrivileges; only purge-win \
                 src/privilege.rs with_restore_privilege (or a #[cfg(feature = \"write\")] use of that file) \
                 may",
                "purge-exec src/y.rs (no function) names RtlAdjustPrivilege; only purge-win \
                 src/privilege.rs with_restore_privilege (or a #[cfg(feature = \"write\")] use of that file) \
                 may",
            ]
        );

        let ntdll = "extern \"system\" { fn RtlAcquirePrivilege(p: u32, n: u32, t: u8, w: *mut u8) -> i32; \
                     fn RtlReleasePrivilege(p: u32) -> i32; }\n";
        assert_eq!(
            check(&[win, reg, exec, (EXEC, "src/z.rs", ntdll)]),
            [
                "purge-exec src/z.rs (no function) names RtlAcquirePrivilege; only purge-win \
                 src/privilege.rs with_restore_privilege (or a #[cfg(feature = \"write\")] use of that file) \
                 may",
                "purge-exec src/z.rs (no function) names RtlReleasePrivilege; only purge-win \
                 src/privilege.rs with_restore_privilege (or a #[cfg(feature = \"write\")] use of that file) \
                 may",
            ]
        );

        // The name: in another file, in a second function, outside a function, missing; other
        // privileges.
        let in_reg = format!("{WIN_REG}fn probe() {{ let _ = w!(\"SeRestorePrivilege\"); }}\n");
        assert_eq!(
            check(&[win, (WIN, "src/reg_write.rs", &in_reg), exec]),
            [
                "purge-win src/reg_write.rs names SeRestorePrivilege; only purge-win src/privilege.rs may"
            ]
        );
        let two = format!("{WIN_PRIV}fn other() {{ let _ = SE_RESTORE_NAME; }}\n");
        assert_eq!(
            check(&[(WIN, "src/privilege.rs", &two), reg, exec]),
            [
                "SeRestorePrivilege is named in 2 functions (purge-win src/privilege.rs restore_luid, purge-win \
              src/privilege.rs other); only one may"
            ]
        );
        let outside = format!("{WIN_PRIV}const NAME: &str = \"SeRestorePrivilege\";\n");
        assert_eq!(
            check(&[(WIN, "src/privilege.rs", &outside), reg, exec]),
            ["purge-win src/privilege.rs names SeRestorePrivilege outside a function"]
        );
        let unnamed = WIN_PRIV.replace("wide(\"SeRestorePrivilege\")", "wide(\"x\")");
        assert_eq!(
            check(&[(WIN, "src/privilege.rs", &unnamed), reg, exec]),
            [
                "no function names SeRestorePrivilege; one function of purge-win src/privilege.rs must (the \
              LUID lookup)"
            ]
        );
        let backup = "fn f() { let _ = \"SeBackupPrivilege\"; let _ = SE_DEBUG_NAME; }\n";
        assert_eq!(
            check(&[win, reg, exec, (WIN, "src/token.rs", backup)]),
            [
                "purge-win src/token.rs names the privilege SeBackupPrivilege; SeRestorePrivilege is the only \
                 one Purge may enable (B9)",
                "purge-win src/token.rs names the privilege constant SE_DEBUG_NAME; SeRestorePrivilege is the \
                 only privilege Purge may enable (B9)",
            ]
        );
        assert_eq!(
            check(&[reg, exec]).len(),
            2,
            "no privilege file: no name, no enabler"
        );
    }

    /// Rule 4e on the real tree: it passes, and names the owner restore's one caller.
    #[test]
    fn rule_4e_holds_on_the_workspace() {
        let members = cargo_members(&crate::workspace_root()).unwrap();
        let (found, ok) = privilege_violations(&production_sources(&members).unwrap());
        assert_eq!(found, Vec::<String>::new());
        assert!(
            ok.unwrap()
                .ends_with("has one caller, purge-exec src/act_service.rs set_recorded_security")
        );
    }

    /// A scratch Cargo workspace with the crates rule 4 names, removed on drop.
    struct FixtureWorkspace(std::path::PathBuf);

    impl FixtureWorkspace {
        /// Members `purge-mcp`, `purge-win`, `purge-exec`, `purge-engine` and `purge-broker` as the real
        /// ones relate (`engine_extra` is added to the engine's `[features]`), plus `purge-other` with
        /// `other_deps`. The engine, the broker and purge-mcp have a binary; purge-win's privilege
        /// files and purge-exec's owner-restore caller have the M3-WIN-PRIV shape.
        fn new(tag: &str, engine_extra: &str, other_deps: &str) -> FixtureWorkspace {
            let root =
                std::env::temp_dir().join(format!("purge-xtask-deps-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let krate = |name: &str, manifest: &str, lib: &str, bin: bool| {
                let dir = root.join(name);
                std::fs::create_dir_all(dir.join("src")).unwrap();
                std::fs::write(dir.join("src").join("lib.rs"), lib).unwrap();
                if bin {
                    std::fs::write(dir.join("src").join("main.rs"), "fn main() {}\n").unwrap();
                }
                std::fs::write(
                    dir.join("Cargo.toml"),
                    format!(
                        "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n{manifest}"
                    ),
                )
                .unwrap();
            };
            krate("purge-mcp", "", "", true);
            krate(
                "purge-win",
                "[features]\ndefault = [\"read\"]\nread = []\nwrite = [\"read\"]\n",
                "mod privilege;\npub mod reg_write;\n",
                false,
            );
            krate(
                "purge-exec",
                "[features]\nfault-inject = []\ntest-support = []\n\
                 [dependencies]\npurge-win = { path = \"../purge-win\", features = [\"write\"] }\n",
                "mod act_service;\n",
                false,
            );
            for (file, text) in [
                ("purge-win/src/privilege.rs", WIN_PRIV),
                ("purge-win/src/reg_write.rs", WIN_REG),
                ("purge-exec/src/act_service.rs", EXEC_CALL),
            ] {
                std::fs::write(root.join(file), text).unwrap();
            }
            krate(
                "purge-engine",
                &format!(
                    "[features]\nrig-exec = [\"dep:purge-exec\", \"purge-exec/fault-inject\"]\n\
                     inject-view = []\n{engine_extra}\n\
                     [dependencies]\npurge-win = {{ path = \"../purge-win\", features = [\"read\"] }}\n\
                     purge-exec = {{ path = \"../purge-exec\", optional = true }}\n\
                     [dev-dependencies]\npurge-exec = {{ path = \"../purge-exec\", features = [\"test-support\"] }}\n"
                ),
                "",
                true,
            );
            krate(
                "purge-broker",
                "[dependencies]\npurge-engine = { path = \"../purge-engine\" }\n\
                 purge-exec = { path = \"../purge-exec\" }\n\
                 purge-win = { path = \"../purge-win\", features = [\"write\"] }\n",
                "",
                true,
            );
            krate(
                "purge-other",
                &format!("[dependencies]\n{other_deps}\n"),
                "",
                false,
            );
            std::fs::write(
                root.join("Cargo.toml"),
                "[workspace]\nresolver = \"2\"\nmembers = [\"purge-mcp\", \"purge-win\", \"purge-exec\", \
                 \"purge-engine\", \"purge-broker\", \"purge-other\"]\n",
            )
            .unwrap();
            FixtureWorkspace(root)
        }

        /// Replaces `from` (which must be there) with `to` in the file at `rel`.
        fn edit(&self, rel: &str, from: &str, to: &str) {
            let path = self.0.join(rel);
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(text.contains(from), "{rel} has no {from:?}");
            std::fs::write(&path, text.replacen(from, to, 1)).unwrap();
        }

        /// Appends `text` to the file at `rel`.
        fn append(&self, rel: &str, text: &str) {
            let path = self.0.join(rel);
            let old = std::fs::read_to_string(&path).unwrap_or_default();
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).unwrap();
            }
            std::fs::write(&path, format!("{old}{text}")).unwrap();
        }

        /// The violations of every rule, each also printed.
        fn found(&self) -> Vec<String> {
            let found = check(&self.0).unwrap().found;
            for v in &found {
                eprintln!("{}: {v}", self.0.display());
            }
            found
        }
    }

    impl Drop for FixtureWorkspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Asserts that each of `wanted` is a violation in `found`.
    fn assert_has(found: &[String], wanted: &[&str]) {
        for w in wanted {
            assert!(found.iter().any(|f| f == w), "missing {w:?} in {found:#?}");
        }
    }

    /// Rule 4 on real manifests: the clean fixture passes; an engine feature that another member (a
    /// binary) switches on links the executor (review M2 M22); an engine that asks for
    /// `purge-win/write`.
    #[test]
    fn rule_4_fails_on_broken_manifests() {
        let clean = FixtureWorkspace::new("clean", "", "");
        // Link arguments are not a cfg: the broker's manifest embedding and a later
        // `/DEPENDENTLOADFLAG:0x800` (M3-HARDEN) stay allowed by rule 4f.
        clean.append(
            "purge-broker/build.rs",
            "fn main() {\n    println!(\"cargo:rustc-link-arg-bins=/MANIFEST:EMBED\");\n    \
             println!(\"cargo::rustc-link-arg=/DEPENDENTLOADFLAG:0x800\");\n}\n",
        );
        assert_eq!(clean.found(), Vec::<String>::new());
        assert!(run(&clean.0).unwrap());

        let unified = FixtureWorkspace::new(
            "unified",
            "exec-core = [\"dep:purge-exec\"]",
            "purge-engine = { path = \"../purge-engine\", features = [\"exec-core\"] }",
        );
        unified.append("purge-other/src/main.rs", "fn main() {}\n");
        let found = unified.found();
        assert_has(
            &found,
            &[
                "a default workspace build links purge-exec into purge-engine",
                "a default workspace build links purge-exec into purge-other",
                "purge-engine links purge-exec without feature rig-exec (with features exec-core,inject-view)",
                "purge-other's release build links purge-exec; only purge-broker's may",
                "purge-other's release build has purge-win with feature `write`; only purge-broker's may",
            ],
        );
        assert!(!run(&unified.0).unwrap());

        let write = FixtureWorkspace::new("write", "", "");
        write.edit(
            "purge-engine/Cargo.toml",
            "features = [\"read\"]",
            "features = [\"read\", \"write\"]",
        );
        assert_has(
            &write.found(),
            &[
                "purge-engine's release build has purge-win with feature `write`; only purge-broker's may",
                "purge-engine asks for purge-win/write; only purge-exec and purge-broker may",
            ],
        );
    }

    /// Rule 4 against M3-R1 ("break check-deps with a feature or a dev-dependency"): the broker
    /// switching on the engine's rig feature, dev-dependencies on the executor and on the broker, the
    /// executor reaching the engine or purge-mcp, purge-mcp reaching purge-win through a feature of its
    /// own, a broker feature, a purge-win feature that implies `write`, and a cfg set outside Cargo's
    /// graph.
    #[test]
    fn rule_4_fails_on_features_and_dev_dependencies() {
        let rig = FixtureWorkspace::new("broker-rig", "", "");
        rig.edit(
            "purge-broker/Cargo.toml",
            "purge-engine = { path = \"../purge-engine\" }",
            "purge-engine = { path = \"../purge-engine\", features = [\"rig-exec\"] }",
        );
        assert_has(
            &rig.found(),
            &[
                "purge-broker builds purge-exec with feature fault-inject; it takes purge-exec with no feature",
                "purge-broker builds purge-engine with feature rig-exec, which the release engine does not have",
                "a default workspace build links purge-exec into purge-engine",
                "a default workspace build turns on purge-exec feature fault-inject",
            ],
        );

        let dev = FixtureWorkspace::new("dev-edges", "", "");
        dev.append(
            "purge-broker/Cargo.toml",
            "[dev-dependencies]\npurge-exec = { path = \"../purge-exec\", features = [\"test-support\"] }\n",
        );
        dev.append(
            "purge-other/Cargo.toml",
            "[dev-dependencies]\npurge-broker = { path = \"../purge-broker\" }\n\
             purge-exec = { path = \"../purge-exec\" }\n",
        );
        assert_has(
            &dev.found(),
            &[
                "purge-broker builds purge-exec with feature test-support; it takes purge-exec with no feature",
                "purge-broker has purge-exec as a dev-dependency; only purge-engine's tests may",
                "purge-other has purge-exec as a dev-dependency; only purge-engine's tests may",
                "purge-other depends on purge-broker; nothing may (under any feature, as any kind of dependency)",
            ],
        );

        let reach = FixtureWorkspace::new("exec-reach", "", "");
        reach.edit(
            "purge-exec/Cargo.toml",
            "[dependencies]\n",
            "[dependencies]\npurge-mcp = { path = \"../purge-mcp\", optional = true }\n",
        );
        reach.append(
            "purge-exec/Cargo.toml",
            "[dev-dependencies]\npurge-engine = { path = \"../purge-engine\" }\n",
        );
        assert_has(
            &reach.found(),
            &[
                "purge-exec reaches purge-engine (under some feature, or as a dev-dependency)",
                "purge-exec reaches purge-mcp (under some feature, or as a dev-dependency)",
            ],
        );

        let features = FixtureWorkspace::new("features", "", "");
        features.append(
            "purge-mcp/Cargo.toml",
            "[features]\nlocal = [\"dep:purge-win\"]\n\
             [dependencies]\npurge-win = { path = \"../purge-win\", optional = true }\n",
        );
        features.append("purge-broker/Cargo.toml", "[features]\nextra = []\n");
        features.edit(
            "purge-win/Cargo.toml",
            "write = [\"read\"]\n",
            "write = [\"read\"]\nturbo = [\"write\"]\n",
        );
        features.append(
            "purge-exec/build.rs",
            "fn main() { println!(\"cargo::rustc-cfg=feature=\\\"test-support\\\"\"); }\n",
        );
        features.append(
            ".cargo/config.toml",
            "[build]\nrustflags = [\"--cfg\", \"feature=\\\"fault-inject\\\"\"]\n",
        );
        let found = features.found();
        assert_has(
            &found,
            &[
                "purge-win is in purge-mcp's dependency tree; only purge-model and purge-rpc are allowed",
                "purge-broker declares cargo features (extra); it may have none",
                "purge-win feature `turbo` turns on `write`",
                ".cargo/config.toml passes --cfg to rustc",
            ],
        );
        assert!(
            found
                .iter()
                .any(|f| f.starts_with("purge-exec's build script")
                    && f.ends_with("emits rustc-cfg; no build script may set a cfg")),
            "{found:#?}"
        );
    }
}
