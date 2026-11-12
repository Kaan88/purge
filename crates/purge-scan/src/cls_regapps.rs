//! CLS-REGAPPS (ENGINE_PLAN.md §5.6): `RegisteredApplications` values, `Capabilities` keys and
//! `Clients\{StartMenuInternet,Mail}\<name>`.
//!
//! # What is looked at
//!
//! Per hive (`HKLM\SOFTWARE` and each user's `HKU\<SID>\Software`):
//!
//! - every key directly under `Clients\StartMenuInternet` and `Clients\Mail`;
//! - every value of `RegisteredApplications`, and the `Capabilities` key its data names (a path below
//!   the hive root, e.g. `Software\Clients\StartMenuInternet\Firefox-<hash>\Capabilities`).
//!
//! # What is offered
//!
//! - **A client key** (`DeleteKey`) "by P / command / token": a harvested token in its name
//!   (`Firefox-<hash>`), a `command` below it that launches a file of the app (Tier A `ChainedRef` to the
//!   file), or `Capabilities` associations that name a ProgID of the set P (Tier A `ChainedRef` to the
//!   ProgID), plus an Inno key-create record or a proven skeleton where they hold. Never when a `command`
//!   below it launches something else: `Clients\Mail\Mozilla Thunderbird` is not Firefox's. Values only
//!   when the key itself may not be offered (no matching baseline, a client Windows ships).
//! - **A `RegisteredApplications` value** (`DeleteValue`; the key is a structural value container) when
//!   the value is in the reference snapshot or the Inno log, carries a harvested token in its name, or
//!   its `Capabilities` key is the app's: a value there points into an InstallRoot or at a file of the
//!   exe set, or an association there names a ProgID of P (`ChainedRef`, §5.3 "Capabilities → owned
//!   ProgIDs"). A `Capabilities` key that lies inside another app's own key proves nothing.
//! - **The `Capabilities` key** itself (`DeleteKey`) under the same conditions, when the registered path
//!   really ends in `Capabilities`. When it lies inside an offered client key it is recorded as that
//!   candidate's child.
//!
//! The 32-bit view is not scanned separately: `WOW6432Node\Clients` and
//! `WOW6432Node\RegisteredApplications` are links to the keys read here.

use purge_guard::prefix::{self, Relation};
use purge_model::{Action, Blocker, Candidate, Category, Target, Tier};

use crate::cls_progid::classes::{self, KeyScan};
use crate::framework::{AppIdentityView, CandidateBuilder, RootSpec, ScanCtx, Scanner};

/// The scanner's catalog id.
pub const ID: &str = "CLS-REGAPPS";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[
    RootSpec::reg(r"*\SOFTWARE\RegisteredApplications", Some(0)),
    RootSpec::reg(r"*\SOFTWARE", None),
    RootSpec::reg(r"*\SOFTWARE\Clients\StartMenuInternet", None),
    RootSpec::reg(r"*\SOFTWARE\Clients\Mail", None),
];

/// The keys the scanner reads single values from (entries of
/// `purge_guard::containers::VALUE_CONTAINERS`).
const VALUE_CONTAINERS: &[&str] = &[r"*\SOFTWARE\RegisteredApplications"];

/// The client categories under `Clients` whose entries are scanned.
const CLIENT_KINDS: &[&str] = &["StartMenuInternet", "Mail"];

/// The name of the key an app describes its associations in.
const CAPABILITIES: &str = "Capabilities";

/// The CLS-REGAPPS scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClsRegApps;

impl Scanner for ClsRegApps {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn value_containers(&self) -> &[&'static str] {
        VALUE_CONTAINERS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, app: &AppIdentityView) -> Vec<Candidate> {
        let mut out = Vec::new();
        for (hive, software) in classes::software_roots(ctx) {
            // Client keys stay open until the hive is done: a Capabilities key found through
            // RegisteredApplications may still become a child of one.
            let mut clients: Vec<CandidateBuilder<'_>> = Vec::new();
            // Client keys that launch something else: what lies inside them is that program's.
            let mut foreign: Vec<String> = Vec::new();
            for kind in CLIENT_KINDS {
                let Some(base) = classes::existing_path(ctx, &software, &["Clients", kind]) else {
                    continue;
                };
                let names = ctx.reg.subkeys(&base).unwrap_or_default();
                if names.len() > ctx.limits.max_key_children {
                    continue;
                }
                for name in names {
                    let Some(scan) = KeyScan::read(ctx, app, &format!("{base}\\{name}")) else {
                        continue;
                    };
                    let offer = if scan.foreign_command() {
                        foreign.push(scan.key.clone());
                        None
                    } else {
                        let chain = app_chain(ctx, &scan);
                        classes::key_candidate(ctx, ID, &scan, Category::Registration, chain)
                    };
                    match offer {
                        Some(builder) => clients.push(builder),
                        None => out.extend(classes::value_candidates(
                            ctx,
                            ID,
                            &scan,
                            Category::Registration,
                        )),
                    }
                }
            }
            if let Some(registered) =
                classes::existing_child(ctx, &software, "RegisteredApplications")
            {
                scan_registered(
                    ctx,
                    app,
                    (&hive, &registered),
                    &foreign,
                    &mut clients,
                    &mut out,
                );
            }
            out.extend(clients.into_iter().map(CandidateBuilder::build));
        }
        out
    }
}

/// What a client or `Capabilities` subtree refers to that the app owns: the file a command launches, a
/// path into an InstallRoot or to a file of the exe set, or a ProgID of the set P.
fn app_chain<'s>(ctx: &'s ScanCtx<'_>, scan: &'s KeyScan) -> Option<(Tier, &'s str)> {
    scan.launch()
        .or_else(|| scan.app_ref())
        .or_else(|| scan.names_one_of(&ctx.fp.anchors.progids))
        .map(|anchor| (Tier::A, anchor))
}

/// The values of one `RegisteredApplications` key (`registered`, in the hive `hive`) and the
/// `Capabilities` keys they name. `foreign` are the client keys of the hive that launch something else.
fn scan_registered<'c>(
    ctx: &'c ScanCtx<'_>,
    app: &AppIdentityView,
    (hive, registered): (&str, &str),
    foreign: &[String],
    clients: &mut [CandidateBuilder<'c>],
    out: &mut Vec<Candidate>,
) {
    let values = ctx.reg.values(registered).unwrap_or_default();
    if values.len() > ctx.limits.max_key_children {
        return;
    }
    let mut offered_keys: Vec<String> = Vec::new();
    for value in values {
        if value.name.is_empty() {
            continue;
        }
        let capabilities = value
            .data
            .string()
            .and_then(|data| capabilities_key(ctx, hive, &data));
        // Another app's own key is that app's, even when it mentions this one; so is what lies inside a
        // client key whose command launches something else.
        let scan = capabilities
            .filter(|key| {
                !ctx.other_apps
                    .key_blockers(key)
                    .iter()
                    .any(|b| matches!(b, Blocker::InsideOtherApp { .. }))
                    && !foreign.iter().any(|client| {
                        matches!(
                            ctx.key_relation(key, client),
                            Relation::Same | Relation::Inside
                        )
                    })
            })
            .and_then(|key| KeyScan::read(ctx, app, &key));
        let chain = scan.as_ref().and_then(|scan| app_chain(ctx, scan));

        let target = Target::RegValue {
            path: registered.to_owned(),
            name: value.name.clone(),
        };
        let mut builder = ctx.candidate(ID, target, Action::DeleteValue, Category::Registration);
        builder.installer_manifest();
        builder.in_ref_snapshot();
        for token in &ctx.fp.tokens {
            builder.harvested_token(&token.token);
        }
        if let Some((tier, anchor)) = chain {
            builder.chained_ref(tier, anchor);
        }
        if builder.has_tier_ab_evidence() {
            builder.common_blockers();
            out.push(builder.build());
        }

        // The Capabilities key itself, once, and only when it is named as one.
        let (Some(scan), Some(chain)) = (&scan, chain) else {
            continue;
        };
        let is_capabilities =
            prefix::leaf(&scan.key).is_some_and(|leaf| leaf.eq_ignore_ascii_case(CAPABILITIES));
        if !is_capabilities || offered_keys.iter().any(|k| ctx.same_key(k, &scan.key)) {
            continue;
        }
        let Some(builder) =
            classes::key_candidate(ctx, ID, scan, Category::Registration, Some(chain))
        else {
            continue;
        };
        let candidate = builder.build();
        for client in clients.iter_mut() {
            let inside = matches!(client.target(), Target::RegKey { path }
                if ctx.key_relation(&scan.key, path) == Relation::Inside);
            if inside {
                client.child(candidate.id.clone());
            }
        }
        offered_keys.push(scan.key.clone());
        out.push(candidate);
    }
}

/// The key a `RegisteredApplications` value names: a path below the hive root that starts with
/// `Software` and is at least three segments long. `None` when the data is not such a path or the key
/// does not exist.
fn capabilities_key(ctx: &ScanCtx<'_>, hive: &str, data: &str) -> Option<String> {
    let segs: Vec<&str> = prefix::segments(data.trim()).collect();
    if segs.len() < 3 || !segs[0].eq_ignore_ascii_case("Software") || segs.contains(&"..") {
        return None;
    }
    let spelled = format!("{hive}\\{}", segs.join("\\"));
    // A user's `Software\Classes\…` is physically `HKU\<SID>_Classes\…`.
    let physical = classes::physical(&spelled);
    if physical != spelled {
        return ctx
            .reg
            .key_exists(&physical)
            .is_present()
            .then_some(physical);
    }
    classes::existing_path(ctx, hive, &segs)
        .or_else(|| ctx.reg.key_exists(&spelled).is_present().then_some(spelled))
}
