//! rigtool: the Purge VM rig's capture, truth and scoring tool. Contract: `vm\RIG.md`.

mod ambient;
mod baseline;
mod canon;
#[cfg(windows)]
mod capture;
mod convert;
mod deep;
mod deny;
mod diff;
mod err;
mod escape;
mod execdiff;
mod fidelity;
mod invdiff;
mod items;
mod jsonio;
mod score;
mod snap;
mod target;
mod traps;
#[cfg(test)]
mod testutil;
mod truth;

use err::{Context, Result, bail};
use std::path::PathBuf;

const USAGE: &str = "\
rigtool - Purge VM rig tool (contract: vm\\RIG.md)

  rigtool snap [--root SPEC]... [--no-values] [--threads N] -o FILE.tsv.gz
  rigtool diff A.tsv.gz B.tsv.gz [--json]
  rigtool truth --s0 F --s1 F --s2 F --lists0 F --lists2 F --run run.json
                [--ambient ambient.json] [--labels labels.json...] [--deny deny.json] [--sid SID] -o truth.json
  rigtool ambient --null DIR... -o ambient.json
  rigtool ambient --m2 --null DIR... -o m2-ambient.json   (M2: removed/changed records of null runs)
  rigtool score --set APPDIR... [--deny deny.json] [--sid SID] [--classes] --json out.json --md out.md
  rigtool score --plan plan.json [--plan ...] --truth truth.json --s0 F --s2 F [--lists0 F]
                [--deny deny.json] [--sid SID] [--classes] --json out.json --md out.md
                (--classes: reporting classes blocking / unticked / preexisting_value_ref / old_empty_ext_key;
                 --lists0: lists whose packages, tasks, services and firewall rules count as pre-existing;
                 --set reads <dir>/lists-*-0.json)
  rigtool convert (--clone FILE | --removed FILE --tool ut|bcu) --app ID -o plan.json
  rigtool baseline --snap snap-0.tsv.gz -o FILE.tsv.gz|DIR\\
  rigtool invdiff --inv inventory.json --lists lists-<run>-<phase>.json [--explain inventory-explain.json]
                  [--sid SID] [--json out.json] [--md out.md]     (exit 1 = unexplained differences)
  rigtool deep --scope FILE... [--sid SID] -o deep.json
                (FILE: purge.rig.deepscope/0, purge.rig.targets/0 or an m2-traps / m2-fixtures manifest)
  rigtool fidelity --before A.json --after C.json --journal journal.jsonl [--ambient ambient.json]
                   [--sid SID] [--keep-items ID...] -o fidelity.json
                   (exit 1 = a differing object or an unverifiable row; --keep-items: ops of these items were
                   left quarantined on purpose, reported as row 'kept quarantined', not compared)
  rigtool execdiff --before A.tsv.gz --after B.tsv.gz --journal journal.jsonl --report report.json
                   [--traps m2-traps.json [m2-fixtures.json]...] [--group main ...] [--ambient ambient.json]
                   [--deep-before A.json --deep-after B.json] [--sid SID] -o execdiff.json
                (exit 1 = a guard escape, collateral, a missing effect, a trap outcome mismatch,
                 an unverified canary or a report/journal inconsistency)
";

struct Args {
    pos: Vec<String>,
    flags: Vec<(String, Vec<String>)>,
}

impl Args {
    fn parse(argv: &[String], bools: &[&str], multis: &[&str], singles: &[&str]) -> Result<Args> {
        let mut a = Args { pos: Vec::new(), flags: Vec::new() };
        let is_flag = |s: &str| s.starts_with("--") || s == "-o";
        let mut i = 0;
        while i < argv.len() {
            let raw = &argv[i];
            i += 1;
            if !is_flag(raw) {
                a.pos.push(raw.clone());
                continue;
            }
            let (name, inline) = match raw.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (raw.clone(), None),
            };
            if bools.contains(&name.as_str()) {
                a.flags.push((name, vec![]));
            } else if multis.contains(&name.as_str()) {
                let mut v: Vec<String> = inline.into_iter().collect();
                while i < argv.len() && !is_flag(&argv[i]) {
                    v.push(argv[i].clone());
                    i += 1;
                }
                if v.is_empty() {
                    bail!("{name} needs at least one value");
                }
                a.flags.push((name, v));
            } else if singles.contains(&name.as_str()) {
                let v = match inline {
                    Some(v) => v,
                    None => {
                        let v = argv.get(i).cloned().with_context(|| format!("{name} needs a value"))?;
                        i += 1;
                        v
                    }
                };
                a.flags.push((name, vec![v]));
            } else {
                bail!("unknown option {name}\n\n{USAGE}");
            }
        }
        Ok(a)
    }
    fn has(&self, n: &str) -> bool {
        self.flags.iter().any(|(k, _)| k == n)
    }
    fn all(&self, n: &str) -> Vec<String> {
        self.flags.iter().filter(|(k, _)| k == n).flat_map(|(_, v)| v.iter().cloned()).collect()
    }
    fn get(&self, n: &str) -> Option<String> {
        self.all(n).pop()
    }
    fn path(&self, n: &str) -> Option<PathBuf> {
        self.get(n).map(PathBuf::from)
    }
    fn req(&self, n: &str) -> Result<PathBuf> {
        self.path(n).with_context(|| format!("missing {n}\n\n{USAGE}"))
    }
}

#[cfg(windows)]
fn cmd_snap(a: &Args) -> Result<()> {
    let out = a.req("-o")?;
    let specs = a.all("--root");
    let (roots, excludes) = if specs.is_empty() {
        capture::default_roots()
    } else {
        let sid = capture::current_user_sid();
        (specs.iter().map(|s| snap::RootSpec::parse(s, sid.as_deref())).collect(), Vec::new())
    };
    let threads = match a.get("--threads") {
        Some(t) => t.parse().context("--threads")?,
        None => std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(16),
    };
    let opts = capture::SnapOpts { roots, excludes, values: !a.has("--no-values"), threads };
    let st = capture::run_snap(&opts, &out)?;
    let codes = st.errors_by_code.iter().map(|(c, n)| format!("{c}:{n}")).collect::<Vec<_>>().join(" ");
    eprintln!(
        "snap: {} records, {} errors (win32 code:count {}), {:.1} s, {} roots -> {}",
        st.records,
        st.errors,
        if codes.is_empty() { "-".to_string() } else { codes },
        st.seconds,
        opts.roots.len(),
        out.display()
    );
    Ok(())
}

#[cfg(not(windows))]
fn cmd_snap(_: &Args) -> Result<()> {
    bail!("snap runs on Windows only")
}

fn run(argv: Vec<String>) -> Result<()> {
    let Some(cmd) = argv.first().cloned() else {
        print!("{USAGE}");
        return Ok(());
    };
    let rest = &argv[1..];
    match cmd.as_str() {
        "snap" => cmd_snap(&Args::parse(rest, &["--no-values"], &[], &["--root", "-o", "--threads"])?),
        "diff" => {
            let a = Args::parse(rest, &["--json"], &[], &[])?;
            if a.pos.len() != 2 {
                bail!("diff needs two snap files\n\n{USAGE}");
            }
            diff::cmd_diff(&PathBuf::from(&a.pos[0]), &PathBuf::from(&a.pos[1]), a.has("--json"))
        }
        "truth" => {
            let a = Args::parse(
                rest,
                &[],
                &["--labels"],
                &["--s0", "--s1", "--s2", "--lists0", "--lists2", "--run", "--ambient", "--deny", "--sid", "-o"],
            )?;
            truth::cmd_truth(&truth::TruthArgs {
                s0: a.req("--s0")?,
                s1: a.path("--s1"),
                s2: a.req("--s2")?,
                // Required: kept_owner anchors come from lists-2 minus lists-0 and run.json's entries_left.
                lists0: Some(a.req("--lists0")?),
                lists2: Some(a.req("--lists2")?),
                run: Some(a.req("--run")?),
                ambient: a.path("--ambient"),
                labels: a.all("--labels").into_iter().map(PathBuf::from).collect(),
                deny: a.path("--deny"),
                sid: a.get("--sid"),
                out: a.req("-o")?,
            })
        }
        "ambient" => {
            let a = Args::parse(rest, &["--m2"], &["--null"], &["-o"])?;
            let dirs: Vec<PathBuf> = a.all("--null").into_iter().map(PathBuf::from).collect();
            if dirs.is_empty() {
                bail!("ambient needs --null DIR...");
            }
            if a.has("--m2") {
                ambient::cmd_ambient_m2(&dirs, &a.req("-o")?)
            } else {
                ambient::cmd_ambient(&dirs, &a.req("-o")?)
            }
        }
        "score" => {
            let a = Args::parse(
                rest,
                &["--classes"],
                &["--set"],
                &["--plan", "--truth", "--s0", "--s2", "--deny", "--sid", "--json", "--md", "--lists0"],
            )?;
            score::cmd_score(&score::ScoreArgs {
                set: a.all("--set").into_iter().map(PathBuf::from).collect(),
                plans: a.all("--plan").into_iter().map(PathBuf::from).collect(),
                truth: a.path("--truth"),
                s0: a.path("--s0"),
                s2: a.path("--s2"),
                deny: a.path("--deny"),
                sid: a.get("--sid"),
                json: a.path("--json"),
                md: a.path("--md"),
                lists0: a.path("--lists0"),
                classes: a.has("--classes"),
            })
        }
        "convert" => {
            let a = Args::parse(rest, &[], &[], &["--clone", "--removed", "--tool", "--app", "-o"])?;
            let app = a.get("--app").context("convert needs --app ID")?;
            convert::cmd_convert(
                a.path("--clone").as_deref(),
                a.path("--removed").as_deref(),
                a.get("--tool").as_deref(),
                &app,
                &a.req("-o")?,
            )
        }
        "baseline" => {
            let a = Args::parse(rest, &[], &[], &["--snap", "-o"])?;
            baseline::cmd_baseline(&a.req("--snap")?, &a.req("-o")?)
        }
        "invdiff" => {
            let a = Args::parse(rest, &[], &[], &["--inv", "--lists", "--explain", "--sid", "--json", "--md"])?;
            let rep = invdiff::cmd_invdiff(&invdiff::InvdiffArgs {
                inv: a.req("--inv")?,
                lists: a.req("--lists")?,
                explain: a.path("--explain"),
                sid: a.get("--sid"),
                json: a.path("--json"),
                md: a.path("--md"),
            })?;
            if rep.exit_code() != 0 {
                bail!("invdiff: {} unexplained differences", rep.unexplained());
            }
            Ok(())
        }
        "deep" => {
            let a = Args::parse(rest, &[], &["--scope"], &["--sid", "-o"])?;
            deep::cmd_deep(&deep::DeepArgs {
                scopes: a.all("--scope").into_iter().map(PathBuf::from).collect(),
                sid: a.get("--sid"),
                out: a.req("-o")?,
            })
        }
        "fidelity" => {
            let a = Args::parse(
                rest,
                &[],
                &["--keep-items"],
                &["--before", "--after", "--journal", "--ambient", "--sid", "-o"],
            )?;
            let rep = fidelity::cmd_fidelity(&fidelity::FidelityArgs {
                before: a.req("--before")?,
                after: a.req("--after")?,
                journal: a.req("--journal")?,
                ambient: a.path("--ambient"),
                sid: a.get("--sid"),
                keep_items: a.all("--keep-items"),
                out: a.req("-o")?,
            })?;
            if !rep.ok {
                bail!("fidelity: {} differing objects, {} failing rows", rep.differences.len(), rep.failing_rows());
            }
            Ok(())
        }
        "execdiff" => {
            let a = Args::parse(
                rest,
                &[],
                &["--traps", "--group"],
                &[
                    "--before",
                    "--after",
                    "--journal",
                    "--report",
                    "--ambient",
                    "--deep-before",
                    "--deep-after",
                    "--sid",
                    "-o",
                ],
            )?;
            let rep = execdiff::cmd_execdiff(&execdiff::ExecdiffArgs {
                before: a.req("--before")?,
                after: a.req("--after")?,
                journal: a.req("--journal")?,
                report: a.req("--report")?,
                traps: a.all("--traps").into_iter().map(PathBuf::from).collect(),
                ambient: a.path("--ambient"),
                deep_before: a.path("--deep-before"),
                deep_after: a.path("--deep-after"),
                groups: a.all("--group"),
                sid: a.get("--sid"),
                out: a.req("-o")?,
            })?;
            if !rep.ok {
                let c = &rep.counts;
                bail!(
                    "execdiff: {} guard escapes, {} collateral, {} missing effects, {} changed though not done, \
                     {} trap mismatches, {} unverified canaries, {} inconsistencies",
                    c.guard_escapes,
                    c.collateral,
                    c.missing_effects,
                    c.changed_not_done,
                    c.trap_mismatches,
                    c.unverified_canaries,
                    c.inconsistencies
                );
            }
            Ok(())
        }
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => bail!("unknown command {other:?}\n\n{USAGE}"),
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(argv) {
        eprintln!("rigtool: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arg_parsing() {
        let v: Vec<String> = ["--set", "a", "b", "--plan", "p1", "--plan=p2", "-o", "x", "--json", "j"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let a = Args::parse(&v, &[], &["--set"], &["--plan", "-o", "--json"]).unwrap();
        assert_eq!(a.all("--set"), vec!["a", "b"]);
        assert_eq!(a.all("--plan"), vec!["p1", "p2"]);
        assert_eq!(a.get("-o").as_deref(), Some("x"));
        assert!(Args::parse(&["--nope".to_string()], &[], &[], &[]).is_err());
    }
}
