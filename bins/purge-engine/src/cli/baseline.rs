//! `baseline build --out <file>` and `baseline info <file>` (BASELINE_LOCAL_DESIGN.md §8.1, package
//! BL-BUILD).
//!
//! `baseline build` reads this Windows' own sources (component manifests, the default profile's hive,
//! `HKU\.DEFAULT`, inbox package manifests) read-only, at background priority, and writes the local
//! baseline to `<file>` through the CLI's one file writer ([`output::write_atomic_bytes`]: temporary
//! file and rename, no link followed). That file is the only thing it writes. Its stderr carries the
//! `#src` lines, the `timing:` lines of every phase and the seal. An incomplete build still writes the
//! file (it records why), and exits 0 with a `warning:` line.
//!
//! `baseline info` reads a local baseline file, checks its `#end` line, and prints the header, the
//! `#src` lines, the record counts and the seal to stdout. A file that is not a correct local baseline
//! (a shipped baseline included) is a usage error (exit 2) naming why.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use purge_index::local_baseline::{
    self, BuildOptions, LocalBaseline, LocalBaselineFile, SealFloors, iso_utc,
};
use purge_source::local_baseline::LocalSources;
use purge_win::sxs::SxsBase;

use super::args::{BaselineBuildArgs, BaselineInfoArgs};
use super::{Env, Exit, output, progress_line};

/// `baseline build`: see the module documentation. `local` are the sources to read and `base` the delta
/// base of the component manifests (the live ones in [`super::run`]).
pub(crate) fn build_verb(
    a: &BaselineBuildArgs,
    env: &mut Env<'_>,
    local: &dyn LocalSources,
    base: Result<SxsBase, String>,
    started: Instant,
) -> Exit {
    progress_line(env.stderr, started, "reading the Windows edition and build");
    let os = match env.sources.sys.os_info() {
        Ok(os) if !os.edition.is_empty() => os,
        Ok(_) => {
            env.error("the Windows edition is unknown; no local baseline is built");
            return Exit::Usage;
        }
        Err(e) => {
            env.error(&format!(
                "the Windows edition and build could not be read: {e}"
            ));
            return Exit::Usage;
        }
    };
    let stamps = local_baseline::file_stamps(env.sources.fs, env.sources.reg, env.sources.sys);
    let mut warnings: Vec<String> = stamps
        .problems
        .iter()
        .map(|p| format!("source id: {p}"))
        .collect();
    if !env.sources.sys.elevated() {
        warnings.push(
            "not elevated: S4 reads only this account's packages, so the build is incomplete"
                .into(),
        );
    }
    if let Err(e) = &base {
        warnings.push(format!("no delta base for the component manifests: {e}"));
    }
    env.warnings(&warnings);
    let computer = env
        .sources
        .sys
        .env()
        .ok()
        .and_then(|e| e.get("COMPUTERNAME").cloned())
        .unwrap_or_default();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    let opts = BuildOptions {
        built_at: iso_utc(now),
        computer,
        base,
        stamps,
        threads: 0,
        background: true,
        floors: SealFloors::default(),
    };
    progress_line(
        env.stderr,
        started,
        &format!(
            "building the local baseline of {} (background priority)",
            os.baseline_name()
        ),
    );
    let built = match local_baseline::build(local, &os, &opts) {
        Ok(b) => b,
        Err(e) => {
            env.error(&format!("cannot encode the local baseline: {e}"));
            return Exit::Runtime;
        }
    };
    report_build(env, &built);
    let write_started = Instant::now();
    let exit = match output::write_atomic_bytes(&a.out, &built.bytes) {
        Ok(()) => {
            env.note(&format!(
                "wrote the local baseline to {} ({} bytes)",
                a.out.display(),
                built.bytes.len()
            ));
            Exit::Ok
        }
        Err(e) => {
            env.error(&format!(
                "cannot write the local baseline to {}: {e}",
                a.out.display()
            ));
            Exit::Runtime
        }
    };
    env.note(&format!(
        "timing: baseline.local.write.file {:.3} s",
        write_started.elapsed().as_secs_f64()
    ));
    progress_line(env.stderr, started, "done");
    exit
}

fn report_build(env: &mut Env<'_>, built: &LocalBaselineFile) {
    for s in &built.sources {
        env.note(&s.line());
    }
    for line in built.timings.lines(built.threads) {
        env.note(&line);
    }
    let c = built.counts;
    env.note(&format!(
        "records: {} ({} keys, {} values, {} dirs, {} files); text {} bytes, file {} bytes; source id {}",
        built.record_count,
        c.keys,
        c.values,
        c.dirs,
        c.files,
        built.text_bytes,
        built.bytes.len(),
        built.header.source_id
    ));
    if built.complete() {
        env.note("seal: complete");
    } else {
        env.note("seal: incomplete (the file is for presence only)");
        let reasons: Vec<String> = built
            .incomplete_reasons()
            .into_iter()
            .map(|r| format!("seal: {r}"))
            .collect();
        env.warnings(&reasons);
    }
}

/// `baseline info`: see the module documentation.
pub(crate) fn info_verb(a: &BaselineInfoArgs, env: &mut Env<'_>) -> Exit {
    let lb = match LocalBaseline::load(&a.file) {
        Ok(lb) => lb,
        Err(e) => {
            env.error(&format!("{}: {e}", a.file.display()));
            return Exit::Usage;
        }
    };
    let h = lb.header();
    let mut text = format!(
        "file\t{}\nbuilt\t{}\ncomputer\t{}\nwindows\t{}-{}.{}\nbuilder\t{}\nsource id\t{}\n",
        a.file.display(),
        h.built_at,
        h.computer,
        h.edition,
        h.build,
        h.ubr,
        h.builder_version,
        h.source_id
    );
    let c = lb.counts();
    text.push_str(&format!(
        "records\t{} ({} keys, {} values, {} dirs, {} files)\n",
        lb.record_count(),
        c.keys,
        c.values,
        c.dirs,
        c.files
    ));
    for s in lb.sources() {
        text.push_str(&s.line());
        text.push('\n');
    }
    if lb.complete() {
        text.push_str("seal\tcomplete\n");
    } else {
        text.push_str("seal\tincomplete\n");
        for r in lb.incomplete_reasons() {
            text.push_str(&format!("why\t{r}\n"));
        }
    }
    match env.stdout.write_all(text.as_bytes()) {
        Ok(()) => Exit::Ok,
        Err(e) => {
            env.error(&format!("cannot write to stdout: {e}"));
            Exit::Runtime
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use purge_inventory::runner::RunOptions;
    use purge_source::fixture::Fixture;

    use super::super::args::{self, Invocation};
    use super::*;
    use crate::pipeline::{Settings, Sources};

    /// A host that must never be used.
    struct NoHost;

    impl purge_inventory::runner::ProcessHost for NoHost {
        fn spawn_in_job(
            &mut self,
            _: &str,
            _: purge_inventory::runner::SpawnContext<'_>,
        ) -> std::io::Result<purge_inventory::runner::JobId> {
            panic!("no process may be started")
        }
        fn job_active_pids(
            &mut self,
            _: purge_inventory::runner::JobId,
        ) -> std::io::Result<Vec<u32>> {
            unreachable!()
        }
        fn job_exit_code(
            &mut self,
            _: purge_inventory::runner::JobId,
        ) -> std::io::Result<Option<u32>> {
            unreachable!()
        }
        fn process_info(&mut self, _: u32) -> Option<purge_model::ProcessSeen> {
            unreachable!()
        }
        fn running_processes(&mut self) -> std::io::Result<Vec<purge_model::ProcessSeen>> {
            unreachable!()
        }
        fn mutex_exists(&mut self, _: &str) -> std::io::Result<bool> {
            unreachable!()
        }
        fn now(&self) -> purge_model::FileTime {
            purge_model::FileTime(0)
        }
        fn sleep(&mut self, _: std::time::Duration) {}
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "purge-engine-baseline-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Runs one verb line against `f` (sources and local sources); (exit, stdout, stderr).
    fn run(f: &Fixture, line: &str) -> (Exit, String, String) {
        let args: Vec<String> = line.split_whitespace().map(String::from).collect();
        let mut host = NoHost;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut env = Env {
            sources: Sources::of(f),
            host: &mut host,
            settings: Settings::default(),
            run_options: RunOptions::default(),
            stdout: &mut out,
            stderr: &mut err,
        };
        let exit = match args::parse(&args).unwrap() {
            Invocation::BaselineBuild(a) => build_verb(
                &a,
                &mut env,
                f,
                Err("not in a fixture".into()),
                Instant::now(),
            ),
            Invocation::BaselineInfo(a) => info_verb(&a, &mut env),
            other => panic!("{other:?}"),
        };
        (
            exit,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn fixture() -> Fixture {
        Fixture::builder()
            .os("Professional", 26100, 9711)
            .env("SystemRoot", r"C:\Windows")
            .env("COMPUTERNAME", "BOX")
            .file_content(
                r"C:\Windows\WinSxS\Manifests\a.manifest",
                br#"<assembly><assemblyIdentity name="a" processorArchitecture="amd64"/><registryKeys><registryKey keyName="HKEY_LOCAL_MACHINE\SOFTWARE\PurgeCliTest"/></registryKeys></assembly>"#.to_vec(),
            )
            .sz(r"HKU\.DEFAULT\Control Panel", "x", "1")
            .build()
    }

    #[test]
    fn build_writes_only_the_named_file_and_info_reads_it() {
        let dir = scratch("build");
        let out = dir.join("local.tsv.gz");
        let f = fixture();
        let (exit, stdout, stderr) = run(&f, &format!("baseline build --out {}", out.display()));
        assert_eq!(exit, Exit::Ok, "{stderr}");
        assert!(stdout.is_empty());
        for want in [
            "#src\tS1\tincomplete\t1\t",
            "#src\tS2\tfailed\t",
            "#src\tS3\tok\t",
            "#src\tS4\t",
            "timing: baseline.local.expand ",
            "timing: baseline.local.write ",
            "seal: incomplete",
            "warning: seal: S1 incomplete: no delta base: not in a fixture",
            "warning: not elevated",
            "wrote the local baseline to ",
        ] {
            assert!(stderr.contains(want), "{want:?} not in\n{stderr}");
        }
        let files: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(files.len(), 1, "only the named file is written");

        let (exit, stdout, stderr) = run(&f, &format!("baseline info {}", out.display()));
        assert_eq!(exit, Exit::Ok, "{stderr}");
        assert!(
            stdout.contains("windows\tProfessional-26100.9711\n"),
            "{stdout}"
        );
        assert!(stdout.contains("computer\tBOX\n"), "{stdout}");
        assert!(stdout.contains("#src\tS3\tok\t"), "{stdout}");
        assert!(
            stdout.contains("seal\tincomplete\nwhy\tS1 incomplete: "),
            "{stdout}"
        );
        let lb = LocalBaseline::load(&out).unwrap();
        assert!(lb.has_key(r"HKLM\SOFTWARE\PurgeCliTest"));
        assert!(lb.has_key(r"HKU\S-1-5-18\Control Panel"));
    }

    #[test]
    fn info_refuses_what_is_not_a_correct_local_baseline() {
        let dir = scratch("info");
        let f = fixture();
        let shipped = dir.join("Professional-26100.9711.tsv");
        std::fs::write(
            &shipped,
            "#purge-baseline 1\tT\tPC\tProfessional\t26100.9711\nK\thklm\\\\software\n",
        )
        .unwrap();
        let (exit, stdout, stderr) = run(&f, &format!("baseline info {}", shipped.display()));
        assert_eq!(exit, Exit::Usage);
        assert!(stdout.is_empty());
        assert!(stderr.contains("not a local baseline header"), "{stderr}");
        let (exit, _, stderr) = run(&f, &format!("baseline info {}", dir.join("none").display()));
        assert_eq!(exit, Exit::Usage);
        assert!(
            stderr.contains("cannot read the local baseline"),
            "{stderr}"
        );
    }

    #[test]
    fn build_needs_the_edition() {
        let dir = scratch("edition");
        let f = Fixture::new();
        let out = dir.join("x.tsv.gz");
        let (exit, _, stderr) = run(&f, &format!("baseline build --out {}", out.display()));
        assert_eq!(exit, Exit::Usage, "{stderr}");
        assert!(!out.exists());
    }
}
