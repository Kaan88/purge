//! The broker's command line (M3 design 3.3 step 1): `purge-broker.exe --pipe <name> --parent <pid>
//! --parent-ctime <filetime>`, each exactly once, and optionally `--consent <taskdialog|toolkit>`, at
//! most once. Nothing else is accepted: the broker takes no path and no directory from its arguments.
//!
//! **`--consent`** chooses who draws the consent dialog: the Win32 TaskDialog, or Purge's own toolkit
//! (`consent::toolkit`). Without it the build's default is used ([`ConsentUi::DEFAULT`]), and the
//! TaskDialog is what is shown whenever the toolkit window cannot be. The choice is an argument, and
//! not a setting the broker reads, on purpose: an elevated process must not take its behaviour from a
//! file or an environment a medium process can write (design T7), and the command line is where the UI
//! already says everything else it has to say. Whoever starts the broker can pass either value, which
//! is harmless only because the two dialogs are held to the same rules: the argument picks the drawing
//! of one view, and nothing in what is said, what approves, or what runs depends on it.

/// Who draws the consent dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentUi {
    /// The Win32 TaskDialog (`purge_win::taskdialog`).
    TaskDialog,
    /// Purge's own toolkit (`consent::toolkit`), with the TaskDialog behind it.
    Toolkit,
}

impl ConsentUi {
    /// What a broker started without `--consent` uses: the TaskDialog, until the toolkit dialog has
    /// passed its security review and the VM mode `m3-consent` (package BROKER-CONSENT-UI, steps 2
    /// to 4).
    pub const DEFAULT: ConsentUi = ConsentUi::TaskDialog;

    /// The value of `--consent` that names it.
    pub fn name(self) -> &'static str {
        match self {
            ConsentUi::TaskDialog => "taskdialog",
            ConsentUi::Toolkit => "toolkit",
        }
    }

    /// The choice a value of `--consent` names, exactly as written here.
    pub fn parse(value: &str) -> Option<ConsentUi> {
        [ConsentUi::TaskDialog, ConsentUi::Toolkit]
            .into_iter()
            .find(|c| c.name() == value)
    }
}

/// What the UI passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// The random part of the pipe name: 32 hex digits.
    pub pipe_name: String,
    /// The UI's process id.
    pub parent_pid: u32,
    /// The UI's process creation time, a `FILETIME` as decimal digits.
    pub parent_ctime: u64,
    /// Who draws the consent dialog: `--consent`, or [`ConsentUi::DEFAULT`] without it.
    pub consent: ConsentUi,
}

/// The usage line.
pub const USAGE: &str = concat!(
    "usage: purge-broker.exe --pipe <32 hex digits> --parent <pid> --parent-ctime <filetime>",
    " [--consent <taskdialog|toolkit>]"
);

/// Reads the arguments after the program name.
pub fn parse(args: &[String]) -> Result<Args, String> {
    let (mut pipe, mut pid, mut ctime, mut consent) = (None, None, None, None);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let slot = match flag.as_str() {
            "--pipe" => &mut pipe,
            "--parent" => &mut pid,
            "--parent-ctime" => &mut ctime,
            "--consent" => &mut consent,
            other => return Err(format!("unknown argument {other:?}")),
        };
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        if slot.replace(value.clone()).is_some() {
            return Err(format!("{flag} given twice"));
        }
    }
    let pipe_name = pipe.ok_or("--pipe is missing")?;
    if !purge_win::pipe::valid_name(&pipe_name) {
        return Err("--pipe is not 32 hex digits".into());
    }
    let number = |what: &str, text: Option<String>| -> Result<u64, String> {
        let text = text.ok_or_else(|| format!("{what} is missing"))?;
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("{what} is not a number"));
        }
        match text.parse::<u64>() {
            Ok(n) if n != 0 => Ok(n),
            _ => Err(format!("{what} is not a positive number")),
        }
    };
    let parent_pid = u32::try_from(number("--parent", pid)?)
        .map_err(|_| "--parent is not a process id".to_owned())?;
    let consent = match consent {
        None => ConsentUi::DEFAULT,
        Some(value) => ConsentUi::parse(&value)
            .ok_or_else(|| "--consent is not taskdialog or toolkit".to_owned())?,
    };
    Ok(Args {
        pipe_name,
        parent_pid,
        parent_ctime: number("--parent-ctime", ctime)?,
        consent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "0123456789abcdef0123456789abcdef";

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn the_three_arguments_in_any_order() {
        let want = Args {
            pipe_name: NAME.into(),
            parent_pid: 4321,
            parent_ctime: 133_800_000_000_000_000,
            consent: ConsentUi::TaskDialog,
        };
        for list in [
            [
                "--pipe",
                NAME,
                "--parent",
                "4321",
                "--parent-ctime",
                "133800000000000000",
            ],
            [
                "--parent-ctime",
                "133800000000000000",
                "--parent",
                "4321",
                "--pipe",
                NAME,
            ],
        ] {
            assert_eq!(parse(&args(&list)), Ok(want.clone()));
        }
    }

    #[test]
    fn anything_else_is_refused() {
        let ok = ["--pipe", NAME, "--parent", "4321", "--parent-ctime", "7"];
        assert!(parse(&args(&ok)).is_ok());
        let bad: Vec<Vec<&str>> = vec![
            vec![],
            vec!["--pipe", NAME, "--parent", "4321"],
            vec!["--pipe", "short", "--parent", "4321", "--parent-ctime", "7"],
            vec!["--pipe", NAME, "--parent", "0", "--parent-ctime", "7"],
            vec!["--pipe", NAME, "--parent", "-4", "--parent-ctime", "7"],
            vec![
                "--pipe",
                NAME,
                "--parent",
                "4294967296",
                "--parent-ctime",
                "7",
            ],
            vec!["--pipe", NAME, "--parent", "4321", "--parent-ctime", "0"],
            vec!["--pipe", NAME, "--parent", "4321", "--parent-ctime", "x"],
            vec![
                "--pipe",
                NAME,
                "--parent",
                "4321",
                "--parent-ctime",
                "7",
                "--kb",
                "C:\\x",
            ],
            vec![
                "--pipe",
                NAME,
                "--pipe",
                NAME,
                "--parent",
                "4321",
                "--parent-ctime",
                "7",
            ],
            vec!["--pipe", NAME, "--parent", "4321", "--parent-ctime"],
            vec!["--pipe=0123", "--parent", "1", "--parent-ctime", "7"],
        ];
        for list in bad {
            assert!(parse(&args(&list)).is_err(), "{list:?}");
        }
    }

    #[test]
    fn the_consent_dialog_is_the_taskdialog_unless_the_toolkit_is_named() {
        let base = ["--pipe", NAME, "--parent", "4321", "--parent-ctime", "7"];
        assert_eq!(ConsentUi::DEFAULT, ConsentUi::TaskDialog);
        assert_eq!(parse(&args(&base)).unwrap().consent, ConsentUi::TaskDialog);
        for (value, want) in [
            ("taskdialog", ConsentUi::TaskDialog),
            ("toolkit", ConsentUi::Toolkit),
        ] {
            let mut list = base.to_vec();
            list.extend(["--consent", value]);
            assert_eq!(parse(&args(&list)).unwrap().consent, want);
            // In any place.
            let mut first = vec!["--consent", value];
            first.extend(base);
            assert_eq!(parse(&args(&first)).unwrap().consent, want);
            assert_eq!(ConsentUi::parse(want.name()), Some(want));
        }
        // Any other value, a second one, a missing one, another spelling: refused, never a guess.
        for tail in [
            vec!["--consent", "Toolkit"],
            vec!["--consent", "toolkit "],
            vec!["--consent", ""],
            vec!["--consent", "none"],
            vec!["--consent", "auto"],
            vec!["--consent"],
            vec!["--consent", "toolkit", "--consent", "toolkit"],
            vec!["--consent", "taskdialog", "--consent", "toolkit"],
            vec!["--consent=toolkit"],
            vec!["--toolkit"],
        ] {
            let mut list = base.to_vec();
            list.extend(tail.iter());
            assert!(parse(&args(&list)).is_err(), "{list:?}");
        }
    }
}
