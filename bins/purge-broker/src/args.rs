//! The broker's command line (M3 design 3.3 step 1): `purge-broker.exe --pipe <name> --parent <pid>
//! --parent-ctime <filetime>`, each exactly once, and optionally `--consent <taskdialog|toolkit>`, at
//! most once. Nothing else is accepted: the broker takes no path and no directory from its arguments.
//!
//! **`--consent`** chooses who draws the consent dialog: the Win32 TaskDialog, or Purge's own toolkit
//! (`consent::toolkit`). Without it the build's default is used ([`ConsentUi::DEFAULT`]), and the
//! TaskDialog is what is shown whenever the toolkit window cannot be. The choice is an argument, and
//! not a setting the broker reads, on purpose: an elevated process must not take its behaviour from a
//! file or an environment a medium process can write (design T7), and the command line is where the UI
//! already says everything else it has to say.
//!
//! **Whoever starts the broker can pass either value** (anyone at medium can: an edited shortcut,
//! `Purge.exe --broker-consent toolkit`, an injected Purge.exe). That is harmless only while the two
//! dialogs give the same guarantees, and the toolkit dialog's have not been shown in a VM yet (review
//! B1, B2; M3_DESIGN 8.3). So the toolkit dialog is in the broker only when it is built with the cargo
//! feature `toolkit-consent`, which no release build turns on: a broker without the feature has no
//! [`ConsentUi`] to name the toolkit, and refuses `--consent toolkit` with [`TOOLKIT_REFUSED`]
//! before it opens its pipe. It does not fall back to the TaskDialog on its own word: the caller asked
//! for something this build cannot do, and is told.

/// Who draws the consent dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentUi {
    /// The Win32 TaskDialog (`purge_win::taskdialog`).
    TaskDialog,
    /// Purge's own toolkit (`consent::toolkit`), with the TaskDialog behind it. Only in a build with
    /// the feature `toolkit-consent`.
    #[cfg(feature = "toolkit-consent")]
    Toolkit,
}

/// The value of `--consent` that names the toolkit dialog, whether or not this build has it.
pub const TOOLKIT_NAME: &str = "toolkit";

/// Why a build without the feature `toolkit-consent` refuses `--consent toolkit`.
pub const TOOLKIT_REFUSED: &str = "--consent toolkit is refused: this purge-broker was built without \
                                   the toolkit consent dialog (cargo feature toolkit-consent, which \
                                   no release build has); start it without --consent, or with \
                                   --consent taskdialog";

impl ConsentUi {
    /// What a broker started without `--consent` uses: the TaskDialog, until the toolkit dialog has
    /// passed its security review and the VM mode `m3-consent` (package BROKER-CONSENT-UI, steps 2
    /// to 4).
    pub const DEFAULT: ConsentUi = ConsentUi::TaskDialog;

    /// Every choice this build has.
    pub const ALL: &'static [ConsentUi] = &[
        ConsentUi::TaskDialog,
        #[cfg(feature = "toolkit-consent")]
        ConsentUi::Toolkit,
    ];

    /// The value of `--consent` that names it.
    pub fn name(self) -> &'static str {
        match self {
            ConsentUi::TaskDialog => "taskdialog",
            #[cfg(feature = "toolkit-consent")]
            ConsentUi::Toolkit => TOOLKIT_NAME,
        }
    }

    /// The choice a value of `--consent` names, exactly as written here. `None` for the toolkit's
    /// name in a build that has no toolkit dialog.
    pub fn parse(value: &str) -> Option<ConsentUi> {
        ConsentUi::ALL.iter().copied().find(|c| c.name() == value)
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

/// The usage line: it names only what this build takes.
#[cfg(feature = "toolkit-consent")]
pub const USAGE: &str = concat!(
    "usage: purge-broker.exe --pipe <32 hex digits> --parent <pid> --parent-ctime <filetime>",
    " [--consent <taskdialog|toolkit>]"
);
/// The usage line: it names only what this build takes.
#[cfg(not(feature = "toolkit-consent"))]
pub const USAGE: &str = concat!(
    "usage: purge-broker.exe --pipe <32 hex digits> --parent <pid> --parent-ctime <filetime>",
    " [--consent taskdialog]"
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
        Some(value) => match ConsentUi::parse(&value) {
            Some(consent) => consent,
            // Named rightly, and not in this build: said in so many words, never read as the
            // TaskDialog and never as a spelling mistake.
            None if value == TOOLKIT_NAME => return Err(TOOLKIT_REFUSED.to_owned()),
            None => return Err("--consent is not taskdialog or toolkit".to_owned()),
        },
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

    const BASE: [&str; 6] = ["--pipe", NAME, "--parent", "4321", "--parent-ctime", "7"];

    /// `--consent <value>` after the three arguments, and before them.
    fn with_consent(value: &'static str) -> [Vec<&'static str>; 2] {
        let mut last = BASE.to_vec();
        last.extend(["--consent", value]);
        let mut first = vec!["--consent", value];
        first.extend(BASE);
        [last, first]
    }

    /// The build with the toolkit dialog takes its name.
    #[cfg(feature = "toolkit-consent")]
    #[test]
    fn a_build_with_the_toolkit_dialog_takes_its_name() {
        assert_eq!(
            ConsentUi::ALL,
            [ConsentUi::TaskDialog, ConsentUi::Toolkit].as_slice()
        );
        assert_eq!(ConsentUi::Toolkit.name(), TOOLKIT_NAME);
        assert_eq!(ConsentUi::parse(TOOLKIT_NAME), Some(ConsentUi::Toolkit));
        for list in with_consent(TOOLKIT_NAME) {
            assert_eq!(parse(&args(&list)).unwrap().consent, ConsentUi::Toolkit);
        }
        assert!(USAGE.contains("taskdialog|toolkit"));
    }

    /// The build every release is: no toolkit dialog to name, and its name refused in so many
    /// words, wherever it stands, and never taken for the TaskDialog (review B2).
    #[cfg(not(feature = "toolkit-consent"))]
    #[test]
    fn a_build_without_the_toolkit_dialog_refuses_its_name() {
        assert_eq!(ConsentUi::ALL, [ConsentUi::TaskDialog].as_slice());
        assert_eq!(ConsentUi::parse(TOOLKIT_NAME), None);
        for list in with_consent(TOOLKIT_NAME) {
            assert_eq!(parse(&args(&list)), Err(TOOLKIT_REFUSED.to_owned()));
        }
        assert!(TOOLKIT_REFUSED.contains("toolkit-consent"));
        assert!(!USAGE.contains("toolkit"));
        // Another wrong value is still the plain refusal.
        let mut list = BASE.to_vec();
        list.extend(["--consent", "auto"]);
        assert_eq!(
            parse(&args(&list)),
            Err("--consent is not taskdialog or toolkit".to_owned())
        );
    }

    #[test]
    fn the_consent_dialog_is_the_taskdialog_unless_the_toolkit_is_named() {
        let base = BASE;
        assert_eq!(ConsentUi::DEFAULT, ConsentUi::TaskDialog);
        assert_eq!(parse(&args(&base)).unwrap().consent, ConsentUi::TaskDialog);
        for list in with_consent("taskdialog") {
            assert_eq!(parse(&args(&list)).unwrap().consent, ConsentUi::TaskDialog);
        }
        for want in ConsentUi::ALL {
            assert_eq!(ConsentUi::parse(want.name()), Some(*want));
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
