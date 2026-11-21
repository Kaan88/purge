//! The broker's command line (M3 design 3.3 step 1): `purge-broker.exe --pipe <name> --parent <pid>
//! --parent-ctime <filetime>`, each exactly once. Nothing else is accepted: the broker takes no path and
//! no directory from its arguments.

/// What the UI passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// The random part of the pipe name: 32 hex digits.
    pub pipe_name: String,
    /// The UI's process id.
    pub parent_pid: u32,
    /// The UI's process creation time, a `FILETIME` as decimal digits.
    pub parent_ctime: u64,
}

/// The usage line.
pub const USAGE: &str =
    "usage: purge-broker.exe --pipe <32 hex digits> --parent <pid> --parent-ctime <filetime>";

/// Reads the arguments after the program name.
pub fn parse(args: &[String]) -> Result<Args, String> {
    let (mut pipe, mut pid, mut ctime) = (None, None, None);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let slot = match flag.as_str() {
            "--pipe" => &mut pipe,
            "--parent" => &mut pid,
            "--parent-ctime" => &mut ctime,
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
    Ok(Args {
        pipe_name,
        parent_pid,
        parent_ctime: number("--parent-ctime", ctime)?,
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
}
