// Copyright (c) 2017 Marcin Szeniak
// Modified by Purge
// Ported from BCU: source/KlocTools/Tools/ProcessStartCommand.cs (Apache-2.0)
// Ported from BCU: source/KlocTools/Tools/ProcessTools.cs (Apache-2.0)

//! Splitting an `UninstallString`-style command line into the executable and its arguments.
//!
//! ENGINE_PLAN.md §4.3 (BCU `ProcessStartCommand`). Pure: no file-system access unless the caller passes
//! an existence probe to [`split_with`]. The rules:
//!
//! - a command that starts with `"` takes everything up to the next `"` as the executable path; the rest
//!   (trimmed) is the argument string;
//! - an unquoted command looks for an executable extension (`.exe`, `.com`, `.bat`, `.cmd`, `.msi`) that is
//!   followed by whitespace, `/`, `"` or the end, so `C:\Program Files\App\uninst.exe /S` keeps the space
//!   in the path; a candidate spans whitespace only when the command is rooted (`X:\`, `\\`, `%VAR%`) and
//!   no spanned word looks like a switch; with a probe, the first candidate that exists wins;
//! - otherwise the command splits at the first whitespace (`msiexec /x {GUID}`, `rundll32 a.dll,Entry`).
//!
//! [`SplitCommand::kind`] recognises the `msiexec` and `rundll32` forms and pulls out the MSI action and
//! ProductCode, or the DLL and entry point.

use std::fmt;

/// Extensions that end an unquoted executable path, lower case, with the dot.
const EXE_EXTENSIONS: [&str; 5] = [".exe", ".com", ".bat", ".cmd", ".msi"];

/// Why a command line could not be split.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CmdlineError {
    /// The command is empty or whitespace, or its quoted executable path is empty.
    #[error("the command line has no executable")]
    Empty,
    /// The command starts with `"` and has no closing quote.
    #[error("the command line starts with a quote that is never closed")]
    UnterminatedQuote,
}

/// A command line split into the executable and its argument string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SplitCommand {
    /// Executable path or name, without surrounding quotes, as written (environment variables unexpanded).
    pub exe: String,
    /// Argument string, trimmed; empty when there are none. Quotes inside it are kept.
    pub args: String,
}

impl SplitCommand {
    /// Rebuilds a command line: the executable is quoted when it contains whitespace.
    pub fn to_command_line(&self) -> String {
        let exe = if self.exe.chars().any(char::is_whitespace) {
            format!("\"{}\"", self.exe)
        } else {
            self.exe.clone()
        };
        if self.args.is_empty() {
            exe
        } else {
            format!("{exe} {}", self.args)
        }
    }

    /// The last path component of [`exe`](Self::exe) (after the last `\` or `/`).
    pub fn file_name(&self) -> &str {
        self.exe.rsplit(['\\', '/']).next().unwrap_or(&self.exe)
    }

    /// The file name without its extension, lower case (`MsiExec.exe` -> `msiexec`).
    fn stem_lower(&self) -> String {
        let name = self.file_name();
        let stem = match name.rfind('.') {
            Some(dot) if dot > 0 => &name[..dot],
            _ => name,
        };
        stem.to_ascii_lowercase()
    }

    /// Recognises the `msiexec` and `rundll32` forms.
    pub fn kind(&self) -> CommandKind {
        match self.stem_lower().as_str() {
            "msiexec" => CommandKind::Msiexec(parse_msiexec(&self.args)),
            "rundll32" => match parse_rundll32(&self.args) {
                Some(r) => CommandKind::Rundll32(r),
                None => CommandKind::Other,
            },
            _ => CommandKind::Other,
        }
    }
}

impl fmt::Display for SplitCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_command_line())
    }
}

/// The recognised shape of a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandKind {
    /// `msiexec[.exe] ...`.
    Msiexec(MsiexecCommand),
    /// `rundll32[.exe] dll,Entry ...`.
    Rundll32(Rundll32Command),
    /// Anything else.
    Other,
}

/// The main action switch of an `msiexec` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MsiexecAction {
    /// `/I` or `/package` (ARP often uses `/I{PC}` to open maintenance mode).
    Install,
    /// `/X` or `/uninstall`.
    Uninstall,
    /// `/F...` (repair).
    Repair,
}

/// The parts of an `msiexec` command that matter to the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsiexecCommand {
    /// The first action switch, if any.
    pub action: Option<MsiexecAction>,
    /// The first braced GUID in the arguments, upper case with braces (`{XXXXXXXX-...}`).
    pub product_code: Option<String>,
}

/// The parts of a `rundll32` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rundll32Command {
    /// DLL path, without quotes.
    pub dll: String,
    /// Entry point after the comma, if present.
    pub entry: Option<String>,
    /// Remaining arguments after the entry point, trimmed.
    pub args: String,
}

/// Splits a command line without touching the file system (the first extension candidate wins).
pub fn split(command: &str) -> Result<SplitCommand, CmdlineError> {
    split_with(command, |_| false)
}

/// Splits a command line; for an unquoted path, the first extension candidate for which `exists`
/// returns true wins, otherwise the first candidate.
pub fn split_with(
    command: &str,
    exists: impl Fn(&str) -> bool,
) -> Result<SplitCommand, CmdlineError> {
    let cmd = command.trim();
    if cmd.is_empty() {
        return Err(CmdlineError::Empty);
    }

    if let Some(rest) = cmd.strip_prefix('"') {
        let close = rest.find('"').ok_or(CmdlineError::UnterminatedQuote)?;
        let exe = rest[..close].trim();
        if exe.is_empty() {
            return Err(CmdlineError::Empty);
        }
        return Ok(SplitCommand {
            exe: exe.to_owned(),
            args: rest[close + 1..].trim().to_owned(),
        });
    }

    // An unquoted path cannot contain a quote, so candidates are searched only before the first one.
    let search_end = cmd.find('"').unwrap_or(cmd.len());
    let candidates = extension_ends(&cmd[..search_end], cmd);
    let chosen = candidates
        .iter()
        .copied()
        .find(|&end| exists(&cmd[..end]))
        .or_else(|| candidates.first().copied());
    let end = chosen.unwrap_or_else(|| cmd.find(char::is_whitespace).unwrap_or(cmd.len()));
    Ok(SplitCommand {
        exe: cmd[..end].trim().to_owned(),
        args: cmd[end..].trim().to_owned(),
    })
}

/// Byte offsets just past every executable extension in `region` that is followed (in `full`) by
/// whitespace, `/`, `"` or the end. Ascending.
fn extension_ends(region: &str, full: &str) -> Vec<usize> {
    let lower = region.to_ascii_lowercase();
    let mut ends = Vec::new();
    for (i, _) in lower.match_indices('.') {
        for ext in EXE_EXTENSIONS {
            if lower[i..].starts_with(ext) {
                let end = i + ext.len();
                let terminated = match full[end..].chars().next() {
                    None => true,
                    Some(c) => c.is_whitespace() || c == '/' || c == '"',
                };
                // A path must have something before the extension, and may only span whitespace when it
                // is rooted and the spanned words do not look like switches.
                if terminated && i > 0 && may_span(&full[..end]) {
                    ends.push(end);
                }
            }
        }
    }
    ends
}

/// Whether `prefix` can be one unquoted path. Without whitespace it always can. With whitespace it must
/// start rooted (`X:\`, `\\` or `%VAR%`), and no later word may look like a switch (`/x`, `-x`), so
/// `msiexec /uninstall x.msi` is not taken as one path.
fn may_span(prefix: &str) -> bool {
    if !prefix.contains(char::is_whitespace) {
        return true;
    }
    let b = prefix.as_bytes();
    let rooted = (b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'\\' || b[2] == b'/'))
        || prefix.starts_with(r"\\")
        || prefix.starts_with('%');
    rooted
        && prefix
            .split_whitespace()
            .skip(1)
            .all(|w| !(w.starts_with('/') || (w.starts_with('-') && w.len() > 1)))
}

/// Parses `msiexec` arguments for the action switch and the ProductCode.
fn parse_msiexec(args: &str) -> MsiexecCommand {
    let mut action = None;
    for token in args.split_whitespace() {
        let Some(sw) = token.strip_prefix('/').or_else(|| token.strip_prefix('-')) else {
            continue;
        };
        let sw = sw.to_ascii_lowercase();
        let found = if sw.starts_with("uninstall") {
            Some(MsiexecAction::Uninstall)
        } else if sw.starts_with("package") {
            Some(MsiexecAction::Install)
        } else if sw.starts_with("forcerestart") {
            None
        } else {
            match sw.chars().next() {
                Some('x') => Some(MsiexecAction::Uninstall),
                Some('i') => Some(MsiexecAction::Install),
                Some('f') => Some(MsiexecAction::Repair),
                _ => None,
            }
        };
        if found.is_some() {
            action = found;
            break;
        }
    }
    MsiexecCommand {
        action,
        product_code: find_braced_guid(args),
    }
}

/// Finds the first `{8-4-4-4-12}` hex GUID in `s`, returned upper case with braces.
pub fn find_braced_guid(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut from = 0;
    while let Some(off) = s[from..].find('{') {
        let start = from + off;
        if let Some(candidate) = s.get(start..start + 38)
            && bytes.get(start + 37) == Some(&b'}')
            && is_guid_body(&candidate[1..37])
        {
            return Some(candidate.to_ascii_uppercase());
        }
        from = start + 1;
    }
    None
}

/// True for `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` (hex, any case).
fn is_guid_body(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// Parses `rundll32` arguments: `"dll path",Entry rest` or `dll,Entry rest` or `dll rest`.
fn parse_rundll32(args: &str) -> Option<Rundll32Command> {
    let args = args.trim();
    if args.is_empty() {
        return None;
    }
    let (dll, after) = if let Some(rest) = args.strip_prefix('"') {
        let close = rest.find('"')?;
        (rest[..close].trim().to_owned(), &rest[close + 1..])
    } else {
        // An unquoted DLL path runs to the comma when there is one before any quote, else to whitespace.
        let quote = args.find('"').unwrap_or(args.len());
        let end = match args[..quote].find(',') {
            Some(comma) => comma,
            None => args.find(char::is_whitespace).unwrap_or(args.len()),
        };
        (args[..end].trim().to_owned(), &args[end..])
    };
    if dll.is_empty() {
        return None;
    }
    let after = after.trim_start();
    let (entry, rest) = match after.strip_prefix(',') {
        Some(e) => {
            let e = e.trim_start();
            let end = e.find(char::is_whitespace).unwrap_or(e.len());
            let entry = &e[..end];
            (
                (!entry.is_empty()).then(|| entry.to_owned()),
                e[end..].trim(),
            )
        }
        None => (None, after.trim()),
    };
    Some(Rundll32Command {
        dll,
        entry,
        args: rest.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sp(cmd: &str) -> (String, String) {
        let s = split(cmd).unwrap();
        (s.exe, s.args)
    }

    #[test]
    fn split_table() {
        let table: &[(&str, &str, &str)] = &[
            (
                r#""C:\Program Files\App\uninstall.exe" /S"#,
                r"C:\Program Files\App\uninstall.exe",
                "/S",
            ),
            (
                r#""C:\x\unins000.exe" /SILENT"#,
                r"C:\x\unins000.exe",
                "/SILENT",
            ),
            (r#""C:\x\unins000.exe""#, r"C:\x\unins000.exe", ""),
            (r#"  "C:\x\a.exe"/S  "#, r"C:\x\a.exe", "/S"),
            (
                r"C:\Program Files\App\uninst.exe",
                r"C:\Program Files\App\uninst.exe",
                "",
            ),
            (
                r"C:\Program Files\App\uninst.exe /S /D=x",
                r"C:\Program Files\App\uninst.exe",
                "/S /D=x",
            ),
            (
                r"C:\Program Files (x86)\My App\un.EXE _?=C:\a b",
                r"C:\Program Files (x86)\My App\un.EXE",
                "_?=C:\\a b",
            ),
            (
                "MsiExec.exe /I{12345678-90AB-CDEF-1234-567890ABCDEF}",
                "MsiExec.exe",
                "/I{12345678-90AB-CDEF-1234-567890ABCDEF}",
            ),
            (
                "MsiExec.exe/X{12345678-90AB-CDEF-1234-567890ABCDEF}",
                "MsiExec.exe",
                "/X{12345678-90AB-CDEF-1234-567890ABCDEF}",
            ),
            (
                "msiexec /x {12345678-90AB-CDEF-1234-567890ABCDEF} /qn",
                "msiexec",
                "/x {12345678-90AB-CDEF-1234-567890ABCDEF} /qn",
            ),
            (
                r#"rundll32.exe "C:\Program Files\x\y.dll",Uninstall /q"#,
                "rundll32.exe",
                r#""C:\Program Files\x\y.dll",Uninstall /q"#,
            ),
            (
                r"RunDll32 C:\PROGRA~1\x\y.dll,Entry",
                "RunDll32",
                r"C:\PROGRA~1\x\y.dll,Entry",
            ),
            (
                r#"C:\Windows\a.exe "C:\b c\d.exe""#,
                r"C:\Windows\a.exe",
                r#""C:\b c\d.exe""#,
            ),
            ("uninstall", "uninstall", ""),
            (r"C:\My.App\tool.exe -x", r"C:\My.App\tool.exe", "-x"),
            (r"C:\dir\setup.bat remove", r"C:\dir\setup.bat", "remove"),
            ("msiexec /uninstall x.msi", "msiexec", "/uninstall x.msi"),
            ("MyTool arg.exe", "MyTool", "arg.exe"),
            (
                r"%ProgramFiles%\My App\u.exe /S",
                r"%ProgramFiles%\My App\u.exe",
                "/S",
            ),
            (
                r"\\server\share\My App\u.exe /S",
                r"\\server\share\My App\u.exe",
                "/S",
            ),
            (r"C:\a\run /x C:\b\c.exe", r"C:\a\run", r"/x C:\b\c.exe"),
        ];
        for (cmd, exe, args) in table {
            assert_eq!(
                sp(cmd),
                ((*exe).to_owned(), (*args).to_owned()),
                "command: {cmd}"
            );
        }
    }

    #[test]
    fn errors() {
        assert_eq!(split("   "), Err(CmdlineError::Empty));
        assert_eq!(
            split(r#""C:\x\a.exe /S"#),
            Err(CmdlineError::UnterminatedQuote)
        );
        assert_eq!(split(r#""" /S"#), Err(CmdlineError::Empty));
    }

    #[test]
    fn probe_picks_existing_candidate() {
        let cmd = r"C:\tools.exe dir\real.exe /S";
        assert_eq!(sp(cmd).0, r"C:\tools.exe");
        let s = split_with(cmd, |p| p == r"C:\tools.exe dir\real.exe").unwrap();
        assert_eq!(
            (s.exe.as_str(), s.args.as_str()),
            (r"C:\tools.exe dir\real.exe", "/S")
        );
        // No candidate exists: fall back to the first.
        assert_eq!(split_with(cmd, |_| false).unwrap().exe, r"C:\tools.exe");
    }

    #[test]
    fn msiexec_kind() {
        let s = split("MsiExec.exe /I{12345678-90ab-cdef-1234-567890abcdef}").unwrap();
        assert_eq!(
            s.kind(),
            CommandKind::Msiexec(MsiexecCommand {
                action: Some(MsiexecAction::Install),
                product_code: Some("{12345678-90AB-CDEF-1234-567890ABCDEF}".into()),
            })
        );
        let s =
            split(r"C:\Windows\System32\msiexec.exe /qn /x {12345678-90AB-CDEF-1234-567890ABCDEF}")
                .unwrap();
        let CommandKind::Msiexec(m) = s.kind() else {
            panic!("not msiexec")
        };
        assert_eq!(m.action, Some(MsiexecAction::Uninstall));
        assert_eq!(
            m.product_code.as_deref(),
            Some("{12345678-90AB-CDEF-1234-567890ABCDEF}")
        );
        let s = split("msiexec /forcerestart /fa {12345678-90AB-CDEF-1234-567890ABCDEF}").unwrap();
        let CommandKind::Msiexec(m) = s.kind() else {
            panic!("not msiexec")
        };
        assert_eq!(m.action, Some(MsiexecAction::Repair));
        let s = split("msiexec /uninstall x.msi").unwrap();
        let CommandKind::Msiexec(m) = s.kind() else {
            panic!("not msiexec")
        };
        assert_eq!(
            (m.action, m.product_code),
            (Some(MsiexecAction::Uninstall), None)
        );
    }

    #[test]
    fn rundll32_kind() {
        let s = split(r#"rundll32.exe "C:\Program Files\x\y.dll",Uninstall /q"#).unwrap();
        assert_eq!(
            s.kind(),
            CommandKind::Rundll32(Rundll32Command {
                dll: r"C:\Program Files\x\y.dll".into(),
                entry: Some("Uninstall".into()),
                args: "/q".into(),
            })
        );
        let s = split(r"RunDll32 C:\PROGRA~1\x\y.dll,Entry").unwrap();
        let CommandKind::Rundll32(r) = s.kind() else {
            panic!("not rundll32")
        };
        assert_eq!(
            (r.dll.as_str(), r.entry.as_deref(), r.args.as_str()),
            (r"C:\PROGRA~1\x\y.dll", Some("Entry"), "")
        );
        let s = split(r"C:\Windows\SysWOW64\rundll32.exe C:\x.dll").unwrap();
        let CommandKind::Rundll32(r) = s.kind() else {
            panic!("not rundll32")
        };
        assert_eq!((r.dll.as_str(), r.entry), (r"C:\x.dll", None));
        assert_eq!(split("rundll32").unwrap().kind(), CommandKind::Other);
        assert_eq!(
            split(r#""C:\x\unins000.exe" /SILENT"#).unwrap().kind(),
            CommandKind::Other
        );
    }

    #[test]
    fn round_trip_command_line() {
        let s = split(r"C:\Program Files\App\uninst.exe /S").unwrap();
        assert_eq!(
            s.to_command_line(),
            r#""C:\Program Files\App\uninst.exe" /S"#
        );
        assert_eq!(s.file_name(), "uninst.exe");
        assert_eq!(split("msiexec").unwrap().to_command_line(), "msiexec");
    }

    #[test]
    fn braced_guid() {
        assert_eq!(
            find_braced_guid("x {nope} {12345678-90AB-CDEF-1234-567890ABCDEF}").as_deref(),
            Some("{12345678-90AB-CDEF-1234-567890ABCDEF}")
        );
        assert_eq!(
            find_braced_guid("{12345678-90AB-CDEF-1234-567890ABCDEG}"),
            None
        );
        assert_eq!(find_braced_guid("{"), None);
    }
}
