//! Index of system objects (services, tasks, firewall rules) and the program each one runs (M1b,
//! contract C-SYSOBJ, ENGINE_PLAN.md §5.6, §5.7.2).
//!
//! Services and firewall rules are read from the registry through [`RegistrySource`]; tasks come from
//! [`SystemSource::tasks`]. Nothing here decides ownership: the readers say which program file an object
//! runs ([`ProgramRef`]), and the harvest and the scanners compare that file with an app's roots and exes.
//!
//! # Program resolution
//!
//! Every attribution of a service, task or firewall rule rests on [`resolve_program`] (command lines:
//! a service's `ImagePath`) and [`resolve_file`] (plain paths: `ServiceDll`, a firewall rule's `App=`, a
//! task's exec path). Both give [`ProgramRef::File`] only for **one** canonical, absolute drive path
//! (`purge_guard::canon::canon_path`) and [`ProgramRef::Unresolved`] for anything that cannot be told to
//! be one file:
//!
//! - an interpreter or host executable (`kb/hosts.json`: `cmd.exe`, `powershell.exe`, `rundll32.exe`,
//!   `svchost.exe`, `java.exe`, `dotnet.exe`, `py.exe`, `bash.exe`, `nssm.exe`, ...), wherever it lies
//!   and whatever its arguments are: the program that matters is in the arguments, and argument-only
//!   attribution is never Tier A;
//! - an unquoted command line any of whose blank-delimited prefixes names such a host
//!   (`C:\Python312\python scripts\run.bat`: Windows runs `python.exe` when it exists);
//! - an unquoted command line in which more than one prefix ends in a program extension
//!   (`C:\Program Files\A.exe B\c.exe`, `C:\App\x.exe C:\Data\y.exe`): which file Windows runs depends
//!   on which of them exists, and this module reads no file system;
//! - an unquoted command line with a blank and no prefix ending in a program extension (`C:\Program
//!   Files\App\tool -x`): the program's name cannot be told from its arguments;
//! - a quote that is never closed; a relative path (other than `System32\...`, which is relative to
//!   `%SystemRoot%`); a UNC or device path; a `%NAME%` left after expansion with the machine
//!   environment; a segment shaped like an 8.3 short name; anything else `canon_path` refuses.
//!
//! Command lines are split with the engine's one splitter, `purge_win::cmdline::split_with` (the one the
//! harvest and the inventory use). Its existence probe is used here only to list every candidate
//! prefix, never to look at the disk. `\SystemRoot\`, `System32\`, `\??\` and `\\?\` prefixes are
//! mapped the way the service control manager and the kernel loader read them.
//!
//! A `svchost.exe` service runs its `ServiceDll`: its program is that DLL ([`ServiceFacts::svchost`]).
//! Only the `svchost.exe` of `%SystemRoot%\System32` (or `SysWOW64`) is taken to load the DLL; a file
//! named `svchost.exe` anywhere else is just a host executable, and the service is `Unresolved`.
//!
//! # Reads
//!
//! [`read_services`] makes one `subkeys` call on the Services key and then exactly one `values` call on
//! each service key and one `value` call for `Parameters\ServiceDll`: `1 + 2 n` reads, no recursion, no
//! key below `Parameters`. [`read_firewall`] makes one `values` call on the `FirewallRules` key. Both use
//! the `CurrentControlSet` spelling, which every source maps to the control set it reports as current;
//! no other control set is read.
//!
//! # Arguments
//!
//! A program inside an app's root may still run another product's code that an argument names
//! (`"C:\App\launcher.exe" C:\Other\svc.dll`). [`argument_paths`] lists every argument that names an
//! absolute path, each as [`ProgramRef::File`] (canonical) or, when it cannot be told to be one local
//! file (a UNC path, an unexpanded `%NAME%`, a drive root, anything `canon_path` refuses),
//! [`ProgramRef::Unresolved`]. The index does not know any app's roots: the harvest and the scanners
//! treat an object as the app's only when every listed argument is a file inside a root of the app
//! (or one of its files), and never when one is `Unresolved` ([`ServiceFacts::arg_paths`],
//! [`TaskPrograms::arg_paths`]).
//!
//! What cannot be read is skipped and counted in the caller's error list; [`build`] never fails. A
//! skipped service is also missing from [`SysObjectIndex::dependents_of`]: callers that act on "no
//! dependents" must treat a non-empty [`SysObjectIndex::errors`] as "dependents unknown".

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::OnceLock;

use purge_guard::canon::{GuardEnv, canon_path};
use purge_guard::prefix::{self, eq_ci, expand_env};
use purge_model::object::{
    FirewallIdentity, FirewallRuleFields, ServiceIdentity, TaskAction, TaskIdentity,
    parse_firewall_rule,
};
use purge_source::registry::RegistrySource;
use purge_source::sysobj::TaskInfo;
use purge_source::system::SystemSource;
use purge_source::types::{REG_MULTI_SZ, REG_SZ, RegData, RegValue, SourceError};

/// The key holding one subkey per service, in the spelling every source maps to the current control set.
pub const SERVICES_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services";

/// The key whose values are the firewall rules of the local (persistent) store: value name = rule id
/// (the WMI `InstanceID`), data = the rule string.
pub const FIREWALL_RULES_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

/// `SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_RECOGNIZER_DRIVER`.
const DRIVER_TYPE_BITS: u32 = 0x1 | 0x2 | 0x8;

/// `SERVICE_USER_SERVICE`: set on per-user service templates and their instances.
const USER_SERVICE_BIT: u32 = 0x40;

/// Firewall rule fields that bind a rule to an AppX package or an AppContainer.
const PACKAGE_FIELDS: [&str; 3] = ["AppPkgId", "PFN", "LUOwn"];

/// The prefix of AppContainer and capability SIDs (`S-1-15-2-...`, `S-1-15-3-...`).
const APP_CONTAINER_SID: &str = "S-1-15-";

/// The interpreter and host list, compiled in from the knowledge base.
const HOSTS_JSON: &str = include_str!("../../../kb/hosts.json");

// ---------------------------------------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------------------------------------

/// The machine environment `%NAME%` references are expanded with: names upper-cased, values as
/// [`SystemSource::env`] returns them. An empty environment expands nothing, and every path that needs
/// a reference then stays `Unresolved`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Env {
    vars: BTreeMap<String, String>,
}

impl Env {
    /// An environment from name/value pairs; names are upper-cased (the first of two names that differ
    /// only in case wins, as in a Windows environment block).
    pub fn new<I, K, V>(vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: Into<String>,
    {
        let mut map = BTreeMap::new();
        for (name, value) in vars {
            map.entry(name.as_ref().to_uppercase())
                .or_insert_with(|| value.into());
        }
        Self { vars: map }
    }

    /// The value of one variable, by name in any case.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars.get(&name.to_uppercase()).map(String::as_str)
    }

    /// The Windows directory (`%SystemRoot%`, else `%WINDIR%`), as the environment spells it.
    pub fn windir(&self) -> Option<&str> {
        ["SYSTEMROOT", "WINDIR"]
            .iter()
            .filter_map(|name| self.vars.get(*name))
            .map(|v| v.trim())
            .find(|v| !v.is_empty())
    }

    /// `text` with every reference to a known variable replaced.
    fn expand(&self, text: &str) -> String {
        expand_env(text, &self.vars)
    }
}

// ---------------------------------------------------------------------------------------------------------
// ProgramRef and resolution
// ---------------------------------------------------------------------------------------------------------

/// The program an object runs, as far as it can be told without the file system.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProgramRef {
    /// One file, as a canonical path (`purge_guard::canon::canon_path`): `X:\seg\seg`.
    File(String),
    /// A program is named but cannot be told to be one file of the object's own (see the module
    /// docs). Never evidence of ownership.
    Unresolved {
        /// The text as stored (before expansion).
        raw: String,
    },
    /// The object names no program (a firewall rule without `App=` or with `App=System`, a COM-handler
    /// task action, an empty command).
    None,
}

impl ProgramRef {
    /// The file of [`ProgramRef::File`].
    pub fn file(&self) -> Option<&str> {
        match self {
            Self::File(path) => Some(path),
            _ => None,
        }
    }

    fn unresolved(raw: &str) -> Self {
        Self::Unresolved {
            raw: raw.to_owned(),
        }
    }
}

/// The file names of `kb/hosts.json`, lower case; `None` when the file does not parse (then every
/// program is treated as a host: nothing is attributed).
fn hosts() -> Option<&'static [String]> {
    static HOSTS: OnceLock<Option<Vec<String>>> = OnceLock::new();
    HOSTS
        .get_or_init(|| {
            let doc: serde_json::Value = serde_json::from_str(HOSTS_JSON).ok()?;
            let list = doc.get("interpreters")?.as_array()?;
            let mut out = Vec::with_capacity(list.len());
            for entry in list {
                let name = entry.as_str()?.trim().to_lowercase();
                if name.is_empty() || name.contains(['\\', '/']) {
                    return None;
                }
                out.push(name);
            }
            (!out.is_empty()).then_some(out)
        })
        .as_deref()
}

/// The interpreter and host file names of `kb/hosts.json`, lower case. Empty when the file does not
/// load (and [`is_host`] is then true for everything).
pub fn host_names() -> &'static [String] {
    hosts().unwrap_or(&[])
}

/// Whether the last segment of `program` (a path or a bare name, quotes around it ignored) is an
/// interpreter or host executable of `kb/hosts.json`, compared ignoring case. A name without an
/// extension matches with `.exe` added (`cmd`, `PowerShell`), as `CreateProcess` would run it.
pub fn is_host(program: &str) -> bool {
    let Some(hosts) = hosts() else {
        return true;
    };
    let name = program
        .trim()
        .trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let with_exe = format!("{name}.exe");
    hosts.iter().any(|h| *h == name || *h == with_exe)
}

/// The program a command line runs (a service's `ImagePath`, a `LocalServer32` command), resolved to
/// one canonical file. See the module docs for what gives `Unresolved`. An empty command gives
/// [`ProgramRef::None`].
pub fn resolve_program(raw: &str, env: &Env) -> ProgramRef {
    if host_prefix(raw, env) {
        return ProgramRef::unresolved(raw);
    }
    match command_exe(raw, env) {
        Exe::Empty => ProgramRef::None,
        Exe::Unresolved => ProgramRef::unresolved(raw),
        Exe::Path(exe, _) if is_host(&exe) => ProgramRef::unresolved(raw),
        Exe::Path(exe, _) => canonical_program(&exe, env)
            .map_or_else(|| ProgramRef::unresolved(raw), ProgramRef::File),
    }
}

/// Whether an unquoted command line, expanded, has a blank-delimited prefix that names an interpreter
/// or host (`C:\Python312\python scripts\run.bat`: whichever prefix Windows tries first may be the
/// host). A quoted command names its program exactly; [`resolve_program`] checks that one.
fn host_prefix(raw: &str, env: &Env) -> bool {
    let expanded = env.expand(raw.trim());
    let command = expanded.trim();
    !command.starts_with('"')
        && command
            .char_indices()
            .filter(|(_, c)| c.is_whitespace())
            .map(|(i, _)| &command[..i])
            .any(|prefix| !prefix.trim().is_empty() && is_host(prefix))
}

/// The file a plain path names (`ServiceDll`, `InprocServer32`, a firewall rule's `App=`, a task's exec
/// path): the whole text is the path, one pair of double quotes around it is dropped and `%NAME%`
/// references are expanded with `env`. The host rule of [`resolve_program`] applies. An empty path
/// gives [`ProgramRef::None`].
pub fn resolve_file(raw: &str, env: &Env) -> ProgramRef {
    let text = raw.trim();
    if text.is_empty() {
        return ProgramRef::None;
    }
    let inner = match text.strip_prefix('"') {
        Some(rest) => match rest.strip_suffix('"') {
            Some(inner) => inner.trim(),
            None => return ProgramRef::unresolved(raw),
        },
        None => text,
    };
    let path = env.expand(inner);
    if path.trim().is_empty() || is_host(&path) {
        return ProgramRef::unresolved(raw);
    }
    canonical_program(&path, env).map_or_else(|| ProgramRef::unresolved(raw), ProgramRef::File)
}

/// What [`command_exe`] found.
enum Exe {
    /// The command is empty.
    Empty,
    /// No single program can be told.
    Unresolved,
    /// The program, expanded, as written (not yet canonical), and the rest of the command line.
    Path(String, String),
}

/// The one program of a command line, expanded with `env`, or why there is none.
fn command_exe(raw: &str, env: &Env) -> Exe {
    if raw.trim().is_empty() {
        return Exe::Empty;
    }
    let expanded = env.expand(raw.trim());
    let command = expanded.trim();
    if command.is_empty() {
        return Exe::Unresolved;
    }
    if command.starts_with('"') {
        return match purge_win::cmdline::split(command) {
            Ok(split) => Exe::Path(split.exe, split.args),
            Err(_) => Exe::Unresolved,
        };
    }
    // Every prefix the splitter would accept as the program; the probe never answers "exists", so the
    // splitter offers each of them in turn.
    let candidates = RefCell::new(Vec::<usize>::new());
    let split = purge_win::cmdline::split_with(command, |prefix| {
        candidates.borrow_mut().push(prefix.len());
        false
    });
    let Ok(split) = split else {
        return Exe::Unresolved;
    };
    let mut candidates = candidates.into_inner();
    // A driver or DLL path the splitter has no extension for: the whole command, when it ends in one
    // and holds no quote (`C:\Program Files\Vendor\drv.sys`).
    let lower = command.to_ascii_lowercase();
    if !command.contains('"') && (lower.ends_with(".sys") || lower.ends_with(".dll")) {
        candidates.push(command.len());
    }
    candidates.sort_unstable();
    candidates.dedup();
    match candidates.as_slice() {
        [] if !command.contains(char::is_whitespace) => {
            Exe::Path(command.to_owned(), String::new())
        }
        // A blank and no program extension: where the program's name ends cannot be told.
        [] => Exe::Unresolved,
        [end] => {
            let exe = command[..*end].trim();
            debug_assert!(split.exe == exe || *end == command.len());
            Exe::Path(exe.to_owned(), command[*end..].trim().to_owned())
        }
        // Two prefixes could each be the program: Windows runs whichever exists first.
        _ => Exe::Unresolved,
    }
}

/// The arguments of a command line (a service's `ImagePath`) that name absolute paths; see
/// [`argument_paths`]. Empty when the command has no program or no arguments.
pub fn command_arguments(raw: &str, env: &Env) -> Vec<ProgramRef> {
    match command_exe(raw, env) {
        Exe::Path(_, args) => argument_paths(&args, env),
        Exe::Empty | Exe::Unresolved => Vec::new(),
    }
}

/// Every argument of `args` (blank-separated, double quotes grouping and dropped) that names an
/// absolute path, after `%NAME%` expansion with `env`: an argument that starts with `\` (UNC, `\\?\`,
/// `\??\`, `\SystemRoot\`, a path rooted on the current drive), or that holds a drive path (`C:\x`) at
/// its start or after a separator (`-config=C:\x`, `/p:C:\x`). Each is [`ProgramRef::File`] when it is one canonical local
/// file, else [`ProgramRef::Unresolved`]; an argument that still holds a `%` and a path separator is
/// `Unresolved` too. Relative arguments are not listed.
pub fn argument_paths(args: &str, env: &Env) -> Vec<ProgramRef> {
    let expanded = env.expand(args);
    let mut out = Vec::new();
    for token in arg_tokens(&expanded) {
        let token = token.trim().trim_end_matches([',', ';']);
        if token.is_empty() {
            continue;
        }
        let path = if token.starts_with('\\') {
            Some(token)
        } else {
            drive_path_start(token).map(|i| &token[i..])
        };
        match path {
            Some(path) => out.push(
                canonical_program(path, env)
                    .map_or_else(|| ProgramRef::unresolved(path), ProgramRef::File),
            ),
            None if token.contains('%') && token.contains(['\\', '/']) => {
                out.push(ProgramRef::unresolved(token));
            }
            None => {}
        }
    }
    out
}

/// The arguments of a command line, split at blanks outside double quotes, quotes dropped.
fn arg_tokens(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in args.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Where a drive path (`X:\` or `X:/`) starts in `token`: at its start or right after a character that
/// is not a letter, a digit or `/` (`=`, `:`, `,`, ...; `http://x:/` is no drive path).
fn drive_path_start(token: &str) -> Option<usize> {
    let b = token.as_bytes();
    (0..b.len().saturating_sub(2)).find(|&i| {
        b[i].is_ascii_alphabetic()
            && b[i + 1] == b':'
            && matches!(b[i + 2], b'\\' | b'/')
            && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'/'))
    })
}

/// The canonical form of a program path that `%NAME%` expansion has been applied to: `\SystemRoot\` and a
/// leading `System32\` mapped to the Windows directory, `\??\` and `\\?\` dropped by `canon_path`.
/// `None` for anything that is not one absolute local file path.
fn canonical_program(path: &str, env: &Env) -> Option<String> {
    let path = path.trim();
    // A reference expansion left behind: what it stands for is not known here.
    if path.contains('%') {
        return None;
    }
    let windir = || env.windir().filter(|w| !w.contains('%'));
    let mapped = if let Some(rest) = strip_prefix_ci(path, r"\SystemRoot\") {
        format!("{}\\{rest}", windir()?.trim_end_matches(['\\', '/']))
    } else if strip_prefix_ci(path, r"System32\").is_some() {
        format!("{}\\{path}", windir()?.trim_end_matches(['\\', '/']))
    } else {
        path.to_owned()
    };
    let canon = canon_path(&mapped, &GuardEnv::default(), None).ok()?;
    (!canon.needs_long_name && prefix::depth(&canon.path) >= 2).then_some(canon.path)
}

/// `text` without `head`, compared ignoring ASCII case.
fn strip_prefix_ci<'a>(text: &'a str, head: &str) -> Option<&'a str> {
    let start = text.get(..head.len())?;
    start
        .eq_ignore_ascii_case(head)
        .then(|| &text[head.len()..])
}

/// The canonical `svchost.exe` paths of the Windows directory (System32 and SysWOW64).
fn system_svchost(env: &Env) -> Vec<String> {
    let Some(windir) = env.windir() else {
        return Vec::new();
    };
    ["System32", "SysWOW64"]
        .iter()
        .filter_map(|dir| {
            canonical_program(
                &format!("{}\\{dir}\\svchost.exe", windir.trim_end_matches('\\')),
                env,
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------------------------------------

/// One service as the registry describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceFacts {
    /// What the object digest is computed from.
    pub identity: ServiceIdentity,
    /// `DisplayName`, as stored (may be a `@resource` reference).
    pub display_name: Option<String>,
    /// `DependOnService` entries, without group entries (`+Group`) and empty ones.
    pub depend_on: Vec<String>,
    /// `DeleteFlag` is non-zero: the service is marked for delete.
    pub delete_flag: bool,
    /// The program: the `ServiceDll` of a `svchost.exe` service, else what `ImagePath` runs.
    pub program: ProgramRef,
    /// The arguments of `ImagePath` that name absolute paths ([`argument_paths`]): the service is an
    /// app's only when each is a file of that app.
    pub arg_paths: Vec<ProgramRef>,
    /// `Type` has a driver bit (kernel, file system or recognizer driver).
    pub is_driver: bool,
    /// A per-user service: `Type` has `SERVICE_USER_SERVICE` (0x40), or the name is `<stem>_<hex>` and a
    /// service named `<stem>` exists.
    pub per_user_template: bool,
    /// `ImagePath` runs a file named `svchost.exe`.
    pub svchost: bool,
}

/// The value named `name` (case-insensitive) of a key's value list.
fn find<'a>(values: &'a [RegValue], name: &str) -> Option<&'a RegData> {
    values
        .iter()
        .find(|v| eq_ci(&v.name, name))
        .map(|v| &v.data)
}

/// A string value that must be read faithfully (it goes into the object digest): `Ok(None)` when
/// absent, `Err` when present but not a complete `REG_SZ` / `REG_EXPAND_SZ`.
fn exact_string(data: Option<&RegData>, what: &str) -> Result<Option<String>, String> {
    match data {
        None => Ok(None),
        Some(data) if data.is_complete() => data
            .string()
            .map(Some)
            .ok_or_else(|| format!("{what} is not a string (type {})", data.ty)),
        Some(_) => Err(format!("{what} is not completely known")),
    }
}

/// A DWORD that goes into the digest: 0 when absent, `Err` when present but not a DWORD.
fn exact_dword(data: Option<&RegData>, what: &str) -> Result<u32, String> {
    match data {
        None => Ok(0),
        Some(data) => data
            .dword()
            .ok_or_else(|| format!("{what} is not a DWORD (type {})", data.ty)),
    }
}

/// `DependOnService`: a `REG_MULTI_SZ` (a `REG_SZ` is read as one entry, so that no dependency is lost).
fn depend_on(data: Option<&RegData>) -> Result<Vec<String>, String> {
    let entries = match data {
        None => return Ok(Vec::new()),
        Some(data) if !data.is_complete() => {
            return Err("DependOnService is not completely known".to_owned());
        }
        Some(data) if data.ty == REG_MULTI_SZ => data.multi_sz().unwrap_or_default(),
        Some(data) if data.ty == REG_SZ => data.sz().into_iter().collect(),
        Some(data) => {
            return Err(format!(
                "DependOnService is not a string list (type {})",
                data.ty
            ));
        }
    };
    Ok(entries
        .into_iter()
        .map(|e| e.trim().to_owned())
        .filter(|e| !e.is_empty() && !e.starts_with('+'))
        .collect())
}

/// Reads every service: one `subkeys` call on [`SERVICES_KEY`], then per service one `values` call and
/// one `value` call for `Parameters\ServiceDll`. A service that cannot be read completely (its key,
/// its `Parameters\ServiceDll`, or a digest field of the wrong type) is skipped with one line in
/// `errors`. Fails only when the Services key itself cannot be listed.
pub fn read_services(
    reg: &dyn RegistrySource,
    env: &Env,
    errors: &mut Vec<String>,
) -> Result<Vec<ServiceFacts>, SourceError> {
    let names = reg.subkeys(SERVICES_KEY)?;
    let svchosts = system_svchost(env);
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let key = format!("{SERVICES_KEY}\\{name}");
        let values = match reg.values(&key) {
            Ok(values) => values,
            Err(e) => {
                errors.push(format!("sysobj: service {name}: {e}"));
                continue;
            }
        };
        let params_dll = match reg.value(&format!("{key}\\Parameters"), "ServiceDll") {
            Ok(data) => Some(data),
            Err(SourceError::NotFound) => None,
            Err(e) => {
                errors.push(format!(
                    "sysobj: service {name}: Parameters\\ServiceDll: {e}"
                ));
                continue;
            }
        };
        match service_facts(&name, &values, params_dll.as_ref(), env, &svchosts) {
            Ok(facts) => out.push(facts),
            Err(why) => errors.push(format!("sysobj: service {name}: {why}")),
        }
    }
    mark_per_user_instances(&mut out);
    Ok(out)
}

fn service_facts(
    name: &str,
    values: &[RegValue],
    params_dll: Option<&RegData>,
    env: &Env,
    svchosts: &[String],
) -> Result<ServiceFacts, String> {
    let image_path = exact_string(find(values, "ImagePath"), "ImagePath")?;
    let service_dll = match exact_string(params_dll, r"Parameters\ServiceDll")? {
        Some(dll) => Some(dll),
        None => exact_string(find(values, "ServiceDll"), "ServiceDll")?,
    };
    let service_type = exact_dword(find(values, "Type"), "Type")?;
    let start = exact_dword(find(values, "Start"), "Start")?;
    let object_name = exact_string(find(values, "ObjectName"), "ObjectName")?;
    let depend_on = depend_on(find(values, "DependOnService"))?;
    let display_name = find(values, "DisplayName").and_then(RegData::string);
    let delete_flag = find(values, "DeleteFlag")
        .and_then(RegData::dword)
        .is_some_and(|v| v != 0);

    let raw = image_path.as_deref().unwrap_or("");
    let (exe, arg_paths) = match command_exe(raw, env) {
        Exe::Path(exe, args) => (Some(exe), argument_paths(&args, env)),
        Exe::Empty | Exe::Unresolved => (None, Vec::new()),
    };
    let svchost = exe.as_deref().is_some_and(|exe| {
        exe.rsplit(['\\', '/'])
            .next()
            .is_some_and(|leaf| leaf.trim().eq_ignore_ascii_case("svchost.exe"))
    });
    let program = if svchost {
        let system = exe
            .as_deref()
            .and_then(|exe| canonical_program(exe, env))
            .is_some_and(|exe| svchosts.iter().any(|s| prefix::is_same(&exe, s)));
        match service_dll.as_deref().map(|dll| resolve_file(dll, env)) {
            Some(file @ ProgramRef::File(_)) if system => file,
            _ => ProgramRef::unresolved(raw),
        }
    } else {
        match resolve_program(raw, env) {
            ProgramRef::None => ProgramRef::unresolved(raw),
            program => program,
        }
    };
    Ok(ServiceFacts {
        identity: ServiceIdentity {
            name: name.to_owned(),
            image_path,
            service_dll,
            service_type,
            start,
            object_name,
        },
        display_name,
        depend_on,
        delete_flag,
        program,
        arg_paths,
        is_driver: service_type & DRIVER_TYPE_BITS != 0,
        per_user_template: service_type & USER_SERVICE_BIT != 0,
        svchost,
    })
}

/// Marks `<stem>_<hex>` services whose `<stem>` is a service too as per-user instances.
fn mark_per_user_instances(services: &mut [ServiceFacts]) {
    let stems: Vec<String> = services
        .iter()
        .map(|s| prefix::fold(&s.identity.name))
        .collect();
    for service in services.iter_mut() {
        let Some((stem, suffix)) = service.identity.name.rsplit_once('_') else {
            continue;
        };
        let hex = (1..=16).contains(&suffix.len()) && suffix.bytes().all(|b| b.is_ascii_hexdigit());
        if hex && !stem.is_empty() && stems.contains(&prefix::fold(stem)) {
            service.per_user_template = true;
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// Firewall rules
// ---------------------------------------------------------------------------------------------------------

/// One firewall rule of the local store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallFacts {
    /// Rule id and raw string: what the object digest is computed from.
    pub identity: FirewallIdentity,
    /// The parsed rule string.
    pub fields: FirewallRuleFields,
    /// `App=` resolved with [`resolve_file`]; `None` without `App=` or with `App=System`;
    /// `Unresolved` when the rule has more than one `App=` or `Svc=`.
    pub program: ProgramRef,
    /// `Svc=` (the first one).
    pub service: Option<String>,
    /// The rule is bound to an AppX package or AppContainer: it has an `AppPkgId`, `PFN` or `LUOwn`
    /// field, or any field holds an AppContainer SID (`S-1-15-...`).
    pub package_bound: bool,
    /// `Name=` is an indirect string (`@resource,-id`).
    pub resource_name: bool,
}

/// Reads every rule: one `values` call on [`FIREWALL_RULES_KEY`]. A value that is not a complete string
/// or does not parse (`parse_firewall_rule`) is left out with one line in `errors`. Fails only when the
/// key cannot be read.
pub fn read_firewall(
    reg: &dyn RegistrySource,
    env: &Env,
    errors: &mut Vec<String>,
) -> Result<Vec<FirewallFacts>, SourceError> {
    let values = reg.values(FIREWALL_RULES_KEY)?;
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let rule = match (value.data.is_complete(), value.data.string()) {
            (true, Some(rule)) => rule,
            _ => {
                errors.push(format!(
                    "sysobj: firewall rule {}: not a complete string (type {})",
                    value.name, value.data.ty
                ));
                continue;
            }
        };
        match parse_firewall_rule(&rule) {
            Ok(fields) => out.push(firewall_facts(value.name, rule, fields, env)),
            Err(e) => errors.push(format!("sysobj: firewall rule {}: {e}", value.name)),
        }
    }
    Ok(out)
}

fn firewall_facts(
    id: String,
    rule: String,
    fields: FirewallRuleFields,
    env: &Env,
) -> FirewallFacts {
    let apps = fields.get_all("App");
    let services = fields.get_all("Svc");
    let program = match apps.as_slice() {
        _ if services.len() > 1 => ProgramRef::unresolved(&apps.join("|")),
        [] => ProgramRef::None,
        [app] if app.trim().is_empty() || app.trim().eq_ignore_ascii_case("System") => {
            ProgramRef::None
        }
        [app] => resolve_file(app, env),
        more => ProgramRef::unresolved(&more.join("|")),
    };
    let package_bound = fields.fields.iter().any(|(key, value)| {
        PACKAGE_FIELDS.iter().any(|f| key.eq_ignore_ascii_case(f))
            || strip_prefix_ci(value.trim(), APP_CONTAINER_SID).is_some()
    });
    let resource_name = fields
        .get("Name")
        .is_some_and(|name| name.trim_start().starts_with('@'));
    FirewallFacts {
        identity: FirewallIdentity { id, rule },
        service: services.first().map(|s| (*s).to_owned()),
        program,
        package_bound,
        resource_name,
        fields,
    }
}

// ---------------------------------------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------------------------------------

/// The programs of one task's actions, in action order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPrograms {
    /// One entry per action: an exec action's path resolved with [`resolve_file`] (its arguments are
    /// ignored); [`ProgramRef::None`] for a COM handler (the scanner resolves its CLSID through the COM
    /// anchors); `Unresolved` for any other action kind.
    pub actions: Vec<ProgramRef>,
    /// One entry per action, in action order: the arguments of an exec action that name absolute paths
    /// ([`argument_paths`]); empty for other actions. An action is the app's only when each is a file
    /// of that app.
    pub arg_paths: Vec<Vec<ProgramRef>>,
}

impl TaskPrograms {
    /// Every argument path of every action.
    pub fn all_arg_paths(&self) -> impl Iterator<Item = &ProgramRef> {
        self.arg_paths.iter().flatten()
    }

    /// The files of the exec actions, when the task has at least one and **every** exec action (and
    /// every action of another kind than COM handler) resolved to a file. Callers test every file.
    /// `None` for a task without actions (a task the scanning user cannot read).
    pub fn files(&self) -> Option<Vec<&str>> {
        let mut files = Vec::new();
        for action in &self.actions {
            match action {
                ProgramRef::File(path) => {
                    if !files.contains(&path.as_str()) {
                        files.push(path.as_str());
                    }
                }
                ProgramRef::None => {}
                ProgramRef::Unresolved { .. } => return None,
            }
        }
        (!files.is_empty()).then_some(files)
    }
}

/// The programs a task's actions run.
pub fn task_programs(task: &TaskIdentity, env: &Env) -> TaskPrograms {
    TaskPrograms {
        actions: task
            .actions
            .iter()
            .map(|action| match action {
                TaskAction::Exec { path, .. } => match resolve_file(path, env) {
                    ProgramRef::None => ProgramRef::unresolved(path),
                    program => program,
                },
                TaskAction::ComHandler { .. } => ProgramRef::None,
                TaskAction::Other { kind } => ProgramRef::unresolved(kind),
            })
            .collect(),
        arg_paths: task
            .actions
            .iter()
            .map(|action| match action {
                TaskAction::Exec {
                    arguments: Some(args),
                    ..
                } => argument_paths(args, env),
                _ => Vec::new(),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------------------------------------
// The index
// ---------------------------------------------------------------------------------------------------------

/// The system objects of one machine, read once per harvest or scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SysObjectIndex {
    /// Every service that could be read.
    pub services: Vec<ServiceFacts>,
    /// Every firewall rule of the local store that could be read and parsed.
    pub firewall: Vec<FirewallFacts>,
    /// Every scheduled task the source returned.
    pub tasks: Vec<TaskInfo>,
    /// One line per list that could not be read and per object left out.
    pub errors: Vec<String>,
}

impl SysObjectIndex {
    /// The names of the services whose `DependOnService` names `service` (compared ignoring case),
    /// in index order. Only services that could be read are seen (see the module docs).
    pub fn dependents_of(&self, service: &str) -> Vec<&str> {
        let service = service.trim();
        self.services
            .iter()
            .filter(|s| s.depend_on.iter().any(|d| eq_ci(d, service)))
            .map(|s| s.identity.name.as_str())
            .collect()
    }

    /// Every rule whose `Name=` equals `display_name` (ignoring case), in index order.
    pub fn rules_named(&self, display_name: &str) -> Vec<&FirewallFacts> {
        self.firewall
            .iter()
            .filter(|r| r.fields.get("Name").is_some_and(|n| eq_ci(n, display_name)))
            .collect()
    }
}

/// Reads services, firewall rules and tasks. A list that cannot be read (`NotCaptured`, `AccessDenied`,
/// anything else) stays empty with one line in `errors`; this never fails. `%NAME%` references are
/// expanded with [`SystemSource::env`]; without it, every path that needs one stays `Unresolved`.
pub fn build(reg: &dyn RegistrySource, sys: &dyn SystemSource) -> SysObjectIndex {
    let mut index = SysObjectIndex::default();
    let env = match sys.env() {
        Ok(vars) => Env::new(vars),
        Err(e) => {
            index.errors.push(format!("sysobj: environment: {e}"));
            Env::default()
        }
    };
    match read_services(reg, &env, &mut index.errors) {
        Ok(services) => index.services = services,
        Err(e) => index.errors.push(format!("sysobj: services: {e}")),
    }
    match read_firewall(reg, &env, &mut index.errors) {
        Ok(rules) => index.firewall = rules,
        Err(e) => index.errors.push(format!("sysobj: firewall rules: {e}")),
    }
    match sys.tasks() {
        Ok(tasks) => index.tasks = tasks,
        Err(e) => index.errors.push(format!("sysobj: tasks: {e}")),
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_json_is_the_contract_list() {
        let expected = [
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
            "wscript.exe",
            "cscript.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "msiexec.exe",
            "svchost.exe",
            "dllhost.exe",
            "conhost.exe",
            "java.exe",
            "javaw.exe",
            "python.exe",
            "pythonw.exe",
            "node.exe",
            "dotnet.exe",
            "py.exe",
            "pyw.exe",
            "bash.exe",
            "sh.exe",
            "git-bash.exe",
            "perl.exe",
            "wperl.exe",
            "ruby.exe",
            "rubyw.exe",
            "php.exe",
            "php-cgi.exe",
            "php-win.exe",
            "deno.exe",
            "bun.exe",
            "nssm.exe",
            "srvany.exe",
            "winsw.exe",
            "prunsrv.exe",
            "pythonservice.exe",
            "mshta.exe",
            "wsl.exe",
            "powershell_ise.exe",
        ];
        assert_eq!(host_names(), expected);
        assert!(is_host("CMD"));
        assert!(is_host(
            r#""C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.EXE""#
        ));
        assert!(!is_host(r"C:\App\cmdx.exe"));
        assert!(!is_host("pwsh.exe.bak"));
    }

    fn env() -> Env {
        Env::new([
            ("SystemRoot", r"C:\Windows"),
            ("ProgramData", r"C:\ProgramData"),
        ])
    }

    #[test]
    fn a_host_prefix_of_an_unquoted_command_is_unresolved() {
        let env = env();
        // R2a S5: `python` without `.exe` before a relative argument.
        for raw in [
            r"C:\Python312\python scripts\run.bat",
            r"C:\Tools\dotnet C:\Other\svc.dll",
            r"C:\Program Files\dotnet\dotnet.exe C:\Other\svc.dll",
            r#""C:\Program Files\dotnet\dotnet.exe" C:\Other\svc.dll"#,
            r"C:\Tools\nssm.exe run Svc",
        ] {
            assert!(
                matches!(resolve_program(raw, &env), ProgramRef::Unresolved { .. }),
                "{raw}"
            );
        }
        assert_eq!(
            resolve_program(r"C:\Python312\pythonx.exe -m x", &env),
            ProgramRef::File(r"C:\Python312\pythonx.exe".into())
        );
    }

    #[test]
    fn argument_paths_lists_absolute_arguments() {
        let env = env();
        let got = command_arguments(
            r#""C:\App\launcher.exe" C:\Other\svc.dll -config="C:\App\a b.ini" /p:D:\x\y.txt rel\z.dll -k netsvcs \\srv\share\q.dll %ProgramData%\App\c.ini %NOPE%\d.dll C:\"#,
            &env,
        );
        assert_eq!(
            got,
            vec![
                ProgramRef::File(r"C:\Other\svc.dll".into()),
                ProgramRef::File(r"C:\App\a b.ini".into()),
                ProgramRef::File(r"D:\x\y.txt".into()),
                ProgramRef::unresolved(r"\\srv\share\q.dll"),
                ProgramRef::File(r"C:\ProgramData\App\c.ini".into()),
                ProgramRef::unresolved(r"%NOPE%\d.dll"),
                ProgramRef::unresolved(r"C:\"),
            ]
        );
        assert!(command_arguments(r"C:\App\svc.exe -run", &env).is_empty());
        assert!(command_arguments(r"C:\App\svc.exe", &env).is_empty());
        assert!(argument_paths("http://x:/y --n=5%", &env).is_empty());
    }

    #[test]
    fn strip_prefix_ci_is_char_safe() {
        assert_eq!(
            strip_prefix_ci(r"\systemroot\x", r"\SystemRoot\"),
            Some("x")
        );
        assert_eq!(strip_prefix_ci("\u{e9}\u{e9}\u{e9}", "ab"), None);
        assert_eq!(strip_prefix_ci("a", "abc"), None);
    }
}
