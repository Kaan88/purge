//! The built-in deny rules of ENGINE_PLAN.md §5.10, as tables. Pattern syntax: see `pattern`.
//!
//! Rule names are stable (`fs.*`, `reg.*`): they are reported in `Blocker::DenyListed` and shown to the
//! user under "Protected".

use serde::{Deserialize, Serialize};

use super::pattern::{Seg, parse_fs_pattern};
use super::{Annotation, Exempt, Matcher, Rule};
use crate::canon::GuardEnv;

const S: Annotation = Annotation::Subtree;
const E: Annotation = Annotation::Exact;
const EA: Annotation = Annotation::ExactAndAncestors;

type Row = (&'static str, Annotation, &'static str, &'static str);

/// File rules added in M1b (C-GUARD). They come before [`FS`] and the `%WINDIR%` and
/// `ProgramData\Microsoft` subtree rules, so that the more specific name is the one reported.
const M1B_FS: &[Row] = &[
    (
        "task.registry-direct",
        S,
        r"%WINDIR%\System32\Tasks",
        "Task definitions: tasks are removed through the Task Scheduler API only.",
    ),
    (
        "task.registry-direct",
        S,
        r"%WINDIR%\Tasks",
        "Task Scheduler 1.0 jobs: never offered.",
    ),
    (
        "fs.wer-root",
        EA,
        r"%ProgramData%\Microsoft\Windows\WER\ReportArchive",
        "A Windows Error Reporting store; only single reports in it are offered.",
    ),
    (
        "fs.wer-root",
        EA,
        r"%ProgramData%\Microsoft\Windows\WER\ReportQueue",
        "A Windows Error Reporting store; only single reports in it are offered.",
    ),
    (
        "fs.wer-root",
        EA,
        r"%ProgramData%\Microsoft\Windows\WER\Temp",
        "A Windows Error Reporting store; only single reports in it are offered.",
    ),
    (
        "fs.wer-root",
        EA,
        r"%LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive",
        "A Windows Error Reporting store; only single reports in it are offered.",
    ),
    (
        "fs.wer-root",
        EA,
        r"%LOCALAPPDATA%\Microsoft\Windows\WER\ReportQueue",
        "A Windows Error Reporting store; only single reports in it are offered.",
    ),
    (
        "fs.wer-root",
        EA,
        r"%LOCALAPPDATA%\Microsoft\Windows\WER\Temp",
        "A Windows Error Reporting store; only single reports in it are offered.",
    ),
];

/// The Package Cache roots as subtree rules: everything in a cache is denied unless the item lies in a
/// listed gone entry that is a direct child of the root (`Exemptions::gone_cache_dirs`). The \[E+A\]
/// rules of [`FS`] keep denying the roots and their ancestors.
const PACKAGE_CACHE_ROOTS: &[Row] = &[
    (
        "fs.package-cache",
        S,
        r"%ProgramData%\Package Cache",
        "The machine Package Cache: only a gone product's or bundle's entry is offered.",
    ),
    (
        "fs.package-cache",
        S,
        r"%LOCALAPPDATA%\Package Cache",
        "The per-user Package Cache: only a gone product's or bundle's entry is offered.",
    ),
];

/// Registry rules added in M1b (C-GUARD) that come before the M1a rules they overlap, so that their name
/// is the one reported. The COM rules from `kb/shared-iids.json` and the Installer database rules follow
/// them (see [`builtin`]).
const M1B_REG: &[Row] = &[
    (
        "fw.policy-store",
        S,
        r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall",
        "The firewall's policy store: rules are removed only as firewall rules.",
    ),
    (
        "task.registry-direct",
        S,
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
        "The Task Scheduler's cache: tasks are removed through the Task Scheduler API only.",
    ),
    (
        "msi.component-foreign",
        E,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Components\*",
        "An MSI component's client list: only a gone product's value in it is offered.",
    ),
    (
        "reg.shareddlls",
        E,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs",
        "Shared file reference counts: only single counters are offered.",
    ),
];

/// The Windows Installer database, as subtree rules lifted only by `installer_shape` (C-GUARD).
const INSTALLER_DATABASE: &[Row] = &[
    (
        "reg.installer",
        S,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer",
        "Windows Installer state.",
    ),
    (
        "reg.installer",
        S,
        r"HKU\*\SOFTWARE\Microsoft\Installer",
        "Per-user Windows Installer registration.",
    ),
    (
        "reg.installer",
        S,
        r"HKCR\Installer",
        "Windows Installer registration.",
    ),
];

/// Rules below `HKLM\SYSTEM`, which the deny-list refuses as a whole (`reg.hklm.system`); these only
/// name what a target there is. `CurrentControlSet` matches every control set.
const SYSTEM: &[Row] = &[
    (
        "fw.registry-direct",
        S,
        r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy",
        "The firewall's store: rules are removed only as firewall rules, never as registry values.",
    ),
    (
        "svc.registry-direct",
        E,
        r"HKLM\SYSTEM\CurrentControlSet\Services\*",
        "A service: removed only as a service, never as a registry key.",
    ),
    (
        "svc.registry-direct",
        E,
        r"HKLM\SYSTEM\CurrentControlSet\Services\*\Parameters",
        "A service: removed only as a service, never as a registry key.",
    ),
    (
        "svc.registry-direct",
        E,
        r"HKLM\SYSTEM\CurrentControlSet\Services\*\Security",
        "A service: removed only as a service, never as a registry key.",
    ),
    (
        "svc.registry-direct",
        E,
        r"HKLM\SYSTEM\CurrentControlSet\Services\*\TriggerInfo",
        "A service: removed only as a service, never as a registry key.",
    ),
    (
        "svc.registry-direct",
        E,
        r"HKLM\SYSTEM\CurrentControlSet\Services\*\Enum",
        "A service: removed only as a service, never as a registry key.",
    ),
    (
        "reg.eventlog-log",
        E,
        r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\*",
        "An event log: only its source keys are offered.",
    ),
];

/// One interface of `kb/shared-iids.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedIid {
    /// The IID, `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
    pub iid: String,
    /// The name as registered (not used by any rule: two IIDs carry the same registered name).
    pub name: String,
    /// Why no single app owns it.
    pub why: String,
}

/// One proxy/stub CLSID of `kb/shared-iids.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedProxyClsid {
    /// The CLSID, `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
    pub clsid: String,
    /// The name as registered.
    pub name: String,
    /// Why it is never an owner.
    pub why: String,
}

/// `kb/shared-iids.json`: interfaces many products register, and proxy/stub CLSIDs that are never an
/// owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedIids {
    /// Interfaces denied as `com.shared-iid` in every Classes view.
    pub iids: Vec<SharedIid>,
    /// CLSIDs denied as `com.shared-proxy` in every Classes view.
    pub shared_proxy_clsids: Vec<SharedProxyClsid>,
}

impl SharedIids {
    /// Whether `iid` (braced, any case) is a listed interface.
    pub fn is_shared_iid(&self, iid: &str) -> bool {
        self.iids.iter().any(|e| e.iid.eq_ignore_ascii_case(iid))
    }

    /// Whether `clsid` (braced, any case) is a listed proxy/stub CLSID: never an owner, never a
    /// candidate.
    pub fn is_shared_proxy_clsid(&self, clsid: &str) -> bool {
        self.shared_proxy_clsids
            .iter()
            .any(|e| e.clsid.eq_ignore_ascii_case(clsid))
    }
}

/// The lists embedded from `kb/shared-iids.json`.
pub fn shared_iids() -> Result<SharedIids, serde_json::Error> {
    serde_json::from_str(include_str!("../../../../kb/shared-iids.json"))
}

/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` with hex digits of either case. A malformed entry would turn
/// into a wider pattern, so the list refuses to compile instead.
fn is_braced_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && b[1..37].iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// The COM rules of `kb/shared-iids.json`: \[S\] on `Interface\{IID}` and `CLSID\{CLSID}` under every
/// Classes root (machine, both views, and every user).
fn com_rules() -> Result<Vec<Rule>, String> {
    let data = shared_iids().map_err(|e| format!("kb/shared-iids.json: {e}"))?;
    let mut out = Vec::new();
    for entry in &data.iids {
        if !is_braced_guid(&entry.iid) {
            return Err(format!("kb/shared-iids.json: bad IID {:?}", entry.iid));
        }
        let pattern = format!(r"HKCR\Interface\{}", entry.iid);
        out.push(Rule::key("com.shared-iid", S, &pattern, &entry.why)?);
    }
    for entry in &data.shared_proxy_clsids {
        if !is_braced_guid(&entry.clsid) {
            return Err(format!("kb/shared-iids.json: bad CLSID {:?}", entry.clsid));
        }
        let pattern = format!(r"HKCR\CLSID\{}", entry.clsid);
        out.push(Rule::key("com.shared-proxy", S, &pattern, &entry.why)?);
    }
    Ok(out)
}

/// The rules below `HKLM\SYSTEM` ([`SYSTEM`]).
pub(super) fn system() -> Result<Vec<Rule>, String> {
    SYSTEM
        .iter()
        .map(|(id, annotation, pattern, why)| Rule::key(id, *annotation, pattern, why))
        .collect()
}

/// File rules without a carve-out.
const FS: &[Row] = &[
    // [S] shared engine directories.
    (
        "fs.common-files.microsoft-shared",
        S,
        r"%CommonProgramFiles%\Microsoft Shared",
        "Shared Microsoft components, including Click-to-Run.",
    ),
    (
        "fs.common-files.installshield",
        S,
        r"%CommonProgramFiles%\InstallShield",
        "The shared InstallShield engine.",
    ),
    // [S] package stores.
    (
        "fs.windowsapps",
        S,
        r"%ProgramFiles%\WindowsApps",
        "Package store: removed through the deployment service only.",
    ),
    (
        "fs.packages",
        S,
        r"%LOCALAPPDATA%\Packages",
        "Per-user package data: removed with the package.",
    ),
    (
        "fs.windowsapps.user",
        S,
        r"%LOCALAPPDATA%\Microsoft\WindowsApps",
        "App execution aliases, owned by the deployment service.",
    ),
    // [S] .NET.
    (
        "fs.dotnet",
        S,
        r"%ProgramFiles%\Reference Assemblies",
        "Shared .NET reference assemblies.",
    ),
    (
        "fs.dotnet",
        S,
        r"%ProgramFiles%\dotnet",
        "The shared .NET runtime.",
    ),
    (
        "fs.dotnet",
        S,
        r"%ProgramFiles%\Microsoft.NET",
        "The shared .NET Framework.",
    ),
    // [S] secrets.
    (
        "fs.secrets",
        S,
        r"%APPDATA%\Microsoft\Protect",
        "DPAPI master keys.",
    ),
    (
        "fs.secrets",
        S,
        r"%APPDATA%\Microsoft\Credentials",
        "Stored credentials.",
    ),
    (
        "fs.secrets",
        S,
        r"%APPDATA%\Microsoft\Crypto",
        "Private keys.",
    ),
    (
        "fs.secrets",
        S,
        r"%APPDATA%\Microsoft\SystemCertificates",
        "The user's certificate stores.",
    ),
    (
        "fs.secrets",
        S,
        r"%APPDATA%\Microsoft\Vault",
        "Credential vault.",
    ),
    (
        "fs.secrets",
        S,
        r"%LOCALAPPDATA%\Microsoft\Credentials",
        "Stored credentials.",
    ),
    (
        "fs.secrets",
        S,
        r"%LOCALAPPDATA%\Microsoft\Vault",
        "Credential vault.",
    ),
    // [S] dotfiles that hold keys and tokens.
    ("fs.dotfiles", S, r"%USERPROFILE%\.ssh", "SSH keys."),
    ("fs.dotfiles", S, r"%USERPROFILE%\.gnupg", "GnuPG keys."),
    (
        "fs.dotfiles",
        S,
        r"%USERPROFILE%\.aws",
        "Cloud credentials.",
    ),
    (
        "fs.dotfiles",
        S,
        r"%USERPROFILE%\.azure",
        "Cloud credentials.",
    ),
    (
        "fs.dotfiles",
        S,
        r"%USERPROFILE%\.kube",
        "Cluster credentials.",
    ),
    (
        "fs.dotfiles",
        S,
        r"%USERPROFILE%\.docker",
        "Registry credentials.",
    ),
    (
        "fs.dotfiles",
        S,
        r"%USERPROFILE%\.gitconfig",
        "Git identity and credential helpers.",
    ),
    (
        "fs.dotfiles",
        S,
        r"%USERPROFILE%\.git-credentials",
        "Stored Git credentials.",
    ),
    (
        "fs.dotfiles",
        S,
        r"%USERPROFILE%\.npmrc",
        "Registry tokens.",
    ),
    (
        "fs.dotfiles",
        S,
        r"%USERPROFILE%\.pypirc",
        "Registry tokens.",
    ),
    ("fs.dotfiles", S, r"%USERPROFILE%\.netrc", "Stored logins."),
    // [S] the registry hive files of a profile (with their logs and transaction files).
    (
        "fs.user-hive",
        S,
        r"%USERPROFILE%\ntuser*",
        "A user's registry hive.",
    ),
    (
        "fs.user-hive",
        S,
        r"%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat*",
        "A user's classes hive.",
    ),
    // [S] volume-level system folders, on every drive.
    (
        "fs.volume-system",
        S,
        r"*:\System Volume Information",
        "Volume system data.",
    ),
    (
        "fs.volume-system",
        S,
        r"*:\$Recycle.Bin",
        "The recycle bin.",
    ),
    (
        "fs.volume-system",
        S,
        r"*:\Recovery",
        "The recovery environment.",
    ),
    ("fs.volume-system", S, r"*:\Boot", "Boot files."),
    // [S] Purge's own stores.
    ("fs.purge", S, r"%ProgramData%\Purge", "Purge's own data."),
    ("fs.purge", S, r"*:\.purge-q", "Purge's quarantine."),
    // [E+A] containers.
    (
        "fs.program-files",
        EA,
        r"%ProgramFiles%",
        "A Program Files directory.",
    ),
    (
        "fs.programdata",
        EA,
        r"%ProgramData%",
        "The ProgramData directory.",
    ),
    (
        "fs.common-files",
        EA,
        r"%CommonProgramFiles%",
        "A Common Files directory.",
    ),
    (
        "fs.package-cache",
        EA,
        r"%ProgramData%\Package Cache",
        "The machine Package Cache root.",
    ),
    (
        "fs.package-cache",
        EA,
        r"%LOCALAPPDATA%\Package Cache",
        "The per-user Package Cache root.",
    ),
    (
        "fs.local-programs",
        EA,
        r"%LOCALAPPDATA%\Programs",
        "The per-user programs root.",
    ),
    (
        "fs.installshield-info",
        EA,
        r"%ProgramFiles%\InstallShield Installation Information",
        "InstallShield's per-product store root.",
    ),
    (
        "fs.profiles-dir",
        EA,
        r"%PROFILES%",
        "The profiles directory.",
    ),
    ("fs.profile-root", EA, r"%USERPROFILE%", "A profile root."),
    // [E+A] known folders in their default places (redirected ones come from the GuardEnv).
    (
        "fs.known-folder",
        EA,
        r"%USERPROFILE%\AppData",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%USERPROFILE%\AppData\LocalLow",
        "Known folder.",
    ),
    ("fs.known-folder", EA, r"%APPDATA%", "Known folder."),
    ("fs.known-folder", EA, r"%LOCALAPPDATA%", "Known folder."),
    (
        "fs.known-folder",
        EA,
        r"%LOCALAPPDATA%\Temp",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%LOCALAPPDATA%\Microsoft\Windows",
        "Known folders (caches, history).",
    ),
    (
        "fs.known-folder",
        EA,
        r"%USERPROFILE%\Desktop",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%USERPROFILE%\Documents",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%USERPROFILE%\Downloads",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%USERPROFILE%\Pictures",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%USERPROFILE%\Videos",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%USERPROFILE%\Music",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%USERPROFILE%\Saved Games",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%USERPROFILE%\Favorites",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%USERPROFILE%\Contacts",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%USERPROFILE%\Links",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%USERPROFILE%\Searches",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%USERPROFILE%\3D Objects",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%USERPROFILE%\OneDrive",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%APPDATA%\Microsoft\Windows\Start Menu",
        "Start Menu root.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%APPDATA%\Microsoft\Windows\Start Menu\Programs",
        "Start Menu root.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
        "Startup folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%APPDATA%\Microsoft\Windows\SendTo",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%APPDATA%\Microsoft\Windows\Templates",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%APPDATA%\Microsoft\Windows\Recent",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%APPDATA%\Microsoft\Windows\Libraries",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%APPDATA%\Microsoft\Windows\Network Shortcuts",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%APPDATA%\Microsoft\Windows\Printer Shortcuts",
        "Known folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar",
        "Taskbar pins folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\StartMenu",
        "Start pins folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\ImplicitAppShortcuts",
        "Pins folder.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%ProgramData%\Microsoft\Windows\Start Menu",
        "Start Menu root.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%ProgramData%\Microsoft\Windows\Start Menu\Programs",
        "Start Menu root.",
    ),
    (
        "fs.known-folder",
        EA,
        r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup",
        "Startup folder.",
    ),
];

/// Start Menu folders that ship with Windows; \[S\] below both Programs roots. Their entries are
/// Windows' own, so not even Tier A evidence offers one (the carve-out in the `ProgramData\Microsoft`
/// rule is for an app's own shortcut or folder directly under `Programs`).
const WINDOWS_START_MENU_FOLDERS: &[&str] = &[
    "Accessories",
    "Accessibility",
    "Administrative Tools",
    "Maintenance",
    "System Tools",
    "Windows PowerShell",
    "Windows Tools",
];

/// Registry rules without flags.
const REG: &[Row] = &[
    (
        "reg.hku.top-level",
        E,
        r"HKU\*\*",
        "A top-level key of a user hive.",
    ),
    (
        "reg.hku.wow6432node",
        EA,
        r"HKU\*\SOFTWARE\WOW6432Node",
        "Structural.",
    ),
    (
        "reg.microsoft",
        EA,
        r"*\SOFTWARE\Microsoft",
        "The Microsoft vendor key.",
    ),
    (
        "reg.clients",
        EA,
        r"*\SOFTWARE\Clients",
        "Default-programs client lists.",
    ),
    (
        "reg.clients",
        E,
        r"*\SOFTWARE\Clients\*",
        "A default-programs client list.",
    ),
    // [S] policies.
    ("reg.policies", S, r"*\SOFTWARE\Policies", "Group Policy."),
    (
        "reg.policies",
        S,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
        "Group Policy.",
    ),
    (
        "reg.policies",
        S,
        r"*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Policies",
        "Group Policy.",
    ),
    // [S] system state.
    (
        "reg.shell-folders",
        S,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        "Known-folder locations.",
    ),
    (
        "reg.shell-folders",
        S,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        "Known-folder locations.",
    ),
    (
        "reg.winlogon",
        S,
        r"*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "Logon configuration.",
    ),
    (
        "reg.profilelist",
        S,
        r"*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
        "The profile list.",
    ),
    (
        "reg.ifeo",
        S,
        r"*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "Report only.",
    ),
    (
        "reg.fonts",
        S,
        r"*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts",
        "Installed fonts.",
    ),
    (
        "reg.taskcache",
        S,
        r"*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
        "Tasks are removed through the Task Scheduler API.",
    ),
    (
        "reg.cryptography",
        S,
        r"*\SOFTWARE\Microsoft\Cryptography",
        "Cryptographic configuration.",
    ),
    (
        "reg.cryptography",
        S,
        r"*\SOFTWARE\Microsoft\SystemCertificates",
        "Certificate stores.",
    ),
    (
        "reg.appmodel",
        S,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel",
        "Owned by the deployment service.",
    ),
    (
        "reg.appx",
        S,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx",
        "Owned by the deployment service.",
    ),
    (
        "reg.capability-access",
        S,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager",
        "The capability consent store.",
    ),
    (
        "reg.restart-manager",
        S,
        r"*\SOFTWARE\Microsoft\RestartManager",
        "Restart Manager session state.",
    ),
    (
        "reg.servicing",
        S,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing",
        "Windows servicing.",
    ),
    (
        "reg.sidebyside",
        S,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide",
        "The side-by-side store.",
    ),
    (
        "reg.windowsupdate",
        S,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate",
        "Windows Update.",
    ),
    (
        "reg.windowsupdate",
        S,
        r"*\SOFTWARE\Microsoft\WindowsUpdate",
        "Windows Update.",
    ),
    (
        "reg.packagedcom",
        S,
        r"HKCR\PackagedCom",
        "The packaged COM catalog.",
    ),
    (
        "reg.appmodel",
        S,
        r"HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel",
        "Owned by the deployment service.",
    ),
    (
        "reg.appcontainer",
        S,
        r"HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer",
        "AppContainer profiles are deleted with the package.",
    ),
    // [S] UserChoice.
    (
        "reg.userchoice",
        S,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\*\UserChoice",
        "Hash-protected default-app choice.",
    ),
    (
        "reg.userchoice",
        S,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\*\UserChoiceLatest",
        "Hash-protected default-app choice.",
    ),
    (
        "reg.userchoice",
        S,
        r"*\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\*\UserChoice",
        "Hash-protected default-app choice.",
    ),
    (
        "reg.userchoice",
        S,
        r"*\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\*\UserChoiceLatest",
        "Hash-protected default-app choice.",
    ),
    // [E+A] registration containers.
    (
        "reg.uninstall",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "The ARP container.",
    ),
    (
        "reg.run",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "Startup container.",
    ),
    (
        "reg.run",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "Startup container.",
    ),
    (
        "reg.run",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        "Startup container.",
    ),
    (
        "reg.run",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "Startup container.",
    ),
    (
        "reg.run",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "Startup container.",
    ),
    (
        "reg.app-paths",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        "The App Paths container.",
    ),
    (
        "reg.registered-applications",
        EA,
        r"*\SOFTWARE\RegisteredApplications",
        "The registered-applications list.",
    ),
    (
        "reg.shell-extensions",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions",
        "Shell extension lists.",
    ),
    (
        "reg.shell-extensions",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        "Shell extension lists.",
    ),
    (
        "reg.shell-extensions",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked",
        "Shell extension lists.",
    ),
    (
        "reg.shell-extensions",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached",
        "Shell extension lists.",
    ),
    // [E+A] Windows Installer containers.
    (
        "reg.installer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer",
        "Windows Installer state.",
    ),
    (
        "reg.installer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders",
        "Windows Installer state.",
    ),
    (
        "reg.installer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes",
        "Windows Installer state.",
    ),
    (
        "reg.installer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Products",
        "Windows Installer state.",
    ),
    (
        "reg.installer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Components",
        "Windows Installer state.",
    ),
    (
        "reg.installer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Products",
        "Windows Installer state.",
    ),
    (
        "reg.installer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Components",
        "Windows Installer state.",
    ),
    (
        "reg.installer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Patches",
        "Windows Installer state.",
    ),
    (
        "reg.installer",
        EA,
        r"HKU\*\SOFTWARE\Microsoft\Installer\Products",
        "Per-user Windows Installer registration.",
    ),
    (
        "reg.installer",
        EA,
        r"HKU\*\SOFTWARE\Microsoft\Installer\Features",
        "Per-user Windows Installer registration.",
    ),
    (
        "reg.installer",
        EA,
        r"HKU\*\SOFTWARE\Microsoft\Installer\Components",
        "Per-user Windows Installer registration.",
    ),
    (
        "reg.installer",
        EA,
        r"HKU\*\SOFTWARE\Microsoft\Installer\UpgradeCodes",
        "Per-user Windows Installer registration.",
    ),
    (
        "reg.installer",
        EA,
        r"HKU\*\SOFTWARE\Microsoft\Installer\Patches",
        "Per-user Windows Installer registration.",
    ),
    (
        "reg.installer",
        EA,
        r"HKCR\Installer\Products",
        "Windows Installer registration.",
    ),
    (
        "reg.installer",
        EA,
        r"HKCR\Installer\Features",
        "Windows Installer registration.",
    ),
    (
        "reg.installer",
        EA,
        r"HKCR\Installer\Components",
        "Windows Installer registration.",
    ),
    (
        "reg.installer",
        EA,
        r"HKCR\Installer\UpgradeCodes",
        "Windows Installer registration.",
    ),
    (
        "reg.installer",
        EA,
        r"HKCR\Installer\Dependencies",
        "Windows Installer registration.",
    ),
    (
        "reg.installer",
        EA,
        r"HKCR\Installer\Patches",
        "Windows Installer registration.",
    ),
    // [E+A] Explorer and the roots of its subtrees.
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        "The Explorer key.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "Explorer settings.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts",
        "Per-user file associations.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
        "Startup approvals.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\*",
        "Startup approvals.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
        "Explorer extension list.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
        "Explorer extension list.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
        "Explorer extension list.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
        "Explorer extension list.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers",
        "AutoPlay registration.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace",
        "Shell namespace.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace",
        "Shell namespace.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace",
        "Shell namespace.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions",
        "Known-folder definitions.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        "Usage data.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage",
        "Usage data.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32",
        "Dialog history.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        "Recent documents.",
    ),
    (
        "reg.explorer",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
        "Mount points.",
    ),
    // [E+A] Classes and its shared roots.
    ("reg.classes", EA, r"HKCR", "The Classes root."),
    ("reg.classes", EA, r"HKCR\CLSID", "Shared Classes root."),
    ("reg.classes", EA, r"HKCR\Interface", "Shared Classes root."),
    ("reg.classes", EA, r"HKCR\TypeLib", "Shared Classes root."),
    ("reg.classes", EA, r"HKCR\AppID", "Shared Classes root."),
    (
        "reg.classes",
        EA,
        r"HKCR\SystemFileAssociations",
        "Shared Classes root.",
    ),
    (
        "reg.classes",
        EA,
        r"HKCR\Applications",
        "Shared Classes root.",
    ),
    (
        "reg.classes",
        EA,
        r"HKCR\AppUserModelId",
        "Shared Classes root.",
    ),
    ("reg.classes", EA, r"HKCR\Installer", "Shared Classes root."),
    (
        "reg.classes",
        EA,
        r"HKCR\Local Settings",
        "Shared Classes root.",
    ),
];

/// Keys whose direct values are as structural as the key: \[E+A\] with values protected.
const REG_WITH_VALUES: &[Row] = &[
    ("reg.hive-root", EA, r"*", "A hive root."),
    (
        "reg.software",
        EA,
        r"*\SOFTWARE",
        "The SOFTWARE key (either view).",
    ),
    (
        "reg.currentversion",
        EA,
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion",
        "Windows configuration.",
    ),
    (
        "reg.nt-currentversion",
        EA,
        r"*\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "Windows configuration.",
    ),
];

/// The shell objects every app's verbs and handlers hang off. Each is \[E+A\], and so are its `shell` and
/// `shellex` roots unless the key is a `ProvenOwnedSkeleton`.
const SHELL_OBJECTS: &[&str] = &[
    "[*]",
    "AllFilesystemObjects",
    "Folder",
    "Directory",
    r"Directory\Background",
    "Drive",
    "DesktopBackground",
    "LibraryFolder",
    r"LibraryFolder\Background",
];

const SHELL_ROOTS: &[&str] = &[
    "shell",
    "shellex",
    r"shellex\ContextMenuHandlers",
    r"shellex\PropertySheetHandlers",
    r"shellex\DragDropHandlers",
    r"shellex\CopyHookHandlers",
];

/// The built-in rules plus the dynamic ones of `env`.
pub(super) fn builtin(env: &GuardEnv) -> Result<Vec<Rule>, String> {
    let mut out = Vec::new();

    // Dynamic rules first, so that the most specific name is the one reported.
    for dir in &env.purge_dirs {
        out.extend(Rule::fs_literal("fs.purge", S, dir, "A Purge directory."));
    }
    for root in &env.sync_roots {
        out.extend(Rule::fs_literal(
            "fs.sync-root",
            S,
            root,
            "A cloud sync root.",
        ));
    }
    for other in &env.other_app_roots {
        let id = format!("fs.other-app-root:{}", other.app);
        out.extend(Rule::fs_literal(
            &id,
            S,
            &other.path,
            "A root of another installed app.",
        ));
    }
    for dir in &env.protected_dirs {
        out.extend(Rule::fs_literal(
            "fs.protected-dir",
            EA,
            dir,
            "A protected directory.",
        ));
    }
    for profile in &env.profiles {
        out.extend(Rule::fs_literal(
            "fs.profile-root",
            EA,
            &profile.root,
            "A profile root.",
        ));
        for folder in profile
            .known_folders
            .iter()
            .chain(&profile.user_content_folders)
        {
            out.extend(Rule::fs_literal(
                "fs.known-folder",
                EA,
                folder,
                "Known folder.",
            ));
        }
    }

    for (id, annotation, pattern, why) in M1B_FS {
        out.extend(Rule::fs(id, *annotation, pattern, why, env)?);
    }
    for (id, annotation, pattern, why) in FS {
        out.extend(Rule::fs(id, *annotation, pattern, why, env)?);
    }
    for (id, annotation, pattern, why) in PACKAGE_CACHE_ROOTS {
        out.extend(
            Rule::fs(id, *annotation, pattern, why, env)?
                .into_iter()
                .map(|r| r.with_exempt(Exempt::GoneCache)),
        );
    }
    for folder in WINDOWS_START_MENU_FOLDERS {
        for base in ["%APPDATA%", "%ProgramData%"] {
            let pattern = format!(r"{base}\Microsoft\Windows\Start Menu\Programs\{folder}");
            let why = "A Start Menu folder that ships with Windows.";
            out.extend(Rule::fs(
                "fs.start-menu.windows-folder",
                S,
                &pattern,
                why,
                env,
            )?);
        }
    }
    for segs in [vec!["steamapps"], vec!["steamapps", "common"]] {
        let pattern = segs.join("\\");
        let matcher = Matcher::FsSuffix(segs.into_iter().map(Seg::parse).collect());
        let why = "A Steam library folder (add the library root to GuardEnv::protected_dirs).";
        out.push(Rule::new("fs.steamapps", E, &pattern, why, matcher));
    }
    // The two subtree rules with a carve-out go last: the Start Menu and container rules above still
    // apply when the carve-out lifts them.
    out.extend(
        Rule::fs("fs.windir", S, "%WINDIR%", "The Windows directory.", env)?
            .into_iter()
            .map(|r| r.with_exempt(Exempt::Prefetch)),
    );
    out.extend(
        Rule::fs(
            "fs.programdata.microsoft",
            S,
            r"%ProgramData%\Microsoft",
            "Windows' machine-wide data.",
            env,
        )?
        .into_iter()
        .map(|r| r.with_exempt(Exempt::StartMenu)),
    );

    for (id, annotation, pattern, why) in M1B_REG {
        out.push(Rule::key(id, *annotation, pattern, why)?);
    }
    out.push(
        Rule::key(
            "reg.tracing-root",
            E,
            r"*\SOFTWARE\Microsoft\Tracing",
            "The RAS tracing root: only an app's own tracing key is offered.",
        )?
        .with_values(true),
    );
    out.extend(com_rules()?);
    for (id, annotation, pattern, why) in INSTALLER_DATABASE {
        out.push(Rule::key(id, *annotation, pattern, why)?.with_exempt(Exempt::GoneInstaller));
    }
    for (id, annotation, pattern, why) in REG_WITH_VALUES {
        out.push(Rule::key(id, *annotation, pattern, why)?.with_values(true));
    }
    for (id, annotation, pattern, why) in REG {
        out.push(Rule::key(id, *annotation, pattern, why)?);
    }
    for object in SHELL_OBJECTS {
        let pattern = format!(r"HKCR\{object}");
        out.push(Rule::key(
            "reg.classes",
            EA,
            &pattern,
            "A shared shell object.",
        )?);
        for root in SHELL_ROOTS {
            let pattern = format!(r"HKCR\{object}\{root}");
            let why = "A shared verb or handler root (removable only as a proven owned skeleton).";
            out.push(
                Rule::key("reg.classes.shell-root", EA, &pattern, why)?
                    .with_exempt(Exempt::Skeleton),
            );
        }
    }
    Ok(out)
}

/// Locations at or below which no app root may live, beyond what the deny rules already refuse.
pub(super) fn root_only(env: &GuardEnv) -> Result<Vec<super::RootOnly>, String> {
    const ROWS: &[(&str, &str)] = &[
        ("root.package-cache", r"%ProgramData%\Package Cache"),
        ("root.package-cache", r"%LOCALAPPDATA%\Package Cache"),
        (
            "root.installshield-info",
            r"%ProgramFiles%\InstallShield Installation Information",
        ),
        ("root.user-content", r"%USERPROFILE%\Desktop"),
        ("root.user-content", r"%USERPROFILE%\Documents"),
        ("root.user-content", r"%USERPROFILE%\Downloads"),
        ("root.user-content", r"%USERPROFILE%\Pictures"),
        ("root.user-content", r"%USERPROFILE%\Videos"),
        ("root.user-content", r"%USERPROFILE%\Music"),
        ("root.user-content", r"%USERPROFILE%\Saved Games"),
    ];
    let mut out = Vec::new();
    for (id, pattern) in ROWS {
        out.extend(
            parse_fs_pattern(pattern, env)?
                .into_iter()
                .map(|segs| (*id, segs)),
        );
    }
    for folder in env.profiles.iter().flat_map(|p| &p.user_content_folders) {
        let segs = super::pattern::literal(folder);
        if !segs.is_empty() {
            out.push(("root.user-content", segs));
        }
    }
    Ok(out)
}
