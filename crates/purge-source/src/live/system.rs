//! [`LiveSystem`]: [`SystemSource`] over `purge_win::{os, sid, known_folders, msi}` and the live registry
//! (ENGINE_PLAN.md §3.2, §4.1 MSI, §5.2 fingerprint `os` / `user_sid`).
//!
//! Session facts describe the **interactive user**: the account the engine runs as, unless a SID is given
//! with [`LiveSystem::for_user`] (a broker running as another account).
//!
//! - The environment ([`interactive_env`]) is rebuilt from the registry the way Windows builds a logon
//!   environment, never taken from the engine's own process: machine facts (`SystemRoot`, the `Program
//!   Files` directories, `ProgramData`, `Public`, the computer name), the system block
//!   (`HKLM\SYSTEM\ControlSet00N\Control\Session Manager\Environment`), the profile variables, the user
//!   block (`HKU\<SID>\Environment`, whose `Path` is appended to the system `Path`), then `HKU\<SID>\Volatile
//!   Environment`. In each block `REG_SZ` values are set before `REG_EXPAND_SZ` values are expanded, and
//!   names are upper-cased.
//! - Known folders come from `SHGetKnownFolderPath` when the interactive user is the engine's own account.
//!   For another user, the machine folders still come from the API and the per-user ones from that user's
//!   `User Shell Folders` ([`user_known_folders`]), expanded against that user's environment, with the
//!   Windows default layout under the profile as fallback.
//! - Profile paths are re-expanded against the machine environment built from the registry.
//!
//! - Processes ([`SystemSource::processes`]) come from a Toolhelp32 snapshot with each image path read by
//!   `QueryFullProcessImageNameW` (`purge-win` feature `read`; nothing here can start a process). Start
//!   time, session and command line are not read and stay `None`.
//! - AppX/MSIX packages ([`SystemSource::packages`], APPX-MIN) come from WinRT `PackageManager`
//!   (`purge-win` feature `appx`): machine-wide with the registered users' SIDs when the engine is
//!   elevated, otherwise the engine account's own packages, recorded for that account's SID. A package
//!   with an `EffectiveExternalPath` is sparse and that path is its external location ([`to_package_info`]).
//! - MSI tables ([`SystemSource::msi_tables`]) come from `purge_win::msi_db::read_tables` (read-only
//!   database open, one handle per call) and scheduled tasks ([`SystemSource::tasks`]) from
//!   `purge_win::taskschd::list_all` (feature `com`); `live/sysobj.rs` maps the wrappers' types and
//!   errors. A failure is an error, never an empty result.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use purge_model::{FileTime, MsiContext, OsInfo};
use purge_win::{appx, known_folders as kf, msi, os, process, sid};

use super::errors::{map_io, map_win32};
use super::registry::LiveRegistry;
use crate::fixture::expand_env;
use crate::registry::{RegistrySource, control_set_name};
use crate::sysobj::{MsiTables, TaskInfo};
use crate::system::SystemSource;
use crate::types::{
    KnownFolder, MsiContextState, MsiProduct, MsiProductState, PackageInfo, PackageSignatureKind,
    ProcessInfo, ProfileInfo, REG_EXPAND_SZ, REG_SZ, SourceResult,
};

const NT_CV: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const CV: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion";
const PROFILE_LIST: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
const USER_SHELL_FOLDERS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";

/// FILETIME ticks between 1601-01-01 and 1970-01-01.
const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;

/// Machine and session facts of the live system.
#[derive(Debug, Default)]
pub struct LiveSystem {
    /// The interactive user's SID; `None` = the account the engine runs as.
    user: Option<String>,
    registry: LiveRegistry,
}

impl LiveSystem {
    /// Facts for the account the engine runs as.
    pub fn new() -> Self {
        Self::default()
    }

    /// Facts for the interactive user with `sid` (upper-cased).
    pub fn for_user(sid: impl Into<String>) -> Self {
        Self {
            user: Some(sid.into().to_ascii_uppercase()),
            registry: LiveRegistry::new(),
        }
    }

    /// Whether the interactive user is the account the engine runs as.
    fn is_process_user(&self) -> bool {
        match &self.user {
            None => true,
            Some(u) => sid::current_user_sid().is_ok_and(|me| me.eq_ignore_ascii_case(u)),
        }
    }
}

/// A non-empty string value; `None` when missing, empty or not a string.
fn reg_string(reg: &dyn RegistrySource, key: &str, name: &str) -> Option<String> {
    reg.value(key, name)
        .ok()?
        .string()
        .filter(|s| !s.is_empty())
}

/// Sets the string values of `key` into `env`: `REG_SZ` first, then `REG_EXPAND_SZ` expanded against what
/// is set so far. With `append_path`, a `PATH` value is appended to the existing one.
fn apply_block(
    env: &mut BTreeMap<String, String>,
    reg: &dyn RegistrySource,
    key: &str,
    append_path: bool,
) {
    let Ok(values) = reg.values(key) else {
        return;
    };
    for pass in [REG_SZ, REG_EXPAND_SZ] {
        for v in values.iter().filter(|v| v.data.ty == pass) {
            let Some(raw) = v.data.string() else { continue };
            if v.name.is_empty() {
                continue;
            }
            let name = v.name.to_uppercase();
            let value = if pass == REG_EXPAND_SZ {
                expand_env(&raw, env)
            } else {
                raw
            };
            let value = match env.get("PATH") {
                Some(sys) if append_path && name == "PATH" && !sys.is_empty() => {
                    if value.is_empty() {
                        sys.clone()
                    } else {
                        format!("{};{value}", sys.trim_end_matches(';'))
                    }
                }
                _ => value,
            };
            env.insert(name, value);
        }
    }
}

/// The machine part of the environment: facts Windows derives itself plus the system block.
pub(crate) fn machine_env(reg: &dyn RegistrySource) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    fn put(env: &mut BTreeMap<String, String>, k: &str, v: String) {
        env.insert(k.to_owned(), v);
    }
    let system_root = reg_string(reg, NT_CV, "SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let drive: String = system_root.chars().take(2).collect();
    put(&mut env, "SYSTEMDRIVE", drive.clone());
    put(&mut env, "SYSTEMROOT", system_root.clone());
    put(&mut env, "WINDIR", system_root);
    let pf =
        reg_string(reg, CV, "ProgramFilesDir").unwrap_or_else(|| format!(r"{drive}\Program Files"));
    let pf86 = reg_string(reg, CV, "ProgramFilesDir (x86)")
        .unwrap_or_else(|| format!(r"{drive}\Program Files (x86)"));
    let pfw = reg_string(reg, CV, "ProgramW6432Dir").unwrap_or_else(|| pf.clone());
    let cf = reg_string(reg, CV, "CommonFilesDir").unwrap_or_else(|| format!(r"{pf}\Common Files"));
    let cf86 = reg_string(reg, CV, "CommonFilesDir (x86)")
        .unwrap_or_else(|| format!(r"{pf86}\Common Files"));
    let cfw = reg_string(reg, CV, "CommonW6432Dir").unwrap_or_else(|| cf.clone());
    put(&mut env, "PROGRAMFILES", pf);
    put(&mut env, "PROGRAMFILES(X86)", pf86);
    put(&mut env, "PROGRAMW6432", pfw);
    put(&mut env, "COMMONPROGRAMFILES", cf);
    put(&mut env, "COMMONPROGRAMFILES(X86)", cf86);
    put(&mut env, "COMMONPROGRAMW6432", cfw);
    let program_data = reg_string(reg, PROFILE_LIST, "ProgramData")
        .map(|s| expand_env(&s, &env))
        .unwrap_or_else(|| format!(r"{drive}\ProgramData"));
    let public = reg_string(reg, PROFILE_LIST, "Public")
        .map(|s| expand_env(&s, &env))
        .unwrap_or_else(|| format!(r"{drive}\Users\Public"));
    put(&mut env, "PROGRAMDATA", program_data.clone());
    put(&mut env, "ALLUSERSPROFILE", program_data);
    put(&mut env, "PUBLIC", public);
    let ccs = reg.current_control_set().ok();
    if let Some(n) = ccs {
        let set = control_set_name(n);
        if let Some(name) = reg_string(
            reg,
            &format!(r"HKLM\SYSTEM\{set}\Control\ComputerName\ComputerName"),
            "ComputerName",
        ) {
            put(&mut env, "COMPUTERNAME", name);
        }
        apply_block(
            &mut env,
            reg,
            &format!(r"HKLM\SYSTEM\{set}\Control\Session Manager\Environment"),
            false,
        );
    }
    env
}

/// The profile directory of `sid` from `ProfileList`, expanded against `env`.
fn profile_path(
    reg: &dyn RegistrySource,
    sid: &str,
    env: &BTreeMap<String, String>,
) -> Option<String> {
    reg_string(reg, &format!(r"{PROFILE_LIST}\{sid}"), "ProfileImagePath")
        .map(|p| expand_env(&p, env))
}

/// The environment block of the user with `sid`, as Windows builds it at logon (see the module docs).
/// Names are upper-cased and values expanded.
pub(crate) fn interactive_env(reg: &dyn RegistrySource, sid: &str) -> BTreeMap<String, String> {
    let mut env = machine_env(reg);
    if let Some(profile) = profile_path(reg, sid, &env) {
        let drive: String = profile.chars().take(2).collect();
        let tail: String = profile.chars().skip(2).collect();
        let user = profile.rsplit('\\').next().unwrap_or_default().to_owned();
        env.insert("HOMEDRIVE".into(), drive);
        env.insert("HOMEPATH".into(), tail);
        if !user.is_empty() {
            env.insert("USERNAME".into(), user);
        }
        env.insert("APPDATA".into(), format!(r"{profile}\AppData\Roaming"));
        env.insert("LOCALAPPDATA".into(), format!(r"{profile}\AppData\Local"));
        env.insert("USERPROFILE".into(), profile);
    }
    apply_block(&mut env, reg, &format!(r"HKU\{sid}\Environment"), true);
    apply_block(
        &mut env,
        reg,
        &format!(r"HKU\{sid}\Volatile Environment"),
        false,
    );
    env
}

/// The per-user known folders of `sid`: `User Shell Folders` expanded against `env`, with the default
/// layout under the profile for folders it does not name. Empty when the profile is unknown.
pub(crate) fn user_known_folders(
    reg: &dyn RegistrySource,
    sid: &str,
    env: &BTreeMap<String, String>,
) -> BTreeMap<KnownFolder, String> {
    let mut out = BTreeMap::new();
    let Some(profile) = env.get("USERPROFILE").cloned() else {
        return out;
    };
    let usf = format!(r"HKU\{sid}\{USER_SHELL_FOLDERS}");
    let named = |name: &str| reg_string(reg, &usf, name).map(|v| expand_env(&v, env));
    let roaming = named("AppData").unwrap_or_else(|| format!(r"{profile}\AppData\Roaming"));
    let local = named("Local AppData").unwrap_or_else(|| format!(r"{profile}\AppData\Local"));
    let start_menu =
        named("Start Menu").unwrap_or_else(|| format!(r"{roaming}\Microsoft\Windows\Start Menu"));
    let programs = named("Programs").unwrap_or_else(|| format!(r"{start_menu}\Programs"));
    let entries = [
        (KnownFolder::Profile, profile.clone()),
        (KnownFolder::RoamingAppData, roaming.clone()),
        (KnownFolder::LocalAppData, local.clone()),
        (
            KnownFolder::LocalAppDataLow,
            named("{A520A1A4-1780-4FF6-BD18-167343C5AF16}")
                .unwrap_or_else(|| format!(r"{profile}\AppData\LocalLow")),
        ),
        (KnownFolder::UserProgramFiles, format!(r"{local}\Programs")),
        (
            KnownFolder::Desktop,
            named("Desktop").unwrap_or_else(|| format!(r"{profile}\Desktop")),
        ),
        (
            KnownFolder::Documents,
            named("Personal").unwrap_or_else(|| format!(r"{profile}\Documents")),
        ),
        (
            KnownFolder::Downloads,
            named("{374DE290-123F-4565-9164-39C4925E467B}")
                .unwrap_or_else(|| format!(r"{profile}\Downloads")),
        ),
        (KnownFolder::StartMenu, start_menu),
        (
            KnownFolder::Startup,
            named("Startup").unwrap_or_else(|| format!(r"{programs}\Startup")),
        ),
        (KnownFolder::Programs, programs),
        (
            KnownFolder::Templates,
            named("Templates").unwrap_or_else(|| format!(r"{roaming}\Microsoft\Windows\Templates")),
        ),
        (
            KnownFolder::SendTo,
            named("SendTo").unwrap_or_else(|| format!(r"{roaming}\Microsoft\Windows\SendTo")),
        ),
    ];
    out.extend(entries);
    out
}

/// The source's name for a `purge-win` known folder; `None` for folders the source does not model.
pub(crate) fn to_source_folder(f: kf::KnownFolder) -> Option<KnownFolder> {
    use kf::KnownFolder as W;
    Some(match f {
        W::Windows => KnownFolder::Windows,
        W::System => KnownFolder::System,
        W::SystemX86 => KnownFolder::SystemX86,
        W::Fonts => KnownFolder::Fonts,
        W::ProgramFiles => KnownFolder::ProgramFiles,
        W::ProgramFilesX86 => KnownFolder::ProgramFilesX86,
        W::ProgramFilesCommon => KnownFolder::ProgramFilesCommon,
        W::ProgramFilesCommonX86 => KnownFolder::ProgramFilesCommonX86,
        W::ProgramData => KnownFolder::ProgramData,
        W::Public => KnownFolder::Public,
        W::PublicDesktop => KnownFolder::PublicDesktop,
        W::CommonStartMenu => KnownFolder::CommonStartMenu,
        W::CommonPrograms => KnownFolder::CommonPrograms,
        W::CommonStartup => KnownFolder::CommonStartup,
        W::Profile => KnownFolder::Profile,
        W::RoamingAppData => KnownFolder::RoamingAppData,
        W::LocalAppData => KnownFolder::LocalAppData,
        W::LocalAppDataLow => KnownFolder::LocalAppDataLow,
        W::UserProgramFiles => KnownFolder::UserProgramFiles,
        W::Desktop => KnownFolder::Desktop,
        W::Documents => KnownFolder::Documents,
        W::Downloads => KnownFolder::Downloads,
        W::StartMenu => KnownFolder::StartMenu,
        W::Programs => KnownFolder::Programs,
        W::Startup => KnownFolder::Startup,
        W::Templates => KnownFolder::Templates,
        W::SendTo => KnownFolder::SendTo,
        W::Pictures
        | W::Videos
        | W::Music
        | W::SavedGames
        | W::Favorites
        | W::UserProfiles
        | W::PublicDocuments
        | W::UserProgramFilesCommon
        | W::CommonTemplates
        | W::Recent
        | W::QuickLaunch
        | W::UserPinned => return None,
    })
}

fn to_model_context(c: msi::MsiContext) -> MsiContext {
    match c {
        msi::MsiContext::Machine => MsiContext::Machine,
        msi::MsiContext::UserManaged => MsiContext::UserManaged,
        msi::MsiContext::UserUnmanaged => MsiContext::UserUnmanaged,
    }
}

fn to_source_state(s: msi::MsiProductState) -> MsiProductState {
    match s {
        msi::MsiProductState::Unknown => MsiProductState::Unknown,
        msi::MsiProductState::Advertised => MsiProductState::Advertised,
        msi::MsiProductState::Absent => MsiProductState::Absent,
        msi::MsiProductState::Installed => MsiProductState::Default,
        msi::MsiProductState::Other(v) => MsiProductState::from_raw(v),
    }
}

fn to_signature_kind(k: Option<appx::SignatureKind>) -> PackageSignatureKind {
    match k {
        Some(appx::SignatureKind::None) => PackageSignatureKind::None,
        Some(appx::SignatureKind::Developer) => PackageSignatureKind::Developer,
        Some(appx::SignatureKind::Enterprise) => PackageSignatureKind::Enterprise,
        Some(appx::SignatureKind::Store) => PackageSignatureKind::Store,
        Some(appx::SignatureKind::System) => PackageSignatureKind::System,
        Some(appx::SignatureKind::Other(_)) | None => PackageSignatureKind::Unknown,
    }
}

/// One `purge-win` package as the source's [`PackageInfo`].
///
/// `EffectiveExternalPath` becomes the external location and marks the package sparse. `users` are the
/// SIDs `FindUsers` reported (every registration state, as the rig lists record them), upper-cased; a
/// current-user listing reports none, so `listed_for` (the SID the listing was made for) is used instead.
pub(crate) fn to_package_info(p: appx::AppxPackage, listed_for: Option<&str>) -> PackageInfo {
    let mut users: Vec<String> = p
        .users
        .iter()
        .map(|u| u.sid.to_ascii_uppercase())
        .filter(|s| !s.is_empty())
        .collect();
    if users.is_empty()
        && let Some(sid) = listed_for
    {
        users.push(sid.to_ascii_uppercase());
    }
    users.dedup();
    let sparse = p.effective_external_path.is_some();
    PackageInfo {
        full_name: p.full_name,
        family: p.family_name,
        install_location: p.installed_location,
        external_location: p.effective_external_path,
        sparse,
        users,
        is_framework: p.is_framework,
        is_resource: p.is_resource_package,
        signature_kind: to_signature_kind(p.signature_kind),
    }
}

/// One Toolhelp32 entry as the source's [`ProcessInfo`], with the image path when it could be read.
fn to_process_info(e: process::ProcessEntry, path: Option<std::path::PathBuf>) -> ProcessInfo {
    ProcessInfo {
        pid: e.pid,
        ppid: Some(e.parent_pid),
        name: e.exe_file,
        path: path.map(path_string),
        start: None,
        session: None,
        cmd: None,
    }
}

fn path_string(p: std::path::PathBuf) -> String {
    p.into_os_string()
        .into_string()
        .unwrap_or_else(|os| os.to_string_lossy().into_owned())
}

impl SystemSource for LiveSystem {
    fn os_info(&self) -> SourceResult<OsInfo> {
        let v = os::os_version().map_err(map_win32)?;
        Ok(OsInfo {
            edition: v.edition_id,
            build: v.build,
            ubr: v.ubr,
        })
    }

    fn user_sid(&self) -> SourceResult<String> {
        match &self.user {
            Some(s) => Ok(s.clone()),
            None => sid::current_user_sid().map_err(map_win32),
        }
    }

    fn elevated(&self) -> bool {
        sid::is_elevated().unwrap_or(false)
    }

    fn profiles(&self) -> SourceResult<Vec<ProfileInfo>> {
        let env = machine_env(&self.registry);
        Ok(sid::profiles()
            .map_err(map_win32)?
            .into_iter()
            .map(|p| ProfileInfo {
                path: expand_env(&p.raw_path, &env),
                sid: p.sid,
            })
            .collect())
    }

    fn known_folders(&self) -> SourceResult<BTreeMap<KnownFolder, String>> {
        let process_user = self.is_process_user();
        let mut out: BTreeMap<KnownFolder, String> = kf::all_known_folders()
            .into_iter()
            .filter_map(|(f, p)| Some((to_source_folder(f)?, path_string(p))))
            .filter(|(f, _)| process_user || !f.is_per_user())
            .collect();
        if !process_user {
            let sid = self.user_sid()?;
            let env = interactive_env(&self.registry, &sid);
            out.extend(user_known_folders(&self.registry, &sid, &env));
        }
        Ok(out)
    }

    fn env(&self) -> SourceResult<BTreeMap<String, String>> {
        let sid = self.user_sid()?;
        Ok(interactive_env(&self.registry, &sid))
    }

    fn machine_env(&self) -> SourceResult<BTreeMap<String, String>> {
        Ok(machine_env(&self.registry))
    }

    fn processes(&self) -> SourceResult<Vec<ProcessInfo>> {
        Ok(process::snapshot_processes()
            .map_err(|e| map_io(&e))?
            .into_iter()
            .map(|e| {
                // A process that exited or cannot be opened (protected, other session) keeps its entry.
                let path = process::process_image_path(e.pid).ok().flatten();
                to_process_info(e, path)
            })
            .collect())
    }

    fn msi_products(&self) -> SourceResult<Vec<MsiProduct>> {
        let refs = if self.elevated() {
            msi::enum_products(msi::EnumScope::AllUsers)
                .or_else(|_| msi::enum_products(msi::EnumScope::CurrentUser))
        } else {
            msi::enum_products(msi::EnumScope::CurrentUser)
        }
        .map_err(|e| map_io(&e))?;
        Ok(refs
            .into_iter()
            .map(|r| {
                // A product that vanished or cannot be read keeps its identity without properties.
                let info = msi::product_info(&r).unwrap_or_default();
                MsiProduct {
                    code: r.product_code.to_ascii_uppercase(),
                    context: to_model_context(r.context),
                    user_sid: r.user_sid,
                    name: info.product_name,
                    version: info.version,
                    publisher: info.publisher,
                    install_location: info.install_location,
                    local_package: info.local_package,
                    install_date: info.install_date,
                }
            })
            .collect())
    }

    fn msi_product_state_all(&self, code: &str) -> SourceResult<Vec<MsiContextState>> {
        Ok(msi::product_state_all_contexts(code)
            .map_err(|e| map_io(&e))?
            .into_iter()
            .map(|(c, s)| MsiContextState {
                context: to_model_context(c),
                state: to_source_state(s),
            })
            .collect())
    }

    fn packages(&self) -> SourceResult<Vec<PackageInfo>> {
        let machine_wide = if self.elevated() {
            appx::list_packages(appx::AppxScope::AllUsers).ok()
        } else {
            None
        };
        let (packages, listed_for) = match machine_wide {
            Some(list) => (list, None),
            None => (
                appx::list_packages(appx::AppxScope::CurrentUser).map_err(|e| map_io(&e))?,
                // `FindPackagesByUserSecurityId("")` lists the engine account's own packages.
                sid::current_user_sid().ok(),
            ),
        };
        Ok(packages
            .into_iter()
            .map(|p| to_package_info(p, listed_for.as_deref()))
            .collect())
    }

    fn msi_tables(&self, local_package: &str) -> SourceResult<MsiTables> {
        super::sysobj::msi_tables(local_package)
    }

    fn tasks(&self) -> SourceResult<Vec<TaskInfo>> {
        super::sysobj::tasks()
    }

    fn now(&self) -> FileTime {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let ticks = u64::try_from(since_epoch.as_nanos() / 100).unwrap_or(u64::MAX);
        FileTime(UNIX_EPOCH_TICKS.saturating_add(ticks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::Fixture;

    const SID: &str = "S-1-5-21-1-2-3-1001";
    const SM_ENV: &str = r"HKLM\SYSTEM\ControlSet001\Control\Session Manager\Environment";

    fn machine() -> crate::fixture::FixtureBuilder {
        Fixture::builder()
            .sz(NT_CV, "SystemRoot", r"D:\WINDOWS")
            .sz(CV, "ProgramFilesDir", r"D:\Program Files")
            .sz(PROFILE_LIST, "ProgramData", r"%SystemDrive%\ProgramData")
            .expand_sz(
                &format!(r"{PROFILE_LIST}\{SID}"),
                "ProfileImagePath",
                r"%SystemDrive%\Users\tester",
            )
            .sz(
                r"HKLM\SYSTEM\ControlSet001\Control\ComputerName\ComputerName",
                "ComputerName",
                "BOX",
            )
            .expand_sz(SM_ENV, "Path", r"%SystemRoot%\system32;%SystemRoot%")
            .sz(SM_ENV, "OS", "Windows_NT")
            .expand_sz(SM_ENV, "TEMP", r"%SystemRoot%\TEMP")
    }

    #[test]
    fn env_blocks_in_windows_order() {
        let f = machine()
            .expand_sz(
                &format!(r"HKU\{SID}\Environment"),
                "Path",
                r"%USERPROFILE%\bin",
            )
            .expand_sz(
                &format!(r"HKU\{SID}\Environment"),
                "TEMP",
                r"%USERPROFILE%\AppData\Local\Temp",
            )
            .sz(&format!(r"HKU\{SID}\Environment"), "MyVar", "x")
            .sz(
                &format!(r"HKU\{SID}\Volatile Environment"),
                "USERNAME",
                "Tester",
            )
            .sz(
                &format!(r"HKU\{SID}\Volatile Environment"),
                "APPDATA",
                r"E:\Roaming",
            )
            .build();
        let env = interactive_env(&f, SID);
        let get = |k: &str| env.get(k).map(String::as_str);
        assert_eq!(get("SYSTEMDRIVE"), Some("D:"));
        assert_eq!(get("WINDIR"), Some(r"D:\WINDOWS"));
        assert_eq!(get("PROGRAMFILES"), Some(r"D:\Program Files"));
        assert_eq!(get("PROGRAMFILES(X86)"), Some(r"D:\Program Files (x86)"));
        assert_eq!(
            get("COMMONPROGRAMFILES"),
            Some(r"D:\Program Files\Common Files")
        );
        assert_eq!(get("PROGRAMDATA"), Some(r"D:\ProgramData"));
        assert_eq!(get("COMPUTERNAME"), Some("BOX"));
        assert_eq!(get("OS"), Some("Windows_NT"));
        assert_eq!(get("USERPROFILE"), Some(r"D:\Users\tester"));
        assert_eq!(get("HOMEPATH"), Some(r"\Users\tester"));
        // The user's TEMP overrides the system one; the user's Path is appended.
        assert_eq!(get("TEMP"), Some(r"D:\Users\tester\AppData\Local\Temp"));
        assert_eq!(
            get("PATH"),
            Some(r"D:\WINDOWS\system32;D:\WINDOWS;D:\Users\tester\bin")
        );
        assert_eq!(get("MYVAR"), Some("x"));
        // Volatile Environment wins last.
        assert_eq!(get("USERNAME"), Some("Tester"));
        assert_eq!(get("APPDATA"), Some(r"E:\Roaming"));
        assert_eq!(get("LOCALAPPDATA"), Some(r"D:\Users\tester\AppData\Local"));
        assert!(env.keys().all(|k| *k == k.to_uppercase()));
    }

    #[test]
    fn env_without_profile_still_has_machine_part() {
        let env = interactive_env(&machine().build(), "S-1-5-21-9-9-9-9");
        assert_eq!(
            env.get("SYSTEMROOT").map(String::as_str),
            Some(r"D:\WINDOWS")
        );
        assert!(!env.contains_key("USERPROFILE"));
    }

    #[test]
    fn user_folders_from_user_shell_folders_with_defaults() {
        let usf = format!(r"HKU\{SID}\{USER_SHELL_FOLDERS}");
        let f = machine()
            .expand_sz(&usf, "Personal", r"E:\Docs")
            .expand_sz(&usf, "AppData", r"%USERPROFILE%\Roam")
            .build();
        let env = interactive_env(&f, SID);
        let kf = user_known_folders(&f, SID, &env);
        let get = |k: KnownFolder| kf.get(&k).map(String::as_str);
        assert_eq!(get(KnownFolder::Documents), Some(r"E:\Docs"));
        assert_eq!(
            get(KnownFolder::RoamingAppData),
            Some(r"D:\Users\tester\Roam")
        );
        assert_eq!(
            get(KnownFolder::StartMenu),
            Some(r"D:\Users\tester\Roam\Microsoft\Windows\Start Menu")
        );
        assert_eq!(
            get(KnownFolder::Startup),
            Some(r"D:\Users\tester\Roam\Microsoft\Windows\Start Menu\Programs\Startup")
        );
        assert_eq!(
            get(KnownFolder::UserProgramFiles),
            Some(r"D:\Users\tester\AppData\Local\Programs")
        );
        assert!(kf.keys().all(|k| k.is_per_user()));
        assert_eq!(
            kf.len(),
            KnownFolder::ALL.iter().filter(|k| k.is_per_user()).count()
        );
        assert!(user_known_folders(&f, "S-1-5-21-9", &BTreeMap::new()).is_empty());
    }

    #[test]
    fn every_source_folder_has_a_win32_source() {
        let mapped: Vec<KnownFolder> = kf::KnownFolder::ALL
            .iter()
            .filter_map(|&f| to_source_folder(f))
            .collect();
        for f in KnownFolder::ALL {
            assert!(mapped.contains(&f), "{f} has no purge-win folder");
        }
    }

    fn appx(full_name: &str) -> appx::AppxPackage {
        appx::AppxPackage {
            full_name: full_name.into(),
            family_name: "Contoso.App_8wekyb3d8bbwe".into(),
            installed_location: Some(r"C:\Program Files\WindowsApps\Contoso.App".into()),
            effective_external_path: None,
            signature_kind: None,
            is_framework: false,
            is_resource_package: false,
            users: Vec::new(),
            dependencies: None,
        }
    }

    #[test]
    fn appx_package_maps_to_package_info() {
        let mut p = appx("Contoso.App_1.0.0.0_x64__8wekyb3d8bbwe");
        p.effective_external_path = Some(r"C:\Program Files\Contoso".into());
        p.signature_kind = Some(appx::SignatureKind::Developer);
        p.is_framework = true;
        p.users = vec![
            appx::AppxUser {
                sid: "s-1-5-21-1-2-3-1001".into(),
                install_state: appx::AppxInstallState::Installed,
            },
            appx::AppxUser {
                sid: "S-1-5-21-1-2-3-1002".into(),
                install_state: appx::AppxInstallState::Staged,
            },
        ];
        let info = to_package_info(p, Some(SID));
        assert_eq!(info.full_name, "Contoso.App_1.0.0.0_x64__8wekyb3d8bbwe");
        assert_eq!(info.family, "Contoso.App_8wekyb3d8bbwe");
        assert_eq!(
            info.install_location.as_deref(),
            Some(r"C:\Program Files\WindowsApps\Contoso.App")
        );
        assert_eq!(
            info.external_location.as_deref(),
            Some(r"C:\Program Files\Contoso")
        );
        assert!(info.sparse && info.is_sparse());
        // FindUsers wins over the listing's user; SIDs are upper-cased.
        assert_eq!(info.users, ["S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"]);
        assert!(info.is_framework && !info.is_resource);
        assert_eq!(info.signature_kind, PackageSignatureKind::Developer);
    }

    #[test]
    fn current_user_package_is_recorded_for_the_listing_user() {
        let mut p = appx("Contoso.App_1.0.0.0_neutral_split.scale-200_8wekyb3d8bbwe");
        p.is_resource_package = true;
        let info = to_package_info(p.clone(), Some("s-1-5-21-1-2-3-1001"));
        assert_eq!(info.users, ["S-1-5-21-1-2-3-1001"]);
        assert!(!info.sparse && !info.is_sparse());
        assert_eq!(info.external_location, None);
        assert!(info.is_resource);
        assert_eq!(info.signature_kind, PackageSignatureKind::Unknown);
        assert!(to_package_info(p, None).users.is_empty());
    }

    #[test]
    fn signature_kinds_map() {
        use appx::SignatureKind as W;
        for (w, s) in [
            (Some(W::None), PackageSignatureKind::None),
            (Some(W::Developer), PackageSignatureKind::Developer),
            (Some(W::Enterprise), PackageSignatureKind::Enterprise),
            (Some(W::Store), PackageSignatureKind::Store),
            (Some(W::System), PackageSignatureKind::System),
            (Some(W::Other(9)), PackageSignatureKind::Unknown),
            (None, PackageSignatureKind::Unknown),
        ] {
            assert_eq!(to_signature_kind(w), s);
        }
    }

    #[test]
    fn process_entry_maps_to_process_info() {
        let e = process::ProcessEntry {
            pid: 42,
            parent_pid: 7,
            exe_file: "Code.exe".into(),
        };
        let info = to_process_info(e.clone(), Some(r"C:\Apps\Code.exe".into()));
        assert_eq!(
            (info.pid, info.ppid, info.name.as_str()),
            (42, Some(7), "Code.exe")
        );
        assert_eq!(info.path.as_deref(), Some(r"C:\Apps\Code.exe"));
        assert_eq!((info.start, info.session, info.cmd), (None, None, None));
        assert_eq!(to_process_info(e, None).path, None);
    }

    #[test]
    fn now_is_after_2025() {
        assert!(LiveSystem::new().now() > FileTime::from_unix_secs(1_735_689_600));
    }
}
