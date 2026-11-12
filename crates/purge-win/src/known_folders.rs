//! Known Folder paths for the current user (`SHGetKnownFolderPath`).
//!
//! The set is the folders ENGINE_PLAN.md §5.2 (`validate_root`: Known Folders and user-content
//! folders) and §5.10 (deny-list: profile roots, `Program Files*`, `ProgramData`,
//! `%LOCALAPPDATA%\Programs`, Start Menu, every KNOWNFOLDERID of every profile) name. Paths are
//! resolved with `KF_FLAG_DONT_VERIFY`, so nothing is created and an unavailable redirected folder
//! still yields its configured path. Other profiles' folders are derived by `purge-source` from
//! `ProfileList` and the user's `User Shell Folders`, not here.
#![cfg(feature = "read")]

use std::path::PathBuf;
use std::ptr;

use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_CommonPrograms, FOLDERID_CommonStartMenu, FOLDERID_CommonStartup,
    FOLDERID_CommonTemplates, FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Downloads,
    FOLDERID_Favorites, FOLDERID_Fonts, FOLDERID_LocalAppData, FOLDERID_LocalAppDataLow,
    FOLDERID_Music, FOLDERID_Pictures, FOLDERID_Profile, FOLDERID_ProgramData,
    FOLDERID_ProgramFiles, FOLDERID_ProgramFilesCommon, FOLDERID_ProgramFilesCommonX86,
    FOLDERID_ProgramFilesX86, FOLDERID_Programs, FOLDERID_Public, FOLDERID_PublicDesktop,
    FOLDERID_PublicDocuments, FOLDERID_QuickLaunch, FOLDERID_Recent, FOLDERID_RoamingAppData,
    FOLDERID_SavedGames, FOLDERID_SendTo, FOLDERID_StartMenu, FOLDERID_Startup, FOLDERID_System,
    FOLDERID_SystemX86, FOLDERID_Templates, FOLDERID_UserPinned, FOLDERID_UserProfiles,
    FOLDERID_UserProgramFiles, FOLDERID_UserProgramFilesCommon, FOLDERID_Videos, FOLDERID_Windows,
    KF_FLAG_DONT_VERIFY, SHGetKnownFolderPath,
};
use windows_sys::core::GUID;

use crate::os::{Win32Error, from_wide_ptr};

/// The Known Folders the engine reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KnownFolder {
    /// `FOLDERID_Desktop`.
    Desktop,
    /// `FOLDERID_Documents`.
    Documents,
    /// `FOLDERID_Downloads`.
    Downloads,
    /// `FOLDERID_Pictures`.
    Pictures,
    /// `FOLDERID_Videos`.
    Videos,
    /// `FOLDERID_Music`.
    Music,
    /// `FOLDERID_SavedGames`.
    SavedGames,
    /// `FOLDERID_Favorites`.
    Favorites,
    /// `FOLDERID_Profile` (`%USERPROFILE%`).
    Profile,
    /// `FOLDERID_UserProfiles` (`C:\Users`).
    UserProfiles,
    /// `FOLDERID_Public`.
    Public,
    /// `FOLDERID_PublicDesktop`.
    PublicDesktop,
    /// `FOLDERID_PublicDocuments`.
    PublicDocuments,
    /// `FOLDERID_RoamingAppData` (`%APPDATA%`).
    RoamingAppData,
    /// `FOLDERID_LocalAppData` (`%LOCALAPPDATA%`).
    LocalAppData,
    /// `FOLDERID_LocalAppDataLow`.
    LocalAppDataLow,
    /// `FOLDERID_UserProgramFiles` (`%LOCALAPPDATA%\Programs`).
    UserProgramFiles,
    /// `FOLDERID_UserProgramFilesCommon` (`%LOCALAPPDATA%\Programs\Common`).
    UserProgramFilesCommon,
    /// `FOLDERID_ProgramData`.
    ProgramData,
    /// `FOLDERID_ProgramFiles` (native `Program Files` in a 64-bit process).
    ProgramFiles,
    /// `FOLDERID_ProgramFilesX86`.
    ProgramFilesX86,
    /// `FOLDERID_ProgramFilesCommon`.
    ProgramFilesCommon,
    /// `FOLDERID_ProgramFilesCommonX86`.
    ProgramFilesCommonX86,
    /// `FOLDERID_Windows` (`%WINDIR%`).
    Windows,
    /// `FOLDERID_System` (`System32`).
    System,
    /// `FOLDERID_SystemX86` (`SysWOW64`).
    SystemX86,
    /// `FOLDERID_Fonts`.
    Fonts,
    /// `FOLDERID_StartMenu` (per user).
    StartMenu,
    /// `FOLDERID_Programs` (per-user Start Menu `Programs`).
    Programs,
    /// `FOLDERID_Startup` (per user).
    Startup,
    /// `FOLDERID_CommonStartMenu`.
    CommonStartMenu,
    /// `FOLDERID_CommonPrograms`.
    CommonPrograms,
    /// `FOLDERID_CommonStartup`.
    CommonStartup,
    /// `FOLDERID_Templates`.
    Templates,
    /// `FOLDERID_CommonTemplates`.
    CommonTemplates,
    /// `FOLDERID_SendTo`.
    SendTo,
    /// `FOLDERID_Recent`.
    Recent,
    /// `FOLDERID_QuickLaunch`.
    QuickLaunch,
    /// `FOLDERID_UserPinned` (taskbar / Start pins under Quick Launch).
    UserPinned,
}

impl KnownFolder {
    /// Every variant, in declaration order.
    pub const ALL: [KnownFolder; 39] = [
        KnownFolder::Desktop,
        KnownFolder::Documents,
        KnownFolder::Downloads,
        KnownFolder::Pictures,
        KnownFolder::Videos,
        KnownFolder::Music,
        KnownFolder::SavedGames,
        KnownFolder::Favorites,
        KnownFolder::Profile,
        KnownFolder::UserProfiles,
        KnownFolder::Public,
        KnownFolder::PublicDesktop,
        KnownFolder::PublicDocuments,
        KnownFolder::RoamingAppData,
        KnownFolder::LocalAppData,
        KnownFolder::LocalAppDataLow,
        KnownFolder::UserProgramFiles,
        KnownFolder::UserProgramFilesCommon,
        KnownFolder::ProgramData,
        KnownFolder::ProgramFiles,
        KnownFolder::ProgramFilesX86,
        KnownFolder::ProgramFilesCommon,
        KnownFolder::ProgramFilesCommonX86,
        KnownFolder::Windows,
        KnownFolder::System,
        KnownFolder::SystemX86,
        KnownFolder::Fonts,
        KnownFolder::StartMenu,
        KnownFolder::Programs,
        KnownFolder::Startup,
        KnownFolder::CommonStartMenu,
        KnownFolder::CommonPrograms,
        KnownFolder::CommonStartup,
        KnownFolder::Templates,
        KnownFolder::CommonTemplates,
        KnownFolder::SendTo,
        KnownFolder::Recent,
        KnownFolder::QuickLaunch,
        KnownFolder::UserPinned,
    ];

    /// The user-content folders a root may never be inside (ENGINE_PLAN.md §5.2): Documents,
    /// Desktop, Downloads, Pictures, Videos, Music, Saved Games.
    pub fn is_user_content(self) -> bool {
        matches!(
            self,
            KnownFolder::Documents
                | KnownFolder::Desktop
                | KnownFolder::Downloads
                | KnownFolder::Pictures
                | KnownFolder::Videos
                | KnownFolder::Music
                | KnownFolder::SavedGames
        )
    }

    fn id(self) -> &'static GUID {
        match self {
            KnownFolder::Desktop => &FOLDERID_Desktop,
            KnownFolder::Documents => &FOLDERID_Documents,
            KnownFolder::Downloads => &FOLDERID_Downloads,
            KnownFolder::Pictures => &FOLDERID_Pictures,
            KnownFolder::Videos => &FOLDERID_Videos,
            KnownFolder::Music => &FOLDERID_Music,
            KnownFolder::SavedGames => &FOLDERID_SavedGames,
            KnownFolder::Favorites => &FOLDERID_Favorites,
            KnownFolder::Profile => &FOLDERID_Profile,
            KnownFolder::UserProfiles => &FOLDERID_UserProfiles,
            KnownFolder::Public => &FOLDERID_Public,
            KnownFolder::PublicDesktop => &FOLDERID_PublicDesktop,
            KnownFolder::PublicDocuments => &FOLDERID_PublicDocuments,
            KnownFolder::RoamingAppData => &FOLDERID_RoamingAppData,
            KnownFolder::LocalAppData => &FOLDERID_LocalAppData,
            KnownFolder::LocalAppDataLow => &FOLDERID_LocalAppDataLow,
            KnownFolder::UserProgramFiles => &FOLDERID_UserProgramFiles,
            KnownFolder::UserProgramFilesCommon => &FOLDERID_UserProgramFilesCommon,
            KnownFolder::ProgramData => &FOLDERID_ProgramData,
            KnownFolder::ProgramFiles => &FOLDERID_ProgramFiles,
            KnownFolder::ProgramFilesX86 => &FOLDERID_ProgramFilesX86,
            KnownFolder::ProgramFilesCommon => &FOLDERID_ProgramFilesCommon,
            KnownFolder::ProgramFilesCommonX86 => &FOLDERID_ProgramFilesCommonX86,
            KnownFolder::Windows => &FOLDERID_Windows,
            KnownFolder::System => &FOLDERID_System,
            KnownFolder::SystemX86 => &FOLDERID_SystemX86,
            KnownFolder::Fonts => &FOLDERID_Fonts,
            KnownFolder::StartMenu => &FOLDERID_StartMenu,
            KnownFolder::Programs => &FOLDERID_Programs,
            KnownFolder::Startup => &FOLDERID_Startup,
            KnownFolder::CommonStartMenu => &FOLDERID_CommonStartMenu,
            KnownFolder::CommonPrograms => &FOLDERID_CommonPrograms,
            KnownFolder::CommonStartup => &FOLDERID_CommonStartup,
            KnownFolder::Templates => &FOLDERID_Templates,
            KnownFolder::CommonTemplates => &FOLDERID_CommonTemplates,
            KnownFolder::SendTo => &FOLDERID_SendTo,
            KnownFolder::Recent => &FOLDERID_Recent,
            KnownFolder::QuickLaunch => &FOLDERID_QuickLaunch,
            KnownFolder::UserPinned => &FOLDERID_UserPinned,
        }
    }
}

/// Maps an `HRESULT` to a Win32 error (`HRESULT_FROM_WIN32` codes unwrap to their Win32 code; other
/// failure codes are kept whole).
fn hresult_error(hr: i32) -> Win32Error {
    let u = hr as u32;
    if u & 0xFFFF_0000 == 0x8007_0000 {
        Win32Error(u & 0xFFFF)
    } else {
        Win32Error(u)
    }
}

/// The path of `folder` for the current user, without verifying or creating it.
pub fn known_folder(folder: KnownFolder) -> Result<PathBuf, Win32Error> {
    let mut p: *mut u16 = ptr::null_mut();
    // SAFETY: `folder.id()` points to a static GUID; a null token means the current user; `p` is a
    // valid out-pointer that receives a CoTaskMemAlloc'd string (also on some failures).
    let hr = unsafe {
        SHGetKnownFolderPath(
            folder.id(),
            KF_FLAG_DONT_VERIFY as u32,
            ptr::null_mut(),
            &mut p,
        )
    };
    // SAFETY: `p` is null or a NUL-terminated string from SHGetKnownFolderPath.
    let s = unsafe { from_wide_ptr(p) };
    // SAFETY: the API requires CoTaskMemFree on the returned pointer, whether or not it failed;
    // freeing null is a no-op.
    unsafe { CoTaskMemFree(p as *const _) };
    if hr < 0 {
        return Err(hresult_error(hr));
    }
    Ok(PathBuf::from(s))
}

/// Every [`KnownFolder`] that resolves for the current user, with its path. Folders that are not
/// defined on this system (an error from the API) are left out.
pub fn all_known_folders() -> Vec<(KnownFolder, PathBuf)> {
    KnownFolder::ALL
        .iter()
        .filter_map(|&f| known_folder(f).ok().map(|p| (f, p)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_path(name: &str) -> PathBuf {
        PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} not set")))
    }

    fn same(a: &std::path::Path, b: &std::path::Path) -> bool {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    }

    #[test]
    fn folders_match_environment() {
        assert!(same(
            &known_folder(KnownFolder::LocalAppData).unwrap(),
            &env_path("LOCALAPPDATA")
        ));
        assert!(same(
            &known_folder(KnownFolder::RoamingAppData).unwrap(),
            &env_path("APPDATA")
        ));
        assert!(same(
            &known_folder(KnownFolder::Profile).unwrap(),
            &env_path("USERPROFILE")
        ));
        assert!(same(
            &known_folder(KnownFolder::ProgramData).unwrap(),
            &env_path("ProgramData")
        ));
        assert!(same(
            &known_folder(KnownFolder::ProgramFiles).unwrap(),
            &env_path("ProgramFiles")
        ));
        assert!(same(
            &known_folder(KnownFolder::ProgramFilesX86).unwrap(),
            &env_path("ProgramFiles(x86)")
        ));
        assert!(same(
            &known_folder(KnownFolder::Windows).unwrap(),
            &env_path("SystemRoot")
        ));
        assert!(same(
            &known_folder(KnownFolder::UserProgramFiles).unwrap(),
            &env_path("LOCALAPPDATA").join("Programs")
        ));
    }

    #[test]
    fn all_variants_listed_and_mostly_resolve() {
        let mut sorted = KnownFolder::ALL.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), KnownFolder::ALL.len());
        let all = all_known_folders();
        assert!(all.len() >= KnownFolder::ALL.len() - 2, "{all:?}");
        assert!(all.iter().all(|(_, p)| p.is_absolute()));
        assert_eq!(
            KnownFolder::ALL
                .iter()
                .filter(|f| f.is_user_content())
                .count(),
            7
        );
    }

    #[test]
    fn hresult_mapping() {
        assert_eq!(
            hresult_error(0x8007_0002u32 as i32),
            Win32Error::FILE_NOT_FOUND
        );
        assert_eq!(
            hresult_error(0x8000_4005u32 as i32),
            Win32Error(0x8000_4005)
        );
    }
}
