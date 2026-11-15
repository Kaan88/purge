//! AppX/MSIX package removal through WinRT `PackageManager` (features `write` + `appx`, M2-WIN-TYPED).
//!
//! ENGINE_PLAN.md §5.6 SYS-APPX, §7.5 and §7.8: a package is removed only through the deployment API, by
//! its exact full name, and the removal has no inverse (Reversibility None). [`remove_package`] removes one
//! package for the calling user ([`RemovalScope::CurrentUser`]) or for every user on the machine
//! ([`RemovalScope::AllUsers`], `RemovalOptions::RemoveForAllUsers`, needs administrator rights and
//! Windows 10 1809 or later). The package's application data goes with it; nothing is preserved.
//!
//! The result is typed: [`RemoveOutcome::Removed`], [`RemoveOutcome::NotFound`] (no package with that full
//! name is registered in the requested scope), [`RemoveOutcome::InUse`], [`RemoveOutcome::Failed`] with
//! the HRESULT, or [`RemoveOutcome::TimedOut`] when the deployment did not finish in time. The full name is
//! validated lexically before any call ([`validate_full_name`]); wildcards, paths and family names are
//! refused. Capturing the package definition for the record is the caller's job (`appx::list_packages`).
//!
//! The module needs WinRT, which lives behind the `appx` feature: with `write` alone it is empty, so a
//! crate that removes packages enables both features.

#![cfg(feature = "appx")]

use std::sync::mpsc;
use std::time::Duration;

use windows::Management::Deployment::{DeploymentResult, PackageManager, RemovalOptions};
use windows::core::HSTRING;
use windows_sys::Win32::Foundation::{
    ERROR_CANCELLED, ERROR_INSTALL_PACKAGE_NOT_FOUND, ERROR_PACKAGES_IN_USE,
};

/// Longest package full name Windows accepts (`PACKAGE_FULL_NAME_MAX_LENGTH`, without the terminator).
pub const FULL_NAME_MAX_LEN: usize = 127;

/// A sensible bound for [`remove_package`]: deployment operations are queued machine-wide, so a removal
/// can wait behind another install or update before it starts.
pub const DEFAULT_REMOVE_TIMEOUT: Duration = Duration::from_secs(300);

/// How long [`remove_package`] waits for a cancelled operation to settle after its timeout.
const CANCEL_GRACE: Duration = Duration::from_secs(30);

/// `E_ACCESSDENIED`.
const E_ACCESSDENIED: i32 = 0x8007_0005_u32 as i32;

/// `Windows.Foundation.AsyncStatus` values, read through the raw field because the `windows` crate does
/// not re-export the type from `windows-future`.
const ASYNC_STARTED: i32 = 0;
const ASYNC_COMPLETED: i32 = 1;
const ASYNC_CANCELED: i32 = 2;

/// `HRESULT_FROM_WIN32` for a non-zero Win32 error code.
const fn hresult_from_win32(code: u32) -> i32 {
    ((code & 0xFFFF) | 0x8007_0000) as i32
}

/// For whom [`remove_package`] removes the package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemovalScope {
    /// The calling user only (`RemovePackageWithOptionsAsync(name, None)`). A package registered only for
    /// other users comes back as [`RemoveOutcome::NotFound`].
    CurrentUser,
    /// Every user on the machine (`RemovalOptions::RemoveForAllUsers`). Requires administrator rights; at
    /// medium integrity the result is [`RemoveOutcome::Failed`] with access denied. Because the service
    /// reports success for a full name that is not on the machine at all, the package is first looked up
    /// machine-wide (`FindPackageByPackageFullName`) and a missing one is [`RemoveOutcome::NotFound`].
    AllUsers,
}

impl RemovalScope {
    fn options(self) -> RemovalOptions {
        match self {
            RemovalScope::CurrentUser => RemovalOptions::None,
            RemovalScope::AllUsers => RemovalOptions::RemoveForAllUsers,
        }
    }
}

/// Error details of a deployment operation that did not remove the package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentError {
    /// The operation's HRESULT (`IAsyncInfo.ErrorCode`, or the error returned when the operation could not
    /// be started).
    pub hresult: i32,
    /// `DeploymentResult.ExtendedErrorCode` when it is non-zero and differs from `hresult`; it usually
    /// carries the specific cause behind a generic `ERROR_REMOVE_FAILED`.
    pub extended_hresult: Option<i32>,
    /// `DeploymentResult.ErrorText` (localized, may name files or processes); `None` when empty.
    pub error_text: Option<String>,
    /// `DeploymentResult.ActivityId`, for the `Microsoft-Windows-AppXDeploymentServer` event log.
    pub activity_id: Option<String>,
}

impl DeploymentError {
    fn from_code(hresult: i32, text: Option<String>) -> Self {
        Self {
            hresult,
            extended_hresult: None,
            error_text: text,
            activity_id: None,
        }
    }

    /// Whether `code` is the primary or the extended HRESULT.
    pub fn has_code(&self, code: i32) -> bool {
        self.hresult == code || self.extended_hresult == Some(code)
    }

    /// The caller lacks the rights for the requested scope (`E_ACCESSDENIED`).
    pub fn is_access_denied(&self) -> bool {
        self.has_code(E_ACCESSDENIED)
    }
}

/// Result of [`remove_package`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoveOutcome {
    /// The deployment operation completed; the package is no longer registered in the requested scope.
    Removed,
    /// No package with this full name is registered in the requested scope (`ERROR_INSTALL_PACKAGE_NOT_FOUND`).
    NotFound,
    /// The package or one of its apps is running (`ERROR_PACKAGES_IN_USE`); nothing was removed.
    InUse(DeploymentError),
    /// Any other failure, with its HRESULT.
    Failed(DeploymentError),
    /// The operation did not finish within the timeout. It was cancelled; whether the package is still
    /// registered is unknown and must be re-checked with `appx::list_packages`.
    TimedOut,
}

/// Why a string is not a package full name (`Name_Version_Architecture_ResourceId_PublisherId`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FullNameError {
    /// The string is empty.
    #[error("the package full name is empty")]
    Empty,
    /// Longer than [`FULL_NAME_MAX_LEN`] characters.
    #[error("the package full name has {0} characters, more than {FULL_NAME_MAX_LEN}")]
    TooLong(usize),
    /// Not exactly five `_`-separated fields (a family name has two).
    #[error("the package full name has {0} fields separated by '_', expected 5")]
    FieldCount(usize),
    /// The name field is not 3 to 50 characters of `A-Z a-z 0-9 . -`.
    #[error("the package name field is not 3 to 50 letters, digits, '.' or '-'")]
    Name,
    /// The version field is not four dot-separated numbers of at most 65535.
    #[error("the package version field is not four dot-separated numbers up to 65535")]
    Version,
    /// The architecture field is not one Windows knows.
    #[error("the package architecture field is not x86, x64, arm, arm64, x86a64 or neutral")]
    Architecture,
    /// The resource id field is not empty, `~` or up to 30 characters of `A-Z a-z 0-9 . -`.
    #[error(
        "the package resource id field is not empty, '~' or up to 30 letters, digits, '.' or '-'"
    )]
    ResourceId,
    /// The publisher id field is not 13 base32 characters.
    #[error("the package publisher id field is not 13 base32 characters")]
    PublisherId,
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-'
}

/// Checks that `full_name` has the shape of one package full name. Purely lexical: it does not say whether
/// the package exists. Rejects wildcards, path characters, whitespace and family names.
pub fn validate_full_name(full_name: &str) -> Result<(), FullNameError> {
    if full_name.is_empty() {
        return Err(FullNameError::Empty);
    }
    let len = full_name.chars().count();
    if len > FULL_NAME_MAX_LEN {
        return Err(FullNameError::TooLong(len));
    }
    let fields: Vec<&str> = full_name.split('_').collect();
    let [name, version, arch, resource_id, publisher_id] = fields[..] else {
        return Err(FullNameError::FieldCount(fields.len()));
    };
    if !(3..=50).contains(&name.len()) || !name.chars().all(is_name_char) {
        return Err(FullNameError::Name);
    }
    let parts: Vec<&str> = version.split('.').collect();
    let version_ok = parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok()
        });
    if !version_ok {
        return Err(FullNameError::Version);
    }
    const ARCHES: [&str; 6] = ["x86", "x64", "arm", "arm64", "x86a64", "neutral"];
    if !ARCHES.iter().any(|a| a.eq_ignore_ascii_case(arch)) {
        return Err(FullNameError::Architecture);
    }
    let resource_ok = resource_id.is_empty()
        || resource_id == "~"
        || (resource_id.len() <= 30 && resource_id.chars().all(is_name_char));
    if !resource_ok {
        return Err(FullNameError::ResourceId);
    }
    // Crockford base32 as used for publisher ids: digits and letters without i, l, o, u.
    const BASE32: &str = "0123456789abcdefghjkmnpqrstvwxyz";
    let publisher_ok = publisher_id.len() == 13
        && publisher_id
            .chars()
            .all(|c| BASE32.contains(c.to_ascii_lowercase()));
    if !publisher_ok {
        return Err(FullNameError::PublisherId);
    }
    Ok(())
}

/// Maps a failed deployment to the typed outcome.
fn classify(error: DeploymentError) -> RemoveOutcome {
    if error.has_code(hresult_from_win32(ERROR_INSTALL_PACKAGE_NOT_FOUND)) {
        RemoveOutcome::NotFound
    } else if error.has_code(hresult_from_win32(ERROR_PACKAGES_IN_USE)) {
        RemoveOutcome::InUse(error)
    } else {
        RemoveOutcome::Failed(error)
    }
}

fn from_core_error(e: &windows::core::Error) -> DeploymentError {
    let text = e.message();
    DeploymentError::from_code(e.code().0, (!text.is_empty()).then_some(text))
}

/// Removes the package `full_name` for `scope` and waits at most `timeout` for the deployment to finish.
///
/// Returns `Err` only when `full_name` is not a valid full name; no API is called then. Everything the
/// deployment service reports is a [`RemoveOutcome`]. The removal is irreversible.
pub fn remove_package(
    full_name: &str,
    scope: RemovalScope,
    timeout: Duration,
) -> Result<RemoveOutcome, FullNameError> {
    validate_full_name(full_name)?;
    Ok(run_removal(full_name, scope, timeout))
}

/// Starts the removal, waits for it (cancelling it after `timeout`) and reads its outcome.
///
/// The operation type (`IAsyncOperationWithProgress`) lives in `windows-future`, which the `windows`
/// crate does not re-export, so it stays an inferred local here.
fn run_removal(full_name: &str, scope: RemovalScope, timeout: Duration) -> RemoveOutcome {
    let pm = match PackageManager::new() {
        Ok(pm) => pm,
        Err(e) => return RemoveOutcome::Failed(from_core_error(&e)),
    };
    let name = HSTRING::from(full_name);
    if scope == RemovalScope::AllUsers {
        // With RemoveForAllUsers the deployment service completes without error for a full name that is
        // not on the machine (observed on 10.0.26300, medium integrity), so existence is checked first.
        // The machine-wide lookup needs administrator rights, like the removal itself.
        match pm.FindPackageByPackageFullName(&name) {
            Ok(_) => {}
            // A null result (no such package) arrives as an error without a code.
            Err(e) if e.code().0 == 0 => return RemoveOutcome::NotFound,
            Err(e) => return classify(from_core_error(&e)),
        }
    }
    let op = match pm.RemovePackageWithOptionsAsync(&name, scope.options()) {
        Ok(op) => op,
        Err(e) => return classify(from_core_error(&e)),
    };
    let (tx, rx) = mpsc::channel();
    if let Err(e) = op.when(move |_| {
        // The receiver may be gone after a timeout; nothing waits for the signal then.
        let _ = tx.send(());
    }) {
        return RemoveOutcome::Failed(from_core_error(&e));
    }
    let mut cancelled = false;
    if rx.recv_timeout(timeout).is_err() {
        cancelled = true;
        let _ = op.Cancel();
        if rx.recv_timeout(CANCEL_GRACE).is_err() {
            return RemoveOutcome::TimedOut;
        }
    }
    match op.Status().map(|s| s.0) {
        Ok(ASYNC_COMPLETED) => RemoveOutcome::Removed,
        Ok(ASYNC_CANCELED | ASYNC_STARTED) if cancelled => RemoveOutcome::TimedOut,
        Ok(ASYNC_CANCELED) => RemoveOutcome::Failed(DeploymentError::from_code(
            hresult_from_win32(ERROR_CANCELLED),
            None,
        )),
        Ok(_) => {
            let hresult = op.ErrorCode().map(|h| h.0).unwrap_or(0);
            classify(error_details(hresult, op.GetResults()))
        }
        Err(e) => RemoveOutcome::Failed(from_core_error(&e)),
    }
}

/// Collects the error details of a finished, failed operation from its `ErrorCode` and `GetResults`.
fn error_details(
    hresult: i32,
    results: windows::core::Result<DeploymentResult>,
) -> DeploymentError {
    let mut error = match results {
        Ok(result) => {
            let extended = result.ExtendedErrorCode().map(|h| h.0).unwrap_or(0);
            DeploymentError {
                hresult,
                extended_hresult: (extended != 0 && extended != hresult).then_some(extended),
                error_text: result
                    .ErrorText()
                    .ok()
                    .map(|t| t.to_string_lossy())
                    .filter(|t| !t.is_empty()),
                activity_id: result.ActivityId().ok().map(|g| format!("{g:?}")),
            }
        }
        Err(e) => {
            let mut error = from_core_error(&e);
            if hresult != 0 {
                error.extended_hresult = (error.hresult != hresult).then_some(error.hresult);
                error.hresult = hresult;
            }
            error
        }
    };
    if error.hresult == 0 {
        // A failed operation without a code; keep the outcome a failure rather than a success.
        error.hresult = error.extended_hresult.take().unwrap_or(E_FAIL);
    }
    error
}

/// `E_FAIL`.
const E_FAIL: i32 = 0x8000_4005_u32 as i32;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appx::{AppxScope, list_packages};

    /// Well formed, but no publisher signs packages with this id and the name is unused.
    const MISSING: &str = "Purge.Test.NoSuchPackage_1.0.0.0_x64__0000000000000";

    #[test]
    fn valid_full_names() {
        for name in [
            "Microsoft.WindowsCalculator_11.2502.2.0_x64__8wekyb3d8bbwe",
            "Microsoft.VCLibs.140.00_14.0.33519.0_x86__8wekyb3d8bbwe",
            "Microsoft.WindowsStore_22305.1401.3.0_neutral_~_8wekyb3d8bbwe",
            "Microsoft.LanguageExperiencePackde-DE_26100.1.2.0_neutral__8wekyb3d8bbwe",
            "Contoso.App_1.0.0.0_neutral_split.scale-100_abcdefghjkmnp",
            "abc_0.0.0.0_ARM64__0123456789ABC",
            "Abc_65535.65535.65535.65535_x86a64__zzzzzzzzzzzzz",
            MISSING,
        ] {
            assert_eq!(validate_full_name(name), Ok(()), "{name}");
        }
    }

    #[test]
    fn invalid_full_names() {
        let long = format!("{}_1.0.0.0_x64__8wekyb3d8bbwe", "a".repeat(110));
        let cases: &[(&str, FullNameError)] = &[
            ("", FullNameError::Empty),
            (&long, FullNameError::TooLong(long.len())),
            (
                "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
                FullNameError::FieldCount(2),
            ),
            ("Microsoft.WindowsCalculator*", FullNameError::FieldCount(1)),
            ("a_b_c_d_e_f", FullNameError::FieldCount(6)),
            ("ab_1.0.0.0_x64__8wekyb3d8bbwe", FullNameError::Name),
            ("Bad Name_1.0.0.0_x64__8wekyb3d8bbwe", FullNameError::Name),
            ("Bad*Name_1.0.0.0_x64__8wekyb3d8bbwe", FullNameError::Name),
            ("C:\\x\\y_1.0.0.0_x64__8wekyb3d8bbwe", FullNameError::Name),
            (
                &format!("{}_1.0.0.0_x64__8wekyb3d8bbwe", "a".repeat(51)),
                FullNameError::Name,
            ),
            ("App.Name_1.0.0_x64__8wekyb3d8bbwe", FullNameError::Version),
            (
                "App.Name_1.0.0.65536_x64__8wekyb3d8bbwe",
                FullNameError::Version,
            ),
            (
                "App.Name_1.0.+0.0_x64__8wekyb3d8bbwe",
                FullNameError::Version,
            ),
            ("App.Name_1..0.0_x64__8wekyb3d8bbwe", FullNameError::Version),
            (
                "App.Name_1.0.0.0_amd64__8wekyb3d8bbwe",
                FullNameError::Architecture,
            ),
            (
                "App.Name_1.0.0.0_x64_a b_8wekyb3d8bbwe",
                FullNameError::ResourceId,
            ),
            (
                &format!("App.Name_1.0.0.0_x64_{}_8wekyb3d8bbwe", "r".repeat(31)),
                FullNameError::ResourceId,
            ),
            (
                "App.Name_1.0.0.0_x64__8wekyb3d8bbw",
                FullNameError::PublisherId,
            ),
            (
                "App.Name_1.0.0.0_x64__8wekyb3d8bbwel",
                FullNameError::PublisherId,
            ),
            (
                "App.Name_1.0.0.0_x64__8wekyb3d8bbwu",
                FullNameError::PublisherId,
            ),
            (
                "App.Name_1.0.0.0_x64__8wekyb3d8bbw\0",
                FullNameError::PublisherId,
            ),
        ];
        for (name, want) in cases {
            assert_eq!(validate_full_name(name).as_ref(), Err(want), "{name:?}");
        }
    }

    #[test]
    fn every_registered_full_name_validates() {
        let packages = list_packages(AppxScope::CurrentUser).expect("FindPackagesForUser");
        assert!(!packages.is_empty());
        for p in &packages {
            assert_eq!(validate_full_name(&p.full_name), Ok(()), "{}", p.full_name);
        }
    }

    #[test]
    fn invalid_name_is_refused_before_any_call() {
        assert_eq!(
            remove_package("*", RemovalScope::CurrentUser, Duration::from_secs(1)),
            Err(FullNameError::FieldCount(1))
        );
        assert_eq!(
            remove_package(
                "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
                RemovalScope::AllUsers,
                Duration::from_secs(1)
            ),
            Err(FullNameError::FieldCount(2))
        );
    }

    #[test]
    fn classification_by_code() {
        let not_found = hresult_from_win32(ERROR_INSTALL_PACKAGE_NOT_FOUND);
        let in_use = hresult_from_win32(ERROR_PACKAGES_IN_USE);
        let remove_failed = 0x8007_3CFA_u32 as i32;
        assert_eq!(not_found, 0x8007_3CF1_u32 as i32);
        assert_eq!(in_use, 0x8007_3D02_u32 as i32);
        assert_eq!(
            classify(DeploymentError::from_code(not_found, None)),
            RemoveOutcome::NotFound
        );
        let wrapped = DeploymentError {
            hresult: remove_failed,
            extended_hresult: Some(not_found),
            error_text: None,
            activity_id: None,
        };
        assert_eq!(classify(wrapped), RemoveOutcome::NotFound);
        let busy = DeploymentError::from_code(in_use, Some("busy".into()));
        assert_eq!(classify(busy.clone()), RemoveOutcome::InUse(busy));
        let denied = DeploymentError::from_code(E_ACCESSDENIED, None);
        assert!(denied.is_access_denied());
        assert_eq!(classify(denied.clone()), RemoveOutcome::Failed(denied));
    }

    #[test]
    fn missing_package_is_not_found_for_current_user() {
        let outcome = remove_package(MISSING, RemovalScope::CurrentUser, DEFAULT_REMOVE_TIMEOUT)
            .expect("valid full name");
        assert_eq!(outcome, RemoveOutcome::NotFound);
    }

    #[test]
    fn missing_package_for_all_users_is_not_found_or_denied() {
        // Elevated, the machine-wide lookup finds nothing; at medium integrity it is refused. Never
        // `Removed`, which the bare RemoveForAllUsers call would report for a missing package.
        let outcome = remove_package(MISSING, RemovalScope::AllUsers, DEFAULT_REMOVE_TIMEOUT)
            .expect("valid full name");
        if crate::sid::is_elevated().expect("TokenElevation") {
            assert_eq!(outcome, RemoveOutcome::NotFound);
        } else {
            match outcome {
                RemoveOutcome::Failed(e) if e.is_access_denied() => {}
                other => panic!("unexpected outcome {other:?}"),
            }
        }
    }

    /// Removes a disposable package installed by the VM rig and named in `PURGE_TEST_APPX_FULL_NAME`.
    #[test]
    #[ignore = "removes a real package irreversibly; runs only in the VM gate with PURGE_TEST_APPX_FULL_NAME set"]
    fn removes_a_real_package() {
        let full_name = std::env::var("PURGE_TEST_APPX_FULL_NAME")
            .expect("PURGE_TEST_APPX_FULL_NAME names the disposable test package");
        let registered = |name: &str| {
            list_packages(AppxScope::CurrentUser)
                .expect("FindPackagesForUser")
                .iter()
                .any(|p| p.full_name == name)
        };
        assert!(registered(&full_name), "test package not registered");
        assert_eq!(
            remove_package(
                &full_name,
                RemovalScope::CurrentUser,
                DEFAULT_REMOVE_TIMEOUT
            ),
            Ok(RemoveOutcome::Removed)
        );
        assert!(!registered(&full_name));
        assert_eq!(
            remove_package(
                &full_name,
                RemovalScope::CurrentUser,
                DEFAULT_REMOVE_TIMEOUT
            ),
            Ok(RemoveOutcome::NotFound)
        );
    }

    /// Removes a disposable package registered for several users, named in
    /// `PURGE_TEST_APPX_ALL_USERS_FULL_NAME`; needs an elevated test process.
    #[test]
    #[ignore = "removes a real package for every user irreversibly and needs elevation; VM gate only"]
    fn removes_a_real_package_for_all_users() {
        let full_name = std::env::var("PURGE_TEST_APPX_ALL_USERS_FULL_NAME")
            .expect("PURGE_TEST_APPX_ALL_USERS_FULL_NAME names the disposable test package");
        assert!(crate::sid::is_elevated().expect("TokenElevation"));
        let registered = |name: &str| {
            list_packages(AppxScope::AllUsers)
                .expect("FindPackages")
                .iter()
                .any(|p| p.full_name == name && !p.users.is_empty())
        };
        assert!(registered(&full_name), "test package not registered");
        assert_eq!(
            remove_package(&full_name, RemovalScope::AllUsers, DEFAULT_REMOVE_TIMEOUT),
            Ok(RemoveOutcome::Removed)
        );
        assert!(!registered(&full_name));
    }
}
