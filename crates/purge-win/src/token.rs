//! Token facts (M3 design 3.3, 3.5; package M3-WIN-PIPE).
//!
//! - [`Token`] is a token handle opened for `TOKEN_QUERY` only: of this process
//!   ([`Token::current_process`]), of another process through a held [`ProcessHandle`]
//!   ([`Token::of_process`]), or of the calling thread when it impersonates
//!   ([`Token::of_current_thread`]).
//! - [`TokenFacts`] are what the broker and the medium engine compare: user SID, `TokenElevation`,
//!   `TokenElevationType` and the integrity RID.
//! - [`shell_owner_facts`] reads the token of the process that owns the shell window
//!   (`GetShellWindow`), for the medium engine's rule "same user and same elevation as the shell"
//!   (design 3.5).
//!
//! Nothing here changes a token: no privilege is enabled, nothing is duplicated, nothing impersonated.
#![cfg(feature = "read")]

use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_NO_TOKEN, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSID, TOKEN_ELEVATION, TOKEN_ELEVATION_TYPE, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenElevationType, TokenElevationTypeDefault,
    TokenElevationTypeFull, TokenElevationTypeLimited, TokenIntegrityLevel, TokenUser,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};

use crate::os::Win32Error;
use crate::process::{ProcessHandle, QueryProcessHandle};
use crate::sid::sid_bytes_to_string;

/// `SECURITY_MANDATORY_MEDIUM_RID`.
pub const INTEGRITY_MEDIUM: u32 = 0x2000;
/// `SECURITY_MANDATORY_HIGH_RID`.
pub const INTEGRITY_HIGH: u32 = 0x3000;
/// `SECURITY_MANDATORY_SYSTEM_RID`.
pub const INTEGRITY_SYSTEM: u32 = 0x4000;

/// `TokenElevationType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElevationType {
    /// `TokenElevationTypeDefault`: no split token (UAC off, a standard user, or a built-in account).
    Default,
    /// `TokenElevationTypeFull`: the elevated half of an administrator's split token.
    Full,
    /// `TokenElevationTypeLimited`: the filtered half of an administrator's split token.
    Limited,
}

/// What the broker and the medium engine read from a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenFacts {
    /// User SID in string form (`S-1-5-21-...`).
    pub user_sid: String,
    /// `TokenElevation.TokenIsElevated`.
    pub elevated: bool,
    /// `TokenElevationType`.
    pub elevation_type: ElevationType,
    /// The last sub-authority of the integrity label (`INTEGRITY_MEDIUM`, `INTEGRITY_HIGH`, ...).
    pub integrity_rid: u32,
}

impl TokenFacts {
    /// Same user SID and same elevation: the medium engine's condition for running a medium-route
    /// uninstaller (design 3.5; with UAC off both sides are elevated, which passes).
    pub fn same_user_and_elevation(&self, other: &TokenFacts) -> bool {
        self.user_sid == other.user_sid && self.elevated == other.elevated
    }
}

/// A token handle with `TOKEN_QUERY` access.
#[derive(Debug)]
pub struct Token(OwnedHandle);

impl Token {
    /// The primary token of this process.
    pub fn current_process() -> Result<Token, Win32Error> {
        // SAFETY: `GetCurrentProcess` is a pseudo handle that needs no closing.
        unsafe { open_process_token(GetCurrentProcess()) }
    }

    /// The primary token of the process behind `process` (which stays open, so it is the process
    /// that was checked).
    pub fn of_process(process: &ProcessHandle) -> Result<Token, Win32Error> {
        // SAFETY: the process handle is live for the call.
        unsafe { open_process_token(process.as_raw_handle() as HANDLE) }
    }

    /// [`Token::of_process`] of a handle opened with the query right only (the UI's look at the
    /// elevated broker).
    pub fn of_query_process(process: &QueryProcessHandle) -> Result<Token, Win32Error> {
        // SAFETY: the process handle is live for the call.
        unsafe { open_process_token(process.as_raw_handle() as HANDLE) }
    }

    /// The impersonation token of the calling thread, or `None` when the thread does not impersonate.
    /// Opened with `OpenAsSelf`, so the access check is made against the process token and an
    /// identification-level token can be opened too.
    pub fn of_current_thread() -> Result<Option<Token>, Win32Error> {
        let mut h: HANDLE = ptr::null_mut();
        // SAFETY: pseudo handle of the calling thread; `h` is a valid out-pointer.
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut h) } == 0 {
            let e = Win32Error::last();
            if e.code() == ERROR_NO_TOKEN {
                return Ok(None);
            }
            return Err(e);
        }
        // SAFETY: a fresh token handle owned by nobody else.
        Ok(Some(Token(unsafe { OwnedHandle::from_raw_handle(h) })))
    }

    /// User SID (`TokenUser`).
    pub fn user_sid(&self) -> Result<String, Win32Error> {
        let buf = self.info(TokenUser)?;
        // SAFETY: on success the buffer starts with a TOKEN_USER (8-byte aligned buffer).
        let psid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
        sid_in_buffer(&buf, psid)
    }

    /// `TokenElevation`.
    pub fn elevated(&self) -> Result<bool, Win32Error> {
        let mut te = TOKEN_ELEVATION { TokenIsElevated: 0 };
        self.fixed(TokenElevation, &mut te)?;
        Ok(te.TokenIsElevated != 0)
    }

    /// `TokenElevationType`.
    pub fn elevation_type(&self) -> Result<ElevationType, Win32Error> {
        let mut t: TOKEN_ELEVATION_TYPE = 0;
        self.fixed(TokenElevationType, &mut t)?;
        #[allow(non_upper_case_globals)]
        match t {
            TokenElevationTypeDefault => Ok(ElevationType::Default),
            TokenElevationTypeFull => Ok(ElevationType::Full),
            TokenElevationTypeLimited => Ok(ElevationType::Limited),
            _ => Err(Win32Error::INVALID_DATA),
        }
    }

    /// Integrity RID (`TokenIntegrityLevel`, last sub-authority of the label SID).
    pub fn integrity_rid(&self) -> Result<u32, Win32Error> {
        let buf = self.info(TokenIntegrityLevel)?;
        // SAFETY: on success the buffer starts with a TOKEN_MANDATORY_LABEL.
        let psid = unsafe { (*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL)).Label.Sid };
        let bytes = sid_slice(&buf, psid)?;
        let count = bytes[1] as usize;
        if count == 0 {
            return Err(Win32Error::INVALID_DATA);
        }
        let at = 8 + 4 * (count - 1);
        Ok(u32::from_le_bytes([
            bytes[at],
            bytes[at + 1],
            bytes[at + 2],
            bytes[at + 3],
        ]))
    }

    /// All of [`TokenFacts`].
    pub fn facts(&self) -> Result<TokenFacts, Win32Error> {
        Ok(TokenFacts {
            user_sid: self.user_sid()?,
            elevated: self.elevated()?,
            elevation_type: self.elevation_type()?,
            integrity_rid: self.integrity_rid()?,
        })
    }

    /// `GetTokenInformation` into an 8-byte-aligned buffer, retried with the reported size.
    fn info(&self, class: i32) -> Result<Vec<u64>, Win32Error> {
        let mut buf = vec![0u64; 16];
        loop {
            let mut needed = 0u32;
            // SAFETY: `buf` has `buf.len() * 8` writable bytes; `needed` is a valid local.
            let ok = unsafe {
                GetTokenInformation(
                    self.0.as_raw_handle(),
                    class,
                    buf.as_mut_ptr().cast(),
                    (buf.len() * 8) as u32,
                    &mut needed,
                )
            };
            if ok != 0 {
                return Ok(buf);
            }
            let e = Win32Error::last();
            if e != Win32Error::INSUFFICIENT_BUFFER || (needed as usize) <= buf.len() * 8 {
                return Err(e);
            }
            buf.resize((needed as usize).div_ceil(8), 0);
        }
    }

    /// `GetTokenInformation` of a fixed-size class into `out` (the exact size is required).
    fn fixed<T>(&self, class: i32, out: &mut T) -> Result<(), Win32Error> {
        let mut needed = 0u32;
        // SAFETY: `out` is a writable `T` of the size passed.
        let ok = unsafe {
            GetTokenInformation(
                self.0.as_raw_handle(),
                class,
                (out as *mut T).cast(),
                size_of::<T>() as u32,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(Win32Error::last());
        }
        Ok(())
    }
}

/// `OpenProcessToken(TOKEN_QUERY)`.
///
/// # Safety
/// `process` must be a live process handle (or the current-process pseudo handle).
unsafe fn open_process_token(process: HANDLE) -> Result<Token, Win32Error> {
    let mut h: HANDLE = ptr::null_mut();
    // SAFETY: `process` is live per the caller; `h` is a valid out-pointer.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut h) } == 0 {
        return Err(Win32Error::last());
    }
    // SAFETY: a fresh token handle owned by nobody else.
    Ok(Token(unsafe { OwnedHandle::from_raw_handle(h) }))
}

/// The bytes of the SID at `psid`, which must lie inside `buf` (a `GetTokenInformation` buffer).
fn sid_slice(buf: &[u64], psid: PSID) -> Result<&[u8], Win32Error> {
    let base = buf.as_ptr() as usize;
    let end = base + buf.len() * 8;
    let p = psid as usize;
    if psid.is_null() || p < base || p + 8 > end {
        return Err(Win32Error::INVALID_DATA);
    }
    // SAFETY: `[p, p + 8)` lies inside the live buffer (checked above); byte 1 of a SID is its
    // sub-authority count, which fixes the length 8 + 4 * count.
    let len = 8 + 4 * unsafe { *(psid as *const u8).add(1) } as usize;
    if p + len > end {
        return Err(Win32Error::INVALID_DATA);
    }
    // SAFETY: `[p, p + len)` lies inside `buf`, which is borrowed for the returned lifetime.
    Ok(unsafe { std::slice::from_raw_parts(psid as *const u8, len) })
}

fn sid_in_buffer(buf: &[u64], psid: PSID) -> Result<String, Win32Error> {
    sid_bytes_to_string(sid_slice(buf, psid)?).ok_or(Win32Error::INVALID_DATA)
}

/// Token facts of this process.
pub fn current_process_facts() -> Result<TokenFacts, Win32Error> {
    Token::current_process()?.facts()
}

/// Token facts of the process that owns the shell window of the calling thread's desktop
/// (`GetShellWindow`, normally Explorer). `None` when there is no shell window (no shell running, or a
/// desktop without one). The process is opened by the pid the window reports, and the window is asked
/// again afterwards: the pid cannot be reused while the handle is held, so an equal answer means the
/// opened process is the shell owner.
pub fn shell_owner_facts() -> Result<Option<TokenFacts>, Win32Error> {
    let Some(pid) = shell_window_pid() else {
        return Ok(None);
    };
    let process = ProcessHandle::open(pid)?;
    if shell_window_pid() != Some(pid) {
        // The shell restarted between the two questions.
        return Err(Win32Error::INVALID_DATA);
    }
    Ok(Some(Token::of_process(&process)?.facts()?))
}

fn shell_window_pid() -> Option<u32> {
    // SAFETY: plain call.
    let hwnd = unsafe { GetShellWindow() };
    if hwnd.is_null() {
        return None;
    }
    let mut pid = 0u32;
    // SAFETY: `hwnd` may already be stale; the call then returns 0 and leaves `pid` as is.
    if unsafe { GetWindowThreadProcessId(hwnd, &mut pid) } == 0 || pid == 0 {
        return None;
    }
    Some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs unelevated (xtask ci, win-unit p1) and elevated (win-unit p2); the expectations follow
    /// the token the test process has.
    #[test]
    fn own_token_facts() {
        let f = current_process_facts().unwrap();
        println!("own token: {f:?}");
        assert_eq!(f.user_sid, crate::sid::current_user_sid().unwrap());
        assert_eq!(f.elevated, crate::sid::is_elevated().unwrap());
        if f.elevated {
            assert!(
                matches!(
                    f.elevation_type,
                    ElevationType::Full | ElevationType::Default
                ),
                "{f:?}"
            );
            assert!(f.integrity_rid >= INTEGRITY_HIGH, "{f:?}");
        } else {
            assert!(
                matches!(
                    f.elevation_type,
                    ElevationType::Limited | ElevationType::Default
                ),
                "{f:?}"
            );
            assert!(f.integrity_rid <= INTEGRITY_MEDIUM, "{f:?}");
        }
        assert!(f.same_user_and_elevation(&f));
        let other = TokenFacts {
            elevated: !f.elevated,
            ..f.clone()
        };
        assert!(!f.same_user_and_elevation(&other));
        let other = TokenFacts {
            user_sid: "S-1-5-18".into(),
            ..f.clone()
        };
        assert!(!f.same_user_and_elevation(&other));
    }

    #[test]
    fn token_of_own_process_handle_matches() {
        let me = ProcessHandle::open(std::process::id()).unwrap();
        let a = Token::of_process(&me).unwrap().facts().unwrap();
        assert_eq!(a, current_process_facts().unwrap());
    }

    #[test]
    fn thread_without_impersonation_has_no_token() {
        assert!(Token::of_current_thread().unwrap().is_none());
    }

    #[test]
    fn shell_owner() {
        // A test runner without a desktop shell (a service session) gets `None`.
        match shell_owner_facts().unwrap() {
            Some(f) => {
                println!("shell owner token: {f:?}");
                assert!(f.user_sid.starts_with("S-1-5-"), "{f:?}");
                assert!(f.integrity_rid >= INTEGRITY_MEDIUM, "{f:?}");
            }
            None => println!("no shell window on this desktop"),
        }
    }

    #[test]
    fn sid_slice_bounds() {
        let buf = [0u64; 4];
        assert_eq!(
            sid_slice(&buf, ptr::null_mut()),
            Err(Win32Error::INVALID_DATA)
        );
        let outside = (buf.as_ptr() as usize + 64) as PSID;
        assert_eq!(sid_slice(&buf, outside), Err(Win32Error::INVALID_DATA));
    }
}
