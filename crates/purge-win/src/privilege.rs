//! The one privilege Purge ever enables, `SeRestorePrivilege`, scoped to one closure on one thread
//! (M3 design, package M3-WIN-PRIV; threat T10; review R8b M1).
//!
//! Rules:
//!
//! - **The process token is never adjusted.** The privilege is enabled on a private impersonation
//!   copy of the process token, set on the calling thread for the closure and reverted right after
//!   it, also when the closure panics. Other threads never see it.
//! - **Only through [`with_restore_privilege`]**, which is `pub(crate)` and `write`-only. Its users
//!   are the two security writes of `reg_write` on a key this undo created
//!   (`CreatedKey::set_security` for an owner the token may not assign, and
//!   `CreatedKey::reopen_and_set_owner` for the owner of a key an interrupted undo left). No delete,
//!   move or quarantine step runs inside it.
//! - **Enabling fails cleanly.** A token that does not hold the privilege (an unelevated one) or a
//!   thread that already impersonates is an error before anything is changed; the closure does not
//!   run.
//!
//! [`restore_privilege_enabled`] reads the state back, for tests and the rig (T10: off before, on
//! inside, off after).

use std::ptr;

#[cfg(feature = "write")]
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LUID};
#[cfg(feature = "write")]
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, RevertToSelf, SecurityImpersonation,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES,
    TokenImpersonation,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_QUERY, TokenPrivileges,
};
#[cfg(feature = "write")]
use windows_sys::Win32::System::Threading::SetThreadToken;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

use crate::os::{Win32Error, wide};

/// `ERROR_PRIVILEGE_NOT_HELD`: the token does not hold `SeRestorePrivilege`.
pub const PRIVILEGE_NOT_HELD: Win32Error = Win32Error(1314);
/// `ERROR_NO_TOKEN`: the thread does not impersonate.
const NO_TOKEN: Win32Error = Win32Error(1008);
/// `ERROR_NOT_ALL_ASSIGNED`: `AdjustTokenPrivileges` succeeded without enabling the privilege.
#[cfg(feature = "write")]
const NOT_ALL_ASSIGNED: u32 = 1300;

/// A token handle, closed on drop.
struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful token open or duplicate, is owned by this value
        // and is closed exactly once here.
        unsafe { CloseHandle(self.0) };
    }
}

/// The LUID of `SeRestorePrivilege` on this system. The only place the privilege is named.
fn restore_luid() -> Result<LUID, Win32Error> {
    let name = wide("SeRestorePrivilege");
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: `name` is NUL-terminated and outlives the call; the system name is null (local);
    // `luid` is a valid out-pointer.
    if unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid) } == 0 {
        return Err(Win32Error::last());
    }
    Ok(luid)
}

/// The current thread's impersonation token opened with `access`, `None` when it does not
/// impersonate. Opened as self, so the check is against the process's own access.
fn thread_token(access: u32) -> Result<Option<Token>, Win32Error> {
    let mut held: HANDLE = ptr::null_mut();
    // SAFETY: the pseudo handle of the current thread needs no closing; `held` is a valid
    // out-pointer.
    if unsafe { OpenThreadToken(GetCurrentThread(), access, 1, &mut held) } != 0 {
        return Ok(Some(Token(held)));
    }
    let e = Win32Error::last();
    if e == NO_TOKEN { Ok(None) } else { Err(e) }
}

/// Whether the current thread impersonates (holds a thread token).
pub fn thread_impersonates() -> Result<bool, Win32Error> {
    thread_token(TOKEN_QUERY).map(|t| t.is_some())
}

/// Whether `SeRestorePrivilege` is enabled in the token the current thread acts with: its
/// impersonation token when it has one, else the process token. `false` also when the token does
/// not hold it.
pub fn restore_privilege_enabled() -> Result<bool, Win32Error> {
    let luid = restore_luid()?;
    let token = match thread_token(TOKEN_QUERY)? {
        Some(t) => t,
        None => {
            let mut process: HANDLE = ptr::null_mut();
            // SAFETY: the pseudo handle of the current process needs no closing; `process` is a
            // valid out-pointer.
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut process) } == 0 {
                return Err(Win32Error::last());
            }
            Token(process)
        }
    };
    let mut needed = 0u32;
    // SAFETY: size probe: a null buffer of length 0, `needed` is a valid out-pointer; `token.0`
    // is live and opened with TOKEN_QUERY.
    unsafe { GetTokenInformation(token.0, TokenPrivileges, ptr::null_mut(), 0, &mut needed) };
    if needed < 4 {
        return Err(Win32Error::last());
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buf` is 8-byte aligned and at least `needed` bytes long; `token.0` is live.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenPrivileges,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(Win32Error::last());
    }
    let base = buf.as_ptr().cast::<u8>();
    // SAFETY: the buffer holds a TOKEN_PRIVILEGES: a u32 count, then `count` LUID_AND_ATTRIBUTES at
    // the offset of its array field (4; both are 4-byte aligned). Reads stay inside the `needed`
    // bytes the call filled, checked below before each read.
    let count = unsafe { base.cast::<u32>().read() } as usize;
    let entry = size_of::<LUID_AND_ATTRIBUTES>();
    if 4 + count * entry > needed as usize {
        return Err(Win32Error::INVALID_DATA);
    }
    for i in 0..count {
        // SAFETY: in bounds by the check above; `read_unaligned` needs no alignment.
        let e = unsafe {
            base.add(4 + i * entry)
                .cast::<LUID_AND_ATTRIBUTES>()
                .read_unaligned()
        };
        if e.Luid.LowPart == luid.LowPart && e.Luid.HighPart == luid.HighPart {
            return Ok(e.Attributes & SE_PRIVILEGE_ENABLED != 0);
        }
    }
    Ok(false)
}

/// Ends the current thread's impersonation on drop (also on unwind). A revert that fails stops the
/// process: the thread would go on with `SeRestorePrivilege` enabled, and Windows documents that a
/// process must not continue then (F5 of the M2 fix-round review).
#[cfg(feature = "write")]
struct Impersonation;

#[cfg(feature = "write")]
impl Drop for Impersonation {
    fn drop(&mut self) {
        // SAFETY: takes no arguments; the thread impersonates since `SetThreadToken` succeeded.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

/// Runs `f` with `SeRestorePrivilege` enabled for the current thread only: on an impersonation copy
/// of the process token (what `ImpersonateSelf` makes), with the privilege enabled on the copy before
/// the thread uses it, set on this thread for the call and reverted right after it, also when `f`
/// panics. The process token is not changed and no other privilege is enabled.
///
/// Fails, without running `f` and without changing the thread, with [`PRIVILEGE_NOT_HELD`] when the
/// token does not hold the privilege (an unelevated token), with [`Win32Error::ACCESS_DENIED`] when
/// the thread already impersonates (that token is left alone), and with the error of a failed token
/// call.
///
/// Anything `f` opens with the privilege's help must be closed inside `f`: a handle outliving the
/// scope would keep what the privilege granted.
#[cfg(feature = "write")]
pub(crate) fn with_restore_privilege<T>(f: impl FnOnce() -> T) -> Result<T, Win32Error> {
    if thread_token(TOKEN_QUERY)?.is_some() {
        return Err(Win32Error::ACCESS_DENIED);
    }
    let mut process: HANDLE = ptr::null_mut();
    // SAFETY: the pseudo handle of the current process needs no closing; `process` is a valid
    // out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &mut process) } == 0 {
        return Err(Win32Error::last());
    }
    let process = Token(process);
    let mut copy: HANDLE = ptr::null_mut();
    // SAFETY: `process.0` is a live token opened with TOKEN_DUPLICATE; no attributes are given;
    // `copy` is a valid out-pointer.
    let ok = unsafe {
        DuplicateTokenEx(
            process.0,
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_IMPERSONATE,
            ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut copy,
        )
    };
    if ok == 0 {
        return Err(Win32Error::last());
    }
    let copy = Token(copy);
    drop(process);
    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: restore_luid()?,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: `copy.0` is a live token opened with TOKEN_ADJUST_PRIVILEGES; `privileges` is a valid
    // TOKEN_PRIVILEGES with one entry; the previous state is not requested.
    let ok = unsafe {
        AdjustTokenPrivileges(copy.0, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut())
    };
    // SAFETY: reads the calling thread's last error, as `AdjustTokenPrivileges` documents.
    let last = unsafe { GetLastError() };
    if ok == 0 {
        return Err(Win32Error(last));
    }
    if last == NOT_ALL_ASSIGNED {
        return Err(PRIVILEGE_NOT_HELD);
    }
    // SAFETY: a null thread pointer means the current thread; `copy.0` is a live impersonation
    // token opened with TOKEN_IMPERSONATE.
    if unsafe { SetThreadToken(ptr::null(), copy.0) } == 0 {
        return Err(Win32Error::last());
    }
    // The thread holds its own reference to the token now; `copy` is closed when this returns.
    let _revert = Impersonation;
    Ok(f())
}

#[cfg(all(test, feature = "write"))]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use windows_sys::Win32::Security::ImpersonateSelf;

    /// Off before (on the thread and in the process token) and after; the error when not held.
    /// Whatever the token: on inside, also after a panic inside, when it holds the privilege.
    #[test]
    fn privilege_is_on_only_inside_the_scope() {
        assert!(!thread_impersonates().unwrap());
        assert!(!restore_privilege_enabled().unwrap());
        match with_restore_privilege(|| {
            (
                thread_impersonates().unwrap(),
                restore_privilege_enabled().unwrap(),
            )
        }) {
            Ok(inside) => assert_eq!(inside, (true, true)),
            Err(e) => assert_eq!(e, PRIVILEGE_NOT_HELD),
        }
        assert!(!thread_impersonates().unwrap());
        assert!(!restore_privilege_enabled().unwrap());
    }

    /// Unelevated (the token does not hold the privilege): refused before anything changes, and the
    /// closure does not run.
    #[test]
    fn not_held_is_refused_without_running_the_closure() {
        if privilege_held() {
            return;
        }
        let mut ran = false;
        assert_eq!(
            with_restore_privilege(|| ran = true),
            Err(PRIVILEGE_NOT_HELD)
        );
        assert!(!ran);
        assert!(!thread_impersonates().unwrap());
        assert!(!restore_privilege_enabled().unwrap());
    }

    /// A thread that already impersonates keeps its token: refused, nothing run, the token left.
    #[test]
    fn a_thread_that_impersonates_is_refused_and_left_alone() {
        // SAFETY: a plain impersonation of the process's own token on this test thread, ended
        // below.
        assert_ne!(unsafe { ImpersonateSelf(SecurityImpersonation) }, 0);
        let mut ran = false;
        let r = with_restore_privilege(|| ran = true);
        let still = thread_impersonates();
        let enabled = restore_privilege_enabled();
        // SAFETY: ends the impersonation started above.
        assert_ne!(unsafe { RevertToSelf() }, 0);
        assert_eq!(r, Err(Win32Error::ACCESS_DENIED));
        assert!(!ran);
        assert!(still.unwrap());
        assert!(!enabled.unwrap());
        assert!(!thread_impersonates().unwrap());
    }

    /// Whether the token holds the privilege (an elevated administrator's does).
    fn privilege_held() -> bool {
        with_restore_privilege(|| ()).is_ok()
    }

    /// The elevated case: on inside, on a copy only (another thread and the process token stay
    /// off), and off after a panic inside. Needs an elevated administrator:
    /// `cargo test -p purge-win --features write --lib -- --ignored elevated_privilege_scope`.
    #[test]
    #[ignore = "needs an elevated administrator (SeRestorePrivilege)"]
    fn elevated_privilege_scope_holds_also_on_panic() {
        assert!(privilege_held(), "run elevated");
        let inside = with_restore_privilege(|| {
            let other = std::thread::spawn(|| {
                (
                    thread_impersonates().unwrap(),
                    restore_privilege_enabled().unwrap(),
                )
            })
            .join()
            .unwrap();
            (
                thread_impersonates().unwrap(),
                restore_privilege_enabled().unwrap(),
                other,
            )
        })
        .unwrap();
        assert_eq!(inside, (true, true, (false, false)));
        assert!(!thread_impersonates().unwrap());
        assert!(!restore_privilege_enabled().unwrap());

        let panicked = catch_unwind(AssertUnwindSafe(|| {
            with_restore_privilege(|| {
                assert!(restore_privilege_enabled().unwrap());
                panic!("inside the scope");
            })
        }));
        assert!(panicked.is_err());
        assert!(!thread_impersonates().unwrap());
        assert!(!restore_privilege_enabled().unwrap());
    }
}
