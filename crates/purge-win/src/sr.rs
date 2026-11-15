//! System Restore: ask Windows for a restore point and report what happened (`write` feature).
//!
//! ENGINE_PLAN.md §7.3 and §7.7. [`create_restore_point`] calls `SRSetRestorePointW` from
//! `srclient.dll` with `BEGIN_SYSTEM_CHANGE` / `APPLICATION_UNINSTALL`, then `END_SYSTEM_CHANGE` with the
//! sequence number it returned, and maps the result to an [`SrOutcome`]. `srclient.dll` is loaded at run
//! time from System32 (`LoadLibraryExW` with `LOAD_LIBRARY_SEARCH_SYSTEM32`, as the API documentation asks
//! instead of load-time linking), so a Windows edition without System Restore still starts Purge.
//!
//! Windows creates at most one API restore point per `SystemRestorePointCreationFrequency` window (24 h by
//! default) and is expected to answer a throttled request with success (to be confirmed in the VM). The
//! throttle is detected by comparing the
//! returned sequence number with the latest existing one, read beforehand by [`latest_sequence`] (WMI
//! `ROOT\DEFAULT:SystemRestore`; needs administrator rights). Purge never reads or writes
//! `SystemRestorePointCreationFrequency` and never enables System Protection: it only asks for a restore
//! point and reports the answer. A restore point supplements quarantine and never replaces it.
//!
//! Both calls block (creating a restore point can take minutes), so callers run them on a helper thread.
//! COM is initialised on the calling thread for [`latest_sequence`] and balanced afterwards.
//!
//! Process-wide COM security (`CoInitializeSecurity`) is never set here. If the broker sets it, it must do
//! so at start-up before any COM call: the first [`latest_sequence`] call would otherwise fix the
//! defaults. Whether `SRSetRestorePointW` needs more than the defaults is checked in the VM.

use std::ffi::c_void;
use std::ptr;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{
    ERROR_INTERNAL_ERROR, ERROR_INVALID_DATA, ERROR_SERVICE_DISABLED, HANDLE, HMODULE,
    RPC_E_CHANGED_MODE, SysAllocString, SysFreeString,
};
use windows_sys::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
    CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
    RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows_sys::Win32::System::Restore::{
    APPLICATION_UNINSTALL, BEGIN_SYSTEM_CHANGE, END_SYSTEM_CHANGE, MAX_DESC_W, RESTOREPOINTINFOW,
    STATEMGRSTATUS,
};
use windows_sys::core::{BOOL, BSTR, GUID, HRESULT, PCSTR, PCWSTR};

use crate::os::{Win32Error, wide};

/// What became of a restore-point request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrOutcome {
    /// A new restore point was created and completed.
    Created {
        /// Its sequence number.
        seq: u64,
    },
    /// Windows answered with success but created no new point, because one was created within the
    /// `SystemRestorePointCreationFrequency` window (24 h by default).
    Throttled {
        /// The sequence number Windows returned (that of the existing point).
        seq: u64,
    },
    /// System Restore is turned off (System Protection disabled), or this Windows edition has no
    /// System Restore (`srclient.dll` or its export missing). Not an error: the caller reports it.
    Disabled,
    /// The request failed with this Win32 code (`STATEMGRSTATUS.nStatus`, or the last error). Known
    /// codes: `ERROR_ACCESS_DENIED` (not elevated), `ERROR_BAD_ENVIRONMENT` (safe mode),
    /// `ERROR_DISK_FULL`, `ERROR_TIMEOUT`, `ERROR_INTERNAL_ERROR`.
    Failed(u32),
}

/// What [`latest_sequence`] knew before the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prior {
    /// No restore point existed.
    NoPoints,
    /// The highest existing sequence number.
    Latest(u64),
    /// The query failed; throttling cannot be told apart from creation.
    Unknown,
}

/// Next step after the `BEGIN_SYSTEM_CHANGE` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Begin {
    /// Final answer; `END_SYSTEM_CHANGE` is not called.
    Done(SrOutcome),
    /// A new point was started with this sequence number; complete it with `END_SYSTEM_CHANGE`.
    End(u64),
}

/// The throttle decision, from the prior state and the `BEGIN_SYSTEM_CHANGE` result (`ok`,
/// `STATEMGRSTATUS.nStatus` or the last error, returned sequence number).
fn decide_begin(prior: Prior, ok: bool, status: u32, seq: i64) -> Begin {
    if !ok {
        return Begin::Done(match status {
            ERROR_SERVICE_DISABLED => SrOutcome::Disabled,
            0 => SrOutcome::Failed(ERROR_INTERNAL_ERROR),
            code => SrOutcome::Failed(code),
        });
    }
    let Ok(seq) = u64::try_from(seq) else {
        return Begin::Done(SrOutcome::Failed(ERROR_INVALID_DATA));
    };
    if seq == 0 {
        return Begin::Done(SrOutcome::Failed(ERROR_INVALID_DATA));
    }
    match prior {
        Prior::Latest(latest) if seq <= latest => Begin::Done(SrOutcome::Throttled { seq }),
        Prior::Latest(_) | Prior::NoPoints | Prior::Unknown => Begin::End(seq),
    }
}

/// `description` as a NUL-terminated `szDescription` field: cut at the first NUL and to
/// `MAX_DESC_W - 1` UTF-16 units without splitting a surrogate pair.
fn description_field(description: &str) -> [u16; MAX_DESC_W as usize] {
    let mut out = [0u16; MAX_DESC_W as usize];
    let max = out.len() - 1;
    let mut len = 0;
    for ch in description.chars().take_while(|&c| c != '\0') {
        let mut buf = [0u16; 2];
        let units = ch.encode_utf16(&mut buf);
        if len + units.len() > max {
            break;
        }
        out[len..len + units.len()].copy_from_slice(units);
        len += units.len();
    }
    out
}

/// `SRSetRestorePointW`.
type SrSetRestorePointW =
    unsafe extern "system" fn(*const RESTOREPOINTINFOW, *mut STATEMGRSTATUS) -> BOOL;

/// `LOAD_LIBRARY_SEARCH_SYSTEM32`.
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

// The `Win32_System_LibraryLoader` feature of windows-sys is not enabled for this crate; these two
// kernel32 functions are declared here instead.
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(name: PCWSTR, file: HANDLE, flags: u32) -> HMODULE;
    fn GetProcAddress(module: HMODULE, name: PCSTR)
    -> Option<unsafe extern "system" fn() -> isize>;
}

/// `SRSetRestorePointW` from `%SystemRoot%\System32\srclient.dll`, loaded once and kept for the life of
/// the process. `Err` holds the Win32 code when the DLL or the export is missing.
fn sr_set_restore_point() -> Result<SrSetRestorePointW, u32> {
    static FUNC: OnceLock<Result<usize, u32>> = OnceLock::new();
    let addr = (*FUNC.get_or_init(|| {
        let name = wide("srclient.dll");
        // SAFETY: NUL-terminated name; System32 only, so no DLL planting from the current directory.
        let module =
            unsafe { LoadLibraryExW(name.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if module.is_null() {
            return Err(Win32Error::last().code());
        }
        // SAFETY: `module` is a loaded module that is never freed; NUL-terminated ANSI export name.
        match unsafe { GetProcAddress(module, c"SRSetRestorePointW".as_ptr().cast()) } {
            Some(f) => Ok(f as usize),
            None => Err(Win32Error::last().code()),
        }
    }))?;
    // SAFETY: `addr` is the address of the `SRSetRestorePointW` export of a module that stays loaded, and
    // `SrSetRestorePointW` is its documented signature.
    Ok(unsafe { std::mem::transmute::<usize, SrSetRestorePointW>(addr) })
}

/// One `SRSetRestorePointW` call: (`ok`, `nStatus` or the last error when `nStatus` is 0, sequence).
fn call_sr(func: SrSetRestorePointW, info: &RESTOREPOINTINFOW) -> (bool, u32, i64) {
    let mut status = STATEMGRSTATUS::default();
    // SAFETY: `info` and `status` are valid, correctly laid out structures for the duration of the call.
    let ok = unsafe { func(info, &mut status) } != 0;
    let mut code = status.nStatus;
    if !ok && code == 0 {
        code = Win32Error::last().code();
    }
    let seq = status.llSequenceNumber;
    (ok, code, seq)
}

/// Asks Windows for a restore point of type `APPLICATION_UNINSTALL` named `description` (cut to 255
/// UTF-16 units) and reports the result. Blocks until System Restore answers.
///
/// Needs an elevated caller. Never changes the System Restore configuration. Throttling is detected only
/// when [`latest_sequence`] succeeds beforehand; when it fails, a throttled request reads as `Created`.
pub fn create_restore_point(description: &str) -> SrOutcome {
    let func = match sr_set_restore_point() {
        Ok(f) => f,
        Err(_) => return SrOutcome::Disabled,
    };
    let prior = match latest_sequence() {
        Ok(Some(seq)) => Prior::Latest(seq),
        Ok(None) => Prior::NoPoints,
        Err(_) => Prior::Unknown,
    };
    let begin = RESTOREPOINTINFOW {
        dwEventType: BEGIN_SYSTEM_CHANGE,
        dwRestorePtType: APPLICATION_UNINSTALL,
        llSequenceNumber: 0,
        szDescription: description_field(description),
    };
    let (ok, status, seq) = call_sr(func, &begin);
    let seq = match decide_begin(prior, ok, status, seq) {
        Begin::Done(outcome) => return outcome,
        Begin::End(seq) => seq,
    };
    let end = RESTOREPOINTINFOW {
        dwEventType: END_SYSTEM_CHANGE,
        dwRestorePtType: APPLICATION_UNINSTALL,
        llSequenceNumber: seq as i64,
        szDescription: [0; MAX_DESC_W as usize],
    };
    let (ok, status, _) = call_sr(func, &end);
    if ok {
        SrOutcome::Created { seq }
    } else if status == ERROR_SERVICE_DISABLED {
        SrOutcome::Disabled
    } else {
        SrOutcome::Failed(status)
    }
}

// ---- WMI read side --------------------------------------------------------------------------------

const CLSID_WBEM_LOCATOR: GUID = GUID::from_u128(0x4590f811_1d3a_11d0_891f_00aa004b2e24);
const IID_IWBEM_LOCATOR: GUID = GUID::from_u128(0xdc12a687_737f_11cf_884d_00aa004b2e24);
/// `RPC_C_AUTHN_WINNT`.
const RPC_C_AUTHN_WINNT: u32 = 10;
/// `RPC_C_AUTHZ_NONE`.
const RPC_C_AUTHZ_NONE: u32 = 0;
/// `WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY`.
const WBEM_QUERY_FLAGS: i32 = 0x10 | 0x20;
/// `WBEM_S_TIMEDOUT`.
const WBEM_S_TIMEDOUT: HRESULT = 0x0004_0004;
/// `WBEM_E_ACCESS_DENIED`.
const WBEM_E_ACCESS_DENIED: HRESULT = 0x8004_1003_u32 as HRESULT;
/// Timeout of one `IEnumWbemClassObject::Next` call, in milliseconds.
const WMI_NEXT_TIMEOUT_MS: i32 = 30_000;
/// `VARTYPE` tags handled for `SequenceNumber`.
const VT_I4: u16 = 3;
const VT_BSTR: u16 = 8;
const VT_UI4: u16 = 19;
const VT_I8: u16 = 20;
const VT_UI8: u16 = 21;

/// `VARIANT` (24 bytes on x64): type tag, three reserved words, 16-byte payload.
#[repr(C)]
struct Variant {
    vt: u16,
    reserved: [u16; 3],
    data: [u64; 2],
}

// `VariantClear` lives in the `Win32_System_Variant` feature, which this crate does not enable.
#[link(name = "oleaut32")]
unsafe extern "system" {
    fn VariantClear(var: *mut Variant) -> HRESULT;
}

type Slot = usize;

#[repr(C)]
struct IUnknownVtbl {
    query_interface: Slot,
    add_ref: Slot,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

#[repr(C)]
struct IWbemLocatorVtbl {
    base: IUnknownVtbl,
    #[allow(clippy::type_complexity)]
    connect_server: unsafe extern "system" fn(
        *mut c_void,
        BSTR,
        BSTR,
        BSTR,
        BSTR,
        i32,
        BSTR,
        *mut c_void,
        *mut *mut c_void,
    ) -> HRESULT,
}

#[repr(C)]
struct IWbemServicesVtbl {
    base: IUnknownVtbl,
    /// `OpenNamespace` … `CreateInstanceEnumAsync`: 17 methods not used here.
    unused: [Slot; 17],
    exec_query: unsafe extern "system" fn(
        *mut c_void,
        BSTR,
        BSTR,
        i32,
        *mut c_void,
        *mut *mut c_void,
    ) -> HRESULT,
}

#[repr(C)]
struct IEnumWbemClassObjectVtbl {
    base: IUnknownVtbl,
    reset: Slot,
    next: unsafe extern "system" fn(*mut c_void, i32, u32, *mut *mut c_void, *mut u32) -> HRESULT,
}

#[repr(C)]
struct IWbemClassObjectVtbl {
    base: IUnknownVtbl,
    get_qualifier_set: Slot,
    get: unsafe extern "system" fn(
        *mut c_void,
        PCWSTR,
        i32,
        *mut Variant,
        *mut i32,
        *mut i32,
    ) -> HRESULT,
}

/// An owned COM interface pointer, released on drop.
struct ComPtr(*mut c_void);

impl ComPtr {
    /// The vtable, typed as `V`.
    ///
    /// # Safety
    /// `V` must be the vtable layout (or a prefix of it) of the interface this pointer holds.
    unsafe fn vtbl<V>(&self) -> &V {
        // SAFETY: a COM interface pointer points at a pointer to its vtable; the caller picks `V`.
        unsafe { &**(self.0 as *const *const V) }
    }
}

impl Drop for ComPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: we own one reference; every interface starts with IUnknown.
            unsafe { (self.vtbl::<IUnknownVtbl>().release)(self.0) };
        }
    }
}

/// An owned `BSTR`, freed on drop.
struct Bstr(BSTR);

impl Bstr {
    fn new(s: &str) -> Result<Bstr, Win32Error> {
        let w = wide(s);
        // SAFETY: NUL-terminated input; the result is owned by this value.
        let b = unsafe { SysAllocString(w.as_ptr()) };
        if b.is_null() {
            Err(Win32Error(
                windows_sys::Win32::Foundation::ERROR_OUTOFMEMORY,
            ))
        } else {
            Ok(Bstr(b))
        }
    }
}

impl Drop for Bstr {
    fn drop(&mut self) {
        // SAFETY: allocated by SysAllocString and freed exactly once.
        unsafe { SysFreeString(self.0) };
    }
}

/// Balances a successful `CoInitializeEx` on drop.
struct ComInit {
    uninit: bool,
}

impl ComInit {
    fn new() -> Result<ComInit, Win32Error> {
        // SAFETY: plain call; the result decides whether we must uninitialise.
        let hr = unsafe { CoInitializeEx(ptr::null(), COINIT_MULTITHREADED as u32) };
        if hr == RPC_E_CHANGED_MODE {
            // The thread is already in a single-threaded apartment: COM is usable as is.
            return Ok(ComInit { uninit: false });
        }
        check(hr)?;
        Ok(ComInit { uninit: true })
    }
}

impl Drop for ComInit {
    fn drop(&mut self) {
        if self.uninit {
            // SAFETY: balances the successful CoInitializeEx in `new` on the same thread.
            unsafe { CoUninitialize() };
        }
    }
}

/// Maps an `HRESULT` to a Win32 error: `HRESULT_FROM_WIN32` codes unwrap to their Win32 code,
/// `WBEM_E_ACCESS_DENIED` becomes `ERROR_ACCESS_DENIED`, other failure codes are kept whole.
fn hresult_error(hr: HRESULT) -> Win32Error {
    let u = hr as u32;
    if hr == WBEM_E_ACCESS_DENIED {
        Win32Error::ACCESS_DENIED
    } else if u & 0xFFFF_0000 == 0x8007_0000 {
        Win32Error(u & 0xFFFF)
    } else {
        Win32Error(u)
    }
}

fn check(hr: HRESULT) -> Result<(), Win32Error> {
    if hr < 0 {
        Err(hresult_error(hr))
    } else {
        Ok(())
    }
}

/// Sets the WMI proxy to impersonation level, as WMI requires.
fn set_blanket(proxy: &ComPtr) -> Result<(), Win32Error> {
    // SAFETY: `proxy` is a live interface pointer; default principal, no auth identity.
    check(unsafe {
        CoSetProxyBlanket(
            proxy.0,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            ptr::null(),
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            ptr::null(),
            EOAC_NONE as u32,
        )
    })
}

/// A `SequenceNumber` value as a number; `None` for null or an unexpected type.
fn variant_u64(v: &Variant) -> Option<u64> {
    match v.vt {
        VT_I4 => u64::try_from(v.data[0] as u32 as i32).ok(),
        VT_UI4 => Some(u64::from(v.data[0] as u32)),
        VT_I8 => u64::try_from(v.data[0] as i64).ok(),
        VT_UI8 => Some(v.data[0]),
        VT_BSTR => {
            // SAFETY: a VT_BSTR variant holds a NUL-terminated BSTR (or null) in its first word.
            let s = unsafe { crate::os::from_wide_ptr(v.data[0] as usize as *const u16) };
            s.trim().parse().ok()
        }
        _ => None,
    }
}

/// The highest sequence number among the existing restore points (`SELECT SequenceNumber FROM
/// SystemRestore` in `ROOT\DEFAULT`), `Ok(None)` when there is none. Read only.
///
/// Needs administrator rights: an unelevated caller gets `ERROR_ACCESS_DENIED`. On an edition without
/// System Restore the class is missing and the WMI error is returned.
pub fn latest_sequence() -> Result<Option<u64>, Win32Error> {
    let _com = ComInit::new()?;

    let mut locator = ptr::null_mut();
    // SAFETY: valid CLSID/IID and out-pointer; COM is initialised on this thread.
    check(unsafe {
        CoCreateInstance(
            &CLSID_WBEM_LOCATOR,
            ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_IWBEM_LOCATOR,
            &mut locator,
        )
    })?;
    let locator = ComPtr(locator);

    let namespace = Bstr::new(r"ROOT\DEFAULT")?;
    let mut services = ptr::null_mut();
    // SAFETY: `locator` is an IWbemLocator; null user, password, locale, authority and context mean the
    // current identity on the local machine; `services` is a valid out-pointer.
    check(unsafe {
        (locator.vtbl::<IWbemLocatorVtbl>().connect_server)(
            locator.0,
            namespace.0,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            ptr::null(),
            ptr::null_mut(),
            &mut services,
        )
    })?;
    let services = ComPtr(services);
    set_blanket(&services)?;

    let language = Bstr::new("WQL")?;
    let query = Bstr::new("SELECT SequenceNumber FROM SystemRestore")?;
    let mut rows = ptr::null_mut();
    // SAFETY: `services` is an IWbemServices; BSTR arguments live across the call; no context.
    check(unsafe {
        (services.vtbl::<IWbemServicesVtbl>().exec_query)(
            services.0,
            language.0,
            query.0,
            WBEM_QUERY_FLAGS,
            ptr::null_mut(),
            &mut rows,
        )
    })?;
    let rows = ComPtr(rows);
    // The enumerator is a separate proxy; give it the same blanket. Failure here is not fatal: the
    // following Next call reports any real access problem.
    let _ = set_blanket(&rows);

    let field = wide("SequenceNumber");
    let mut latest: Option<u64> = None;
    loop {
        let mut obj = ptr::null_mut();
        let mut returned = 0u32;
        // SAFETY: `rows` is an IEnumWbemClassObject; room for exactly one object.
        let hr = unsafe {
            (rows.vtbl::<IEnumWbemClassObjectVtbl>().next)(
                rows.0,
                WMI_NEXT_TIMEOUT_MS,
                1,
                &mut obj,
                &mut returned,
            )
        };
        check(hr)?;
        if returned == 0 {
            if hr == WBEM_S_TIMEDOUT {
                return Err(Win32Error(windows_sys::Win32::Foundation::ERROR_TIMEOUT));
            }
            break;
        }
        let obj = ComPtr(obj);
        let mut value = Variant {
            vt: 0,
            reserved: [0; 3],
            data: [0; 2],
        };
        // SAFETY: `obj` is an IWbemClassObject; NUL-terminated property name; `value` is an empty
        // VARIANT; type and flavor are not requested.
        let hr = unsafe {
            (obj.vtbl::<IWbemClassObjectVtbl>().get)(
                obj.0,
                field.as_ptr(),
                0,
                &mut value,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        let seq = if hr >= 0 { variant_u64(&value) } else { None };
        // SAFETY: `value` is a VARIANT that Get filled or left empty.
        unsafe { VariantClear(&mut value) };
        check(hr)?;
        if let Some(seq) = seq {
            latest = Some(latest.map_or(seq, |l| l.max(seq)));
        }
    }
    Ok(latest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_failures() {
        for prior in [Prior::NoPoints, Prior::Latest(5), Prior::Unknown] {
            assert_eq!(
                decide_begin(prior, false, ERROR_SERVICE_DISABLED, 0),
                Begin::Done(SrOutcome::Disabled)
            );
            assert_eq!(
                decide_begin(prior, false, 5, 0),
                Begin::Done(SrOutcome::Failed(5))
            );
            assert_eq!(
                decide_begin(prior, false, 0, 9),
                Begin::Done(SrOutcome::Failed(ERROR_INTERNAL_ERROR))
            );
            // Success without a usable sequence number.
            assert_eq!(
                decide_begin(prior, true, 0, 0),
                Begin::Done(SrOutcome::Failed(ERROR_INVALID_DATA))
            );
            assert_eq!(
                decide_begin(prior, true, 0, -3),
                Begin::Done(SrOutcome::Failed(ERROR_INVALID_DATA))
            );
        }
    }

    #[test]
    fn throttle_decision() {
        // Returned sequence at or below the latest existing one: nothing new was created.
        assert_eq!(
            decide_begin(Prior::Latest(102), true, 0, 102),
            Begin::Done(SrOutcome::Throttled { seq: 102 })
        );
        assert_eq!(
            decide_begin(Prior::Latest(102), true, 0, 90),
            Begin::Done(SrOutcome::Throttled { seq: 90 })
        );
        // Higher sequence: a new point, to be completed.
        assert_eq!(
            decide_begin(Prior::Latest(102), true, 0, 103),
            Begin::End(103)
        );
        assert_eq!(decide_begin(Prior::NoPoints, true, 0, 1), Begin::End(1));
        // Unknown prior state cannot detect throttling.
        assert_eq!(decide_begin(Prior::Unknown, true, 0, 7), Begin::End(7));
    }

    #[test]
    fn description_is_cut_and_terminated() {
        let d = description_field("Purge: Example App");
        assert_eq!(crate::os::from_wide(&d), "Purge: Example App");

        let long = "x".repeat(400);
        let d = description_field(&long);
        assert_eq!(d[MAX_DESC_W as usize - 1], 0);
        assert_eq!(crate::os::from_wide(&d).len(), MAX_DESC_W as usize - 1);

        // A surrogate pair that would straddle the limit is dropped whole.
        let s = format!("{}\u{1F600}", "y".repeat(254));
        let d = description_field(&s);
        assert_eq!(crate::os::from_wide(&d), "y".repeat(254));

        assert_eq!(crate::os::from_wide(&description_field("a\0b")), "a");
    }

    #[test]
    fn variant_values() {
        let v = |vt, d| Variant {
            vt,
            reserved: [0; 3],
            data: [d, 0],
        };
        assert_eq!(variant_u64(&v(VT_I4, 102)), Some(102));
        assert_eq!(variant_u64(&v(VT_I4, 0xFFFF_FFFF)), None);
        assert_eq!(variant_u64(&v(VT_UI4, 0xFFFF_FFFF)), Some(0xFFFF_FFFF));
        assert_eq!(variant_u64(&v(VT_UI8, 7)), Some(7));
        assert_eq!(variant_u64(&v(1, 7)), None);
    }

    #[test]
    fn hresult_mapping() {
        assert_eq!(
            hresult_error(WBEM_E_ACCESS_DENIED),
            Win32Error::ACCESS_DENIED
        );
        assert_eq!(
            hresult_error(0x8007_0005_u32 as i32),
            Win32Error::ACCESS_DENIED
        );
        assert_eq!(
            hresult_error(0x8004_1010_u32 as i32),
            Win32Error(0x8004_1010)
        );
    }

    #[test]
    fn srclient_export_resolves() {
        // Loading the DLL and resolving the export changes nothing on the system.
        match sr_set_restore_point() {
            Ok(_) => {}
            Err(code) => panic!("srclient.dll!SRSetRestorePointW not available: {code}"),
        }
    }

    #[test]
    fn latest_sequence_read_only() {
        // Unelevated, WMI refuses the SystemRestore class; elevated, it lists the points.
        match latest_sequence() {
            Ok(seq) => println!("latest restore point: {seq:?}"),
            Err(e) => {
                println!("latest_sequence: {e}");
                assert_eq!(e, Win32Error::ACCESS_DENIED, "{e}");
            }
        }
    }

    #[test]
    #[ignore = "creates a real restore point; VM only (elevated, System Protection on)"]
    fn create_restore_point_vm() {
        let before = latest_sequence().expect("latest_sequence needs elevation");
        let outcome = create_restore_point("Purge test restore point");
        println!("before {before:?}, outcome {outcome:?}");
        match outcome {
            SrOutcome::Created { seq } => {
                assert!(before.is_none_or(|b| seq > b));
                assert_eq!(latest_sequence().unwrap(), Some(seq));
            }
            SrOutcome::Throttled { seq } => assert!(before.is_some_and(|b| seq <= b)),
            other => panic!("unexpected outcome {other:?}"),
        }
        // A second request right away: throttled unless the rig set a test-only frequency override.
        println!(
            "second request: {:?}",
            create_restore_point("Purge test restore point 2")
        );
    }
}
