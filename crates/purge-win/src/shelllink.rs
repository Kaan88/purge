//! Reading shell links (`.lnk`) without resolving them.
//!
//! ENGINE_PLAN.md Â§3.2 and Â§5.6 (FS-SHORTCUTS). The link is loaded with `IShellLinkW` +
//! `IPersistFile::Load`, then read with `GetPath(SLGP_RAWPATH)` (environment variables unexpanded),
//! `GetArguments`, `GetWorkingDirectory`, and the AppUserModelID through `IPropertyStore`
//! (`System.AppUserModel.ID`). `IShellLinkW::Resolve` is never called: resolving can search the disk,
//! touch the network and rewrite the link.
//!
//! COM is initialised on the calling thread (`CoInitializeEx`, apartment-threaded) for the duration of
//! each call and balanced afterwards; a thread already in the multithreaded apartment is used as is. A
//! thread that reads many links holds an [`Apartment`], so that COM stays up between the calls.
//! `windows-sys` has no COM method bindings, so the few vtable slots used here are declared locally.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows_sys::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance,
    CoInitializeEx, CoUninitialize,
};
use windows_sys::core::{BOOL, GUID, HRESULT, PCWSTR, PWSTR};

/// What a shell link points at, as stored. Empty values are `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShellLinkInfo {
    /// Target path from `GetPath(SLGP_RAWPATH)`; `None` for links to non-file-system items.
    pub raw_path: Option<String>,
    /// Command-line arguments.
    pub arguments: Option<String>,
    /// Working directory.
    pub working_directory: Option<String>,
    /// `System.AppUserModel.ID`, when the link carries one.
    pub aumid: Option<String>,
}

const CLSID_SHELL_LINK: GUID = GUID::from_u128(0x00021401_0000_0000_c000_000000000046);
const IID_ISHELL_LINK_W: GUID = GUID::from_u128(0x000214f9_0000_0000_c000_000000000046);
const IID_IPERSIST_FILE: GUID = GUID::from_u128(0x0000010b_0000_0000_c000_000000000046);
const IID_IPROPERTY_STORE: GUID = GUID::from_u128(0x886d8eeb_8cf2_4446_8d02_cdba1dbdcf99);
/// `PKEY_AppUserModel_ID`.
const PKEY_APP_USER_MODEL_ID: PropertyKey = PropertyKey {
    fmtid: GUID::from_u128(0x9f4c2855_9f79_4b39_a8d0_e1d42de1d5f3),
    pid: 5,
};

/// `SLGP_RAWPATH`.
const SLGP_RAWPATH: u32 = 0x4;
/// `STGM_READ`.
const STGM_READ: u32 = 0;
/// `VT_EMPTY` / `VT_LPWSTR`.
const VT_EMPTY: u16 = 0;
const VT_LPWSTR: u16 = 31;
/// Buffer size for paths and arguments, in characters.
const BUF_CHARS: usize = 32 * 1024;

#[repr(C)]
struct PropertyKey {
    fmtid: GUID,
    pid: u32,
}

/// `PROPVARIANT` (24 bytes on x64): type tag, three reserved words, 16-byte payload.
#[repr(C)]
struct PropVariant {
    vt: u16,
    reserved: [u16; 3],
    data: [usize; 2],
}

#[link(name = "ole32")]
unsafe extern "system" {
    fn PropVariantClear(pvar: *mut PropVariant) -> HRESULT;
}

type Slot = usize;

#[repr(C)]
struct IUnknownVtbl {
    query_interface:
        unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

#[repr(C)]
struct IShellLinkWVtbl {
    base: IUnknownVtbl,
    get_path: unsafe extern "system" fn(*mut c_void, PWSTR, i32, *mut c_void, u32) -> HRESULT,
    get_id_list: Slot,
    set_id_list: Slot,
    get_description: Slot,
    set_description: Slot,
    get_working_directory: unsafe extern "system" fn(*mut c_void, PWSTR, i32) -> HRESULT,
    set_working_directory: unsafe extern "system" fn(*mut c_void, PCWSTR) -> HRESULT,
    get_arguments: unsafe extern "system" fn(*mut c_void, PWSTR, i32) -> HRESULT,
    set_arguments: unsafe extern "system" fn(*mut c_void, PCWSTR) -> HRESULT,
    get_hotkey: Slot,
    set_hotkey: Slot,
    get_show_cmd: Slot,
    set_show_cmd: Slot,
    get_icon_location: Slot,
    set_icon_location: Slot,
    set_relative_path: Slot,
    /// Present for layout only; never called.
    resolve: Slot,
    set_path: unsafe extern "system" fn(*mut c_void, PCWSTR) -> HRESULT,
}

#[repr(C)]
struct IPersistFileVtbl {
    base: IUnknownVtbl,
    get_class_id: Slot,
    is_dirty: Slot,
    load: unsafe extern "system" fn(*mut c_void, PCWSTR, u32) -> HRESULT,
    save: unsafe extern "system" fn(*mut c_void, PCWSTR, BOOL) -> HRESULT,
    save_completed: Slot,
    get_cur_file: Slot,
}

#[repr(C)]
struct IPropertyStoreVtbl {
    base: IUnknownVtbl,
    get_count: Slot,
    get_at: Slot,
    get_value:
        unsafe extern "system" fn(*mut c_void, *const PropertyKey, *mut PropVariant) -> HRESULT,
    set_value:
        unsafe extern "system" fn(*mut c_void, *const PropertyKey, *const PropVariant) -> HRESULT,
    commit: unsafe extern "system" fn(*mut c_void) -> HRESULT,
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

    fn query(&self, iid: &GUID) -> io::Result<ComPtr> {
        let mut out = ptr::null_mut();
        // SAFETY: every COM interface starts with IUnknown.
        let hr = unsafe { (self.vtbl::<IUnknownVtbl>().query_interface)(self.0, iid, &mut out) };
        check(hr)?;
        Ok(ComPtr(out))
    }
}

impl Drop for ComPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: we own one reference.
            unsafe { (self.vtbl::<IUnknownVtbl>().release)(self.0) };
        }
    }
}

fn check(hr: HRESULT) -> io::Result<()> {
    if hr < 0 {
        Err(io::Error::from_raw_os_error(hr))
    } else {
        Ok(())
    }
}

/// Balances a successful `CoInitializeEx` on drop.
struct ComInit {
    uninit: bool,
}

impl ComInit {
    fn new() -> io::Result<Self> {
        // SAFETY: plain call; the result decides whether we must uninitialise.
        let hr = unsafe {
            CoInitializeEx(
                ptr::null(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
            )
        };
        if hr == RPC_E_CHANGED_MODE {
            // Already in the MTA: COM is usable, but this call did not initialise it.
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

/// The calling thread's membership in a single-threaded apartment, for a thread that reads many links:
/// with it held, each [`read_shell_link`] on the thread joins the apartment that is already there
/// instead of starting COM up and shutting it down again for every link. The reads are the same.
/// Left on drop, on the thread that entered it (the type is neither `Send` nor `Sync`).
pub struct Apartment {
    _init: ComInit,
    _not_send: std::marker::PhantomData<*const ()>,
}

impl Apartment {
    /// Enters a single-threaded apartment (or, on a thread already in the multithreaded one, uses that).
    ///
    /// # Errors
    ///
    /// The `CoInitializeEx` failure.
    pub fn enter() -> io::Result<Apartment> {
        Ok(Apartment {
            _init: ComInit::new()?,
            _not_send: std::marker::PhantomData,
        })
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn buf_to_option(buf: &[u16]) -> Option<String> {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let s = String::from_utf16_lossy(&buf[..len]);
    (!s.is_empty()).then_some(s)
}

fn create_shell_link() -> io::Result<ComPtr> {
    let mut link = ptr::null_mut();
    // SAFETY: valid CLSID/IID and out-pointer; COM is initialised by the caller.
    let hr = unsafe {
        CoCreateInstance(
            &CLSID_SHELL_LINK,
            ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_ISHELL_LINK_W,
            &mut link,
        )
    };
    check(hr)?;
    Ok(ComPtr(link))
}

/// Reads a `.lnk` file. Never resolves it.
pub fn read_shell_link(path: &Path) -> io::Result<ShellLinkInfo> {
    // Report a missing file as such rather than as an opaque HRESULT.
    std::fs::metadata(path)?;
    let _com = ComInit::new()?;
    let link = create_shell_link()?;
    let persist = link.query(&IID_IPERSIST_FILE)?;
    let path_w = wide_path(path);
    // SAFETY: `persist` holds an IPersistFile; `path_w` is NUL-terminated.
    check(unsafe {
        (persist.vtbl::<IPersistFileVtbl>().load)(persist.0, path_w.as_ptr(), STGM_READ)
    })?;

    // SAFETY: `link` holds an IShellLinkW.
    let vt = unsafe { link.vtbl::<IShellLinkWVtbl>() };
    let mut buf = vec![0u16; BUF_CHARS];

    // S_FALSE (no path) leaves the buffer empty.
    // SAFETY: buffer of BUF_CHARS characters; pfd may be null.
    check(unsafe {
        (vt.get_path)(
            link.0,
            buf.as_mut_ptr(),
            BUF_CHARS as i32,
            ptr::null_mut(),
            SLGP_RAWPATH,
        )
    })?;
    let raw_path = buf_to_option(&buf);

    buf.fill(0);
    // SAFETY: as above.
    check(unsafe { (vt.get_arguments)(link.0, buf.as_mut_ptr(), BUF_CHARS as i32) })?;
    let arguments = buf_to_option(&buf);

    buf.fill(0);
    // SAFETY: as above.
    check(unsafe { (vt.get_working_directory)(link.0, buf.as_mut_ptr(), BUF_CHARS as i32) })?;
    let working_directory = buf_to_option(&buf);

    let aumid = link
        .query(&IID_IPROPERTY_STORE)
        .ok()
        .and_then(|store| read_aumid(&store));

    Ok(ShellLinkInfo {
        raw_path,
        arguments,
        working_directory,
        aumid,
    })
}

/// `System.AppUserModel.ID` from a link's property store.
fn read_aumid(store: &ComPtr) -> Option<String> {
    let mut pv = PropVariant {
        vt: VT_EMPTY,
        reserved: [0; 3],
        data: [0; 2],
    };
    // SAFETY: `store` holds an IPropertyStore; `pv` is a valid, empty PROPVARIANT.
    let hr = unsafe {
        (store.vtbl::<IPropertyStoreVtbl>().get_value)(store.0, &PKEY_APP_USER_MODEL_ID, &mut pv)
    };
    if hr < 0 {
        return None;
    }
    let value = if pv.vt == VT_LPWSTR && pv.data[0] != 0 {
        let p = pv.data[0] as *const u16;
        // SAFETY: a VT_LPWSTR PROPVARIANT holds a NUL-terminated string.
        let len = unsafe { (0..).take_while(|&i| *p.add(i) != 0).count() };
        // SAFETY: `len` characters were just counted.
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) });
        (!s.is_empty()).then_some(s)
    } else {
        None
    };
    // SAFETY: frees whatever GetValue allocated.
    unsafe { PropVariantClear(&mut pv) };
    value
}

/// Writes a `.lnk` with the same COM API. Used by tests to create fixtures in a temp directory.
#[cfg(test)]
pub(crate) fn write_shell_link_for_test(
    path: &Path,
    target: &str,
    arguments: &str,
    working_directory: &str,
    aumid: Option<&str>,
) -> io::Result<()> {
    let _com = ComInit::new()?;
    let link = create_shell_link()?;
    let w = |s: &str| {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>()
    };
    let (target_w, args_w, wd_w) = (w(target), w(arguments), w(working_directory));
    // SAFETY: `link` holds an IShellLinkW; strings are NUL-terminated.
    unsafe {
        let vt = link.vtbl::<IShellLinkWVtbl>();
        check((vt.set_path)(link.0, target_w.as_ptr()))?;
        check((vt.set_arguments)(link.0, args_w.as_ptr()))?;
        check((vt.set_working_directory)(link.0, wd_w.as_ptr()))?;
    }
    if let Some(id) = aumid {
        let store = link.query(&IID_IPROPERTY_STORE)?;
        let id_w = w(id);
        let pv = PropVariant {
            vt: VT_LPWSTR,
            reserved: [0; 3],
            data: [id_w.as_ptr() as usize, 0],
        };
        // SAFETY: SetValue copies the value; `id_w` outlives the call.
        unsafe {
            let vt = store.vtbl::<IPropertyStoreVtbl>();
            check((vt.set_value)(store.0, &PKEY_APP_USER_MODEL_ID, &pv))?;
            check((vt.commit)(store.0))?;
        }
    }
    let persist = link.query(&IID_IPERSIST_FILE)?;
    let path_w = wide_path(path);
    // SAFETY: `persist` holds an IPersistFile.
    check(unsafe { (persist.vtbl::<IPersistFileVtbl>().save)(persist.0, path_w.as_ptr(), 1) })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("purge-win-lnk-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn round_trip_raw_path_and_arguments() {
        let dir = temp_dir("rt");
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let target = format!(r"{root}\System32\cmd.exe");
        let lnk = dir.join("test link.lnk");
        let args = r#"/c echo "hello world" & exit 3"#;
        write_shell_link_for_test(&lnk, &target, args, &root, Some("Purge.Test.Link")).unwrap();

        let info = read_shell_link(&lnk).unwrap();
        assert_eq!(
            info.raw_path.as_deref().map(str::to_ascii_lowercase),
            Some(target.to_ascii_lowercase())
        );
        assert_eq!(info.arguments.as_deref(), Some(args));
        assert_eq!(
            info.working_directory
                .as_deref()
                .map(str::to_ascii_lowercase),
            Some(root.to_ascii_lowercase())
        );
        assert_eq!(info.aumid.as_deref(), Some("Purge.Test.Link"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn link_without_aumid_or_arguments() {
        let dir = temp_dir("plain");
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let target = format!(r"{root}\notepad.exe");
        let lnk = dir.join("plain.lnk");
        write_shell_link_for_test(&lnk, &target, "", "", None).unwrap();
        let info = read_shell_link(&lnk).unwrap();
        assert_eq!(
            info.raw_path.as_deref().map(str::to_ascii_lowercase),
            Some(target.to_ascii_lowercase())
        );
        assert_eq!(
            (info.arguments, info.working_directory, info.aumid),
            (None, None, None)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn works_from_an_mta_thread() {
        use windows_sys::Win32::System::Com::COINIT_MULTITHREADED;
        let dir = temp_dir("mta");
        let lnk = dir.join("mta.lnk");
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let target = format!(r"{root}\System32\cmd.exe");
        let lnk2 = lnk.clone();
        std::thread::spawn(move || {
            // SAFETY: initialise this thread as MTA, then the reader must cope with RPC_E_CHANGED_MODE.
            let hr = unsafe { CoInitializeEx(ptr::null(), COINIT_MULTITHREADED as u32) };
            assert!(hr >= 0);
            write_shell_link_for_test(&lnk2, &target, "/k", "", None).unwrap();
            let info = read_shell_link(&lnk2).unwrap();
            assert_eq!(info.arguments.as_deref(), Some("/k"));
            // SAFETY: balances the CoInitializeEx above.
            unsafe { CoUninitialize() };
        })
        .join()
        .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_or_bad_link_is_error() {
        assert!(read_shell_link(Path::new(r"C:\definitely\not\here.lnk")).is_err());
        let dir = temp_dir("bad");
        let bad = dir.join("bad.lnk");
        std::fs::write(&bad, b"not a link").unwrap();
        assert!(read_shell_link(&bad).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
