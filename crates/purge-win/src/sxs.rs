//! WinSxS component manifests: list them and expand them to XML (`read` feature; BL-WIN-SXS).
//!
//! `docs/BASELINE_LOCAL_DESIGN.md` §3.1 source S1. Most files in `%SystemRoot%\WinSxS\Manifests` are
//! not XML on disk but a 4-byte container tag followed by a payload:
//!
//! - `DCM\x01` + a `PA30` delta: [`expand`] applies it with `msdelta.dll` `ApplyDeltaB(0, base,
//!   file[4..])`, where the base ([`SxsBase`]) is resource type `0x266`, id `1` of `wcp.dll` in the
//!   newest `WinSxS\amd64_microsoft-windows-servicingstack_*` directory ([`find_base`]);
//! - `DCN\x01` + a `PA30` delta without a base: applied the same way to an empty source;
//! - `DCS\x01` (LZMS-compressed): not handled, reported as [`ExpandError::Unsupported`] so the caller
//!   counts it (none were found on the development hosts);
//! - anything whose first byte after an optional byte-order mark is `<`: plain XML, returned as is.
//!
//! [`list`] gives names, sizes and write times of the directory in one `FindFirstFileExW` pass.
//!
//! Rules (package BL-WIN-SXS): no write API and no process spawn; `wcp.dll` is mapped as a data file
//! (`LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE`, so none of its code runs), the base is
//! copied out and the module unloaded, and the caller reads the base once per build. A failed expansion
//! is an error value per file, never a panic; the caller counts it for the completeness seal (§3.4).
//! An expanded manifest larger than [`MAX_MANIFEST_SIZE`] is an error; the input read is capped at the
//! same size. The cap on the output is checked after `ApplyDeltaB` returned: the delta header declares
//! the target size and msdelta allocates it, so a corrupt delta can make msdelta allocate more first.
//!
//! `msdelta.dll` is loaded at run time from System32 only (`LOAD_LIBRARY_SEARCH_SYSTEM32`, as in `sr`),
//! so no copy next to the executable or in the current directory is ever used.
//!
//! Threads: `ApplyDeltaB` takes all its state in its arguments and returns a fresh buffer; Microsoft does
//! not document it as thread-safe or unsafe. The win-unit test
//! `parallel_expansion_matches_serial` expands the same manifests on 4 threads at once and compares
//! every output with a serial run, and the ignored `all_manifests_expand` expands every manifest on 4
//! threads. On the host (2026-11-21, Professional 26100.9711, 40,343 manifests: 39,562 `DCM`, 781
//! plain, no `DCN`/`DCS`) both found no difference and no failure; release build, 575.5 MB of XML in
//! 7.5 s on 1 thread and 2.8 s on 4 threads (directory listing 50-70 ms, base 40 ms). So no mutex is
//! taken and [`expand`] may be called from several threads with the same [`SxsBase`].

#![cfg(feature = "read")]

use std::ffi::c_void;
use std::fmt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{HANDLE, HMODULE};
use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
    DELTA_INPUT, DELTA_INPUT_0, DELTA_OUTPUT,
};
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::core::{BOOL, PCSTR, PCWSTR};

use crate::fs::{DirEntry, list_dir, read_bytes};
use crate::os::{Win32Error, from_wide, wide};

/// Largest expanded manifest (and largest manifest file read): 64 MiB.
pub const MAX_MANIFEST_SIZE: usize = 64 * 1024 * 1024;

/// Resource type of the delta base inside `wcp.dll`.
const BASE_RESOURCE_TYPE: u16 = 0x266;
/// Resource id of the delta base inside `wcp.dll`.
const BASE_RESOURCE_ID: u16 = 1;
/// Directory name prefix of the servicing stack component (lower case).
const SERVICING_STACK_PREFIX: &str = "amd64_microsoft-windows-servicingstack_";

/// The container of a manifest file, from its first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManifestFormat {
    /// XML as is (first byte `<`, after an optional UTF-8 or UTF-16 byte-order mark).
    Plain,
    /// `DCM\x01`: a `PA30` delta against the `wcp.dll` base.
    Dcm,
    /// `DCN\x01`: a `PA30` delta without a base.
    Dcn,
    /// `DCS\x01`: LZMS-compressed (not handled).
    Dcs,
    /// Zero bytes.
    Empty,
    /// None of the above.
    Unknown,
}

impl ManifestFormat {
    /// Detects the container from the first bytes of a file.
    pub fn detect(bytes: &[u8]) -> ManifestFormat {
        if bytes.is_empty() {
            return ManifestFormat::Empty;
        }
        match bytes.get(..4) {
            Some(b"DCM\x01") => return ManifestFormat::Dcm,
            Some(b"DCN\x01") => return ManifestFormat::Dcn,
            Some(b"DCS\x01") => return ManifestFormat::Dcs,
            _ => {}
        }
        let body = if let Some(rest) = bytes.strip_prefix(b"\xEF\xBB\xBF") {
            rest
        } else if let Some(rest) = bytes.strip_prefix(b"\xFF\xFE") {
            // UTF-16 LE: `<` is `3C 00`.
            return if rest.starts_with(b"<\0") {
                ManifestFormat::Plain
            } else {
                ManifestFormat::Unknown
            };
        } else {
            bytes
        };
        if body.first() == Some(&b'<') {
            ManifestFormat::Plain
        } else {
            ManifestFormat::Unknown
        }
    }
}

impl fmt::Display for ManifestFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ManifestFormat::Plain => "plain",
            ManifestFormat::Dcm => "DCM",
            ManifestFormat::Dcn => "DCN",
            ManifestFormat::Dcs => "DCS",
            ManifestFormat::Empty => "empty",
            ManifestFormat::Unknown => "unknown",
        })
    }
}

/// Why the base could not be found or loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BaseError {
    /// `GetSystemWindowsDirectoryW` failed.
    #[error("cannot find the Windows directory: {0}")]
    WindowsDir(Win32Error),
    /// The WinSxS directory could not be listed.
    #[error("cannot list {path}: {err}")]
    List {
        /// The directory.
        path: PathBuf,
        /// The error.
        err: Win32Error,
    },
    /// No servicing stack directory holds a `wcp.dll`.
    #[error("no amd64_microsoft-windows-servicingstack_* directory with wcp.dll under {0}")]
    NoServicingStack(PathBuf),
    /// `wcp.dll` could not be mapped as a data file.
    #[error("cannot load {path} as a data file: {err}")]
    Load {
        /// The `wcp.dll` path.
        path: PathBuf,
        /// The error.
        err: Win32Error,
    },
    /// `wcp.dll` has no resource type `0x266`, id `1`, or it is empty.
    #[error("{path} has no delta base resource (type 0x266, id 1): {err}")]
    NoResource {
        /// The `wcp.dll` path.
        path: PathBuf,
        /// The error.
        err: Win32Error,
    },
}

/// Why one manifest could not be expanded. The caller counts these (completeness seal).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExpandError {
    /// The file could not be read.
    #[error("cannot read the manifest: {0}")]
    Read(Win32Error),
    /// The file or the expanded output is larger than [`MAX_MANIFEST_SIZE`].
    #[error("manifest larger than {MAX_MANIFEST_SIZE} bytes ({0} or more)")]
    TooLarge(u64),
    /// Zero bytes.
    #[error("empty manifest file")]
    Empty,
    /// The first bytes are neither XML nor a known container.
    #[error("unknown manifest container")]
    UnknownFormat,
    /// A known container this module does not expand (`DCS`).
    #[error("unsupported manifest container {0}")]
    Unsupported(ManifestFormat),
    /// `msdelta.dll` or one of its exports could not be loaded.
    #[error("msdelta.dll unavailable: {0}")]
    MsDelta(Win32Error),
    /// `ApplyDeltaB` failed (a truncated or corrupt delta, or the wrong base); the last error.
    #[error("ApplyDeltaB failed: {0}")]
    Delta(Win32Error),
    /// `ApplyDeltaB` succeeded but the output is not XML. The `PA30` deltas of the manifests carry no
    /// target hash, so a wrong base expands "successfully" to garbage; this check catches it.
    #[error("expanded manifest is not XML")]
    NotXml,
}

/// The delta base: resource type `0x266`, id `1` of a servicing stack's `wcp.dll`.
#[derive(Clone, PartialEq, Eq)]
pub struct SxsBase {
    bytes: Vec<u8>,
    wcp: PathBuf,
}

impl SxsBase {
    /// The base bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The `wcp.dll` the base was read from.
    pub fn wcp_path(&self) -> &Path {
        &self.wcp
    }

    /// A base from bytes already read (tests, fixtures).
    pub fn from_bytes(bytes: Vec<u8>, wcp: PathBuf) -> SxsBase {
        SxsBase { bytes, wcp }
    }
}

impl fmt::Debug for SxsBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SxsBase")
            .field("len", &self.bytes.len())
            .field("wcp", &self.wcp)
            .finish()
    }
}

/// `%SystemRoot%` from `GetSystemWindowsDirectoryW` (not from the environment, which the caller sets).
pub fn windows_dir() -> Result<PathBuf, Win32Error> {
    let mut buf = vec![0u16; 260];
    loop {
        let cap = u32::try_from(buf.len()).map_err(|_| Win32Error::INSUFFICIENT_BUFFER)?;
        // SAFETY: `buf` holds `cap` writable UTF-16 units.
        let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), cap) } as usize;
        if n == 0 {
            return Err(Win32Error::last());
        }
        if n < buf.len() {
            return Ok(PathBuf::from(from_wide(&buf[..n])));
        }
        // `n` is the size needed, including the terminator.
        buf.resize(n + 1, 0);
    }
}

/// `%SystemRoot%\WinSxS`.
pub fn winsxs_dir() -> Result<PathBuf, Win32Error> {
    Ok(windows_dir()?.join("WinSxS"))
}

/// `%SystemRoot%\WinSxS\Manifests`.
pub fn manifests_dir() -> Result<PathBuf, Win32Error> {
    Ok(winsxs_dir()?.join("Manifests"))
}

/// The four-part version in a WinSxS component directory name
/// (`<arch>_<name>_<token>_<a.b.c.d>_<lang>_<hash>`), for the servicing stack only.
fn servicing_stack_version(dir_name: &str) -> Option<[u32; 4]> {
    let lower = dir_name.to_ascii_lowercase();
    let rest = lower.strip_prefix(SERVICING_STACK_PREFIX)?;
    let parts: Vec<&str> = rest.split('_').collect();
    // token, version, language, hash.
    let [_token, version, _lang, _hash] = parts.as_slice() else {
        return None;
    };
    let mut out = [0u32; 4];
    let mut fields = version.split('.');
    for slot in &mut out {
        *slot = fields.next()?.parse().ok()?;
    }
    if fields.next().is_some() {
        return None;
    }
    Some(out)
}

/// Servicing stack directories among `entries`, newest version first.
fn servicing_stacks_newest_first(entries: &[DirEntry]) -> Vec<(&str, [u32; 4])> {
    let mut out: Vec<(&str, [u32; 4])> = entries
        .iter()
        .filter(|e| e.is_dir() && !e.is_reparse_point())
        .filter_map(|e| servicing_stack_version(&e.name).map(|v| (e.name.as_str(), v)))
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(a.0)));
    out
}

/// The base of this Windows installation: [`find_base_in`] on `%SystemRoot%\WinSxS`.
pub fn find_base() -> Result<SxsBase, BaseError> {
    find_base_in(&winsxs_dir().map_err(BaseError::WindowsDir)?)
}

/// The base from the newest `amd64_microsoft-windows-servicingstack_*` directory (by its four-part
/// version) under `winsxs` that holds a `wcp.dll`. A directory without `wcp.dll` is skipped; a `wcp.dll`
/// that fails to load or has no base resource is an error (an older stack's base could mis-expand).
pub fn find_base_in(winsxs: &Path) -> Result<SxsBase, BaseError> {
    let entries = list_dir(winsxs).map_err(|err| BaseError::List {
        path: winsxs.to_path_buf(),
        err,
    })?;
    for (name, _) in servicing_stacks_newest_first(&entries) {
        let wcp = winsxs.join(name).join("wcp.dll");
        if std::fs::symlink_metadata(&wcp).is_ok_and(|m| m.is_file()) {
            return load_base(&wcp);
        }
    }
    Err(BaseError::NoServicingStack(winsxs.to_path_buf()))
}

/// `LOAD_LIBRARY_AS_DATAFILE`.
const LOAD_LIBRARY_AS_DATAFILE: u32 = 0x0000_0002;
/// `LOAD_LIBRARY_AS_IMAGE_RESOURCE`.
const LOAD_LIBRARY_AS_IMAGE_RESOURCE: u32 = 0x0000_0020;
/// `LOAD_LIBRARY_SEARCH_SYSTEM32`.
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

// The `Win32_System_LibraryLoader` feature of windows-sys is not enabled for this crate; these kernel32
// functions are declared here instead (as in `sr`).
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(name: PCWSTR, file: HANDLE, flags: u32) -> HMODULE;
    fn FreeLibrary(module: HMODULE) -> BOOL;
    fn GetProcAddress(module: HMODULE, name: PCSTR)
    -> Option<unsafe extern "system" fn() -> isize>;
    fn FindResourceW(module: HMODULE, name: PCWSTR, kind: PCWSTR) -> *mut c_void;
    fn SizeofResource(module: HMODULE, res: *mut c_void) -> u32;
    fn LoadResource(module: HMODULE, res: *mut c_void) -> *mut c_void;
    fn LockResource(data: *mut c_void) -> *mut c_void;
}

/// Unloads a module on drop.
struct Module(HMODULE);

impl Drop for Module {
    fn drop(&mut self) {
        // SAFETY: the module came from a successful LoadLibraryExW and is freed exactly once.
        unsafe { FreeLibrary(self.0) };
    }
}

/// `MAKEINTRESOURCEW`.
fn int_resource(id: u16) -> PCWSTR {
    usize::from(id) as PCWSTR
}

/// Maps `wcp` as a data file and copies out resource `0x266` / `1`.
fn load_base(wcp: &Path) -> Result<SxsBase, BaseError> {
    let path_w = wide(wcp);
    // SAFETY: NUL-terminated path; data-file mapping only, no code of the DLL runs.
    let module = unsafe {
        LoadLibraryExW(
            path_w.as_ptr(),
            ptr::null_mut(),
            LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE,
        )
    };
    if module.is_null() {
        return Err(BaseError::Load {
            path: wcp.to_path_buf(),
            err: Win32Error::last(),
        });
    }
    let module = Module(module);
    let no_resource = |err| BaseError::NoResource {
        path: wcp.to_path_buf(),
        err,
    };
    // SAFETY: `module.0` is a loaded module; integer resource name and type.
    let res = unsafe {
        FindResourceW(
            module.0,
            int_resource(BASE_RESOURCE_ID),
            int_resource(BASE_RESOURCE_TYPE),
        )
    };
    if res.is_null() {
        return Err(no_resource(Win32Error::last()));
    }
    // SAFETY: `res` is a resource of `module.0`.
    let size = unsafe { SizeofResource(module.0, res) } as usize;
    // SAFETY: as above.
    let handle = unsafe { LoadResource(module.0, res) };
    if size == 0 || handle.is_null() {
        return Err(no_resource(if size == 0 {
            Win32Error::INVALID_DATA
        } else {
            Win32Error::last()
        }));
    }
    // SAFETY: `handle` came from LoadResource of a module that is still loaded.
    let data = unsafe { LockResource(handle) };
    if data.is_null() {
        return Err(no_resource(Win32Error::INVALID_DATA));
    }
    // SAFETY: the resource holds `size` readable bytes while `module` is loaded; they are copied before
    // `module` is dropped.
    let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), size) }.to_vec();
    drop(module);
    Ok(SxsBase {
        bytes,
        wcp: wcp.to_path_buf(),
    })
}

/// `ApplyDeltaB`.
type ApplyDeltaBFn =
    unsafe extern "system" fn(i64, DELTA_INPUT, DELTA_INPUT, *mut DELTA_OUTPUT) -> BOOL;
/// `DeltaFree`.
type DeltaFreeFn = unsafe extern "system" fn(*const c_void) -> BOOL;

/// `ApplyDeltaB` and `DeltaFree` of System32 `msdelta.dll`, loaded once for the life of the process.
#[derive(Clone, Copy)]
struct MsDelta {
    apply: ApplyDeltaBFn,
    free: DeltaFreeFn,
}

/// Loads System32 `msdelta.dll` and looks up `name` (NUL-terminated ANSI) once; the module is never freed.
fn msdelta_export(name: &'static [u8]) -> Result<usize, Win32Error> {
    static MODULE: OnceLock<Result<usize, u32>> = OnceLock::new();
    let module = (*MODULE.get_or_init(|| {
        let dll = wide("msdelta.dll");
        // SAFETY: NUL-terminated name; System32 only, so no DLL planting from the current directory.
        let m =
            unsafe { LoadLibraryExW(dll.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if m.is_null() {
            Err(Win32Error::last().code())
        } else {
            Ok(m as usize)
        }
    }))
    .map_err(Win32Error)?;
    // SAFETY: `module` is a loaded module that is never freed; `name` is NUL-terminated.
    match unsafe { GetProcAddress(module as HMODULE, name.as_ptr()) } {
        Some(f) => Ok(f as usize),
        None => Err(Win32Error::last()),
    }
}

fn msdelta() -> Result<MsDelta, Win32Error> {
    static FUNCS: OnceLock<Result<(usize, usize), u32>> = OnceLock::new();
    let (apply, free) = (*FUNCS.get_or_init(|| {
        let apply = msdelta_export(b"ApplyDeltaB\0").map_err(Win32Error::code)?;
        let free = msdelta_export(b"DeltaFree\0").map_err(Win32Error::code)?;
        Ok((apply, free))
    }))
    .map_err(Win32Error)?;
    // SAFETY: both are export addresses of a module that stays loaded, and the types are the documented
    // signatures of `ApplyDeltaB` and `DeltaFree`.
    unsafe {
        Ok(MsDelta {
            apply: std::mem::transmute::<usize, ApplyDeltaBFn>(apply),
            free: std::mem::transmute::<usize, DeltaFreeFn>(free),
        })
    }
}

/// A read-only `DELTA_INPUT` over `bytes`.
fn delta_input(bytes: &[u8]) -> DELTA_INPUT {
    DELTA_INPUT {
        Anonymous: DELTA_INPUT_0 {
            lpcStart: if bytes.is_empty() {
                ptr::null()
            } else {
                bytes.as_ptr().cast()
            },
        },
        uSize: bytes.len(),
        Editable: 0,
    }
}

/// `ApplyDeltaB(0, source, delta)`, the output copied and freed with `DeltaFree`.
fn apply_delta(source: &[u8], delta: &[u8]) -> Result<Vec<u8>, ExpandError> {
    let md = msdelta().map_err(ExpandError::MsDelta)?;
    let mut out = DELTA_OUTPUT::default();
    // SAFETY: both inputs point to `uSize` readable bytes for the duration of the call and are not
    // editable; `out` is a writable DELTA_OUTPUT.
    let ok = unsafe { (md.apply)(0, delta_input(source), delta_input(delta), &mut out) } != 0;
    if !ok {
        return Err(ExpandError::Delta(Win32Error::last()));
    }
    let result = if out.uSize > MAX_MANIFEST_SIZE {
        Err(ExpandError::TooLarge(out.uSize as u64))
    } else if out.uSize == 0 || out.lpStart.is_null() {
        Ok(Vec::new())
    } else {
        // SAFETY: on success msdelta returns `uSize` readable bytes at `lpStart`, valid until DeltaFree.
        Ok(unsafe { std::slice::from_raw_parts(out.lpStart.cast::<u8>(), out.uSize) }.to_vec())
    };
    if !out.lpStart.is_null() {
        // SAFETY: `lpStart` was allocated by ApplyDeltaB and is freed exactly once.
        unsafe { (md.free)(out.lpStart) };
    }
    result
}

/// An expanded delta must itself look like XML ([`ManifestFormat::Plain`]).
fn xml_only(out: Vec<u8>) -> Result<Vec<u8>, ExpandError> {
    if ManifestFormat::detect(&out) == ManifestFormat::Plain {
        Ok(out)
    } else {
        Err(ExpandError::NotXml)
    }
}

/// Expands one manifest file's bytes to XML. `DCM` needs `base`; `DCN` uses an empty source; plain XML is
/// returned unchanged (byte-order mark included); `DCS`, empty and unknown content are errors, and so is
/// an expanded delta that does not start like XML.
pub fn expand(bytes: &[u8], base: &SxsBase) -> Result<Vec<u8>, ExpandError> {
    if bytes.len() > MAX_MANIFEST_SIZE {
        return Err(ExpandError::TooLarge(bytes.len() as u64));
    }
    match ManifestFormat::detect(bytes) {
        ManifestFormat::Plain => Ok(bytes.to_vec()),
        ManifestFormat::Dcm => xml_only(apply_delta(&base.bytes, &bytes[4..])?),
        ManifestFormat::Dcn => xml_only(apply_delta(&[], &bytes[4..])?),
        ManifestFormat::Dcs => Err(ExpandError::Unsupported(ManifestFormat::Dcs)),
        ManifestFormat::Empty => Err(ExpandError::Empty),
        ManifestFormat::Unknown => Err(ExpandError::UnknownFormat),
    }
}

/// Reads `path` (at most [`MAX_MANIFEST_SIZE`] bytes; a symbolic link or junction is refused) and
/// [`expand`]s it.
pub fn expand_file(path: &Path, base: &SxsBase) -> Result<Vec<u8>, ExpandError> {
    let bytes = read_bytes(path, MAX_MANIFEST_SIZE + 1).map_err(ExpandError::Read)?;
    expand(&bytes, base)
}

/// One file of `WinSxS\Manifests`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// File name (one component).
    pub name: String,
    /// Size on disk in bytes (of the container, not the expanded XML).
    pub size: u64,
    /// Last write time (FILETIME ticks).
    pub last_write_time: u64,
}

/// The files of `%SystemRoot%\WinSxS\Manifests` ([`list_in`]).
pub fn list() -> Result<Vec<ManifestEntry>, Win32Error> {
    list_in(&manifests_dir()?)
}

/// The files directly in `dir`, in one directory pass; subdirectories and reparse points are left out.
pub fn list_in(dir: &Path) -> Result<Vec<ManifestEntry>, Win32Error> {
    Ok(list_dir(dir)?
        .into_iter()
        .filter(|e| !e.is_dir() && !e.is_reparse_point())
        .map(|e| ManifestEntry {
            name: e.name,
            size: e.size,
            last_write_time: e.last_write_time,
        })
        .collect())
}

/// Per-outcome counts over many expansions, for the completeness seal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExpandCounts {
    /// Expanded `DCM` or `DCN` files.
    pub expanded: u64,
    /// Plain XML files passed through.
    pub plain: u64,
    /// `DCS` (or other known but unhandled) containers.
    pub unsupported: u64,
    /// Every other error (read, empty, unknown, delta, too large, msdelta missing).
    pub failed: u64,
}

impl ExpandCounts {
    /// Adds one outcome; `format` is the container of the input.
    pub fn add(&mut self, format: ManifestFormat, result: &Result<Vec<u8>, ExpandError>) {
        match result {
            Ok(_) if format == ManifestFormat::Plain => self.plain += 1,
            Ok(_) => self.expanded += 1,
            Err(ExpandError::Unsupported(_)) => self.unsupported += 1,
            Err(_) => self.failed += 1,
        }
    }

    /// All outcomes counted.
    pub fn total(&self) -> u64 {
        self.expanded + self.plain + self.unsupported + self.failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_containers() {
        assert_eq!(
            ManifestFormat::detect(b"DCM\x01PA30xxxx"),
            ManifestFormat::Dcm
        );
        assert_eq!(ManifestFormat::detect(b"DCN\x01PA30"), ManifestFormat::Dcn);
        assert_eq!(ManifestFormat::detect(b"DCS\x01\0\0"), ManifestFormat::Dcs);
        assert_eq!(
            ManifestFormat::detect(b"<?xml version=\"1.0\"?>"),
            ManifestFormat::Plain
        );
        assert_eq!(
            ManifestFormat::detect(b"\xEF\xBB\xBF<?xml"),
            ManifestFormat::Plain
        );
        assert_eq!(
            ManifestFormat::detect(b"\xFF\xFE<\0?\0"),
            ManifestFormat::Plain
        );
        assert_eq!(ManifestFormat::detect(b""), ManifestFormat::Empty);
        // A tag needs all four bytes; a wrong version byte is not the container.
        assert_eq!(ManifestFormat::detect(b"DCM"), ManifestFormat::Unknown);
        assert_eq!(
            ManifestFormat::detect(b"DCM\x02PA30"),
            ManifestFormat::Unknown
        );
        assert_eq!(ManifestFormat::detect(b"PA30"), ManifestFormat::Unknown);
        assert_eq!(
            ManifestFormat::detect(b"\xEF\xBB\xBF"),
            ManifestFormat::Unknown
        );
    }

    #[test]
    fn expand_without_delta_cases() {
        let base = SxsBase::from_bytes(Vec::new(), PathBuf::new());
        let xml = b"<?xml version=\"1.0\"?><assembly/>";
        assert_eq!(expand(xml, &base).unwrap(), xml.to_vec());
        assert_eq!(expand(b"", &base), Err(ExpandError::Empty));
        assert_eq!(expand(b"junk", &base), Err(ExpandError::UnknownFormat));
        assert_eq!(
            expand(b"DCS\x01abcd", &base),
            Err(ExpandError::Unsupported(ManifestFormat::Dcs))
        );
    }

    #[test]
    fn servicing_stack_versions() {
        assert_eq!(
            servicing_stack_version(
                "amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.26100.9703_none_a5009b9d7769c1f5"
            ),
            Some([10, 0, 26100, 9703])
        );
        assert_eq!(
            servicing_stack_version(
                "AMD64_Microsoft-Windows-ServicingStack_31bf3856ad364e35_10.0.26100.1_none_065309a92fd714e9"
            ),
            Some([10, 0, 26100, 1])
        );
        // Another component with the same prefix, a bad version, a missing field.
        assert_eq!(
            servicing_stack_version(
                "amd64_microsoft-windows-servicingstack-onecore_31bf3856ad364e35_10.0.26100.1_none_0"
            ),
            None
        );
        assert_eq!(
            servicing_stack_version("amd64_microsoft-windows-servicingstack_t_10.0.x.1_none_h"),
            None
        );
        assert_eq!(
            servicing_stack_version("amd64_microsoft-windows-servicingstack_t_10.0.1.1_none"),
            None
        );
    }

    #[test]
    fn newest_stack_is_by_version_not_by_name() {
        let dir = |name: &str| DirEntry {
            name: name.into(),
            attributes: crate::fs::FILE_ATTRIBUTE_DIRECTORY,
            size: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            reparse_tag: 0,
        };
        let mut file = dir("amd64_microsoft-windows-servicingstack_t_10.0.26100.99999_none_h");
        file.attributes = 0;
        let entries = vec![
            dir("amd64_microsoft-windows-servicingstack_t_10.0.26100.9703_none_h"),
            dir("amd64_microsoft-windows-servicingstack_t_10.0.26100.10000_none_h"),
            dir("amd64_microsoft-windows-servicingstack_t_10.0.26100.1_none_h"),
            dir("x86_microsoft-windows-servicingstack_t_10.0.26100.20000_none_h"),
            file,
        ];
        let order: Vec<[u32; 4]> = servicing_stacks_newest_first(&entries)
            .into_iter()
            .map(|(_, v)| v)
            .collect();
        assert_eq!(
            order,
            vec![
                [10, 0, 26100, 10000],
                [10, 0, 26100, 9703],
                [10, 0, 26100, 1]
            ]
        );
    }

    #[test]
    fn counts() {
        let mut c = ExpandCounts::default();
        c.add(ManifestFormat::Dcm, &Ok(vec![1]));
        c.add(ManifestFormat::Plain, &Ok(vec![1]));
        c.add(
            ManifestFormat::Dcs,
            &Err(ExpandError::Unsupported(ManifestFormat::Dcs)),
        );
        c.add(
            ManifestFormat::Dcm,
            &Err(ExpandError::Delta(Win32Error(13))),
        );
        assert_eq!(
            c,
            ExpandCounts {
                expanded: 1,
                plain: 1,
                unsupported: 1,
                failed: 1
            }
        );
        assert_eq!(c.total(), 4);
    }

    /// Real-Windows tests ("win-unit"): read-only, no elevation needed (WinSxS\Manifests and the
    /// servicing stack directories are readable by Users).
    mod win_unit {
        use super::super::*;

        /// Skips the BOM so a plain XML file is checked like an expanded one.
        fn starts_with_xml_decl(text: &[u8]) -> bool {
            text.strip_prefix(b"\xEF\xBB\xBF")
                .unwrap_or(text)
                .starts_with(b"<?xml")
        }

        /// Up to `n` manifest entries spread evenly over the listing.
        fn sample(entries: &[ManifestEntry], n: usize) -> Vec<&ManifestEntry> {
            let step = (entries.len() / n).max(1);
            entries.iter().step_by(step).take(n).collect()
        }

        #[test]
        fn base_is_found() {
            let base = find_base().expect("base");
            assert!(base.bytes().len() > 1000, "{base:?}");
            let dir = base.wcp_path().parent().unwrap().file_name().unwrap();
            assert!(servicing_stack_version(&dir.to_string_lossy()).is_some());
        }

        #[test]
        fn two_hundred_manifests_expand_to_xml() {
            let base = find_base().unwrap();
            let dir = manifests_dir().unwrap();
            let entries = list().unwrap();
            assert!(entries.len() > 1000, "{} manifests", entries.len());
            let mut dcm = 0;
            for e in sample(&entries, 200) {
                let bytes = read_bytes(&dir.join(&e.name), MAX_MANIFEST_SIZE + 1).unwrap();
                assert_eq!(bytes.len() as u64, e.size, "{}", e.name);
                if ManifestFormat::detect(&bytes) == ManifestFormat::Dcm {
                    dcm += 1;
                }
                let xml = expand(&bytes, &base).unwrap_or_else(|err| panic!("{}: {err}", e.name));
                assert!(starts_with_xml_decl(&xml), "{}", e.name);
            }
            assert!(dcm > 100, "{dcm} DCM files among 200");
        }

        #[test]
        fn truncated_dcm_is_an_error() {
            let base = find_base().unwrap();
            let dir = manifests_dir().unwrap();
            let entries = list().unwrap();
            let bytes = entries
                .iter()
                .filter(|e| e.size > 200)
                .map(|e| read_bytes(&dir.join(&e.name), MAX_MANIFEST_SIZE + 1).unwrap())
                .find(|b| ManifestFormat::detect(b) == ManifestFormat::Dcm)
                .expect("a DCM manifest");
            assert!(expand(&bytes, &base).is_ok());
            for cut in [4, 8, 20, bytes.len() / 2, bytes.len() - 1] {
                assert!(
                    matches!(expand(&bytes[..cut], &base), Err(ExpandError::Delta(_))),
                    "cut at {cut} of {}",
                    bytes.len()
                );
            }
            // The wrong base: msdelta expands it without complaint (no target hash), and the XML check
            // turns the garbage into an error.
            let wrong = SxsBase::from_bytes(vec![0u8; base.bytes().len()], PathBuf::new());
            assert!(
                matches!(
                    expand(&bytes, &wrong),
                    Err(ExpandError::NotXml | ExpandError::Delta(_))
                ),
                "{:?}",
                expand(&bytes, &wrong).map(|v| v.len())
            );
        }

        #[test]
        fn plain_xml_file_passes_through() {
            let base = find_base().unwrap();
            let dir = manifests_dir().unwrap();
            let entries = list().unwrap();
            let (name, bytes) = entries
                .iter()
                .map(|e| {
                    let b = read_bytes(&dir.join(&e.name), MAX_MANIFEST_SIZE + 1).unwrap();
                    (e.name.clone(), b)
                })
                .find(|(_, b)| ManifestFormat::detect(b) == ManifestFormat::Plain)
                .expect("a plain XML manifest");
            assert_eq!(expand(&bytes, &base).unwrap(), bytes, "{name}");
            assert_eq!(expand_file(&dir.join(&name), &base).unwrap(), bytes);
        }

        /// `CreateDeltaB` (test only, in memory) makes a delta without a base, wrapped as `DCN`.
        #[test]
        fn dcn_round_trip() {
            type CreateDeltaBFn = unsafe extern "system" fn(
                i64,
                i64,
                i64,
                DELTA_INPUT,
                DELTA_INPUT,
                DELTA_INPUT,
                DELTA_INPUT,
                DELTA_INPUT,
                *const c_void,
                u32,
                *mut DELTA_OUTPUT,
            ) -> BOOL;
            let addr = msdelta_export(b"CreateDeltaB\0").unwrap();
            // SAFETY: the export of a loaded module, with its documented signature.
            let create = unsafe { std::mem::transmute::<usize, CreateDeltaBFn>(addr) };
            let target = b"<?xml version=\"1.0\"?><assembly>DCN test</assembly>".repeat(20);
            let mut out = DELTA_OUTPUT::default();
            // SAFETY: valid inputs for the call; `out` is writable. DELTA_FILE_TYPE_RAW = 1, no hash.
            let ok = unsafe {
                create(
                    1,
                    0,
                    0,
                    delta_input(&[]),
                    delta_input(&target),
                    delta_input(&[]),
                    delta_input(&[]),
                    delta_input(&[]),
                    ptr::null(),
                    0,
                    &mut out,
                )
            } != 0;
            assert!(ok, "CreateDeltaB: {}", Win32Error::last());
            // SAFETY: `uSize` bytes at `lpStart` until DeltaFree.
            let delta =
                unsafe { std::slice::from_raw_parts(out.lpStart.cast::<u8>(), out.uSize) }.to_vec();
            // SAFETY: allocated by CreateDeltaB, freed once.
            unsafe { (msdelta().unwrap().free)(out.lpStart) };
            let mut file = b"DCN\x01".to_vec();
            file.extend_from_slice(&delta);
            let base = SxsBase::from_bytes(Vec::new(), PathBuf::new());
            assert_eq!(expand(&file, &base).unwrap(), target);
        }

        /// Thread-safety check of `ApplyDeltaB` (module docs): 4 threads expand the same 400 manifests at
        /// once; every output must equal the serial one.
        #[test]
        fn parallel_expansion_matches_serial() {
            let base = find_base().unwrap();
            let dir = manifests_dir().unwrap();
            let entries = list().unwrap();
            let files: Vec<Vec<u8>> = sample(&entries, 400)
                .into_iter()
                .map(|e| read_bytes(&dir.join(&e.name), MAX_MANIFEST_SIZE + 1).unwrap())
                .collect();
            let serial: Vec<_> = files.iter().map(|b| expand(b, &base)).collect();
            std::thread::scope(|s| {
                let handles: Vec<_> = (0..4)
                    .map(|t| {
                        let (files, base, serial) = (&files, &base, &serial);
                        s.spawn(move || {
                            // Each thread walks the list from a different offset so calls overlap.
                            let n = files.len();
                            for i in 0..n {
                                let k = (i + t * n / 4) % n;
                                assert_eq!(expand(&files[k], base), serial[k], "file {k}");
                            }
                        })
                    })
                    .collect();
                for h in handles {
                    h.join().unwrap();
                }
            });
        }

        /// Every manifest of this machine, with counts and timings (acceptance measurement). Ignored by
        /// default because it reads the whole directory (tens of seconds); run with
        /// `cargo test -p purge-win sxs -- --ignored --nocapture`.
        #[test]
        #[ignore = "reads every manifest of the machine; acceptance measurement, run by hand"]
        fn all_manifests_expand() {
            let t0 = std::time::Instant::now();
            let base = find_base().unwrap();
            let t_base = t0.elapsed();
            let t1 = std::time::Instant::now();
            let dir = manifests_dir().unwrap();
            let entries = list().unwrap();
            let t_list = t1.elapsed();
            let threads = std::env::var("PURGE_TEST_SXS_THREADS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(4usize)
                .max(1);
            let t2 = std::time::Instant::now();
            let results: Vec<(ExpandCounts, u64, Vec<String>)> = std::thread::scope(|s| {
                let handles: Vec<_> = (0..threads)
                    .map(|t| {
                        let (entries, dir, base) = (&entries, &dir, &base);
                        s.spawn(move || {
                            let mut c = ExpandCounts::default();
                            let mut bytes_out = 0u64;
                            let mut bad = Vec::new();
                            for e in entries.iter().skip(t).step_by(threads) {
                                let path = dir.join(&e.name);
                                let (format, r) = match read_bytes(&path, MAX_MANIFEST_SIZE + 1) {
                                    Ok(b) => (ManifestFormat::detect(&b), expand(&b, base)),
                                    Err(err) => {
                                        (ManifestFormat::Unknown, Err(ExpandError::Read(err)))
                                    }
                                };
                                match &r {
                                    Ok(x)
                                        if starts_with_xml_decl(x)
                                            || format == ManifestFormat::Plain =>
                                    {
                                        bytes_out += x.len() as u64
                                    }
                                    Ok(_) => bad.push(format!("{}: not <?xml", e.name)),
                                    Err(err) => bad.push(format!("{} ({format}): {err}", e.name)),
                                }
                                c.add(format, &r);
                            }
                            (c, bytes_out, bad)
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });
            let t_expand = t2.elapsed();
            let mut total = ExpandCounts::default();
            let mut out_bytes = 0;
            let mut bad = Vec::new();
            for (c, b, e) in results {
                total.expanded += c.expanded;
                total.plain += c.plain;
                total.unsupported += c.unsupported;
                total.failed += c.failed;
                out_bytes += b;
                bad.extend(e);
            }
            println!(
                "sxs: {} files; {total:?}; {out_bytes} bytes of XML; base {} bytes from {} in {t_base:?}; \
                 list {t_list:?}; expand on {threads} threads {t_expand:?}",
                entries.len(),
                base.bytes().len(),
                base.wcp_path().display(),
            );
            for b in bad.iter().take(50) {
                println!("  {b}");
            }
            assert!(bad.is_empty(), "{} failures", bad.len());
        }
    }
}
