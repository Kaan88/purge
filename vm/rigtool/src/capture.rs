//! `rigtool snap`: raw registry + filesystem capture (Windows only).
//!
//! Registry: 64-bit view (`KEY_WOW64_64KEY`), every non-root key opened with `REG_OPTION_OPEN_LINK` so
//! registry symbolic links are recorded (with their `SymbolicLinkValue`) and never followed.
//! Filesystem: `FindFirstFileExW(FindExInfoBasic, FIND_FIRST_EX_LARGE_FETCH)`, reparse points recorded
//! and never traversed.
//!
//! Output order is deterministic: roots in the given order; inside a root, a pre-order walk where each
//! key's / directory's children are sorted case-insensitively. Work is split into subtree tasks that
//! run on a thread pool; their outputs are written back in walk order.

use crate::canon::{self, CiStr, CiString};
use crate::err::{Context, Result};
use crate::snap::{self, Header, RootSpec};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::collections::HashSet;
use std::ffi::c_void;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Instant;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const MAX_ERR_PATHS: usize = 20;

pub struct SnapOpts {
    pub roots: Vec<RootSpec>,
    pub excludes: Vec<String>,
    pub values: bool,
    pub threads: usize,
}

pub struct SnapStats {
    pub records: u64,
    pub errors: u64,
    pub errors_by_code: std::collections::BTreeMap<u32, u64>,
    pub seconds: f64,
}

// ---------------------------------------------------------------------------------------------
// Small Win32 helpers
// ---------------------------------------------------------------------------------------------

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn ft(f: FILETIME) -> u64 {
    ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
}

/// `\\?\` form of an absolute path for Win32 calls.
fn long_path(p: &str) -> String {
    if let Some(r) = p.strip_prefix("\\\\") { format!("\\\\?\\UNC\\{r}") } else { format!("\\\\?\\{p}") }
}

fn join(parent: &str, name: &str) -> String {
    if parent.ends_with('\\') { format!("{parent}{name}") } else { format!("{parent}\\{name}") }
}

#[derive(Default)]
struct Errs {
    n: u64,
    paths: Vec<String>,
    /// Win32 error code -> count (reported on stderr, not in the file).
    by_code: std::collections::BTreeMap<u32, u64>,
}
impl Errs {
    fn add(&mut self, p: &str, code: u32) {
        self.n += 1;
        *self.by_code.entry(code).or_default() += 1;
        if self.paths.len() < MAX_ERR_PATHS {
            self.paths.push(p.to_string());
        }
    }
    fn merge(&mut self, o: &Errs) {
        self.n += o.n;
        for (c, n) in &o.by_code {
            *self.by_code.entry(*c).or_default() += n;
        }
        for p in &o.paths {
            if self.paths.len() < MAX_ERR_PATHS {
                self.paths.push(p.clone());
            }
        }
    }
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

fn open_key(parent: HKEY, sub: &str, link: bool) -> std::result::Result<Key, u32> {
    let w = wide(sub);
    let opts = if link { REG_OPTION_OPEN_LINK } else { 0 };
    let mut h: HKEY = std::ptr::null_mut();
    let mut r = unsafe { RegOpenKeyExW(parent, w.as_ptr(), opts, KEY_READ | KEY_WOW64_64KEY, &mut h) };
    if r == ERROR_ACCESS_DENIED {
        r = unsafe {
            RegOpenKeyExW(parent, w.as_ptr(), opts, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &mut h)
        };
    }
    if r == ERROR_SUCCESS { Ok(Key(h)) } else { Err(r) }
}

/// Split a canonical key into (hive handle, subpath).
fn hive_of(k: &str) -> Option<(HKEY, &str)> {
    let (head, rest) = match k.split_once('\\') {
        Some((h, r)) => (h, r),
        None => (k, ""),
    };
    match head.to_ascii_uppercase().as_str() {
        "HKLM" => Some((HKEY_LOCAL_MACHINE, rest)),
        "HKU" => Some((HKEY_USERS, rest)),
        _ => None,
    }
}

fn open_canon(k: &str, link: bool) -> std::result::Result<Key, u32> {
    let (hive, sub) = hive_of(k).ok_or(ERROR_INVALID_PARAMETER)?;
    open_key(hive, sub, link)
}

struct KeyInfo {
    nsub: u32,
    max_sub: u32,
    nval: u32,
    max_vname: u32,
    max_vdata: u32,
    lwt: u64,
}

fn query_info(h: HKEY) -> std::result::Result<KeyInfo, u32> {
    let (mut nsub, mut max_sub, mut nval, mut max_vname, mut max_vdata) = (0u32, 0u32, 0u32, 0u32, 0u32);
    let mut f = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let r = unsafe {
        RegQueryInfoKeyW(
            h,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut nsub,
            &mut max_sub,
            std::ptr::null_mut(),
            &mut nval,
            &mut max_vname,
            &mut max_vdata,
            std::ptr::null_mut(),
            &mut f,
        )
    };
    if r != ERROR_SUCCESS {
        return Err(r);
    }
    Ok(KeyInfo { nsub, max_sub, nval, max_vname, max_vdata, lwt: ft(f) })
}

fn enum_subkeys(h: HKEY, info: &KeyInfo) -> (Vec<(String, u64)>, Option<u32>) {
    let mut out = Vec::with_capacity(info.nsub as usize);
    let mut buf = vec![0u16; (info.max_sub as usize + 1).max(256)];
    let mut i = 0u32;
    let mut retries = 0;
    loop {
        let mut len = buf.len() as u32;
        let mut f = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let r = unsafe {
            RegEnumKeyExW(
                h,
                i,
                buf.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut f,
            )
        };
        match r {
            ERROR_SUCCESS => {
                out.push((String::from_utf16_lossy(&buf[..len as usize]), ft(f)));
                i += 1;
                retries = 0;
            }
            ERROR_NO_MORE_ITEMS => return (out, None),
            ERROR_MORE_DATA if retries < 4 => {
                let n = (buf.len() * 2).min(32768);
                buf.resize(n, 0);
                retries += 1;
            }
            e => return (out, Some(e)),
        }
    }
}

struct Val {
    name: String,
    typ: u32,
    len: u32,
    hash: u64,
    preview: String,
}

fn enum_values(h: HKEY, info: &KeyInfo) -> (Vec<Val>, Option<u32>) {
    let mut out = Vec::with_capacity(info.nval as usize);
    let mut name = vec![0u16; (info.max_vname as usize + 1).max(256)];
    let mut data = vec![0u8; (info.max_vdata as usize).max(256)];
    let mut i = 0u32;
    let mut retries = 0;
    loop {
        let mut nlen = name.len() as u32;
        let mut dlen = data.len() as u32;
        let mut typ = 0u32;
        let r = unsafe {
            RegEnumValueW(h, i, name.as_mut_ptr(), &mut nlen, std::ptr::null(), &mut typ, data.as_mut_ptr(), &mut dlen)
        };
        match r {
            ERROR_SUCCESS => {
                let d = &data[..dlen as usize];
                out.push(Val {
                    name: String::from_utf16_lossy(&name[..nlen as usize]),
                    typ,
                    len: dlen,
                    hash: snap::data_hash(d),
                    preview: snap::preview(typ, d),
                });
                i += 1;
                retries = 0;
            }
            ERROR_NO_MORE_ITEMS => break,
            ERROR_MORE_DATA if retries < 6 => {
                if name.len() < 16384 {
                    name.resize(16384, 0);
                }
                let want = (dlen as usize).max(data.len() * 2);
                data.resize(want, 0);
                retries += 1;
            }
            e => return (out, Some(e)),
        }
    }
    out.sort_by(|a, b| canon::ci_cmp(&a.name, &b.name).then_with(|| a.name.cmp(&b.name)));
    (out, None)
}

/// For --no-values: the SymbolicLinkValue of a link key, if any.
fn link_value(h: HKEY) -> Option<Val> {
    let w = wide("SymbolicLinkValue");
    let mut typ = 0u32;
    let mut len = 0u32;
    let r = unsafe { RegQueryValueExW(h, w.as_ptr(), std::ptr::null(), &mut typ, std::ptr::null_mut(), &mut len) };
    if r != ERROR_SUCCESS || typ != snap::REG_LINK {
        return None;
    }
    let mut data = vec![0u8; len as usize + 2];
    let mut l2 = data.len() as u32;
    let r = unsafe { RegQueryValueExW(h, w.as_ptr(), std::ptr::null(), &mut typ, data.as_mut_ptr(), &mut l2) };
    if r != ERROR_SUCCESS {
        return None;
    }
    let d = &data[..l2 as usize];
    Some(Val {
        name: "SymbolicLinkValue".into(),
        typ,
        len: l2,
        hash: snap::data_hash(d),
        preview: snap::preview(typ, d),
    })
}

fn reg_query_string(k: &str, name: &str) -> Option<String> {
    let key = open_canon(k, false).ok()?;
    let w = wide(name);
    let mut typ = 0u32;
    let mut len = 0u32;
    let r = unsafe { RegQueryValueExW(key.0, w.as_ptr(), std::ptr::null(), &mut typ, std::ptr::null_mut(), &mut len) };
    if r != ERROR_SUCCESS {
        return None;
    }
    let mut data = vec![0u8; len as usize + 2];
    let mut l2 = data.len() as u32;
    let r = unsafe { RegQueryValueExW(key.0, w.as_ptr(), std::ptr::null(), &mut typ, data.as_mut_ptr(), &mut l2) };
    if r != ERROR_SUCCESS {
        return None;
    }
    let p = snap::preview(typ, &data[..l2 as usize]);
    if p.is_empty() { None } else { Some(p) }
}

/// SID string of the user running this process.
pub fn current_user_sid() -> Option<String> {
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return None;
        }
        let mut need = 0u32;
        GetTokenInformation(tok, TokenUser, std::ptr::null_mut(), 0, &mut need);
        let mut buf = vec![0u8; need as usize + 16];
        let ok = GetTokenInformation(tok, TokenUser, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut need);
        CloseHandle(tok);
        if ok == 0 {
            return None;
        }
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut s: windows_sys::core::PWSTR = std::ptr::null_mut();
        if windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW(tu.User.Sid, &mut s) == 0 {
            return None;
        }
        let mut n = 0;
        while *s.add(n) != 0 {
            n += 1;
        }
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
        LocalFree(s as _);
        Some(out)
    }
}

pub fn header_now() -> Header {
    let cv = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    let edition = reg_query_string(cv, "EditionID").unwrap_or_default();
    let build = reg_query_string(cv, "CurrentBuild").unwrap_or_default();
    let ubr = reg_query_string(cv, "UBR").unwrap_or_else(|| "0".into());
    Header {
        time: iso_now(),
        computer: std::env::var("COMPUTERNAME").unwrap_or_default(),
        edition,
        build: format!("{build}.{ubr}"),
    }
}

pub fn iso_now() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    iso_from_unix(secs as i64)
}

pub fn iso_from_unix(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // civil from days (H. Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, (rem % 3600) / 60, rem % 60)
}

// ---------------------------------------------------------------------------------------------
// Walk context
// ---------------------------------------------------------------------------------------------

struct Ctx {
    values: bool,
    /// folded canonical paths of every root (fs and reg)
    roots: HashSet<CiString>,
    excludes: Vec<String>, // folded
}

impl Ctx {
    /// Is canonical key `k` (or an ancestor of it) one of the capture's roots?
    fn under_root(&self, k: &str) -> bool {
        self.is_root(k) || canon::ancestors(k).any(|a| self.is_root(a))
    }
    fn excluded(&self, k: &str) -> bool {
        if self.excludes.is_empty() {
            return false;
        }
        let f = canon::fold(k);
        self.excludes.iter().any(|x| canon::is_under_or_eq_folded(&f, x))
    }
    fn is_root(&self, p: &str) -> bool {
        self.roots.contains(CiStr::new(p))
    }
}

#[derive(Default)]
struct Out {
    buf: String,
    n: u64,
    errs: Errs,
}

impl Out {
    /// `#denied\t<path>`: the listing of this key or directory (subkeys, values or entries) failed or is
    /// incomplete, so the scorer must not read "absent below it" as "removed".
    fn denied(&mut self, path: &str) {
        self.buf.push_str(&snap::meta_line("denied", &[path.to_string()]));
    }
}

enum Task {
    /// Recursive registry subtree: canonical path, lwt from the parent's enumeration.
    Reg(String, u64),
    /// Recursive directory subtree (its own D record was already written).
    Dir(String),
}

enum Unit {
    Ready(Out),
    Task(usize),
}

// ---- registry ----

fn emit_key(ctx: &Ctx, h: HKEY, path: &str, with_values: bool, out: &mut Out) -> Option<KeyInfo> {
    let info = match query_info(h) {
        Ok(i) => i,
        Err(e) => {
            snap::write_k(&mut out.buf, path, 0, None, None);
            out.n += 1;
            out.errs.add(path, e);
            return None;
        }
    };
    snap::write_k(&mut out.buf, path, info.lwt, Some(info.nval), Some(info.nsub));
    out.n += 1;
    if ctx.values && with_values {
        let (vals, err) = enum_values(h, &info);
        for v in vals {
            snap::write_v(&mut out.buf, path, &v.name, v.typ, v.len, v.hash, &v.preview);
            out.n += 1;
        }
        if let Some(e) = err {
            out.errs.add(path, e);
            out.denied(path);
        }
    } else if let Some(v) = link_value(h) {
        // Symbolic links are always recorded with their target.
        snap::write_v(&mut out.buf, path, &v.name, v.typ, v.len, v.hash, &v.preview);
        out.n += 1;
    }
    Some(info)
}

/// Children of an open key, filtered (exclusions, other roots) and sorted.
fn key_children(ctx: &Ctx, h: HKEY, info: &KeyInfo, path: &str, out: &mut Out) -> Vec<(String, String, u64)> {
    let (mut subs, err) = enum_subkeys(h, info);
    if let Some(e) = err {
        out.errs.add(path, e);
        out.denied(path);
    }
    subs.sort_by(|a, b| canon::ci_cmp(&a.0, &b.0).then_with(|| a.0.cmp(&b.0)));
    subs.into_iter()
        .filter_map(|(n, lwt)| {
            let p = join(path, &n);
            if ctx.excluded(&p) || ctx.is_root(&p) { None } else { Some((n, p, lwt)) }
        })
        .collect()
}

/// Recursive walk of one key opened relative to its parent.
fn walk_key(ctx: &Ctx, parent: HKEY, name: &str, path: &str, enum_lwt: u64, recurse: bool, out: &mut Out) {
    let key = match open_key(parent, name, true) {
        Ok(k) => k,
        Err(e) => {
            snap::write_k(&mut out.buf, path, enum_lwt, None, None);
            out.n += 1;
            out.errs.add(path, e);
            return;
        }
    };
    // Depth-1 children (recurse == false) are recorded as keys only.
    let Some(info) = emit_key(ctx, key.0, path, recurse, out) else {
        return;
    };
    if !recurse || info.nsub == 0 {
        return;
    }
    for (n, p, lwt) in key_children(ctx, key.0, &info, path, out) {
        walk_key(ctx, key.0, &n, &p, lwt, true, out);
    }
}

fn run_reg_task(ctx: &Ctx, path: &str, enum_lwt: u64) -> Out {
    let mut out = Out::default();
    let (pp, name) = match path.rsplit_once('\\') {
        Some(x) => x,
        None => return out,
    };
    match open_canon(pp, false) {
        Ok(parent) => walk_key(ctx, parent.0, name, path, enum_lwt, true, &mut out),
        Err(e) => {
            snap::write_k(&mut out.buf, path, enum_lwt, None, None);
            out.n += 1;
            out.errs.add(path, e);
        }
    }
    out
}

/// Plan a registry root: write the root (and `split` levels below it) now, queue deeper subtrees.
fn plan_reg(ctx: &Ctx, root: &RootSpec, split: u32, units: &mut Vec<Unit>, tasks: &mut Vec<Task>) {
    let mut out = Out::default();
    // A root that is itself a registry link onto another captured root (HKU\S-1-5-18 -> HKU\.DEFAULT) is
    // recorded as a link key only; following it would capture that hive twice under two names. A link
    // root whose target is not captured otherwise (HKLM\SYSTEM\CurrentControlSet) is followed.
    // (canon_reg maps ControlSet00N back to CurrentControlSet, so a target equal to or below the root
    // itself means "follow".)
    if let Ok(lk) = open_canon(&root.path, true)
        && let Some(t) = link_value(lk.0).map(|v| canon::canon_reg(&v.preview, None))
        && !canon::is_under_or_eq(&t, &root.path)
        && ctx.under_root(&t)
    {
        emit_key(ctx, lk.0, &root.path, true, &mut out);
        units.push(Unit::Ready(out));
        return;
    }
    let key = match open_canon(&root.path, false) {
        Ok(k) => k,
        Err(e) => {
            out.errs.add(&root.path, e);
            if e != ERROR_FILE_NOT_FOUND {
                out.denied(&root.path);
            }
            units.push(Unit::Ready(out));
            return;
        }
    };
    let Some(info) = emit_key(ctx, key.0, &root.path, true, &mut out) else {
        units.push(Unit::Ready(out));
        return;
    };
    let children = key_children(ctx, key.0, &info, &root.path, &mut out);
    if root.depth1 {
        for (n, p, lwt) in children {
            walk_key(ctx, key.0, &n, &p, lwt, false, &mut out);
        }
        units.push(Unit::Ready(out));
        return;
    }
    units.push(Unit::Ready(out));
    plan_reg_children(ctx, key.0, children, split, units, tasks);
}

fn plan_reg_children(
    ctx: &Ctx,
    parent: HKEY,
    children: Vec<(String, String, u64)>,
    split: u32,
    units: &mut Vec<Unit>,
    tasks: &mut Vec<Task>,
) {
    for (n, p, lwt) in children {
        if split <= 1 {
            units.push(Unit::Task(tasks.len()));
            tasks.push(Task::Reg(p, lwt));
            continue;
        }
        let mut out = Out::default();
        let key = match open_key(parent, &n, true) {
            Ok(k) => k,
            Err(e) => {
                snap::write_k(&mut out.buf, &p, lwt, None, None);
                out.n += 1;
                out.errs.add(&p, e);
                units.push(Unit::Ready(out));
                continue;
            }
        };
        let Some(info) = emit_key(ctx, key.0, &p, true, &mut out) else {
            units.push(Unit::Ready(out));
            continue;
        };
        let grand = if info.nsub > 0 { key_children(ctx, key.0, &info, &p, &mut out) } else { Vec::new() };
        units.push(Unit::Ready(out));
        plan_reg_children(ctx, key.0, grand, split - 1, units, tasks);
    }
}

// ---- filesystem ----

struct Entry {
    name: String,
    attrs: u32,
    mtime: u64,
    size: u64,
    reparse: u32,
}

fn list_dir(path: &str) -> std::result::Result<Vec<Entry>, u32> {
    let pat = wide(&join(&long_path(path), "*"));
    let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    let h = unsafe {
        FindFirstFileExW(
            pat.as_ptr(),
            FindExInfoBasic,
            &mut data as *mut _ as *mut c_void,
            FindExSearchNameMatch,
            std::ptr::null(),
            FIND_FIRST_EX_LARGE_FETCH,
        )
    };
    if h == INVALID_HANDLE_VALUE {
        let e = unsafe { GetLastError() };
        return if e == ERROR_FILE_NOT_FOUND { Ok(Vec::new()) } else { Err(e) };
    }
    let mut out = Vec::new();
    loop {
        let n = data.cFileName.iter().position(|&c| c == 0).unwrap_or(data.cFileName.len());
        let name = String::from_utf16_lossy(&data.cFileName[..n]);
        if name != "." && name != ".." {
            let reparse = if data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 { data.dwReserved0 } else { 0 };
            out.push(Entry {
                name,
                attrs: data.dwFileAttributes,
                mtime: ft(data.ftLastWriteTime),
                size: ((data.nFileSizeHigh as u64) << 32) | data.nFileSizeLow as u64,
                reparse,
            });
        }
        if unsafe { FindNextFileW(h, &mut data) } == 0 {
            let e = unsafe { GetLastError() };
            unsafe { FindClose(h) };
            if e != ERROR_NO_MORE_FILES {
                return Err(e);
            }
            break;
        }
    }
    out.sort_by(|a, b| canon::ci_cmp(&a.name, &b.name).then_with(|| a.name.cmp(&b.name)));
    Ok(out)
}

fn is_dir(e: &Entry) -> bool {
    e.attrs & FILE_ATTRIBUTE_DIRECTORY != 0
}

/// List one directory, write its entries, return the subdirectories to descend into.
fn list_and_emit(ctx: &Ctx, path: &str, out: &mut Out) -> Vec<String> {
    let entries = match list_dir(path) {
        Ok(e) => e,
        Err(e) => {
            out.errs.add(path, e);
            out.denied(path);
            return Vec::new();
        }
    };
    let mut subs = Vec::new();
    for e in entries {
        let p = join(path, &e.name);
        if is_dir(&e) {
            snap::write_d(&mut out.buf, &p, e.attrs, e.mtime, e.reparse);
            if e.attrs & FILE_ATTRIBUTE_REPARSE_POINT == 0 && !ctx.is_root(&p) {
                subs.push(p);
            }
        } else {
            snap::write_f(&mut out.buf, &p, e.size, e.attrs, e.mtime, e.reparse);
        }
        out.n += 1;
    }
    subs
}

fn walk_dir(ctx: &Ctx, path: &str, out: &mut Out) {
    for s in list_and_emit(ctx, path, out) {
        walk_dir(ctx, &s, out);
    }
}

/// D record for a root directory nobody else lists. Returns false if the root is missing or a reparse point.
fn emit_root_dir(path: &str, emit: bool, out: &mut Out) -> bool {
    let w = wide(&long_path(path));
    let mut a: WIN32_FILE_ATTRIBUTE_DATA = unsafe { std::mem::zeroed() };
    if unsafe { GetFileAttributesExW(w.as_ptr(), GetFileExInfoStandard, &mut a as *mut _ as *mut c_void) } == 0 {
        let e = unsafe { GetLastError() };
        out.errs.add(path, e);
        if e != ERROR_FILE_NOT_FOUND && e != ERROR_PATH_NOT_FOUND {
            out.denied(path);
        }
        return false;
    }
    let mut reparse = 0u32;
    if a.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        let mut d: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
        let h = unsafe {
            FindFirstFileExW(
                w.as_ptr(),
                FindExInfoBasic,
                &mut d as *mut _ as *mut c_void,
                FindExSearchNameMatch,
                std::ptr::null(),
                0,
            )
        };
        if h != INVALID_HANDLE_VALUE {
            reparse = d.dwReserved0;
            unsafe { FindClose(h) };
        }
    }
    if emit {
        if a.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            snap::write_d(&mut out.buf, path, a.dwFileAttributes, ft(a.ftLastWriteTime), reparse);
        } else {
            let size = ((a.nFileSizeHigh as u64) << 32) | a.nFileSizeLow as u64;
            snap::write_f(&mut out.buf, path, size, a.dwFileAttributes, ft(a.ftLastWriteTime), reparse);
        }
        out.n += 1;
    }
    a.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 && a.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
}

fn plan_fs(
    ctx: &Ctx,
    root: &RootSpec,
    listed_elsewhere: bool,
    split: u32,
    units: &mut Vec<Unit>,
    tasks: &mut Vec<Task>,
) {
    let mut out = Out::default();
    if !emit_root_dir(&root.path, !listed_elsewhere, &mut out) {
        units.push(Unit::Ready(out));
        return;
    }
    let subs = list_and_emit(ctx, &root.path, &mut out);
    units.push(Unit::Ready(out));
    if root.depth1 {
        return;
    }
    plan_fs_children(ctx, subs, split, units, tasks);
}

fn plan_fs_children(ctx: &Ctx, subs: Vec<String>, split: u32, units: &mut Vec<Unit>, tasks: &mut Vec<Task>) {
    for s in subs {
        if split <= 1 {
            units.push(Unit::Task(tasks.len()));
            tasks.push(Task::Dir(s));
            continue;
        }
        let mut out = Out::default();
        let grand = list_and_emit(ctx, &s, &mut out);
        units.push(Unit::Ready(out));
        plan_fs_children(ctx, grand, split - 1, units, tasks);
    }
}

fn run_task(ctx: &Ctx, t: &Task) -> Out {
    match t {
        Task::Reg(p, lwt) => run_reg_task(ctx, p, *lwt),
        Task::Dir(p) => {
            let mut out = Out::default();
            walk_dir(ctx, p, &mut out);
            out
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Roots
// ---------------------------------------------------------------------------------------------

/// Default roots and exclusions per RIG.md §2.
pub fn default_roots() -> (Vec<RootSpec>, Vec<String>) {
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let sysdrive = canon::canon_path(&env("SystemDrive", "C:"));
    let windir = canon::canon_path(&env("SystemRoot", "C:\\Windows"));
    let pf = canon::canon_path(&env("ProgramW6432", &env("ProgramFiles", "C:\\Program Files")));
    let pf86 = canon::canon_path(&env("ProgramFiles(x86)", "C:\\Program Files (x86)"));
    let pd = canon::canon_path(&env("ProgramData", "C:\\ProgramData"));
    let users = join(&sysdrive, "Users");
    let r = |p: &str, reg: bool, d1: bool| RootSpec { reg, path: p.to_string(), depth1: d1 };
    let mut v = vec![r("HKLM\\SOFTWARE", true, false), r("HKLM\\SYSTEM\\CurrentControlSet", true, false)];
    if let Ok(h) = open_key(HKEY_USERS, "", false)
        && let Ok(info) = query_info(h.0)
    {
        // Every loaded hive. HKU\S-1-5-18 is a link to HKU\.DEFAULT: plan_reg records it as a link key
        // only (K + SymbolicLinkValue), so .DEFAULT is captured once, under its own name.
        let (mut subs, _) = enum_subkeys(h.0, &info);
        subs.sort_by(|a, b| canon::ci_cmp(&a.0, &b.0));
        for (n, _) in subs {
            v.push(r(&format!("HKU\\{n}"), true, false));
        }
    }
    for p in [pf, pf86, pd, users] {
        v.push(r(&p, false, false));
    }
    for d in ["Installer", "Prefetch", "System32\\Tasks", "Tasks"] {
        v.push(r(&join(&windir, d), false, false));
    }
    v.push(r(&sysdrive, false, true));
    for d in ["", "System32", "SysWOW64", "System32\\drivers", "Fonts"] {
        let p = if d.is_empty() { windir.clone() } else { join(&windir, d) };
        v.push(r(&p, false, true));
    }
    let ex = vec![
        "HKLM\\SYSTEM\\CurrentControlSet\\Enum".to_string(),
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses".to_string(),
    ];
    (v, ex)
}

/// Is fs root `r` listed by another fs root's walk?
fn listed_elsewhere(r: &RootSpec, all: &[RootSpec]) -> bool {
    all.iter().any(|o| {
        if o.reg || std::ptr::eq(o, r) || canon::ci_eq(&o.path, &r.path) {
            return false;
        }
        if o.depth1 {
            canon::parent(&r.path).is_some_and(|p| canon::ci_eq(p, &o.path))
        } else {
            canon::is_strictly_under(&r.path, &o.path)
        }
    })
}

pub fn run_snap(opts: &SnapOpts, out_path: &Path) -> Result<SnapStats> {
    let t0 = Instant::now();
    let ctx = Ctx {
        values: opts.values,
        roots: opts.roots.iter().map(|r| CiString(r.path.clone())).collect(),
        excludes: opts.excludes.iter().map(|x| canon::fold(x)).collect(),
    };
    let header = header_now();

    // Plan (serial, shallow), then run subtree tasks on a pool.
    let mut units: Vec<Unit> = Vec::new();
    let mut tasks: Vec<Task> = Vec::new();
    for r in &opts.roots {
        if r.reg {
            plan_reg(&ctx, r, 2, &mut units, &mut tasks);
        } else {
            let le = listed_elsewhere(r, &opts.roots);
            plan_fs(&ctx, r, le, 3, &mut units, &mut tasks);
        }
    }

    let file = std::fs::File::create(out_path).with_context(|| format!("create {}", out_path.display()))?;
    let mut w = GzEncoder::new(BufWriter::with_capacity(1 << 20, file), Compression::new(3));
    w.write_all(snap::header_line(&header).as_bytes())?;
    w.write_all(snap::meta_line("roots", &opts.roots.iter().map(|r| r.spec_string()).collect::<Vec<_>>()).as_bytes())?;
    if !opts.excludes.is_empty() {
        w.write_all(snap::meta_line("exclude", &opts.excludes).as_bytes())?;
    }

    let slots: Mutex<Vec<Option<Out>>> = Mutex::new((0..tasks.len()).map(|_| None).collect());
    let cv = Condvar::new();
    let next = AtomicUsize::new(0);
    let mut total = Out::default();
    let threads = opts.threads.max(1);

    let write_result: Result<()> = std::thread::scope(|s| {
        for _ in 0..threads.min(tasks.len().max(1)) {
            std::thread::Builder::new()
                .stack_size(16 << 20)
                .spawn_scoped(s, || {
                    loop {
                        let i = next.fetch_add(1, Ordering::SeqCst);
                        if i >= tasks.len() {
                            break;
                        }
                        let o = run_task(&ctx, &tasks[i]);
                        slots.lock().unwrap()[i] = Some(o);
                        cv.notify_all();
                    }
                })
                .expect("spawn worker");
        }
        for u in units.drain(..) {
            let o = match u {
                Unit::Ready(o) => o,
                Unit::Task(i) => {
                    let mut g = slots.lock().unwrap();
                    loop {
                        if let Some(o) = g[i].take() {
                            break o;
                        }
                        g = cv.wait(g).unwrap();
                    }
                }
            };
            w.write_all(o.buf.as_bytes())?;
            total.n += o.n;
            total.errs.merge(&o.errs);
        }
        Ok(())
    });
    write_result?;
    w.write_all(snap::meta_line("errors", &[total.errs.n.to_string(), total.errs.paths.join("|")]).as_bytes())?;
    w.finish()?.flush()?;
    Ok(SnapStats {
        records: total.n,
        errors: total.errs.n,
        errors_by_code: total.errs.by_code,
        seconds: t0.elapsed().as_secs_f64(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso() {
        assert_eq!(iso_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_from_unix(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso_from_unix(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn listed_elsewhere_rules() {
        let (roots, _) = (
            vec![
                RootSpec { reg: false, path: "C:\\".into(), depth1: true },
                RootSpec { reg: false, path: "C:\\Program Files".into(), depth1: false },
                RootSpec { reg: false, path: "C:\\Windows".into(), depth1: true },
                RootSpec { reg: false, path: "C:\\Windows\\System32\\Tasks".into(), depth1: false },
            ],
            (),
        );
        assert!(!listed_elsewhere(&roots[0], &roots));
        assert!(listed_elsewhere(&roots[1], &roots));
        assert!(listed_elsewhere(&roots[2], &roots));
        assert!(!listed_elsewhere(&roots[3], &roots));
    }
}
