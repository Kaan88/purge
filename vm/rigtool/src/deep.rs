//! `rigtool deep`: deep snapshot of chosen objects, with every field the round-trip fidelity check needs
//! (ENGINE_PLAN.md §10.3; consumer: `fidelity.rs`).
//!
//! Only the objects named by the scope are captured: plan targets and their parents, trap and fixture roots,
//! canaries. Per file or directory: content SHA-256, attributes, alternate data streams (name, size, SHA-256),
//! hard link count, FileId and volume serial, reparse tag and link target text (a reparse point is recorded and
//! never traversed), owner and SDDL (O/G/D), 8.3 name and LastWriteTime (recorded, excluded by `fidelity`).
//! Per registry key: SDDL (O/G/D), class, link flag and target (a link key is never followed), LastWriteTime,
//! values (name, type, length, SHA-256 of the raw data). Services, tasks and firewall rules are captured through
//! the registry keys and files that hold their definition, minus runtime state (a service's volatile `Enum`
//! subkey; a task's TaskCache `Id` and `Index`).

use crate::canon;
use crate::err::{Context, Result, bail};
use crate::jsonio;
use crate::target::{self, Target};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const SCHEMA: &str = "purge.rig.deep/1";
pub const SCOPE_SCHEMA: &str = "purge.rig.deepscope/0";

/// Subkeys of a service key that hold runtime state, not definition.
pub const SERVICE_RUNTIME_SUBKEYS: &[&str] = &["Enum"];
/// Values of a task's `TaskCache\Tree` key that change on re-registration (not definition).
pub const TASK_TREE_RUNTIME_VALUES: &[&str] = &["Id", "Index"];

// ---------------------------------------------------------------------------------------------
// Document
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DeepDoc {
    pub schema: String,
    #[serde(default)]
    pub time: String,
    #[serde(default)]
    pub computer: String,
    #[serde(default)]
    pub build: String,
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub files: Vec<FileRec>,
    #[serde(default)]
    pub keys: Vec<KeyRec>,
    /// M1b: the typed objects' own definition, for the fidelity measure of C-RIG: a task's XML and security
    /// descriptor as Task Scheduler returns them, a firewall rule's registry string. Absent in documents written
    /// before M1b.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<ObjRec>,
    /// Records with an `error` field.
    #[serde(default)]
    pub errors: u64,
}

/// A typed object as its own API shows it (M1b). `kind`: `task` (`id` = the task path, `xml` =
/// `IRegisteredTask::get_Xml`, `sddl` = `GetSecurityDescriptor(OWNER|GROUP|DACL)`) or `firewall_rule` (`id` = the
/// value name under `FirewallRules`, `rule` = its REG_SZ string, unchanged).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ObjRec {
    pub kind: String,
    pub id: String,
    pub present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xml: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sddl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One file or directory. Optional fields are absent when they do not apply or could not be read (`error`).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FileRec {
    pub path: String,
    pub present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_dir: Option<bool>,
    /// `0x%08X`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Main data stream; files that are not reparse points only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Alternate data streams (the unnamed `::$DATA` stream is `sha256`), sorted by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<StreamRec>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<u32>,
    /// 64-bit file index, `%016x`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_serial: Option<u32>,
    /// `0x%08X`, reparse points only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reparse_tag: Option<String>,
    /// Substitute name of a junction or symbolic link (text only; never followed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_target: Option<String>,
    /// SHA-256 of the whole reparse buffer (any tag).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reparse_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Owner, group and DACL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sddl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    /// FILETIME
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_write: Option<u64>,
    /// `Service:<name>` / `Task:<path>` / `FirewallRule:<id>` when captured for a typed scope entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct StreamRec {
    /// As the file system reports it, e.g. `:Zone.Identifier:$DATA`.
    pub name: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KeyRec {
    pub key: String,
    pub present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sddl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_link: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_write: Option<u64>,
    #[serde(default)]
    pub values: Vec<ValueRec>,
    /// Only these values were captured (a value-level scope entry); `None` = all values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub only_values: Option<Vec<String>>,
    /// Runtime state left out on purpose (subkeys or values; see the module comment).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omitted: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ValueRec {
    /// Value name (lossy for names that are not valid UTF-16; then `name_hex` holds the raw UTF-16LE bytes).
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_hex: Option<String>,
    #[serde(rename = "type")]
    pub typ: u32,
    pub len: u32,
    pub sha256: String,
}

#[cfg(test)]
impl KeyRec {
    pub fn value(&self, name: &str) -> Option<&ValueRec> {
        self.values.iter().find(|v| v.name.eq_ignore_ascii_case(name))
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(data))
}

pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

// ---------------------------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------------------------

/// What to capture. `paths` and `keys` are specs: a path or canonical key, optionally suffixed `@0` (the object
/// only; for a key: the key and its values, no subkeys) or `@1` (the object and its direct children); no suffix
/// = the whole tree.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Scope {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub values: Vec<ValueSpec>,
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub tasks: Vec<String>,
    #[serde(default)]
    pub firewall_rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ValueSpec {
    pub key: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    Object,
    Children,
    Tree,
}

pub fn split_spec(spec: &str) -> (&str, Depth) {
    if let Some(b) = spec.strip_suffix("@0") {
        (b, Depth::Object)
    } else if let Some(b) = spec.strip_suffix("@1") {
        (b, Depth::Children)
    } else {
        (spec, Depth::Tree)
    }
}

/// Input file accepted by `--scope`: `purge.rig.deepscope/0` (fields of [`Scope`] plus `targets`: purge-model
/// Target JSON), `purge.rig.targets/0` (m2-traps / m2-fixtures targets files), or a `purge.rig.m2traps/*` /
/// `purge.rig.m2fixtures/*` manifest (roots, item targets, objects, canaries).
#[derive(Default)]
pub struct ScopeBuilder {
    pub scope: Scope,
    sid: Option<String>,
    localappdata: Option<String>,
}

impl ScopeBuilder {
    pub fn new(sid: Option<&str>, localappdata: Option<&str>) -> ScopeBuilder {
        ScopeBuilder {
            scope: Scope::default(),
            sid: sid.map(str::to_string),
            localappdata: localappdata.map(str::to_string),
        }
    }

    fn subst(&self, s: &str) -> String {
        let mut t = s.to_string();
        if let Some(sid) = &self.sid {
            t = t.replace("{user-sid}", sid);
        }
        if let Some(l) = &self.localappdata {
            t = t.replace("{localappdata}", l);
        }
        t
    }

    fn warn(&mut self, w: String) {
        if !self.scope.warnings.contains(&w) {
            self.scope.warnings.push(w);
        }
    }

    /// Adds a path spec (a path, `@0` / `@1` allowed). Relative or placeholder-bearing paths are a warning.
    pub fn path(&mut self, spec: &str) {
        let s = self.subst(spec);
        let (body, d) = split_spec(&s);
        let p = canon::canon_path(&snap_expand(body));
        if !is_abs_path(&p) || p.contains('{') {
            self.warn(format!("not an absolute path, skipped: {spec}"));
            return;
        }
        self.scope.paths.push(with_depth(&p, d));
    }

    pub fn key(&mut self, spec: &str) {
        let s = self.subst(spec);
        let (body, d) = split_spec(&s);
        let k = canon::canon_reg(body, self.sid.as_deref());
        if !(k.starts_with("HKLM") || k.starts_with("HKU\\")) || k.contains('{') {
            self.warn(format!("not a HKLM or HKU key, skipped: {spec}"));
            return;
        }
        self.scope.keys.push(with_depth(&k, d));
    }

    pub fn value(&mut self, key: &str, name: &str) {
        let k = canon::canon_reg(&self.subst(key), self.sid.as_deref());
        if !(k.starts_with("HKLM") || k.starts_with("HKU\\")) || k.contains('{') {
            self.warn(format!("not a HKLM or HKU key, skipped: {key}"));
            return;
        }
        self.scope.values.push(ValueSpec { key: k, name: name.to_string() });
    }

    /// A plan target: the object (whole tree) and its parent (object only); a value target: its key with all
    /// values; typed targets as typed scope entries.
    pub fn target(&mut self, t: &Target) {
        let t = t.map_reg(|p| self.subst(p)).canonical(self.sid.as_deref());
        match &t {
            Target::Path { path } => {
                let p = self.subst(path);
                self.path(&p);
                if let Some(par) = canon::parent(&canon::canon_path(&p)) {
                    self.path(&format!("{par}@0"));
                }
            }
            Target::RegKey { path } => {
                self.key(path);
                if let Some(par) = canon::parent(path) {
                    self.key(&format!("{par}@0"));
                }
            }
            Target::RegValue { path, .. }
            | Target::RegValueChanged { path, .. }
            | Target::RegMultiSzSegment { path, .. } => self.key(&format!("{path}@0")),
            Target::Service { name } => self.scope.services.push(name.clone()),
            Target::Task { path } => self.scope.tasks.push(path.clone()),
            Target::FirewallRule { id } => self.scope.firewall_rules.push(id.clone()),
            Target::AppxPackage { full_name } => {
                self.warn(format!("AppxPackage {full_name}: RemovePackage has no inverse; not captured"))
            }
        }
    }

    pub fn add_file(&mut self, path: &Path) -> Result<()> {
        let v: Value = jsonio::read(path)?;
        self.add_doc(&v).with_context(|| format!("scope {}", path.display()))
    }

    pub fn add_doc(&mut self, v: &Value) -> Result<()> {
        let schema = v.get("schema").and_then(Value::as_str).unwrap_or("");
        if schema == SCOPE_SCHEMA {
            let s: Scope = serde_json::from_value(v.clone())?;
            for p in &s.paths {
                self.path(p);
            }
            for k in &s.keys {
                self.key(k);
            }
            for x in &s.values {
                self.value(&x.key, &x.name);
            }
            for t in v.get("targets").and_then(Value::as_array).into_iter().flatten() {
                self.target(&serde_json::from_value(t.clone()).context("targets[]")?);
            }
            self.scope.services.extend(s.services);
            self.scope.tasks.extend(s.tasks);
            self.scope.firewall_rules.extend(s.firewall_rules);
        } else if schema == "purge.rig.targets/0" {
            for t in v.get("targets").and_then(Value::as_array).into_iter().flatten() {
                let tj = t.get("target").context("targets[].target missing")?;
                self.target(&serde_json::from_value(tj.clone()).context("targets[].target")?);
            }
        } else if schema.starts_with("purge.rig.m2traps/") || schema.starts_with("purge.rig.m2fixtures/") {
            self.add_manifest(v)?;
        } else {
            bail!("unknown scope schema {schema:?} (want {SCOPE_SCHEMA}, purge.rig.targets/0 or an m2 manifest)");
        }
        Ok(())
    }

    fn add_manifest(&mut self, v: &Value) -> Result<()> {
        if self.sid.is_none()
            && let Some(s) = v.get("user_sid").and_then(Value::as_str)
            && !s.starts_with('{')
        {
            self.sid = Some(s.to_string());
        }
        let strs = |x: Option<&Value>| -> Vec<String> {
            x.and_then(Value::as_array).into_iter().flatten().filter_map(|s| s.as_str().map(str::to_string)).collect()
        };
        for t in v.get("traps").and_then(Value::as_array).into_iter().flatten() {
            for p in strs(t.get("fs_roots")) {
                self.path(&p);
            }
            for k in strs(t.get("reg_roots")) {
                self.key(&k);
            }
            for it in t.get("items").and_then(Value::as_array).into_iter().flatten() {
                if let Some(tj) = it.get("target")
                    && let Ok(tg) = serde_json::from_value::<Target>(tj.clone())
                {
                    self.target(&tg);
                }
            }
            for o in t.get("objects").and_then(Value::as_array).into_iter().flatten() {
                let (Some(k), Some(p)) = (o.get("k").and_then(Value::as_str), o.get("path").and_then(Value::as_str))
                else {
                    continue;
                };
                match k {
                    "file" | "dir" | "hardlink" | "canary-file" | "stream" | "attrs" | "file-sddl" | "junction"
                    | "dirsym" | "filesym" => self.path(&format!("{p}@0")),
                    "key" | "canary-key" | "reglink" => self.key(&format!("{p}@0")),
                    "value" | "canary-value" | "key-sddl" | "path-segment" => self.key(&format!("{p}@0")),
                    _ => {}
                }
            }
        }
        for c in v.get("canaries").and_then(Value::as_array).into_iter().flatten() {
            let (Some(kind), Some(p)) = (c.get("kind").and_then(Value::as_str), c.get("path").and_then(Value::as_str))
            else {
                continue;
            };
            match kind {
                "file" => self.path(&format!("{p}@0")),
                "regkey" => self.key(p),
                "regvalue" => self.key(&format!("{p}@0")),
                _ => {}
            }
        }
        Ok(())
    }

    pub fn finish(mut self) -> Scope {
        let s = &mut self.scope;
        for v in [&mut s.paths, &mut s.keys, &mut s.services, &mut s.tasks, &mut s.firewall_rules] {
            let mut seen = std::collections::HashSet::new();
            v.retain(|x| seen.insert(canon::fold(x)));
        }
        let mut seen = std::collections::HashSet::new();
        s.values.retain(|x| seen.insert((canon::fold(&x.key), x.name.to_ascii_lowercase())));
        self.scope
    }
}

fn with_depth(p: &str, d: Depth) -> String {
    match d {
        Depth::Object => format!("{p}@0"),
        Depth::Children => format!("{p}@1"),
        Depth::Tree => p.to_string(),
    }
}

fn snap_expand(s: &str) -> String {
    crate::snap::expand_env(s)
}

fn is_abs_path(p: &str) -> bool {
    let b = p.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\') || p.starts_with("\\\\")
}

// ---------------------------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------------------------

pub struct DeepArgs {
    pub scopes: Vec<PathBuf>,
    pub sid: Option<String>,
    pub out: PathBuf,
}

#[cfg(windows)]
pub fn cmd_deep(a: &DeepArgs) -> Result<()> {
    if a.scopes.is_empty() {
        bail!("deep needs --scope FILE");
    }
    let sid = a.sid.clone().or_else(crate::capture::current_user_sid);
    let lad = std::env::var("LOCALAPPDATA").ok();
    let mut b = ScopeBuilder::new(sid.as_deref(), lad.as_deref());
    for s in &a.scopes {
        b.add_file(s)?;
    }
    let scope = b.finish();
    let t0 = std::time::Instant::now();
    let backup = win::enable_backup_privilege();
    let doc = capture(&scope, sid.as_deref());
    jsonio::write(&a.out, &doc)?;
    for w in &doc.scope.warnings {
        eprintln!("deep: warning: {w}");
    }
    eprintln!(
        "deep: {} files, {} keys, {} with errors, backup privilege {}, {:.1} s -> {}",
        doc.files.len(),
        doc.keys.len(),
        doc.errors,
        if backup { "on" } else { "off" },
        t0.elapsed().as_secs_f64(),
        a.out.display()
    );
    Ok(())
}

#[cfg(not(windows))]
pub fn cmd_deep(_: &DeepArgs) -> Result<()> {
    bail!("deep runs on Windows only")
}

/// Captures everything the scope names.
#[cfg(windows)]
pub fn capture(scope: &Scope, sid: Option<&str>) -> DeepDoc {
    let mut c = win::Cap::default();
    for p in &scope.paths {
        let (body, d) = split_spec(p);
        c.fs(body, d, None);
    }
    for k in &scope.keys {
        let (body, d) = split_spec(k);
        c.reg(body, d, None, &win::KeyOpts::default());
    }
    for s in &scope.services {
        let o = win::KeyOpts { skip_subkeys: SERVICE_RUNTIME_SUBKEYS, ..Default::default() };
        c.reg(&format!("{}\\{s}", target::SERVICES), Depth::Tree, Some(format!("Service:{s}")), &o);
    }
    for t in &scope.tasks {
        let rel = t.trim_start_matches('\\');
        let tag = Some(format!("Task:{t}"));
        c.fs(&format!("{}\\{rel}", target::TASKS_DIR), Depth::Object, tag.clone());
        let o = win::KeyOpts { skip_values: TASK_TREE_RUNTIME_VALUES, ..Default::default() };
        c.reg(&format!("{}\\Tree\\{rel}", target::TASKCACHE), Depth::Object, tag, &o);
    }
    // Value-level entries last: a key captured whole already holds them.
    let mut only: BTreeMap<String, (String, Vec<String>, Option<String>)> = BTreeMap::new();
    for v in &scope.values {
        let e = only.entry(canon::fold(&v.key)).or_insert_with(|| (v.key.clone(), Vec::new(), None));
        e.1.push(v.name.clone());
    }
    for id in &scope.firewall_rules {
        let e = only
            .entry(canon::fold(target::FW_RULES))
            .or_insert_with(|| (target::FW_RULES.to_string(), Vec::new(), None));
        e.1.push(id.clone());
        e.2 = Some(format!("FirewallRule:{id}"));
    }
    for (_, (key, names, tag)) in only {
        if c.has_full_key(&key) {
            continue;
        }
        let o = win::KeyOpts { only_values: Some(names), ..Default::default() };
        c.reg(&key, Depth::Object, tag, &o);
    }
    let h = crate::capture::header_now();
    let mut doc = DeepDoc {
        schema: SCHEMA.to_string(),
        time: h.time,
        computer: h.computer,
        build: h.build,
        sid: sid.map(str::to_string),
        scope: scope.clone(),
        ..Default::default()
    };
    doc.files = c.files.into_values().collect();
    doc.files.sort_by(|a, b| canon::ci_cmp(&a.path, &b.path).then_with(|| a.path.cmp(&b.path)));
    doc.keys = c.keys.into_values().collect();
    doc.keys.sort_by(|a, b| canon::ci_cmp(&a.key, &b.key).then_with(|| a.key.cmp(&b.key)));
    doc.objects = win::task_objects(&scope.tasks);
    for id in &scope.firewall_rules {
        doc.objects.push(win::firewall_object(id));
    }
    doc.errors = (doc.files.iter().filter(|f| f.error.is_some()).count()
        + doc.keys.iter().filter(|k| k.error.is_some()).count()
        + doc.objects.iter().filter(|o| o.error.is_some()).count()) as u64;
    doc
}

// ---------------------------------------------------------------------------------------------
// Win32 capture
// ---------------------------------------------------------------------------------------------

#[cfg(windows)]
pub(crate) mod win {
    use super::{Depth, FileRec, KeyRec, ObjRec, StreamRec, ValueRec, hex};
    use crate::canon;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::io::Read;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::Authorization::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::Storage::FileSystem::*;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Registry::*;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const FSCTL_GET_REPARSE_POINT: u32 = 0x0009_00A8;
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
    const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
    const REG_LINK: u32 = 6;
    const SECINFO: OBJECT_SECURITY_INFORMATION =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

    pub(crate) fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn long_path(p: &str) -> String {
        if let Some(r) = p.strip_prefix("\\\\") { format!("\\\\?\\UNC\\{r}") } else { format!("\\\\?\\{p}") }
    }

    fn join(parent: &str, name: &str) -> String {
        if parent.ends_with('\\') { format!("{parent}{name}") } else { format!("{parent}\\{name}") }
    }

    fn ft(f: FILETIME) -> u64 {
        ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
    }

    fn last_error() -> u32 {
        unsafe { GetLastError() }
    }

    /// Best effort: SeBackupPrivilege lets an elevated capture read files whose DACL denies Administrators.
    pub fn enable_backup_privilege() -> bool {
        unsafe {
            let mut tok: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut tok) == 0 {
                return false;
            }
            let tok = OwnedHandle::from_raw_handle(tok);
            let mut luid = LUID { LowPart: 0, HighPart: 0 };
            let name = wide("SeBackupPrivilege");
            if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
                return false;
            }
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
            };
            let ok = AdjustTokenPrivileges(tok.as_raw_handle(), 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut());
            ok != 0 && GetLastError() == ERROR_SUCCESS
        }
    }

    fn open(path: &str, access: u32, extra_flags: u32) -> std::result::Result<OwnedHandle, u32> {
        let w = wide(&long_path(path));
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | extra_flags,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE { Err(last_error()) } else { Ok(unsafe { OwnedHandle::from_raw_handle(h) }) }
    }

    fn pwstr_to_string(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0;
        unsafe {
            while *p.add(n) != 0 {
                n += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
        }
    }

    /// SDDL (owner, group, DACL) of a security descriptor.
    fn sd_to_sddl(sd: PSECURITY_DESCRIPTOR) -> std::result::Result<String, u32> {
        let mut s: windows_sys::core::PWSTR = std::ptr::null_mut();
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                SECINFO,
                &mut s,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        let out = pwstr_to_string(s);
        unsafe { LocalFree(s as _) };
        Ok(out)
    }

    /// Owner part of an SDDL string (`O:BA` -> `BA`).
    pub fn sddl_owner(sddl: &str) -> Option<String> {
        let r = sddl.strip_prefix("O:")?;
        let end = r.find(':').map(|i| i.saturating_sub(1)).unwrap_or(r.len());
        Some(r[..end].to_string())
    }

    fn file_sddl(h: &OwnedHandle) -> std::result::Result<String, u32> {
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let r = unsafe {
            GetSecurityInfo(
                h.as_raw_handle(),
                SE_FILE_OBJECT,
                SECINFO,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        if r != ERROR_SUCCESS {
            return Err(r);
        }
        let out = sd_to_sddl(sd);
        unsafe { LocalFree(sd as _) };
        out
    }

    fn hash_handle(h: OwnedHandle) -> std::result::Result<(String, u64), String> {
        let mut f = std::fs::File::from(h);
        let mut hs = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut n_total = 0u64;
        loop {
            let n = f.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            hs.update(&buf[..n]);
            n_total += n as u64;
        }
        Ok((hex(&hs.finalize()), n_total))
    }

    fn streams(h: &OwnedHandle) -> std::result::Result<Vec<(String, u64)>, u32> {
        let mut buf = vec![0u8; 4096];
        loop {
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    h.as_raw_handle(),
                    FileStreamInfo,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len() as u32,
                )
            };
            if ok != 0 {
                break;
            }
            match last_error() {
                ERROR_HANDLE_EOF => return Ok(Vec::new()),
                ERROR_MORE_DATA | ERROR_INSUFFICIENT_BUFFER if buf.len() < (1 << 24) => {
                    let n = buf.len() * 4;
                    buf.resize(n, 0);
                }
                e => return Err(e),
            }
        }
        let mut out = Vec::new();
        let mut off = 0usize;
        loop {
            // FILE_STREAM_INFO: NextEntryOffset u32, StreamNameLength u32 (bytes), StreamSize i64,
            // StreamAllocationSize i64, StreamName [u16].
            if off + 24 > buf.len() {
                break;
            }
            let rd32 = |o: usize| u32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
            let next = rd32(off) as usize;
            let nlen = rd32(off + 4) as usize;
            let size = i64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap()) as u64;
            let s = off + 24;
            if s + nlen > buf.len() {
                break;
            }
            let w: Vec<u16> = buf[s..s + nlen].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
            out.push((String::from_utf16_lossy(&w), size));
            if next == 0 {
                break;
            }
            off += next;
        }
        Ok(out)
    }

    /// (tag, substitute name for junctions/symlinks, sha256 of the whole buffer).
    fn reparse(h: &OwnedHandle) -> std::result::Result<(u32, Option<String>, String), u32> {
        let mut buf = vec![0u8; 16 * 1024];
        let mut got = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                h.as_raw_handle(),
                FSCTL_GET_REPARSE_POINT,
                std::ptr::null(),
                0,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut got,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        let b = &buf[..got as usize];
        Ok(parse_reparse(b))
    }

    pub(crate) fn parse_reparse(b: &[u8]) -> (u32, Option<String>, String) {
        let rd16 = |o: usize| b.get(o..o + 2).map(|x| u16::from_le_bytes([x[0], x[1]]) as usize);
        let tag = b.get(0..4).map(|x| u32::from_le_bytes(x.try_into().unwrap())).unwrap_or(0);
        let path_at = match tag {
            IO_REPARSE_TAG_MOUNT_POINT => Some(16),
            IO_REPARSE_TAG_SYMLINK => Some(20),
            _ => None,
        };
        let target = path_at.and_then(|base| {
            let (so, sl) = (rd16(8)?, rd16(10)?);
            let s = b.get(base + so..base + so + sl)?;
            let w: Vec<u16> = s.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
            Some(String::from_utf16_lossy(&w))
        });
        (tag, target, super::sha256_hex(b))
    }

    fn short_name(path: &str) -> Option<String> {
        let w = wide(&long_path(path));
        let mut d: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
        let h = unsafe {
            FindFirstFileExW(
                w.as_ptr(),
                FindExInfoStandard,
                &mut d as *mut _ as *mut c_void,
                FindExSearchNameMatch,
                std::ptr::null(),
                0,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        unsafe { FindClose(h) };
        let n = d.cAlternateFileName.iter().position(|&c| c == 0).unwrap_or(d.cAlternateFileName.len());
        if n == 0 { None } else { Some(String::from_utf16_lossy(&d.cAlternateFileName[..n])) }
    }

    fn list_names(path: &str) -> std::result::Result<Vec<String>, u32> {
        let pat = wide(&join(&long_path(path), "*"));
        let mut d: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
        let h = unsafe {
            FindFirstFileExW(
                pat.as_ptr(),
                FindExInfoBasic,
                &mut d as *mut _ as *mut c_void,
                FindExSearchNameMatch,
                std::ptr::null(),
                FIND_FIRST_EX_LARGE_FETCH,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            let e = last_error();
            return if e == ERROR_FILE_NOT_FOUND { Ok(Vec::new()) } else { Err(e) };
        }
        let mut out = Vec::new();
        loop {
            let n = d.cFileName.iter().position(|&c| c == 0).unwrap_or(d.cFileName.len());
            let name = String::from_utf16_lossy(&d.cFileName[..n]);
            if name != "." && name != ".." {
                out.push(name);
            }
            if unsafe { FindNextFileW(h, &mut d) } == 0 {
                let e = last_error();
                unsafe { FindClose(h) };
                if e != ERROR_NO_MORE_FILES {
                    return Err(e);
                }
                break;
            }
        }
        out.sort_by(|a, b| canon::ci_cmp(a, b).then_with(|| a.cmp(b)));
        Ok(out)
    }

    /// Every fidelity field of one file system object (a link itself, never its target).
    pub fn file_rec(path: &str) -> FileRec {
        let mut r = FileRec { path: path.to_string(), ..Default::default() };
        let mut errs: Vec<String> = Vec::new();
        let h = match open(path, FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE, 0) {
            Ok(h) => Some(h),
            Err(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => return r,
            Err(ERROR_ACCESS_DENIED) => match open(path, FILE_READ_ATTRIBUTES | SYNCHRONIZE, 0) {
                Ok(h) => {
                    errs.push("sddl: open denied (5)".into());
                    Some(h)
                }
                Err(e) => {
                    errs.push(format!("open: {e}"));
                    None
                }
            },
            Err(e) => {
                errs.push(format!("open: {e}"));
                None
            }
        };
        r.present = true;
        let Some(h) = h else {
            r.error = Some(errs.join("; "));
            return r;
        };
        let mut i: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(h.as_raw_handle(), &mut i) } == 0 {
            errs.push(format!("info: {}", last_error()));
            r.error = Some(errs.join("; "));
            return r;
        }
        let is_dir = i.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let is_reparse = i.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        r.is_dir = Some(is_dir);
        r.attributes = Some(format!("0x{:08X}", i.dwFileAttributes));
        r.links = Some(i.nNumberOfLinks);
        r.file_id = Some(format!("{:016x}", ((i.nFileIndexHigh as u64) << 32) | i.nFileIndexLow as u64));
        r.volume_serial = Some(i.dwVolumeSerialNumber);
        r.last_write = Some(ft(i.ftLastWriteTime));
        if !is_dir {
            r.size = Some(((i.nFileSizeHigh as u64) << 32) | i.nFileSizeLow as u64);
        }
        if is_reparse {
            match reparse(&h) {
                Ok((tag, target, sha)) => {
                    r.reparse_tag = Some(format!("0x{tag:08X}"));
                    r.link_target = target;
                    r.reparse_sha256 = Some(sha);
                }
                Err(e) => {
                    let mut t = FILE_ATTRIBUTE_TAG_INFO { FileAttributes: 0, ReparseTag: 0 };
                    let ok = unsafe {
                        GetFileInformationByHandleEx(
                            h.as_raw_handle(),
                            FileAttributeTagInfo,
                            &mut t as *mut _ as *mut c_void,
                            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
                        )
                    };
                    if ok != 0 {
                        r.reparse_tag = Some(format!("0x{:08X}", t.ReparseTag));
                    }
                    errs.push(format!("reparse: {e}"));
                }
            }
        }
        if !errs.iter().any(|e| e.starts_with("sddl")) {
            match file_sddl(&h) {
                Ok(s) => {
                    r.owner = sddl_owner(&s);
                    r.sddl = Some(s);
                }
                Err(e) => errs.push(format!("sddl: {e}")),
            }
        }
        match streams(&h) {
            Ok(list) => {
                let mut v = Vec::new();
                for (name, size) in list {
                    if name.eq_ignore_ascii_case("::$DATA") {
                        continue;
                    }
                    let sha =
                        match open(&format!("{path}{name}"), FILE_READ_DATA | SYNCHRONIZE, FILE_FLAG_SEQUENTIAL_SCAN) {
                            Ok(sh) => match hash_handle(sh) {
                                Ok((s, _)) => Some(s),
                                Err(e) => {
                                    errs.push(format!("stream {name}: {e}"));
                                    None
                                }
                            },
                            Err(e) => {
                                errs.push(format!("stream {name}: open {e}"));
                                None
                            }
                        };
                    v.push(StreamRec { name, size, sha256: sha });
                }
                v.sort_by(|a, b| a.name.cmp(&b.name));
                r.streams = Some(v);
            }
            Err(e) => errs.push(format!("streams: {e}")),
        }
        if !is_dir && !is_reparse {
            match open(path, FILE_READ_DATA | SYNCHRONIZE, FILE_FLAG_SEQUENTIAL_SCAN) {
                Ok(ch) => match hash_handle(ch) {
                    Ok((s, _)) => r.sha256 = Some(s),
                    Err(e) => errs.push(format!("content: {e}")),
                },
                Err(e) => errs.push(format!("content: open {e}")),
            }
        }
        r.short_name = short_name(path);
        if !errs.is_empty() {
            r.error = Some(errs.join("; "));
        }
        r
    }

    // ---- registry ----

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open_key(canon_key: &str) -> std::result::Result<Key, u32> {
        let (head, sub) = canon_key.split_once('\\').unwrap_or((canon_key, ""));
        let hive = match head.to_ascii_uppercase().as_str() {
            "HKLM" => HKEY_LOCAL_MACHINE,
            "HKU" => HKEY_USERS,
            _ => return Err(ERROR_INVALID_PARAMETER),
        };
        let w = wide(sub);
        let mut h: HKEY = std::ptr::null_mut();
        let opts = REG_OPTION_OPEN_LINK;
        let mut r = unsafe { RegOpenKeyExW(hive, w.as_ptr(), opts, KEY_READ | KEY_WOW64_64KEY, &mut h) };
        if r == ERROR_ACCESS_DENIED {
            r = unsafe {
                RegOpenKeyExW(
                    hive,
                    w.as_ptr(),
                    opts,
                    KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY,
                    &mut h,
                )
            };
        }
        if r == ERROR_SUCCESS { Ok(Key(h)) } else { Err(r) }
    }

    struct Info {
        class: String,
        nsub: u32,
        max_sub: u32,
        max_vname: u32,
        max_vdata: u32,
        lwt: u64,
    }

    fn query_info(h: HKEY) -> std::result::Result<Info, u32> {
        let mut cls = vec![0u16; 1024];
        loop {
            let mut ccls = cls.len() as u32;
            let (mut nsub, mut max_sub, mut nval, mut max_vname, mut max_vdata) = (0u32, 0u32, 0u32, 0u32, 0u32);
            let mut f = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
            let r = unsafe {
                RegQueryInfoKeyW(
                    h,
                    cls.as_mut_ptr(),
                    &mut ccls,
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
            if r == ERROR_MORE_DATA && cls.len() < 65536 {
                let n = cls.len() * 4;
                cls.resize(n, 0);
                continue;
            }
            if r != ERROR_SUCCESS {
                return Err(r);
            }
            let class = String::from_utf16_lossy(&cls[..ccls as usize]);
            return Ok(Info { class, nsub, max_sub, max_vname, max_vdata, lwt: ft(f) });
        }
    }

    fn key_sddl(h: HKEY) -> std::result::Result<String, u32> {
        let mut cb = 0u32;
        let r = unsafe { RegGetKeySecurity(h, SECINFO, std::ptr::null_mut(), &mut cb) };
        if r != ERROR_INSUFFICIENT_BUFFER && r != ERROR_SUCCESS {
            return Err(r);
        }
        let mut b = vec![0u8; cb as usize + 16];
        let mut cb2 = b.len() as u32;
        let r = unsafe { RegGetKeySecurity(h, SECINFO, b.as_mut_ptr() as PSECURITY_DESCRIPTOR, &mut cb2) };
        if r != ERROR_SUCCESS {
            return Err(r);
        }
        sd_to_sddl(b.as_mut_ptr() as PSECURITY_DESCRIPTOR)
    }

    fn enum_subkeys(h: HKEY, info: &Info) -> std::result::Result<Vec<String>, u32> {
        let mut out = Vec::new();
        let mut buf = vec![0u16; (info.max_sub as usize + 1).max(256)];
        let mut i = 0u32;
        loop {
            let mut len = buf.len() as u32;
            let r = unsafe {
                RegEnumKeyExW(
                    h,
                    i,
                    buf.as_mut_ptr(),
                    &mut len,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            match r {
                ERROR_SUCCESS => {
                    out.push(String::from_utf16_lossy(&buf[..len as usize]));
                    i += 1;
                }
                ERROR_NO_MORE_ITEMS => break,
                ERROR_MORE_DATA if buf.len() < 32768 => buf.resize(32768, 0),
                e => return Err(e),
            }
        }
        out.sort_by(|a, b| canon::ci_cmp(a, b).then_with(|| a.cmp(b)));
        Ok(out)
    }

    /// (values, SymbolicLinkValue target if the key is a link).
    fn enum_values(h: HKEY, info: &Info) -> std::result::Result<(Vec<ValueRec>, Option<String>), u32> {
        let mut out = Vec::new();
        let mut link = None;
        let mut name = vec![0u16; (info.max_vname as usize + 1).max(256)];
        let mut data = vec![0u8; (info.max_vdata as usize).max(256)];
        let mut i = 0u32;
        let mut retries = 0;
        loop {
            let mut nlen = name.len() as u32;
            let mut dlen = data.len() as u32;
            let mut typ = 0u32;
            let r = unsafe {
                RegEnumValueW(
                    h,
                    i,
                    name.as_mut_ptr(),
                    &mut nlen,
                    std::ptr::null(),
                    &mut typ,
                    data.as_mut_ptr(),
                    &mut dlen,
                )
            };
            match r {
                ERROR_SUCCESS => {
                    let raw = &name[..nlen as usize];
                    let n = String::from_utf16_lossy(raw);
                    let clean = n.encode_utf16().eq(raw.iter().copied());
                    let d = &data[..dlen as usize];
                    if typ == REG_LINK && n.eq_ignore_ascii_case("SymbolicLinkValue") {
                        link = Some(crate::snap::preview(typ, d));
                    }
                    out.push(ValueRec {
                        name: n,
                        name_hex: if clean {
                            None
                        } else {
                            Some(hex(&raw.iter().flat_map(|c| c.to_le_bytes()).collect::<Vec<u8>>()))
                        },
                        typ,
                        len: dlen,
                        sha256: super::sha256_hex(d),
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
                e => return Err(e),
            }
        }
        out.sort_by(|a, b| canon::ci_cmp(&a.name, &b.name).then_with(|| a.name.cmp(&b.name)));
        Ok((out, link))
    }

    /// A firewall rule's registry string (M1b): the REG_SZ value `id` under `FirewallRules`, read as stored.
    pub fn firewall_object(id: &str) -> ObjRec {
        let mut r = ObjRec { kind: "firewall_rule".into(), id: id.to_string(), ..Default::default() };
        let h = match open_key(crate::target::FW_RULES) {
            Ok(h) => h,
            Err(ERROR_FILE_NOT_FOUND) => return r,
            Err(e) => {
                r.error = Some(format!("open: {e}"));
                return r;
            }
        };
        let w = wide(id);
        let mut buf = vec![0u8; 4096];
        loop {
            let (mut typ, mut len) = (0u32, buf.len() as u32);
            let e =
                unsafe { RegQueryValueExW(h.0, w.as_ptr(), std::ptr::null(), &mut typ, buf.as_mut_ptr(), &mut len) };
            match e {
                ERROR_SUCCESS => {
                    r.present = true;
                    if typ != REG_SZ {
                        r.error = Some(format!("type {typ}, want REG_SZ"));
                        return r;
                    }
                    let units: Vec<u16> =
                        buf[..len as usize].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
                    r.rule = Some(String::from_utf16_lossy(&units[..end]));
                    return r;
                }
                ERROR_FILE_NOT_FOUND => return r,
                ERROR_MORE_DATA if buf.len() < (1 << 20) => buf.resize((len as usize).max(buf.len() * 2), 0),
                e => {
                    r.error = Some(format!("query: {e}"));
                    return r;
                }
            }
        }
    }

    /// The task capture script (Windows PowerShell 5.1, `Schedule.Service`): `@@LIST@@` = the task paths as
    /// base64 (UTF-8) literals. One output line per task: `OK<TAB>path<TAB>xml<TAB>sddl`, `ABSENT<TAB>path` or
    /// `ERR<TAB>path<TAB>message`, every field after the tag base64 (UTF-8).
    const TASK_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$s = New-Object -ComObject Schedule.Service
$s.Connect()
$u = New-Object System.Text.UTF8Encoding($false)
foreach ($b in @(@@LIST@@)) {
    $p = $u.GetString([Convert]::FromBase64String($b))
    try {
        $i = $p.LastIndexOf('\')
        $dir = if ($i -le 0) { '\' } else { $p.Substring(0, $i) }
        $t = $s.GetFolder($dir).GetTask($p.Substring($i + 1))
        $x = [Convert]::ToBase64String($u.GetBytes([string]$t.Xml))
        $d = [Convert]::ToBase64String($u.GetBytes([string]$t.GetSecurityDescriptor(7)))
        "OK`t$b`t$x`t$d"
    } catch {
        $e = $_.Exception
        if ($e.InnerException) { $e = $e.InnerException }
        if ($e.HResult -eq -2147024894 -or $e.HResult -eq -2147024893) { "ABSENT`t$b" }
        else { "ERR`t$b`t" + [Convert]::ToBase64String($u.GetBytes(('0x{0:X8} {1}' -f $e.HResult, $e.Message))) }
    }
}
"#;

    /// Tasks as Task Scheduler returns them (M1b): one Windows PowerShell run over the `Schedule.Service` COM
    /// object for all `paths` (XML and `GetSecurityDescriptor(7)` = OWNER|GROUP|DACL, as the M1b spike read
    /// them). A missing task or folder (0x80070002 / 0x80070003) is `present: false`, any other failure an `error`.
    pub fn task_objects(paths: &[String]) -> Vec<ObjRec> {
        if paths.is_empty() {
            return Vec::new();
        }
        let list = paths.iter().map(|p| format!("'{}'", b64::encode(p.as_bytes()))).collect::<Vec<_>>().join(",");
        let script = TASK_SCRIPT.replace("@@LIST@@", &list);
        let fail = |e: String| -> Vec<ObjRec> {
            paths
                .iter()
                .map(|p| ObjRec {
                    kind: "task".into(),
                    id: p.clone(),
                    present: true,
                    error: Some(e.clone()),
                    ..Default::default()
                })
                .collect()
        };
        let file = std::env::temp_dir().join(format!("rigtool-tasks-{}.ps1", std::process::id()));
        // UTF-8 with a BOM: Windows PowerShell 5.1 reads a script without one in the ANSI code page.
        let mut body = vec![0xEF, 0xBB, 0xBF];
        body.extend_from_slice(script.as_bytes());
        if let Err(e) = std::fs::write(&file, body) {
            return fail(format!("task scheduler: write script: {e}"));
        }
        let sys = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let out = std::process::Command::new(format!("{sys}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(&file)
            .stdin(std::process::Stdio::null())
            .output();
        let _ = std::fs::remove_file(&file);
        let out = match out {
            Ok(o) if o.status.success() => o,
            Ok(o) => {
                return fail(format!(
                    "task scheduler: powershell exit {:?}: {}",
                    o.status.code(),
                    String::from_utf8_lossy(&o.stderr).trim()
                ));
            }
            Err(e) => return fail(format!("task scheduler: powershell: {e}")),
        };
        let dec = |b: &str| b64::decode(b).map(|v| String::from_utf8_lossy(&v).into_owned());
        let mut got: HashMap<String, ObjRec> = HashMap::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let f: Vec<&str> = line.trim_end().split('\t').collect();
            let Some(path) = f.get(1).and_then(|b| dec(b)) else { continue };
            let mut r = ObjRec { kind: "task".into(), id: path.clone(), ..Default::default() };
            match (f[0], f.len()) {
                ("OK", 4) => {
                    r.present = true;
                    r.xml = dec(f[2]);
                    r.sddl = dec(f[3]);
                    if r.xml.is_none() || r.sddl.is_none() {
                        r.error = Some("task scheduler: undecodable output".into());
                    }
                }
                ("ABSENT", 2) => {}
                ("ERR", 3) => {
                    r.present = true;
                    r.error = Some(format!("task scheduler: {}", dec(f[2]).unwrap_or_default()));
                }
                _ => continue,
            }
            got.insert(path, r);
        }
        paths
            .iter()
            .map(|p| {
                got.remove(p).unwrap_or_else(|| ObjRec {
                    kind: "task".into(),
                    id: p.clone(),
                    present: true,
                    error: Some("task scheduler: no output for this task".into()),
                    ..Default::default()
                })
            })
            .collect()
    }

    /// Standard base64 (RFC 4648, padded), for the task capture's exchange with PowerShell.
    pub(crate) mod b64 {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        pub fn encode(b: &[u8]) -> String {
            let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
            for c in b.chunks(3) {
                let n = ((c[0] as u32) << 16)
                    | ((c.get(1).copied().unwrap_or(0) as u32) << 8)
                    | c.get(2).copied().unwrap_or(0) as u32;
                for i in 0..4 {
                    if i <= c.len() {
                        s.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
                    } else {
                        s.push('=');
                    }
                }
            }
            s
        }

        pub fn decode(s: &str) -> Option<Vec<u8>> {
            let s = s.trim().as_bytes();
            if !s.len().is_multiple_of(4) {
                return None;
            }
            let mut out = Vec::with_capacity(s.len() / 4 * 3);
            for q in s.chunks(4) {
                let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
                if pad > 2 || q[..4 - pad].contains(&b'=') {
                    return None;
                }
                let mut n = 0u32;
                for (i, &c) in q[..4 - pad].iter().enumerate() {
                    n |= (A.iter().position(|&x| x == c)? as u32) << (18 - 6 * i);
                }
                out.push((n >> 16) as u8);
                if pad < 2 {
                    out.push((n >> 8) as u8);
                }
                if pad < 1 {
                    out.push(n as u8);
                }
            }
            Some(out)
        }
    }

    #[derive(Default)]
    pub struct KeyOpts {
        pub skip_subkeys: &'static [&'static str],
        pub skip_values: &'static [&'static str],
        pub only_values: Option<Vec<String>>,
    }

    /// One key record and its subkey names (empty for a link key: never followed).
    pub fn key_rec(key: &str, o: &KeyOpts) -> (KeyRec, Vec<String>) {
        let mut r = KeyRec { key: key.to_string(), ..Default::default() };
        let h = match open_key(key) {
            Ok(h) => h,
            Err(ERROR_FILE_NOT_FOUND) => return (r, Vec::new()),
            Err(e) => {
                r.present = true;
                r.error = Some(format!("open: {e}"));
                return (r, Vec::new());
            }
        };
        r.present = true;
        let mut errs = Vec::new();
        let info = match query_info(h.0) {
            Ok(i) => i,
            Err(e) => {
                r.error = Some(format!("info: {e}"));
                return (r, Vec::new());
            }
        };
        r.class = Some(info.class.clone());
        r.last_write = Some(info.lwt);
        match key_sddl(h.0) {
            Ok(s) => {
                r.owner = sddl_owner(&s);
                r.sddl = Some(s);
            }
            Err(e) => errs.push(format!("sddl: {e}")),
        }
        let mut omitted: Vec<String> = Vec::new();
        match enum_values(h.0, &info) {
            Ok((vals, link)) => {
                r.is_link = Some(link.is_some());
                r.link_target = link;
                r.values = vals
                    .into_iter()
                    .filter(|v| {
                        if o.skip_values.iter().any(|s| s.eq_ignore_ascii_case(&v.name)) {
                            omitted.push(format!("value:{}", v.name));
                            return false;
                        }
                        match &o.only_values {
                            Some(only) => only.iter().any(|n| n.eq_ignore_ascii_case(&v.name)),
                            None => true,
                        }
                    })
                    .collect();
            }
            Err(e) => errs.push(format!("values: {e}")),
        }
        r.only_values = o.only_values.clone();
        let mut subs = Vec::new();
        if r.is_link != Some(true) && info.nsub > 0 {
            match enum_subkeys(h.0, &info) {
                Ok(v) => {
                    for s in v {
                        if o.skip_subkeys.iter().any(|x| x.eq_ignore_ascii_case(&s)) {
                            omitted.push(format!("subkey:{s}"));
                        } else {
                            subs.push(s);
                        }
                    }
                }
                Err(e) => errs.push(format!("subkeys: {e}")),
            }
        }
        if !omitted.is_empty() {
            r.omitted = Some(omitted);
        }
        if !errs.is_empty() {
            r.error = Some(errs.join("; "));
        }
        (r, subs)
    }

    #[derive(Default)]
    pub struct Cap {
        pub files: HashMap<String, FileRec>,
        pub keys: HashMap<String, KeyRec>,
        /// Folded keys captured with all their values.
        full_keys: std::collections::HashSet<String>,
    }

    impl Cap {
        pub fn has_full_key(&self, k: &str) -> bool {
            self.full_keys.contains(&canon::fold(k))
        }

        pub fn fs(&mut self, path: &str, d: Depth, typed: Option<String>) {
            let f = canon::fold(path);
            let mut rec = match self.files.get(&f) {
                Some(r) if d == Depth::Object => {
                    if typed.is_some() && r.typed.is_none() {
                        self.files.get_mut(&f).unwrap().typed = typed;
                    }
                    return;
                }
                Some(r) => r.clone(),
                None => file_rec(path),
            };
            if typed.is_some() {
                rec.typed = typed;
            }
            let walk = d != Depth::Object && rec.present && rec.is_dir == Some(true) && rec.reparse_tag.is_none();
            let mut children = Vec::new();
            if walk {
                match list_names(path) {
                    Ok(v) => children = v,
                    Err(e) => {
                        let m = format!("list: {e}");
                        rec.error = Some(match rec.error.take() {
                            Some(x) => format!("{x}; {m}"),
                            None => m,
                        });
                    }
                }
            }
            self.files.insert(f, rec);
            let cd = if d == Depth::Children { Depth::Object } else { Depth::Tree };
            for c in children {
                self.fs(&join(path, &c), cd, None);
            }
        }

        pub fn reg(&mut self, key: &str, d: Depth, typed: Option<String>, o: &KeyOpts) {
            let f = canon::fold(key);
            if self.full_keys.contains(&f) && d == Depth::Object && o.only_values.is_none() {
                if typed.is_some() && self.keys.get(&f).is_some_and(|r| r.typed.is_none()) {
                    self.keys.get_mut(&f).unwrap().typed = typed;
                }
                return;
            }
            let (mut rec, subs) = key_rec(key, o);
            if typed.is_some() {
                rec.typed = typed;
            } else if let Some(old) = self.keys.get(&f) {
                rec.typed = old.typed.clone();
            }
            if o.only_values.is_none() {
                self.full_keys.insert(f.clone());
            }
            self.keys.insert(f, rec);
            if d == Depth::Object {
                return;
            }
            let cd = if d == Depth::Children { Depth::Object } else { Depth::Tree };
            let child_opts = KeyOpts { skip_subkeys: &[], skip_values: &[], only_values: None };
            for s in subs {
                self.reg(&join(key, &s), cd, None, &child_opts);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

/// Test helpers shared with `fidelity.rs`: a temp dir and a `HKCU\Software\PurgeRigTest-<random>` key that are
/// removed on drop.
#[cfg(all(test, windows))]
pub(crate) mod testenv {
    use super::win::wide;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::System::Registry::*;

    pub fn unique(tag: &str) -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        format!("{tag}-{}-{:x}-{}", std::process::id(), t & 0xffff_ffff, N.fetch_add(1, Ordering::SeqCst))
    }

    pub struct TempDir(pub std::path::PathBuf);
    impl TempDir {
        pub fn new() -> TempDir {
            let p = std::env::temp_dir().join(unique("purge-rigdeep"));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
        pub fn path(&self) -> String {
            crate::canon::canon_path(&self.0.to_string_lossy())
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            // Junctions inside are removed as links (remove_dir_all does not follow them).
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `HKCU\Software\PurgeRigTest-<random>`, deleted on drop.
    pub struct TestKey {
        pub sub: String,
    }
    impl TestKey {
        pub fn new() -> TestKey {
            let sub = format!("Software\\{}", unique("PurgeRigTest"));
            create(&sub, None);
            TestKey { sub }
        }
        /// Canonical name (`HKU\<sid>\Software\...`).
        pub fn canon(&self, rel: &str) -> String {
            let sid = crate::capture::current_user_sid().unwrap();
            if rel.is_empty() {
                format!("HKU\\{sid}\\{}", self.sub)
            } else {
                format!("HKU\\{sid}\\{}\\{rel}", self.sub)
            }
        }
        pub fn create(&self, rel: &str, class: Option<&str>) {
            create(&format!("{}\\{rel}", self.sub), class);
        }
        pub fn set(&self, rel: &str, name: &str, typ: u32, data: &[u8]) {
            let k = open(&self.full(rel));
            let n = wide(name);
            let r = unsafe { RegSetValueExW(k, n.as_ptr(), 0, typ, data.as_ptr(), data.len() as u32) };
            unsafe { RegCloseKey(k) };
            assert_eq!(r, ERROR_SUCCESS);
        }
        pub fn set_sddl(&self, rel: &str, sddl: &str) {
            use windows_sys::Win32::Security::Authorization::*;
            use windows_sys::Win32::Security::*;
            let k = open(&self.full(rel));
            let w = wide(sddl);
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    w.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    std::ptr::null_mut(),
                )
            };
            assert_ne!(ok, 0);
            let r = unsafe { RegSetKeySecurity(k, DACL_SECURITY_INFORMATION, sd) };
            unsafe {
                LocalFree(sd as _);
                RegCloseKey(k);
            }
            assert_eq!(r, ERROR_SUCCESS);
        }
        fn full(&self, rel: &str) -> String {
            if rel.is_empty() { self.sub.clone() } else { format!("{}\\{rel}", self.sub) }
        }
    }
    impl Drop for TestKey {
        fn drop(&mut self) {
            let w = wide(&self.sub);
            unsafe {
                RegDeleteTreeW(HKEY_CURRENT_USER, w.as_ptr());
                RegDeleteKeyW(HKEY_CURRENT_USER, w.as_ptr());
            }
        }
    }

    fn create(sub: &str, class: Option<&str>) {
        let w = wide(sub);
        let c = class.map(wide);
        let mut h: HKEY = std::ptr::null_mut();
        let r = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                w.as_ptr(),
                0,
                c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
                0,
                KEY_ALL_ACCESS,
                std::ptr::null(),
                &mut h,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(r, ERROR_SUCCESS, "create HKCU\\{sub}");
        unsafe { RegCloseKey(h) };
    }

    fn open(sub: &str) -> HKEY {
        let w = wide(sub);
        let mut h: HKEY = std::ptr::null_mut();
        let r = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, w.as_ptr(), 0, KEY_ALL_ACCESS, &mut h) };
        assert_eq!(r, ERROR_SUCCESS, "open HKCU\\{sub}");
        h
    }

    /// `mklink /J` (no elevation needed for a junction).
    pub fn junction(link: &str, target: &str) {
        let o = std::process::Command::new("cmd").args(["/c", "mklink", "/J", link, target]).output().unwrap();
        assert!(o.status.success(), "mklink /J failed: {}", String::from_utf8_lossy(&o.stderr));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_depths() {
        assert_eq!(split_spec("C:\\a@0"), ("C:\\a", Depth::Object));
        assert_eq!(split_spec("HKLM\\X@1"), ("HKLM\\X", Depth::Children));
        assert_eq!(split_spec("C:\\a"), ("C:\\a", Depth::Tree));
    }

    #[test]
    fn scope_from_targets_and_manifest() {
        let mut b = ScopeBuilder::new(Some("S-1-5-21-1"), Some("C:\\Users\\u\\AppData\\Local"));
        let targets = serde_json::json!({
            "schema": "purge.rig.targets/0", "source": "x", "origin": "ManualUser",
            "targets": [
                {"id": "a", "target": {"type": "Path", "path": "C:\\Program Files\\App\\dir"}, "action": "Quarantine"},
                {"id": "b", "target": {"type": "RegKey", "path": "HKCU\\Software\\App\\Tree"}, "action": "DeleteKey"},
                {"id": "c", "target": {"type": "RegValue", "path": "HKLM\\SOFTWARE\\App\\Values", "name": "v"}, "action": "DeleteValue"},
                {"id": "d", "target": {"type": "Service", "name": "AppSvc"}, "action": "Quarantine"},
                {"id": "e", "target": {"type": "FirewallRule", "id": "{R1}"}, "action": "Quarantine"}
            ]
        });
        b.add_doc(&targets).unwrap();
        let manifest = serde_json::json!({
            "schema": "purge.rig.m2fixtures/0", "user_sid": "{user-sid}",
            "traps": [{
                "id": "t", "fs_roots": ["C:\\Fx\\ads", "System.Collections.Hashtable\\x", "{localappdata}\\Purge\\fp"],
                "reg_roots": ["HKU\\{user-sid}\\Software\\Fx"],
                "items": [{"id": "i", "target": {"type": "RegKey", "path": "HKLM\\SOFTWARE\\Fx\\K"}}],
                "objects": [{"k": "value", "path": "HKLM\\SOFTWARE\\Fx\\V", "name": "n"}, {"k": "stream", "path": "C:\\Fx\\ads\\a.bin"}]
            }],
            "canaries": [{"kind": "file", "path": "C:\\Canary\\a.txt"}, {"kind": "regkey", "path": "HKLM\\SOFTWARE\\Canary\\K"}]
        });
        b.add_doc(&manifest).unwrap();
        assert!(b.add_doc(&serde_json::json!({"schema": "nope/1"})).is_err());
        let s = b.finish();
        assert!(s.paths.contains(&"C:\\Program Files\\App\\dir".to_string()));
        assert!(s.paths.contains(&"C:\\Program Files\\App@0".to_string()));
        assert!(s.keys.contains(&"HKU\\S-1-5-21-1\\Software\\App\\Tree".to_string()));
        assert!(s.keys.contains(&"HKU\\S-1-5-21-1\\Software\\App@0".to_string()));
        assert!(s.keys.contains(&"HKLM\\SOFTWARE\\App\\Values@0".to_string()));
        assert_eq!(s.services, vec!["AppSvc".to_string()]);
        assert_eq!(s.firewall_rules, vec!["{R1}".to_string()]);
        assert!(s.paths.contains(&"C:\\Fx\\ads".to_string()));
        assert!(s.paths.contains(&"C:\\Users\\u\\AppData\\Local\\Purge\\fp".to_string()));
        assert!(s.keys.contains(&"HKU\\S-1-5-21-1\\Software\\Fx".to_string()));
        assert!(s.keys.contains(&"HKLM\\SOFTWARE\\Fx\\K".to_string()));
        assert!(s.keys.contains(&"HKLM\\SOFTWARE\\Fx\\V@0".to_string()));
        assert!(s.paths.contains(&"C:\\Fx\\ads\\a.bin@0".to_string()));
        assert!(s.paths.contains(&"C:\\Canary\\a.txt@0".to_string()));
        assert!(s.keys.contains(&"HKLM\\SOFTWARE\\Canary\\K".to_string()));
        assert!(s.warnings.iter().any(|w| w.contains("System.Collections.Hashtable")));
    }

    #[cfg(windows)]
    #[test]
    fn reparse_buffer_parsing() {
        // Mount point: tag, len, reserved, sub off/len, print off/len, then names.
        let sub: Vec<u8> = "\\??\\C:\\T".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut b = Vec::new();
        b.extend_from_slice(&0xA000_0003u32.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(sub.len() as u16).to_le_bytes());
        b.extend_from_slice(&(sub.len() as u16 + 2).to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&sub);
        b.extend_from_slice(&[0, 0]);
        let (tag, t, _) = win::parse_reparse(&b);
        assert_eq!(tag, 0xA000_0003);
        assert_eq!(t.as_deref(), Some("\\??\\C:\\T"));
        assert_eq!(win::sddl_owner("O:BAG:SYD:(A;;FA;;;SY)").as_deref(), Some("BA"));
        assert_eq!(win::sddl_owner("O:S-1-5-21-1-2G:SY").as_deref(), Some("S-1-5-21-1-2"));
    }

    #[cfg(windows)]
    #[test]
    fn capture_files_ads_hardlink_junction() {
        use std::os::windows::fs::MetadataExt;
        let td = testenv::TempDir::new();
        let root = td.path();
        let f = format!("{root}\\app\\data.bin");
        std::fs::create_dir_all(format!("{root}\\app\\sub")).unwrap();
        std::fs::create_dir_all(format!("{root}\\outside\\inner")).unwrap();
        std::fs::write(&f, b"hello deep").unwrap();
        std::fs::write(format!("{f}:meta"), b"stream data").unwrap();
        std::fs::hard_link(&f, format!("{root}\\app\\sub\\link.bin")).unwrap();
        std::fs::write(format!("{root}\\outside\\inner\\secret.txt"), b"never read through the junction").unwrap();
        testenv::junction(&format!("{root}\\app\\j"), &format!("{root}\\outside"));
        let ro = format!("{root}\\app\\ro.txt");
        std::fs::write(&ro, b"read only").unwrap();
        let mut p = std::fs::metadata(&ro).unwrap().permissions();
        p.set_readonly(true);
        std::fs::set_permissions(&ro, p).unwrap();

        let scope = Scope { paths: vec![format!("{root}\\app"), format!("{root}\\missing")], ..Default::default() };
        let doc = capture(&scope, None);
        let get = |p: &str| doc.files.iter().find(|r| canon::ci_eq(&r.path, p)).unwrap_or_else(|| panic!("{p}"));
        let data = get(&f);
        assert!(data.present && data.error.is_none(), "{data:?}");
        assert_eq!(data.sha256.as_deref(), Some(sha256_hex(b"hello deep").as_str()));
        assert_eq!(data.links, Some(2));
        let st = data.streams.as_ref().unwrap();
        assert_eq!(st.len(), 1);
        assert_eq!(st[0].name, ":meta:$DATA");
        assert_eq!(st[0].size, 11);
        assert_eq!(st[0].sha256.as_deref(), Some(sha256_hex(b"stream data").as_str()));
        assert!(data.sddl.as_deref().is_some_and(|s| s.starts_with("O:")));
        assert!(data.owner.is_some());
        let link = get(&format!("{root}\\app\\sub\\link.bin"));
        assert_eq!(link.file_id, data.file_id);
        assert_eq!(link.volume_serial, data.volume_serial);
        let j = get(&format!("{root}\\app\\j"));
        assert_eq!(j.reparse_tag.as_deref(), Some("0xA0000003"));
        assert!(j.link_target.as_deref().is_some_and(|t| t.ends_with("\\outside")), "{j:?}");
        assert!(j.sha256.is_none());
        assert!(!doc.files.iter().any(|r| r.path.to_ascii_lowercase().contains("secret")), "junction was followed");
        let r = get(&ro);
        let attrs = u32::from_str_radix(r.attributes.as_deref().unwrap().trim_start_matches("0x"), 16).unwrap();
        assert_eq!(attrs & 1, 1);
        assert_eq!(attrs, std::fs::metadata(&ro).unwrap().file_attributes());
        let m = get(&format!("{root}\\missing"));
        assert!(!m.present);
        assert!(get(&format!("{root}\\app\\sub")).is_dir == Some(true));
        // @0 records the object only.
        let doc0 = capture(&Scope { paths: vec![format!("{root}\\app@0")], ..Default::default() }, None);
        assert_eq!(doc0.files.len(), 1);
        let mut p = std::fs::metadata(&ro).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        p.set_readonly(false);
        std::fs::set_permissions(&ro, p).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn capture_registry_tree() {
        let k = testenv::TestKey::new();
        k.create("Tree", Some("FixtureClass"));
        k.create("Tree\\Sub", None);
        k.create("Tree\\Sub\\Deep", None);
        k.set("Tree", "", 1, &"def\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<u8>>());
        k.set("Tree", "bin", 3, &[0, 1, 2, 255]);
        k.set("Tree", "dw", 4, &7u32.to_le_bytes());
        k.set("Tree", "odd", 0x1234_5678, &[9]);
        k.set("Tree\\Sub", "leaf", 4, &1u32.to_le_bytes());
        k.create("Other", None);
        k.set("Other", "keep", 4, &1u32.to_le_bytes());
        k.set("Other", "drop", 4, &2u32.to_le_bytes());

        let scope = Scope {
            keys: vec![k.canon("Tree"), format!("{}@0", k.canon(""))],
            values: vec![ValueSpec { key: k.canon("Other"), name: "keep".into() }],
            ..Default::default()
        };
        let doc = capture(&scope, None);
        let get = |p: &str| doc.keys.iter().find(|r| canon::ci_eq(&r.key, p)).unwrap_or_else(|| panic!("{p}"));
        let t = get(&k.canon("Tree"));
        assert!(t.present && t.error.is_none(), "{t:?}");
        assert_eq!(t.class.as_deref(), Some("FixtureClass"));
        assert_eq!(t.is_link, Some(false));
        assert!(t.sddl.as_deref().is_some_and(|s| s.contains("D:")));
        assert_eq!(t.values.len(), 4);
        assert_eq!(t.value("bin").unwrap().sha256, sha256_hex(&[0, 1, 2, 255]));
        assert_eq!(t.value("odd").unwrap().typ, 0x1234_5678);
        assert_eq!(t.value("").unwrap().len, 8);
        assert!(get(&k.canon("Tree\\Sub\\Deep")).present);
        // @0 parent: no subkeys walked beyond the listed ones.
        assert!(!doc.keys.iter().any(|r| canon::ci_eq(&r.key, &k.canon("Other\\x"))));
        let o = get(&k.canon("Other"));
        assert_eq!(o.values.len(), 1);
        assert_eq!(o.only_values.as_deref(), Some(&["keep".to_string()][..]));
        let missing = capture(&Scope { keys: vec![k.canon("Nope")], ..Default::default() }, None);
        assert!(!missing.keys[0].present);
    }

    #[cfg(windows)]
    #[test]
    fn b64_round_trip() {
        use super::win::b64::{decode, encode};
        for s in ["", "a", "ab", "abc", "\\Vendor\\Täsk", "x\ty"] {
            let e = encode(s.as_bytes());
            assert_eq!(decode(&e).unwrap(), s.as_bytes(), "{e}");
        }
        assert_eq!(encode(b"Man"), "TWFu");
        assert_eq!(encode(b"Ma"), "TWE=");
        assert!(decode("TWE").is_none());
        assert!(decode("T=E=").is_none());
    }

    /// M1b typed objects through their own API: a missing task and a missing firewall rule are absent, not
    /// errors; a task Windows ships (when this machine has it) comes back with its XML and SDDL.
    #[cfg(windows)]
    #[test]
    fn capture_typed_objects() {
        let scope = Scope {
            tasks: vec!["\\PurgeRigtoolNoSuchFolder\\NoSuchTask".into(), "\\PurgeRigtoolNoSuchTask".into()],
            firewall_rules: vec!["{00000000-0000-0000-0000-00000000dead}".into()],
            ..Default::default()
        };
        let doc = capture(&scope, None);
        let objs: Vec<_> = doc.objects.iter().map(|o| (o.kind.as_str(), o.present, o.error.is_some())).collect();
        assert_eq!(objs, [("task", false, false), ("task", false, false), ("firewall_rule", false, false)], "{doc:?}");
        let known = "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag";
        let o = &super::win::task_objects(&[known.to_string()])[0];
        if o.present {
            assert!(o.error.is_none(), "{o:?}");
            assert!(o.xml.as_deref().is_some_and(|x| x.contains("<Task")), "{o:?}");
            assert!(o.sddl.as_deref().is_some_and(|s| s.contains("D:")), "{o:?}");
        }
    }
}
