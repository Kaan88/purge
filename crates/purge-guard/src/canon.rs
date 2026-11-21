//! Canonicalisation of file paths and registry keys (gate G1, ENGINE_PLAN.md §5.10), and [`GuardEnv`], the
//! system facts every guard function works from.
//!
//! Everything here is pure. Facts that need I/O (the Windows directory, the current control set, the
//! profile list, sync roots, other apps' roots) arrive in a [`GuardEnv`] that the caller fills once per
//! scan. The process environment is never read.
//!
//! **File paths** ([`canon_path`]) come out as `X:\seg\seg`: upper-case drive letter, backslashes, no
//! doubled or trailing separator (a drive root is `X:\`). A leading environment token is expanded when it
//! is on the whitelist and known to the `GuardEnv`; `\\?\X:\` and `\??\X:\` prefixes are stripped. A path
//! is rejected when it is relative, UNC, in the device namespace, names `GLOBALROOT`, contains `..` or `.`
//! segments, an alternate data stream, a DOS device name, a segment ending in a dot or a space, or a
//! character Win32 does not allow in a name. Resolving 8.3 names needs the file system, so a segment that
//! looks like one only sets [`CanonPath::needs_long_name`]; the caller resolves it and canonicalises again.
//!
//! **Registry keys** ([`canon_key`]) come out as (hive, view, path) in the vocabulary of
//! [`purge_model::TypedTarget`]: `HKEY_*` and short root names map to `HKLM` or `HKU\<SID>`; `HKCU` needs
//! the SID it is bound to; `HKCR` is rejected (it is a merged view, never a physical location).
//! `HKLM\SYSTEM\CurrentControlSet` becomes `ControlSet00N` and `HKU\<SID>\Software\Classes` becomes
//! `HKU\<SID>_Classes`: the only two links resolved lexically. The second only where the hive has a
//! classes hive ([`purge_model::has_classes_hive`]): below `.DEFAULT` and the three service accounts
//! `Software\Classes` is an ordinary key and stays where it is. The WOW64 view is explicit: a
//! `WOW6432Node` spelling (including the `HKLM\SOFTWARE\Classes\WOW6432Node` alias) or a caller-supplied
//! view both yield [`View::K32`]. Case is preserved except for the root, the SID, and the well-known
//! segments this module rewrites (`SOFTWARE`, `SYSTEM`, `Software`, `Classes`, `ControlSet00N`); compare
//! canonical keys with [`crate::prefix`], not with `==`.

use std::fmt;

use purge_model::{Hive, RegKind, Target, TypedTarget, View};
use serde::{Deserialize, Serialize};

use crate::prefix::eq_ci;

#[cfg(test)]
pub(crate) mod tests;

/// One user profile as the guard sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfileEnv {
    /// The profile's SID (`S-1-5-21-...`).
    pub sid: String,
    /// `%USERPROFILE%`.
    pub root: String,
    /// `%APPDATA%` (roaming).
    pub appdata: String,
    /// `%LOCALAPPDATA%`.
    pub local_appdata: String,
    /// The path of every KNOWNFOLDERID of this profile (redirected folders included). The default layout
    /// under the profile root is protected even when this list is empty.
    pub known_folders: Vec<String>,
    /// The known folders that hold user content (Documents, Desktop, Downloads, Pictures, Videos, Music,
    /// Saved Games) when they are redirected away from the default layout. Nothing inside them can be an
    /// app root (§5.2 `validate_root`).
    pub user_content_folders: Vec<String>,
}

/// A root of an installed app other than the one being cleaned.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OtherAppRoot {
    /// A display name or program id of the owning app (used in the rule name only).
    pub app: String,
    /// The root directory.
    pub path: String,
}

/// The system facts the guard needs. Filled by the caller (from `purge-win` on a live system, from a
/// fixture in tests); the guard itself does no I/O.
///
/// The deny-list fails closed: [`GuardEnv::missing`] names required fields that are empty, and
/// `deny::check` denies every file and registry target while any is missing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardEnv {
    /// `%SystemDrive%`, e.g. `C:`.
    pub system_drive: String,
    /// `%WINDIR%`, e.g. `C:\Windows`.
    pub windir: String,
    /// The native Program Files directory (`%ProgramFiles%` of a 64-bit process, `%ProgramW6432%`).
    pub program_files: String,
    /// `%ProgramFiles(x86)%`, when the system has one.
    pub program_files_x86: Option<String>,
    /// `%ProgramData%`.
    pub program_data: String,
    /// The directory holding the profiles, e.g. `C:\Users`.
    pub profiles_dir: String,
    /// Every profile on the machine (`ProfileList`), loaded or not.
    pub profiles: Vec<ProfileEnv>,
    /// `HKLM\SYSTEM\Select\Current`: N of `ControlSet00N`. Zero means unknown; a `CurrentControlSet` key
    /// then fails to canonicalise.
    pub current_control_set: u32,
    /// Cloud sync roots (`SyncRootManager`, `StorageProviderSyncRootManager`).
    pub sync_roots: Vec<String>,
    /// Roots of every other installed app. Must not contain the roots of the app being cleaned.
    pub other_app_roots: Vec<OtherAppRoot>,
    /// Further directories that must never be removed, nor any ancestor of them: discovered Steam
    /// libraries, Java homes and the like.
    pub protected_dirs: Vec<String>,
    /// SIDs whose hives are loaded under `HKEY_USERS`. A key under any other SID is denied.
    pub loaded_sids: Vec<String>,
    /// Purge's own directories (install dir, quarantine and journal stores).
    pub purge_dirs: Vec<String>,
}

impl GuardEnv {
    /// A typical single-user Windows 11 layout on drive `C:`. Meant for tests and fixtures in this and
    /// other crates; the one profile has [`GuardEnv::SAMPLE_SID`].
    pub fn sample() -> Self {
        let sid = Self::SAMPLE_SID.to_owned();
        Self {
            system_drive: "C:".into(),
            windir: r"C:\Windows".into(),
            program_files: r"C:\Program Files".into(),
            program_files_x86: Some(r"C:\Program Files (x86)".into()),
            program_data: r"C:\ProgramData".into(),
            profiles_dir: r"C:\Users".into(),
            profiles: vec![ProfileEnv {
                sid: sid.clone(),
                root: r"C:\Users\tester".into(),
                appdata: r"C:\Users\tester\AppData\Roaming".into(),
                local_appdata: r"C:\Users\tester\AppData\Local".into(),
                known_folders: Vec::new(),
                user_content_folders: Vec::new(),
            }],
            current_control_set: 1,
            sync_roots: Vec::new(),
            other_app_roots: Vec::new(),
            protected_dirs: Vec::new(),
            loaded_sids: vec![sid],
            purge_dirs: vec![r"C:\Program Files\Purge".into()],
        }
    }

    /// The SID of the profile in [`GuardEnv::sample`].
    pub const SAMPLE_SID: &'static str = "S-1-5-21-1004336348-1177238915-682003330-1001";

    /// The names of required fields that are empty. Non-empty means the deny-list cannot be trusted and
    /// denies everything.
    pub fn missing(&self) -> Vec<&'static str> {
        [
            ("system_drive", &self.system_drive),
            ("windir", &self.windir),
            ("program_files", &self.program_files),
            ("program_data", &self.program_data),
            ("profiles_dir", &self.profiles_dir),
        ]
        .into_iter()
        .filter(|(_, v)| v.trim().is_empty())
        .map(|(name, _)| name)
        .collect()
    }

    /// The profile with the given SID.
    pub fn profile(&self, sid: &str) -> Option<&ProfileEnv> {
        self.profiles.iter().find(|p| eq_ci(&p.sid, sid))
    }

    /// The Program Files directories that exist on this system (native first).
    pub fn program_files_dirs(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.program_files.as_str())
            .chain(self.program_files_x86.as_deref())
            .filter(|s| !s.is_empty())
    }

    /// A copy with every directory in canonical form ([`canon_path`]), so that rules compiled from it
    /// match canonical targets. A fact that arrives as `C:/Windows`, `\\?\C:\Windows` or `c:\windows\`
    /// must protect the same directory as `C:\Windows`; compared raw it would protect nothing.
    ///
    /// Fails (and the deny-list then denies everything) when a required directory is not an absolute
    /// drive path below a drive root, or when any other directory cannot be canonicalised. Blank optional
    /// entries are dropped, and so are UNC ones: a target on a UNC path is refused by canonicalisation
    /// anyway, so a redirected folder on a share needs no rule.
    pub fn normalised(&self) -> Result<GuardEnv, String> {
        let bare = GuardEnv::default();
        let canon = |what: &str, path: &str| -> Result<Option<String>, String> {
            if path.trim().is_empty() {
                return Ok(None);
            }
            match canon_path(path, &bare, None) {
                Ok(canon) => Ok(Some(canon.path)),
                Err(CanonError::Unc) => Ok(None),
                Err(e) => Err(format!("GuardEnv.{what} {path:?}: {e}")),
            }
        };
        let required = |what: &str, path: &str| -> Result<String, String> {
            let path = canon(what, path)?
                .ok_or_else(|| format!("GuardEnv.{what} is not a local directory"))?;
            if crate::prefix::depth(&path) < 2 {
                return Err(format!("GuardEnv.{what} {path:?} is a drive root"));
            }
            Ok(path)
        };
        let list = |what: &str, paths: &[String]| -> Result<Vec<String>, String> {
            let mut out = Vec::with_capacity(paths.len());
            for path in paths {
                out.extend(canon(what, path)?);
            }
            Ok(out)
        };

        let drive = self.system_drive.trim().trim_end_matches(['\\', '/']);
        let b = drive.as_bytes();
        if !(b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':') {
            return Err(format!(
                "GuardEnv.system_drive {:?} is not a drive",
                self.system_drive
            ));
        }
        let mut profiles = Vec::with_capacity(self.profiles.len());
        for p in &self.profiles {
            profiles.push(ProfileEnv {
                sid: p.sid.trim().to_owned(),
                root: canon("profiles.root", &p.root)?.unwrap_or_default(),
                appdata: canon("profiles.appdata", &p.appdata)?.unwrap_or_default(),
                local_appdata: canon("profiles.local_appdata", &p.local_appdata)?
                    .unwrap_or_default(),
                known_folders: list("profiles.known_folders", &p.known_folders)?,
                user_content_folders: list(
                    "profiles.user_content_folders",
                    &p.user_content_folders,
                )?,
            });
        }
        let mut other_app_roots = Vec::with_capacity(self.other_app_roots.len());
        for other in &self.other_app_roots {
            if let Some(path) = canon("other_app_roots", &other.path)? {
                other_app_roots.push(OtherAppRoot {
                    app: other.app.clone(),
                    path,
                });
            }
        }
        Ok(GuardEnv {
            system_drive: drive.to_ascii_uppercase(),
            windir: required("windir", &self.windir)?,
            program_files: required("program_files", &self.program_files)?,
            program_files_x86: match &self.program_files_x86 {
                Some(path) if !path.trim().is_empty() => Some(required("program_files_x86", path)?),
                _ => None,
            },
            program_data: required("program_data", &self.program_data)?,
            profiles_dir: required("profiles_dir", &self.profiles_dir)?,
            profiles,
            current_control_set: self.current_control_set,
            sync_roots: list("sync_roots", &self.sync_roots)?,
            other_app_roots,
            protected_dirs: list("protected_dirs", &self.protected_dirs)?,
            loaded_sids: self
                .loaded_sids
                .iter()
                .map(|s| s.trim().to_owned())
                .collect(),
            purge_dirs: list("purge_dirs", &self.purge_dirs)?,
        })
    }

    /// The canonical name of the current control set (`ControlSet001`), if known.
    pub fn control_set_name(&self) -> Option<String> {
        (self.current_control_set != 0)
            .then(|| format!("ControlSet{:03}", self.current_control_set))
    }
}

/// Why a path or key could not be canonicalised. Every case is a reason to refuse the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonError {
    /// The input is empty.
    Empty,
    /// Not an absolute drive path (`foo\bar`, `\foo`, `C:`, `C:foo`).
    Relative,
    /// A `.` or `..` segment.
    DotSegment,
    /// `GLOBALROOT` appears in the path.
    GlobalRoot,
    /// A UNC path (`\\server\share`, `\\?\UNC\...`).
    Unc,
    /// The device namespace (`\\.\...`) or a `\\?\` form that is not a drive path (volume GUIDs).
    DeviceNamespace,
    /// A `:` after the drive letter: an alternate data stream.
    Ads,
    /// A segment is a DOS device name (`NUL`, `COM1`, `LPT1.txt`, ...).
    DeviceName(String),
    /// A segment ends in a dot or a space (Win32 strips these, so the name aliases another).
    TrailingDotOrSpace,
    /// A control character, or one of `< > " | ? *` in a file name.
    InvalidChar,
    /// An environment token that is not on the whitelist, is unknown to the `GuardEnv`, or is malformed.
    EnvToken(String),
    /// A per-user environment token or `HKCU` without a SID, or a SID with no profile in the `GuardEnv`.
    NoProfile,
    /// `HKEY_CLASSES_ROOT`: a merged view, not a location.
    Hkcr,
    /// A registry root other than HKLM, HKU or HKCU.
    UnknownRoot(String),
    /// `HKEY_USERS` with no SID below it.
    MissingSid,
    /// The segment below `HKEY_USERS` is not a SID.
    BadSid(String),
    /// `CurrentControlSet` while the current control set number is unknown.
    NoControlSet,
}

impl CanonError {
    /// A short, stable code for rule names and logs (`canon.<code>`).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Relative => "relative",
            Self::DotSegment => "dot-segment",
            Self::GlobalRoot => "globalroot",
            Self::Unc => "unc",
            Self::DeviceNamespace => "device-namespace",
            Self::Ads => "ads",
            Self::DeviceName(_) => "device-name",
            Self::TrailingDotOrSpace => "trailing-dot-or-space",
            Self::InvalidChar => "invalid-char",
            Self::EnvToken(_) => "env-token",
            Self::NoProfile => "no-profile",
            Self::Hkcr => "hkcr",
            Self::UnknownRoot(_) => "unknown-root",
            Self::MissingSid => "missing-sid",
            Self::BadSid(_) => "bad-sid",
            Self::NoControlSet => "no-control-set",
        }
    }
}

impl fmt::Display for CanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty path"),
            Self::Relative => f.write_str("not an absolute drive path"),
            Self::DotSegment => f.write_str("path contains a `.` or `..` segment"),
            Self::GlobalRoot => f.write_str("path names GLOBALROOT"),
            Self::Unc => f.write_str("UNC paths are not accepted"),
            Self::DeviceNamespace => f.write_str("device-namespace paths are not accepted"),
            Self::Ads => f.write_str("alternate data streams are not accepted"),
            Self::DeviceName(name) => write!(f, "segment {name:?} is a DOS device name"),
            Self::TrailingDotOrSpace => f.write_str("a segment ends in a dot or a space"),
            Self::InvalidChar => f.write_str("path contains a character not allowed in a name"),
            Self::EnvToken(token) => write!(f, "environment token {token:?} cannot be expanded"),
            Self::NoProfile => f.write_str("a per-user location needs a known profile SID"),
            Self::Hkcr => f.write_str("HKEY_CLASSES_ROOT is a merged view and is not accepted"),
            Self::UnknownRoot(root) => write!(f, "registry root {root:?} is not HKLM, HKU or HKCU"),
            Self::MissingSid => f.write_str("HKEY_USERS without a SID"),
            Self::BadSid(sid) => write!(f, "{sid:?} is not a SID"),
            Self::NoControlSet => f.write_str("the current control set number is unknown"),
        }
    }
}

impl std::error::Error for CanonError {}

/// A canonical file path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonPath {
    /// `X:\seg\seg`, or `X:\` for a drive root.
    pub path: String,
    /// A segment looks like an 8.3 short name (`PROGRA~1`). Short names alias long ones, so the caller
    /// must resolve the long name (I/O) and canonicalise the result before trusting any prefix test.
    pub needs_long_name: bool,
}

const WOW_NODE: &str = "WOW6432Node";
const CLASSES_SUFFIX: &str = "_Classes";

/// Canonicalises a file path. `sid` selects the profile for per-user environment tokens.
pub fn canon_path(input: &str, env: &GuardEnv, sid: Option<&str>) -> Result<CanonPath, CanonError> {
    if input.is_empty() {
        return Err(CanonError::Empty);
    }
    if input.chars().any(char::is_control) {
        return Err(CanonError::InvalidChar);
    }
    let unified = input.replace('/', "\\");
    let mut rest: &str = &unified;
    if let Some(after) = rest
        .strip_prefix(r"\\?\")
        .or_else(|| rest.strip_prefix(r"\??\"))
    {
        let first = after.split('\\').next().unwrap_or("");
        if eq_ci(first, "UNC") {
            return Err(CanonError::Unc);
        }
        if eq_ci(first, "GLOBALROOT") {
            return Err(CanonError::GlobalRoot);
        }
        if !is_drive_absolute(after) {
            return Err(CanonError::DeviceNamespace);
        }
        rest = after;
    } else if rest.starts_with(r"\\.\") {
        return Err(CanonError::DeviceNamespace);
    } else if rest.starts_with(r"\\") {
        return Err(CanonError::Unc);
    }

    let expanded;
    if rest.starts_with('%') {
        expanded = expand_token(rest, env, sid)?;
        rest = &expanded;
    }
    if !is_drive_absolute(rest) {
        return Err(CanonError::Relative);
    }

    let mut out = String::with_capacity(rest.len());
    out.push(rest.as_bytes()[0].to_ascii_uppercase() as char);
    out.push(':');
    let mut needs_long_name = false;
    let mut any = false;
    for segment in rest[2..].split('\\').filter(|s| !s.is_empty()) {
        check_segment(segment)?;
        needs_long_name |= looks_like_short_name(segment);
        out.push('\\');
        out.push_str(segment);
        any = true;
    }
    if !any {
        out.push('\\');
    }
    Ok(CanonPath {
        path: out,
        needs_long_name,
    })
}

/// `X:\...` (a bare `X:` or `X:foo` is drive-relative and does not count).
fn is_drive_absolute(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

fn check_segment(segment: &str) -> Result<(), CanonError> {
    if segment.chars().all(|c| c == '.') {
        return Err(CanonError::DotSegment);
    }
    if segment.ends_with('.') || segment.ends_with(' ') {
        return Err(CanonError::TrailingDotOrSpace);
    }
    if segment.contains(':') {
        return Err(CanonError::Ads);
    }
    if segment.contains(['<', '>', '"', '|', '?', '*']) {
        return Err(CanonError::InvalidChar);
    }
    if eq_ci(segment, "GLOBALROOT") {
        return Err(CanonError::GlobalRoot);
    }
    if is_device_name(segment) {
        return Err(CanonError::DeviceName(segment.to_owned()));
    }
    Ok(())
}

/// DOS device names, with or without an extension (`NUL`, `nul.txt`, `COM1`, `LPT9.log`, `CONIN$`).
fn is_device_name(segment: &str) -> bool {
    let base = segment
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ');
    const FIXED: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];
    if FIXED.iter().any(|d| base.eq_ignore_ascii_case(d)) {
        return true;
    }
    let mut chars = base.chars();
    let prefix: String = chars.by_ref().take(3).collect();
    let (Some(digit), None) = (chars.next(), chars.next()) else {
        return false;
    };
    (prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT"))
        && (digit.is_ascii_digit() || matches!(digit, '\u{b9}' | '\u{b2}' | '\u{b3}'))
}

/// A segment shaped like a generated 8.3 name: at most 8 characters of base ending in `~<digits>`, an
/// extension of at most 3, no spaces.
fn looks_like_short_name(segment: &str) -> bool {
    let (base, ext) = segment.rsplit_once('.').unwrap_or((segment, ""));
    if base.chars().count() > 8 || ext.chars().count() > 3 || segment.contains(' ') {
        return false;
    }
    let Some((head, digits)) = base.rsplit_once('~') else {
        return false;
    };
    !head.is_empty() && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Expands the leading `%NAME%` of `s` from the whitelist. Tokens elsewhere in the path are left as
/// literal text: `%` is legal in file names and nothing is ever read from the process environment.
fn expand_token(s: &str, env: &GuardEnv, sid: Option<&str>) -> Result<String, CanonError> {
    let bad = || CanonError::EnvToken(s.split('\\').next().unwrap_or(s).to_owned());
    let (name, tail) = s[1..].split_once('%').ok_or_else(bad)?;
    if !(tail.is_empty() || tail.starts_with('\\')) {
        return Err(bad());
    }
    let profile = || {
        sid.and_then(|sid| env.profile(sid))
            .ok_or(CanonError::NoProfile)
    };
    let common = |pf: &str| format!("{pf}\\Common Files");
    let base: String = match name.to_ascii_uppercase().as_str() {
        "SYSTEMDRIVE" | "HOMEDRIVE" => env.system_drive.clone(),
        "WINDIR" | "SYSTEMROOT" => env.windir.clone(),
        "PROGRAMFILES" | "PROGRAMW6432" => env.program_files.clone(),
        "PROGRAMFILES(X86)" => env.program_files_x86.clone().ok_or_else(bad)?,
        "COMMONPROGRAMFILES" | "COMMONPROGRAMW6432" => common(&env.program_files),
        "COMMONPROGRAMFILES(X86)" => common(env.program_files_x86.as_deref().ok_or_else(bad)?),
        "PROGRAMDATA" | "ALLUSERSPROFILE" => env.program_data.clone(),
        "PUBLIC" => format!("{}\\Public", env.profiles_dir),
        "USERPROFILE" => profile()?.root.clone(),
        "APPDATA" => profile()?.appdata.clone(),
        "LOCALAPPDATA" => profile()?.local_appdata.clone(),
        _ => return Err(bad()),
    };
    if base.trim_matches('\\').len() < 2 || base.starts_with('\\') {
        return Err(bad());
    }
    Ok(format!("{}{tail}", base.trim_end_matches('\\')))
}

/// A canonical registry key: the (hive, view, path) triple of [`TypedTarget`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonKey {
    /// The physical hive.
    pub hive: Hive,
    /// The WOW64 view. Always [`View::K64`] where no redirection applies.
    pub view: View,
    /// The path inside the hive and view, without `WOW6432Node`; empty for the hive root.
    pub path: String,
}

impl CanonKey {
    /// The canonical wire spelling, e.g. `HKLM\SOFTWARE\WOW6432Node\X`.
    pub fn key_path(&self) -> String {
        self.typed(RegKind::Key).key_path()
    }

    /// The typed target for this key and `kind`.
    pub fn typed(&self, kind: RegKind) -> TypedTarget {
        TypedTarget::new(self.hive.clone(), self.view, self.path.clone(), kind)
    }
}

/// Canonicalises a registry key path.
///
/// `view` is the view the caller read the key through, when it knows; a `WOW6432Node` spelling in the path
/// always selects the 32-bit view. `sid` binds `HKCU` / `HKEY_CURRENT_USER`.
pub fn canon_key(
    input: &str,
    view: Option<View>,
    env: &GuardEnv,
    sid: Option<&str>,
) -> Result<CanonKey, CanonError> {
    if input.chars().any(char::is_control) {
        return Err(CanonError::InvalidChar);
    }
    let mut segs: Vec<&str> = input.split('\\').filter(|s| !s.is_empty()).collect();
    if segs.first().is_some_and(|s| eq_ci(s, "Computer")) {
        segs.remove(0);
    }
    // The NT object-manager spelling `\REGISTRY\MACHINE`, `\REGISTRY\USER`.
    let mut root = *segs.first().ok_or(CanonError::Empty)?;
    let mut rest = &segs[1..];
    if eq_ci(root, "REGISTRY") && input.starts_with('\\') {
        root = match rest.first() {
            Some(s) if eq_ci(s, "MACHINE") => "HKLM",
            Some(s) if eq_ci(s, "USER") => "HKU",
            _ => return Err(CanonError::UnknownRoot(root.to_owned())),
        };
        rest = &rest[1..];
    }
    let wants_32 = view == Some(View::K32);
    match root.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => machine_key(rest, wants_32, env),
        "HKU" | "HKEY_USERS" => {
            let (sid, tail) = rest.split_first().ok_or(CanonError::MissingSid)?;
            user_key(sid, tail, wants_32)
        }
        "HKCU" | "HKEY_CURRENT_USER" => user_key(sid.ok_or(CanonError::NoProfile)?, rest, wants_32),
        "HKCR" | "HKEY_CLASSES_ROOT" => Err(CanonError::Hkcr),
        _ => Err(CanonError::UnknownRoot(root.to_owned())),
    }
}

fn is_wow(segment: Option<&&str>) -> bool {
    segment.is_some_and(|s| eq_ci(s, WOW_NODE))
}

fn machine_key(rest: &[&str], wants_32: bool, env: &GuardEnv) -> Result<CanonKey, CanonError> {
    let mut out: Vec<String> = Vec::with_capacity(rest.len());
    let mut view = View::K64;
    match rest.split_first() {
        Some((first, tail)) if eq_ci(first, "SOFTWARE") => {
            out.push("SOFTWARE".into());
            let mut tail = tail;
            if wants_32 {
                view = View::K32;
            }
            if is_wow(tail.first()) {
                view = View::K32;
                tail = &tail[1..];
            }
            if tail.first().is_some_and(|s| eq_ci(s, "Classes")) {
                out.push("Classes".into());
                tail = &tail[1..];
                // `HKLM\SOFTWARE\Classes\WOW6432Node` is a link to `HKLM\SOFTWARE\WOW6432Node\Classes`.
                if is_wow(tail.first()) {
                    view = View::K32;
                    tail = &tail[1..];
                }
            }
            out.extend(tail.iter().map(|s| (*s).to_owned()));
        }
        Some((first, tail)) if eq_ci(first, "SYSTEM") => {
            out.push("SYSTEM".into());
            let mut tail = tail;
            if let Some(set) = tail.first() {
                if eq_ci(set, "CurrentControlSet") {
                    out.push(env.control_set_name().ok_or(CanonError::NoControlSet)?);
                    tail = &tail[1..];
                } else if let Some(digits) = control_set_digits(set) {
                    out.push(format!("ControlSet{digits}"));
                    tail = &tail[1..];
                }
            }
            out.extend(tail.iter().map(|s| (*s).to_owned()));
        }
        _ => out.extend(rest.iter().map(|s| (*s).to_owned())),
    }
    Ok(CanonKey {
        hive: Hive::Hklm,
        view,
        path: out.join("\\"),
    })
}

/// The digits of a `ControlSetNNN` segment (any case).
fn control_set_digits(segment: &str) -> Option<&str> {
    const PREFIX: &str = "ControlSet";
    let cut = PREFIX.len();
    if segment.len() != cut + 3 || !segment.is_char_boundary(cut) {
        return None;
    }
    let (head, digits) = segment.split_at(cut);
    (head.eq_ignore_ascii_case(PREFIX) && digits.bytes().all(|b| b.is_ascii_digit()))
        .then_some(digits)
}

fn user_key(sid: &str, rest: &[&str], wants_32: bool) -> Result<CanonKey, CanonError> {
    let cut = sid.len().saturating_sub(CLASSES_SUFFIX.len());
    let classes_hive =
        cut > 0 && sid.is_char_boundary(cut) && sid[cut..].eq_ignore_ascii_case(CLASSES_SUFFIX);
    let sid = canon_sid(if classes_hive { &sid[..cut] } else { sid })?;

    let mut rest = rest;
    let mut in_classes = classes_hive;
    // Only where `Software\Classes` is the link to a classes hive. `.DEFAULT` and the service accounts
    // have none: a key below their `Software\Classes` is canonical where it is, as the Live source reads
    // it.
    if !classes_hive
        && purge_model::has_classes_hive(&sid)
        && rest.len() >= 2
        && eq_ci(rest[0], "Software")
        && eq_ci(rest[1], "Classes")
    {
        in_classes = true;
        rest = &rest[2..];
    }
    if in_classes {
        let mut view = if wants_32 { View::K32 } else { View::K64 };
        if is_wow(rest.first()) {
            view = View::K32;
            rest = &rest[1..];
        }
        return Ok(CanonKey {
            hive: Hive::HkuClasses(sid),
            view,
            path: rest.join("\\"),
        });
    }
    let mut out: Vec<&str> = rest.to_vec();
    if out.first().is_some_and(|s| eq_ci(s, "Software")) {
        out[0] = "Software";
    }
    // A user hive has no redirected `Software` node: `Software\WOW6432Node` there is an ordinary key.
    Ok(CanonKey {
        hive: Hive::Hku(sid),
        view: View::K64,
        path: out.join("\\"),
    })
}

/// `.DEFAULT` or `S-1-...` (digits and dashes), upper-cased.
fn canon_sid(sid: &str) -> Result<String, CanonError> {
    if sid.eq_ignore_ascii_case(".DEFAULT") {
        return Ok(".DEFAULT".into());
    }
    let upper = sid.to_ascii_uppercase();
    let ok = upper.strip_prefix("S-1-").is_some_and(|tail| {
        !tail.is_empty()
            && tail
                .split('-')
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    });
    if ok {
        Ok(upper)
    } else {
        Err(CanonError::BadSid(sid.to_owned()))
    }
}

/// A canonical target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonTarget {
    /// The target with its path or key in canonical form. Other fields are unchanged.
    pub target: Target,
    /// See [`CanonPath::needs_long_name`]; always false for registry and API-object targets.
    pub needs_long_name: bool,
}

/// Canonicalises the path or key of a target. Service, task, firewall-rule and package targets have no
/// path and are returned as they are.
///
/// Registry keys under the current control set come out as `ControlSet00N`; a caller that writes plans for
/// the rig scorer, which spells `CurrentControlSet`, translates on emission.
pub fn canon_target(
    target: &Target,
    env: &GuardEnv,
    sid: Option<&str>,
) -> Result<CanonTarget, CanonError> {
    let key = |path: &str| canon_key(path, None, env, sid).map(|k| k.key_path());
    let mut needs_long_name = false;
    let target = match target {
        Target::Path { path } => {
            let canon = canon_path(path, env, sid)?;
            needs_long_name = canon.needs_long_name;
            Target::Path { path: canon.path }
        }
        Target::RegKey { path } => Target::RegKey { path: key(path)? },
        Target::RegValue { path, name } => Target::RegValue {
            path: key(path)?,
            name: name.clone(),
        },
        Target::RegValueChanged {
            path,
            name,
            before,
            after,
        } => Target::RegValueChanged {
            path: key(path)?,
            name: name.clone(),
            before: before.clone(),
            after: after.clone(),
        },
        Target::RegMultiSzSegment {
            path,
            name,
            segment,
            index,
        } => Target::RegMultiSzSegment {
            path: key(path)?,
            name: name.clone(),
            segment: segment.clone(),
            index: *index,
        },
        other @ (Target::Service { .. }
        | Target::Task { .. }
        | Target::FirewallRule { .. }
        | Target::AppxPackage { .. }) => other.clone(),
    };
    Ok(CanonTarget {
        target,
        needs_long_name,
    })
}
