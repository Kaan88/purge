//! The [`LocalSources`] trait: what this Windows installation says about itself, read once and read-only,
//! for the local baseline (BASELINE_LOCAL_DESIGN.md §3.1, package BL-SOURCES).
//!
//! | Method | Source | Read how |
//! |---|---|---|
//! | [`LocalSources::manifests`] | S1, `%SystemRoot%\WinSxS\Manifests\*.manifest` | one directory listing, then each file by path, bytes as stored (mostly `DCM\x01` deltas; the caller expands them with `purge-win` `sxs`) |
//! | [`LocalSources::default_hive`] | S2, the default profile's `NTUSER.DAT` | `ProfileList\Default` (else `ProfileList\ProfilesDirectory` + `\Default`), walked offline, never mounted |
//! | [`LocalSources::system_default`] | S3, `HKU\.DEFAULT` | the live key through [`RegistrySource`] ([`walk_registry`]) |
//! | [`LocalSources::inbox_packages`] | S4, inbox package manifests | package list, `<install dir>\AppxManifest.xml` by path, the package repository's generated ProgIDs ([`collect_inbox_packages`]) |
//!
//! Everything here is read only, and every source only adds to "Windows' own" (invariant L1): a source
//! that fails reports it (an error, or a count in its summary) and the build's completeness seal decides
//! (BL-BUILD, §3.4); nothing here is fatal for the others.
//!
//! **Inbox package** means: signature kind System, or published by Microsoft (publisher id
//! `8wekyb3d8bbwe` or `cw5n1h2txyewy`) **and** provisioned for every user (its family is under
//! `AppxAllUserStore\Applications`). Any other package is counted in [`InboxPackages::not_inbox`] and never
//! returned: its keys belong to another app, not to Windows. Package directories are read file by file;
//! `WindowsApps` is never listed.
//!
//! **Generated ProgIDs** (the design's S4 spike, answered on Windows 11 26100/26300): the `AppX…` ProgIDs
//! Windows writes into each user's classes hive for a package's file types and protocols are named by
//! `HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions`:
//! - `ProgIDs\<AppX…>` holds one value per package that uses that ProgID, the value **name** being the
//!   package full name (no data);
//! - `windows.fileTypeAssociation\<.ext>\<AppX…>` and `windows.protocol\<scheme>\<AppX…>` likewise hold a
//!   value named by the full name, which links each ProgID to its extensions and schemes.
//!
//! The per-package tree `PackageRepository\Packages\<full name>\<app>\windows.fileTypeAssociation\<.ext>`
//! has only `ACID` and `Logo` values and does not name the ProgID.

use std::collections::{BTreeMap, BTreeSet};

use crate::filesystem::FileSystemSource;
use crate::registry::RegistrySource;
use crate::system::SystemSource;
use crate::types::{PackageInfo, PackageSignatureKind, SourceError, SourceResult};

/// Deepest key a registry walk yields, in path components below its root (as `purge-win` `offreg`).
pub const MAX_WALK_DEPTH: u32 = 64;
/// Most keys one walk yields (as `purge-win` `offreg`).
pub const MAX_WALK_KEYS: u64 = 2_000_000;
/// Largest component manifest read; a larger file is an error for that file.
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
/// Largest `AppxManifest.xml` read; a larger file is an error for that package.
pub const MAX_APPX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;

/// `ProfileList`, where the default profile's directory is named.
pub const PROFILE_LIST: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
/// The key S3 walks.
pub const SYSTEM_DEFAULT_KEY: &str = r"HKU\.DEFAULT";
/// Provisioned packages, one subkey per package (bundle) full name.
pub const PROVISIONED_KEY: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications";
/// The package repository's extension index (see the module documentation).
pub const REPOSITORY_EXTENSIONS_KEY: &str = r"HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions";
/// Publisher ids of Microsoft's package signing identities (`CN=Microsoft Corporation, …` and
/// `CN=Microsoft Windows, …`).
pub const MICROSOFT_PUBLISHER_IDS: [&str; 2] = ["8wekyb3d8bbwe", "cw5n1h2txyewy"];

/// One component manifest: its file name and its bytes as stored, or why they could not be read.
pub type ManifestItem = (String, SourceResult<Vec<u8>>);

/// The component manifests, read lazily one by one.
pub type ManifestIter<'a> = Box<dyn Iterator<Item = ManifestItem> + Send + 'a>;

/// One item of a hive walk. Paths are relative to the walked root, `\`-separated, without a leading `\`,
/// with names as stored; the root itself is the empty path. A key comes before its values and subkeys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HiveEntry<'a> {
    /// A key.
    Key {
        /// Its path below the root.
        path: &'a str,
    },
    /// A value of the key yielded last (the default value has the empty name). Data is never read.
    Value {
        /// Path of the key that holds it.
        key: &'a str,
        /// The value name.
        name: &'a str,
        /// Its `REG_*` type.
        kind: u32,
    },
}

/// What one hive walk saw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HiveWalk {
    /// What was walked: the hive file path (S2) or the key (S3).
    pub origin: String,
    /// Keys yielded, the root included.
    pub keys: u64,
    /// Values yielded.
    pub values: u64,
    /// Keys whose values or subkeys could not be read (access denied, any error but "gone").
    pub unreadable: u64,
    /// Listed keys that were not found when the walk opened them: yielded, their content unknown. A
    /// live hive can change while it is read; a source can also fail to open a key its parent lists
    /// (the Live registry maps `HKU\.DEFAULT\Software\Classes\X` onto a `.DEFAULT_Classes` hive that
    /// does not exist).
    pub vanished: u64,
    /// Registry links met; yielded, never followed.
    pub links: u64,
    /// A depth or key cap was reached.
    pub capped: bool,
}

impl HiveWalk {
    /// Every key and value below the root was yielded: no cap, nothing unreadable or vanished.
    pub fn is_complete(&self) -> bool {
        self.unreadable == 0 && self.vanished == 0 && !self.capped
    }
}

/// Why a package counts as inbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InboxReason {
    /// Signature kind System.
    System,
    /// Microsoft-published and provisioned for every user.
    MicrosoftProvisioned,
}

/// A generated ProgID of a package, from the package repository.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepositoryProgId {
    /// The ProgID (`AppX…`).
    pub prog_id: String,
    /// File extensions it is registered for (`.jpg`), as the repository spells them.
    pub file_types: Vec<String>,
    /// URI schemes it is registered for (`ms-settings`).
    pub protocols: Vec<String>,
}

/// One inbox package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxPackage {
    /// Package full name.
    pub full_name: String,
    /// Package family name.
    pub family: String,
    /// Why it counts as inbox.
    pub reason: InboxReason,
    /// The text of its `AppxManifest.xml`, or why it could not be read (counted by the caller, never
    /// fatal).
    pub manifest: SourceResult<String>,
    /// Its generated ProgIDs, sorted; empty when the repository names none (or could not be read, see
    /// [`InboxPackages::repository`]).
    pub repository_prog_ids: Vec<RepositoryProgId>,
}

/// The inbox packages and how they were found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxPackages {
    /// The inbox packages, sorted by full name.
    pub packages: Vec<InboxPackage>,
    /// The package list covers every user (elevated). Otherwise it is the engine account's own list.
    pub machine_wide: bool,
    /// Packages listed that are not inbox (third-party, or Microsoft-published but not provisioned).
    pub not_inbox: u64,
    /// The provisioned list could be read (`Ok(number of provisioned packages)`); without it no package
    /// qualifies as [`InboxReason::MicrosoftProvisioned`].
    pub provisioned: SourceResult<u64>,
    /// The repository index could be read; without it no package has repository ProgIDs.
    pub repository: SourceResult<()>,
}

/// The four local sources. Object safe; read only.
pub trait LocalSources: Send + Sync {
    /// S1: every `*.manifest` file of `%SystemRoot%\WinSxS\Manifests`, in listing order, as stored on
    /// disk (`DCM\x01` delta or plain XML; expansion is the caller's). An error here means the directory
    /// itself could not be listed; a file that cannot be read is an `Err` item.
    fn manifests(&self) -> SourceResult<ManifestIter<'_>>;

    /// S2: walks the default profile's `NTUSER.DAT` without mounting it. Paths are relative to the hive
    /// root.
    fn default_hive(&self, visit: &mut dyn FnMut(HiveEntry<'_>)) -> SourceResult<HiveWalk>;

    /// S3: walks `HKU\.DEFAULT` through the [`RegistrySource`]. Paths are relative to `HKU\.DEFAULT`.
    fn system_default(&self, visit: &mut dyn FnMut(HiveEntry<'_>)) -> SourceResult<HiveWalk>;

    /// S4: the inbox packages with their manifest text and repository ProgIDs. An error here means the
    /// package list itself could not be read.
    fn inbox_packages(&self) -> SourceResult<InboxPackages>;
}

// ---------------------------------------------------------------------------------------------------------
// Shared readers (Live and Fixture use the same code)
// ---------------------------------------------------------------------------------------------------------

/// `%SystemRoot%` from the source's environment.
pub fn system_root(sys: &dyn SystemSource) -> SourceResult<String> {
    let env = sys.env()?;
    env.get("SYSTEMROOT")
        .or_else(|| env.get("WINDIR"))
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('\\').to_owned())
        .ok_or(SourceError::NotCaptured)
}

/// The S1 listing and lazy reads, through `fs`.
pub fn list_manifests<'a>(
    fs: &'a dyn FileSystemSource,
    sys: &dyn SystemSource,
) -> SourceResult<ManifestIter<'a>> {
    let dir = format!(r"{}\WinSxS\Manifests", system_root(sys)?);
    let mut names: Vec<String> = fs
        .list_dir(&dir)?
        .into_iter()
        .filter(|e| !e.meta.is_dir() && !e.meta.is_reparse_point())
        .map(|e| e.name)
        .filter(|n| has_suffix_ci(n, ".manifest"))
        .collect();
    names.sort_by_cached_key(|n| n.to_ascii_lowercase());
    Ok(Box::new(names.into_iter().map(move |name| {
        let bytes = read_capped(fs, &format!(r"{dir}\{name}"), MAX_MANIFEST_BYTES);
        (name, bytes)
    })))
}

/// The default profile's hive file: `<ProfileList\Default>\NTUSER.DAT`, or, when that value is missing
/// or empty, `<ProfileList\ProfilesDirectory>\Default\NTUSER.DAT`. Environment references are expanded
/// with the source's environment; a reference left unexpanded is an error.
pub fn default_hive_path(reg: &dyn RegistrySource, sys: &dyn SystemSource) -> SourceResult<String> {
    let text = |name: &str| -> SourceResult<Option<String>> {
        match reg.value(PROFILE_LIST, name) {
            Ok(d) => Ok(d.string().filter(|s| !s.trim().is_empty())),
            Err(SourceError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    };
    let dir = match text("Default")? {
        Some(d) => d,
        None => match text("ProfilesDirectory")? {
            Some(p) => format!(r"{}\Default", p.trim_end_matches('\\')),
            None => return Err(SourceError::NotFound),
        },
    };
    let env: purge_win::env::EnvMap = sys.env()?.into_iter().collect();
    let dir = purge_win::env::expand_with(dir.trim(), &env);
    if dir.contains('%') {
        return Err(SourceError::InvalidPath(dir));
    }
    Ok(format!(r"{}\NTUSER.DAT", dir.trim_end_matches('\\')))
}

/// Walks `root` and everything below it through `reg`, depth-first (a key, its values, then its subkeys
/// in the order the source lists them), within [`MAX_WALK_DEPTH`] and [`MAX_WALK_KEYS`]. A link key is
/// yielded with its values and not descended into. A key that cannot be read is yielded, counted in
/// [`HiveWalk::unreadable`] and not descended into; a listed key that is gone is counted in
/// [`HiveWalk::vanished`]. An error only when `root` itself cannot be read.
pub fn walk_registry(
    reg: &dyn RegistrySource,
    root: &str,
    visit: &mut dyn FnMut(HiveEntry<'_>),
) -> SourceResult<HiveWalk> {
    let root = root.trim_end_matches('\\');
    let mut walk = HiveWalk {
        origin: root.to_owned(),
        ..HiveWalk::default()
    };
    let mut walker = reg.walker();
    // (path below the root, depth)
    let mut stack: Vec<(String, u32)> = vec![(String::new(), 0)];
    while let Some((rel, depth)) = stack.pop() {
        if walk.keys >= MAX_WALK_KEYS {
            walk.capped = true;
            break;
        }
        let full = if rel.is_empty() {
            root.to_owned()
        } else {
            format!(r"{root}\{rel}")
        };
        let info = match walker.enter(&full) {
            Ok(i) => Ok(i),
            Err(e) if rel.is_empty() => return Err(e),
            Err(e) => Err(e),
        };
        // A listed key is yielded even when it cannot be opened: its parent named it (L1, additive).
        visit(HiveEntry::Key { path: &rel });
        walk.keys += 1;
        let info = match info {
            Ok(i) => i,
            Err(SourceError::NotFound) => {
                walk.vanished += 1;
                continue;
            }
            Err(_) => {
                walk.unreadable += 1;
                continue;
            }
        };
        match walker.values() {
            Ok(values) => {
                for v in &values {
                    visit(HiveEntry::Value {
                        key: &rel,
                        name: &v.name,
                        kind: v.data.ty,
                    });
                    walk.values += 1;
                }
            }
            Err(_) => {
                walk.unreadable += 1;
                continue;
            }
        }
        if info.is_link {
            walk.links += 1;
            continue;
        }
        let subkeys = match walker.subkeys() {
            Ok(s) => s,
            Err(_) => {
                walk.unreadable += 1;
                continue;
            }
        };
        if subkeys.is_empty() {
            continue;
        }
        if depth >= MAX_WALK_DEPTH {
            walk.capped = true;
            continue;
        }
        for name in subkeys.into_iter().rev() {
            let child = if rel.is_empty() {
                name
            } else {
                format!(r"{rel}\{name}")
            };
            stack.push((child, depth + 1));
        }
    }
    Ok(walk)
}

/// The publisher id of a package full name (`Name_Version_Arch_Resource_PublisherId`) or family name
/// (`Name_PublisherId`): the text after the last `_`, lower-cased.
pub fn publisher_id(name: &str) -> Option<String> {
    let (_, id) = name.rsplit_once('_')?;
    (!id.is_empty()).then(|| id.to_ascii_lowercase())
}

/// The family name (`Name_PublisherId`, lower-cased) of a package or bundle full name; `None` when the
/// name does not have the five `_`-separated parts.
pub fn family_of_full_name(full_name: &str) -> Option<String> {
    let parts: Vec<&str> = full_name.split('_').collect();
    match parts.as_slice() {
        [name, _version, _arch, _resource, publisher]
            if !name.is_empty() && !publisher.is_empty() =>
        {
            Some(format!("{name}_{publisher}").to_ascii_lowercase())
        }
        _ => None,
    }
}

/// Whether a package is inbox, and why. `provisioned` holds lower-cased family names.
pub fn inbox_reason(p: &PackageInfo, provisioned: &BTreeSet<String>) -> Option<InboxReason> {
    if p.signature_kind == PackageSignatureKind::System {
        return Some(InboxReason::System);
    }
    let family = if p.family.is_empty() {
        family_of_full_name(&p.full_name)?
    } else {
        p.family.to_ascii_lowercase()
    };
    let microsoft = publisher_id(&family)
        .is_some_and(|id| MICROSOFT_PUBLISHER_IDS.iter().any(|m| *m == id));
    (microsoft && provisioned.contains(&family)).then_some(InboxReason::MicrosoftProvisioned)
}

/// S4 through the three sources: the package list ([`SystemSource::packages`], machine-wide when
/// elevated), the provisioned list ([`PROVISIONED_KEY`]), each inbox package's
/// `<install location>\AppxManifest.xml` read by path, and the repository index
/// ([`REPOSITORY_EXTENSIONS_KEY`]).
pub fn collect_inbox_packages(
    reg: &dyn RegistrySource,
    fs: &dyn FileSystemSource,
    sys: &dyn SystemSource,
) -> SourceResult<InboxPackages> {
    let listed = sys.packages()?;
    let machine_wide = sys.elevated();

    let provisioned_list = reg.subkeys(PROVISIONED_KEY);
    let provisioned: BTreeSet<String> = provisioned_list
        .as_ref()
        .map(|names| {
            names
                .iter()
                .filter_map(|n| family_of_full_name(n))
                .collect()
        })
        .unwrap_or_default();

    let mut not_inbox = 0u64;
    let mut chosen: BTreeMap<String, (PackageInfo, InboxReason)> = BTreeMap::new();
    for p in listed {
        match inbox_reason(&p, &provisioned) {
            Some(reason) => {
                chosen
                    .entry(p.full_name.to_ascii_lowercase())
                    .or_insert((p, reason));
            }
            None => not_inbox += 1,
        }
    }

    let (by_package, repository) = match repository_prog_ids(reg) {
        Ok(map) => (map, Ok(())),
        Err(e) => (BTreeMap::new(), Err(e)),
    };

    let packages = chosen
        .into_iter()
        .map(|(folded, (p, reason))| {
            let manifest = match p.install_location.as_deref() {
                Some(dir) if !dir.trim().is_empty() => {
                    let path = format!(r"{}\AppxManifest.xml", dir.trim_end_matches('\\'));
                    read_capped(fs, &path, MAX_APPX_MANIFEST_BYTES).and_then(|b| decode_text(&b))
                }
                _ => Err(SourceError::NotFound),
            };
            InboxPackage {
                repository_prog_ids: by_package.get(&folded).cloned().unwrap_or_default(),
                full_name: p.full_name,
                family: p.family,
                reason,
                manifest,
            }
        })
        .collect();

    Ok(InboxPackages {
        packages,
        machine_wide,
        not_inbox,
        provisioned: provisioned_list.map(|n| n.len() as u64),
        repository,
    })
}

/// The repository index as lower-cased package full name -> its generated ProgIDs.
fn repository_prog_ids(
    reg: &dyn RegistrySource,
) -> SourceResult<BTreeMap<String, Vec<RepositoryProgId>>> {
    // (package, ProgID folded) -> entry
    type Index = BTreeMap<String, BTreeMap<String, RepositoryProgId>>;
    fn entry<'m>(
        out: &'m mut Index,
        package: &str,
        prog_id: &str,
    ) -> Option<&'m mut RepositoryProgId> {
        if package.is_empty() || prog_id.is_empty() {
            return None;
        }
        Some(
            out.entry(package.to_ascii_lowercase())
                .or_default()
                .entry(prog_id.to_ascii_lowercase())
                .or_insert_with(|| RepositoryProgId {
                    prog_id: prog_id.to_owned(),
                    ..RepositoryProgId::default()
                }),
        )
    }
    let mut out = Index::new();

    let base = REPOSITORY_EXTENSIONS_KEY;
    let prog_ids_key = format!(r"{base}\ProgIDs");
    for prog_id in reg.subkeys(&prog_ids_key)? {
        for v in reg.values(&format!(r"{prog_ids_key}\{prog_id}"))? {
            entry(&mut out, &v.name, &prog_id);
        }
    }
    for (category, is_file_type) in [
        ("windows.fileTypeAssociation", true),
        ("windows.protocol", false),
    ] {
        let cat_key = format!(r"{base}\{category}");
        let names = match reg.subkeys(&cat_key) {
            Ok(n) => n,
            Err(SourceError::NotFound) => continue,
            Err(e) => return Err(e),
        };
        for name in names {
            let name_key = format!(r"{cat_key}\{name}");
            for prog_id in reg.subkeys(&name_key)? {
                for v in reg.values(&format!(r"{name_key}\{prog_id}"))? {
                    if let Some(e) = entry(&mut out, &v.name, &prog_id) {
                        let list = if is_file_type {
                            &mut e.file_types
                        } else {
                            &mut e.protocols
                        };
                        if !list.iter().any(|x| x.eq_ignore_ascii_case(&name)) {
                            list.push(name.clone());
                        }
                    }
                }
            }
        }
    }
    Ok(out
        .into_iter()
        .map(|(package, ids)| {
            let ids = ids
                .into_values()
                .map(|mut e| {
                    e.file_types.sort_by_cached_key(|s| s.to_ascii_lowercase());
                    e.protocols.sort_by_cached_key(|s| s.to_ascii_lowercase());
                    e
                })
                .collect();
            (package, ids)
        })
        .collect())
}

/// Reads a whole file of at most `max` bytes; a larger file is [`SourceError::WrongKind`].
fn read_capped(fs: &dyn FileSystemSource, path: &str, max: usize) -> SourceResult<Vec<u8>> {
    let bytes = fs.read_bytes(path, max + 1)?;
    if bytes.len() > max {
        return Err(SourceError::WrongKind);
    }
    Ok(bytes)
}

/// Manifest bytes as text: UTF-8 (BOM dropped) or UTF-16 LE/BE with a BOM. Anything else is
/// [`SourceError::WrongKind`].
pub fn decode_text(bytes: &[u8]) -> SourceResult<String> {
    let utf16 = |b: &[u8], le: bool| -> SourceResult<String> {
        if b.len() % 2 != 0 {
            return Err(SourceError::WrongKind);
        }
        let units: Vec<u16> = b
            .chunks_exact(2)
            .map(|c| {
                if le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16(&units).map_err(|_| SourceError::WrongKind)
    };
    match bytes {
        [0xEF, 0xBB, 0xBF, rest @ ..] => std::str::from_utf8(rest)
            .map(str::to_owned)
            .map_err(|_| SourceError::WrongKind),
        [0xFF, 0xFE, rest @ ..] => utf16(rest, true),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, false),
        _ => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| SourceError::WrongKind),
    }
}

fn has_suffix_ci(s: &str, suffix: &str) -> bool {
    s.len() >= suffix.len()
        && s.is_char_boundary(s.len() - suffix.len())
        && s[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(full: &str, family: &str, kind: PackageSignatureKind) -> PackageInfo {
        PackageInfo {
            full_name: full.into(),
            family: family.into(),
            install_location: None,
            external_location: None,
            sparse: false,
            users: Vec::new(),
            is_framework: false,
            is_resource: false,
            signature_kind: kind,
        }
    }

    #[test]
    fn inbox_rule() {
        let provisioned: BTreeSet<String> = [
            "microsoft.windowsnotepad_8wekyb3d8bbwe",
            "clipchamp.clipchamp_yxz26nhyzhsrt",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let system = pkg(
            "Microsoft.Windows.FileExplorer_10.0.1.0_neutral_neutral_cw5n1h2txyewy",
            "Microsoft.Windows.FileExplorer_cw5n1h2txyewy",
            PackageSignatureKind::System,
        );
        assert_eq!(
            inbox_reason(&system, &provisioned),
            Some(InboxReason::System)
        );
        let notepad = pkg(
            "Microsoft.WindowsNotepad_11.2.0.0_x64__8wekyb3d8bbwe",
            "Microsoft.WindowsNotepad_8wekyb3d8bbwe",
            PackageSignatureKind::Store,
        );
        assert_eq!(
            inbox_reason(&notepad, &provisioned),
            Some(InboxReason::MicrosoftProvisioned)
        );
        // Microsoft-published but not provisioned (installed from the Store by the user).
        let code = pkg(
            "Microsoft.VisualStudioCode_1.0.0.0_x64__8wekyb3d8bbwe",
            "Microsoft.VisualStudioCode_8wekyb3d8bbwe",
            PackageSignatureKind::Store,
        );
        assert_eq!(inbox_reason(&code, &provisioned), None);
        // Provisioned but not Microsoft-published: third-party.
        let clip = pkg(
            "Clipchamp.Clipchamp_3.0.0.0_neutral__yxz26nhyzhsrt",
            "Clipchamp.Clipchamp_yxz26nhyzhsrt",
            PackageSignatureKind::Store,
        );
        assert_eq!(inbox_reason(&clip, &provisioned), None);
        // No family given: derived from the full name.
        let mut no_family = notepad.clone();
        no_family.family.clear();
        assert_eq!(
            inbox_reason(&no_family, &provisioned),
            Some(InboxReason::MicrosoftProvisioned)
        );
    }

    #[test]
    fn names() {
        assert_eq!(
            family_of_full_name("Microsoft.549981C3F5F10_4.2308.1005.0_neutral_~_8wekyb3d8bbwe")
                .as_deref(),
            Some("microsoft.549981c3f5f10_8wekyb3d8bbwe")
        );
        assert_eq!(family_of_full_name("A_B"), None);
        assert_eq!(publisher_id("A_8WEKYB3D8BBWE").as_deref(), Some("8wekyb3d8bbwe"));
        assert_eq!(publisher_id("nounderscore"), None);
    }

    #[test]
    fn text_decoding() {
        assert_eq!(decode_text(b"\xEF\xBB\xBF<a/>").unwrap(), "<a/>");
        assert_eq!(decode_text(b"<a/>").unwrap(), "<a/>");
        let le: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("<a/>".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(decode_text(&le).unwrap(), "<a/>");
        assert_eq!(decode_text(b"\xFF\xFE\x00"), Err(SourceError::WrongKind));
        assert_eq!(decode_text(b"\xC3"), Err(SourceError::WrongKind));
    }
}
