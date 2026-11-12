//! FS-SHORTCUTS (ENGINE_PLAN.md §5.6): shortcuts in the Start Menu, on the desktops, in Quick Launch and
//! the Startup folders.
//!
//! # Where
//!
//! The user's and the all-users Start Menu (with their Startup folders), the user's and the public
//! desktop (not below them), and Quick Launch with `User Pinned\TaskBar` and `ImplicitAppShortcuts`.
//! Files ending in `.lnk`, `.url` and `.appref-ms` are looked at; reparse points are not followed.
//!
//! # The gate: where the shortcut leads
//!
//! A shortcut is the app's only when what it starts is the app's. The name of the file never decides
//! that: `Notepad.lnk` pointing at `%windir%\system32\notepad.exe` is not Notepad++'s, whatever it is
//! called. A `.lnk` is read with [`FileSystemSource::read_shortcut`] (raw path, arguments, AUMID; never
//! resolved) and passes the gate when
//!
//! - its AUMID property, or a `shell:AppsFolder\<AUMID>` target or argument, is one of the app's AUMIDs;
//! - its target lies in one of the app's install or inferred roots, or is a file of the exe set outside
//!   them that is proven gone, and is not inside another installed app's root or one of its recorded
//!   files;
//! - its target is missing and [`ScanCtx::dangling`] proves it dangling below a root's recorded parent;
//! - it starts a Squirrel stub next to an InstallRoot with `--processStart <exe>` naming a file of the
//!   exe set.
//!
//! A shortcut that leads anywhere else, or nowhere (a shell-item link), is never offered. A `.url` file
//! passes when its `URL=` is a `file:` path, or its `IconFile=` a path, that passes the same test. A
//! shortcut that cannot be read (a rig snapshot, an `.appref-ms`) is offered only when the Inno log names
//! exactly that file.
//!
//! # Evidence
//!
//! The gate decides whether a shortcut is offered; the evidence is what the framework can state about a
//! file: `InstallerManifest` when the Inno log names it (Tier A), the app's name in the file name
//! (`ExactFullName` / `NameTokenExact`) and `TimeWindow`. `PointsIntoInstallRoot` and `DanglingRef` are
//! requested too, but the §5.3 table records them for values only, so today they add nothing to a file
//! target; a shortcut that passes the gate without any other evidence is not offered. An all-users Start
//! Menu shortcut therefore needs the installer's record to get past the guard (§5.10).
//!
//! A program group directly under `Start Menu\Programs` is offered as a directory when it carries the
//! app's name or the Inno log names it, and everything in it is an offered shortcut (or `desktop.ini`).
//!
//! [`FileSystemSource::read_shortcut`]: purge_source::filesystem::FileSystemSource::read_shortcut

use purge_guard::prefix;
use purge_identity::identity::IdentityMatch;
use purge_model::{Action, Blocker, Candidate, CandidateId, Category, RootKind, Target};
use purge_source::types::FileMeta;

use crate::framework::{AppIdentityView, Dangling, RootSpec, ScanCtx, Scanner};
use crate::fs_installdir::{
    Places, clean_path, emit, expand_env, has_extension, is_plain_dir, join, list, measure, sized,
    stem,
};

/// The scanner's catalog id.
pub const ID: &str = "FS-SHORTCUTS";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[
    RootSpec::fs(r"%APPDATA%\Microsoft\Windows\Start Menu", None),
    RootSpec::fs(r"%ProgramData%\Microsoft\Windows\Start Menu", None),
    RootSpec::fs(r"%USERPROFILE%\Desktop", Some(1)),
    RootSpec::fs(r"%PROFILES%\Public\Desktop", Some(1)),
    RootSpec::fs(r"%APPDATA%\Microsoft\Internet Explorer\Quick Launch", None),
];

/// The file extensions of shortcuts.
const SHORTCUT_EXTS: &[&str] = &["lnk", "url", "appref-ms"];

/// How deep below a Start Menu or Quick Launch directory shortcuts are looked for.
const MAX_DEPTH: u32 = 6;

/// Most bytes read from a `.url` file.
const URL_FILE_MAX: usize = 64 * 1024;

/// The FS-SHORTCUTS scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsShortcuts;

impl Scanner for FsShortcuts {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, app: &AppIdentityView) -> Vec<Candidate> {
        let places = Places::of(ctx);
        let mut scan = Scan {
            ctx,
            app,
            places: &places,
            out: Vec::new(),
            offered: Vec::new(),
        };
        for (dir, recursive) in places.shortcut_dirs() {
            scan.dir(dir, if recursive { MAX_DEPTH } else { 0 });
        }
        for programs in [&places.programs, &places.common_programs]
            .into_iter()
            .flatten()
        {
            scan.groups(programs);
        }
        scan.out
    }
}

/// Where a shortcut leads, as far as the app is concerned.
enum Leads<'a> {
    /// To the app.
    Ours {
        /// The file or directory under a root it points at, when it names one.
        target: Option<String>,
        /// The proof that the target is dangling, when it is missing.
        dangling: Option<Dangling<'a>>,
    },
    /// Somewhere else, or nowhere.
    Elsewhere,
    /// The shortcut could not be read.
    Unreadable,
}

struct Scan<'a, 'c> {
    ctx: &'a ScanCtx<'c>,
    app: &'a AppIdentityView,
    places: &'a Places,
    out: Vec<Candidate>,
    /// Path and candidate id of every offered shortcut.
    offered: Vec<(String, CandidateId)>,
}

impl<'a> Scan<'a, '_> {
    /// Looks at the shortcuts in `dir` and, `depth` levels down, in its subdirectories.
    fn dir(&mut self, dir: &str, depth: u32) {
        let Some(entries) = list(self.ctx, dir) else {
            return;
        };
        for entry in &entries {
            let path = join(dir, &entry.name);
            if is_plain_dir(&entry.meta) {
                if depth > 0 {
                    self.dir(&path, depth - 1);
                }
            } else if !entry.meta.is_dir()
                && !entry.meta.is_reparse_point()
                && has_extension(&entry.name, SHORTCUT_EXTS)
            {
                self.shortcut(&path, &entry.name, &entry.meta);
            }
        }
    }

    /// Offers one shortcut file when it leads to the app.
    fn shortcut(&mut self, path: &str, name: &str, meta: &FileMeta) {
        let ctx = self.ctx;
        let leads = if has_extension(name, &["lnk"]) {
            self.lnk(path)
        } else if has_extension(name, &["url"]) {
            self.url(path)
        } else {
            Leads::Unreadable
        };
        if matches!(leads, Leads::Elsewhere) {
            return;
        }
        let category = if self.places.in_startup(path) {
            Category::Startup
        } else {
            Category::AppFiles
        };
        let mut b = ctx.candidate(
            ID,
            Target::Path {
                path: path.to_owned(),
            },
            Action::Quarantine,
            category,
        );
        let declared = b.installer_manifest();
        match &leads {
            Leads::Ours { target, dangling } => {
                if let Some(dangling) = dangling {
                    b.dangling_ref(dangling);
                } else if let Some(target) = target {
                    b.points_into_install_root(target);
                }
            }
            // Unknown target: only the installer's own record makes it the app's.
            Leads::Unreadable if declared => {}
            Leads::Unreadable | Leads::Elsewhere => return,
        }
        for m in self.name_matches(stem(name)) {
            b.name_match(&m);
        }
        if let Some(when) = meta.times.created.or(meta.times.modified) {
            b.time_window(when);
        }
        if !b.has_positive_evidence() {
            return;
        }
        b.common_blockers();
        sized(&mut b, &measure(ctx, path, meta));
        if emit(&mut self.out, b)
            && let Some(candidate) = self.out.last()
        {
            self.offered.push((path.to_owned(), candidate.id.clone()));
        }
    }

    /// Where a `.lnk` leads.
    fn lnk(&self, path: &str) -> Leads<'a> {
        let ctx: &'a ScanCtx<'_> = self.ctx;
        let Ok(info) = ctx.fs.read_shortcut(path) else {
            return Leads::Unreadable;
        };
        let ours = |aumid: &str| {
            ctx.fp
                .anchors
                .aumids
                .iter()
                .any(|a| prefix::eq_ci(a, aumid))
        };
        if info.aumid.as_deref().is_some_and(ours) {
            return Leads::Ours {
                target: None,
                dangling: None,
            };
        }
        // `shell:AppsFolder\<AUMID>`, as the target or as an argument of explorer.exe.
        let shell_aumid = [&info.raw_path, &info.args]
            .into_iter()
            .flatten()
            .find_map(|text| apps_folder_aumid(text));
        if let Some(aumid) = shell_aumid {
            return if ours(&aumid) {
                Leads::Ours {
                    target: None,
                    dangling: None,
                }
            } else {
                Leads::Elsewhere
            };
        }
        match info.raw_path.as_deref().and_then(|raw| self.resolve(raw)) {
            Some(target) => self.target(&target, info.args.as_deref()),
            None => Leads::Elsewhere,
        }
    }

    /// Where a `.url` file leads: its `URL=` when that is a local file, else its `IconFile=`.
    fn url(&self, path: &str) -> Leads<'a> {
        let Ok(bytes) = self.ctx.fs.read_bytes(path, URL_FILE_MAX) else {
            return Leads::Unreadable;
        };
        let text = String::from_utf8_lossy(&bytes);
        let (url, icon) = url_file_fields(&text);
        let local = url
            .as_deref()
            .and_then(file_url_path)
            .and_then(|p| self.resolve(&p));
        if let Some(target) = local {
            return self.target(&target, None);
        }
        match icon.as_deref().and_then(|p| self.resolve(p)) {
            Some(target) => self.target(&target, None),
            None => Leads::Elsewhere,
        }
    }

    /// A raw shortcut path with the interactive user's environment expanded, as an absolute path.
    fn resolve(&self, raw: &str) -> Option<String> {
        clean_path(&expand_env(raw, self.ctx.env))
    }

    /// Whether `target` (an absolute path) is the app's.
    fn target(&self, target: &str, args: Option<&str>) -> Leads<'a> {
        let ctx: &'a ScanCtx<'_> = self.ctx;
        // What the shortcut starts is another installed app's (a newer version installed into the same
        // directory under another ARP entry, a stale root): not this app's leftover.
        if self.foreign(target) {
            return Leads::Elsewhere;
        }
        let in_root = ctx.fp.roots.iter().any(|r| {
            r.kind != RootKind::ReferencedDataDir && prefix::is_same_or_inside(target, &r.path)
        });
        // A file of the app outside its roots (`py.exe` in `C:\Windows`) only counts once it is proven
        // gone: a target that exists outside the roots never passes the gate (§5.2: such files serve
        // dangling detection only).
        let app_file_gone =
            !in_root && ctx.is_app_file(target) && ctx.fs.exists(target).is_absent();
        if in_root || app_file_gone {
            return Leads::Ours {
                dangling: ctx.dangling(target),
                target: Some(target.to_owned()),
            };
        }
        // Squirrel: `<dir>\Update.exe --processStart App.exe`, the app living in `<dir>\app-<version>`.
        let stub_dir = prefix::parent(target);
        let started = args.and_then(process_start).and_then(|exe| {
            ctx.fp.exes.iter().find(|e| {
                prefix::leaf(&e.path).is_some_and(|name| prefix::eq_ci(name, &exe))
                    && stub_dir.is_some_and(|dir| prefix::is_inside(&e.path, dir))
                    && ctx.inside_install_root(&e.path).is_some()
                    && !self.foreign(&e.path)
            })
        });
        match started {
            Some(exe) => Leads::Ours {
                target: Some(exe.path.clone()),
                dangling: None,
            },
            None => Leads::Elsewhere,
        }
    }

    /// Whether `path` is inside another installed app's root or is a file its records point at.
    fn foreign(&self, path: &str) -> bool {
        self.ctx.other_apps.path_blockers(path).iter().any(|b| {
            matches!(
                b,
                Blocker::InsideOtherApp { .. } | Blocker::ReferencedByOtherApp { .. }
            )
        })
    }

    /// The identity match of a shortcut or group name: the full name when it is one, otherwise a
    /// whole-token match.
    fn name_matches(&self, name: &str) -> Vec<IdentityMatch> {
        let identity = &self.app.identity;
        identity
            .matches_full_name(name)
            .or_else(|| identity.matches_name(name))
            .into_iter()
            .collect()
    }

    /// Offers the program groups directly under a `Start Menu\Programs` directory.
    fn groups(&mut self, programs: &str) {
        let Some(entries) = list(self.ctx, programs) else {
            return;
        };
        for entry in &entries {
            let path = join(programs, &entry.name);
            if is_plain_dir(&entry.meta) && !self.places.in_startup(&path) {
                self.group(&path, &entry.name, &entry.meta);
            }
        }
    }

    /// Offers one program group when it is the app's and holds nothing but offered shortcuts.
    fn group(&mut self, path: &str, name: &str, meta: &FileMeta) {
        let ctx = self.ctx;
        let identity = &self.app.identity;
        // A vendor's folder is FS-VENDORPARENT's (delete-if-empty), unless it is the app's name too.
        if identity.matches_vendor(name).is_some() && identity.matches_full_name(name).is_none() {
            return;
        }
        let Some(files) = files_below(ctx, path, MAX_DEPTH) else {
            return;
        };
        let mut children = Vec::new();
        for file in &files {
            match self
                .offered
                .iter()
                .find(|(offered, _)| prefix::is_same(offered, file))
            {
                Some((_, id)) => children.push(id.clone()),
                None if prefix::leaf(file)
                    .is_some_and(|n| n.eq_ignore_ascii_case("desktop.ini")) => {}
                None => return,
            }
        }
        let mut b = ctx.candidate(
            ID,
            Target::Path {
                path: path.to_owned(),
            },
            Action::Quarantine,
            Category::AppFiles,
        );
        b.installer_manifest();
        for m in self.name_matches(name) {
            b.name_match(&m);
        }
        if !b.has_positive_evidence() {
            return;
        }
        for id in children {
            b.child(id);
        }
        b.common_blockers();
        sized(&mut b, &measure(ctx, path, meta));
        emit(&mut self.out, b);
    }
}

/// Every file at or below `dir`, or `None` when the tree could not be read completely or is deeper than
/// `depth` levels. Reparse points count as files.
fn files_below(ctx: &ScanCtx<'_>, dir: &str, depth: u32) -> Option<Vec<String>> {
    let mut files = Vec::new();
    for entry in list(ctx, dir)? {
        let path = join(dir, &entry.name);
        if is_plain_dir(&entry.meta) {
            if depth == 0 {
                return None;
            }
            files.extend(files_below(ctx, &path, depth - 1)?);
        } else {
            files.push(path);
        }
    }
    Some(files)
}

/// The AUMID of a `shell:AppsFolder\<AUMID>` reference in a shortcut target or argument string.
fn apps_folder_aumid(text: &str) -> Option<String> {
    const MARK: &str = r"shell:appsfolder\";
    let at = text.to_ascii_lowercase().find(MARK)?;
    let quoted = text[..at].ends_with('"');
    let rest = &text[at + MARK.len()..];
    let end = rest
        .find(|c: char| c == '"' || (!quoted && c.is_whitespace()))
        .unwrap_or(rest.len());
    let aumid = rest[..end].trim();
    (!aumid.is_empty()).then(|| aumid.to_owned())
}

/// The exe name after `--processStart` in a Squirrel stub's arguments.
fn process_start(args: &str) -> Option<String> {
    const FLAG: &str = "--processstart";
    let at = args.to_ascii_lowercase().find(FLAG)?;
    let rest = args[at + FLAG.len()..].trim_start_matches(['=', ' ', '\t']);
    let name = match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or(""),
        None => rest.split_whitespace().next().unwrap_or(""),
    };
    (!name.is_empty()).then(|| name.to_owned())
}

/// The `URL=` and `IconFile=` values of an Internet shortcut (`.url`, an INI file).
fn url_file_fields(text: &str) -> (Option<String>, Option<String>) {
    let (mut url, mut icon) = (None, None);
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let slot = match key.trim().trim_start_matches('\u{feff}') {
            k if k.eq_ignore_ascii_case("URL") => &mut url,
            k if k.eq_ignore_ascii_case("IconFile") => &mut icon,
            _ => continue,
        };
        if slot.is_none() && !value.is_empty() {
            *slot = Some(value.to_owned());
        }
    }
    (url, icon)
}

/// The local path of a `file:` URL (`file:///C:/Program%20Files/App/x.htm`); `None` for any other URL
/// and for a `file:` URL that names a host.
fn file_url_path(url: &str) -> Option<String> {
    let scheme = url.get(..5)?;
    if !scheme.eq_ignore_ascii_case("file:") {
        return None;
    }
    let rest = &url[5..];
    let path = match rest.strip_prefix("//") {
        // `file:///C:/x`: an empty host. `file://host/share` is not local.
        Some(with_host) => with_host.strip_prefix('/')?,
        None => rest.trim_start_matches('/'),
    };
    let path = path.split(['?', '#']).next().unwrap_or(path);
    Some(percent_decode(path).replace('/', "\\"))
}

/// Decodes `%XX` escapes; a malformed escape is kept as written.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| char::from(b).to_digit(16);
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push(u8::try_from(hi * 16 + lo).unwrap_or(b'?'));
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apps_folder_references() {
        assert_eq!(
            apps_folder_aumid(r"shell:AppsFolder\Mozilla.Firefox.308046B0AF4A39CB").as_deref(),
            Some("Mozilla.Firefox.308046B0AF4A39CB")
        );
        assert_eq!(
            apps_folder_aumid(r"shell:appsfolder\Vendor.App!Main --flag").as_deref(),
            Some("Vendor.App!Main")
        );
        assert_eq!(
            apps_folder_aumid(r#""shell:AppsFolder\Vendor App!Main" --flag"#).as_deref(),
            Some("Vendor App!Main")
        );
        assert_eq!(apps_folder_aumid(r"shell:AppsFolder\"), None);
        assert_eq!(apps_folder_aumid(r"C:\Windows\explorer.exe"), None);
    }

    #[test]
    fn squirrel_process_start() {
        assert_eq!(
            process_start("--processStart App.exe").as_deref(),
            Some("App.exe")
        );
        assert_eq!(
            process_start(r#"--processStart "My App.exe" --process-start-args "x""#).as_deref(),
            Some("My App.exe")
        );
        assert_eq!(
            process_start("--ProcessStart=App.exe").as_deref(),
            Some("App.exe")
        );
        assert_eq!(process_start("--processStart"), None);
        assert_eq!(process_start("--other App.exe"), None);
    }

    #[test]
    fn url_files() {
        let text = "[InternetShortcut]\r\nURL=file:///C:/Program%20Files/App/readme.htm\r\n\
                    IconFile=C:\\Program Files\\App\\app.ico\r\nIconIndex=0\r\n";
        let (url, icon) = url_file_fields(text);
        assert_eq!(
            url.as_deref(),
            Some("file:///C:/Program%20Files/App/readme.htm")
        );
        assert_eq!(icon.as_deref(), Some(r"C:\Program Files\App\app.ico"));
        assert_eq!(
            file_url_path(url.as_deref().unwrap()).as_deref(),
            Some(r"C:\Program Files\App\readme.htm")
        );
        assert_eq!(
            file_url_path("FILE:C:/x/y.htm#top").as_deref(),
            Some(r"C:\x\y.htm")
        );
        assert_eq!(file_url_path("file://server/share/x.htm"), None);
        assert_eq!(file_url_path("https://example.org/"), None);
        assert_eq!(file_url_path("fil"), None);
        assert_eq!(url_file_fields("no ini here"), (None, None));
        assert_eq!(percent_decode("a%20b%2"), "a b%2");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }
}
