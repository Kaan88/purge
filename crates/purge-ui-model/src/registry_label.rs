//! A registry candidate in words (the port of `ui/Purge.Client/Model/RegistryLabel.cs`): what the key or
//! value is ([`RegistryLabel::title`]) and where it lives ([`RegistryLabel::location`]). Display only:
//! the raw wire path stays the authority (the consent prompt, the tooltip and the detail pane show it
//! unchanged).
//!
//! The Leftovers page's rows use it; it lives at the crate root so every model can.

use purge_rpc::methods::ItemKind;

use crate::casefold::{eq_ignore_case, starts_with_ignore_case, to_upper_invariant};

/// The breadcrumb separator.
const SEP: &str = " \u{203A} ";

/// A registry path described for people.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryLabel {
    /// What the key or value is.
    pub title: String,
    /// Where it lives, as a breadcrumb.
    pub location: String,
}

impl RegistryLabel {
    /// Describes a canonical wire path (`HKLM\SOFTWARE\...`, `HKU\<SID>\...`, `HKU\<SID>_Classes\...`; a
    /// value is `key\name` or `key\(Default)`). `None` for a non-registry kind or a path whose root it does
    /// not know, so the caller keeps showing the raw path.
    pub fn describe(path: &str, kind: ItemKind, current_user_sid: Option<&str>) -> Option<Self> {
        if !matches!(
            kind,
            ItemKind::RegistryKey | ItemKind::RegistryValue | ItemKind::RegistryData
        ) {
            return None;
        }
        if path.trim().is_empty() {
            return None;
        }
        let segments: Vec<String> = path
            .trim_end_matches('\\')
            .split('\\')
            .map(str::to_owned)
            .collect();
        let hive = try_hive(&segments, current_user_sid)?;

        let is_value = kind != ItemKind::RegistryKey;
        let mut key = hive.rest.clone();
        let mut value = None;
        if is_value && !key.is_empty() {
            let (k, v) = split_value(&key);
            key = k;
            value = Some(v);
        }

        let mut label = recognise(&hive, &key, value.as_deref(), is_value);
        if kind == ItemKind::RegistryData {
            label.title.push_str(" (one entry)");
        }
        Some(label)
    }
}

// ---- Hive -----------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Branch {
    Software,
    Classes,
    System,
    Other,
}

struct Hive {
    scope: String,
    bits32: bool,
    branch: Branch,
    rest: Vec<String>,
}

impl Hive {
    fn scope_text(&self) -> String {
        if self.bits32 {
            format!("{} (32-bit)", self.scope)
        } else {
            self.scope.clone()
        }
    }
}

fn try_hive(segs: &[String], current_user_sid: Option<&str>) -> Option<Hive> {
    let root = segs[0].as_str();
    let mut rest: Vec<String> = segs[1..].to_vec();
    let scope: String;
    let mut classes_root = false;
    if is(root, "HKLM") || is(root, "HKEY_LOCAL_MACHINE") {
        scope = "All users".into();
    } else if is(root, "HKCU") || is(root, "HKEY_CURRENT_USER") {
        scope = "Your account".into();
    } else if is(root, "HKCR") || is(root, "HKEY_CLASSES_ROOT") {
        scope = "All users".into();
        classes_root = true;
    } else if is(root, "HKU") || is(root, "HKEY_USERS") {
        if rest.first().is_none_or(String::is_empty) {
            return None;
        }
        let mut sid = rest.remove(0);
        const CLASSES: &str = "_Classes";
        if sid.len() >= CLASSES.len()
            && sid.is_char_boundary(sid.len() - CLASSES.len())
            && is(&sid[sid.len() - CLASSES.len()..], CLASSES)
        {
            sid.truncate(sid.len() - CLASSES.len());
            classes_root = true;
        }
        scope = account_name(&sid, current_user_sid).into();
    } else {
        return None;
    }

    let mut bits32 = false;
    let mut branch;
    if classes_root {
        branch = Branch::Classes;
    } else if at(&rest, 0, "SOFTWARE") {
        rest.remove(0);
        branch = Branch::Software;
        if at(&rest, 0, "WOW6432Node") {
            bits32 = true;
            rest.remove(0);
        }
        if at(&rest, 0, "Classes") {
            rest.remove(0);
            branch = Branch::Classes;
        }
    } else if at(&rest, 0, "SYSTEM") && scope == "All users" {
        rest.remove(0);
        branch = Branch::System;
    } else {
        branch = Branch::Other;
    }
    if branch == Branch::Classes && at(&rest, 0, "WOW6432Node") {
        bits32 = true;
        rest.remove(0);
    }
    Some(Hive {
        scope,
        bits32,
        branch,
        rest,
    })
}

fn account_name(sid: &str, current_user_sid: Option<&str>) -> &'static str {
    if let Some(me) = current_user_sid.filter(|s| !s.is_empty())
        && is(sid, me)
    {
        return "Your account";
    }
    match to_upper_invariant(sid).as_str() {
        "S-1-5-18" => "System account",
        "S-1-5-19" => "Local service account",
        "S-1-5-20" => "Network service account",
        ".DEFAULT" => "Default account",
        _ => "Another account",
    }
}

// ---- Value name -----------------------------------------------------------------------------------

/// Splits a value's display path into key segments and the value name. A value name may hold `\`
/// (SharedDLLs and compatibility values are file paths), so a known key or a drive letter marks the start.
fn split_value(segs: &[String]) -> (Vec<String>, String) {
    for i in 0..segs.len().saturating_sub(1) {
        let s = segs[i].as_str();
        let prev_is = |name: &str| i > 0 && is(&segs[i - 1], name);
        let path_valued = is(s, "SharedDLLs")
            || is(s, "MuiCache")
            || (is(s, "Folders") && prev_is("Installer"))
            || (is(s, "Layers") && prev_is("AppCompatFlags"))
            || (is(s, "Store") && prev_is("Compatibility Assistant"));
        if path_valued {
            return (segs[..=i].to_vec(), segs[i + 1..].join("\\"));
        }
    }
    for i in 1..segs.len() {
        if is_drive(&segs[i]) {
            return (segs[..i].to_vec(), segs[i..].join("\\"));
        }
    }
    let last = segs.len() - 1;
    (segs[..last].to_vec(), segs[last].clone())
}

/// `^[A-Za-z]:$`.
fn is_drive(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

// ---- Patterns -------------------------------------------------------------------------------------

struct Hit {
    title: String,
    location: String,
    consumed: bool,
}

fn hit(title: impl Into<String>, location: impl Into<String>) -> Hit {
    Hit {
        title: title.into(),
        location: location.into(),
        consumed: false,
    }
}

fn consumed(title: impl Into<String>, location: impl Into<String>) -> Hit {
    Hit {
        title: title.into(),
        location: location.into(),
        consumed: true,
    }
}

fn recognise(hive: &Hive, key: &[String], value: Option<&str>, is_value: bool) -> RegistryLabel {
    let found = match hive.branch {
        Branch::Software => software(hive, key, value),
        Branch::Classes => classes(hive, key, value),
        Branch::System => system_branch(hive, key),
        Branch::Other => None,
    };
    if let Some(hit) = found {
        let title = if hit.consumed || !is_value {
            hit.title
        } else {
            with_value(&hit.title, value)
        };
        return RegistryLabel {
            title,
            location: hit.location,
        };
    }

    // Fallback: the key's last segment, and the readable breadcrumb.
    let crumbs = crumbs(hive, key);
    let last = match key.last() {
        Some(last) => last.clone(),
        None => branch_name(hive.branch)
            .map(str::to_owned)
            .unwrap_or_else(|| hive.scope_text()),
    };
    RegistryLabel {
        title: if is_value {
            with_value(&last, value)
        } else {
            last
        },
        location: crumbs.join(SEP),
    }
}

fn is_default(value: Option<&str>) -> bool {
    value.is_none_or(|v| v.is_empty() || is(v, "(Default)"))
}

fn with_value(title: &str, value: Option<&str>) -> String {
    match value {
        Some(v) if !is_default(value) => format!("{title}: value {v}"),
        _ => format!("{title}: default value"),
    }
}

fn value_text(value: Option<&str>) -> String {
    match value {
        Some(v) if !is_default(value) => v.to_owned(),
        _ => "default value".into(),
    }
}

fn software(hive: &Hive, k: &[String], value: Option<&str>) -> Option<Hit> {
    let scope = hive.scope_text();
    if k.is_empty() {
        return None;
    }

    // Microsoft\Windows\CurrentVersion\...
    if at(k, 0, "Microsoft") && at(k, 1, "Windows") && at(k, 2, "CurrentVersion") && k.len() > 3 {
        let below = &k[3..];
        if is(&below[0], "Uninstall") {
            return Some(if below.len() > 1 {
                hit(
                    format!("Uninstall entry for {}{}", below[1], tail(below, 2)),
                    format!("{scope}{SEP}Installed programs list"),
                )
            } else {
                hit("Installed programs list", scope)
            });
        }
        if below.len() == 1 && is_run_key(&below[0]) {
            return Some(run_hit(&below[0], value, &scope));
        }
        if below.len() == 3
            && at(below, 0, "Policies")
            && at(below, 1, "Explorer")
            && at(below, 2, "Run")
        {
            return Some(run_hit("Run", value, &scope));
        }
        if below.len() == 3
            && at(below, 0, "Explorer")
            && at(below, 1, "StartupApproved")
            && value.is_some()
        {
            return Some(consumed(
                format!("Startup on/off switch: {}", value_text(value)),
                format!("{scope}{SEP}Startup apps"),
            ));
        }
        if is(&below[0], "App Paths") && below.len() > 1 {
            return Some(hit(
                format!("App path for {}{}", below[1], tail(below, 2)),
                format!("{scope}{SEP}App paths"),
            ));
        }
        if is(&below[0], "SharedDLLs") && below.len() == 1 {
            return Some(match value {
                None => hit("Shared DLL counts", scope),
                Some(v) => consumed(
                    format!("Shared DLL count: {v}"),
                    format!("{scope}{SEP}Shared DLL counts"),
                ),
            });
        }
        if is(&below[0], "Installer") {
            return installer(&scope, &below[1..], value);
        }
    }
    if at(k, 0, "Microsoft") && at(k, 1, "Installer") {
        return installer(&scope, &k[2..], value);
    }

    // Microsoft\Windows NT\CurrentVersion\AppCompatFlags\...
    if at(k, 0, "Microsoft")
        && at(k, 1, "Windows NT")
        && at(k, 2, "CurrentVersion")
        && at(k, 3, "AppCompatFlags")
        && value.is_some()
    {
        if k.len() == 5 && at(k, 4, "Layers") {
            return Some(consumed(
                format!("Compatibility setting: {}", value_text(value)),
                format!("{scope}{SEP}Compatibility settings"),
            ));
        }
        if k.len() == 6 && at(k, 4, "Compatibility Assistant") && at(k, 5, "Store") {
            return Some(consumed(
                format!("Compatibility record: {}", value_text(value)),
                format!("{scope}{SEP}Compatibility settings"),
            ));
        }
    }

    if is(&k[0], "RegisteredApplications") && k.len() == 1 && value.is_some() {
        return Some(consumed(
            format!("Default apps entry: {}", value_text(value)),
            format!("{scope}{SEP}Default apps"),
        ));
    }
    if is(&k[0], "Clients") && k.len() > 2 {
        return Some(hit(
            format!("Default app registration: {}{}", k[2], tail(k, 3)),
            format!("{scope}{SEP}Default apps{SEP}{}", k[1]),
        ));
    }

    // Software\<Vendor>\<Product>: the app's own settings.
    if is_vendor(k) {
        let vendor = &k[0];
        let name = if k.len() > 1 {
            if starts_with_ignore_case(&k[1], vendor) {
                k[1].clone()
            } else {
                format!("{vendor} {}", k[1])
            }
        } else {
            vendor.clone()
        };
        return Some(match value {
            None => hit(
                format!("Settings of {name}{}", tail(k, 2)),
                format!("{scope}{SEP}Software"),
            ),
            Some(_) => consumed(
                format!("{name} setting: {}", value_text(value)),
                format!("{scope}{SEP}Software{SEP}{name}{}", tail(k, 2)),
            ),
        });
    }
    None
}

fn is_run_key(s: &str) -> bool {
    [
        "Run",
        "RunOnce",
        "RunOnceEx",
        "RunServices",
        "RunServicesOnce",
    ]
    .iter()
    .any(|n| is(s, n))
}

fn run_hit(run_key: &str, value: Option<&str>, scope: &str) -> Hit {
    let once = to_upper_invariant(run_key).contains("ONCE");
    if value.is_none() {
        return hit(
            if once {
                "Run-once list"
            } else {
                "Startup list"
            },
            scope,
        );
    }
    consumed(
        format!(
            "{}{}",
            if once {
                "Runs once at next start: "
            } else {
                "Starts with Windows: "
            },
            value_text(value)
        ),
        format!("{scope}{SEP}Startup apps"),
    )
}

const NOT_VENDORS: [&str; 6] = [
    "Classes",
    "Policies",
    "Clients",
    "RegisteredApplications",
    "WOW6432Node",
    "Wow6432Node",
];

fn is_vendor(k: &[String]) -> bool {
    if NOT_VENDORS.iter().any(|n| is(n, &k[0])) {
        return false;
    }
    if is(&k[0], "Microsoft") && k.len() > 1 && (is(&k[1], "Windows") || is(&k[1], "Windows NT")) {
        return false;
    }
    true
}

fn installer(scope: &str, k: &[String], value: Option<&str>) -> Option<Hit> {
    let location = format!("{scope}{SEP}Windows Installer");
    let k = if k.len() > 1 && is(&k[0], "UserData") {
        &k[2..]
    } else {
        k
    };
    if k.is_empty() {
        return Some(hit("Windows Installer records", scope));
    }
    if is(&k[0], "Folders") && k.len() == 1 {
        return Some(match value {
            None => hit("Windows Installer folder records", location),
            Some(v) => consumed(format!("Windows Installer folder record: {v}"), location),
        });
    }
    let what = match to_upper_invariant(&k[0]).as_str() {
        "PRODUCTS" => Some("Windows Installer product record"),
        "FEATURES" => Some("Windows Installer feature record"),
        "COMPONENTS" => Some("Windows Installer component record"),
        "UPGRADECODES" => Some("Windows Installer upgrade code"),
        "PATCHES" => Some("Windows Installer patch record"),
        "DEPENDENCIES" => Some("Installer dependency record"),
        _ => None,
    };
    let Some(what) = what else {
        return Some(hit(
            format!("Windows Installer record: {}", k.join(SEP)),
            location,
        ));
    };
    Some(hit(
        if k.len() > 1 {
            format!("{what} {}{}", k[1], tail(k, 2))
        } else {
            format!("{what}s")
        },
        location,
    ))
}

const MENU_ROOTS: [&str; 6] = [
    "*",
    "Directory",
    "Folder",
    "Drive",
    "AllFilesystemObjects",
    "DesktopBackground",
];

fn classes(hive: &Hive, k: &[String], value: Option<&str>) -> Option<Hit> {
    let scope = hive.scope_text();
    let location = format!("{scope}{SEP}File types & COM");
    if k.is_empty() {
        return Some(hit("File types & COM", scope));
    }
    let head = k[0].as_str();

    if is(head, "CLSID") && k.len() > 1 {
        let title = format!("COM component {}", k[1]);
        if k.len() > 2 && is(&k[2], "InprocServer32") {
            return Some(hit(
                format!("{title}: DLL location{}", tail(k, 3)),
                location,
            ));
        }
        if k.len() > 2 && is(&k[2], "LocalServer32") {
            return Some(hit(
                format!("{title}: program location{}", tail(k, 3)),
                location,
            ));
        }
        return Some(hit(format!("{title}{}", tail(k, 2)), location));
    }
    if is(head, "TypeLib") && k.len() > 1 {
        return Some(hit(
            format!("COM type library {}{}", k[1], tail(k, 2)),
            location,
        ));
    }
    if is(head, "Interface") && k.len() > 1 {
        return Some(hit(
            format!("COM interface {}{}", k[1], tail(k, 2)),
            location,
        ));
    }
    if is(head, "AppID") && k.len() > 1 {
        return Some(hit(format!("COM app ID {}{}", k[1], tail(k, 2)), location));
    }
    if is(head, "Installer") {
        return installer(&scope, &k[1..], value);
    }
    if is(head, "Applications") && k.len() > 1 {
        return Some(hit(
            format!("Open with entry for {}{}", k[1], tail(k, 2)),
            location,
        ));
    }
    if is(head, "Local Settings") {
        if is(&k[k.len() - 1], "MuiCache") && value.is_some() {
            return Some(consumed(
                format!("App name cache: {}", value_text(value)),
                location,
            ));
        }
        return None;
    }

    // Right-click menus: *\shell\X, Directory\Background\shell\X, SystemFileAssociations\.ext\shell\X, ...
    let mut menu_at = 0;
    if MENU_ROOTS.iter().any(|r| is(r, head)) {
        menu_at = if at(k, 1, "Background") { 2 } else { 1 };
    } else if is(head, "SystemFileAssociations") && k.len() > 2 {
        menu_at = 2;
    }
    if menu_at > 0 && k.len() > menu_at {
        if is(&k[menu_at], "shell") && k.len() > menu_at + 1 {
            return Some(hit(
                format!(
                    "Right-click menu entry: {}{}",
                    k[menu_at + 1],
                    tail(k, menu_at + 2)
                ),
                format!("{location}{SEP}{}", menu_on(k, menu_at)),
            ));
        }
        if is(&k[menu_at], "shellex") && k.len() > menu_at + 2 {
            return Some(hit(
                format!(
                    "Right-click menu handler: {}{}",
                    k[menu_at + 2],
                    tail(k, menu_at + 3)
                ),
                format!("{location}{SEP}{}", menu_on(k, menu_at)),
            ));
        }
    }

    if head.starts_with('.') && head.chars().count() > 1 {
        return Some(hit(format!("File type {head}{}", tail(k, 1)), location));
    }
    Some(hit(
        format!("File type handler: {head}{}", tail(k, 1)),
        location,
    ))
}

fn menu_on(k: &[String], menu_at: usize) -> String {
    let head = k[0].as_str();
    if is(head, "SystemFileAssociations") {
        return format!("{} files", k[1]);
    }
    if menu_at == 2 {
        return if is(head, "Directory") {
            "Folder background".into()
        } else {
            format!("{head} background")
        };
    }
    if head == "*" {
        "All files".into()
    } else if is(head, "Directory") || is(head, "Folder") {
        "Folders".into()
    } else if is(head, "Drive") {
        "Drives".into()
    } else if is(head, "DesktopBackground") {
        "Desktop".into()
    } else {
        "Files and folders".into()
    }
}

fn system_branch(hive: &Hive, k: &[String]) -> Option<Hit> {
    if k.len() < 3 {
        return None;
    }
    if !(is(&k[0], "CurrentControlSet") || is_control_set(&k[0])) || !is(&k[1], "Services") {
        return None;
    }
    let location = format!("{}{SEP}Services", hive.scope_text());
    if is(&k[2], "EventLog") && k.len() > 4 {
        return Some(hit(
            format!("Event log source: {}{}", k[4], tail(k, 5)),
            location,
        ));
    }
    Some(hit(format!("Service {}{}", k[2], tail(k, 3)), location))
}

/// `^ControlSet[0-9]+$`, not case sensitive.
fn is_control_set(s: &str) -> bool {
    const PREFIX: &str = "ControlSet";
    s.len() > PREFIX.len()
        && s.is_char_boundary(PREFIX.len())
        && is(&s[..PREFIX.len()], PREFIX)
        && s[PREFIX.len()..].bytes().all(|b| b.is_ascii_digit())
}

// ---- Breadcrumbs ----------------------------------------------------------------------------------

fn branch_name(branch: Branch) -> Option<&'static str> {
    match branch {
        Branch::Software => Some("Software"),
        Branch::Classes => Some("File types & COM"),
        Branch::System => Some("System"),
        Branch::Other => None,
    }
}

fn crumbs(hive: &Hive, key: &[String]) -> Vec<String> {
    let mut crumbs = vec![hive.scope_text()];
    if let Some(branch) = branch_name(hive.branch) {
        crumbs.push(branch.into());
    }
    let mut i = 0;
    if at(key, 0, "Microsoft")
        && (at(key, 1, "Windows") || at(key, 1, "Windows NT"))
        && at(key, 2, "CurrentVersion")
    {
        crumbs.push("Windows".into());
        i = 3;
    }
    crumbs.extend(key.iter().skip(i).cloned());
    crumbs
}

/// The segments from `from` on, as " › a › b" (empty when there are none).
fn tail(k: &[String], from: usize) -> String {
    if from >= k.len() {
        String::new()
    } else {
        format!("{SEP}{}", k[from..].join(SEP))
    }
}

fn at(k: &[String], i: usize, s: &str) -> bool {
    k.get(i).is_some_and(|x| is(x, s))
}

fn is(a: &str, b: &str) -> bool {
    eq_ignore_case(a, b)
}

#[cfg(test)]
mod tests;
