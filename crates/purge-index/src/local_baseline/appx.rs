//! Source S4: inbox package manifests (`AppxManifest.xml`) and the package repository's generated
//! ProgIDs to baseline records under the Classes roots (BASELINE_LOCAL_DESIGN.md §3.1 S4).
//!
//! Declarations read (elements matched by local name, any namespace prefix):
//!
//! | Declaration | Records |
//! |---|---|
//! | `FileTypeAssociation` / `FileType` `.ext` | `<C>\.ext`, `<C>\.ext\OpenWithProgids` for both Classes roots |
//! | `Protocol Name="scheme"` (category `windows.protocol`) | `<C>\scheme` for both Classes roots |
//! | `comServer`: `Class Id`, its `ProgId` / `VersionIndependentProgId` attributes, `ProgId Id [Clsid]` | `HKLM\SOFTWARE\Classes\CLSID\{id}`, `…\Classes\<ProgId>[\CLSID]`, and the packaged-COM catalog `…\Classes\PackagedCom\ClassIndex\{id}\<full name>`, `…\ProgIdIndex\<ProgId>\<full name>`, `…\Package\<full name>\Class\{id}`, `…\Package\<full name>\Server` |
//! | `comInterface`: `Interface Id`, `ProxyStub Id`, `ProxyStubClsid`, `TypeLib Id` | `…\Classes\Interface\{id}`, `…\PackagedCom\InterfaceIndex\{id}\<full name>`, `…\Package\<full name>\Interface\{id}`; proxy stubs as classes; `…\Classes\TypeLib\{id}`, `…\PackagedCom\TypeLibIndex\{id}\<full name>` |
//! | repository ProgID `AppX…` (from [`RepositoryProgId`]) | `<U>\AppX…` with `Application`, `DefaultIcon`, `Shell`, `Shell\open`, `Shell\open\command`, and `Shell\<verb>\command` for each `Verb` of a file type it serves; `V <U>\.ext\OpenWithProgids AppX…`; `<U>\scheme` |
//!
//! `<C>` is `HKLM\SOFTWARE\Classes` and the user classes root `<U>` = `HKU\S-1-5-21-0-0-0-1000_Classes`
//! (the normaliser turns it into `<sid>_Classes`). Package registrations are per user (Windows writes the
//! generated ProgIDs and `OpenWithProgids` values into each user's classes hive) and packaged COM is
//! catalogued machine-wide under `PackagedCom`; recording the declared names under both Classes roots
//! over-states presence, which is the safe side (L1).
//!
//! A name that cannot be a key segment (empty, longer than 255, with `\` or a control character) and an
//! id that is not a GUID are skipped and counted. A manifest that is not well-formed XML is an error for
//! that package and adds no record. Third-party packages never reach this module (the source drops
//! them).

use std::collections::BTreeSet;
use std::fmt;

use purge_source::local_baseline::{InboxPackages, InboxReason, LocalSources, RepositoryProgId};
use purge_source::types::SourceResult;

use super::Records;
use super::hive::{DEFAULT_PROFILE_SID, record_count};

/// The machine Classes root.
pub const MACHINE_CLASSES: &str = r"HKLM\SOFTWARE\Classes";
/// The user Classes root the records use.
pub const USER_CLASSES: &str = r"HKU\S-1-5-21-0-0-0-1000_Classes";
/// The packaged-COM catalog.
pub const PACKAGED_COM: &str = r"HKLM\SOFTWARE\Classes\PackagedCom";
/// `REG_NONE`, the type of an `OpenWithProgids` entry.
const REG_NONE: u32 = 0;
/// Deepest element nesting accepted.
const MAX_XML_DEPTH: usize = 256;

const _: () = assert!(USER_CLASSES.len() == 4 + DEFAULT_PROFILE_SID.len() + 8);

/// Why a manifest was not used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlError {
    /// Byte offset in the text.
    pub at: usize,
    /// What is wrong.
    pub reason: &'static str,
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed XML at byte {}: {}", self.at, self.reason)
    }
}

impl std::error::Error for XmlError {}

/// What the declarations of one manifest were.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppxStats {
    /// File extensions declared.
    pub file_types: u64,
    /// URI schemes declared.
    pub protocols: u64,
    /// COM classes declared (proxy stubs included).
    pub classes: u64,
    /// COM interfaces declared.
    pub interfaces: u64,
    /// Type libraries declared.
    pub type_libs: u64,
    /// ProgIDs declared in the manifest.
    pub prog_ids: u64,
    /// Generated ProgIDs from the repository.
    pub generated_prog_ids: u64,
    /// Names or ids skipped (not a usable key segment, not a GUID).
    pub skipped: u64,
}

impl AppxStats {
    fn add(&mut self, o: &AppxStats) {
        self.file_types += o.file_types;
        self.protocols += o.protocols;
        self.classes += o.classes;
        self.interfaces += o.interfaces;
        self.type_libs += o.type_libs;
        self.prog_ids += o.prog_ids;
        self.generated_prog_ids += o.generated_prog_ids;
        self.skipped += o.skipped;
    }
}

/// What S4 gave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InboxStats {
    /// Inbox packages the source returned.
    pub packages: u64,
    /// Of them signature kind System.
    pub system: u64,
    /// Manifests read and parsed.
    pub parsed: u64,
    /// Manifests that could not be read, or were not well-formed: (full name, reason). Counted, never
    /// fatal (the seal decides, BL-BUILD).
    pub failed: Vec<(String, String)>,
    /// Packages the source listed and left out as not inbox.
    pub not_inbox: u64,
    /// The package list covered every user.
    pub machine_wide: bool,
    /// The provisioned list was read.
    pub provisioned_read: bool,
    /// The repository index was read.
    pub repository_read: bool,
    /// Declarations over all parsed manifests.
    pub declarations: AppxStats,
    /// Records added to the set (new ones only).
    pub records: u64,
}

/// S4: every inbox package of `src` into `out`. An error only when the package list itself could not
/// be read.
pub fn inbox_records(src: &dyn LocalSources, out: &mut Records) -> SourceResult<InboxStats> {
    Ok(packages_records(&src.inbox_packages()?, out))
}

/// S4 from a package list already read ([`LocalSources::inbox_packages`]) into `out`; the builder
/// keeps the list for the package names of its source id.
pub fn packages_records(inbox: &InboxPackages, out: &mut Records) -> InboxStats {
    let before = record_count(out);
    let mut stats = InboxStats {
        packages: inbox.packages.len() as u64,
        not_inbox: inbox.not_inbox,
        machine_wide: inbox.machine_wide,
        provisioned_read: inbox.provisioned.is_ok(),
        repository_read: inbox.repository.is_ok(),
        ..InboxStats::default()
    };
    for p in &inbox.packages {
        if p.reason == InboxReason::System {
            stats.system += 1;
        }
        let xml = match &p.manifest {
            Ok(x) => x,
            Err(e) => {
                stats.failed.push((p.full_name.clone(), e.to_string()));
                continue;
            }
        };
        match manifest_records(xml, &p.full_name, &p.repository_prog_ids, out) {
            Ok(s) => {
                stats.parsed += 1;
                stats.declarations.add(&s);
            }
            Err(e) => stats.failed.push((p.full_name.clone(), e.to_string())),
        }
    }
    stats.records = record_count(out) - before;
    stats
}

/// One manifest (and the package's repository ProgIDs) into `out`. On an XML error nothing is added.
pub fn manifest_records(
    xml: &str,
    full_name: &str,
    repository: &[RepositoryProgId],
    out: &mut Records,
) -> Result<AppxStats, XmlError> {
    let root = parse_xml(xml)?;
    let mut d = Declarations::default();
    collect(&root, None, &mut d);

    let mut stats = AppxStats::default();
    let ok_name = |s: &str, stats: &mut AppxStats| -> Option<String> {
        let s = s.trim();
        let good = !s.is_empty()
            && s.chars().count() <= 255
            && !s.contains('\\')
            && !s.chars().any(char::is_control);
        if !good {
            stats.skipped += 1;
        }
        good.then(|| s.to_owned())
    };
    let package = ok_name(full_name, &mut stats);

    for ext in &d.file_types {
        let Some(ext) = ok_name(ext, &mut stats).filter(|e| e.starts_with('.') && e.len() > 1)
        else {
            continue;
        };
        stats.file_types += 1;
        for c in [MACHINE_CLASSES, USER_CLASSES] {
            out.add_key(&format!(r"{c}\{ext}\OpenWithProgids"));
        }
    }
    for scheme in &d.protocols {
        let Some(scheme) = ok_name(scheme, &mut stats) else {
            continue;
        };
        stats.protocols += 1;
        for c in [MACHINE_CLASSES, USER_CLASSES] {
            out.add_key(&format!(r"{c}\{scheme}"));
        }
    }

    let mut com = false;
    for (kind, ids) in [
        (ComKind::Class, &d.classes),
        (ComKind::Interface, &d.interfaces),
        (ComKind::TypeLib, &d.type_libs),
    ] {
        for id in ids {
            let Some(g) = guid(id) else {
                stats.skipped += 1;
                continue;
            };
            com = true;
            let (classes_sub, index, package_sub) = match kind {
                ComKind::Class => {
                    stats.classes += 1;
                    ("CLSID", "ClassIndex", Some("Class"))
                }
                ComKind::Interface => {
                    stats.interfaces += 1;
                    ("Interface", "InterfaceIndex", Some("Interface"))
                }
                ComKind::TypeLib => {
                    stats.type_libs += 1;
                    ("TypeLib", "TypeLibIndex", None)
                }
            };
            out.add_key(&format!(r"{MACHINE_CLASSES}\{classes_sub}\{g}"));
            if let Some(p) = &package {
                out.add_key(&format!(r"{PACKAGED_COM}\{index}\{g}\{p}"));
                if let Some(sub) = package_sub {
                    out.add_key(&format!(r"{PACKAGED_COM}\Package\{p}\{sub}\{g}"));
                }
            }
        }
    }
    for (prog_id, clsid) in &d.prog_ids {
        let Some(prog_id) = ok_name(prog_id, &mut stats) else {
            continue;
        };
        stats.prog_ids += 1;
        com = true;
        out.add_key(&format!(r"{MACHINE_CLASSES}\{prog_id}"));
        if clsid.as_deref().and_then(guid).is_some() {
            out.add_key(&format!(r"{MACHINE_CLASSES}\{prog_id}\CLSID"));
        }
        if let Some(p) = &package {
            out.add_key(&format!(r"{PACKAGED_COM}\ProgIdIndex\{prog_id}\{p}"));
        }
    }
    if let Some(p) = package.as_ref().filter(|_| com && d.com_server) {
        out.add_key(&format!(r"{PACKAGED_COM}\Package\{p}\Server"));
    }

    for r in repository {
        let Some(prog_id) = ok_name(&r.prog_id, &mut stats) else {
            continue;
        };
        stats.generated_prog_ids += 1;
        let base = format!(r"{USER_CLASSES}\{prog_id}");
        for sub in ["Application", "DefaultIcon", r"Shell\open\command"] {
            out.add_key(&format!(r"{base}\{sub}"));
        }
        let mut verbs: BTreeSet<String> = BTreeSet::new();
        for ext in &r.file_types {
            let Some(ext) = ok_name(ext, &mut stats) else {
                continue;
            };
            out.add_value(
                &format!(r"{USER_CLASSES}\{ext}\OpenWithProgids"),
                &prog_id,
                REG_NONE,
            );
            for fta in d
                .associations
                .iter()
                .filter(|a| a.exts.iter().any(|e| e.trim().eq_ignore_ascii_case(&ext)))
            {
                verbs.extend(fta.verbs.iter().cloned());
            }
        }
        for verb in verbs {
            if let Some(verb) = ok_name(&verb, &mut stats) {
                out.add_key(&format!(r"{base}\Shell\{verb}\command"));
            }
        }
        for scheme in &r.protocols {
            if let Some(scheme) = ok_name(scheme, &mut stats) {
                out.add_key(&format!(r"{USER_CLASSES}\{scheme}"));
            }
        }
    }
    Ok(stats)
}

#[derive(Clone, Copy)]
enum ComKind {
    Class,
    Interface,
    TypeLib,
}

/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` (upper case) from an id with or without braces.
fn guid(id: &str) -> Option<String> {
    let s = id.trim();
    let s = s
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(s);
    let groups: Vec<&str> = s.split('-').collect();
    let lens = [8, 4, 4, 4, 12];
    (groups.len() == 5
        && groups
            .iter()
            .zip(lens)
            .all(|(g, n)| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit())))
    .then(|| format!("{{{}}}", s.to_ascii_uppercase()))
}

// ---------------------------------------------------------------------------------------------------------
// Declarations
// ---------------------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Association {
    exts: Vec<String>,
    verbs: Vec<String>,
}

#[derive(Debug, Default)]
struct Declarations {
    file_types: Vec<String>,
    associations: Vec<Association>,
    protocols: Vec<String>,
    classes: Vec<String>,
    interfaces: Vec<String>,
    type_libs: Vec<String>,
    /// (ProgID, its CLSID when declared)
    prog_ids: Vec<(String, Option<String>)>,
    com_server: bool,
}

fn category_is(category: Option<&str>, suffix: &str) -> bool {
    category.is_some_and(|c| {
        c.len() >= suffix.len()
            && c.is_char_boundary(c.len() - suffix.len())
            && c[c.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    })
}

fn collect<'a>(el: &'a Element, category: Option<&'a str>, d: &mut Declarations) {
    let category = if el.name == "Extension" {
        el.attr("Category").or(category)
    } else {
        category
    };
    match el.name.as_str() {
        "FileTypeAssociation" => {
            let mut a = Association::default();
            el.each(&mut |e| match e.name.as_str() {
                "FileType" => a.exts.push(e.text.trim().to_owned()),
                "Verb" => a.verbs.extend(e.attr("Id").map(str::to_owned)),
                _ => {}
            });
            d.file_types.extend(a.exts.iter().cloned());
            d.associations.push(a);
            return;
        }
        "Protocol" if category_is(category, "protocol") => {
            d.protocols.extend(el.attr("Name").map(str::to_owned));
        }
        "ExeServer" | "SurrogateServer" | "ServiceServer" if category_is(category, "comServer") => {
            d.com_server = true;
        }
        "Class" if category_is(category, "comServer") => {
            d.classes.extend(el.attr("Id").map(str::to_owned));
            for a in ["ProgId", "VersionIndependentProgId"] {
                if let Some(p) = el.attr(a) {
                    d.prog_ids
                        .push((p.to_owned(), el.attr("Id").map(str::to_owned)));
                }
            }
        }
        "ProgId" if category_is(category, "comServer") => {
            if let Some(id) = el.attr("Id") {
                d.prog_ids
                    .push((id.to_owned(), el.attr("Clsid").map(str::to_owned)));
            }
        }
        "Interface" if category_is(category, "comInterface") => {
            d.interfaces.extend(el.attr("Id").map(str::to_owned));
            d.classes
                .extend(el.attr("ProxyStubClsid").map(str::to_owned));
        }
        "ProxyStub" | "ProxyStubClsid" if category_is(category, "comInterface") => {
            d.classes.extend(el.attr("Id").map(str::to_owned));
        }
        "TypeLib" if category_is(category, "comInterface") => {
            d.type_libs.extend(el.attr("Id").map(str::to_owned));
        }
        _ => {}
    }
    for c in &el.children {
        collect(c, category, d);
    }
}

// ---------------------------------------------------------------------------------------------------------
// A small XML reader: elements, attributes and text, enough for AppxManifest.xml. No DTD, no external
// anything.
// ---------------------------------------------------------------------------------------------------------

/// One element: local name (prefix dropped), attributes by local name, children, concatenated text.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Element {
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Element>,
    text: String,
}

impl Element {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Every descendant, depth-first.
    fn each(&self, f: &mut dyn FnMut(&Element)) {
        for c in &self.children {
            f(c);
            c.each(f);
        }
    }
}

fn local(qname: &str) -> &str {
    qname.rsplit_once(':').map_or(qname, |(_, l)| l)
}

fn parse_xml(text: &str) -> Result<Element, XmlError> {
    let b = text.as_bytes();
    let err = |at: usize, reason: &'static str| XmlError { at, reason };
    let mut i = 0usize;
    if text.starts_with('\u{feff}') {
        i = 3;
    }
    // (qualified name, element)
    let mut stack: Vec<(String, Element)> = Vec::new();
    let mut root: Option<Element> = None;

    while i < b.len() {
        if b[i] != b'<' {
            let end = text[i..].find('<').map_or(b.len(), |n| i + n);
            let chunk = &text[i..end];
            match stack.last_mut() {
                Some((_, el)) => el.text.push_str(&decode(chunk, i)?),
                None if chunk.trim().is_empty() => {}
                None => return Err(err(i, "text outside the root element")),
            }
            i = end;
            continue;
        }
        let rest = &text[i..];
        if rest.starts_with("<?") {
            i += rest.find("?>").ok_or(err(i, "unterminated <?"))? + 2;
        } else if rest.starts_with("<!--") {
            i += rest.find("-->").ok_or(err(i, "unterminated comment"))? + 3;
        } else if rest.starts_with("<![CDATA[") {
            let n = rest.find("]]>").ok_or(err(i, "unterminated CDATA"))?;
            match stack.last_mut() {
                Some((_, el)) => el.text.push_str(&rest[9..n]),
                None => return Err(err(i, "CDATA outside the root element")),
            }
            i += n + 3;
        } else if rest.starts_with("<!") {
            return Err(err(i, "DTD or declaration not supported"));
        } else if let Some(close) = rest.strip_prefix("</") {
            let n = close.find('>').ok_or(err(i, "unterminated end tag"))?;
            let name = close[..n].trim();
            let (open, el) = stack.pop().ok_or(err(i, "end tag without start tag"))?;
            if open != name {
                return Err(err(i, "end tag does not match"));
            }
            i += 2 + n + 1;
            match stack.last_mut() {
                Some((_, parent)) => parent.children.push(el),
                None if root.is_none() => root = Some(el),
                None => return Err(err(i, "second root element")),
            }
        } else {
            let (el_qname, el, self_closing, len) = start_tag(text, i)?;
            i += len;
            if root.is_some() {
                return Err(err(i, "second root element"));
            }
            if self_closing {
                match stack.last_mut() {
                    Some((_, parent)) => parent.children.push(el),
                    None => root = Some(el),
                }
            } else {
                if stack.len() >= MAX_XML_DEPTH {
                    return Err(err(i, "nesting too deep"));
                }
                stack.push((el_qname, el));
            }
        }
    }
    if !stack.is_empty() {
        return Err(err(b.len(), "unclosed element"));
    }
    root.ok_or(err(b.len(), "no root element"))
}

/// Parses the start tag at `at` (`<name a="v" …>` or `…/>`): (qualified name, element, self-closing,
/// length in bytes).
fn start_tag(text: &str, at: usize) -> Result<(String, Element, bool, usize), XmlError> {
    let err = |off: usize, reason: &'static str| XmlError {
        at: at + off,
        reason,
    };
    let s = &text[at..];
    let b = s.as_bytes();
    let is_name = |c: u8| !(c.is_ascii_whitespace() || matches!(c, b'/' | b'>' | b'=' | b'<'));
    let mut j = 1;
    while j < b.len() && is_name(b[j]) {
        j += 1;
    }
    if j == 1 {
        return Err(err(0, "element without a name"));
    }
    let qname = s[1..j].to_owned();
    let mut el = Element {
        name: local(&qname).to_owned(),
        ..Element::default()
    };
    loop {
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        match b.get(j) {
            None => return Err(err(j, "unterminated start tag")),
            Some(b'>') => return Ok((qname, el, false, j + 1)),
            Some(b'/') => {
                return if b.get(j + 1) == Some(&b'>') {
                    Ok((qname, el, true, j + 2))
                } else {
                    Err(err(j, "stray / in start tag"))
                };
            }
            Some(_) => {}
        }
        let name_start = j;
        while j < b.len() && is_name(b[j]) {
            j += 1;
        }
        if j == name_start {
            return Err(err(j, "bad attribute name"));
        }
        let aname = &s[name_start..j];
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if b.get(j) != Some(&b'=') {
            return Err(err(j, "attribute without a value"));
        }
        j += 1;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        let quote = match b.get(j) {
            Some(q @ (b'"' | b'\'')) => *q,
            _ => return Err(err(j, "attribute value not quoted")),
        };
        let vstart = j + 1;
        let vlen = s[vstart..]
            .bytes()
            .position(|c| c == quote)
            .ok_or(err(j, "unterminated attribute value"))?;
        let raw = &s[vstart..vstart + vlen];
        if raw.contains('<') {
            return Err(err(vstart, "< in attribute value"));
        }
        let value = decode(raw, at + vstart)?;
        j = vstart + vlen + 1;
        if !aname.starts_with("xmlns") {
            el.attrs.push((local(aname).to_owned(), value));
        }
    }
}

/// Decodes the five predefined entities and character references.
fn decode(s: &str, at: usize) -> Result<String, XmlError> {
    if !s.contains('&') {
        return Ok(s.to_owned());
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(n) = rest.find('&') {
        out.push_str(&rest[..n]);
        let after = &rest[n + 1..];
        let end = after.find(';').ok_or(XmlError {
            at,
            reason: "unterminated entity",
        })?;
        let ent = &after[..end];
        let c = match ent {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => ent
                .strip_prefix("#x")
                .or_else(|| ent.strip_prefix("#X"))
                .map(|h| u32::from_str_radix(h, 16))
                .or_else(|| ent.strip_prefix('#').map(str::parse::<u32>))
                .and_then(Result::ok)
                .and_then(char::from_u32),
        };
        out.push(c.ok_or(XmlError {
            at,
            reason: "unknown entity",
        })?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::Baseline;

    const PHOTOS: &str = "Microsoft.Windows.Photos_1.0.0.0_x64__8wekyb3d8bbwe";

    /// Hand-written in the shape of an inbox manifest (no real Microsoft manifest is committed).
    const FTA_PROTOCOL: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<!-- hand-written fixture -->
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:uap2="http://schemas.microsoft.com/appx/manifest/uap/windows10/2"
         xmlns:uap3="http://schemas.microsoft.com/appx/manifest/uap/windows10/3">
  <Identity Name="Microsoft.Windows.Photos" Publisher="CN=Microsoft Corporation" Version="1.0.0.0"/>
  <Applications>
    <Application Id="App" Executable="Photos.exe" EntryPoint="Windows.FullTrustApplication">
      <Extensions>
        <uap:Extension Category="windows.fileTypeAssociation">
          <uap3:FileTypeAssociation Name="image.types" Parameters="&quot;%1&quot;">
            <uap:SupportedFileTypes>
              <uap:FileType>.jpg</uap:FileType>
              <uap:FileType ContentType="image/png"> .png </uap:FileType>
            </uap:SupportedFileTypes>
            <uap2:SupportedVerbs>
              <uap3:Verb Id="edit" Parameters="-edit &amp; more">Edit</uap3:Verb>
              <uap3:Verb Id="print">Print</uap3:Verb>
            </uap2:SupportedVerbs>
          </uap3:FileTypeAssociation>
        </uap:Extension>
        <uap:Extension Category="windows.fileTypeAssociation">
          <uap:FileTypeAssociation Name="video">
            <uap:SupportedFileTypes><uap:FileType>.mp4</uap:FileType></uap:SupportedFileTypes>
          </uap:FileTypeAssociation>
        </uap:Extension>
        <uap:Extension Category="windows.protocol">
          <uap:Protocol Name="ms-photos"><uap:DisplayName>Photos</uap:DisplayName></uap:Protocol>
        </uap:Extension>
        <uap:Extension Category="windows.appService">
          <uap:AppService Name="Protocol"/>
          <Protocol Name="not-a-protocol-here"/>
        </uap:Extension>
      </Extensions>
    </Application>
  </Applications>
</Package>
"#;

    const COM: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:com="http://schemas.microsoft.com/appx/manifest/com/windows10"
         xmlns:com2="http://schemas.microsoft.com/appx/manifest/com/windows10/2">
  <Applications>
    <Application Id="App">
      <Extensions>
        <com:Extension Category="windows.comServer">
          <com:ComServer>
            <com:ExeServer Executable="Server.exe" DisplayName="Server">
              <com:Class Id="1e71da0c-e2f7-49a7-b40a-f6c5f9ea832a" DisplayName="A" ProgId="Inbox.Thing.1" VersionIndependentProgId="Inbox.Thing"/>
              <com:Class Id="{26EC7652-46E4-4B59-B9EB-A76060DD693A}"/>
              <com:Class Id="not-a-guid"/>
            </com:ExeServer>
            <com:ProgId Id="Inbox.Other" Clsid="{26EC7652-46E4-4B59-B9EB-A76060DD693A}"/>
            <com:ProgId Id="Bad\Name"/>
          </com:ComServer>
        </com:Extension>
        <com:Extension Category="windows.comInterface">
          <com:ComInterface>
            <com:ProxyStub Id="{41BD826D-F49F-4FD2-8CEA-D9F054D434E7}" DisplayName="PS">
              <com:Path>ps.dll</com:Path>
            </com:ProxyStub>
            <com:Interface Id="{011FB326-F2C7-5F6B-A6A4-294A46F73788}" ProxyStubClsid="{41BD826D-F49F-4FD2-8CEA-D9F054D434E7}">
              <com:TypeLib Id="{B9AA1F11-F480-4054-A84E-B5D9277E40A8}" VersionNumber="1.0"/>
            </com:Interface>
            <com2:TypeLib Id="{C9AA1F11-F480-4054-A84E-B5D9277E40A8}"><com2:Version Number="1.0"/></com2:TypeLib>
          </com:ComInterface>
        </com:Extension>
      </Extensions>
    </Application>
  </Applications>
</Package>
"#;

    fn keys(r: &Records) -> Vec<String> {
        r.keys()
            .map(|k| format!("K {k}"))
            .chain(
                r.values()
                    .map(|v| format!("V {}|{}|{}", v.key(), v.name(), v.ty())),
            )
            .collect()
    }

    /// Records are case-folded; `line` is compared folded.
    fn has(r: &Records, line: &str) -> bool {
        let (kind, rest) = line.split_at(2);
        let line = format!("{kind}{}", rest.to_ascii_lowercase());
        keys(r).contains(&line)
    }

    fn text(r: &Records) -> String {
        let mut out = Vec::new();
        r.write_records(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn file_types_protocols_and_generated_prog_ids() {
        let repo = [
            RepositoryProgId {
                prog_id: "AppXimages1".into(),
                file_types: vec![".jpg".into(), ".PNG".into()],
                protocols: vec![],
            },
            RepositoryProgId {
                prog_id: "AppXvideo1".into(),
                file_types: vec![".mp4".into()],
                protocols: vec![],
            },
            RepositoryProgId {
                prog_id: "AppXproto1".into(),
                file_types: vec![],
                protocols: vec!["ms-photos".into()],
            },
        ];
        let mut out = Records::new();
        let s = manifest_records(FTA_PROTOCOL, PHOTOS, &repo, &mut out).unwrap();
        assert_eq!(
            (s.file_types, s.protocols, s.generated_prog_ids, s.skipped),
            (3, 1, 3, 0)
        );
        for c in [MACHINE_CLASSES, USER_CLASSES] {
            for k in [
                format!(r"K {c}\.jpg"),
                format!(r"K {c}\.jpg\OpenWithProgids"),
                format!(r"K {c}\.png\OpenWithProgids"),
                format!(r"K {c}\.mp4\OpenWithProgids"),
                format!(r"K {c}\ms-photos"),
            ] {
                assert!(has(&out, &k), "{k}\n{:#?}", keys(&out));
            }
        }
        let u = USER_CLASSES;
        for k in [
            format!(r"V {u}\.jpg\OpenWithProgids|AppXimages1|0"),
            format!(r"V {u}\.PNG\OpenWithProgids|AppXimages1|0"),
            format!(r"V {u}\.mp4\OpenWithProgids|AppXvideo1|0"),
            format!(r"K {u}\AppXimages1\Application"),
            format!(r"K {u}\AppXimages1\DefaultIcon"),
            format!(r"K {u}\AppXimages1\Shell\open\command"),
            format!(r"K {u}\AppXimages1\Shell\edit\command"),
            format!(r"K {u}\AppXimages1\Shell\print\command"),
            format!(r"K {u}\AppXvideo1\Shell\open\command"),
            format!(r"K {u}\AppXproto1\Shell\open\command"),
        ] {
            assert!(has(&out, &k), "{k}\n{:#?}", keys(&out));
        }
        // The video type declares no verbs; only `open` is recorded for it.
        assert!(!has(&out, &format!(r"K {u}\AppXvideo1\Shell\edit")));
        // `Protocol` outside a protocol extension is not a protocol.
        assert!(!keys(&out).iter().any(|k| k.contains("not-a-protocol")));
        // Generated ProgIDs are per user only.
        assert!(!has(&out, &format!(r"K {MACHINE_CLASSES}\AppXimages1")));

        // Through the loader: any user's classes hive, in either spelling.
        let text = format!("#purge-baseline 1\tT\tPC\tSynthetic\t1.2\n{}", text(&out));
        let b = Baseline::from_bytes(text.as_bytes()).unwrap();
        let sid = "S-1-5-21-7-8-9-1001";
        assert!(b.has_key(&format!(r"HKU\{sid}_Classes\AppXimages1\Shell\open")));
        assert!(b.has_key(&format!(r"HKU\{sid}\Software\Classes\.jpg\OpenWithProgids")));
        assert!(b.has_value(
            &format!(r"HKU\{sid}_Classes\.jpg\OpenWithProgids"),
            "appximages1"
        ));
        assert!(b.has_key(r"HKCR\ms-photos"));
    }

    #[test]
    fn com_server_and_com_interface() {
        let mut out = Records::new();
        let s = manifest_records(COM, PHOTOS, &[], &mut out).unwrap();
        assert_eq!(
            (s.classes, s.interfaces, s.type_libs, s.prog_ids, s.skipped),
            (4, 1, 2, 3, 2),
            "{s:?}"
        );
        let m = MACHINE_CLASSES;
        let p = PACKAGED_COM;
        for k in [
            format!(r"K {m}\CLSID\{{1E71DA0C-E2F7-49A7-B40A-F6C5F9EA832A}}"),
            format!(r"K {m}\CLSID\{{26EC7652-46E4-4B59-B9EB-A76060DD693A}}"),
            format!(r"K {m}\CLSID\{{41BD826D-F49F-4FD2-8CEA-D9F054D434E7}}"),
            format!(r"K {m}\Interface\{{011FB326-F2C7-5F6B-A6A4-294A46F73788}}"),
            format!(r"K {m}\TypeLib\{{B9AA1F11-F480-4054-A84E-B5D9277E40A8}}"),
            format!(r"K {m}\TypeLib\{{C9AA1F11-F480-4054-A84E-B5D9277E40A8}}"),
            format!(r"K {m}\Inbox.Thing.1"),
            format!(r"K {m}\Inbox.Thing.1\CLSID"),
            format!(r"K {m}\Inbox.Thing\CLSID"),
            format!(r"K {m}\Inbox.Other\CLSID"),
            format!(r"K {p}\ClassIndex\{{1E71DA0C-E2F7-49A7-B40A-F6C5F9EA832A}}\{PHOTOS}"),
            format!(r"K {p}\InterfaceIndex\{{011FB326-F2C7-5F6B-A6A4-294A46F73788}}\{PHOTOS}"),
            format!(r"K {p}\TypeLibIndex\{{B9AA1F11-F480-4054-A84E-B5D9277E40A8}}\{PHOTOS}"),
            format!(r"K {p}\ProgIdIndex\Inbox.Other\{PHOTOS}"),
            format!(r"K {p}\Package\{PHOTOS}\Class\{{26EC7652-46E4-4B59-B9EB-A76060DD693A}}"),
            format!(r"K {p}\Package\{PHOTOS}\Interface\{{011FB326-F2C7-5F6B-A6A4-294A46F73788}}"),
            format!(r"K {p}\Package\{PHOTOS}\Server"),
        ] {
            assert!(has(&out, &k), "{k}\n{:#?}", keys(&out));
        }
        assert!(
            !keys(&out)
                .iter()
                .any(|k| k.contains("not-a-guid") || k.contains("bad"))
        );
        // COM is machine-wide only.
        assert!(
            !keys(&out)
                .iter()
                .any(|k| k.contains(&USER_CLASSES.to_ascii_lowercase()))
        );

        let text = format!("#purge-baseline 1\tT\tPC\tSynthetic\t1.2\n{}", text(&out));
        let b = Baseline::from_bytes(text.as_bytes()).unwrap();
        assert!(b.has_key(r"HKCR\CLSID\{1e71da0c-e2f7-49a7-b40a-f6c5f9ea832a}"));
        assert!(
            b.has_key(r"HKLM\SOFTWARE\Classes\Interface\{011FB326-F2C7-5F6B-A6A4-294A46F73788}")
        );
    }

    #[test]
    fn malformed_xml_adds_nothing() {
        for bad in [
            "<Package><Applications></Package>",
            "<Package>",
            "<Package a=b/>",
            "<Package/><Second/>",
            "<!DOCTYPE x [<!ENTITY e 'x'>]><Package/>",
            "<Package>&bogus;</Package>",
            "text<Package/>",
            "",
        ] {
            let mut out = Records::new();
            let r = manifest_records(bad, PHOTOS, &[], &mut out);
            assert!(r.is_err(), "{bad:?}");
            assert!(out.is_empty(), "{bad:?}");
        }
        // A manifest with no declarations is fine and adds only repository records.
        let mut out = Records::new();
        let s = manifest_records("<Package/>", PHOTOS, &[], &mut out).unwrap();
        assert_eq!(s, AppxStats::default());
        assert!(out.is_empty());
    }

    #[test]
    fn xml_reader_details() {
        let el = parse_xml(
            "\u{feff}<?xml version='1.0'?><a:R xmlns:a='u' x='1 &lt; 2'><![CDATA[<raw>]]>t&#65;&#x42;<b/></a:R>",
        )
        .unwrap();
        assert_eq!(el.name, "R");
        assert_eq!(el.attr("x"), Some("1 < 2"));
        assert_eq!(el.attrs.len(), 1);
        assert_eq!(el.text, "<raw>tAB");
        assert_eq!(el.children.len(), 1);
        assert_eq!(guid("{abc}"), None);
        assert_eq!(
            guid(" 1e71da0c-e2f7-49a7-b40a-f6c5f9ea832a ").as_deref(),
            Some("{1E71DA0C-E2F7-49A7-B40A-F6C5F9EA832A}")
        );
        let deep = "<a>".repeat(300) + &"</a>".repeat(300);
        assert!(parse_xml(&deep).is_err());
    }

    #[test]
    fn inbox_records_count_failures() {
        use purge_source::fixture::Fixture;
        use purge_source::types::{PackageInfo, PackageSignatureKind};

        let pkg = |full: &str, dir: &str| PackageInfo {
            full_name: full.into(),
            family: String::new(),
            install_location: Some(dir.into()),
            external_location: None,
            sparse: false,
            users: Vec::new(),
            is_framework: false,
            is_resource: false,
            signature_kind: PackageSignatureKind::System,
        };
        let f = Fixture::builder()
            .package(pkg(
                "A.Good_1.0.0.0_x64__cw5n1h2txyewy",
                r"C:\Windows\SystemApps\Good",
            ))
            .package(pkg(
                "A.Bad_1.0.0.0_x64__cw5n1h2txyewy",
                r"C:\Windows\SystemApps\Bad",
            ))
            .package(pkg(
                "A.Gone_1.0.0.0_x64__cw5n1h2txyewy",
                r"C:\Windows\SystemApps\Gone",
            ))
            .file_content(
                r"C:\Windows\SystemApps\Good\AppxManifest.xml",
                FTA_PROTOCOL.as_bytes().to_vec(),
            )
            .file_content(
                r"C:\Windows\SystemApps\Bad\AppxManifest.xml",
                b"<Package>".to_vec(),
            )
            .build();
        let mut out = Records::new();
        let s = inbox_records(&f, &mut out).unwrap();
        assert_eq!((s.packages, s.system, s.parsed), (3, 3, 1));
        assert_eq!(s.failed.len(), 2, "{:?}", s.failed);
        assert!(!s.repository_read && !s.provisioned_read && !s.machine_wide);
        assert_eq!(s.declarations.file_types, 3);
        assert_eq!(s.records, record_count(&out));
        assert!(out.contains_key(r"HKLM\SOFTWARE\Classes\.mp4"));
    }
}
