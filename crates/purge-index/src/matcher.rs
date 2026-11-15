//! The reference matcher: does a registry string refer to one of an app's anchors? (ENGINE_PLAN.md §5.5
//! "Reference index", §5.3 `InPreUninstallRefSnapshot`, `PointsIntoInstallRoot`, `HarvestedToken`.)
//!
//! The harvest and the scanners hand every candidate string to a [`RefMatcher`]: a value **name**, `REG_SZ`
//! / `REG_EXPAND_SZ` data, each `REG_MULTI_SZ` segment, and each UTF-16 run found in binary data
//! ([`utf16_runs`]). The matcher is pure and knows nothing about where the string came from.
//!
//! An [`AnchorSet`] lists what counts as "the app": roots, exe paths, exe names, ProgIDs, CLSIDs, AUMIDs
//! and tokens. [`RefMatcher::new`] compiles it once; a test is then linear in the string's length however
//! many anchors there are, so one matcher can be run over every value of the reference-index scope.
//!
//! # Rules
//!
//! Comparison is case-insensitive (Unicode lower-casing). In the tested string `/` is read as `\` and
//! runs of `\` as one, so `C:/Program Files/Git` and JSON-style `C:\\Program Files\\Git` match too. A
//! string holding `%NAME%` references is tested as written **and** with the references expanded from the
//! environment the matcher was built with.
//!
//! An anchor may occur anywhere in the string (quoted, inside a command line, in a `;`-separated list),
//! but only at a boundary that fits its kind:
//!
//! | Anchor | Must be preceded by | Must be followed by |
//! |---|---|---|
//! | root | start, or anything but a letter or digit | end; `\` (a path below it); `"` `;` `\|` `<` `>` `*` `?`; an icon index `,-12`; white space up to the end or a `"` |
//! | exe path | as a root | end; white space; `"` `,` `;` `\|` `<` `>` `*` `?` `:`; a MuiCache suffix (`.FriendlyAppName`, `.ApplicationCompany`) |
//! | exe name | start, `\`, white space, or one of `"` `'` `;` `,` `=` `\|` `<` `>` `:` `*` `?` | as an exe path |
//! | ProgID, AUMID, token | start, or anything but a letter, digit, `.`, `-`, `_` | end, or anything but those |
//! | ProgID, AUMID, in addition | not the `\` of a file path (below) | |
//! | CLSID (`{…}`) | anything | anything |
//!
//! So the root `C:\Program Files\Git` matches `C:\Program Files\Git\cmd` and
//! `"C:\Program Files\Git\bin\bash.exe" -c x`, never `C:\Program Files\GitHub` or
//! `C:\Program Files\Git Extensions`. A token is a **whole segment**: `308046B0AF4A39CB` matches as a
//! value's whole data or as `…\updates\308046B0AF4A39CB`, not inside `A308046B0AF4A39CB0` and not inside
//! `FirefoxURL-308046B0AF4A39CB` (which is a ProgID anchor of its own). Composite names such as the
//! `<ProgID>_<.ext>` values of `ApplicationAssociationToasts` are for their scanner to take apart.
//!
//! A ProgID or AUMID is the name of a registration, not of a folder. A short one (`vscode`, the URL
//! protocol) is also what people call a folder: `D:\Tools\VSCode\Code.exe` is the user's own copy of
//! the program and names no registration of the installed app (rig run x1-vscode-userstate). So an
//! id is not matched inside a **file path**. The id is looked at in the piece of text it stands in
//! (from one of `"` `;` `|` `<` `>` `*` `?` or a line end to the next): when that piece has a `\` or
//! `/` anywhere, it is a path, and the id matches only when the path is a registry path, that is,
//! when it starts with `HKEY_…`, `HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`, `Software`, `SYSTEM` or
//! `Classes`, or with `\Registry\Machine\` or `\Registry\User\` (the one spelling with a `\` in
//! front), or with `shell:`
//! (`shell:AppsFolder\<AUMID>`). So `Software\Classes\git_shell\shell\open` and
//! `Software\Clients\StartMenuInternet\<id>\Capabilities` match, and `C:\Tools\My VSCode\Code.exe`,
//! `Tools\vscode\Code.exe`, `..\vscode\x`, `~\vscode\x` and `%LOCALAPPDATA%\vscode\x` do not.
//!
//! A piece that starts with one of those words is still a file path, and the id is not matched,
//! when anything in it shows so:
//!
//! - it starts with a separator and is not `\Registry\Machine\…` or `\Registry\User\…`
//!   (`\\` is read as `\` here, so a server called `registry` with a share called `machine` is the
//!   one UNC path still taken for a key): `\\software\share\vscode\Code.exe` and
//!   `\\system\c$\vscode\x.exe` are UNC paths to servers of those names, and
//!   `\Software\Stuff\vscode\readme.txt` is a folder at the root of a drive (no value of the
//!   captured rig runs spells a key with a `\` in front);
//! - it holds a drive path (`X:\` or `X:/`) anywhere: `HKLM\Software\X\C:\Tools\vscode\Code.exe`;
//! - it holds a `%` before the id (`software\%x%\vscode`: what the reference expands to is not
//!   known here).
//!
//! An id followed by `:` is a URL scheme and matches in two spellings only: at the very start of
//! its piece (`vscode:x`, `"mailto:%1"`), or followed by `://` where it does not stand directly
//! after a separator (`run.exe --open-url vscode://file/…`; `:/` and `:\` read the same as `://`
//! here). As the name of a file or folder it is not a scheme: `C:\Tools\vscode:stream`,
//! `/opt/vscode:/usr/bin`, `D:\x\vscode: failed to start`. (No value of the captured rig runs has
//! an id followed by `:` at all; the protocol registrations name the scheme as a key name and as
//! `URL:<id>`, where the id ends the piece.) A token keeps matching path segments: that is what it
//! is harvested from.
//!
//! The price: an id written without quotes after a path in one command line
//! (`C:\x\run.exe --open vscode`) is not matched either. What remains matched although it could
//! be a file path: a relative one that starts with a root word, `Software\Tools\vscode\Code.exe`.
//! Nothing tells it from `Software\Clients\…\<id>\Capabilities`. An id match is no Tier A fact
//! by itself wherever it is used (`CandidateBuilder::in_ref_snapshot` caps an id-anchored
//! snapshot entry at Tier B unless the installer's record covers the value), so such a value is
//! listed and never preselected.
//!
//! A root never matches a path that steps back out of it: `C:\Program Files\Git\..\Other\x.exe` is not a
//! reference into `C:\Program Files\Git`. A root or exe path that starts with a separator (a UNC path;
//! `\\` runs are folded to one `\`) must start the string or follow white space, a quote or a list
//! character, so `\\srv\apps\Foo` is not found inside `D:\srv\apps\Foo`.
//!
//! 8.3 names cannot be derived lexically; the caller reads them from the file system and adds them with
//! [`AnchorSet::add_root_alias`] / [`AnchorSet::add_exe_alias`]. A match on an alias reports the anchor it
//! stands for.
//!
//! What to add is the caller's decision: a bare exe name such as `update.exe` is a weak anchor, and this
//! module reports such matches with [`RefMatch::name_only`] set so that they are not mistaken for a path.

use std::collections::HashMap;

use purge_model::{AnchorKind, AnchorRef, Fingerprint};

/// How the tested string relates to the anchor it matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MatchHow {
    /// The string is the anchor, apart from surrounding white space and one pair of quotes.
    Whole,
    /// The anchor is a root and the string names something below it.
    Below,
    /// The anchor occurs inside a longer string (a command line, a list, a name with a suffix).
    Embedded,
}

/// One anchor found in a tested string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefMatch {
    /// The anchor: its kind and its text exactly as it was added to the [`AnchorSet`].
    pub anchor: AnchorRef,
    /// How the string relates to it.
    pub how: MatchHow,
    /// The match needed `%NAME%` expansion; the string as written did not match this anchor.
    pub via_env: bool,
    /// The anchor is a bare exe **name** (an [`AnchorKind::Exe`] added with [`AnchorSet::add_exe_name`]),
    /// which says nothing about the directory.
    pub name_only: bool,
    /// For a root or exe-path match: the path the string names, best effort. It is cut at the closing
    /// quote, at a list or redirection character, or before what looks like command-line arguments; an
    /// icon index and a MuiCache suffix are dropped. It is in the matcher's folded form (lower case, `\`
    /// separators, `%NAME%` expanded), which is enough to probe the file system. Use a command-line
    /// parser when the exact argument split matters.
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Class {
    /// A full path to a file of the exe set. Strongest: it names one file.
    File,
    /// A root directory.
    Dir,
    /// A ProgID or AUMID.
    Ident,
    /// A `{GUID}`.
    Clsid,
    /// A harvested token.
    Token,
    /// A bare file name.
    FileName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Needle {
    /// Folded text.
    text: Box<str>,
    class: Class,
    /// Index into the anchor list.
    anchor: u32,
}

/// The anchors of one app, as the reference matcher needs them. Build it once per harvest or scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnchorSet {
    anchors: Vec<AnchorRef>,
    needles: Vec<Needle>,
}

impl AnchorSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// The anchors of a fingerprint: its roots, the exe set and the files declared outside the roots
    /// (as paths), the names of the **main** exes, the ProgID set P, CLSIDs, AUMIDs and tokens.
    ///
    /// Names of the other files of the exe set are left out on purpose: library names such as
    /// `ffmpeg.dll` are shared by many apps.
    pub fn from_fingerprint(fp: &Fingerprint) -> Self {
        let mut set = Self::new();
        for root in &fp.roots {
            set.add_root(&root.path);
        }
        for exe in &fp.exes {
            set.add_exe_path(&exe.path);
            if exe.main {
                if let Some(name) = exe.path.rsplit(['\\', '/']).next() {
                    set.add_exe_name(name);
                }
            }
        }
        for file in &fp.outside_root_files {
            set.add_exe_path(&file.path);
        }
        for progid in &fp.anchors.progids {
            set.add_progid(progid);
        }
        for clsid in &fp.anchors.clsids {
            set.add_clsid(clsid);
        }
        for aumid in &fp.anchors.aumids {
            set.add_aumid(aumid);
        }
        for token in &fp.tokens {
            set.add_token(&token.token);
        }
        set
    }

    /// Adds a root directory. Returns `false` (and adds nothing) for an empty path or a bare drive,
    /// which would match everything on it.
    pub fn add_root(&mut self, path: &str) -> bool {
        let text = path.trim().trim_end_matches(['\\', '/']);
        is_real_dir(text) && self.add(AnchorKind::Root, text, text, Class::Dir)
    }

    /// Adds another spelling of a root (its 8.3 form, a junction's other name). A match on the alias is
    /// reported as the root itself. The root is added if it was not yet.
    pub fn add_root_alias(&mut self, root: &str, alias: &str) -> bool {
        let text = root.trim().trim_end_matches(['\\', '/']);
        let alias = alias.trim().trim_end_matches(['\\', '/']);
        is_real_dir(text)
            && is_real_dir(alias)
            && self.add(AnchorKind::Root, text, alias, Class::Dir)
    }

    /// Adds the full path of a file of the exe set.
    pub fn add_exe_path(&mut self, path: &str) -> bool {
        let text = path.trim();
        is_real_dir(text) && self.add(AnchorKind::Exe, text, text, Class::File)
    }

    /// Adds another spelling of an exe path (its 8.3 form); reported as the exe path itself.
    pub fn add_exe_alias(&mut self, path: &str, alias: &str) -> bool {
        let (text, alias) = (path.trim(), alias.trim());
        is_real_dir(text)
            && is_real_dir(alias)
            && self.add(AnchorKind::Exe, text, alias, Class::File)
    }

    /// Adds a bare exe file name (`firefox.exe`). Matches are flagged [`RefMatch::name_only`].
    pub fn add_exe_name(&mut self, name: &str) -> bool {
        let text = name.trim();
        !text.contains(['\\', '/']) && self.add(AnchorKind::Exe, text, text, Class::FileName)
    }

    /// Adds a ProgID of the set P.
    pub fn add_progid(&mut self, progid: &str) -> bool {
        let text = progid.trim();
        self.add(AnchorKind::ProgId, text, text, Class::Ident)
    }

    /// Adds a CLSID (or AppID, or type-library id), with or without its braces.
    pub fn add_clsid(&mut self, clsid: &str) -> bool {
        let bare = clsid.trim().trim_start_matches('{').trim_end_matches('}');
        if bare.is_empty() {
            return false;
        }
        let braced = format!("{{{bare}}}");
        self.add(AnchorKind::Clsid, &braced, &braced, Class::Clsid)
    }

    /// Adds an AppUserModelID.
    pub fn add_aumid(&mut self, aumid: &str) -> bool {
        let text = aumid.trim();
        self.add(AnchorKind::Aumid, text, text, Class::Ident)
    }

    /// Adds a harvested token (a GUID or a long hex run). It matches as a whole segment only.
    ///
    /// Returns `false` (and adds nothing) for a token shorter than [`MIN_TOKEN_LEN`] characters without
    /// its braces: §5.3 defines a `HarvestedToken` as a GUID or a hex run of at least 12 digits, and a
    /// short token would match unrelated names.
    pub fn add_token(&mut self, token: &str) -> bool {
        let text = token.trim();
        let bare = text.trim_start_matches('{').trim_end_matches('}');
        bare.chars().count() >= MIN_TOKEN_LEN
            && self.add(AnchorKind::Token, text, text, Class::Token)
    }

    /// The anchors, in the order they were first added.
    pub fn anchors(&self) -> &[AnchorRef] {
        &self.anchors
    }

    /// Whether the set has no anchors; such a matcher matches nothing.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// The number of anchors (aliases not counted).
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    fn add(&mut self, kind: AnchorKind, text: &str, spelling: &str, class: Class) -> bool {
        let folded = fold(spelling);
        if text.is_empty() || folded.is_empty() {
            return false;
        }
        // A root and an exe name may share their text with an anchor of another class; the class is
        // part of the identity only through `name_only`, so keep bare names apart from paths.
        let anchor = match self
            .anchors
            .iter()
            .position(|a| a.kind == kind && a.text == text)
        {
            Some(at) => at,
            None => {
                self.anchors.push(AnchorRef {
                    kind,
                    text: text.to_owned(),
                });
                self.anchors.len() - 1
            }
        };
        let needle = Needle {
            text: folded.into_boxed_str(),
            class,
            anchor: anchor as u32,
        };
        if !self.needles.contains(&needle) {
            self.needles.push(needle);
        }
        true
    }
}

/// The shortest token [`AnchorSet::add_token`] accepts (§5.3 `HarvestedToken`: "GUID or ≥ 12-hex").
pub const MIN_TOKEN_LEN: usize = 12;

/// A path with at least one segment below its first one (`C:\X`, not `C:\` or `C:`).
fn is_real_dir(path: &str) -> bool {
    path.split(['\\', '/']).filter(|s| !s.is_empty()).count() >= 2
}

/// The folded form everything is compared in: lower case, `/` as `\`, runs of `\` as one.
fn fold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut after_sep = false;
    for c in s.chars() {
        if c == '\\' || c == '/' {
            if !after_sep {
                out.push('\\');
            }
            after_sep = true;
            continue;
        }
        after_sep = false;
        if c.is_ascii() {
            out.push(c.to_ascii_lowercase());
        } else {
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// A compiled [`AnchorSet`], with the environment used to expand `%NAME%` references.
#[derive(Debug, Clone)]
pub struct RefMatcher {
    anchors: Vec<AnchorRef>,
    /// Sorted by text, so that all needles sharing a prefix are contiguous and a shorter needle comes
    /// before the longer ones it is a prefix of.
    needles: Vec<Needle>,
    /// For each first byte, the range of needles starting with it.
    first: Box<[(u32, u32); 256]>,
    /// Environment variables, names upper-cased.
    env: HashMap<String, String>,
}

/// A needle occurrence that passed its boundary rules.
#[derive(Debug, Clone, Copy)]
struct Hit {
    needle: u32,
    start: usize,
    end: usize,
    how: MatchHow,
}

impl RefMatcher {
    /// Compiles the set, without environment expansion.
    pub fn new(set: &AnchorSet) -> Self {
        Self::with_env(set, std::iter::empty::<(&str, &str)>())
    }

    /// Compiles the set with the (name, value) pairs of the interactive user's environment (§5.5).
    /// Names are case-insensitive.
    pub fn with_env<I, K, V>(set: &AnchorSet, env: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut needles = set.needles.clone();
        needles.sort_by(|a, b| {
            (a.text.as_bytes(), a.class, a.anchor).cmp(&(b.text.as_bytes(), b.class, b.anchor))
        });
        let mut first = Box::new([(0u32, 0u32); 256]);
        for (i, needle) in needles.iter().enumerate() {
            let slot = &mut first[usize::from(needle.text.as_bytes()[0])];
            if slot.0 == slot.1 {
                slot.0 = i as u32;
            }
            slot.1 = i as u32 + 1;
        }
        Self {
            anchors: set.anchors.clone(),
            needles,
            first,
            env: env
                .into_iter()
                .map(|(k, v)| (k.as_ref().to_uppercase(), v.as_ref().to_owned()))
                .collect(),
        }
    }

    /// The anchors this matcher looks for.
    pub fn anchors(&self) -> &[AnchorRef] {
        &self.anchors
    }

    /// Whether the string refers to any anchor.
    pub fn is_match(&self, s: &str) -> bool {
        self.find(s).is_some()
    }

    /// The strongest anchor the string refers to: an exe path before a root (the deepest root first),
    /// then ProgIDs, CLSIDs and AUMIDs, then tokens, then bare exe names.
    pub fn find(&self, s: &str) -> Option<RefMatch> {
        self.find_all(s).into_iter().next()
    }

    /// Every anchor the string refers to, strongest first (the order of [`RefMatcher::find`]); each
    /// anchor at most once, with its best match.
    pub fn find_all(&self, s: &str) -> Vec<RefMatch> {
        if self.needles.is_empty() || s.is_empty() {
            return Vec::new();
        }
        // At most two spellings are searched: as written, and with the environment expanded.
        let mut hays = vec![fold(s)];
        hays.extend(self.expand(s).map(|expanded| fold(&expanded)));
        let mut found: Vec<(usize, Hit)> = Vec::new();
        let mut hits = Vec::new();
        for (spelling, hay) in hays.iter().enumerate() {
            hits.clear();
            self.scan(hay, &mut hits);
            found.extend(hits.iter().map(|hit| (spelling, *hit)));
        }
        // Strongest class first; within a class the longest needle (the deepest root), then the
        // closest relation, the unexpanded spelling, the leftmost position.
        found.sort_by_key(|(spelling, hit)| {
            let needle = &self.needles[hit.needle as usize];
            (
                needle.class,
                std::cmp::Reverse(needle.text.len()),
                hit.how,
                *spelling,
                hit.start,
                needle.anchor,
            )
        });
        let mut out: Vec<RefMatch> = Vec::new();
        let mut seen: Vec<(u32, bool)> = Vec::new();
        for (spelling, hit) in found {
            let needle = &self.needles[hit.needle as usize];
            let (class, hay) = (needle.class, &hays[spelling]);
            let id = (needle.anchor, class == Class::FileName);
            if seen.contains(&id) {
                continue;
            }
            seen.push(id);
            out.push(RefMatch {
                anchor: self.anchors[needle.anchor as usize].clone(),
                how: hit.how,
                via_env: spelling > 0,
                name_only: class == Class::FileName,
                path: match class {
                    Class::File => Some(hay[hit.start..hit.end].to_owned()),
                    Class::Dir => Some(path_from(hay, hit.start, hit.end)),
                    _ => None,
                },
            });
        }
        out
    }

    /// Tests each segment of a `REG_MULTI_SZ` (or of any pre-split list); yields (segment index, match).
    pub fn find_in_segments<'a, I>(&self, segments: I) -> Vec<(usize, RefMatch)>
    where
        I: IntoIterator<Item = &'a str>,
    {
        segments
            .into_iter()
            .enumerate()
            .flat_map(|(i, seg)| self.find_all(seg).into_iter().map(move |m| (i, m)))
            .collect()
    }

    /// Tests the UTF-16 strings inside binary data (see [`utf16_runs`]). The caller bounds the data
    /// (§5.5: 4 KB per value). Each anchor is reported once.
    pub fn find_in_binary(&self, data: &[u8]) -> Vec<RefMatch> {
        let mut out: Vec<RefMatch> = Vec::new();
        for run in utf16_runs(data, MIN_BINARY_RUN) {
            for m in self.find_all(&run) {
                if !out
                    .iter()
                    .any(|o| o.anchor == m.anchor && o.name_only == m.name_only)
                {
                    out.push(m);
                }
            }
        }
        out
    }

    /// Expands `%NAME%` references the environment knows; `None` when nothing changed.
    fn expand(&self, s: &str) -> Option<String> {
        if self.env.is_empty() || !s.contains('%') {
            return None;
        }
        let mut out = String::with_capacity(s.len() + 32);
        let mut rest = s;
        let mut changed = false;
        while let Some(open) = rest.find('%') {
            out.push_str(&rest[..open]);
            let after = &rest[open + 1..];
            let value = after
                .find('%')
                .and_then(|close| Some((close, self.env.get(&after[..close].to_uppercase())?)));
            match value {
                Some((close, value)) => {
                    out.push_str(value);
                    rest = &after[close + 1..];
                    changed = true;
                }
                None => {
                    out.push('%');
                    rest = after;
                }
            }
        }
        out.push_str(rest);
        changed.then_some(out)
    }

    /// Finds every needle occurrence in a folded string that satisfies its boundary rules.
    fn scan(&self, hay: &str, hits: &mut Vec<Hit>) {
        let bytes = hay.as_bytes();
        let (whole_start, whole_end) = whole_span(hay);
        for start in 0..bytes.len() {
            let (lo, hi) = self.first[usize::from(bytes[start])];
            let (mut lo, mut hi) = (lo as usize, hi as usize);
            // Invariant: needles[lo..hi] are exactly those whose first `depth` bytes equal
            // bytes[start..start + depth]; those of length `depth` come first in the range.
            let mut depth = 1;
            while lo < hi {
                while lo < hi && self.needles[lo].text.len() == depth {
                    let end = start + depth;
                    if let Some(how) = boundary(self.needles[lo].class, hay, start, end) {
                        let how = if (start, end) == (whole_start, whole_end) {
                            MatchHow::Whole
                        } else {
                            how
                        };
                        hits.push(Hit {
                            needle: lo as u32,
                            start,
                            end,
                            how,
                        });
                    }
                    lo += 1;
                }
                let Some(&next) = bytes.get(start + depth) else {
                    break;
                };
                let range = &self.needles[lo..hi];
                let from = range.partition_point(|n| n.text.as_bytes()[depth] < next);
                let to = range.partition_point(|n| n.text.as_bytes()[depth] <= next);
                (lo, hi) = (lo + from, lo + to);
                depth += 1;
            }
        }
    }
}

/// The span of `hay` without surrounding white space and one pair of double quotes.
fn whole_span(hay: &str) -> (usize, usize) {
    let trimmed = hay.trim();
    let start = hay.len() - hay.trim_start().len();
    let inner = trimmed
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .filter(|_| trimmed.len() >= 2);
    match inner {
        Some(inner) => (start + 1, start + 1 + inner.len()),
        None => (start, start + trimmed.len()),
    }
}

const MUI_SUFFIXES: [&str; 2] = [".friendlyappname", ".applicationcompany"];

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '-' | '_')
}

/// `,0`, `,-101`: an icon index up to the end of the string or a closing quote.
fn is_icon_index(rest: &str) -> bool {
    let Some(digits) = rest.strip_prefix(',') else {
        return false;
    };
    let digits = digits.trim_start_matches(' ');
    let digits = digits.strip_prefix('-').unwrap_or(digits);
    let n = digits.bytes().take_while(u8::is_ascii_digit).count();
    n > 0 && matches!(digits[n..].trim_start().chars().next(), None | Some('"'))
}

/// Whether a root or exe-path needle may start at `start`: not inside a word, and, when the needle
/// itself starts with a separator (a UNC path), not in the middle of another path.
fn path_start(hay: &str, start: usize, before: Option<char>) -> bool {
    match before {
        None => true,
        Some(c) if hay[start..].starts_with('\\') => {
            c.is_whitespace() || matches!(c, '"' | '\'' | ';' | ',' | '=' | '|' | '<' | '>' | '(')
        }
        Some(c) => !c.is_alphanumeric(),
    }
}

/// Whether the path continuing below a root (up to where a quoted or listed path ends) has a `..`
/// segment, i.e. may leave the root again. A segment made of dots only counts (Win32 drops trailing
/// dots and spaces).
fn steps_back(below: &str) -> bool {
    let end = below
        .find(['"', ';', '|', '<', '>', '*', '?', '\0', '\r', '\n'])
        .unwrap_or(below.len());
    below[..end].split('\\').any(|segment| {
        let segment = segment.trim();
        segment.len() >= 2 && segment.bytes().all(|b| b == b'.')
    })
}

/// The first segments of a registry path as values spell them (folded). `\Registry\Machine\…`
/// and `\Registry\User\…`, the one spelling that starts with a separator, are tested apart.
const REGISTRY_ROOTS: [&str; 8] = [
    "hklm", "hkcu", "hkcr", "hku", "hkcc", "software", "system", "classes",
];

/// Whether the folded `piece` holds a drive path (`x:\` or `x:/`) anywhere.
fn holds_drive_path(piece: &str) -> bool {
    piece
        .as_bytes()
        .windows(3)
        .any(|w| w[0].is_ascii_alphabetic() && w[1] == b':' && matches!(w[2], b'\\' | b'/'))
}

/// Whether the id at `start..end` of the folded `hay` stands inside a file path: the piece of text
/// around it (between the characters that end a quoted or listed path) has a separator and is not a
/// registry path, a `shell:` name or a URL of the id's own scheme. See the module documentation.
fn in_file_path(hay: &str, start: usize, end: usize) -> bool {
    const ENDS: [char; 11] = ['"', ';', '|', '<', '>', '*', '?', '\0', '\t', '\r', '\n'];
    // `… vscode://file/…`: the id is the scheme. The text is folded, so `://` reads `:\` here and
    // `/opt/vscode:/usr/bin` looks the same after the id: what tells them apart is that a scheme
    // does not stand directly after a separator.
    if hay[end..].starts_with(":\\") && !hay[..start].ends_with('\\') {
        return false;
    }
    let from = hay[..start].rfind(ENDS).map_or(0, |at| at + 1);
    let to = hay[end..].find(ENDS).map_or(hay.len(), |at| end + at);
    let before = hay[from..start].trim_start();
    // `vscode:x`: a scheme only where the piece starts with it. After anything else the `:` is
    // part of a path (`C:\Tools\vscode:stream`) or of a sentence.
    if before.is_empty() && hay[end..].starts_with(':') {
        return false;
    }
    let piece = hay[from..to].trim_start();
    if !piece.contains(['\\', '/']) {
        return false;
    }
    if piece.starts_with("shell:") {
        return false;
    }
    // A key path holds no drive path, and nothing shows what a `%NAME%` in front of the id stands
    // for.
    if holds_drive_path(piece) || before.contains('%') {
        return true;
    }
    // With a separator in front it is a UNC path or a folder at the root of a drive, unless it is
    // the kernel's spelling of a key.
    if piece.starts_with('\\') {
        return !(piece.starts_with("\\registry\\machine\\")
            || piece.starts_with("\\registry\\user\\"));
    }
    let first = piece.split('\\').next().unwrap_or("");
    !(first.starts_with("hkey_") || REGISTRY_ROOTS.contains(&first))
}

/// Applies the boundary rules of the module documentation to a needle found at `start..end`.
fn boundary(class: Class, hay: &str, start: usize, end: usize) -> Option<MatchHow> {
    let before = hay[..start].chars().next_back();
    let rest = &hay[end..];
    let after = rest.chars().next();
    let file_end = || {
        matches!(
            after,
            None | Some('"' | ',' | ';' | '|' | '<' | '>' | '*' | '?' | ':' | '\0')
        ) || after.is_some_and(char::is_whitespace)
            || MUI_SUFFIXES.contains(&rest)
    };
    let ok = match class {
        Class::Clsid => true,
        Class::Token => !before.is_some_and(is_ident_char) && !after.is_some_and(is_ident_char),
        Class::Ident => {
            !before.is_some_and(is_ident_char)
                && !after.is_some_and(is_ident_char)
                && !in_file_path(hay, start, end)
        }
        Class::File => path_start(hay, start, before) && file_end(),
        Class::FileName => {
            let left = match before {
                None => true,
                Some(c) => {
                    c.is_whitespace()
                        || matches!(
                            c,
                            '\\' | '"' | '\'' | ';' | ',' | '=' | '|' | '<' | '>' | ':' | '*' | '?'
                        )
                }
            };
            left && file_end()
        }
        Class::Dir => {
            if !path_start(hay, start, before) {
                return None;
            }
            return match after {
                None | Some('"' | ';' | '|' | '<' | '>' | '*' | '?' | '\0') => {
                    Some(MatchHow::Embedded)
                }
                Some('\\') => {
                    // `C:\X\` and `C:\X\"` still name the root itself.
                    let below = rest[1..].chars().next();
                    if matches!(below, None | Some('"' | ';' | '|')) {
                        Some(MatchHow::Embedded)
                    } else if steps_back(&rest[1..]) {
                        // `<root>\..\elsewhere` does not point into the root.
                        None
                    } else {
                        Some(MatchHow::Below)
                    }
                }
                Some(',') if is_icon_index(rest) => Some(MatchHow::Embedded),
                Some(c) if c.is_whitespace() => {
                    matches!(rest.trim_start().chars().next(), None | Some('"'))
                        .then_some(MatchHow::Embedded)
                }
                _ => None,
            };
        }
    };
    ok.then_some(MatchHow::Embedded)
}

/// The path a root match names: from the root's start to where the path most plausibly ends.
fn path_from(hay: &str, start: usize, end: usize) -> String {
    let quoted = hay[..start].ends_with('"');
    let tail = &hay[end..];
    let mut stop = tail
        .find(['"', ';', '|', '<', '>', '*', '?', '\0', '\t', '\r', '\n'])
        .unwrap_or(tail.len());
    if !quoted {
        // Unquoted: arguments start at white space followed by a switch, a placeholder or another
        // absolute path. (`/` was folded to `\`, and no path segment starts with white space.)
        let bytes = tail.as_bytes();
        for i in 0..stop.saturating_sub(1) {
            let drive = bytes[i + 1].is_ascii_alphabetic() && bytes.get(i + 2) == Some(&b':');
            if bytes[i] == b' ' && (drive || matches!(bytes[i + 1], b'-' | b'\\' | b'%' | b' ')) {
                stop = i;
                break;
            }
        }
    }
    // A colon cannot occur below a root: what follows is a stream name or another path.
    stop = tail[..stop].find(':').unwrap_or(stop);
    let mut path = &hay[start..end + stop];
    if let Some(comma) = path.rfind(',') {
        if comma >= end - start && is_icon_index(&path[comma..]) {
            path = &path[..comma];
        }
    }
    path = path.trim_end().trim_end_matches('\\');
    for suffix in MUI_SUFFIXES {
        if let Some(stripped) = path.strip_suffix(suffix) {
            if stripped.len() > end - start {
                path = stripped;
            }
        }
    }
    path.to_owned()
}

/// The shortest UTF-16 run [`RefMatcher::find_in_binary`] looks at.
pub const MIN_BINARY_RUN: usize = 4;

/// The UTF-16LE strings inside binary data: maximal runs of at least `min_chars` code units that are
/// printable characters, at either byte alignment. Surrogates and control characters end a run.
pub fn utf16_runs(data: &[u8], min_chars: usize) -> Vec<String> {
    let mut runs = Vec::new();
    for offset in 0..2.min(data.len()) {
        let mut current = String::new();
        let mut count = 0usize;
        let mut flush = |current: &mut String, count: &mut usize| {
            if *count >= min_chars.max(1) {
                runs.push(std::mem::take(current));
            } else {
                current.clear();
            }
            *count = 0;
        };
        for pair in data[offset..].chunks_exact(2) {
            let unit = u16::from_le_bytes([pair[0], pair[1]]);
            match char::from_u32(u32::from(unit)) {
                // Private-use and non-characters do not occur in paths or identifiers; treating them
                // as breaks keeps random binary from forming long runs.
                Some(c)
                    if !c.is_control()
                        && !('\u{e000}'..='\u{f8ff}').contains(&c)
                        && unit < 0xfff0 =>
                {
                    current.push(c);
                    count += 1;
                }
                _ => flush(&mut current, &mut count),
            }
        }
        flush(&mut current, &mut count);
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIT: &str = r"C:\Program Files\Git";
    const FIREFOX: &str = r"C:\Program Files\Mozilla Firefox";
    const FIREFOX_EXE: &str = r"C:\Program Files\Mozilla Firefox\firefox.exe";
    const FIREFOX_HASH: &str = "308046B0AF4A39CB";
    const CODE: &str = r"C:\Users\kim\AppData\Local\Programs\Microsoft VS Code";
    const CODE_EXE: &str = r"C:\Users\kim\AppData\Local\Programs\Microsoft VS Code\Code.exe";

    fn git() -> RefMatcher {
        let mut set = AnchorSet::new();
        assert!(set.add_root(GIT));
        assert!(set.add_root_alias(GIT, r"C:\PROGRA~1\Git"));
        assert!(set.add_exe_path(r"C:\Program Files\Git\git-bash.exe"));
        assert!(set.add_exe_name("git-bash.exe"));
        assert!(set.add_progid("git_shell"));
        assert!(set.add_clsid("ca586c7f-7c84-4b88-8537-726724df6929"));
        RefMatcher::with_env(
            &set,
            [
                ("ProgramFiles", r"C:\Program Files"),
                ("SystemDrive", "C:"),
                ("GIT_HOME", r"C:\Program Files\Git\"),
            ],
        )
    }

    fn firefox() -> RefMatcher {
        let mut set = AnchorSet::new();
        set.add_root(FIREFOX);
        set.add_exe_path(FIREFOX_EXE);
        set.add_exe_name("firefox.exe");
        set.add_progid("FirefoxHTML-308046B0AF4A39CB");
        set.add_progid("FirefoxURL-308046B0AF4A39CB");
        set.add_aumid(FIREFOX_HASH);
        set.add_token(FIREFOX_HASH);
        RefMatcher::new(&set)
    }

    fn vscode() -> RefMatcher {
        let mut set = AnchorSet::new();
        set.add_root(CODE);
        set.add_exe_path(CODE_EXE);
        for progid in ["VSCode.txt", "VSCode.py", "VSCodeSourceFile"] {
            set.add_progid(progid);
        }
        set.add_aumid("Microsoft.VisualStudioCode");
        RefMatcher::new(&set)
    }

    fn kinds(m: &RefMatcher, s: &str) -> Vec<(AnchorKind, MatchHow)> {
        m.find_all(s)
            .into_iter()
            .map(|m| (m.anchor.kind, m.how))
            .collect()
    }

    fn root_of(m: &RefMatcher, s: &str) -> Option<RefMatch> {
        m.find_all(s)
            .into_iter()
            .find(|m| m.anchor.kind == AnchorKind::Root)
    }

    #[test]
    fn root_positive_table() {
        let m = git();
        let cases: &[(&str, MatchHow, &str)] = &[
            (
                r"C:\Program Files\Git",
                MatchHow::Whole,
                r"c:\program files\git",
            ),
            (
                r"c:\PROGRAM FILES\git",
                MatchHow::Whole,
                r"c:\program files\git",
            ),
            (
                r"C:\Program Files\Git\",
                MatchHow::Embedded,
                r"c:\program files\git",
            ),
            (
                r#""C:\Program Files\Git""#,
                MatchHow::Whole,
                r"c:\program files\git",
            ),
            (
                r"  C:\Program Files\Git  ",
                MatchHow::Whole,
                r"c:\program files\git",
            ),
            (
                r"C:\Program Files\Git\cmd",
                MatchHow::Below,
                r"c:\program files\git\cmd",
            ),
            (
                "C:/Program Files/Git/cmd",
                MatchHow::Below,
                r"c:\program files\git\cmd",
            ),
            (
                r"C:\\Program Files\\Git\\cmd",
                MatchHow::Below,
                r"c:\program files\git\cmd",
            ),
            (
                r"\\?\C:\Program Files\Git\cmd",
                MatchHow::Below,
                r"c:\program files\git\cmd",
            ),
            (
                r#""C:\Program Files\Git\bin\bash.exe" --login -i "%1""#,
                MatchHow::Below,
                r"c:\program files\git\bin\bash.exe",
            ),
            (
                r"C:\Program Files\Git\usr\bin\gpg.exe --batch /S %1",
                MatchHow::Below,
                r"c:\program files\git\usr\bin\gpg.exe",
            ),
            (
                r"C:\Program Files\Git\mingw64\share\git\git-for-windows.ico,0",
                MatchHow::Below,
                r"c:\program files\git\mingw64\share\git\git-for-windows.ico",
            ),
            (
                r#""C:\Program Files\Git\mingw64\bin\x.dll",-101"#,
                MatchHow::Below,
                r"c:\program files\git\mingw64\bin\x.dll",
            ),
            (
                r"C:\Program Files\Git,0",
                MatchHow::Embedded,
                r"c:\program files\git",
            ),
            (
                r"C:\Windows;C:\Program Files\Git\cmd;C:\Tools",
                MatchHow::Below,
                r"c:\program files\git\cmd",
            ),
            (
                r"C:\Windows;C:\Program Files\Git",
                MatchHow::Embedded,
                r"c:\program files\git",
            ),
            (
                r"rundll32.exe shell32.dll,X C:\Program Files\Git\a b\c.txt",
                MatchHow::Below,
                r"c:\program files\git\a b\c.txt",
            ),
            (
                r"file:///C:/Program Files/Git/ReleaseNotes.html",
                MatchHow::Below,
                r"c:\program files\git\releasenotes.html",
            ),
            // The 8.3 alias the caller supplied reports the root itself.
            (
                r"C:\PROGRA~1\Git\cmd\git.exe",
                MatchHow::Below,
                r"c:\progra~1\git\cmd\git.exe",
            ),
        ];
        for (input, how, path) in cases {
            let hit = root_of(&m, input).unwrap_or_else(|| panic!("no root match for {input:?}"));
            assert_eq!(hit.anchor.text, GIT, "{input:?}");
            assert_eq!(hit.how, *how, "{input:?}");
            assert_eq!(hit.path.as_deref(), Some(*path), "{input:?}");
            assert!(!hit.via_env && !hit.name_only, "{input:?}");
        }
    }

    /// A path that steps back out of the root is not a reference into it.
    #[test]
    fn root_with_parent_steps_is_not_below() {
        let m = git();
        for input in [
            r"C:\Program Files\Git\..\GitHub\gh.exe",
            r"C:\Program Files\Git\..",
            r"C:\Program Files\Git\..\",
            r#""C:\Program Files\Git\cmd\..\..\Other App\x.exe" --run"#,
            "C:/Program Files/Git/../../Windows/System32/cmd.exe",
            r"C:\Program Files\Git\.. \x",
            r"C:\Program Files\Git\...\x",
            r"%ProgramFiles%\Git\..\Other",
            r"C:\Tools;C:\Program Files\Git\..\Other",
        ] {
            assert_eq!(root_of(&m, input), None, "{input:?}");
        }
        // Dots inside a name, a `.` segment, and `..` in a later list item or argument are harmless.
        for input in [
            r"C:\Program Files\Git\a..b\x",
            r"C:\Program Files\Git\.\cmd",
            r"C:\Program Files\Git\..config",
            r"C:\Program Files\Git\cmd;C:\Other\..\x",
            r#""C:\Program Files\Git\bin\bash.exe" ..\x"#,
        ] {
            assert_eq!(
                root_of(&m, input).map(|m| m.how),
                Some(MatchHow::Below),
                "{input:?}"
            );
        }
    }

    /// A UNC root (folded to one leading separator) is not found in the middle of a local path.
    #[test]
    fn unc_root_needs_a_path_start() {
        let mut set = AnchorSet::new();
        assert!(set.add_root(r"\\srv\apps\Foo"));
        assert!(set.add_exe_path(r"\\srv\apps\Foo\foo.exe"));
        let m = RefMatcher::new(&set);
        for input in [
            r"\\srv\apps\Foo\bin",
            r"\\SRV\Apps\Foo\foo.exe",
            r#""\\srv\apps\Foo\foo.exe" -x"#,
            r"C:\Tools;\\srv\apps\Foo\bin",
            r"cmd /c \\srv\apps\Foo\foo.exe",
        ] {
            assert!(m.is_match(input), "{input:?}");
        }
        for input in [
            r"D:\srv\apps\Foo\bin",
            r"D:\srv\apps\Foo\foo.exe",
            r"\\other\srv\apps\Foo\foo.exe",
            r"\\srv2\apps\Foo",
            r"C:\data.\srv\apps\Foo\foo.exe",
        ] {
            assert_eq!(m.find(input), None, "{input:?}");
        }
    }

    #[test]
    fn short_tokens_are_refused() {
        let mut set = AnchorSet::new();
        assert!(!set.add_token(""));
        assert!(!set.add_token("a"));
        assert!(!set.add_token("{abc}"));
        assert!(!set.add_token("308046B0AF4"));
        assert!(set.is_empty());
        assert!(set.add_token("308046B0AF4A"));
        assert!(set.add_token("{EC8030F7-C20A-464F-9B0E-13A3A9E97384}"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn root_near_misses() {
        let m = git();
        for input in [
            r"C:\Program Files\GitHub",
            r"C:\Program Files\GitHub\bin\gh.exe",
            r"C:\Program Files\Git Extensions\GitExtensions.exe",
            r"C:\Program Files\Git2\cmd",
            r"C:\Program Files\Git.old\cmd",
            r"C:\Program Files\Git-2.47\cmd",
            r"C:\Program Files\Git_backup",
            r"C:\Program Files\Git, Inc\app.exe",
            r"C:\Program Files\Git's\x",
            r"C:\Program Files (x86)\Git\cmd",
            r"C:\Program Files\Gi",
            r"C:\Program Files",
            r"D:\Program Files\Git\cmd",
            r"XC:\Program Files\Git\cmd",
            r"C:\Program Files\Git -x",
            r"C:\PROGRA~2\Git\cmd",
            "git",
            "",
        ] {
            assert_eq!(root_of(&m, input), None, "{input:?}");
            assert_eq!(m.find(input), None, "{input:?}");
        }
    }

    #[test]
    fn environment_is_expanded_and_also_compared_unexpanded() {
        let m = git();
        let hit = m.find(r"%ProgramFiles%\Git\cmd\git.exe").unwrap();
        assert_eq!(
            (hit.anchor.kind, hit.how, hit.via_env),
            (AnchorKind::Root, MatchHow::Below, true)
        );
        assert_eq!(
            hit.path.as_deref(),
            Some(r"c:\program files\git\cmd\git.exe")
        );

        let hit = m
            .find(r#""%PROGRAMFILES%\Git\git-bash.exe" --cd=%1"#)
            .unwrap();
        assert_eq!((hit.anchor.kind, hit.via_env), (AnchorKind::Exe, true));
        assert_eq!(hit.anchor.text, r"C:\Program Files\Git\git-bash.exe");

        // A variable whose value ends in a separator, and two variables in one string.
        assert_eq!(m.find(r"%GIT_HOME%\cmd").unwrap().how, MatchHow::Below);
        assert_eq!(
            m.find(r"%systemdrive%\Program Files\Git").unwrap().how,
            MatchHow::Whole
        );

        // Already literal: found without expansion, even with an unknown or stray `%`.
        let hit = m
            .find(r"C:\Program Files\Git\cmd\git.exe %1 %UNKNOWN%")
            .unwrap();
        assert!(!hit.via_env);
        assert!(!m.find(r"100% C:\Program Files\Git").unwrap().via_env);

        // Unknown variables stay as written and match nothing.
        assert_eq!(m.find(r"%ProgramW6432%\Git\cmd"), None);
        assert_eq!(m.find(r"%ProgramFiles%\GitHub"), None);
        // Without an environment the reference is opaque.
        let mut set = AnchorSet::new();
        set.add_root(GIT);
        assert_eq!(RefMatcher::new(&set).find(r"%ProgramFiles%\Git\cmd"), None);
    }

    #[test]
    fn exe_paths_and_names() {
        let m = git();
        let exe = r"C:\Program Files\Git\git-bash.exe";
        for (input, how) in [
            (exe, MatchHow::Whole),
            (r#""C:\Program Files\Git\git-bash.exe""#, MatchHow::Whole),
            (
                r#""C:\Program Files\Git\git-bash.exe" "--cd=%1""#,
                MatchHow::Embedded,
            ),
            (
                r"C:\Program Files\Git\git-bash.exe --cd=%1",
                MatchHow::Embedded,
            ),
            (r"C:\Program Files\Git\git-bash.exe,0", MatchHow::Embedded),
            (
                r"C:\Program Files\Git\git-bash.exe.FriendlyAppName",
                MatchHow::Embedded,
            ),
            (
                r"C:\Program Files\Git\git-bash.exe.ApplicationCompany",
                MatchHow::Embedded,
            ),
            (
                r"C:\Program Files\Git\git-bash.exe:Zone.Identifier",
                MatchHow::Embedded,
            ),
        ] {
            let all = m.find_all(input);
            let best = &all[0];
            assert_eq!(
                (best.anchor.kind, best.anchor.text.as_str()),
                (AnchorKind::Exe, exe),
                "{input:?}"
            );
            assert_eq!(best.how, how, "{input:?}");
            assert!(!best.name_only, "{input:?}");
            assert_eq!(
                best.path.as_deref(),
                Some(r"c:\program files\git\git-bash.exe"),
                "{input:?}"
            );
            // The root and the bare name are reported after it.
            assert_eq!(all[1].anchor.kind, AnchorKind::Root, "{input:?}");
            assert_eq!(
                all[1].path.as_deref(),
                Some(r"c:\program files\git\git-bash.exe"),
                "{input:?}"
            );
            assert!(all[2].name_only, "{input:?}");
        }
        // Not this file.
        for input in [
            r"C:\Program Files\Git\git-bash.exe.config",
            r"C:\Program Files\Git\git-bash.exe.bak",
            r"C:\Program Files\Git\git-bash.exe2",
        ] {
            assert_eq!(
                m.find(input).unwrap().anchor.kind,
                AnchorKind::Root,
                "{input:?}"
            );
            assert!(
                m.find_all(input)
                    .iter()
                    .all(|m| m.anchor.kind != AnchorKind::Exe),
                "{input:?}"
            );
        }

        // The bare name, elsewhere.
        for input in [
            "git-bash.exe",
            r"D:\Portable\git-bash.exe",
            r#""git-bash.exe" --login"#,
            "open=GIT-BASH.EXE",
        ] {
            let hit = m.find(input).unwrap();
            assert_eq!(
                (hit.anchor.kind, hit.anchor.text.as_str()),
                (AnchorKind::Exe, "git-bash.exe"),
                "{input:?}"
            );
            assert!(hit.name_only, "{input:?}");
            assert_eq!(hit.path, None);
        }
        for input in [
            "mygit-bash.exe",
            "git-bash.exe.config",
            "git-bash.exec",
            "x.git-bash.exe",
            "git-bash",
        ] {
            assert_eq!(m.find(input), None, "{input:?}");
        }
    }

    #[test]
    fn progids_clsids_and_aumids() {
        let m = git();
        assert_eq!(
            kinds(&m, "git_shell"),
            [(AnchorKind::ProgId, MatchHow::Whole)]
        );
        assert_eq!(
            kinds(&m, "GIT_SHELL"),
            [(AnchorKind::ProgId, MatchHow::Whole)]
        );
        assert_eq!(
            kinds(&m, r"Software\Classes\git_shell\shell\open"),
            [(AnchorKind::ProgId, MatchHow::Embedded)]
        );
        for input in [
            "git_shell2",
            "my.git_shell",
            "git_shell.1",
            "git_shell_.sh",
            "xgit_shell",
            "git-git_shell",
        ] {
            assert_eq!(m.find(input), None, "{input:?}");
        }
        assert_eq!(
            kinds(&m, "{CA586C7F-7C84-4B88-8537-726724DF6929}"),
            [(AnchorKind::Clsid, MatchHow::Whole)]
        );
        let hit = m
            .find("clsid:{ca586c7f-7c84-4b88-8537-726724df6929}.1")
            .unwrap();
        assert_eq!(
            (hit.anchor.kind, hit.how),
            (AnchorKind::Clsid, MatchHow::Embedded)
        );
        assert_eq!(hit.anchor.text, "{ca586c7f-7c84-4b88-8537-726724df6929}");
        assert_eq!(m.find("{CA586C7F-7C84-4B88-8537-726724DF6920}"), None);
        // Without braces it is not a CLSID reference.
        assert_eq!(m.find("CA586C7F-7C84-4B88-8537-726724DF6929"), None);

        // A registry path names the registration; a file path with a folder of that name does not
        // (rig run x1-vscode-userstate: the user's own copy in `…\Tools\VSCode`).
        let mut set = AnchorSet::new();
        set.add_progid("vscode");
        set.add_aumid("Microsoft.VisualStudioCode");
        let url = RefMatcher::new(&set);
        for input in [
            "vscode",
            r"Software\Classes\vscode\shell\open\command",
            r"HKEY_CURRENT_USER\Software\Classes\vscode",
            "vscode://file/x",
            r"shell:AppsFolder\Microsoft.VisualStudioCode",
        ] {
            assert!(url.find(input).is_some(), "{input:?}");
        }
        for input in [
            r#""C:\Users\tester\Tools\VSCode\Code.exe" "%1""#,
            r"C:\Users\tester\Tools\VSCode",
            r"D:/portable/vscode/bin",
            r"%USERPROFILE%\vscode\Code.exe",
            r"\\srv\share\vscode\Code.exe",
            r#"cmd /c "D:\Apps\vscode\code.cmd""#,
            // Not directly after a separator, or not in an absolute path.
            r"C:\Tools\My VSCode\Code.exe",
            r"C:\Tools\(vscode)\Code.exe",
            r"C:\Tools\apps,vscode\Code.exe",
            r"Tools\vscode\Code.exe",
            r"..\vscode\Code.exe",
            r".\vscode\Code.exe",
            r"C:vscode\Code.exe",
            r"~\vscode\Code.exe",
            r"$env:LOCALAPPDATA\vscode\Code.exe",
            r"C:\Tools\a;b\vscode\Code.exe",
            r"C:\Tools\vscode",
            r"vscode\Code.exe",
            // A `:` after the id is a scheme only at the start of the piece or as `://`.
            r"C:\Tools\vscode:stream",
            "/opt/vscode:/usr/bin",
            r"D:\x\vscode: failed to start",
            r"C:\Tools\vscode://x",
            r"D:\x\run.exe vscode: failed to start",
            // A separator in front: a UNC path or a folder at the root of a drive, whatever the
            // first name is.
            r"\Software\Stuff\vscode\readme.txt",
            r"\Software\Classes\vscode",
            r"\\software\share\vscode\Code.exe",
            r"\\system\c$\vscode\x.exe",
            r"\\registry\share\vscode\x.exe",
            r"\registry",
            r"\HKLM\Software\vscode",
            "//software/share/vscode/x",
            // A root word in front of what is a file path all the same.
            r"software\%x%\vscode",
            r"HKLM\Software\X\C:\Tools\vscode\Code.exe",
            r"HKLM\Software\X\C:/Tools/vscode/Code.exe",
        ] {
            assert_eq!(url.find(input), None, "{input:?}");
        }
        // A scheme at the start of its piece, or followed by `://` anywhere.
        for input in [
            "vscode:",
            "vscode:x",
            r#""vscode:%1""#,
            " vscode:x",
            r"vscode:\x",
            r"C:\Tools\run.exe vscode://file/x",
            r"C:\Tools\run.exe --url=vscode://file/x",
        ] {
            assert!(url.find(input).is_some(), "{input:?}");
        }
        // Registry paths in every spelling values use.
        for input in [
            r"\Registry\Machine\Software\Classes\vscode",
            r"\REGISTRY\USER\S-1-5-21-1-2-3-1001\Software\Classes\vscode",
            r"Software\Classes\vscode",
            r"Software\Classes\vscode\100%",
            // Relative, and nothing tells it from a key path (see the module documentation).
            r"Software\Tools\vscode\Code.exe",
            r"HKEY_CLASSES_ROOT\vscode\shell\open\command",
            r"HKCR\vscode",
            r"Classes\vscode\shell",
            r"SYSTEM\CurrentControlSet\Services\vscode",
        ] {
            assert!(url.find(input).is_some(), "{input:?}");
        }
        // Two things in one text are judged each at its own place.
        assert!(
            url.find(r#""C:\Tools\VSCode\Code.exe" --open-url vscode"#)
                .is_some()
        );

        let code = vscode();
        assert_eq!(
            kinds(&code, "Microsoft.VisualStudioCode"),
            [(AnchorKind::Aumid, MatchHow::Whole)]
        );
        assert_eq!(code.find("Microsoft.VisualStudioCode.Insiders"), None);
        assert_eq!(code.find("Microsoft.VisualStudioCodeInsiders"), None);
        assert_eq!(
            kinds(&code, "Microsoft.VisualStudioCode!App"),
            [(AnchorKind::Aumid, MatchHow::Embedded)]
        );
    }

    #[test]
    fn token_is_a_whole_segment() {
        let mut set = AnchorSet::new();
        set.add_token(FIREFOX_HASH);
        set.add_token("EC8030F7-C20A-464F-9B0E-13A3A9E97384");
        let m = RefMatcher::new(&set);
        for (input, how) in [
            ("308046B0AF4A39CB", MatchHow::Whole),
            ("308046b0af4a39cb", MatchHow::Whole),
            (
                r"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB",
                MatchHow::Embedded,
            ),
            (
                r"C:\ProgramData\Mozilla\updates\308046B0AF4A39CB\update.status",
                MatchHow::Embedded,
            ),
            (
                "Software/Mozilla/Firefox/308046B0AF4A39CB",
                MatchHow::Embedded,
            ),
            ("id=308046B0AF4A39CB;other", MatchHow::Embedded),
            ("{EC8030F7-C20A-464F-9B0E-13A3A9E97384}", MatchHow::Embedded),
            // Braces delimit a segment: an Inno ARP key name carries the AppId GUID.
            (
                "{EC8030F7-C20A-464F-9B0E-13A3A9E97384}_is1",
                MatchHow::Embedded,
            ),
            ("ec8030f7-c20a-464f-9b0e-13a3a9e97384", MatchHow::Whole),
        ] {
            let hit = m
                .find(input)
                .unwrap_or_else(|| panic!("no token match for {input:?}"));
            assert_eq!(
                (hit.anchor.kind, hit.how),
                (AnchorKind::Token, how),
                "{input:?}"
            );
        }
        for input in [
            // Longer hex runs.
            "308046B0AF4A39CB0",
            "A308046B0AF4A39CB",
            "00308046B0AF4A39CBFF",
            "308046B0AF4A39CB308046B0AF4A39CB",
            // Part of a longer name.
            "FirefoxURL-308046B0AF4A39CB",
            "UpdateLock-308046B0AF4A39CB",
            "308046B0AF4A39CB.ini",
            "308046B0AF4A39CB_1",
            "308046B0AF4A39C",
            "EC8030F7-C20A-464F-9B0E-13A3A9E97384_is1",
            "1-EC8030F7-C20A-464F-9B0E-13A3A9E97384",
        ] {
            assert_eq!(m.find(input), None, "{input:?}");
        }
    }

    /// §5.5 golden: `HKCU\Software\Mozilla\Firefox\TaskBarIDs` has a value NAMED by the install
    /// directory whose data is the install hash.
    #[test]
    fn golden_firefox_taskbar_ids_value_name() {
        let m = firefox();
        let name = m.find(r"C:\Program Files\Mozilla Firefox").unwrap();
        assert_eq!(
            name.anchor,
            AnchorRef {
                kind: AnchorKind::Root,
                text: FIREFOX.into()
            }
        );
        assert_eq!(name.how, MatchHow::Whole);

        let data = m.find_all("308046B0AF4A39CB");
        assert_eq!(
            data.iter()
                .map(|m| (m.anchor.kind, m.how))
                .collect::<Vec<_>>(),
            [
                (AnchorKind::Aumid, MatchHow::Whole),
                (AnchorKind::Token, MatchHow::Whole)
            ]
        );
        // Thunderbird's entry in the same key is not ours.
        assert_eq!(m.find(r"C:\Program Files\Mozilla Thunderbird"), None);
        assert_eq!(m.find("D78BF5DD33499EC2"), None);
    }

    /// §5.5 golden: `HKCU\Software\Mozilla\Firefox\Launcher` value NAMES are `<exe path>|<suffix>`.
    #[test]
    fn golden_firefox_launcher_value_names() {
        let m = firefox();
        for suffix in ["Browser", "Image", "Telemetry", "Blocklist"] {
            let name = format!(r"C:\Program Files\Mozilla Firefox\firefox.exe|{suffix}");
            let all = m.find_all(&name);
            assert_eq!(
                all.iter()
                    .map(|m| (m.anchor.kind, m.how, m.name_only))
                    .collect::<Vec<_>>(),
                [
                    (AnchorKind::Exe, MatchHow::Embedded, false),
                    (AnchorKind::Root, MatchHow::Below, false),
                    (AnchorKind::Exe, MatchHow::Embedded, true),
                ],
                "{name}"
            );
            assert_eq!(all[0].anchor.text, FIREFOX_EXE);
            assert_eq!(
                all[1].path.as_deref(),
                Some(r"c:\program files\mozilla firefox\firefox.exe")
            );
        }
        assert_eq!(
            m.find(r"C:\Program Files\Mozilla Thunderbird\thunderbird.exe|Browser"),
            None
        );
        // A Firefox installed elsewhere shares only the exe name.
        let other = m.find(r"D:\Nightly\firefox.exe|Browser").unwrap();
        assert!(other.name_only);
    }

    /// §5.5 golden: VS Code registers under `.ext\OpenWithProgids` values NAMED by its ProgIDs, with
    /// empty data.
    #[test]
    fn golden_vscode_openwithprogids_names_with_empty_data() {
        let m = vscode();
        for name in ["VSCode.txt", "VSCode.py", "vscode.TXT", "VSCodeSourceFile"] {
            let hit = m.find(name).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(
                (hit.anchor.kind, hit.how),
                (AnchorKind::ProgId, MatchHow::Whole),
                "{name}"
            );
            assert_eq!(hit.path, None);
        }
        assert_eq!(m.find("VSCode.txt").unwrap().anchor.text, "VSCode.txt");
        // The data of those values is empty.
        assert_eq!(m.find(""), None);
        assert!(m.find_all("").is_empty());
        // Other apps' values in the same key, and near-miss names.
        for name in [
            "txtfile",
            "Applications\\notepad++.exe",
            "VSCode.tx",
            "VSCode.txt2",
            "VSCode.txtx",
            "VSCode",
            "XVSCode.txt",
            "VSCodeInsiders.txt",
            "VSCode.txt_.txt",
        ] {
            assert_eq!(m.find(name), None, "{name}");
        }
    }

    /// §5.5 golden: MuiCache value names are `<exe path>.FriendlyAppName` / `.ApplicationCompany`.
    #[test]
    fn golden_muicache_value_name() {
        let m = vscode();
        for suffix in ["FriendlyAppName", "ApplicationCompany"] {
            let name = format!("{CODE_EXE}.{suffix}");
            let all = m.find_all(&name);
            assert_eq!(
                all[0].anchor,
                AnchorRef {
                    kind: AnchorKind::Exe,
                    text: CODE_EXE.into()
                },
                "{name}"
            );
            assert_eq!(all[0].how, MatchHow::Embedded);
            assert_eq!(all[1].anchor.kind, AnchorKind::Root);
            assert_eq!(all[1].how, MatchHow::Below);
            assert_eq!(
                all[1].path.as_deref(),
                Some(CODE_EXE.to_lowercase().as_str()),
                "{name}"
            );
        }
        // An exe of the root that is not in the exe set still resolves through the root.
        let tunnel = format!(r"{CODE}\bin\code-tunnel.exe.FriendlyAppName");
        let hit = m.find(&tunnel).unwrap();
        assert_eq!(
            (hit.anchor.kind, hit.how),
            (AnchorKind::Root, MatchHow::Below)
        );
        assert_eq!(
            hit.path.unwrap(),
            format!(r"{CODE}\bin\code-tunnel.exe").to_lowercase()
        );
        // Another user's install of the same app is not this root.
        assert_eq!(
            m.find(
                r"C:\Users\lee\AppData\Local\Programs\Microsoft VS Code\Code.exe.FriendlyAppName"
            ),
            None
        );
        assert_eq!(m.find(r"C:\Users\kim\AppData\Local\Programs\Microsoft VS Code Insiders\Code.exe.FriendlyAppName"), None);
    }

    #[test]
    fn nested_roots_report_the_deepest_first() {
        let mut set = AnchorSet::new();
        set.add_root(r"C:\Tools\Suite");
        set.add_root(r"C:\Tools\Suite\Plugin\");
        let m = RefMatcher::new(&set);
        let all = m.find_all(r"C:\Tools\Suite\Plugin\p.dll");
        assert_eq!(
            all.iter()
                .map(|m| m.anchor.text.as_str())
                .collect::<Vec<_>>(),
            [r"C:\Tools\Suite\Plugin", r"C:\Tools\Suite"]
        );
        assert_eq!(m.find_all(r"C:\Tools\Suite\Other").len(), 1);
        // The same anchor twice in one string is reported once, with its best match.
        let twice = m.find_all(r"C:\Tools\Suite\a.exe;C:\Tools\Suite");
        assert_eq!(twice.len(), 1);
        assert_eq!(twice[0].how, MatchHow::Below);
    }

    #[test]
    fn anchor_set_rejects_what_would_match_everything() {
        let mut set = AnchorSet::new();
        for bad in ["", "  ", r"C:\", "C:", r"\", "C:/"] {
            assert!(!set.add_root(bad), "{bad:?}");
        }
        assert!(!set.add_root_alias(r"C:\App", "C:"));
        assert!(!set.add_exe_path("app.exe"));
        assert!(!set.add_exe_name(r"C:\App\app.exe"));
        assert!(!set.add_exe_name(""));
        assert!(!set.add_progid(" "));
        assert!(!set.add_clsid("{}"));
        assert!(!set.add_aumid(""));
        assert!(!set.add_token(""));
        assert!(set.is_empty());
        let m = RefMatcher::new(&set);
        assert_eq!(m.find(r"C:\App\app.exe"), None);

        assert!(set.add_root(r"C:\App\"));
        assert!(set.add_root(r"C:\App"), "adding twice is harmless");
        assert!(set.add_clsid("{11111111-2222-3333-4444-555555555555}"));
        assert!(set.add_clsid("11111111-2222-3333-4444-555555555555"));
        assert_eq!(set.len(), 2);
        assert_eq!(set.anchors()[0].text, r"C:\App");
        assert_eq!(
            set.anchors()[1].text,
            "{11111111-2222-3333-4444-555555555555}"
        );
    }

    #[test]
    fn non_ascii_names_fold() {
        let mut set = AnchorSet::new();
        set.add_root(r"C:\Program Files\Übersicht Größe");
        set.add_progid("Çalışma.Belge");
        let m = RefMatcher::new(&set);
        assert_eq!(
            m.find(r"c:\program files\ÜBERSICHT GRÖßE\app.exe")
                .unwrap()
                .how,
            MatchHow::Below
        );
        assert_eq!(m.find(r"C:\Program Files\Übersicht Größer\app.exe"), None);
        assert_eq!(m.find("çalışma.belge").unwrap().how, MatchHow::Whole);
        assert_eq!(m.find("éÇalışma.Belge"), None);
        assert_eq!(
            m.find("日本語 Çalışma.Belge 日本語").unwrap().how,
            MatchHow::Embedded
        );
    }

    #[test]
    fn multi_sz_segments_and_binary_runs() {
        let m = git();
        let segments = [
            r"C:\Windows\system32",
            r"C:\Program Files\GitHub",
            r"C:\Program Files\Git\cmd",
            "",
            "git_shell",
        ];
        let hits = m.find_in_segments(segments);
        assert_eq!(
            hits.iter()
                .map(|(i, m)| (*i, m.anchor.kind))
                .collect::<Vec<_>>(),
            [(2, AnchorKind::Root), (4, AnchorKind::ProgId)]
        );

        let utf16 = |s: &str| {
            s.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>()
        };
        // A header, a string, a NUL, another string; then the same at an odd offset.
        let mut data = vec![0x01, 0x00, 0x02, 0x00];
        data.extend(utf16(r"C:\Program Files\Git\git-bash.exe"));
        data.extend([0, 0]);
        data.extend(utf16(r"C:\Program Files\GitHub\gh.exe"));
        data.extend([0, 0, 0xff, 0xff]);
        let runs = utf16_runs(&data, 4);
        assert!(
            runs.contains(&r"C:\Program Files\Git\git-bash.exe".to_owned()),
            "{runs:?}"
        );
        assert!(
            runs.contains(&r"C:\Program Files\GitHub\gh.exe".to_owned()),
            "{runs:?}"
        );
        let hits = m.find_in_binary(&data);
        assert_eq!(
            hits.iter()
                .map(|m| (m.anchor.kind, m.name_only))
                .collect::<Vec<_>>(),
            [
                (AnchorKind::Exe, false),
                (AnchorKind::Root, false),
                (AnchorKind::Exe, true)
            ]
        );

        let mut odd = vec![0x7f];
        odd.extend(utf16("git_shell"));
        odd.extend([0, 0]);
        assert_eq!(m.find_in_binary(&odd)[0].anchor.kind, AnchorKind::ProgId);

        // ANSI text, short runs and noise are not UTF-16 strings.
        assert!(
            m.find_in_binary(br"C:\Program Files\Git\git-bash.exe")
                .is_empty()
        );
        assert!(utf16_runs(&utf16("abc"), 4).is_empty());
        assert!(utf16_runs(&[], 4).is_empty());
        assert!(utf16_runs(&[0x41], 1).is_empty());
        assert!(
            m.find_in_binary(&[0xd8, 0xd8, 0x00, 0xd8, 0x01, 0x00])
                .is_empty()
        );
    }

    #[test]
    fn many_anchors_do_not_confuse_the_search() {
        let mut set = AnchorSet::new();
        set.add_root(GIT);
        for i in 0..2000 {
            set.add_exe_path(&format!(r"C:\Program Files\Git\mingw64\bin\lib{i}.dll"));
            set.add_progid(&format!("VSCode.ext{i}"));
        }
        let m = RefMatcher::new(&set);
        for i in [0, 7, 19, 199, 1999] {
            let hit = m
                .find(&format!(r"C:\Program Files\Git\mingw64\bin\lib{i}.dll,-5"))
                .unwrap();
            assert_eq!(
                hit.anchor.text,
                format!(r"C:\Program Files\Git\mingw64\bin\lib{i}.dll")
            );
            assert_eq!(
                m.find(&format!("vscode.ext{i}")).unwrap().how,
                MatchHow::Whole
            );
        }
        assert_eq!(
            m.find(r"C:\Program Files\Git\mingw64\bin\lib2000.dll")
                .unwrap()
                .anchor
                .kind,
            AnchorKind::Root
        );
        assert_eq!(m.find("VSCode.ext2000"), None);
        assert_eq!(m.find(r"C:\Program Files\Gix\mingw64\bin\lib1.dll"), None);
    }

    #[test]
    fn from_fingerprint_field_mapping_is_covered_by_builder_methods() {
        // `from_fingerprint` only forwards to the builder methods tested above; check the name rule.
        let mut set = AnchorSet::new();
        set.add_exe_path(r"C:\App\bin\app.exe");
        set.add_exe_name("app.exe");
        assert_eq!(set.len(), 2, "a path and a bare name are distinct anchors");
        let m = RefMatcher::new(&set);
        let all = m.find_all(r"C:\App\bin\app.exe");
        assert_eq!(
            all.iter().map(|m| m.name_only).collect::<Vec<_>>(),
            [false, true]
        );
    }
}
