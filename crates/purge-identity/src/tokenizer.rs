//! Name tokenizer and the installed-apps corpus (ENGINE_PLAN §5.4, tokenizer steps 1 to 5).
//!
//! Everything here is a pure function of its input strings; nothing touches the system.
//!
//! # Steps
//!
//! 1. **Normalise** ([`normalize`]): NFKC, then a locale-independent case fold. Full-width forms become
//!    ASCII (`Ｎｏｔｅｐａｄ＋＋` → `notepad++`). Both Turkish i's fold to plain `i` (`İ` → `i`, `ı` → `i`), so
//!    `DİZİ`, `DIZI`, `dizi` and `dızı` are one token whatever the system locale; this conflates dotted
//!    and dotless i on purpose, because a Turkish-locale tool may have upper-cased either way. `ß` folds
//!    to `ss` and final sigma to `σ`. Trademark signs (`®`, `™`, `©`, `(R)`, `(TM)`) are removed.
//! 2. **Split** ([`lex`]): whitespace and every character that is not a letter, a digit or one of
//!    `+ # . _ -` separates chunks (so brackets, slashes and commas split; apostrophes are dropped without
//!    splitting). Inside a chunk, `_`, `-` and `.` split only **between alphanumerics**. Symbols are
//!    therefore kept: `notepad++`, `c#`, `f#`, `c++` and a leading-dot `.net` stay whole and are different
//!    tokens from `notepad`, `c`, `f` and `net`.
//! 3. **Classify.** Each token gets a [`TokenClass`]:
//!    - [`TokenClass::Noise`]: version-like tokens (`24.08`, `3.13.1150.0`, `2015-2022`, `v2`, bare numbers
//!      after the first word), architecture tags (`x64`, `x86`, `64-bit`, `amd64`, …), locale tags
//!      (`en-US`) and GUIDs. A bare integer **before** the first word is part of the name (`7-Zip` →
//!      `7`, `zip`) and is not noise.
//!    - [`TokenClass::Stopword`]: `setup edition inc corp corporation ltd llc gmbh foundation the for
//!      windows` and a few peers such as `by`, `of`, `limited` ([`STOPWORDS`]).
//!    - [`TokenClass::Generic`]: listed in `kb/generic-tokens.json` (only [`tokenize`] assigns this).
//!    - [`TokenClass::Significant`]: everything else.
//! 4. **IDF** ([`Corpus`]): a token present in more than [`IDF_MAX_APPS`] installed apps' names, publishers
//!    or key names is common and does not count as distinctive.
//!
//! Three derived forms are used by the matcher: the significant token set, the **full-name key**
//! ([`full_name_key`]: every non-noise token, in order, joined by one space) and the **vendor key**
//! ([`vendor_key`]: the same without stopwords, so `Mozilla Corporation` and `Mozilla` are both `mozilla`).

use std::collections::{BTreeMap, BTreeSet};

use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;

use crate::kbdata::GenericTokens;

/// A token present in more than this many installed apps is too common to be distinctive (§5.4 step 5).
pub const IDF_MAX_APPS: usize = 2;

/// Word stopwords (§5.4 step 3 plus obvious peers). Architecture and version tokens are handled separately
/// as [`TokenClass::Noise`].
pub const STOPWORDS: &[&str] = &[
    "and",
    "bit",
    "by",
    "co",
    "company",
    "corp",
    "corporation",
    "edition",
    "for",
    "foundation",
    "gmbh",
    "inc",
    "incorporated",
    "limited",
    "llc",
    "ltd",
    "of",
    "plc",
    "setup",
    "the",
    "version",
    "windows",
];

/// Architecture and bitness tags, dropped as noise.
const ARCH_TAGS: &[&str] = &[
    "32-bit", "32bit", "64-bit", "64bit", "amd64", "arm64", "ia64", "win32", "win64", "x64", "x86",
    "x86-64", "x86_64",
];

/// Locale tags installers put in display names (`Mozilla Firefox (x64 en-US)`), dropped as noise. A closed
/// list, so that product names shaped like a tag (`No-IP`) are not swallowed.
const LOCALE_TAGS: &[&str] = &[
    "ar-sa", "bg-bg", "cs-cz", "da-dk", "de-at", "de-ch", "de-de", "el-gr", "en-au", "en-ca",
    "en-gb", "en-in", "en-us", "es-ar", "es-es", "es-mx", "et-ee", "fi-fi", "fr-ca", "fr-ch",
    "fr-fr", "he-il", "hi-in", "hr-hr", "hu-hu", "id-id", "it-it", "ja-jp", "ko-kr", "lt-lt",
    "lv-lv", "nb-no", "nl-be", "nl-nl", "pl-pl", "pt-br", "pt-pt", "ro-ro", "ru-ru", "sk-sk",
    "sl-si", "sr-rs", "sv-se", "th-th", "tr-tr", "uk-ua", "vi-vn", "zh-cn", "zh-hk", "zh-tw",
];

/// What kind of token this is; see the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TokenClass {
    /// Version, architecture, locale or GUID: carries no name information at all.
    Noise,
    /// A stopword ([`STOPWORDS`]).
    Stopword,
    /// A generic token from `kb/generic-tokens.json`.
    Generic,
    /// A token that can identify an app (before the IDF rule).
    Significant,
}

/// One token of a name, in normalised form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Token {
    /// Normalised text.
    pub text: String,
    /// Its class.
    pub class: TokenClass,
}

/// NFKC plus a locale-independent case fold; see the module documentation for the special cases.
pub fn normalize(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let kept = input
        .chars()
        .filter(|c| !matches!(c, '®' | '©' | '™' | '℠'));
    for c in kept.nfkc() {
        match c {
            'İ' | 'ı' => out.push('i'),
            'ß' | 'ẞ' => out.push_str("ss"),
            'ς' => out.push('σ'),
            _ => out.extend(c.to_lowercase()),
        }
    }
    if out.contains("(r)") || out.contains("(tm)") {
        out = out.replace("(r)", " ").replace("(tm)", " ");
    }
    out
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || is_combining_mark(c)
}

fn is_inner_separator(c: char) -> bool {
    matches!(c, '_' | '-' | '.')
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `24.08`, `3.13.1150.0`, `2015-2022`, `v2`, `v1.2`: an optional `v`, then digit groups joined by `. _ -`.
fn is_version_like(s: &str) -> bool {
    let body = s.strip_prefix('v').unwrap_or(s);
    !body.is_empty() && body.split(['.', '_', '-']).all(is_digits)
}

/// `8-4-4-4-12` hex digits (the braces are already gone: they are separators).
fn is_guid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8usize, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_locale_tag(s: &str) -> bool {
    s.len() == 5 && LOCALE_TAGS.contains(&s.replace('_', "-").as_str())
}

/// Removes separators and symbols that cannot start a token, and separators that cannot end one. A single
/// leading dot survives when a letter follows (`.net`).
fn trim_chunk(chunk: &str) -> &str {
    let mut s = chunk.trim_end_matches(is_inner_separator);
    loop {
        let mut chars = s.chars();
        match chars.next() {
            Some('_' | '-' | '+' | '#') => s = &s[1..],
            Some('.') if !chars.next().is_some_and(char::is_alphabetic) => s = &s[1..],
            _ => return s,
        }
    }
}

fn lex_chunk(chunk: &str, seen_word: &mut bool, out: &mut Vec<Token>) {
    let chunk = trim_chunk(chunk);
    if !chunk.chars().any(is_word_char) {
        return;
    }
    let noise = |text: &str| Token {
        text: text.to_owned(),
        class: TokenClass::Noise,
    };
    let whole_is_noise = ARCH_TAGS.contains(&chunk)
        || is_locale_tag(chunk)
        || is_guid(chunk)
        || (is_version_like(chunk) && (*seen_word || !is_digits(chunk)));
    if whole_is_noise {
        out.push(noise(chunk));
        return;
    }

    let chars: Vec<char> = chunk.chars().collect();
    let mut parts: Vec<String> = vec![String::new()];
    for (i, &c) in chars.iter().enumerate() {
        let splits = is_inner_separator(c)
            && i > 0
            && i + 1 < chars.len()
            && is_word_char(chars[i - 1])
            && is_word_char(chars[i + 1]);
        if splits {
            parts.push(String::new());
        } else if let Some(last) = parts.last_mut() {
            last.push(c);
        }
    }
    for part in parts {
        let class = if is_digits(&part) {
            // A number in front of the first word belongs to the name (`7-Zip`); later ones are versions.
            if *seen_word {
                TokenClass::Noise
            } else {
                TokenClass::Significant
            }
        } else if is_version_like(&part) || ARCH_TAGS.contains(&part.as_str()) {
            TokenClass::Noise
        } else if STOPWORDS.contains(&part.as_str()) {
            TokenClass::Stopword
        } else {
            *seen_word = true;
            TokenClass::Significant
        };
        out.push(Token { text: part, class });
    }
}

/// Steps 1 to 3 without the knowledge base: every token of `input`, in order, classed as
/// [`TokenClass::Noise`], [`TokenClass::Stopword`] or [`TokenClass::Significant`].
pub fn lex(input: &str) -> Vec<Token> {
    let normalized = normalize(input);
    let mut out = Vec::new();
    let mut seen_word = false;
    let mut chunk = String::new();
    for c in normalized.chars().chain(std::iter::once(' ')) {
        if matches!(c, '\'' | '\u{2019}' | '\u{2018}' | '`') {
            continue;
        }
        if is_word_char(c) || matches!(c, '+' | '#' | '.' | '_' | '-') {
            chunk.push(c);
        } else if !chunk.is_empty() {
            lex_chunk(&chunk, &mut seen_word, &mut out);
            chunk.clear();
        }
    }
    out
}

/// Steps 1 to 4: like [`lex`], with tokens from `generic` classed as [`TokenClass::Generic`].
pub fn tokenize(input: &str, generic: &GenericTokens) -> Vec<Token> {
    let mut tokens = lex(input);
    for token in &mut tokens {
        if token.class == TokenClass::Significant && generic.contains(&token.text) {
            token.class = TokenClass::Generic;
        }
    }
    tokens
}

/// The significant tokens of `input` (steps 1 to 4), first occurrence order, without duplicates.
pub fn significant_tokens(input: &str, generic: &GenericTokens) -> Vec<String> {
    let mut seen = BTreeSet::new();
    tokenize(input, generic)
        .into_iter()
        .filter(|t| t.class == TokenClass::Significant && seen.insert(t.text.clone()))
        .map(|t| t.text)
        .collect()
}

fn join_tokens(input: &str, keep: impl Fn(TokenClass) -> bool) -> String {
    let mut out = String::new();
    for token in lex(input).into_iter().filter(|t| keep(t.class)) {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&token.text);
    }
    out
}

/// The full-name key: every non-noise token in order, joined by single spaces. `Mozilla Firefox (x64
/// en-US) 146.0` and a folder named `Mozilla Firefox` share the key `mozilla firefox`; stopwords are kept,
/// so `Git for Windows` (`git for windows`) is not `Git` (`git`).
pub fn full_name_key(input: &str) -> String {
    join_tokens(input, |c| c != TokenClass::Noise)
}

/// The vendor key: the full-name key without stopwords, so legal suffixes do not matter (`Mozilla
/// Corporation` → `mozilla`, `The Git Development Community` → `git development community`).
pub fn vendor_key(input: &str) -> String {
    join_tokens(input, |c| c > TokenClass::Stopword)
}

/// Document frequencies of name tokens over all installed apps (§5.4 step 5).
///
/// One *document* is one app: all of its names, publishers and ARP key names together. A token counts once
/// per app however often the app repeats it. Noise tokens are not counted; stopwords and generic tokens
/// are, which is harmless because they are never distinctive anyway.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Corpus {
    apps: usize,
    doc_freq: BTreeMap<String, usize>,
}

impl Corpus {
    /// An empty corpus: no token is common.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a corpus from one string list per app.
    pub fn from_apps<A, I, S>(apps: A) -> Self
    where
        A: IntoIterator<Item = I>,
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut corpus = Self::new();
        for app in apps {
            corpus.add_app(app);
        }
        corpus
    }

    /// Adds one app: every name, publisher and key name it goes by.
    pub fn add_app<I, S>(&mut self, strings: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut tokens = BTreeSet::new();
        for s in strings {
            tokens.extend(
                lex(s.as_ref())
                    .into_iter()
                    .filter(|t| t.class != TokenClass::Noise)
                    .map(|t| t.text),
            );
        }
        self.apps += 1;
        for token in tokens {
            *self.doc_freq.entry(token).or_insert(0) += 1;
        }
    }

    /// Number of apps added.
    pub fn app_count(&self) -> usize {
        self.apps
    }

    /// In how many apps `token` (normalised) appears.
    pub fn doc_freq(&self, token: &str) -> usize {
        self.doc_freq.get(token).copied().unwrap_or(0)
    }

    /// The IDF rule: `token` appears in more than [`IDF_MAX_APPS`] apps.
    pub fn is_common(&self, token: &str) -> bool {
        self.doc_freq(token) > IDF_MAX_APPS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kbdata::Kb;

    fn texts(input: &str) -> Vec<String> {
        lex(input).into_iter().map(|t| t.text).collect()
    }

    fn sig(input: &str) -> Vec<String> {
        significant_tokens(input, &Kb::shipped().generic)
    }

    fn classes(input: &str) -> Vec<(String, TokenClass)> {
        tokenize(input, &Kb::shipped().generic)
            .into_iter()
            .map(|t| (t.text, t.class))
            .collect()
    }

    #[test]
    fn step1_normalize_table() {
        let cases = [
            ("Mozilla Firefox", "mozilla firefox"),
            ("Ｎｏｔｅｐａｄ＋＋", "notepad++"),
            ("ＡＢＣ　１２３", "abc 123"),
            ("ﬁle", "file"),
            ("Straße", "strasse"),
            ("ΟΔΟΣ", "οδοσ"),
            ("οδός", "οδόσ"),
            ("Intel® Graphics™", "intel graphics"),
            ("Cafe\u{301}", "café"),
            ("", ""),
        ];
        for (input, want) in cases {
            assert_eq!(normalize(input), want, "{input:?}");
        }
        assert_eq!(
            normalize("Intel(R) Core(TM)")
                .split_whitespace()
                .collect::<Vec<_>>(),
            ["intel", "core"]
        );
    }

    /// The fold is locale-independent and maps both Turkish i's to `i` (documented in the module docs).
    #[test]
    fn step1_turkish_i() {
        for s in ["DİZİ", "DIZI", "dizi", "dızı", "Dİzı", "DI\u{307}ZI\u{307}"] {
            assert_eq!(normalize(s), "dizi", "{s:?}");
        }
        assert_eq!(normalize("TITAN"), "titan");
        assert_eq!(sig("Çalışma Aracı"), ["çalişma", "araci"]);
    }

    #[test]
    fn step1_split_table() {
        let cases: &[(&str, &[&str])] = &[
            ("Mozilla  Firefox\tESR", &["mozilla", "firefox", "esr"]),
            ("foo_bar-baz.qux", &["foo", "bar", "baz", "qux"]),
            ("Node.js", &["node", "js"]),
            ("Microsoft.NET", &["microsoft", "net"]),
            ("Tcl/Tk Support", &["tcl", "tk", "support"]),
            (
                "WinMerge (portable), [beta]",
                &["winmerge", "portable", "beta"],
            ),
            ("Assassin's Creed", &["assassins", "creed"]),
            ("-leading- .trailing. _x_", &["leading", ".trailing", "x"]),
            ("a--b", &["a--b"]),
            ("...", &[]),
            ("+ # -", &[]),
            ("日本語 ソフト", &["日本語", "ソフト"]),
            ("हिन्दी", &["हिन्दी"]),
        ];
        for (input, want) in cases {
            assert_eq!(&texts(input), want, "{input:?}");
        }
    }

    #[test]
    fn step2_symbol_tokens_table() {
        let cases: &[(&str, &[&str])] = &[
            ("Notepad++", &["notepad++"]),
            ("Notepad", &["notepad"]),
            ("C#", &["c#"]),
            ("F# Tools", &["f#", "tools"]),
            ("Visual C++", &["visual", "c++"]),
            (".NET", &[".net"]),
            ("Microsoft .NET Runtime", &["microsoft", ".net", "runtime"]),
            ("ASP.NET Core", &["asp", "net", "core"]),
            ("#hashtag", &["hashtag"]),
            ("Ｃ＋＋", &["c++"]),
        ];
        for (input, want) in cases {
            assert_eq!(&texts(input), want, "{input:?}");
        }
        assert_ne!(sig("Notepad++"), sig("Notepad"));
        assert_ne!(sig(".NET"), sig("net"));
    }

    #[test]
    fn step3_versions_and_architecture_are_noise() {
        use TokenClass::{Noise, Significant as S, Stopword};
        let c =
            |input: &str| -> Vec<TokenClass> { classes(input).into_iter().map(|t| t.1).collect() };
        assert_eq!(c("7-Zip 24.08 (x64)"), [S, S, Noise, Noise]);
        // Not version-like as a whole (a word inside), so it splits; the numbers are still noise.
        let git: Vec<(String, TokenClass)> = [
            ("git", S),
            ("2", Noise),
            ("51", Noise),
            ("0", Noise),
            ("windows", Stopword),
            ("1", Noise),
        ]
        .map(|(t, c)| (t.to_owned(), c))
        .into();
        assert_eq!(classes("Git 2.51.0.windows.1"), git);
        let noise_only = [
            "24.08",
            "3.13.1150.0",
            "2015-2022",
            "v2",
            "v1.2.3",
            "x64",
            "x86",
            "(64-bit)",
            "(32-bit)",
            "x86_64",
            "amd64",
            "arm64",
            "en-US",
            "pt_BR",
            "{771FD6B0-FA20-440A-A002-3B3BAC16DC50}",
        ];
        for s in noise_only {
            let got = c(s);
            assert!(
                !got.is_empty() && got.iter().all(|&k| k == Noise),
                "{s:?}: {got:?}"
            );
            assert_eq!(full_name_key(s), "", "{s:?}");
        }
        // A number after the first word is a version; before it, part of the name.
        assert_eq!(sig("Firefox 146"), ["firefox"]);
        assert_eq!(sig("Visual Studio 2022"), ["visual", "studio"]);
        assert_eq!(sig("7-Zip"), ["7", "zip"]);
        assert_eq!(sig("7 Days to Die"), ["7", "days", "to", "die"]);
        // Not versions: letters mixed in.
        assert_eq!(sig("1Password 8"), ["1password"]);
        assert_eq!(sig("No-IP DUC"), ["no", "ip", "duc"]);
        assert_eq!(sig("vlc"), ["vlc"]);
    }

    #[test]
    fn step3_stopwords_table() {
        for w in [
            "setup",
            "edition",
            "inc",
            "corp",
            "corporation",
            "ltd",
            "llc",
            "gmbh",
            "foundation",
            "the",
            "for",
            "windows",
        ] {
            assert!(STOPWORDS.contains(&w), "{w}");
            assert_eq!(classes(w), [(w.to_owned(), TokenClass::Stopword)]);
            assert!(sig(&format!("Foo {w} Bar")) == ["foo", "bar"], "{w}");
        }
        assert_eq!(sig("Git for Windows"), ["git"]);
        assert_eq!(sig("The Document Foundation"), ["document"]);
        assert_eq!(sig("Python 3.13.1 (64-bit)"), ["python"]);
        assert_eq!(sig("Something (64 bit)"), ["something"]);
        let mut sorted = STOPWORDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, STOPWORDS, "sorted and unique");
        assert!(STOPWORDS.iter().all(|w| normalize(w) == *w));
    }

    #[test]
    fn step4_generic_tokens_table() {
        use TokenClass::{Generic, Significant as S};
        assert_eq!(
            classes("Mozilla Maintenance Service"),
            [
                ("mozilla".to_owned(), S),
                ("maintenance".to_owned(), Generic),
                ("service".to_owned(), Generic)
            ]
        );
        assert_eq!(sig("Steam Launcher Helper Tools"), ["steam"]);
        assert_eq!(sig("Update Helper"), Vec::<String>::new());
        assert_eq!(
            sig("Python 3.13.1 Core Interpreter (64-bit)"),
            ["python", "interpreter"]
        );
        // Without the kb list nothing is generic.
        assert_eq!(
            significant_tokens("Update Helper", &GenericTokens::empty()),
            ["update", "helper"]
        );
        // Duplicates collapse, order is kept.
        assert_eq!(sig("Foo Bar foo BAR baz"), ["foo", "bar", "baz"]);
    }

    #[test]
    fn keys() {
        assert_eq!(
            full_name_key("Mozilla Firefox (x64 en-US) 146.0"),
            "mozilla firefox"
        );
        assert_eq!(full_name_key("Mozilla Firefox"), "mozilla firefox");
        assert_eq!(full_name_key("Git for Windows"), "git for windows");
        assert_eq!(full_name_key("7-Zip 24.08 (x64)"), "7 zip");
        assert_eq!(full_name_key("Zip"), "zip");
        assert_eq!(full_name_key("Notepad++ (64-bit x64)"), "notepad++");
        assert_eq!(vendor_key("Mozilla Corporation"), "mozilla");
        assert_eq!(vendor_key("Mozilla"), "mozilla");
        assert_eq!(
            vendor_key("The Git Development Community"),
            "git development community"
        );
        assert_eq!(vendor_key("Python Software Foundation"), "python software");
        assert_eq!(vendor_key("Valve Corp."), "valve");
        assert_eq!(vendor_key("NV Access Limited"), "nv access");
        assert_eq!(vendor_key("mozilla.org"), "mozilla org");
        assert_eq!(vendor_key("Inc."), "");
    }

    #[test]
    fn step5_corpus_counts_each_app_once() {
        let corpus = Corpus::from_apps([
            vec![
                "Mozilla Firefox (x64 en-US)",
                "Mozilla",
                "Mozilla Firefox 146.0 (x64 en-US)",
            ],
            vec!["Mozilla Thunderbird (x64 en-US) 160.0", "Mozilla"],
            vec!["Mozilla Maintenance Service", "Mozilla"],
            vec!["Steam 2.10.91.91", "Valve Corporation", "Steam"],
        ]);
        assert_eq!(corpus.app_count(), 4);
        assert_eq!(corpus.doc_freq("mozilla"), 3);
        assert_eq!(corpus.doc_freq("firefox"), 1);
        assert_eq!(corpus.doc_freq("steam"), 1);
        assert_eq!(corpus.doc_freq("146.0"), 0, "noise is not counted");
        assert_eq!(corpus.doc_freq("x64"), 0);
        assert_eq!(corpus.doc_freq("absent"), 0);
        assert!(corpus.is_common("mozilla"));
        assert!(!corpus.is_common("firefox"));
        assert!(!Corpus::new().is_common("mozilla"));
    }

    #[test]
    fn step5_idf_threshold_is_more_than_two_apps() {
        let mut corpus = Corpus::new();
        corpus.add_app(["Alpha Player"]);
        corpus.add_app(["Beta Player"]);
        assert_eq!(corpus.doc_freq("player"), IDF_MAX_APPS);
        assert!(!corpus.is_common("player"));
        corpus.add_app(["Gamma PLAYER"]);
        assert!(corpus.is_common("player"));
    }
}
