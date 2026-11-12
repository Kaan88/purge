//! The file-association journal (ENGINE_PLAN.md §5.7.1 step 1).
//!
//! File associations are cleaned at value level: an app adds its ProgID to an extension's
//! `OpenWithProgids`, sometimes takes the extension's default, and its uninstaller removes less than it
//! added. To undo exactly the app's part afterwards, the harvest records the state of every extension
//! the app registered with **before** the uninstaller runs.
//!
//! # What is recorded
//!
//! For every `.ext` key under `HKLM\SOFTWARE\Classes` and `HKU\<sid>_Classes` that the ProgID set P
//! touches (a value of `OpenWithProgids` is named in P, the default is in P, or the app left a backup
//! of the previous default), an [`ExtJournalEntry`]:
//!
//! - the `OpenWithProgids` value names, split into ours (in P) and others;
//! - the number of subkeys, and the names of the subkeys other than `OpenWithProgids`;
//! - the default value, and the names of the other values;
//! - the TrustedInstaller flag of the key;
//! - the vendor's backup of the previous default (`<Name>_backup`, where `<Name>` begins one of the
//!   app's ProgIDs, exe names or its display name), and from it the previous default when the app holds
//!   the default now.
//!
//! And for the users the harvest reads:
//!
//! - `Explorer\FileExts\<.ext>`: `OpenWithProgids` values in P, `OpenWithList` entries naming one of the
//!   app's main exes (with the `MRUList`), and a `UserChoice` in P;
//! - `ApplicationAssociationToasts` values named `<ProgID>_<.ext>` with the ProgID in P (both hives).
//!
//! These are attached to the entries of the same extension. An extension that only has such user-side
//! traces gets an entry for its `HKLM\SOFTWARE\Classes` key, holding whatever that key holds (nothing,
//! if it does not exist).
//!
//! [`capture`] returns the entries the fingerprint stores. [`capture_detailed`] adds what the
//! fingerprint model has no field for yet: whether the default is ours, whether the extension and its
//! `OpenWithProgids` are part of clean Windows, the owner flag of `OpenWithProgids`, and the `FileExts`
//! details. Everything is ordered by key, case-insensitively.

use purge_guard::prefix;
use purge_index::baseline::Baseline;
use purge_model::{ExtJournalEntry, VendorBackup};
use purge_source::types::{RegValue, SourceError};

use crate::refsnap::{HKLM_CLASSES, HarvestCtx};

const OPEN_WITH_PROGIDS: &str = "OpenWithProgids";
const BACKUP_SUFFIX: &str = "_backup";
const CURRENT_VERSION: &str = r"Microsoft\Windows\CurrentVersion";

/// What a user's `Explorer\FileExts\<.ext>` key says about the app.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileExtsRecord {
    /// Canonical path of the `FileExts\<.ext>` key.
    pub key: String,
    /// `OpenWithProgids` value names that are in P.
    pub openwith_progids: Vec<String>,
    /// `OpenWithList` entries naming one of the app's main exes: (value name, exe name).
    pub openwith_list: Vec<(String, String)>,
    /// The `MRUList` of `OpenWithList`, when one of its entries is ours.
    pub mru_list: Option<String>,
    /// The `UserChoice` ProgID, when it is in P. Report-only: Windows protects the key with a hash.
    pub user_choice: Option<String>,
}

impl FileExtsRecord {
    fn is_empty(&self) -> bool {
        self.openwith_progids.is_empty()
            && self.openwith_list.is_empty()
            && self.user_choice.is_none()
    }
}

/// One extension of the journal with the facts the fingerprint entry has no field for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtRecord {
    /// The entry as the fingerprint stores it.
    pub entry: ExtJournalEntry,
    /// The extension's key exists.
    pub ext_exists: bool,
    /// The extension's default is a ProgID of P.
    pub default_is_ours: bool,
    /// The extension's key is part of clean Windows; `None` without a baseline for this Windows.
    pub ext_in_baseline: Option<bool>,
    /// The key has an `OpenWithProgids` subkey.
    pub openwith_exists: bool,
    /// `OpenWithProgids` is part of clean Windows; `None` without a baseline for this Windows.
    pub openwith_in_baseline: Option<bool>,
    /// `OpenWithProgids` is owned by TrustedInstaller or carries a TrustedInstaller ACE.
    pub openwith_ti_owned: bool,
    /// The user's `FileExts` entry of the extension, when it names the app.
    pub file_exts: Option<FileExtsRecord>,
}

impl ExtRecord {
    /// The app's value is the only one in `OpenWithProgids`.
    pub fn only_ours(&self) -> bool {
        !self.entry.openwith_ours.is_empty() && self.entry.openwith_others.is_empty()
    }
}

/// The outcome of [`capture_detailed`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssocJournal {
    /// One record per touched extension key, ordered by key.
    pub records: Vec<ExtRecord>,
    /// Things worth a line in the fingerprint's warnings.
    pub warnings: Vec<String>,
}

fn sorted_ci(mut names: Vec<String>) -> Vec<String> {
    names.sort_by_key(|name| prefix::fold(name));
    names
}

fn starts_with_ci(text: &str, start: &str) -> bool {
    text.len() >= start.len()
        && text.is_char_boundary(start.len())
        && prefix::eq_ci(&text[..start.len()], start)
}

/// Whether `text` begins with `start` as a whole word: what follows is the end or not a letter or
/// digit. `App_backup` is not the backup of "Apple Music".
fn starts_word(text: &str, start: &str) -> bool {
    starts_with_ci(text, start)
        && !text[start.len()..]
            .chars()
            .next()
            .is_some_and(char::is_alphanumeric)
}

fn ends_with_ci(text: &str, end: &str) -> bool {
    let cut = text.len().saturating_sub(end.len());
    text.len() >= end.len() && text.is_char_boundary(cut) && prefix::eq_ci(&text[cut..], end)
}

fn non_empty_string(value: &RegValue) -> Option<String> {
    value.data.string().filter(|s| !s.is_empty())
}

struct Journal<'a, 'c> {
    ctx: &'c HarvestCtx<'a>,
    baseline: Option<&'a Baseline>,
    exe_names: Vec<&'a str>,
    warnings: Vec<String>,
}

impl Journal<'_, '_> {
    /// Reads a key that may be missing; any other failure is worth a warning.
    fn read<T: Default>(&mut self, what: &str, result: Result<T, SourceError>) -> T {
        match result {
            Ok(value) => value,
            Err(SourceError::NotFound) => T::default(),
            Err(error) => {
                self.warnings
                    .push(format!("assoc: {what} could not be read ({error})"));
                T::default()
            }
        }
    }

    /// Whether `<name>_backup` is a backup value of this app: `<name>` begins one of its ProgIDs, one
    /// of its exe names or its display name.
    fn is_our_backup(&self, value_name: &str) -> bool {
        if !ends_with_ci(value_name, BACKUP_SUFFIX) {
            return false;
        }
        let stem = &value_name[..value_name.len() - BACKUP_SUFFIX.len()];
        stem.chars().count() >= 3
            && (self.ctx.progids().any(|p| starts_word(p, stem))
                || self.exe_names.iter().any(|e| starts_word(e, stem))
                || starts_word(&self.ctx.target.display_name, stem))
    }

    /// The record of one extension key. `None` when the key says nothing about the app, unless `force`.
    fn ext(&mut self, key: &str, ext: &str, force: bool) -> Option<ExtRecord> {
        let ctx = self.ctx;
        let info = match ctx.reg.key_info(key) {
            Ok(info) => Some(info),
            Err(SourceError::NotFound) => None,
            Err(error) => {
                self.warnings
                    .push(format!("assoc: {key} could not be read ({error})"));
                None
            }
        };
        let exists = info.is_some();
        let (values, subkeys) = if exists {
            (
                self.read(key, ctx.reg.values(key)),
                sorted_ci(self.read(key, ctx.reg.subkeys(key))),
            )
        } else {
            (Vec::new(), Vec::new())
        };

        let mut default = None;
        let mut vendor_backup = None;
        let mut other_values = Vec::new();
        for value in &values {
            if value.name.is_empty() {
                default = non_empty_string(value);
            } else if vendor_backup.is_none() && self.is_our_backup(&value.name) {
                vendor_backup = Some(VendorBackup {
                    name: value.name.clone(),
                    data: value.data.string().unwrap_or_default(),
                });
            } else {
                other_values.push(value.name.clone());
            }
        }
        let other_values = sorted_ci(other_values);
        let default_is_ours = default.as_deref().is_some_and(|d| ctx.is_progid(d));

        let openwith_key = format!("{key}\\{OPEN_WITH_PROGIDS}");
        let openwith_exists = subkeys.iter().any(|s| prefix::eq_ci(s, OPEN_WITH_PROGIDS));
        let mut ours = Vec::new();
        let mut others = Vec::new();
        let mut openwith_ti_owned = false;
        if openwith_exists {
            openwith_ti_owned = ctx
                .reg
                .key_info(&openwith_key)
                .is_ok_and(|i| i.ti_owned == Some(true));
            let names = self
                .read(&openwith_key, ctx.reg.values(&openwith_key))
                .into_iter()
                .map(|value| value.name);
            for name in sorted_ci(names.collect()) {
                if ctx.is_progid(&name) {
                    ours.push(name);
                } else {
                    others.push(name);
                }
            }
        }

        let touched = !ours.is_empty() || default_is_ours || vendor_backup.is_some();
        if !touched && !force {
            return None;
        }
        let previous_default = if default_is_ours {
            vendor_backup
                .as_ref()
                .map(|backup| backup.data.clone())
                .filter(|data| !data.is_empty())
        } else {
            None
        };
        let in_baseline = |key: &str| self.baseline.map(|b| b.has_key(key));
        Some(ExtRecord {
            ext_exists: exists,
            default_is_ours,
            ext_in_baseline: in_baseline(key),
            openwith_exists,
            openwith_in_baseline: in_baseline(&openwith_key),
            openwith_ti_owned,
            file_exts: None,
            entry: ExtJournalEntry {
                ext: ext.to_owned(),
                key: key.to_owned(),
                openwith_ours: ours,
                openwith_others: others,
                subkey_count: info.as_ref().map_or(0, |i| i.n_subkeys),
                default,
                previous_default,
                other_values,
                other_subkeys: subkeys
                    .into_iter()
                    .filter(|s| !prefix::eq_ci(s, OPEN_WITH_PROGIDS))
                    .collect(),
                ti_owned: info.is_some_and(|i| i.ti_owned == Some(true)),
                vendor_backup,
                file_exts_key: None,
                toast_values: Vec::new(),
            },
        })
    }

    /// Makes sure the extension has a record for its `HKLM\SOFTWARE\Classes` key, whatever that key
    /// holds.
    fn machine_entry(&mut self, records: &mut Vec<ExtRecord>, ext: &str) {
        let key = format!("{HKLM_CLASSES}\\{ext}");
        if !records.iter().any(|r| prefix::is_same(&r.entry.key, &key)) {
            records.extend(self.ext(&key, ext, true));
        }
    }

    /// The `FileExts` entries of one user that name the app, ordered by extension.
    fn file_exts(&mut self, sid: &str) -> Vec<(String, FileExtsRecord)> {
        let ctx = self.ctx;
        let base = format!(r"HKU\{sid}\Software\{CURRENT_VERSION}\Explorer\FileExts");
        let exts = sorted_ci(self.read(&base, ctx.reg.subkeys(&base)));
        let mut out = Vec::new();
        for ext in exts.into_iter().filter(|e| e.starts_with('.')) {
            let key = format!("{base}\\{ext}");
            let mut record = FileExtsRecord {
                key: key.clone(),
                ..FileExtsRecord::default()
            };
            let progids = format!("{key}\\{OPEN_WITH_PROGIDS}");
            let names = self
                .read(&progids, ctx.reg.values(&progids))
                .into_iter()
                .map(|value| value.name)
                .filter(|name| ctx.is_progid(name));
            record.openwith_progids = sorted_ci(names.collect());

            let list = format!(r"{key}\OpenWithList");
            let mut mru = None;
            for value in self.read(&list, ctx.reg.values(&list)) {
                let Some(data) = value.data.string() else {
                    continue;
                };
                if prefix::eq_ci(&value.name, "MRUList") {
                    mru = Some(data);
                } else if self.exe_names.iter().any(|exe| prefix::eq_ci(exe, &data)) {
                    record.openwith_list.push((value.name, data));
                }
            }
            record
                .openwith_list
                .sort_by_key(|(name, _)| prefix::fold(name));
            if !record.openwith_list.is_empty() {
                record.mru_list = mru;
            }

            let choice = format!(r"{key}\UserChoice");
            record.user_choice = match ctx.reg.value(&choice, "ProgId") {
                Ok(data) => data.string().filter(|progid| ctx.is_progid(progid)),
                Err(_) => None,
            };
            if !record.is_empty() {
                out.push((ext, record));
            }
        }
        out
    }

    /// The `ApplicationAssociationToasts` values `<ProgID>_<.ext>` of one container: (ext, value name).
    fn toasts(&mut self, software: &str) -> Vec<(String, String)> {
        let ctx = self.ctx;
        let key = format!(r"{software}\{CURRENT_VERSION}\ApplicationAssociationToasts");
        let names = self
            .read(&key, ctx.reg.values(&key))
            .into_iter()
            .map(|value| value.name);
        let mut out = Vec::new();
        for name in sorted_ci(names.collect()) {
            // The longest ProgID of P that the name starts with, followed by `_.`.
            let ext = ctx
                .progids()
                .filter(|progid| {
                    starts_with_ci(&name, progid) && name[progid.len()..].starts_with("_.")
                })
                .map(str::len)
                .max()
                .map(|len| name[len + 1..].to_owned());
            if let Some(ext) = ext {
                out.push((ext, name));
            }
        }
        out
    }
}

/// The journal with the facts the fingerprint has no field for, and what could not be read.
pub fn capture_detailed(ctx: &HarvestCtx<'_>) -> AssocJournal {
    let mut journal = Journal {
        ctx,
        baseline: ctx.matching_baseline(),
        exe_names: ctx.exe_names().collect(),
        warnings: Vec::new(),
    };
    if ctx.progids().next().is_none() && journal.exe_names.is_empty() {
        return AssocJournal::default();
    }
    let sids = ctx.user_sids();
    let mut records: Vec<ExtRecord> = Vec::new();

    // The extension keys of the Classes roots.
    for classes in ctx.classes_roots() {
        let names = sorted_ci(journal.read(&classes, ctx.reg.subkeys(&classes)));
        for ext in names.into_iter().filter(|name| name.starts_with('.')) {
            let key = format!("{classes}\\{ext}");
            records.extend(journal.ext(&key, &ext, false));
        }
    }

    // The user-side traces, attached to the entries of their extension.
    for sid in &sids {
        let user_classes = format!(r"HKU\{sid}_Classes");
        for (ext, found) in journal.file_exts(sid) {
            let mine = |r: &ExtRecord| {
                prefix::eq_ci(&r.entry.ext, &ext)
                    && (prefix::is_inside(&r.entry.key, HKLM_CLASSES)
                        || prefix::is_inside(&r.entry.key, &user_classes))
            };
            if !records.iter().any(mine) {
                journal.machine_entry(&mut records, &ext);
            }
            for record in records.iter_mut().filter(|r| mine(r)) {
                if record.file_exts.is_none() {
                    record.entry.file_exts_key = Some(found.key.clone());
                    record.file_exts = Some(found.clone());
                }
            }
        }
    }
    let containers = std::iter::once(r"HKLM\SOFTWARE".to_owned())
        .chain(sids.iter().map(|sid| format!(r"HKU\{sid}\Software")));
    for software in containers {
        for (ext, name) in journal.toasts(&software) {
            if !records.iter().any(|r| prefix::eq_ci(&r.entry.ext, &ext)) {
                journal.machine_entry(&mut records, &ext);
            }
            for record in records
                .iter_mut()
                .filter(|r| prefix::eq_ci(&r.entry.ext, &ext))
            {
                let toasts = &mut record.entry.toast_values;
                if !toasts.iter().any(|t| prefix::eq_ci(t, &name)) {
                    toasts.push(name.clone());
                }
            }
        }
    }

    records.sort_by_key(|record| prefix::fold(&record.entry.key));
    AssocJournal {
        records,
        warnings: journal.warnings,
    }
}

/// The file-association journal of the fingerprint: one entry per extension key the app registered
/// with, ordered by key.
pub fn capture(ctx: &HarvestCtx<'_>) -> Vec<ExtJournalEntry> {
    capture_detailed(ctx)
        .records
        .into_iter()
        .map(|record| record.entry)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_insensitive_affixes() {
        assert!(starts_with_ci("VSCode.txt_.txt", "vscode.TXT"));
        assert!(!starts_with_ci("VS", "VSCode"));
        assert!(ends_with_ci("Notepad++_BACKUP", "_backup"));
        assert!(!ends_with_ci("backup", "_backup"));
        assert!(starts_word("Notepad++_file", "notepad++"));
        assert!(starts_word("Notepad++ (64-bit x64)", "Notepad++"));
        assert!(starts_word("Code.exe", "code"));
        assert!(starts_word("VSCode", "VSCode"));
        assert!(!starts_word("Apple Music", "App"));
        assert!(!starts_word("VSCode.txt", "VSC"));
        // A multi-byte character at the cut must not panic.
        assert!(!starts_with_ci("éa", "a"));
        assert!(!ends_with_ci("aé", "a"));
    }
}
