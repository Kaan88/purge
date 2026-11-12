//! Harvested tokens (ENGINE_PLAN.md §5.3 `HarvestedToken`).
//!
//! Installers stamp opaque identifiers into the names they register: Firefox's install hash in
//! `FirefoxHTML-308046B0AF4A39CB`, an Inno Setup AppId GUID in the Uninstall key name, an MSI
//! ProductCode. Such a token names the app as exactly as a path does, and it also occurs in leftovers
//! that carry no path at all (`Mozilla\Firefox\TaskBarIDs`, `ProgramData\Mozilla-<guid>\updates\<hash>`).
//!
//! # What is a token
//!
//! - a GUID, taken **without braces** (`771FD6B0-FA20-440A-A002-3B3BAC16DC50`), so that the matcher's
//!   whole-segment rule finds it in `{GUID}`, `{GUID}_is1` and `Prefix-{GUID}` alike;
//! - a run of at least [`MIN_HEX_LEN`] hexadecimal digits with at least one decimal digit and at least
//!   one letter, delimited by anything that is not a letter or a digit. A run of decimal digits alone
//!   (a date, a build number, a timestamp) is not an identifier of one app and is never a token.
//!
//! # Where tokens are taken from
//!
//! Only from the app's own names: the Uninstall key name, the MSI ProductCode and UpgradeCode, the Inno
//! Setup AppId, the ProgIDs of P and the AUMIDs. Never from paths or from value data.
//!
//! # What is kept
//!
//! A token is kept only when it occurs in **no other app's anchors** (the fields of every other
//! inventory entry, and the names other programs registered, see `anchors`) and is **absent from the
//! baseline** of this Windows, when there is one. A token two products share, or that Windows itself
//! uses, identifies neither.

use purge_guard::prefix;
use purge_index::baseline::Baseline;
use purge_model::{HarvestedToken, InventoryEntry, SourceId};

/// Fewest hexadecimal digits of a non-GUID token.
pub const MIN_HEX_LEN: usize = 12;

/// Length of a GUID without braces.
const GUID_LEN: usize = 36;

/// Why a candidate token was not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    /// It occurs in an anchor of another inventory entry (its display name).
    OtherApp(String),
    /// It occurs in a name another program registered.
    ForeignName(String),
    /// It occurs in the clean-Windows baseline.
    Baseline,
}

/// A candidate token that was not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedToken {
    /// The token.
    pub token: String,
    /// Where it was taken from.
    pub source: SourceId,
    /// Why it was dropped.
    pub reason: DropReason,
}

/// The tokens of one app.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenHarvest {
    /// The kept tokens, in the order of their sources, each once.
    pub tokens: Vec<HarvestedToken>,
    /// The candidates that were dropped.
    pub dropped: Vec<DroppedToken>,
}

/// What the token harvest reads.
#[derive(Debug, Clone, Copy)]
pub struct TokenInput<'a> {
    /// The entry being harvested.
    pub entry: &'a InventoryEntry,
    /// Every entry of the inventory (the target may be among them).
    pub inventory: &'a [InventoryEntry],
    /// The ProgID set P.
    pub progids: &'a [String],
    /// The app's AUMIDs.
    pub aumids: &'a [String],
    /// The `AppId` of the Inno Setup uninstall log, when one was read.
    pub inno_app_id: Option<&'a str>,
    /// Names other programs registered (ProgIDs, AUMIDs, registered applications).
    pub foreign_names: &'a [String],
    /// The baseline **for this Windows**, when there is one.
    pub baseline: Option<&'a Baseline>,
}

fn is_guid_at(bytes: &[u8]) -> bool {
    bytes.len() >= GUID_LEN
        && bytes[..GUID_LEN].iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// The tokens a name contains, in order, as found (GUIDs without braces).
pub fn extract(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if !bytes[i].is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        // At the start of a run of letters and digits.
        if is_guid_at(&bytes[i..])
            && bytes
                .get(i + GUID_LEN)
                .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'-')
        {
            out.push(text[i..i + GUID_LEN].to_owned());
            i += GUID_LEN;
            continue;
        }
        let end = bytes[i..]
            .iter()
            .position(|b| !b.is_ascii_alphanumeric())
            .map_or(bytes.len(), |n| i + n);
        let run = &bytes[i..end];
        // A run next to a non-ASCII letter is part of a longer word.
        let delimited = text[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric())
            && text[end..]
                .chars()
                .next()
                .is_none_or(|c| !c.is_alphanumeric());
        if delimited
            && run.len() >= MIN_HEX_LEN
            && run.iter().all(u8::is_ascii_hexdigit)
            && run.iter().any(u8::is_ascii_digit)
            && run.iter().any(u8::is_ascii_alphabetic)
        {
            out.push(text[i..end].to_owned());
        }
        i = end;
    }
    out
}

/// The strings of another entry a token must not occur in.
fn entry_anchors(entry: &InventoryEntry) -> impl Iterator<Item = &str> {
    prefix::leaf(&entry.key_path)
        .into_iter()
        .chain(entry.product_code.as_deref())
        .chain(entry.upgrade_code.as_deref())
        .chain(entry.inno_app_id.as_deref())
        .chain(entry.uninstall_string.as_deref())
        .chain(entry.quiet_uninstall_string.as_deref())
        .chain(entry.install_location.as_deref())
        .chain(entry.display_icon.as_deref())
}

/// Whether `other` is another app than `entry`: not the entry itself, and not the same registration
/// seen through another view or hive (the same `UninstallString`).
fn is_other_app(entry: &InventoryEntry, other: &InventoryEntry) -> bool {
    if other.program_id == entry.program_id {
        return false;
    }
    match (&entry.uninstall_string, &other.uninstall_string) {
        // Two empty commands say nothing about being the same registration.
        (Some(a), Some(b)) => a.trim().is_empty() || !a.trim().eq_ignore_ascii_case(b.trim()),
        _ => true,
    }
}

/// Extracts the app's tokens and keeps the ones that are its alone; see the module documentation.
pub fn harvest(input: TokenInput<'_>) -> TokenHarvest {
    // Candidates, in source order.
    let mut candidates: Vec<(String, SourceId)> = Vec::new();
    let mut add = |text: &str, source: String| {
        for token in extract(text) {
            if !candidates
                .iter()
                .any(|(t, _)| t.eq_ignore_ascii_case(&token))
            {
                candidates.push((token, SourceId(source.clone())));
            }
        }
    };
    if let Some(name) = prefix::leaf(&input.entry.key_path) {
        add(name, "arp:key".into());
    }
    if let Some(code) = &input.entry.product_code {
        add(code, "msi:product-code".into());
    }
    if let Some(code) = &input.entry.upgrade_code {
        add(code, "msi:upgrade-code".into());
    }
    for app_id in input
        .inno_app_id
        .into_iter()
        .chain(input.entry.inno_app_id.as_deref())
    {
        add(app_id, "inno:appid".into());
    }
    for progid in input.progids {
        add(progid, format!("progid:{progid}"));
    }
    for aumid in input.aumids {
        add(aumid, format!("aumid:{aumid}"));
    }

    // What the others hold, folded once.
    let others: Vec<(&str, Vec<String>)> = input
        .inventory
        .iter()
        .filter(|other| is_other_app(input.entry, other))
        .map(|other| {
            (
                other.display_name.as_str(),
                entry_anchors(other).map(prefix::fold).collect(),
            )
        })
        .collect();
    let foreign: Vec<(&str, String)> = input
        .foreign_names
        .iter()
        .map(|n| (n.as_str(), prefix::fold(n)))
        .collect();

    let mut out = TokenHarvest::default();
    for (token, source) in candidates {
        let folded = prefix::fold(&token);
        let reason = others
            .iter()
            .find(|(_, anchors)| anchors.iter().any(|a| a.contains(&folded)))
            .map(|(name, _)| DropReason::OtherApp((*name).to_owned()))
            .or_else(|| {
                foreign
                    .iter()
                    .find(|(_, name)| name.contains(&folded))
                    .map(|(name, _)| DropReason::ForeignName((*name).to_owned()))
            })
            .or_else(|| {
                input
                    .baseline
                    .is_some_and(|b| b.has_token(&token))
                    .then_some(DropReason::Baseline)
            });
        match reason {
            None => out.tokens.push(HarvestedToken { token, source }),
            Some(reason) => out.dropped.push(DroppedToken {
                token,
                source,
                reason,
            }),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roots::tests_support::entry;

    const HASH: &str = "308046B0AF4A39CB";

    #[test]
    fn extracts_guids_and_long_hex_runs() {
        assert_eq!(extract("FirefoxHTML-308046B0AF4A39CB"), [HASH]);
        assert_eq!(
            extract("{EA457B21-F73E-494C-ACAB-524FDE069978}_is1"),
            ["EA457B21-F73E-494C-ACAB-524FDE069978"]
        );
        // An Inno AppId as the log stores it, and a GUID followed by more text.
        assert_eq!(
            extract("{{771FD6B0-FA20-440A-A002-3B3BAC16DC50}"),
            ["771FD6B0-FA20-440A-A002-3B3BAC16DC50"]
        );
        assert_eq!(
            extract("Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38.updates"),
            ["1de4eec8-1241-4177-a864-e594e8d1fb38"]
        );
        // Two tokens in one name, in order.
        assert_eq!(
            extract("App_0123456789ab.{11111111-2222-3333-4444-555555555555}"),
            ["0123456789ab", "11111111-2222-3333-4444-555555555555"]
        );
        // Too short, not hexadecimal, hexadecimal letters only, or part of a longer word.
        for none in [
            "",
            "VSCode.txt",
            "Firefox-308046B0AF4",
            "App-308046B0AF4A39CG",
            "deadbeefcafe",
            "X308046B0AF4A39CB",
            "308046B0AF4A39CBx",
            "é308046B0AF4A39CB",
            "Git_is1",
        ] {
            assert!(extract(none).is_empty(), "{none:?} -> {:?}", extract(none));
        }
        // A GUID with a group too many is not a GUID; its last groups are still a long hex run.
        assert_eq!(
            extract("11111111-2222-3333-4444-55555555555A-6666"),
            ["55555555555A"]
        );
        // Regression: a run of decimal digits alone is a date, a build number or a timestamp, never
        // an identifier of one app.
        for none in [
            "build.202611120815",
            "App_20261112081530",
            "11111111-2222-3333-4444-555555555555-6666",
        ] {
            assert!(extract(none).is_empty(), "{none:?} -> {:?}", extract(none));
        }
    }

    /// Regression: two entries with an empty `UninstallString` are not "the same registration"; the
    /// other entry's anchors still drop a shared token.
    #[test]
    fn an_empty_uninstall_string_does_not_make_two_entries_one_app() {
        let mut target = entry("App-308046B0AF4A39CB", "App");
        target.uninstall_string = Some("  ".into());
        let mut other = entry("Other", "Other App");
        other.uninstall_string = Some(String::new());
        other.display_icon = Some(format!(r"C:\ProgramData\Shared\{HASH}\icon.ico"));
        let inventory = [target.clone(), other];
        let got = harvest(input(&target, &inventory, &[], &[]));
        assert!(got.tokens.is_empty(), "{:?}", got.tokens);
        assert_eq!(
            got.dropped[0].reason,
            DropReason::OtherApp("Other App".into())
        );
    }

    fn firefox() -> InventoryEntry {
        let mut e = entry(
            "Mozilla Firefox 145.0 (x64 en-US)",
            "Mozilla Firefox (x64 en-US)",
        );
        e.uninstall_string =
            Some(r#""C:\Program Files\Mozilla Firefox\uninstall\helper.exe""#.into());
        e
    }

    fn input<'a>(
        entry: &'a InventoryEntry,
        inventory: &'a [InventoryEntry],
        progids: &'a [String],
        foreign: &'a [String],
    ) -> TokenInput<'a> {
        TokenInput {
            entry,
            inventory,
            progids,
            aumids: &[],
            inno_app_id: None,
            foreign_names: foreign,
            baseline: None,
        }
    }

    #[test]
    fn the_firefox_install_hash_is_harvested() {
        let target = firefox();
        let mut thunderbird = entry(
            "Mozilla Thunderbird 140.0 (x64 en-US)",
            "Mozilla Thunderbird (x64 en-US)",
        );
        thunderbird.uninstall_string =
            Some(r#""C:\Program Files\Mozilla Thunderbird\uninstall\helper.exe""#.into());
        let inventory = [target.clone(), thunderbird];
        let progids = [
            format!("FirefoxHTML-{HASH}"),
            format!("FirefoxPDF-{HASH}"),
            format!("FirefoxURL-{HASH}"),
        ];
        // Thunderbird's own ProgIDs carry another hash.
        let foreign = [
            "ThunderbirdEML-D78BF5DD33499EC2".to_owned(),
            "Thunderbird.Url.mailto".to_owned(),
        ];
        let aumids = [format!("FirefoxToast-{HASH}")];
        let got = harvest(TokenInput {
            aumids: &aumids,
            ..input(&target, &inventory, &progids, &foreign)
        });
        assert_eq!(
            got.tokens,
            [HarvestedToken {
                token: HASH.into(),
                source: SourceId(format!("progid:FirefoxHTML-{HASH}")),
            }]
        );
        assert!(got.dropped.is_empty());
    }

    #[test]
    fn a_token_another_app_also_carries_is_dropped() {
        let target = firefox();
        let inventory = [target.clone()];
        let progids = [
            format!("FirefoxHTML-{HASH}"),
            "FirefoxURL-AAAA0000BBBB1111".to_owned(),
        ];
        // The same hash in one of Thunderbird's ProgIDs.
        let foreign = [format!("ThunderbirdEML-{}", HASH.to_lowercase())];
        let got = harvest(input(&target, &inventory, &progids, &foreign));
        assert_eq!(got.tokens.len(), 1);
        assert_eq!(got.tokens[0].token, "AAAA0000BBBB1111");
        assert_eq!(
            got.dropped,
            [DroppedToken {
                token: HASH.into(),
                source: SourceId(format!("progid:FirefoxHTML-{HASH}")),
                reason: DropReason::ForeignName(foreign[0].clone()),
            }]
        );

        // The same hash in another inventory entry's fields.
        let mut thunderbird = entry("Mozilla Thunderbird", "Mozilla Thunderbird (x64 en-US)");
        thunderbird.display_icon = Some(format!(r"C:\ProgramData\Mozilla\{HASH}\icon.ico"));
        let inventory = [target.clone(), thunderbird];
        let got = harvest(input(&target, &inventory, &progids[..1], &[]));
        assert!(got.tokens.is_empty());
        assert_eq!(
            got.dropped[0].reason,
            DropReason::OtherApp("Mozilla Thunderbird (x64 en-US)".into())
        );
    }

    #[test]
    fn arp_key_msi_codes_and_inno_appid_are_sources_and_twins_are_not_other_apps() {
        const GUID: &str = "EA457B21-F73E-494C-ACAB-524FDE069978";
        let mut target = entry(&format!("{{{GUID}}}_is1"), "Microsoft Visual Studio Code");
        target.uninstall_string =
            Some(r#""C:\Program Files\Microsoft VS Code\unins000.exe""#.into());
        target.inno_app_id = Some(format!("{{{GUID}}}"));
        target.upgrade_code = Some("{11111111-2222-3333-4444-555555555555}".into());
        // The same registration seen through the 32-bit view: not another app.
        let mut twin = target.clone();
        twin.program_id =
            purge_model::ProgramId::machine(purge_model::View::K32, format!("{{{GUID}}}_is1"))
                .unwrap();
        let inventory = [target.clone(), twin];
        let got = harvest(TokenInput {
            inno_app_id: Some(&format!("{{{{{}}}", GUID.to_lowercase())),
            ..input(&target, &inventory, &[], &[])
        });
        assert_eq!(
            got.tokens,
            [
                HarvestedToken {
                    token: GUID.into(),
                    source: SourceId("arp:key".into()),
                },
                HarvestedToken {
                    token: "11111111-2222-3333-4444-555555555555".into(),
                    source: SourceId("msi:upgrade-code".into()),
                },
            ]
        );

        // A different product with the same key name in another hive is another app.
        let mut other = entry(&format!("{{{GUID}}}_is1"), "Something Else");
        other.program_id =
            purge_model::ProgramId::machine(purge_model::View::K32, format!("{{{GUID}}}_is1"))
                .unwrap();
        other.uninstall_string = Some(r#""C:\Else\unins000.exe""#.into());
        let inventory = [target.clone(), other];
        let got = harvest(input(&target, &inventory, &[], &[]));
        assert_eq!(got.tokens.len(), 1);
        assert_eq!(got.tokens[0].source, SourceId("msi:upgrade-code".into()));
        assert_eq!(
            got.dropped[0].reason,
            DropReason::OtherApp("Something Else".into())
        );
    }
}
