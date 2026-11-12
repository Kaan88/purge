//! Merging Windows Installer's product list into the ARP entries (ENGINE_PLAN.md §4.1 "MSI").
//!
//! The products come from `SystemSource::msi_products()` (`MsiEnumProductsExW` over every context the
//! engine can see). A product is attached to an entry **by ProductCode only**, never by name: product
//! names and `DisplayName`s differ freely (`7-Zip 24.08 (x64 edition)` vs `7-Zip 24.08 (x64)`), and two
//! products may share a name.
//!
//! The entry's ProductCode is the one kind detection found ([`crate::kind`]). An entry that kind detection
//! could not classify but whose key name is a `{GUID}` equal to a product's code is that product's ARP key
//! by definition; it takes the code and becomes [`InstallerKind::Msi`].
//!
//! Matching, in two passes so a loose match never takes a product's own key:
//! 1. **Context-consistent**: a machine product attaches to `HKLM` entries with its code, a per-user
//!    product to the entries of its user's hive (`HKU\<sid>`).
//! 2. **Code only**: a product with no consistent entry attaches to entries with its code that have no
//!    product yet (a per-user product whose key Windows Installer registered elsewhere).
//!
//! Attaching sets [`InventoryEntry::msi`] and adds the product's `InstallDate` as
//! [`InstallTimeSource::MsiInstallDate`] evidence; values from the key are never overwritten. A product
//! that matches no entry goes to [`InventoryDoc::msi_only`]. An entry never gains or loses a place in the
//! list here: the entry set is exactly the ARP enumeration.

use purge_model::{
    InstallTimeEvidence, InstallTimeSource, InstallerKind, InventoryDoc, InventoryEntry,
    InventorySchema, MsiContext, MsiInfo, MsiOnlyRow,
};
use purge_source::types::MsiProduct;

use crate::arp::parse_install_date;
use crate::kind::is_braced_guid;

/// The ProductCode an entry is matched by: its own, or its `{GUID}` key name when kind detection left it
/// [`InstallerKind::Unknown`]. Upper case.
fn match_code(e: &InventoryEntry) -> Option<String> {
    match (&e.product_code, e.installer_kind) {
        (Some(code), _) => Some(code.to_ascii_uppercase()),
        (None, InstallerKind::Unknown) if is_braced_guid(e.program_id.key_name()) => {
            Some(e.program_id.key_name().to_ascii_uppercase())
        }
        _ => None,
    }
}

/// Whether the entry's hive is where a product of this context and user registers.
fn context_consistent(e: &InventoryEntry, p: &MsiProduct) -> bool {
    match (p.context, e.hive_sid.as_deref()) {
        (MsiContext::Machine, sid) => sid.is_none(),
        (_, None) => false,
        (_, Some(sid)) => p
            .user_sid
            .as_deref()
            .is_none_or(|u| u.eq_ignore_ascii_case(sid)),
    }
}

fn attach(e: &mut InventoryEntry, p: &MsiProduct, code: &str, utc_offset_secs: i64) {
    if e.product_code.is_none() {
        e.product_code = Some(code.to_owned());
        if e.installer_kind == InstallerKind::Unknown {
            e.installer_kind = InstallerKind::Msi;
        }
    }
    e.msi = Some(MsiInfo {
        context: p.context,
        local_package: p.local_package.clone(),
        install_date: p.install_date.clone(),
    });
    if let Some(time) = p
        .install_date
        .as_deref()
        .and_then(|d| parse_install_date(d, utc_offset_secs))
    {
        e.install_time_evidence.push(InstallTimeEvidence {
            source: InstallTimeSource::MsiInstallDate,
            time,
        });
    }
}

/// Merges `products` into `entries` by ProductCode (see the module documentation) and builds the
/// inventory document. `utc_offset_secs` turns MSI's `InstallDate` day into local midnight, as in
/// [`crate::arp::ArpOptions::utc_offset_secs`].
pub fn merge(
    mut entries: Vec<InventoryEntry>,
    products: &[MsiProduct],
    utc_offset_secs: i64,
) -> InventoryDoc {
    let codes: Vec<Option<String>> = entries.iter().map(match_code).collect();
    let product_codes: Vec<String> = products
        .iter()
        .map(|p| p.code.trim().to_ascii_uppercase())
        .collect();
    let mut matched = vec![false; products.len()];

    // Pass 1: context-consistent matches.
    for (pi, p) in products.iter().enumerate() {
        let code = &product_codes[pi];
        for (ei, e) in entries.iter_mut().enumerate() {
            if codes[ei].as_deref() == Some(code.as_str()) && context_consistent(e, p) {
                matched[pi] = true;
                if e.msi.is_none() {
                    attach(e, p, code, utc_offset_secs);
                }
            }
        }
    }
    // Pass 2: code-only matches for products that found no consistent entry.
    for (pi, p) in products.iter().enumerate() {
        if matched[pi] {
            continue;
        }
        let code = &product_codes[pi];
        for (ei, e) in entries.iter_mut().enumerate() {
            if codes[ei].as_deref() == Some(code.as_str()) && e.msi.is_none() {
                matched[pi] = true;
                attach(e, p, code, utc_offset_secs);
            }
        }
    }

    let msi_only = products
        .iter()
        .zip(product_codes)
        .zip(matched)
        .filter(|(_, m)| !m)
        .map(|((p, code), _)| MsiOnlyRow {
            product_code: code,
            context: p.context,
            user_sid: match p.context {
                MsiContext::Machine => None,
                _ => p.user_sid.clone(),
            },
            product_name: p.name.clone(),
            version: p.version.clone(),
            publisher: p.publisher.clone(),
            install_location: p.install_location.clone(),
            local_package: p.local_package.clone(),
            install_date: p.install_date.clone(),
        })
        .collect();
    InventoryDoc {
        schema: InventorySchema,
        entries,
        msi_only,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arp::{ArpOptions, enumerate, inventory};
    use purge_source::fixture::Fixture;
    use purge_source::types::RegData;

    const SID: &str = "S-1-5-21-1-2-3-1001";
    const HKLM64: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    const ZIP: &str = "{23170F69-40C1-2702-2408-000001000000}";
    const HIDDEN: &str = "{AAAAAAAA-0000-0000-0000-000000000001}";
    const USERPC: &str = "{BBBBBBBB-0000-0000-0000-000000000002}";

    fn product(code: &str, context: MsiContext, sid: Option<&str>, name: &str) -> MsiProduct {
        MsiProduct {
            code: code.into(),
            context,
            user_sid: sid.map(String::from),
            name: Some(name.into()),
            version: Some("1.0".into()),
            publisher: Some("Vendor".into()),
            install_location: None,
            local_package: Some(r"C:\Windows\Installer\1a2b.msi".into()),
            install_date: Some("20261112".into()),
        }
    }

    fn fixture() -> Fixture {
        let mut f = Fixture::new();
        // Differing names: the merge must not care.
        let zip = format!(r"{HKLM64}\{ZIP}");
        f.set_value(
            &zip,
            "DisplayName",
            RegData::from_sz("7-Zip 24.08 (x64 edition)"),
        );
        f.set_value(
            &zip,
            "UninstallString",
            RegData::from_expand_sz(&format!("MsiExec.exe /I{ZIP}")),
        );
        // A GUID key without msiexec: Unknown until the merge recognises the code.
        let sc = format!(
            r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Uninstall\{}",
            USERPC.to_ascii_lowercase()
        );
        f.set_value(&sc, "SystemComponent", RegData::from_dword(1));
        // A non-MSI entry that shares nothing.
        f.set_value(
            &format!(r"{HKLM64}\Git_is1"),
            "DisplayName",
            RegData::from_sz("Git"),
        );
        f.system_mut().user_sid = Some(SID.into());
        f.add_msi_product(product(ZIP, MsiContext::Machine, None, "7-Zip 24.08 (x64)"));
        f.add_msi_product(product(
            HIDDEN,
            MsiContext::Machine,
            Some("S-1-5-18"),
            "Hidden Runtime",
        ));
        f.add_msi_product(product(
            USERPC,
            MsiContext::UserUnmanaged,
            Some(SID),
            "Per-user thing",
        ));
        f
    }

    #[test]
    fn merge_by_code_with_differing_names_and_msi_only() {
        let f = fixture();
        let inv = inventory(&f, &f, &f, 0);
        assert!(inv.warnings.is_empty(), "{:?}", inv.warnings);
        let doc = inv.doc;
        assert_eq!(doc.entries.len(), 3, "the entry set is the ARP enumeration");

        let zip = doc
            .entry(&format!("HKLM|64|{ZIP}").parse().unwrap())
            .unwrap();
        assert_eq!(zip.display_name, "7-Zip 24.08 (x64 edition)");
        assert_eq!(zip.installer_kind, InstallerKind::Msi);
        let msi = zip.msi.as_ref().unwrap();
        assert_eq!(msi.context, MsiContext::Machine);
        assert_eq!(msi.install_date.as_deref(), Some("20261112"));
        let day = parse_install_date("20261112", 0).unwrap();
        assert!(zip.install_time_evidence.contains(&InstallTimeEvidence {
            source: InstallTimeSource::MsiInstallDate,
            time: day
        }));

        let user = &doc.entries[2];
        assert_eq!(user.hive_sid.as_deref(), Some(SID));
        assert_eq!(user.installer_kind, InstallerKind::Msi);
        assert_eq!(user.product_code.as_deref(), Some(USERPC));
        assert_eq!(
            user.msi.as_ref().unwrap().context,
            MsiContext::UserUnmanaged
        );

        let git = doc.entry(&"HKLM|64|Git_is1".parse().unwrap()).unwrap();
        assert_eq!(git.msi, None);

        assert_eq!(doc.msi_only.len(), 1);
        let row = &doc.msi_only[0];
        assert_eq!(row.product_code, HIDDEN);
        assert_eq!(row.user_sid, None, "machine rows carry no SID");
        assert_eq!(row.product_name.as_deref(), Some("Hidden Runtime"));
        // The document serialises as purge.inventory/0 and reads back equal.
        let json = serde_json::to_string(&doc).unwrap();
        assert_eq!(serde_json::from_str::<InventoryDoc>(&json).unwrap(), doc);
    }

    #[test]
    fn context_decides_between_two_keys_with_one_code() {
        // The same code under HKLM and under a user hive: the machine product takes the HKLM key, the
        // user's product the user's key.
        let mut f = Fixture::new();
        f.set_value(
            &format!(r"{HKLM64}\{ZIP}"),
            "WindowsInstaller",
            RegData::from_dword(1),
        );
        f.set_value(
            &format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Uninstall\{ZIP}"),
            "WindowsInstaller",
            RegData::from_dword(1),
        );
        let scan = enumerate(&f, &f, &ArpOptions::default());
        let mut user_product = product(ZIP, MsiContext::UserManaged, Some(SID), "u");
        user_product.local_package = Some("user.msi".into());
        let doc = merge(
            scan.entries,
            &[user_product, product(ZIP, MsiContext::Machine, None, "m")],
            0,
        );
        assert_eq!(doc.entries[0].hive_sid, None);
        assert_eq!(
            doc.entries[0].msi.as_ref().unwrap().context,
            MsiContext::Machine
        );
        assert_eq!(
            doc.entries[1]
                .msi
                .as_ref()
                .unwrap()
                .local_package
                .as_deref(),
            Some("user.msi")
        );
        assert!(doc.msi_only.is_empty());
    }

    #[test]
    fn loose_match_only_when_no_consistent_key() {
        // A per-user product of another user whose only key is under HKLM: attached by code in pass 2.
        let mut f = Fixture::new();
        f.set_value(
            &format!(r"{HKLM64}\{ZIP}"),
            "WindowsInstaller",
            RegData::from_dword(1),
        );
        let scan = enumerate(&f, &f, &ArpOptions::default());
        let doc = merge(
            scan.entries,
            &[product(
                ZIP,
                MsiContext::UserUnmanaged,
                Some("S-1-5-21-9"),
                "x",
            )],
            0,
        );
        assert_eq!(
            doc.entries[0].msi.as_ref().unwrap().context,
            MsiContext::UserUnmanaged
        );
        assert!(doc.msi_only.is_empty());
        // A Burn bundle whose GUID key happens to equal a code is never taken.
        let mut e = doc.entries[0].clone();
        e.installer_kind = InstallerKind::Burn;
        e.product_code = None;
        e.msi = None;
        let doc = merge(vec![e], &[product(ZIP, MsiContext::Machine, None, "x")], 0);
        assert_eq!(doc.entries[0].msi, None);
        assert_eq!(doc.msi_only.len(), 1);
        assert_eq!(doc.msi_only[0].product_code, ZIP);
    }

    #[test]
    fn missing_product_list_warns() {
        let mut f = fixture();
        f.set_msi_products(None);
        let inv = inventory(&f, &f, &f, 0);
        assert_eq!(inv.doc.entries.len(), 3);
        assert!(inv.doc.msi_only.is_empty());
        assert_eq!(inv.warnings.len(), 1, "{:?}", inv.warnings);
        assert_eq!(inv.warnings[0].location, "msi");
    }
}
