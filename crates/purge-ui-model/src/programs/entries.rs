//! The engine's list notifications as the Programs page's rows (the port of
//! `ui/Purge.Client/Model/ProgramEntries.cs`): a raw ARP row first (`programs.batch`), then what
//! `programs.patch` and `programs.get` learn about it.

use std::collections::HashMap;

use purge_model::{
    InstallScope, InstallTimeEvidence, InstallTimeSource, InstallerKind, InventoryEntry, ProgramId,
    RawFlags, WritableBy,
};
use purge_rpc::methods::{Icon, ProgramDetails, ProgramPatch, ProgramRow as WireRow};

/// One program of the list: the engine's [`InventoryEntry`] and whether it is an AppX package (a fact
/// `programs.patch` states that the inventory document has no field for).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramEntry {
    /// The entry as the engine described it so far.
    pub entry: InventoryEntry,
    /// An AppX (Store) package.
    pub appx: bool,
}

impl ProgramEntry {
    /// The entry a raw row stands for. The row carries no flags yet, so it reads as a named, non-system app.
    pub fn from_row(row: &WireRow) -> Self {
        let id = &row.program_id;
        let writable_by = match row.scope {
            InstallScope::Machine => WritableBy::Admin,
            InstallScope::User => WritableBy::User,
        };
        let entry = InventoryEntry {
            program_id: id.clone(),
            key_path: id.key_path(),
            hive_sid: id.hive_sid().map(str::to_owned),
            view: id.view(),
            display_name: row.name.clone(),
            version: row.version.clone(),
            publisher: row.publisher.clone(),
            flags: RawFlags {
                system_component: false,
                has_display_name: true,
                has_uninstall_string: true,
                parent_key: None,
                release_type: None,
                windows_installer: false,
            },
            installer_kind: InstallerKind::Unknown,
            scope: row.scope,
            product_code: None,
            upgrade_code: None,
            inno_app_id: None,
            writable_by,
            install_location: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            display_icon: None,
            install_time_evidence: row
                .install_time
                .map(|time| InstallTimeEvidence {
                    source: InstallTimeSource::ArpInstallDate,
                    time,
                })
                .into_iter()
                .collect(),
            msi: None,
        };
        Self { entry, appx: false }
    }

    /// An entry of an inventory document (the sample data): not an AppX package.
    pub fn from_inventory(entry: InventoryEntry) -> Self {
        Self { entry, appx: false }
    }

    /// The program id.
    pub fn id(&self) -> &ProgramId {
        &self.entry.program_id
    }

    /// The entry with a `programs.patch` applied; only the members the patch states change.
    pub fn apply_patch(&mut self, patch: &ProgramPatch) {
        let e = &mut self.entry;
        let kind = patch.installer.unwrap_or(e.installer_kind);
        let mut parent = patch
            .parent_key
            .clone()
            .or_else(|| e.flags.parent_key.clone());
        // A bundle id other than the entry's own names the Burn bundle it hangs under.
        if parent.is_none()
            && let Some(bundle) = &patch.bundle
            && *bundle != e.program_id
        {
            parent = Some(bundle.key_name().to_owned());
        }
        e.flags.system_component = patch.system_component.unwrap_or(e.flags.system_component);
        if let Some(unnamed) = patch.unnamed {
            e.flags.has_display_name = !unnamed;
        }
        e.flags.parent_key = parent;
        e.flags.windows_installer = e.flags.windows_installer || kind == InstallerKind::Msi;
        e.installer_kind = kind;
        if let Some(code) = &patch.product_code {
            e.product_code = Some(code.clone());
        }
        self.appx = patch.appx.unwrap_or(self.appx);
    }

    /// The entry with the details of `programs.get` filled in.
    pub fn apply_details(&mut self, details: &ProgramDetails) {
        let e = &mut self.entry;
        e.installer_kind = details.installer;
        e.writable_by = details.writable_by;
        e.install_location = details.install_location.clone();
        e.uninstall_string = details.uninstall_command.clone();
        e.quiet_uninstall_string = details.quiet_uninstall_command.clone();
        if let Some(code) = &details.product_code {
            e.product_code = Some(code.clone());
        }
        e.flags.has_uninstall_string = details.uninstall_command.is_some();
    }

    /// The entries of one `programs.list`: its `programs.batch` rows in order, with the `programs.patch`es
    /// that came before its reply applied (a patch for an id the list did not send is dropped). This is
    /// what the WinUI client's `ListProgramsAsync` built.
    pub fn from_list(rows: &[WireRow], patches: &[ProgramPatch]) -> Vec<ProgramEntry> {
        let mut entries: Vec<ProgramEntry> = rows.iter().map(Self::from_row).collect();
        let mut at: HashMap<&ProgramId, usize> = HashMap::with_capacity(entries.len());
        for (i, row) in rows.iter().enumerate() {
            at.insert(&row.program_id, i);
        }
        for patch in patches {
            if let Some(&i) = at.get(&patch.program_id) {
                entries[i].apply_patch(patch);
            }
        }
        entries
    }
}

/// One icon of an `icon.batch`, decoded: `bgra` is `None` when the engine could not read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramIcon {
    /// The program.
    pub program_id: ProgramId,
    /// Edge length in pixels (at most 256).
    pub px: u16,
    /// `px * px` BGRA pixels, not premultiplied.
    pub bgra: Option<Vec<u8>>,
}

impl ProgramIcon {
    /// The icon of an `icon.batch` entry; a missing, malformed or wrongly sized pixel buffer is "no icon".
    pub fn from_wire(icon: &Icon) -> Self {
        let px = icon.px.min(256);
        let bgra = icon
            .bgra
            .as_deref()
            .filter(|t| !t.is_empty() && px > 0)
            .and_then(decode_base64)
            .filter(|b| b.len() == usize::from(px) * usize::from(px) * 4);
        Self {
            program_id: icon.program_id.clone(),
            px,
            bgra,
        }
    }
}

/// `Convert.FromBase64String`: standard alphabet, `=` padding required, white space ignored.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = text
        .bytes()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .collect();
    if clean.len() % 4 != 0 {
        return None;
    }
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let groups = clean.len() / 4;
    let mut out = Vec::with_capacity(groups * 3);
    for (i, g) in clean.chunks_exact(4).enumerate() {
        let pad = match (i + 1 == groups, g[2], g[3]) {
            (true, b'=', b'=') => 2,
            (true, _, b'=') => 1,
            _ => 0,
        };
        let mut n = 0u32;
        for &c in &g[..4 - pad] {
            n = (n << 6) | value(c)?;
        }
        n <<= 6 * pad;
        let [_, b0, b1, b2] = n.to_be_bytes();
        out.push(b0);
        if pad < 2 {
            out.push(b1);
        }
        if pad < 1 {
            out.push(b2);
        }
    }
    Some(out)
}
