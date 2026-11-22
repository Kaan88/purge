//! Tests of the ownership index (M1B-OWNERSHIP, contract C-OWNERSHIP). Every source is a fixture.

mod cache;
mod components;
mod limits;
mod rows;
mod stores;

use std::path::PathBuf;

use purge_index::ownership::{
    MACHINE_SID, OwnershipIndex, OwnershipInput, TableCache, USERDATA, pack_guid,
};
use purge_model::{
    InstallScope, InstallerKind, InventoryEntry, MsiContext, MsiInfo, ProgramId, RawFlags, View,
    WritableBy,
};
use purge_source::fixture::Fixture;
use purge_source::registry::RegistrySource;
use purge_source::types::{KeyInfo, RegData, RegValue, SourceError, SourceResult};

/// A user SID with a loaded hive in the tests.
pub const USER: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";

/// A product code.
pub const P1: &str = "{11111111-1111-1111-1111-111111111111}";
/// A second product code.
pub const P2: &str = "{22222222-2222-2222-2222-222222222222}";
/// A third product code.
pub const P3: &str = "{33333333-3333-3333-3333-333333333333}";
/// A component id.
pub const C1: &str = "{C1C1C1C1-0000-0000-0000-000000000001}";
/// A second component id.
pub const C2: &str = "{C2C2C2C2-0000-0000-0000-000000000002}";

/// The packed form of a `{GUID}`.
pub fn packed(guid: &str) -> String {
    pack_guid(guid).expect("test GUID")
}

/// The `Components\<packed component>` key under `UserData\<sid>`.
pub fn component_key(sid: &str, component: &str) -> String {
    format!("{USERDATA}\\{sid}\\Components\\{}", packed(component))
}

/// Registers `product` as a client of `component` under `sid` with key path `data`.
pub fn client(fx: &mut Fixture, sid: &str, component: &str, product: &str, data: &str) {
    fx.set_value(
        &component_key(sid, component),
        &packed(product),
        RegData::from_sz(data),
    );
}

/// A fixture with the current control set 1, the user's hive loaded and `UserData` present.
pub fn base() -> Fixture {
    let mut fx = Fixture::new();
    fx.set_current_control_set(1);
    fx.add_key(&format!("HKU\\{USER}\\Software"));
    fx.add_key(&format!("{USERDATA}\\{MACHINE_SID}\\Components"));
    fx.set_msi_tables_captured(true);
    fx
}

/// An inventory entry for an MSI product.
pub fn entry(
    code: &str,
    context: MsiContext,
    user_sid: Option<&str>,
    local_package: Option<&str>,
) -> InventoryEntry {
    let id = match user_sid {
        Some(sid) => ProgramId::user(sid, View::K64, code).unwrap(),
        None => ProgramId::machine(View::K64, code).unwrap(),
    };
    InventoryEntry {
        key_path: id.key_path(),
        program_id: id,
        hive_sid: user_sid.map(str::to_owned),
        view: View::K64,
        display_name: format!("Product {code}"),
        version: None,
        publisher: None,
        flags: RawFlags::default(),
        installer_kind: InstallerKind::Msi,
        scope: if user_sid.is_some() {
            InstallScope::User
        } else {
            InstallScope::Machine
        },
        product_code: Some(code.to_owned()),
        upgrade_code: None,
        inno_app_id: None,
        writable_by: WritableBy::Admin,
        install_location: None,
        uninstall_string: None,
        quiet_uninstall_string: None,
        display_icon: None,
        install_time_evidence: Vec::new(),
        msi: Some(MsiInfo {
            context,
            local_package: local_package.map(str::to_owned),
            install_date: None,
        }),
    }
}

/// A per-machine product with a package.
pub fn machine(code: &str, local_package: &str) -> InventoryEntry {
    entry(code, MsiContext::Machine, None, Some(local_package))
}

/// Builds the index over one fixture.
pub fn build(fx: &Fixture, products: &[InventoryEntry]) -> OwnershipIndex {
    build_with(fx, products, None)
}

/// Builds the index over one fixture with a cache.
pub fn build_with(
    fx: &Fixture,
    products: &[InventoryEntry],
    cache: Option<&dyn TableCache>,
) -> OwnershipIndex {
    OwnershipIndex::build(&OwnershipInput {
        reg: fx,
        fs: fx,
        sys: fx,
        products,
        msi_only: &[],
        cache,
        threads: 3,
    })
}

/// A fresh, empty directory under the system temp directory, removed by [`TempDir::drop`].
pub struct TempDir(pub PathBuf);

impl TempDir {
    /// Creates the directory for test `name`.
    pub fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("purge-ownership-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// The directory as a string.
    pub fn path_str(&self) -> String {
        self.0.to_str().unwrap().to_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The test data directory of this suite.
pub fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/ownership")
}

/// A registry that refuses a path through a registry link the way the live one does: a read of a key
/// below a link key is [`SourceError::ReparsePoint`], the link key itself is read. (The fixture alone
/// answers below a link as if the link were an ordinary key.)
pub struct LinkRefusing<'a>(pub &'a Fixture);

impl LinkRefusing<'_> {
    fn through_no_link(&self, key: &str) -> SourceResult<()> {
        let mut at = key.trim_end_matches('\\');
        while let Some((parent, _)) = at.rsplit_once('\\') {
            if self.0.key_info(parent).is_ok_and(|info| info.is_link) {
                return Err(SourceError::ReparsePoint);
            }
            at = parent;
        }
        Ok(())
    }
}

impl RegistrySource for LinkRefusing<'_> {
    fn key_info(&self, key: &str) -> SourceResult<KeyInfo> {
        self.through_no_link(key)?;
        self.0.key_info(key)
    }
    fn subkeys(&self, key: &str) -> SourceResult<Vec<String>> {
        self.through_no_link(key)?;
        self.0.subkeys(key)
    }
    fn values(&self, key: &str) -> SourceResult<Vec<RegValue>> {
        self.through_no_link(key)?;
        self.0.values(key)
    }
    fn value(&self, key: &str, name: &str) -> SourceResult<RegData> {
        self.through_no_link(key)?;
        self.0.value(key, name)
    }
    fn loaded_user_sids(&self) -> SourceResult<Vec<String>> {
        self.0.loaded_user_sids()
    }
    fn current_control_set(&self) -> SourceResult<u32> {
        self.0.current_control_set()
    }
}

/// Builds the index over one fixture whose registry is read through [`LinkRefusing`].
pub fn build_refusing_links(fx: &Fixture) -> OwnershipIndex {
    OwnershipIndex::build(&OwnershipInput {
        reg: &LinkRefusing(fx),
        fs: fx,
        sys: fx,
        products: &[],
        msi_only: &[],
        cache: None,
        threads: 3,
    })
}
