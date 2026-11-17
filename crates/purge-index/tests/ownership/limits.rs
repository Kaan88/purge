//! Memory limits and the key-open budget.

use purge_index::ownership::{
    MACHINE_SID, OwnershipIndex, OwnershipInput, OwnershipLimits, unpack_guid,
};
use purge_model::{InventoryEntry, MsiContext};
use purge_source::metered::{Meter, MeteredRegistry, Op};
use purge_source::types::RegData;

use crate::rows::{row, tables};
use crate::*;

fn build_limited(
    fx: &purge_source::fixture::Fixture,
    products: &[InventoryEntry],
    limits: OwnershipLimits,
) -> OwnershipIndex {
    OwnershipIndex::build_with_limits(
        &OwnershipInput {
            reg: fx,
            fs: fx,
            sys: fx,
            products,
            msi_only: &[],
            cache: None,
            threads: 4,
        },
        limits,
    )
}

#[test]
fn memory_cap_marks_rest_unreadable() {
    let mut fx = base();
    let codes = [P1, P2, P3];
    let mut products = Vec::new();
    for (i, code) in codes.iter().enumerate() {
        let lp = format!(r"C:\Windows\Installer\{i}.msi");
        let rows = (0..10)
            .map(|n| {
                row(
                    &format!("r{i}_{n}"),
                    2,
                    &format!(r"SOFTWARE\P{i}\K{n}"),
                    Some("V"),
                    Some("1"),
                )
            })
            .collect();
        fx.set_msi_tables(&lp, tables(rows));
        products.push(machine(code, &lp));
    }
    // Each package has 10 registry rows, 3 properties and 1 component: 14 rows read.
    let limits = OwnershipLimits {
        max_component_clients: 2_000_000,
        max_rows: 20,
    };
    let ix = build_limited(&fx, &products, limits);
    assert!(ix.stats().capped);
    assert!(!ix.stats().complete("rows"));
    let unreadable: Vec<&str> = ix
        .unreadable()
        .iter()
        .map(|p| p.product_code.as_str())
        .collect();
    assert_eq!(unreadable, vec![P2, P3]);
    assert_eq!(ix.key_owners(r"HKLM\SOFTWARE\P0").len(), 10);
    assert!(ix.key_owners(r"HKLM\SOFTWARE\P1").is_empty());

    // The component pairs: past the limit, reading stops and every product is unknown territory.
    let mut fx = base();
    for i in 0..10u32 {
        let comp = unpack_guid(&format!("{i:032X}")).unwrap();
        client(&mut fx, MACHINE_SID, &comp, P1, &format!(r"C:\App\{i}.dll"));
    }
    let limits = OwnershipLimits {
        max_component_clients: 4,
        max_rows: 2_000_000,
    };
    let ix = build_limited(&fx, &[], limits);
    assert!(ix.stats().capped);
    assert!(!ix.stats().complete("components"));
    assert!(ix.stats().components <= 4);
}

#[test]
fn budget_key_opens() {
    const PRODUCTS: usize = 300;
    const COMPONENTS: usize = 20_000;
    let mut fx = base();
    let sids = [MACHINE_SID, USER];
    let codes: Vec<String> = (0..PRODUCTS)
        .map(|i| unpack_guid(&format!("{:032X}", 0xA000_0000_u64 + i as u64)).unwrap())
        .collect();
    for c in 0..COMPONENTS {
        let sid = sids[c % 2];
        let comp = format!("{:032X}", 0xB000_0000_u64 + c as u64);
        let key = format!("{USERDATA}\\{sid}\\Components\\{comp}");
        fx.set_value(
            &key,
            &packed(&codes[c % PRODUCTS]),
            RegData::from_sz(&format!(r"C:\Program Files\P{}\f{c}.dll", c % PRODUCTS)),
        );
    }
    // Something else under UserData that the read must not open.
    for sid in sids {
        fx.add_key(&format!(
            "{USERDATA}\\{sid}\\Products\\X\\InstallProperties"
        ));
    }
    let products: Vec<InventoryEntry> = codes
        .iter()
        .map(|c| entry(c, MsiContext::Machine, None, None))
        .collect();
    let meter = Meter::new();
    let reg = MeteredRegistry::new(&fx, &meter);
    let ix = OwnershipIndex::build(&OwnershipInput {
        reg: &reg,
        fs: &fx,
        sys: &fx,
        products: &products,
        msi_only: &[],
        cache: None,
        threads: 8,
    });
    let bound = (COMPONENTS + sids.len() + 4) as u64;
    let opens = meter.snapshot().get(Op::RegKeyInfo).calls;
    assert!(opens <= bound, "{opens} key opens > {bound}");
    assert!(u64::from(ix.stats().component_keys_opened) <= bound);
    assert_eq!(ix.stats().components as usize, COMPONENTS);
    assert_eq!(ix.stats().products as usize, PRODUCTS);
    // One values() per component key and nothing below them.
    let values = meter.snapshot().get(Op::RegValues).calls;
    assert!(values <= (COMPONENTS + 4) as u64, "{values}");
    assert_eq!(
        ix.components_of(&packed(&codes[7])).len(),
        COMPONENTS / PRODUCTS + 1
    );
}
