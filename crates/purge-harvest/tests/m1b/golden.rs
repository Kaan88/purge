//! Without MSI, Burn or system objects, the fingerprint is the M1a document byte for byte. The golden
//! files were written by the M1a harvest (commit 52b0e56) from the shapes in [`super::shapes`].

use super::shapes::m1a_shapes;
use super::*;

#[test]
fn fingerprint_without_msi_is_byte_equal_to_m1a() {
    let data = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/m1b");
    for (name, file, f) in m1a_shapes() {
        let report = harvest_of(&f, name);
        let fp = &report.fingerprint;
        assert!(
            fp.msi.is_empty() && fp.burn.is_none() && fp.sys.is_empty(),
            "{name}"
        );
        assert!(
            report.ownership.is_none(),
            "{name}: no ownership index for a non-MSI app"
        );
        let golden = std::fs::read_to_string(data.join(file)).unwrap();
        let golden = golden.replace("\r\n", "\n");
        assert_eq!(purge_harvest::harvest::to_json(fp), golden, "{name}");
    }
}
