//! Embeds `purge-broker.manifest` (common controls v6 for the consent TaskDialog) in the MSVC binary.

fn main() {
    println!("cargo:rerun-if-changed=purge-broker.manifest");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-bins=/MANIFESTINPUT:{dir}\\purge-broker.manifest");
        println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:NO");
    }
}
