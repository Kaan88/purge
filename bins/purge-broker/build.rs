//! Embeds `purge-broker.manifest` (common controls v6 for the consent TaskDialog) in the MSVC binary,
//! and a VERSIONINFO resource (the workspace version) through `../versioninfo.rs`. The manifest is
//! linked by the linker (`/MANIFEST:EMBED`), the version block as a compiled `.res`: separate
//! resource types, so neither replaces the other.

include!("../versioninfo.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=purge-broker.manifest");
    embed_version_resource("purge-broker.exe", "Purge elevated broker");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-bins=/MANIFESTINPUT:{dir}\\purge-broker.manifest");
        println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:NO");
        // M3-R1 M1: the loader resolves the static imports before `main` runs, so the application
        // directory is searched for every import that is not a KnownDLL. This flag makes that search
        // System32 only, which also covers a copy of the broker outside the checked install directory.
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
}
