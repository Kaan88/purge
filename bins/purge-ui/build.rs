//! Embeds `purge-ui.manifest` (asInvoker, per-monitor v2 DPI awareness, common controls v6) and the
//! product icon in Purge.exe, and a VERSIONINFO resource (the workspace version) through
//! `../versioninfo.rs`. The manifest is linked by the linker (`/MANIFEST:EMBED`); the version block
//! and the icon are one compiled `.res`.

include!("../versioninfo.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=purge-ui.manifest");
    println!("cargo:rerun-if-changed=assets/Purge.ico");
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    // The icon, resource id 1 (the one Explorer shows), compiled with the version block.
    let icon = std::path::Path::new(&dir).join("assets").join("Purge.ico");
    let extra = format!(
        "1 ICON \"{}\"\n",
        icon.display().to_string().replace('\\', "/")
    );
    embed_version_resource_with("Purge.exe", "Purge", &extra);
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-bins=/MANIFESTINPUT:{dir}\\purge-ui.manifest");
        println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:NO");
    }
}
