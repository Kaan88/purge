//! Embeds a VERSIONINFO resource (the workspace version) in Purge.exe: `../versioninfo.rs`. Hub reads
//! the installed Purge.exe's fixed FILEVERSION, and the release checks (install\inno\check-version.ps1,
//! purge.iss) refuse a Purge.exe without it.
//!
//! Minimal on purpose (UI-SHIP): UI-SHELL adds the window's own resources (manifest, icon); merge
//! those into this file and keep the `embed_version_resource` call.

include!("../versioninfo.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    embed_version_resource("Purge.exe", "Purge");
}
