//! Embeds a VERSIONINFO resource (the workspace version) in purge-engine.exe: `../versioninfo.rs`.

include!("../versioninfo.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    embed_version_resource("purge-engine.exe", "Purge engine");
}
