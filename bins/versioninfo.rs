// A VERSIONINFO resource for a release binary, shared by `bins/purge-engine/build.rs`,
// `bins/purge-broker/build.rs` and `bins/purge-ui/build.rs` (`include!`, so no build-dependency
// crate). Hub (`Kaan88/mdhub`, docs/COMPLIANCE.md section 5) reads an installed app's version from
// the fixed FILEVERSION of its exe (Purge.exe), and Windows' Details tab shows the strings. All carry
// the package version, which is the
// workspace version in the root Cargo.toml: the one version of Purge (install\inno\check-version.ps1
// checks every shipped exe against it).
//
// The fixed FILEVERSION has four numbers, so a pre-release maps to the fourth (`file_version_parts`,
// the same rule as `install\inno\check-version.ps1 -FileVersion`): X.Y.Z -> X.Y.Z.0,
// X.Y.Z-alpha.N -> X.Y.Z.N, X.Y.Z-beta.N -> X.Y.Z.(1000+N), X.Y.Z-rc.N -> X.Y.Z.(2000+N), N 1..=999;
// any other suffix -> X.Y.Z.0. The strings (FileVersion, ProductVersion) carry the full version.
//
// Compiled with the Windows SDK's rc.exe. Without rc.exe the build still succeeds and prints a
// warning; the exe then has no version resource, which `check-version.ps1` refuses for a release.

/// Writes `<file>.rc`, compiles it into `<file>.res` in OUT_DIR and links it into the package's
/// binaries. Only for an MSVC Windows target; a no-op elsewhere.
#[allow(dead_code)] // Purge.exe's build script calls the form below, with its icon
fn embed_version_resource(file_name: &str, description: &str) {
    embed_version_resource_with(file_name, description, "");
}

/// As [`embed_version_resource`], with more resource-script lines (`extra`, e.g. an `ICON`) in the
/// same `.rc`, so one `.res` carries them all.
fn embed_version_resource_with(file_name: &str, description: &str, extra: &str) {
    println!("cargo:rerun-if-changed=../versioninfo.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc")
    {
        return;
    }
    let Some(rc) = find_rc() else {
        println!("cargo:warning=rc.exe not found; {file_name} is built without a version resource");
        return;
    };
    let Some(out) = std::env::var_os("OUT_DIR").map(std::path::PathBuf::from) else {
        return;
    };
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let [a, b, c, d] = file_version_parts(&version);
    let stem = file_name.trim_end_matches(".exe");
    let script = out.join(format!("{stem}.rc"));
    let res = out.join(format!("{stem}.res"));
    // FILEOS VOS_NT_WINDOWS32, FILETYPE VFT_APP; language 0409 (en-US), code page 1200 (Unicode).
    let text = format!(
        "{extra}1 VERSIONINFO\n FILEVERSION {a},{b},{c},{d}\n PRODUCTVERSION {a},{b},{c},{d}\n FILEOS 0x40004\n FILETYPE 1\n\
         BEGIN\n BLOCK \"StringFileInfo\"\n BEGIN\n BLOCK \"040904B0\"\n BEGIN\n\
         VALUE \"CompanyName\", \"Purge\\0\"\n VALUE \"FileDescription\", \"{description}\\0\"\n\
         VALUE \"FileVersion\", \"{version}\\0\"\n VALUE \"InternalName\", \"{stem}\\0\"\n\
         VALUE \"LegalCopyright\", \"MIT License\\0\"\n\
         VALUE \"OriginalFilename\", \"{file_name}\\0\"\n VALUE \"ProductName\", \"Purge\\0\"\n\
         VALUE \"ProductVersion\", \"{version}\\0\"\n END\n END\n\
         BLOCK \"VarFileInfo\"\n BEGIN\n VALUE \"Translation\", 0x0409, 1200\n END\n END\n"
    );
    if std::fs::write(&script, text).is_err() {
        println!(
            "cargo:warning=could not write {}; {file_name} has no version resource",
            script.display()
        );
        return;
    }
    let ok = std::process::Command::new(rc)
        .arg("/nologo")
        .arg("/fo")
        .arg(&res)
        .arg(&script)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        println!("cargo:rustc-link-arg-bins={}", res.display());
    } else {
        println!("cargo:warning=the resource compiler failed; {file_name} has no version resource");
    }
}

/// The four numbers of the fixed FILEVERSION for a Cargo version (the rule at the top of this file).
fn file_version_parts(version: &str) -> [u32; 4] {
    let (core, pre) = match version.split('+').next().unwrap_or("").split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (version.split('+').next().unwrap_or(""), None),
    };
    let mut n = core.split('.').map(|p| p.parse().unwrap_or(0));
    let (a, b, c) = (
        n.next().unwrap_or(0),
        n.next().unwrap_or(0),
        n.next().unwrap_or(0),
    );
    let d = pre
        .and_then(|pre| pre.split_once('.'))
        .and_then(|(stage, num)| {
            let offset = match stage {
                "alpha" => 0,
                "beta" => 1000,
                "rc" => 2000,
                _ => return None,
            };
            let ok = !num.is_empty()
                && num.len() <= 3
                && !num.starts_with('0')
                && num.bytes().all(|b| b.is_ascii_digit());
            ok.then(|| offset + num.parse::<u32>().unwrap_or(0))
        })
        .unwrap_or(0);
    [a, b, c, d]
}

/// rc.exe on PATH (a Developer prompt), else the newest x64 one of the Windows 10/11 SDK.
fn find_rc() -> Option<std::path::PathBuf> {
    let paths = std::env::var_os("PATH").unwrap_or_default();
    if let Some(p) = std::env::split_paths(&paths)
        .map(|d| d.join("rc.exe"))
        .find(|p| p.is_file())
    {
        return Some(p);
    }
    let base = std::path::PathBuf::from(std::env::var_os("ProgramFiles(x86)")?)
        .join("Windows Kits/10/bin");
    let mut found: Vec<std::path::PathBuf> = std::fs::read_dir(base)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path().join("x64/rc.exe"))
        .filter(|p| p.is_file())
        .collect();
    found.sort();
    found.pop()
}
