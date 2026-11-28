//! The staging marker on the real binary (review S-A of BROKER-CONSENT-UI): a `purge-broker.exe`
//! built without the feature `toolkit-consent` holds [`STAGING_MARKER`] and no path of the
//! toolkit's sources; one built with it holds no marker and the toolkit's paths. `install.ps1`,
//! `build-installer.ps1` and the release workflow read these, so that a rig build with the feature
//! is never installed or shipped as the release broker. Run with the feature off and on.
//!
//! Also: the PowerShell scripts that check a staged broker name the same strings as the broker.

use std::path::{Path, PathBuf};

use purge_broker::args::{STAGING_MARKER, TOOLKIT_MARKERS};

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the repository root")
        .to_path_buf()
}

#[test]
fn the_built_broker_carries_the_marker_of_its_build() {
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_purge-broker"));
    let bytes = std::fs::read(&exe).expect("the built broker");
    let marker = contains(&bytes, STAGING_MARKER);
    let toolkit: Vec<&str> = TOOLKIT_MARKERS
        .iter()
        .copied()
        .filter(|m| contains(&bytes, m))
        .collect();
    if cfg!(feature = "toolkit-consent") {
        assert!(
            !marker,
            "{}: a toolkit build holds the release marker",
            exe.display()
        );
        assert!(
            !toolkit.is_empty(),
            "{}: a toolkit build holds none of {TOOLKIT_MARKERS:?}",
            exe.display()
        );
    } else {
        assert!(marker, "{}: the release marker is missing", exe.display());
        assert!(
            toolkit.is_empty(),
            "{}: a release build holds {toolkit:?}",
            exe.display()
        );
    }
}

#[test]
fn the_staging_checks_name_the_brokers_strings() {
    let install = std::fs::read_to_string(repo().join("install").join("install.ps1")).unwrap();
    assert!(
        install.contains(&format!("$script:BrokerReleaseMarker = '{STAGING_MARKER}'")),
        "install.ps1 names another release marker"
    );
    let quoted: Vec<String> = TOOLKIT_MARKERS.iter().map(|m| format!("'{m}'")).collect();
    assert!(
        install.contains(&format!(
            "$script:BrokerToolkitMarkers = @({})",
            quoted.join(", ")
        )),
        "install.ps1 names other toolkit markers"
    );
    let release =
        std::fs::read_to_string(repo().join(".github").join("workflows").join("release.yml"))
            .unwrap();
    assert!(
        release.contains("Assert-ReleaseBroker"),
        "the release workflow does not check the staged broker"
    );
    let inno = std::fs::read_to_string(
        repo()
            .join("install")
            .join("inno")
            .join("build-installer.ps1"),
    )
    .unwrap();
    assert!(
        inno.contains("Assert-ReleaseBroker"),
        "build-installer.ps1 does not check the staged broker"
    );
}
