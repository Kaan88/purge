//! The port of `ui/Purge.Client.Tests/RegistryLabelTests.cs`: every recognised place, the 32-bit view,
//! other accounts, values and (Default), and the breadcrumb fallback for a path nothing recognises.

use super::*;

const ME: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
const OTHER: &str = "S-1-5-21-1111111111-2222222222-3333333333-1002";
const G: &str = "{1814CEEB-49E2-407F-AF99-FA755A7D2607}";
const S: &str = " \u{203A} ";

fn key(path: &str) -> RegistryLabel {
    RegistryLabel::describe(path, ItemKind::RegistryKey, Some(ME)).expect("described")
}

fn value(path: &str) -> RegistryLabel {
    RegistryLabel::describe(path, ItemKind::RegistryValue, Some(ME)).expect("described")
}

#[track_caller]
fn is_label(label: RegistryLabel, title: &str, location: &str) {
    assert_eq!(label.title, title);
    assert_eq!(label.location, location);
}

#[test]
fn uninstall_entry() {
    is_label(
        key(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox 128.0 (x64 en-US)",
        ),
        "Uninstall entry for Mozilla Firefox 128.0 (x64 en-US)",
        &format!("All users{S}Installed programs list"),
    );
    is_label(
        key(&format!(
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{G}"
        )),
        &format!("Uninstall entry for {G}"),
        &format!("All users (32-bit){S}Installed programs list"),
    );
    is_label(
        key(&format!(
            r"HKU\{ME}\Software\Microsoft\Windows\CurrentVersion\Uninstall\Spotify"
        )),
        "Uninstall entry for Spotify",
        &format!("Your account{S}Installed programs list"),
    );
    is_label(
        value(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\App\DisplayIcon"),
        "Uninstall entry for App: value DisplayIcon",
        &format!("All users{S}Installed programs list"),
    );
}

#[test]
fn startup_values() {
    is_label(
        value(&format!(
            r"HKU\{ME}\Software\Microsoft\Windows\CurrentVersion\Run\Discord"
        )),
        "Starts with Windows: Discord",
        &format!("Your account{S}Startup apps"),
    );
    is_label(
        value(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\Setup"),
        "Runs once at next start: Setup",
        &format!("All users (32-bit){S}Startup apps"),
    );
    is_label(
        value(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\Agent"),
        "Starts with Windows: Agent",
        &format!("All users{S}Startup apps"),
    );
    is_label(
        value(&format!(
            r"HKU\{ME}\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\Discord"
        )),
        "Startup on/off switch: Discord",
        &format!("Your account{S}Startup apps"),
    );
}

#[test]
fn com_components() {
    let com = format!("All users{S}File types & COM");
    is_label(
        key(&format!(r"HKLM\SOFTWARE\Classes\CLSID\{G}")),
        &format!("COM component {G}"),
        &com,
    );
    is_label(
        key(&format!(r"HKLM\SOFTWARE\Classes\CLSID\{G}\InprocServer32")),
        &format!("COM component {G}: DLL location"),
        &com,
    );
    is_label(
        value(&format!(
            r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{G}\LocalServer32\(Default)"
        )),
        &format!("COM component {G}: program location: default value"),
        &format!("All users (32-bit){S}File types & COM"),
    );
    is_label(
        key(&format!(r"HKU\{ME}_Classes\CLSID\{G}\ProgID")),
        &format!("COM component {G}{S}ProgID"),
        &format!("Your account{S}File types & COM"),
    );
    is_label(
        key(&format!(r"HKLM\SOFTWARE\Classes\TypeLib\{G}")),
        &format!("COM type library {G}"),
        &com,
    );
    is_label(
        key(&format!(r"HKLM\SOFTWARE\Classes\Interface\{G}")),
        &format!("COM interface {G}"),
        &com,
    );
    is_label(
        key(r"HKLM\SOFTWARE\Classes\AppID\Foo.exe"),
        "COM app ID Foo.exe",
        &com,
    );
}

#[test]
fn file_types_and_handlers() {
    let com = format!("All users{S}File types & COM");
    is_label(key(r"HKLM\SOFTWARE\Classes\.mkv"), "File type .mkv", &com);
    is_label(
        value(&format!(r"HKU\{ME}_Classes\.mkv\OpenWithProgids\VLC.mkv")),
        &format!("File type .mkv{S}OpenWithProgids: value VLC.mkv"),
        &format!("Your account{S}File types & COM"),
    );
    is_label(
        key(r"HKLM\SOFTWARE\Classes\FirefoxHTML-308046B0AF4A39CB"),
        "File type handler: FirefoxHTML-308046B0AF4A39CB",
        &com,
    );
    is_label(
        key(r"HKLM\SOFTWARE\Classes\VLC.mp4\shell\Open"),
        &format!("File type handler: VLC.mp4{S}shell{S}Open"),
        &com,
    );
    is_label(
        key(r"HKLM\SOFTWARE\Classes\Applications\vlc.exe"),
        "Open with entry for vlc.exe",
        &com,
    );
    is_label(
        key(&format!(r"HKU\{ME}\Software\Classes\.7z")),
        "File type .7z",
        &format!("Your account{S}File types & COM"),
    );
}

#[test]
fn right_click_menus() {
    let com = format!("All users{S}File types & COM");
    is_label(
        key(r"HKLM\SOFTWARE\Classes\*\shell\7-Zip"),
        "Right-click menu entry: 7-Zip",
        &format!("{com}{S}All files"),
    );
    is_label(
        key(r"HKLM\SOFTWARE\Classes\Directory\Background\shell\VSCode\command"),
        &format!("Right-click menu entry: VSCode{S}command"),
        &format!("{com}{S}Folder background"),
    );
    is_label(
        key(r"HKLM\SOFTWARE\Classes\Directory\shell\Open with Code"),
        "Right-click menu entry: Open with Code",
        &format!("{com}{S}Folders"),
    );
    is_label(
        key(r"HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\7-Zip"),
        "Right-click menu handler: 7-Zip",
        &format!("{com}{S}All files"),
    );
    is_label(
        key(r"HKLM\SOFTWARE\Classes\SystemFileAssociations\.png\shell\Edit"),
        "Right-click menu entry: Edit",
        &format!("{com}{S}.png files"),
    );
}

#[test]
fn app_paths_shared_dlls_and_installer_records() {
    let wi = format!("All users{S}Windows Installer");
    is_label(
        key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe"),
        "App path for firefox.exe",
        &format!("All users{S}App paths"),
    );
    // A SharedDLLs value name is a file path: the whole path is the value, not the last segment.
    is_label(
        value(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs\C:\Program Files\Common Files\Foo\foo.dll",
        ),
        r"Shared DLL count: C:\Program Files\Common Files\Foo\foo.dll",
        &format!("All users{S}Shared DLL counts"),
    );
    is_label(
        value(
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs\\\server\share\x.dll",
        ),
        r"Shared DLL count: \\server\share\x.dll",
        &format!("All users (32-bit){S}Shared DLL counts"),
    );
    is_label(
        key(r"HKLM\SOFTWARE\Classes\Installer\Products\8C1F2D9E4A7B3C5D6E7F8A9B0C1D2E3F"),
        "Windows Installer product record 8C1F2D9E4A7B3C5D6E7F8A9B0C1D2E3F",
        &wi,
    );
    is_label(
        key(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\ABC",
        ),
        "Windows Installer component record ABC",
        &wi,
    );
    is_label(
        key(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\ABC\InstallProperties",
        ),
        &format!("Windows Installer product record ABC{S}InstallProperties"),
        &wi,
    );
    is_label(
        value(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders\C:\Program Files\Foo\",
        ),
        r"Windows Installer folder record: C:\Program Files\Foo",
        &wi,
    );
    is_label(
        key(&format!(
            r"HKU\{ME}\Software\Microsoft\Installer\UpgradeCodes\XYZ"
        )),
        "Windows Installer upgrade code XYZ",
        &format!("Your account{S}Windows Installer"),
    );
    is_label(
        key(r"HKLM\SOFTWARE\Classes\Installer\Dependencies\{guid}"),
        "Installer dependency record {guid}",
        &wi,
    );
}

#[test]
fn services_and_event_log_sources() {
    let services = format!("All users{S}Services");
    is_label(
        key(r"HKLM\SYSTEM\CurrentControlSet\Services\MozillaMaintenance"),
        "Service MozillaMaintenance",
        &services,
    );
    is_label(
        key(r"HKLM\SYSTEM\ControlSet001\Services\Foo\Parameters"),
        &format!("Service Foo{S}Parameters"),
        &services,
    );
    is_label(
        key(r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\FooSvc"),
        "Event log source: FooSvc",
        &services,
    );
}

#[test]
fn app_settings() {
    is_label(
        key(&format!(r"HKU\{ME}\Software\Mozilla\Firefox")),
        "Settings of Mozilla Firefox",
        &format!("Your account{S}Software"),
    );
    is_label(
        key(r"HKLM\SOFTWARE\WOW6432Node\VideoLAN\VLC"),
        "Settings of VideoLAN VLC",
        &format!("All users (32-bit){S}Software"),
    );
    is_label(
        key(&format!(r"HKU\{ME}\Software\Mozilla\Mozilla Firefox\128.0")),
        &format!("Settings of Mozilla Firefox{S}128.0"),
        &format!("Your account{S}Software"),
    );
    is_label(
        key(&format!(r"HKU\{ME}\Software\Notepad++")),
        "Settings of Notepad++",
        &format!("Your account{S}Software"),
    );
    is_label(
        value(&format!(r"HKU\{ME}\Software\VideoLAN\VLC\Lang")),
        "VideoLAN VLC setting: Lang",
        &format!("Your account{S}Software{S}VideoLAN VLC"),
    );
    is_label(
        value(&format!(r"HKU\{ME}\Software\VideoLAN\VLC\Prefs\(Default)")),
        "VideoLAN VLC setting: default value",
        &format!("Your account{S}Software{S}VideoLAN VLC{S}Prefs"),
    );
    // HKCU in the offline sample reads the same way.
    is_label(
        RegistryLabel::describe(
            r"HKCU\Software\Mozilla\Firefox",
            ItemKind::RegistryKey,
            None,
        )
        .expect("described"),
        "Settings of Mozilla Firefox",
        &format!("Your account{S}Software"),
    );
}

#[test]
fn default_apps_and_compatibility() {
    is_label(
        value(r"HKLM\SOFTWARE\RegisteredApplications\Firefox-308046B0AF4A39CB"),
        "Default apps entry: Firefox-308046B0AF4A39CB",
        &format!("All users{S}Default apps"),
    );
    is_label(
        key(r"HKLM\SOFTWARE\Clients\StartMenuInternet\Firefox-308046B0AF4A39CB"),
        "Default app registration: Firefox-308046B0AF4A39CB",
        &format!("All users{S}Default apps{S}StartMenuInternet"),
    );
    is_label(
        value(&format!(
            r"HKU\{ME}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers\C:\Games\old.exe"
        )),
        r"Compatibility setting: C:\Games\old.exe",
        &format!("Your account{S}Compatibility settings"),
    );
    is_label(
        value(&format!(
            r"HKU\{ME}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store\C:\Apps\x.exe"
        )),
        r"Compatibility record: C:\Apps\x.exe",
        &format!("Your account{S}Compatibility settings"),
    );
    is_label(
        value(&format!(
            r"HKU\{ME}_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache\C:\Apps\x.exe.FriendlyAppName"
        )),
        r"App name cache: C:\Apps\x.exe.FriendlyAppName",
        &format!("Your account{S}File types & COM"),
    );
}

#[test]
fn accounts_in_words() {
    assert_eq!(
        key(&format!(r"HKU\{OTHER}\Software\Mozilla\Firefox")).location,
        format!("Another account{S}Software")
    );
    assert_eq!(
        key(&format!(r"HKU\{OTHER}_Classes\.mkv")).location,
        format!("Another account{S}File types & COM")
    );
    assert_eq!(
        key(r"HKU\S-1-5-18\Software\Foo\Bar").location,
        format!("System account{S}Software")
    );
    assert_eq!(
        key(r"HKU\S-1-5-19\Software\Foo\Bar").location,
        format!("Local service account{S}Software")
    );
    assert_eq!(
        key(r"HKU\S-1-5-20\Software\Foo\Bar").location,
        format!("Network service account{S}Software")
    );
    assert_eq!(
        key(r"HKU\.DEFAULT\Software\Foo\Bar").location,
        format!("Default account{S}Software")
    );
    // With no SID passed in, even the user's own hive is "another account": nothing is claimed as yours.
    assert_eq!(
        RegistryLabel::describe(
            &format!(r"HKU\{ME}\Software\Foo"),
            ItemKind::RegistryKey,
            None
        )
        .expect("described")
        .location,
        format!("Another account{S}Software")
    );
    // The 32-bit view of an account's file types.
    assert_eq!(
        key(&format!(r"HKU\{ME}_Classes\WOW6432Node\CLSID\{G}")).location,
        format!("Your account (32-bit){S}File types & COM")
    );
}

#[test]
fn unknown_places_fall_back_to_a_breadcrumb() {
    is_label(
        key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mkv"),
        ".mkv",
        &format!("All users{S}Software{S}Windows{S}Explorer{S}FileExts{S}.mkv"),
    );
    is_label(
        key(r"HKLM\SOFTWARE\Policies\Mozilla\Firefox"),
        "Firefox",
        &format!("All users{S}Software{S}Policies{S}Mozilla{S}Firefox"),
    );
    is_label(
        value(&format!(r"HKU\{ME}\Environment\FOO_HOME")),
        "Environment: value FOO_HOME",
        &format!("Your account{S}Environment"),
    );
    is_label(
        value(&format!(r"HKU\{ME}\Environment\(Default)")),
        "Environment: default value",
        &format!("Your account{S}Environment"),
    );
    is_label(
        key(r"HKLM\SYSTEM\Setup\Foo"),
        "Foo",
        &format!("All users{S}System{S}Setup{S}Foo"),
    );
    is_label(
        key(r"HKLM\SOFTWARE"),
        "Software",
        &format!("All users{S}Software"),
    );
}

#[test]
fn registry_data_is_one_entry_of_a_value() {
    let label = RegistryLabel::describe(
        &format!(r"HKU\{ME}\Software\Mozilla\Firefox\Paths"),
        ItemKind::RegistryData,
        Some(ME),
    )
    .expect("described");
    is_label(
        label,
        "Mozilla Firefox setting: Paths (one entry)",
        &format!("Your account{S}Software{S}Mozilla Firefox"),
    );
}

#[test]
fn other_kinds_and_unknown_roots_are_left_alone() {
    assert!(
        RegistryLabel::describe(
            r"C:\Program Files\Mozilla Firefox",
            ItemKind::Folder,
            Some(ME)
        )
        .is_none()
    );
    assert!(
        RegistryLabel::describe("Mozilla Maintenance Service", ItemKind::Service, Some(ME))
            .is_none()
    );
    assert!(RegistryLabel::describe(r"HKCC\System\Foo", ItemKind::RegistryKey, Some(ME)).is_none());
    assert!(RegistryLabel::describe("HKU", ItemKind::RegistryKey, Some(ME)).is_none());
    assert!(RegistryLabel::describe("", ItemKind::RegistryKey, Some(ME)).is_none());
}
