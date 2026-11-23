using Purge.Client.Model;
using Purge.Client.Rpc;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// The Leftovers page's registry rows in words: every recognised place, the 32-bit view, other accounts,
/// values and (Default), and the breadcrumb fallback for a path nothing recognises.
/// </summary>
public sealed class RegistryLabelTests
{
    private const string Me = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    private const string Other = "S-1-5-21-1111111111-2222222222-3333333333-1002";
    private const string G = "{1814CEEB-49E2-407F-AF99-FA755A7D2607}";
    private const string S = " \u203A ";

    private static RegistryLabel Key(string path) => RegistryLabel.Describe(path, ItemKind.RegistryKey, Me)!;
    private static RegistryLabel Value(string path) => RegistryLabel.Describe(path, ItemKind.RegistryValue, Me)!;

    private static void Is(RegistryLabel label, string title, string location)
    {
        Assert.Equal(title, label.Title);
        Assert.Equal(location, label.Location);
    }

    [Fact]
    public void UninstallEntry()
    {
        Is(Key(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox 128.0 (x64 en-US)"),
            "Uninstall entry for Mozilla Firefox 128.0 (x64 en-US)", "All users" + S + "Installed programs list");
        Is(Key(@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" + G),
            "Uninstall entry for " + G, "All users (32-bit)" + S + "Installed programs list");
        Is(Key(@"HKU\" + Me + @"\Software\Microsoft\Windows\CurrentVersion\Uninstall\Spotify"),
            "Uninstall entry for Spotify", "Your account" + S + "Installed programs list");
        Is(Value(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\App\DisplayIcon"),
            "Uninstall entry for App: value DisplayIcon", "All users" + S + "Installed programs list");
    }

    [Fact]
    public void StartupValues()
    {
        Is(Value(@"HKU\" + Me + @"\Software\Microsoft\Windows\CurrentVersion\Run\Discord"),
            "Starts with Windows: Discord", "Your account" + S + "Startup apps");
        Is(Value(@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\Setup"),
            "Runs once at next start: Setup", "All users (32-bit)" + S + "Startup apps");
        Is(Value(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\Agent"),
            "Starts with Windows: Agent", "All users" + S + "Startup apps");
        Is(Value(@"HKU\" + Me + @"\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\Discord"),
            "Startup on/off switch: Discord", "Your account" + S + "Startup apps");
    }

    [Fact]
    public void ComComponents()
    {
        Is(Key(@"HKLM\SOFTWARE\Classes\CLSID\" + G), "COM component " + G, "All users" + S + "File types & COM");
        Is(Key(@"HKLM\SOFTWARE\Classes\CLSID\" + G + @"\InprocServer32"),
            "COM component " + G + ": DLL location", "All users" + S + "File types & COM");
        Is(Value(@"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\" + G + @"\LocalServer32\(Default)"),
            "COM component " + G + ": program location: default value", "All users (32-bit)" + S + "File types & COM");
        Is(Key(@"HKU\" + Me + @"_Classes\CLSID\" + G + @"\ProgID"),
            "COM component " + G + S + "ProgID", "Your account" + S + "File types & COM");
        Is(Key(@"HKLM\SOFTWARE\Classes\TypeLib\" + G), "COM type library " + G, "All users" + S + "File types & COM");
        Is(Key(@"HKLM\SOFTWARE\Classes\Interface\" + G), "COM interface " + G, "All users" + S + "File types & COM");
        Is(Key(@"HKLM\SOFTWARE\Classes\AppID\Foo.exe"), "COM app ID Foo.exe", "All users" + S + "File types & COM");
    }

    [Fact]
    public void FileTypesAndHandlers()
    {
        Is(Key(@"HKLM\SOFTWARE\Classes\.mkv"), "File type .mkv", "All users" + S + "File types & COM");
        Is(Value(@"HKU\" + Me + @"_Classes\.mkv\OpenWithProgids\VLC.mkv"),
            "File type .mkv" + S + "OpenWithProgids: value VLC.mkv", "Your account" + S + "File types & COM");
        Is(Key(@"HKLM\SOFTWARE\Classes\FirefoxHTML-308046B0AF4A39CB"),
            "File type handler: FirefoxHTML-308046B0AF4A39CB", "All users" + S + "File types & COM");
        Is(Key(@"HKLM\SOFTWARE\Classes\VLC.mp4\shell\Open"),
            "File type handler: VLC.mp4" + S + "shell" + S + "Open", "All users" + S + "File types & COM");
        Is(Key(@"HKLM\SOFTWARE\Classes\Applications\vlc.exe"), "Open with entry for vlc.exe", "All users" + S + "File types & COM");
        Is(Key(@"HKU\" + Me + @"\Software\Classes\.7z"), "File type .7z", "Your account" + S + "File types & COM");
    }

    [Fact]
    public void RightClickMenus()
    {
        Is(Key(@"HKLM\SOFTWARE\Classes\*\shell\7-Zip"),
            "Right-click menu entry: 7-Zip", "All users" + S + "File types & COM" + S + "All files");
        Is(Key(@"HKLM\SOFTWARE\Classes\Directory\Background\shell\VSCode\command"),
            "Right-click menu entry: VSCode" + S + "command", "All users" + S + "File types & COM" + S + "Folder background");
        Is(Key(@"HKLM\SOFTWARE\Classes\Directory\shell\Open with Code"),
            "Right-click menu entry: Open with Code", "All users" + S + "File types & COM" + S + "Folders");
        Is(Key(@"HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\7-Zip"),
            "Right-click menu handler: 7-Zip", "All users" + S + "File types & COM" + S + "All files");
        Is(Key(@"HKLM\SOFTWARE\Classes\SystemFileAssociations\.png\shell\Edit"),
            "Right-click menu entry: Edit", "All users" + S + "File types & COM" + S + ".png files");
    }

    [Fact]
    public void AppPathsSharedDllsAndInstallerRecords()
    {
        Is(Key(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe"),
            "App path for firefox.exe", "All users" + S + "App paths");
        // A SharedDLLs value name is a file path: the whole path is the value, not the last segment.
        Is(Value(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs\C:\Program Files\Common Files\Foo\foo.dll"),
            @"Shared DLL count: C:\Program Files\Common Files\Foo\foo.dll", "All users" + S + "Shared DLL counts");
        Is(Value(@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs\\\server\share\x.dll"),
            @"Shared DLL count: \\server\share\x.dll", "All users (32-bit)" + S + "Shared DLL counts");
        Is(Key(@"HKLM\SOFTWARE\Classes\Installer\Products\8C1F2D9E4A7B3C5D6E7F8A9B0C1D2E3F"),
            "Windows Installer product record 8C1F2D9E4A7B3C5D6E7F8A9B0C1D2E3F", "All users" + S + "Windows Installer");
        Is(Key(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\ABC"),
            "Windows Installer component record ABC", "All users" + S + "Windows Installer");
        Is(Key(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\ABC\InstallProperties"),
            "Windows Installer product record ABC" + S + "InstallProperties", "All users" + S + "Windows Installer");
        Is(Value(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders\C:\Program Files\Foo\"),
            @"Windows Installer folder record: C:\Program Files\Foo", "All users" + S + "Windows Installer");
        Is(Key(@"HKU\" + Me + @"\Software\Microsoft\Installer\UpgradeCodes\XYZ"),
            "Windows Installer upgrade code XYZ", "Your account" + S + "Windows Installer");
        Is(Key(@"HKLM\SOFTWARE\Classes\Installer\Dependencies\{guid}"),
            "Installer dependency record {guid}", "All users" + S + "Windows Installer");
    }

    [Fact]
    public void ServicesAndEventLogSources()
    {
        Is(Key(@"HKLM\SYSTEM\CurrentControlSet\Services\MozillaMaintenance"), "Service MozillaMaintenance", "All users" + S + "Services");
        Is(Key(@"HKLM\SYSTEM\ControlSet001\Services\Foo\Parameters"), "Service Foo" + S + "Parameters", "All users" + S + "Services");
        Is(Key(@"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\FooSvc"),
            "Event log source: FooSvc", "All users" + S + "Services");
    }

    [Fact]
    public void AppSettings()
    {
        Is(Key(@"HKU\" + Me + @"\Software\Mozilla\Firefox"), "Settings of Mozilla Firefox", "Your account" + S + "Software");
        Is(Key(@"HKLM\SOFTWARE\WOW6432Node\VideoLAN\VLC"), "Settings of VideoLAN VLC", "All users (32-bit)" + S + "Software");
        Is(Key(@"HKU\" + Me + @"\Software\Mozilla\Mozilla Firefox\128.0"),
            "Settings of Mozilla Firefox" + S + "128.0", "Your account" + S + "Software");
        Is(Key(@"HKU\" + Me + @"\Software\Notepad++"), "Settings of Notepad++", "Your account" + S + "Software");
        Is(Value(@"HKU\" + Me + @"\Software\VideoLAN\VLC\Lang"),
            "VideoLAN VLC setting: Lang", "Your account" + S + "Software" + S + "VideoLAN VLC");
        Is(Value(@"HKU\" + Me + @"\Software\VideoLAN\VLC\Prefs\(Default)"),
            "VideoLAN VLC setting: default value", "Your account" + S + "Software" + S + "VideoLAN VLC" + S + "Prefs");
        // HKCU in the offline sample reads the same way.
        Is(RegistryLabel.Describe(@"HKCU\Software\Mozilla\Firefox", ItemKind.RegistryKey, null)!,
            "Settings of Mozilla Firefox", "Your account" + S + "Software");
    }

    [Fact]
    public void DefaultAppsAndCompatibility()
    {
        Is(Value(@"HKLM\SOFTWARE\RegisteredApplications\Firefox-308046B0AF4A39CB"),
            "Default apps entry: Firefox-308046B0AF4A39CB", "All users" + S + "Default apps");
        Is(Key(@"HKLM\SOFTWARE\Clients\StartMenuInternet\Firefox-308046B0AF4A39CB"),
            "Default app registration: Firefox-308046B0AF4A39CB", "All users" + S + "Default apps" + S + "StartMenuInternet");
        Is(Value(@"HKU\" + Me + @"\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers\C:\Games\old.exe"),
            @"Compatibility setting: C:\Games\old.exe", "Your account" + S + "Compatibility settings");
        Is(Value(@"HKU\" + Me + @"\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store\C:\Apps\x.exe"),
            @"Compatibility record: C:\Apps\x.exe", "Your account" + S + "Compatibility settings");
        Is(Value(@"HKU\" + Me + @"_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache\C:\Apps\x.exe.FriendlyAppName"),
            @"App name cache: C:\Apps\x.exe.FriendlyAppName", "Your account" + S + "File types & COM");
    }

    [Fact]
    public void AccountsInWords()
    {
        Assert.Equal("Another account" + S + "Software",
            Key(@"HKU\" + Other + @"\Software\Mozilla\Firefox").Location);
        Assert.Equal("Another account" + S + "File types & COM", Key(@"HKU\" + Other + @"_Classes\.mkv").Location);
        Assert.Equal("System account" + S + "Software", Key(@"HKU\S-1-5-18\Software\Foo\Bar").Location);
        Assert.Equal("Local service account" + S + "Software", Key(@"HKU\S-1-5-19\Software\Foo\Bar").Location);
        Assert.Equal("Network service account" + S + "Software", Key(@"HKU\S-1-5-20\Software\Foo\Bar").Location);
        Assert.Equal("Default account" + S + "Software", Key(@"HKU\.DEFAULT\Software\Foo\Bar").Location);
        // With no SID passed in, even the user's own hive is "another account": nothing is claimed as yours.
        Assert.Equal("Another account" + S + "Software",
            RegistryLabel.Describe(@"HKU\" + Me + @"\Software\Foo", ItemKind.RegistryKey, null)!.Location);
        // The 32-bit view of an account's file types.
        Assert.Equal("Your account (32-bit)" + S + "File types & COM",
            Key(@"HKU\" + Me + @"_Classes\WOW6432Node\CLSID\" + G).Location);
    }

    [Fact]
    public void UnknownPlacesFallBackToABreadcrumb()
    {
        Is(Key(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mkv"),
            ".mkv", "All users" + S + "Software" + S + "Windows" + S + "Explorer" + S + "FileExts" + S + ".mkv");
        Is(Key(@"HKLM\SOFTWARE\Policies\Mozilla\Firefox"),
            "Firefox", "All users" + S + "Software" + S + "Policies" + S + "Mozilla" + S + "Firefox");
        Is(Value(@"HKU\" + Me + @"\Environment\FOO_HOME"), "Environment: value FOO_HOME", "Your account" + S + "Environment");
        Is(Value(@"HKU\" + Me + @"\Environment\(Default)"), "Environment: default value", "Your account" + S + "Environment");
        Is(Key(@"HKLM\SYSTEM\Setup\Foo"), "Foo", "All users" + S + "System" + S + "Setup" + S + "Foo");
        Is(Key(@"HKLM\SOFTWARE"), "Software", "All users" + S + "Software");
    }

    [Fact]
    public void RegistryDataIsOneEntryOfAValue()
    {
        var label = RegistryLabel.Describe(@"HKU\" + Me + @"\Software\Mozilla\Firefox\Paths", ItemKind.RegistryData, Me)!;
        Is(label, "Mozilla Firefox setting: Paths (one entry)", "Your account" + S + "Software" + S + "Mozilla Firefox");
    }

    [Fact]
    public void OtherKindsAndUnknownRootsAreLeftAlone()
    {
        Assert.Null(RegistryLabel.Describe(@"C:\Program Files\Mozilla Firefox", ItemKind.Folder, Me));
        Assert.Null(RegistryLabel.Describe("Mozilla Maintenance Service", ItemKind.Service, Me));
        Assert.Null(RegistryLabel.Describe(@"HKCC\System\Foo", ItemKind.RegistryKey, Me));
        Assert.Null(RegistryLabel.Describe(@"HKU", ItemKind.RegistryKey, Me));
        Assert.Null(RegistryLabel.Describe("", ItemKind.RegistryKey, Me));
    }
}
