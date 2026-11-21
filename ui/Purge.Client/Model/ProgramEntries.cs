namespace Purge.Client.Model;

/// <summary>One icon of an <c>icon.batch</c>, decoded: <see cref="Bgra"/> is null when the engine could not read it.</summary>
public sealed record ProgramIcon(string ProgramId, int Px, byte[]? Bgra);

/// <summary>
/// Turns the engine's list notifications into the UI's <see cref="InventoryEntry"/> rows: a raw ARP row first
/// (<c>programs.batch</c>), then what <c>programs.patch</c> and <c>programs.get</c> learn about it.
/// </summary>
public static class ProgramEntries
{
    /// <summary>The entry a raw row stands for. The row carries no flags yet, so it reads as a named, non-system app.</summary>
    public static InventoryEntry FromRow(Rpc.ProgramRow row)
    {
        // A program id is "HKLM|64|key" or "HKU:<sid>|32|key".
        var parts = row.ProgramId.Split('|', 3);
        var hive = parts[0];
        var view = parts.Length > 1 && parts[1] == "32" ? RegistryView.K32 : RegistryView.K64;
        var key = parts.Length > 2 ? parts[2] : row.ProgramId;
        var sid = hive.StartsWith("HKU:", StringComparison.Ordinal) ? hive[4..] : null;
        var software = sid is null ? "SOFTWARE" : "Software";
        var wow = view == RegistryView.K32 ? "\\WOW6432Node" : "";
        var keyPath = $"{(sid is null ? "HKLM" : "HKU\\" + sid)}\\{software}{wow}\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{key}";
        var scope = row.Scope == Rpc.InstallScope.User ? InstallScope.User : InstallScope.Machine;
        IReadOnlyList<InstallTimeEvidence>? time = row.InstallTime is { } t ? [new InstallTimeEvidence(InstallTimeSource.ArpInstallDate, t)] : null;
        return new InventoryEntry(
            ProgramId: row.ProgramId, KeyPath: keyPath, HiveSid: sid, View: view, DisplayName: row.Name, Version: row.Version,
            Publisher: row.Publisher,
            Flags: new RawFlags(SystemComponent: false, HasDisplayName: true, HasUninstallString: true, ParentKey: null, ReleaseType: null,
                WindowsInstaller: false),
            InstallerKind: InstallerKind.Unknown, Scope: scope, ProductCode: null, UpgradeCode: null, InnoAppId: null,
            WritableBy: scope == InstallScope.Machine ? WritableBy.Admin : WritableBy.User, InstallLocation: null,
            UninstallString: null, QuietUninstallString: null, DisplayIcon: null, InstallTimeEvidence: time, Msi: null);
    }

    /// <summary>The entry with a <c>programs.patch</c> applied; only the members the patch states change.</summary>
    public static InventoryEntry Apply(InventoryEntry entry, Rpc.ProgramPatch patch)
    {
        var kind = patch.Installer is { } installer ? Map(installer) : entry.InstallerKind;
        var parent = patch.ParentKey ?? entry.Flags.ParentKey;
        // A bundle id other than the entry's own names the Burn bundle it hangs under.
        if (parent is null && patch.Bundle is { } bundle && bundle != entry.ProgramId) parent = KeyNameOf(bundle);
        var flags = entry.Flags with
        {
            SystemComponent = patch.SystemComponent ?? entry.Flags.SystemComponent,
            HasDisplayName = patch.Unnamed is { } unnamed ? !unnamed : entry.Flags.HasDisplayName,
            ParentKey = parent,
            WindowsInstaller = entry.Flags.WindowsInstaller || kind == InstallerKind.Msi,
        };
        return entry with
        {
            InstallerKind = kind,
            ProductCode = patch.ProductCode ?? entry.ProductCode,
            Appx = patch.Appx ?? entry.Appx,
            Flags = flags,
        };
    }

    /// <summary>The entry with the details of <c>programs.get</c> filled in.</summary>
    public static InventoryEntry Apply(InventoryEntry entry, Rpc.ProgramDetails details) => entry with
    {
        InstallerKind = Map(details.Installer),
        WritableBy = details.WritableBy == Rpc.WritableBy.User ? WritableBy.User : WritableBy.Admin,
        InstallLocation = details.InstallLocation,
        UninstallString = details.UninstallCommand,
        QuietUninstallString = details.QuietUninstallCommand,
        ProductCode = details.ProductCode ?? entry.ProductCode,
        Flags = entry.Flags with { HasUninstallString = details.UninstallCommand is not null },
    };

    /// <summary>The icon of an <c>icon.batch</c> entry; a missing, malformed or wrongly sized pixel buffer is "no icon".</summary>
    public static ProgramIcon ToIcon(Rpc.Icon icon)
    {
        var px = (int)Math.Clamp(icon.Px, 0, 256);
        byte[]? bgra = null;
        if (icon.Bgra is { Length: > 0 } text && px > 0)
        {
            try
            {
                var bytes = Convert.FromBase64String(text);
                if (bytes.Length == px * px * 4) bgra = bytes;
            }
            catch (FormatException) { }
        }
        return new ProgramIcon(icon.ProgramId, px, bgra);
    }

    private static InstallerKind Map(Rpc.InstallerKind kind) => kind switch
    {
        Rpc.InstallerKind.Msi => InstallerKind.Msi,
        Rpc.InstallerKind.Inno => InstallerKind.Inno,
        Rpc.InstallerKind.Nsis => InstallerKind.Nsis,
        Rpc.InstallerKind.Burn => InstallerKind.Burn,
        _ => InstallerKind.Unknown,
    };

    private static string KeyNameOf(string programId)
    {
        var parts = programId.Split('|', 3);
        return parts.Length > 2 ? parts[2] : programId;
    }
}
