using System.Text.RegularExpressions;
using Purge.Client.Rpc;

namespace Purge.Client.Model;

/// <summary>
/// A registry candidate in words: what the key or value is (<see cref="Title"/>) and where it lives
/// (<see cref="Location"/>). Display only: the raw wire path stays the authority (the consent prompt, the
/// tooltip and the detail pane show it unchanged).
/// </summary>
public sealed partial record RegistryLabel(string Title, string Location)
{
    private const string Sep = " › ";

    /// <summary>
    /// Describes a canonical wire path (<c>HKLM\SOFTWARE\...</c>, <c>HKU\&lt;SID&gt;\...</c>,
    /// <c>HKU\&lt;SID&gt;_Classes\...</c>; a value is <c>key\name</c> or <c>key\(Default)</c>). Returns null for a
    /// non-registry kind or a path whose root it does not know, so the caller keeps showing the raw path.
    /// </summary>
    public static RegistryLabel? Describe(string path, ItemKind kind, string? currentUserSid)
    {
        if (kind is not (ItemKind.RegistryKey or ItemKind.RegistryValue or ItemKind.RegistryData)) return null;
        if (string.IsNullOrWhiteSpace(path)) return null;
        var segments = path.TrimEnd('\\').Split('\\');
        if (!TryHive(segments, currentUserSid, out var hive)) return null;

        var isValue = kind is not ItemKind.RegistryKey;
        var keySegs = hive.Rest;
        string? value = null;
        if (isValue && keySegs.Count > 0) (keySegs, value) = SplitValue(keySegs);

        var label = Recognise(hive, keySegs, value, isValue);
        if (kind == ItemKind.RegistryData) label = label with { Title = label.Title + " (one entry)" };
        return label;
    }

    // ---- Hive ---------------------------------------------------------------------------------

    private enum Branch { Software, Classes, System, Other }

    private sealed record Hive(string Scope, bool Bits32, Branch Branch, List<string> Rest)
    {
        public string ScopeText => Bits32 ? Scope + " (32-bit)" : Scope;
    }

    private static bool TryHive(string[] segs, string? currentUserSid, out Hive hive)
    {
        hive = null!;
        var root = segs[0];
        var rest = segs.Skip(1).ToList();
        string scope;
        var classesRoot = false;
        if (Is(root, "HKLM") || Is(root, "HKEY_LOCAL_MACHINE"))
        {
            scope = "All users";
        }
        else if (Is(root, "HKCU") || Is(root, "HKEY_CURRENT_USER"))
        {
            scope = "Your account";
        }
        else if (Is(root, "HKCR") || Is(root, "HKEY_CLASSES_ROOT"))
        {
            scope = "All users";
            classesRoot = true;
        }
        else if (Is(root, "HKU") || Is(root, "HKEY_USERS"))
        {
            if (rest.Count == 0 || rest[0].Length == 0) return false;
            var sid = rest[0];
            rest.RemoveAt(0);
            if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
            {
                sid = sid[..^"_Classes".Length];
                classesRoot = true;
            }
            scope = AccountName(sid, currentUserSid);
        }
        else
        {
            return false;
        }

        var bits32 = false;
        Branch branch;
        if (classesRoot)
        {
            branch = Branch.Classes;
        }
        else if (rest.Count > 0 && Is(rest[0], "SOFTWARE"))
        {
            rest.RemoveAt(0);
            branch = Branch.Software;
            if (rest.Count > 0 && Is(rest[0], "WOW6432Node"))
            {
                bits32 = true;
                rest.RemoveAt(0);
            }
            if (rest.Count > 0 && Is(rest[0], "Classes"))
            {
                rest.RemoveAt(0);
                branch = Branch.Classes;
            }
        }
        else if (rest.Count > 0 && Is(rest[0], "SYSTEM") && scope == "All users")
        {
            rest.RemoveAt(0);
            branch = Branch.System;
        }
        else
        {
            branch = Branch.Other;
        }
        if (branch == Branch.Classes && rest.Count > 0 && Is(rest[0], "WOW6432Node"))
        {
            bits32 = true;
            rest.RemoveAt(0);
        }
        hive = new Hive(scope, bits32, branch, rest);
        return true;
    }

    private static string AccountName(string sid, string? currentUserSid)
    {
        if (currentUserSid is { Length: > 0 } && Is(sid, currentUserSid)) return "Your account";
        return sid.ToUpperInvariant() switch
        {
            "S-1-5-18" => "System account",
            "S-1-5-19" => "Local service account",
            "S-1-5-20" => "Network service account",
            ".DEFAULT" => "Default account",
            _ => "Another account",
        };
    }

    // ---- Value name ---------------------------------------------------------------------------

    /// <summary>
    /// Splits a value's display path into key segments and the value name. A value name may hold <c>\</c>
    /// (SharedDLLs and compatibility values are file paths), so a known key or a drive letter marks the start.
    /// </summary>
    private static (List<string> Key, string Value) SplitValue(List<string> segs)
    {
        for (var i = 0; i < segs.Count - 1; i++)
        {
            var s = segs[i];
            var pathValued = Is(s, "SharedDLLs") || Is(s, "MuiCache")
                             || (Is(s, "Folders") && i > 0 && Is(segs[i - 1], "Installer"))
                             || (Is(s, "Layers") && i > 0 && Is(segs[i - 1], "AppCompatFlags"))
                             || (Is(s, "Store") && i > 0 && Is(segs[i - 1], "Compatibility Assistant"));
            if (pathValued) return (segs.Take(i + 1).ToList(), string.Join('\\', segs.Skip(i + 1)));
        }
        for (var i = 1; i < segs.Count; i++)
        {
            if (DriveRegex().IsMatch(segs[i])) return (segs.Take(i).ToList(), string.Join('\\', segs.Skip(i)));
        }
        return (segs.Take(segs.Count - 1).ToList(), segs[^1]);
    }

    [GeneratedRegex("^[A-Za-z]:$")]
    private static partial Regex DriveRegex();

    // ---- Patterns -----------------------------------------------------------------------------

    private static RegistryLabel Recognise(Hive hive, List<string> key, string? value, bool isValue)
    {
        var found = hive.Branch switch
        {
            Branch.Software => Software(hive, key, value),
            Branch.Classes => Classes(hive, key, value),
            Branch.System => SystemBranch(hive, key),
            _ => null,
        };
        if (found is { } hit)
        {
            return new RegistryLabel(hit.Consumed || !isValue ? hit.Title : WithValue(hit.Title, value), hit.Location);
        }

        // Fallback: the key's last segment, and the readable breadcrumb.
        var crumbs = Crumbs(hive, key);
        var last = key.Count > 0 ? key[^1] : BranchName(hive.Branch) ?? hive.ScopeText;
        return new RegistryLabel(isValue ? WithValue(last, value) : last, string.Join(Sep, crumbs));
    }

    private sealed record Hit(string Title, string Location, bool Consumed = false);

    private static string WithValue(string title, string? value) =>
        title + ": " + (value is null || Is(value, "(Default)") || value.Length == 0 ? "default value" : "value " + value);

    private static string ValueText(string? value) =>
        value is null || Is(value, "(Default)") || value.Length == 0 ? "default value" : value;

    private static Hit? Software(Hive hive, List<string> k, string? value)
    {
        var scope = hive.ScopeText;
        if (k.Count == 0) return null;

        // Microsoft\Windows\CurrentVersion\...
        if (At(k, 0, "Microsoft") && At(k, 1, "Windows") && At(k, 2, "CurrentVersion") && k.Count > 3)
        {
            var below = k.Skip(3).ToList();
            if (Is(below[0], "Uninstall"))
            {
                return below.Count > 1
                    ? new Hit("Uninstall entry for " + below[1] + Tail(below, 2), scope + Sep + "Installed programs list")
                    : new Hit("Installed programs list", scope);
            }
            if (below.Count == 1 && IsRunKey(below[0]))
            {
                return RunHit(below[0], value, scope);
            }
            if (below.Count == 3 && At(below, 0, "Policies") && At(below, 1, "Explorer") && At(below, 2, "Run"))
            {
                return RunHit("Run", value, scope);
            }
            if (below.Count == 3 && At(below, 0, "Explorer") && At(below, 1, "StartupApproved") && value is not null)
            {
                return new Hit("Startup on/off switch: " + ValueText(value), scope + Sep + "Startup apps", true);
            }
            if (Is(below[0], "App Paths") && below.Count > 1)
            {
                return new Hit("App path for " + below[1] + Tail(below, 2), scope + Sep + "App paths");
            }
            if (Is(below[0], "SharedDLLs") && below.Count == 1)
            {
                return value is null
                    ? new Hit("Shared DLL counts", scope)
                    : new Hit("Shared DLL count: " + value, scope + Sep + "Shared DLL counts", true);
            }
            if (Is(below[0], "Installer")) return Installer(scope, below.Skip(1).ToList(), value);
        }
        if (At(k, 0, "Microsoft") && At(k, 1, "Installer")) return Installer(scope, k.Skip(2).ToList(), value);

        // Microsoft\Windows NT\CurrentVersion\AppCompatFlags\...
        if (At(k, 0, "Microsoft") && At(k, 1, "Windows NT") && At(k, 2, "CurrentVersion") && At(k, 3, "AppCompatFlags")
            && value is not null)
        {
            if (k.Count == 5 && At(k, 4, "Layers"))
                return new Hit("Compatibility setting: " + ValueText(value), scope + Sep + "Compatibility settings", true);
            if (k.Count == 6 && At(k, 4, "Compatibility Assistant") && At(k, 5, "Store"))
                return new Hit("Compatibility record: " + ValueText(value), scope + Sep + "Compatibility settings", true);
        }

        if (Is(k[0], "RegisteredApplications") && k.Count == 1 && value is not null)
        {
            return new Hit("Default apps entry: " + ValueText(value), scope + Sep + "Default apps", true);
        }
        if (Is(k[0], "Clients") && k.Count > 2)
        {
            return new Hit("Default app registration: " + k[2] + Tail(k, 3), scope + Sep + "Default apps" + Sep + k[1]);
        }

        // Software\<Vendor>\<Product>: the app's own settings.
        if (IsVendor(k))
        {
            var vendor = k[0];
            var name = k.Count > 1
                ? (k[1].StartsWith(vendor, StringComparison.OrdinalIgnoreCase) ? k[1] : vendor + " " + k[1])
                : vendor;
            return value is null
                ? new Hit("Settings of " + name + Tail(k, 2), scope + Sep + "Software")
                : new Hit(name + " setting: " + ValueText(value), scope + Sep + "Software" + Sep + name + Tail(k, 2), true);
        }
        return null;
    }

    private static bool IsRunKey(string s) =>
        Is(s, "Run") || Is(s, "RunOnce") || Is(s, "RunOnceEx") || Is(s, "RunServices") || Is(s, "RunServicesOnce");

    private static Hit RunHit(string runKey, string? value, string scope)
    {
        var once = runKey.Contains("Once", StringComparison.OrdinalIgnoreCase);
        if (value is null) return new Hit(once ? "Run-once list" : "Startup list", scope);
        return new Hit((once ? "Runs once at next start: " : "Starts with Windows: ") + ValueText(value),
            scope + Sep + "Startup apps", true);
    }

    private static readonly string[] NotVendors =
        ["Classes", "Policies", "Clients", "RegisteredApplications", "WOW6432Node", "Wow6432Node"];

    private static bool IsVendor(List<string> k)
    {
        if (NotVendors.Any(n => Is(n, k[0]))) return false;
        if (Is(k[0], "Microsoft") && k.Count > 1 && (Is(k[1], "Windows") || Is(k[1], "Windows NT"))) return false;
        return true;
    }

    private static Hit? Installer(string scope, List<string> k, string? value)
    {
        var location = scope + Sep + "Windows Installer";
        if (k.Count > 1 && Is(k[0], "UserData")) k = k.Skip(2).ToList();
        if (k.Count == 0) return new Hit("Windows Installer records", scope);
        if (Is(k[0], "Folders") && k.Count == 1)
        {
            return value is null
                ? new Hit("Windows Installer folder records", location)
                : new Hit("Windows Installer folder record: " + value, location, true);
        }
        var what = k[0].ToUpperInvariant() switch
        {
            "PRODUCTS" => "Windows Installer product record",
            "FEATURES" => "Windows Installer feature record",
            "COMPONENTS" => "Windows Installer component record",
            "UPGRADECODES" => "Windows Installer upgrade code",
            "PATCHES" => "Windows Installer patch record",
            "DEPENDENCIES" => "Installer dependency record",
            _ => null,
        };
        if (what is null) return new Hit("Windows Installer record: " + string.Join(Sep, k), location);
        return new Hit(k.Count > 1 ? what + " " + k[1] + Tail(k, 2) : what + "s", location);
    }

    private static readonly string[] MenuRoots =
        ["*", "Directory", "Folder", "Drive", "AllFilesystemObjects", "DesktopBackground"];

    private static Hit? Classes(Hive hive, List<string> k, string? value)
    {
        var location = hive.ScopeText + Sep + "File types & COM";
        if (k.Count == 0) return new Hit("File types & COM", hive.ScopeText);
        var head = k[0];

        if (Is(head, "CLSID") && k.Count > 1)
        {
            var title = "COM component " + k[1];
            if (k.Count > 2 && Is(k[2], "InprocServer32")) return new Hit(title + ": DLL location" + Tail(k, 3), location);
            if (k.Count > 2 && Is(k[2], "LocalServer32")) return new Hit(title + ": program location" + Tail(k, 3), location);
            return new Hit(title + Tail(k, 2), location);
        }
        if (Is(head, "TypeLib") && k.Count > 1) return new Hit("COM type library " + k[1] + Tail(k, 2), location);
        if (Is(head, "Interface") && k.Count > 1) return new Hit("COM interface " + k[1] + Tail(k, 2), location);
        if (Is(head, "AppID") && k.Count > 1) return new Hit("COM app ID " + k[1] + Tail(k, 2), location);
        if (Is(head, "Installer")) return Installer(hive.ScopeText, k.Skip(1).ToList(), value);
        if (Is(head, "Applications") && k.Count > 1) return new Hit("Open with entry for " + k[1] + Tail(k, 2), location);
        if (Is(head, "Local Settings"))
        {
            if (Is(k[^1], "MuiCache") && value is not null)
                return new Hit("App name cache: " + ValueText(value), location, true);
            return null;
        }

        // Right-click menus: *\shell\X, Directory\Background\shell\X, SystemFileAssociations\.ext\shell\X, ...
        var menuAt = -1;
        if (MenuRoots.Any(r => Is(r, head))) menuAt = At(k, 1, "Background") ? 2 : 1;
        else if (Is(head, "SystemFileAssociations") && k.Count > 2) menuAt = 2;
        if (menuAt > 0 && k.Count > menuAt)
        {
            if (Is(k[menuAt], "shell") && k.Count > menuAt + 1)
                return new Hit("Right-click menu entry: " + k[menuAt + 1] + Tail(k, menuAt + 2), location + Sep + MenuOn(k, menuAt));
            if (Is(k[menuAt], "shellex") && k.Count > menuAt + 2)
                return new Hit("Right-click menu handler: " + k[menuAt + 2] + Tail(k, menuAt + 3), location + Sep + MenuOn(k, menuAt));
        }

        if (head.StartsWith('.') && head.Length > 1) return new Hit("File type " + head + Tail(k, 1), location);
        return new Hit("File type handler: " + head + Tail(k, 1), location);
    }

    private static string MenuOn(List<string> k, int menuAt)
    {
        var head = k[0];
        if (Is(head, "SystemFileAssociations")) return k[1] + " files";
        if (menuAt == 2) return Is(head, "Directory") ? "Folder background" : head + " background";
        return head switch
        {
            "*" => "All files",
            _ when Is(head, "Directory") || Is(head, "Folder") => "Folders",
            _ when Is(head, "Drive") => "Drives",
            _ when Is(head, "DesktopBackground") => "Desktop",
            _ => "Files and folders",
        };
    }

    private static Hit? SystemBranch(Hive hive, List<string> k)
    {
        if (k.Count < 3) return null;
        if (!(Is(k[0], "CurrentControlSet") || ControlSetRegex().IsMatch(k[0])) || !Is(k[1], "Services")) return null;
        var location = hive.ScopeText + Sep + "Services";
        if (Is(k[2], "EventLog") && k.Count > 4) return new Hit("Event log source: " + k[4] + Tail(k, 5), location);
        return new Hit("Service " + k[2] + Tail(k, 3), location);
    }

    [GeneratedRegex("^ControlSet[0-9]+$", RegexOptions.IgnoreCase)]
    private static partial Regex ControlSetRegex();

    // ---- Breadcrumbs --------------------------------------------------------------------------

    private static string? BranchName(Branch branch) => branch switch
    {
        Branch.Software => "Software",
        Branch.Classes => "File types & COM",
        Branch.System => "System",
        _ => null,
    };

    private static List<string> Crumbs(Hive hive, List<string> key)
    {
        var crumbs = new List<string> { hive.ScopeText };
        if (BranchName(hive.Branch) is { } branch) crumbs.Add(branch);
        var i = 0;
        if (At(key, 0, "Microsoft") && (At(key, 1, "Windows") || At(key, 1, "Windows NT")) && At(key, 2, "CurrentVersion"))
        {
            crumbs.Add("Windows");
            i = 3;
        }
        for (; i < key.Count; i++) crumbs.Add(key[i]);
        return crumbs;
    }

    /// <summary>The segments from <paramref name="from"/> on, as " › a › b" (empty when there are none).</summary>
    private static string Tail(List<string> k, int from) =>
        from >= k.Count ? "" : Sep + string.Join(Sep, k.Skip(from));

    private static bool At(List<string> k, int i, string s) => i < k.Count && Is(k[i], s);

    private static bool Is(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
}
