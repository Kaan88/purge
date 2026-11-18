# kb: Purge knowledge base

Static data the engine loads (ENGINE_PLAN.md §3.2, §5.9). Loaded by `purge-kb` and `purge-index`; every
file is code-reviewed and shipped as a snapshot per release, with no network fetch.

JSON has no comment syntax, so each data file is described here; the list files start as an empty array.

| Path | Contents | Used by | Lands in |
|---|---|---|---|
| `packs/` | Per-app knowledge packs (declarative JSON, §5.9) | `purge-kb`, `purge-scan` | M4 |
| `baselines/` | Clean-Windows key/value/path sets per (edition, build); format in `baselines/README.md` | `purge-index` | M0 (built by the rig) |
| `generic-tokens.json` | Name tokens too generic to count as identity evidence on their own (e.g. "update", "helper") | `purge-identity` | M1a |
| `mega-vendors.json` | Publishers with many unrelated products, whose name alone never proves ownership | `purge-identity` | M1a |
| `shared-components.json` | Paths and keys shared between products (runtimes, common files) that are never offered as one app's leftover | `purge-guard`, `purge-index` | M1a, M1b |
| `shared-iids.json` | `{ "iids": [{iid, name, why}], "shared_proxy_clsids": [{clsid, name, why}] }`: COM interface ids registered by many products, and proxy/stub CLSIDs that are never an owner | `purge-guard`, `purge-scan` (COM scanners) | M1b |
| `hosts.json` | `{ "interpreters": [file name] }`: interpreters and host executables whose command line never attributes a service, task or rule to an app | `purge-index` (`resolve_program`) | M1b |
| `deny.json` | Deny-list data beyond the built-in rules of `purge-guard` (§5.10), seeded from BCU's (Apache-2.0, attributed) | `purge-guard` | M1a |

Licence-clean seed sources only (§5.9): our VM truth runs, winget-pkgs (MIT), Scoop Main (Unlicense),
`chocolatey-community/chocolatey-packages` (Apache-2.0), BCU deny data (Apache-2.0). Winapp2 and BleachBit
are reference reading only.

## Provenance of the M1b entries (M1B-KB)

Every entry comes from a rig capture on disk, never from memory. Snaps are `vm/runs/<run>/snap-<run>-<n>.tsv.gz`
(format: `baselines/README.md`); `crates/purge-guard/tests/kb_data.rs` checks the IIDs against the dirty-base
snap when `PURGE_DIRTY_BASE_SNAP` points at it (or it sits at its default path).

| File / entries | Source |
|---|---|
| `shared-iids.json` `iids`: ISimpleDOMNode, ISimpleDOMDocument, ISimpleDOMText | `vm/runs/dirty-base/snap-dirty-base-0.tsv.gz`: `HKLM\SOFTWARE\Classes\Interface\{IID}` default value = the name; ProxyStubClsid32 `{1814CEEB-...}` = Zotero's AccessibleMarshal.dll. The same proxy CLSID points at Firefox's and Thunderbird's AccessibleMarshal.dll in `firefox/snap-firefox-1` and `x0-thunderbird/snap-x0-thunderbird-1`. |
| `shared-iids.json` `iids`: the 18 IAccessible2 interfaces | dirty-base snap, both views, ProxyStubClsid32 `{01C20F2B-...}` = `System32\ia2comproxy.dll` / `SysWOW64\ia2comproxy.dll`. Also present in both clean baselines. Two IIDs carry the registered name IAccessibleAction (`{B70D9F59-...}`, `{C48C7FCF-...}`); the names are copied as registered. |
| `shared-iids.json` `iids`: IOleInPlaceObjectWindowless, IOleInPlaceSiteWindowless, IViewObjectEx | dirty-base snap, both views, ProxyStubClsid32 `{B196B286-...}` (oleaut32.dll); absent from the EnterpriseSEval-26100.1742 baseline of the same machine, so written by the dirty-base install set. |
| `shared-iids.json` `shared_proxy_clsids` | dirty-base snap: `HKLM\SOFTWARE\Classes\CLSID\{CLSID}` default value = the name, InprocServer32 = `System32\oleaut32.dll` (the six `{0002042x-...}` and `{B196B286-...}`), `System32\ia2comproxy.dll` (`{01C20F2B-...}`) or a product's AccessibleMarshal.dll (`{1814CEEB-...}`). |
| `shared-components.json` `python-launcher` | `vm/truth/labels/python.json` (kept_owner rules of the Python Launcher MSI `{73831AC2-...}`), `vm/runs/python/snap-python-1` and `-2` (`C:\WINDOWS\py.exe`, `pyw.exe`, `pyshellext.amd64.dll`, `Package Cache\{73831AC2-...}v3.12.7150.0`, `WOW6432Node\Python\PyLauncher`), dirty-base snap (ARP DisplayName "Python Launcher" of `{7102CAE5-...}`, `Package Cache\{7102CAE5-...}v3.13.1150.0\launcher.msi`, the `.py*` and `Python.*` keys, CLSID `{BEA218D2-...}` = `C:\WINDOWS\pyshellext.amd64.dll`). The cache entries use Burn's `{ProductCode}v<version>` naming with the version as a glob. The entry shape has no product-name pattern field; the launcher's product name is the entry's `name`. `burn_link` (M1b gate fix, SYS-BURNDEPS without a provider record): `vm/runs/m1b-python` and `m1b-python313-with-312` snaps. The CPython bundles write only their own `Dependencies\CPython-3.x\Dependents\{bundle}` record (no record on the launcher's provider), so the link is by bundle provider `CPython-*` and the launcher's UpgradeCode `{1B68A0EC-4DD3-5134-840E-73854B0863F1}` (packed `CE0A86B13DD4431548E03758B480361F`), the same for the 3.12.7 launcher `{73831AC2-...}` and the 3.13.17 launcher `{8078A005-...}`. |
| `shared-components.json` `vcredist-files` | `vm/runs/vcredist/snap-vcredist-1` against `-0` and `-2`: the 26 files the VC++ 2015-2022 x64 redistributable 14.44.35211 adds to `C:\WINDOWS\System32` and removes on uninstall. |
| `shared-components.json` `windowsappruntime-registration` | dirty-base snap: the registry keys of the `Microsoft.WindowsAppRuntime.*` packages outside the package store (PackageRepository, per-user Repository, CapAuthz ApplicationsEx, AppxAllUserStore). The existing `windowsappruntime` entry (packages) is unchanged. |
| `hosts.json` | The interpreter list of C-SYSOBJ `resolve_program` in `docs/M1B_DESIGN.json`, copied exactly. |
| `deny.json` | No M1b additions: everything M1b blocks is expressible as rules in code (M1B-GUARD). |

### Gaps (no capture on disk has the data)

- **IAccessible2_3, IAccessibleDocument** (`shared-iids.json`): no snap in `vm/runs` or
  `E:\purge-build\gate-evidence` has an `Interface` key with either name; Windows' ia2comproxy.dll registers
  only the 18 listed. Filled by a dirty-base-style snap of a VM with a product that registers the IAccessible2
  1.3 proxy (for example a screen reader or browser that ships its own IAccessible2 proxy dll).
- **SysWOW64 VC++ runtime files** (`vcredist-files`): the vcredist run installed the x64 package only. Filled by
  a rig run of `vc_redist.x86.exe` (snap-1 against snap-0, `C:\WINDOWS\SysWOW64`).
- **Java Access Bridge** (`WindowsAccessBridge-64.dll` in System32): no rig run installed a JDK or JRE; the only
  windowsaccessbridge.dll on disk is NVDA's own copy in its install folder. Filled by the temurin run of M1b
  (M1B-RIG-GUEST `apps.ps1` temurin, snap-1), checking `C:\WINDOWS\System32`.
- **.NET hosting** (dotnet.exe host, hostfxr): no rig run installed a .NET runtime; the only hostfxr.dll on disk
  is an app-local copy of a self-contained app, which is that app's own. The existing `dotnet` entry covers
  `%ProgramFiles%\dotnet`. Filled by a rig run of the .NET Desktop Runtime installer (snap-1 against snap-0).
- **Per-user Python Launcher** (`%LOCALAPPDATA%\Programs\Python\Launcher`): every Python run used
  `InstallAllUsers=1`. Filled by a python run with `InstallAllUsers=0`.
