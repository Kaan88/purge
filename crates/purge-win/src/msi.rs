//! Read-only Windows Installer queries through `msi.dll`, plus packed-GUID conversion.
//!
//! ENGINE_PLAN.md §3.2 and §4.1 (MSI). What this module offers:
//!
//! - [`enum_products`]: `MsiEnumProductsExW` over the user-unmanaged, user-managed and machine contexts.
//!   [`EnumScope::CurrentUser`] passes a NULL user SID (the caller's own installs plus machine ones; works
//!   at medium integrity); [`EnumScope::AllUsers`] passes `s-1-1-0` (every user; needs elevation).
//! - [`product_info`]: `MsiGetProductInfoExW` for ProductName, VersionString, InstallLocation,
//!   LocalPackage, InstallDate and Publisher.
//! - [`product_state`] / [`product_state_all_contexts`]: the `MsiQueryProductStateW` answer per context,
//!   read as the `State` property of `MsiGetProductInfoExW`.
//! - [`pack_guid`] / [`unpack_guid`]: the pure `{GUID}` <-> packed (registry) form used under
//!   `Installer\UserData\<sid>\Products\<packed>`.
//!
//! Nothing here changes system state.

use std::io;
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, ERROR_UNKNOWN_PRODUCT,
    ERROR_UNKNOWN_PROPERTY,
};
use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
    INSTALLPROPERTY_INSTALLDATE, INSTALLPROPERTY_INSTALLEDPRODUCTNAME,
    INSTALLPROPERTY_INSTALLLOCATION, INSTALLPROPERTY_LOCALPACKAGE, INSTALLPROPERTY_PRODUCTNAME,
    INSTALLPROPERTY_PRODUCTSTATE, INSTALLPROPERTY_PUBLISHER, INSTALLPROPERTY_VERSIONSTRING,
    MSIINSTALLCONTEXT, MSIINSTALLCONTEXT_MACHINE, MSIINSTALLCONTEXT_USERMANAGED,
    MSIINSTALLCONTEXT_USERUNMANAGED, MsiEnumProductsExW, MsiGetProductInfoExW,
};
use windows_sys::core::PCWSTR;

/// The SID string meaning "all users" for `MsiEnumProductsExW`.
const ALL_USERS_SID: &str = "s-1-1-0";

/// A Windows Installer installation context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MsiContext {
    /// Per-user, managed (installed by policy).
    UserManaged,
    /// Per-user, unmanaged.
    UserUnmanaged,
    /// Per-machine.
    Machine,
}

impl MsiContext {
    /// All three contexts, in the order queried.
    pub const ALL: [MsiContext; 3] = [
        MsiContext::UserManaged,
        MsiContext::UserUnmanaged,
        MsiContext::Machine,
    ];

    fn raw(self) -> MSIINSTALLCONTEXT {
        match self {
            MsiContext::UserManaged => MSIINSTALLCONTEXT_USERMANAGED,
            MsiContext::UserUnmanaged => MSIINSTALLCONTEXT_USERUNMANAGED,
            MsiContext::Machine => MSIINSTALLCONTEXT_MACHINE,
        }
    }

    fn from_raw(raw: MSIINSTALLCONTEXT) -> Option<Self> {
        match raw {
            MSIINSTALLCONTEXT_USERMANAGED => Some(MsiContext::UserManaged),
            MSIINSTALLCONTEXT_USERUNMANAGED => Some(MsiContext::UserUnmanaged),
            MSIINSTALLCONTEXT_MACHINE => Some(MsiContext::Machine),
            _ => None,
        }
    }
}

/// Whose products [`enum_products`] lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumScope {
    /// The calling user's per-user products plus per-machine products (NULL user SID).
    CurrentUser,
    /// Every user's products plus per-machine products (`s-1-1-0`; requires administrator rights).
    AllUsers,
}

/// One installed (or advertised) product in one context.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MsiProductRef {
    /// ProductCode, upper case with braces.
    pub product_code: String,
    /// The context the product is installed in.
    pub context: MsiContext,
    /// The owning user's SID for per-user contexts; `None` for [`MsiContext::Machine`].
    pub user_sid: Option<String>,
}

/// Product properties read with `MsiGetProductInfoExW`. A property the installer does not have is `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MsiProductInfo {
    /// `InstalledProductName`, or `ProductName` for an advertised product.
    pub product_name: Option<String>,
    /// `VersionString`.
    pub version: Option<String>,
    /// `InstallLocation` (often empty for MSI packages that do not set `ARPINSTALLLOCATION`).
    pub install_location: Option<String>,
    /// `LocalPackage`: the cached `.msi` under `%WINDIR%\Installer`.
    pub local_package: Option<String>,
    /// `InstallDate` as stored (`YYYYMMDD`).
    pub install_date: Option<String>,
    /// `Publisher`.
    pub publisher: Option<String>,
}

/// The product state in one context (`INSTALLSTATE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MsiProductState {
    /// Not known to the installer in this context (`INSTALLSTATE_UNKNOWN`).
    Unknown,
    /// Advertised but not installed (`INSTALLSTATE_ADVERTISED`).
    Advertised,
    /// Installed for a different user (`INSTALLSTATE_ABSENT`).
    Absent,
    /// Installed (`INSTALLSTATE_DEFAULT`).
    Installed,
    /// Any other value the installer reports.
    Other(i32),
}

impl MsiProductState {
    fn from_raw(v: i32) -> Self {
        match v {
            -1 => MsiProductState::Unknown,
            1 => MsiProductState::Advertised,
            2 => MsiProductState::Absent,
            5 => MsiProductState::Installed,
            other => MsiProductState::Other(other),
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

fn win32_err(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

/// Lists products with `MsiEnumProductsExW` in all three contexts.
pub fn enum_products(scope: EnumScope) -> io::Result<Vec<MsiProductRef>> {
    enum_products_inner(None, scope)
}

/// Lists the contexts (and, with [`EnumScope::AllUsers`], the users) in which one ProductCode is
/// installed or advertised.
pub fn product_contexts(product_code: &str, scope: EnumScope) -> io::Result<Vec<MsiProductRef>> {
    enum_products_inner(Some(product_code), scope)
}

fn enum_products_inner(
    product_code: Option<&str>,
    scope: EnumScope,
) -> io::Result<Vec<MsiProductRef>> {
    let code_w = product_code.map(wide);
    let code_ptr: PCWSTR = code_w.as_ref().map_or(ptr::null(), |w| w.as_ptr());
    let sid_w = match scope {
        EnumScope::CurrentUser => None,
        EnumScope::AllUsers => Some(wide(ALL_USERS_SID)),
    };
    let sid_ptr: PCWSTR = sid_w.as_ref().map_or(ptr::null(), |w| w.as_ptr());
    let contexts = (MSIINSTALLCONTEXT_USERMANAGED
        | MSIINSTALLCONTEXT_USERUNMANAGED
        | MSIINSTALLCONTEXT_MACHINE) as u32;

    let mut out = Vec::new();
    let mut index = 0u32;
    let mut sid_buf = vec![0u16; 256];
    loop {
        let mut code = [0u16; 39];
        let mut ctx: MSIINSTALLCONTEXT = 0;
        let mut sid_len = sid_buf.len() as u32;
        // SAFETY: every out-pointer refers to a live buffer of the stated size; the inputs are
        // NUL-terminated or NULL.
        let rc = unsafe {
            MsiEnumProductsExW(
                code_ptr,
                sid_ptr,
                contexts,
                index,
                code.as_mut_ptr(),
                &mut ctx,
                sid_buf.as_mut_ptr(),
                &mut sid_len,
            )
        };
        match rc {
            ERROR_SUCCESS => {}
            ERROR_NO_MORE_ITEMS => break,
            ERROR_UNKNOWN_PRODUCT if product_code.is_some() => break,
            ERROR_MORE_DATA => {
                // The SID buffer was too small: grow it and retry the same index.
                sid_buf = vec![0u16; sid_len as usize + 1];
                continue;
            }
            other => return Err(win32_err(other)),
        }
        index += 1;
        let Some(context) = MsiContext::from_raw(ctx) else {
            continue;
        };
        let sid = from_wide(&sid_buf);
        out.push(MsiProductRef {
            product_code: from_wide(&code).to_ascii_uppercase(),
            context,
            user_sid: (context != MsiContext::Machine && !sid.is_empty()).then_some(sid),
        });
    }
    Ok(out)
}

/// Reads one property with `MsiGetProductInfoExW`. `Ok(None)` when the property is unknown or empty.
fn get_property(
    code: &[u16],
    sid: Option<&[u16]>,
    ctx: MsiContext,
    property: PCWSTR,
) -> io::Result<Option<String>> {
    let sid_ptr = sid.map_or(ptr::null(), <[u16]>::as_ptr);
    let mut buf = vec![0u16; 260];
    loop {
        let mut len = buf.len() as u32;
        // SAFETY: `code`, `sid` and `property` are NUL-terminated; `buf` holds `len` characters.
        let rc = unsafe {
            MsiGetProductInfoExW(
                code.as_ptr(),
                sid_ptr,
                ctx.raw(),
                property,
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        match rc {
            ERROR_SUCCESS => {
                let s = String::from_utf16_lossy(&buf[..(len as usize).min(buf.len())]);
                let s = s.trim_end_matches('\0').to_owned();
                return Ok((!s.is_empty()).then_some(s));
            }
            ERROR_MORE_DATA => buf = vec![0u16; len as usize + 1],
            ERROR_UNKNOWN_PROPERTY => return Ok(None),
            other => return Err(win32_err(other)),
        }
    }
}

/// The user SID argument `MsiGetProductInfoExW` accepts: NULL for the machine context.
fn sid_arg(user_sid: Option<&str>, ctx: MsiContext) -> Option<Vec<u16>> {
    match ctx {
        MsiContext::Machine => None,
        _ => user_sid.map(wide),
    }
}

/// Reads the product properties of `product`. Fails with `ERROR_UNKNOWN_PRODUCT` (1605) when the product
/// is not in that context any more.
pub fn product_info(product: &MsiProductRef) -> io::Result<MsiProductInfo> {
    product_info_ex(
        &product.product_code,
        product.user_sid.as_deref(),
        product.context,
    )
}

/// [`product_info`] for an explicit ProductCode, user SID (`None` = the calling user) and context.
pub fn product_info_ex(
    product_code: &str,
    user_sid: Option<&str>,
    ctx: MsiContext,
) -> io::Result<MsiProductInfo> {
    let code = wide(product_code);
    let sid = sid_arg(user_sid, ctx);
    let get = |p: PCWSTR| get_property(&code, sid.as_deref(), ctx, p);
    let product_name = match get(INSTALLPROPERTY_INSTALLEDPRODUCTNAME)? {
        Some(n) => Some(n),
        None => get(INSTALLPROPERTY_PRODUCTNAME)?,
    };
    Ok(MsiProductInfo {
        product_name,
        version: get(INSTALLPROPERTY_VERSIONSTRING)?,
        install_location: get(INSTALLPROPERTY_INSTALLLOCATION)?,
        local_package: get(INSTALLPROPERTY_LOCALPACKAGE)?,
        install_date: get(INSTALLPROPERTY_INSTALLDATE)?,
        publisher: get(INSTALLPROPERTY_PUBLISHER)?,
    })
}

/// The state of a product in one context for one user (`None` = the calling user).
pub fn product_state(
    product_code: &str,
    user_sid: Option<&str>,
    ctx: MsiContext,
) -> io::Result<MsiProductState> {
    let code = wide(product_code);
    let sid = sid_arg(user_sid, ctx);
    match get_property(&code, sid.as_deref(), ctx, INSTALLPROPERTY_PRODUCTSTATE) {
        Ok(Some(v)) => Ok(v
            .trim()
            .parse::<i32>()
            .map_or(MsiProductState::Unknown, MsiProductState::from_raw)),
        Ok(None) => Ok(MsiProductState::Unknown),
        Err(e) if e.raw_os_error() == Some(ERROR_UNKNOWN_PRODUCT as i32) => {
            Ok(MsiProductState::Unknown)
        }
        Err(e) => Err(e),
    }
}

/// The state of a product for the calling user in each of the three contexts (always three entries, in
/// [`MsiContext::ALL`] order). Other users' per-user installs are found with [`product_contexts`] and
/// [`EnumScope::AllUsers`].
pub fn product_state_all_contexts(
    product_code: &str,
) -> io::Result<Vec<(MsiContext, MsiProductState)>> {
    MsiContext::ALL
        .iter()
        .map(|&ctx| Ok((ctx, product_state(product_code, None, ctx)?)))
        .collect()
}

/// Strips braces and hyphens and checks for 32 hex digits.
fn hex32(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    let s = s
        .strip_prefix('{')
        .and_then(|x| x.strip_suffix('}'))
        .unwrap_or(s);
    let hex: Vec<u8> = s
        .bytes()
        .filter(|&b| b != b'-')
        .map(|b| b.to_ascii_uppercase())
        .collect();
    (hex.len() == 32 && hex.iter().all(u8::is_ascii_hexdigit)).then_some(hex)
}

/// The packing permutation: reverse the first three groups (8, 4, 4 digits) and swap the two digits of
/// each of the last eight bytes. It is its own inverse.
fn permute(hex: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend(hex[0..8].iter().rev());
    out.extend(hex[8..12].iter().rev());
    out.extend(hex[12..16].iter().rev());
    for i in (16..32).step_by(2) {
        out.push(hex[i + 1]);
        out.push(hex[i]);
    }
    out
}

/// `{12345678-90AB-CDEF-1234-567890ABCDEF}` -> `87654321BA09FEDC2143658709BADCFE`. Braces and hyphens
/// are optional on input; output is upper case. `None` for anything that is not a GUID.
pub fn pack_guid(guid: &str) -> Option<String> {
    let s = guid.trim();
    let inner = s
        .strip_prefix('{')
        .and_then(|x| x.strip_suffix('}'))
        .unwrap_or(s);
    // With hyphens, they must be in GUID positions.
    if inner.contains('-')
        && !(inner.len() == 36
            && inner
                .bytes()
                .enumerate()
                .all(|(i, b)| (b == b'-') == matches!(i, 8 | 13 | 18 | 23)))
    {
        return None;
    }
    let hex = hex32(inner)?;
    String::from_utf8(permute(&hex)).ok()
}

/// `87654321BA09FEDC2143658709BADCFE` -> `{12345678-90AB-CDEF-1234-567890ABCDEF}`. `None` unless the input
/// is exactly 32 hex digits.
pub fn unpack_guid(packed: &str) -> Option<String> {
    let p = packed.trim();
    if p.len() != 32 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let hex = hex32(p)?;
    let g = String::from_utf8(permute(&hex)).ok()?;
    Some(format!(
        "{{{}-{}-{}-{}-{}}}",
        &g[0..8],
        &g[8..12],
        &g[12..16],
        &g[16..20],
        &g[20..32]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn pack_vectors() {
        let table = [
            (
                "{12345678-90AB-CDEF-1234-567890ABCDEF}",
                "87654321BA09FEDC2143658709BADCFE",
            ),
            (
                "{00000000-0000-0000-0000-000000000000}",
                "00000000000000000000000000000000",
            ),
            (
                "{90160000-008C-0000-1000-0000000FF1CE}",
                "00006109C80000000100000000F01FEC",
            ),
            (
                "{a1b2c3d4-e5f6-0718-293a-4b5c6d7e8f90}",
                "4D3C2B1A6F5E817092A3B4C5D6E7F809",
            ),
        ];
        for (guid, packed) in table {
            assert_eq!(pack_guid(guid).as_deref(), Some(packed), "pack {guid}");
            assert_eq!(
                unpack_guid(packed),
                Some(guid.to_ascii_uppercase()),
                "unpack {packed}"
            );
        }
        // Braces and hyphens optional.
        assert_eq!(
            pack_guid("12345678-90AB-CDEF-1234-567890ABCDEF").as_deref(),
            Some("87654321BA09FEDC2143658709BADCFE")
        );
        assert_eq!(
            pack_guid("1234567890ABCDEF1234567890ABCDEF").as_deref(),
            Some("87654321BA09FEDC2143658709BADCFE")
        );
    }

    #[test]
    fn pack_rejects_garbage() {
        assert_eq!(pack_guid(""), None);
        assert_eq!(pack_guid("{12345678-90AB-CDEF-1234-567890ABCDEG}"), None);
        assert_eq!(pack_guid("{1234567-890AB-CDEF-1234-567890ABCDEF}"), None);
        assert_eq!(pack_guid("{12345678-90AB-CDEF-1234-567890ABCDE}"), None);
        assert_eq!(unpack_guid("87654321BA09FEDC2143658709BADCF"), None);
        assert_eq!(unpack_guid("87654321-A09FEDC2143658709BADCFE"), None);
    }

    #[test]
    fn round_trip_is_identity() {
        let g = "{F0E1D2C3-B4A5-9687-7869-5A4B3C2D1E0F}";
        assert_eq!(unpack_guid(&pack_guid(g).unwrap()).as_deref(), Some(g));
    }

    /// Packed product codes listed under `HKLM\...\Installer\UserData\*\Products`, unpacked.
    fn registry_product_codes() -> BTreeSet<String> {
        use windows_sys::Win32::System::Registry::{
            HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, RegCloseKey, RegEnumKeyExW,
            RegOpenKeyExW,
        };
        fn subkeys(parent: HKEY, path: &str) -> Vec<String> {
            let path_w = wide(path);
            let mut key: HKEY = ptr::null_mut();
            // SAFETY: valid NUL-terminated path and out-pointer.
            if unsafe {
                RegOpenKeyExW(
                    parent,
                    path_w.as_ptr(),
                    0,
                    KEY_READ | KEY_WOW64_64KEY,
                    &mut key,
                )
            } != 0
            {
                return Vec::new();
            }
            let mut names = Vec::new();
            let mut i = 0;
            loop {
                let mut buf = [0u16; 256];
                let mut len = buf.len() as u32;
                // SAFETY: `key` is open; buffer sizes are correct.
                let rc = unsafe {
                    RegEnumKeyExW(
                        key,
                        i,
                        buf.as_mut_ptr(),
                        &mut len,
                        ptr::null(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                    )
                };
                if rc != 0 {
                    break;
                }
                names.push(String::from_utf16_lossy(&buf[..len as usize]));
                i += 1;
            }
            // SAFETY: `key` was opened above.
            unsafe { RegCloseKey(key) };
            names
        }
        let base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData";
        let mut set = BTreeSet::new();
        for sid in subkeys(HKEY_LOCAL_MACHINE, base) {
            for packed in subkeys(HKEY_LOCAL_MACHINE, &format!(r"{base}\{sid}\Products")) {
                if let Some(g) = unpack_guid(&packed) {
                    set.insert(g);
                }
            }
        }
        set
    }

    #[test]
    fn host_enumeration_matches_registry() {
        let products = enum_products(EnumScope::CurrentUser).expect("MsiEnumProductsExW");
        let api: BTreeSet<String> = products.iter().map(|p| p.product_code.clone()).collect();
        let reg = registry_product_codes();
        let only_api: Vec<_> = api.difference(&reg).collect();
        let only_reg: Vec<_> = reg.difference(&api).collect();
        println!(
            "MSI API: {} products, registry UserData: {} products",
            api.len(),
            reg.len()
        );
        println!("only in MSI API ({}): {only_api:?}", only_api.len());
        println!("only in registry ({}): {only_reg:?}", only_reg.len());

        // Every product the API reports as installed must have its UserData registration.
        let mut missing = Vec::new();
        for p in &products {
            let state =
                product_state(&p.product_code, p.user_sid.as_deref(), p.context).expect("state");
            if state == MsiProductState::Installed && !reg.contains(&p.product_code) {
                missing.push(p.product_code.clone());
            }
        }
        assert!(
            missing.is_empty(),
            "installed products without UserData registration: {missing:?}"
        );

        // Property reads and the all-context state never fail on a listed product.
        for p in products.iter().take(10) {
            let info = product_info(p).expect("product info");
            let states = product_state_all_contexts(&p.product_code).expect("states");
            assert_eq!(states.len(), 3);
            assert!(
                states
                    .iter()
                    .any(|(c, s)| *c == p.context && *s != MsiProductState::Unknown),
                "{p:?} {states:?}"
            );
            println!(
                "{} {:?} {:?} {:?}",
                p.product_code, p.context, info.product_name, info.version
            );
        }
    }

    #[test]
    fn unknown_product_is_unknown_everywhere() {
        let states = product_state_all_contexts("{00000000-1111-2222-3333-444444444444}").unwrap();
        assert!(states.iter().all(|(_, s)| *s == MsiProductState::Unknown));
        assert!(
            product_contexts(
                "{00000000-1111-2222-3333-444444444444}",
                EnumScope::CurrentUser
            )
            .unwrap()
            .is_empty()
        );
    }
}
