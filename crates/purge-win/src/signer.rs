//! The Authenticode signer of a file: subject common name of the embedded signature.
//!
//! ENGINE_PLAN.md §3.2 and §4.4 ("S2 shows the exact command and its Authenticode signer"), and the
//! vendor tokens of §5.4. `CryptQueryObject` opens the embedded PKCS #7 signature,
//! `CMSG_SIGNER_INFO_PARAM` names the signer's issuer and serial number, the matching certificate is
//! found in the message store, and `CertGetNameStringW` returns its subject CN.
//!
//! This reads the signature only; it does **not** verify it. No revocation check, no network, no trust
//! decision. Catalog-signed files (most of `System32`) have no embedded signature and return `None`.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_FIND_SUBJECT_CERT, CERT_INFO, CERT_NAME_ATTR_TYPE,
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO,
    CMSG_SIGNER_INFO_PARAM, CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
    CertGetNameStringW, CryptMsgClose, CryptMsgGetParam, CryptQueryObject, HCERTSTORE,
    PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

/// `szOID_COMMON_NAME`, NUL-terminated ANSI.
const OID_COMMON_NAME: &[u8] = b"2.5.4.3\0";

/// Closes the store and message returned by `CryptQueryObject`.
struct QueryHandles {
    store: HCERTSTORE,
    msg: *mut c_void,
}

impl Drop for QueryHandles {
    fn drop(&mut self) {
        // SAFETY: both handles came from `CryptQueryObject` and are closed exactly once.
        unsafe {
            if !self.msg.is_null() {
                CryptMsgClose(self.msg);
            }
            if !self.store.is_null() {
                CertCloseStore(self.store, 0);
            }
        }
    }
}

/// Frees a certificate context from `CertFindCertificateInStore`.
struct CertContext(*mut CERT_CONTEXT);

impl Drop for CertContext {
    fn drop(&mut self) {
        // SAFETY: the context is non-null and owned by this guard.
        unsafe { CertFreeCertificateContext(self.0) };
    }
}

/// The subject CN of the first signer of `path`'s embedded Authenticode signature.
///
/// `Ok(None)` when the file has no embedded signature (unsigned, catalog-signed or not a PE file).
/// `Err` only when the file cannot be read at all (missing, access denied).
pub fn signer_subject_cn(path: &Path) -> io::Result<Option<String>> {
    // Distinguish "cannot open" from "no signature": CryptQueryObject reports both as failures.
    std::fs::File::open(path)?;

    let path_w: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut h = QueryHandles {
        store: ptr::null_mut(),
        msg: ptr::null_mut(),
    };
    let mut encoding = 0u32;
    let mut content = 0u32;
    let mut format = 0u32;
    // SAFETY: `path_w` is NUL-terminated; all out-pointers are valid; the handles are owned by `h`.
    let ok = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path_w.as_ptr().cast(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &mut encoding,
            &mut content,
            &mut format,
            &mut h.store,
            &mut h.msg,
            ptr::null_mut(),
        )
    };
    if ok == 0 || h.msg.is_null() || h.store.is_null() {
        return Ok(None);
    }

    // Signer info: size, then data (8-byte aligned buffer; the structure holds pointers).
    let mut size = 0u32;
    // SAFETY: querying the size with a null buffer.
    if unsafe { CryptMsgGetParam(h.msg, CMSG_SIGNER_INFO_PARAM, 0, ptr::null_mut(), &mut size) }
        == 0
        || size == 0
    {
        return Ok(None);
    }
    let mut buf = vec![0u64; (size as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `size` bytes.
    if unsafe {
        CryptMsgGetParam(
            h.msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    } == 0
    {
        return Ok(None);
    }
    // SAFETY: the buffer now holds a CMSG_SIGNER_INFO whose pointers refer into the same buffer.
    let signer = unsafe { &*(buf.as_ptr() as *const CMSG_SIGNER_INFO) };

    // SAFETY: CERT_INFO is plain data; all-zero is a valid value.
    let mut cert_info: CERT_INFO = unsafe { std::mem::zeroed() };
    cert_info.Issuer = signer.Issuer;
    cert_info.SerialNumber = signer.SerialNumber;
    // SAFETY: the store is open; `cert_info` outlives the call.
    let ctx = unsafe {
        CertFindCertificateInStore(
            h.store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            (&cert_info as *const CERT_INFO).cast(),
            ptr::null(),
        )
    };
    if ctx.is_null() {
        return Ok(None);
    }
    let ctx = CertContext(ctx);

    let cn = name_string(&ctx, CERT_NAME_ATTR_TYPE, OID_COMMON_NAME.as_ptr().cast())
        .or_else(|| name_string(&ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, ptr::null()));
    Ok(cn)
}

/// `CertGetNameStringW` for the subject; `None` when empty.
fn name_string(ctx: &CertContext, kind: u32, para: *const c_void) -> Option<String> {
    // SAFETY: valid context; a null buffer queries the size (in characters, including the NUL).
    let len = unsafe { CertGetNameStringW(ctx.0, kind, 0, para, ptr::null_mut(), 0) };
    if len <= 1 {
        return None;
    }
    let mut buf = vec![0u16; len as usize];
    // SAFETY: `buf` holds `len` characters.
    let got = unsafe { CertGetNameStringW(ctx.0, kind, 0, para, buf.as_mut_ptr(), len) };
    let n = (got as usize).saturating_sub(1).min(buf.len());
    let s = String::from_utf16_lossy(&buf[..n]).trim().to_owned();
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn system_root() -> PathBuf {
        PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into()))
    }

    #[test]
    fn notepad_does_not_panic() {
        // notepad.exe is usually catalog-signed (None); an embedded signature yields a CN.
        let notepad = system_root().join(r"System32\notepad.exe");
        if notepad.exists() {
            let cn = signer_subject_cn(&notepad).expect("readable");
            println!("notepad signer: {cn:?}");
            if let Some(cn) = cn {
                assert!(!cn.is_empty());
            }
        }
    }

    #[test]
    fn some_embedded_signature_is_read() {
        // A few files that commonly carry an embedded Microsoft signature; report what was found.
        let root = system_root();
        let candidates = [
            root.join(r"System32\MRT.exe"),
            root.join(r"System32\ntoskrnl.exe"),
            root.join(r"explorer.exe"),
            root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe"),
            PathBuf::from(r"C:\Program Files\Windows Defender\MsMpEng.exe"),
        ];
        for path in candidates.iter().filter(|p| p.exists()) {
            match signer_subject_cn(path) {
                Ok(cn) => println!("{}: {cn:?}", path.display()),
                Err(e) => println!("{}: error {e}", path.display()),
            }
        }
    }

    #[test]
    fn unsigned_file_is_none() {
        // The test binary itself is unsigned.
        let exe = std::env::current_exe().unwrap();
        assert_eq!(signer_subject_cn(&exe).unwrap(), None);
        // A non-PE file.
        let dir = std::env::temp_dir().join(format!("purge-win-signer-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let txt = dir.join("plain.txt");
        std::fs::write(&txt, b"not signed").unwrap();
        assert_eq!(signer_subject_cn(&txt).unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_file_is_error() {
        assert!(signer_subject_cn(Path::new(r"C:\definitely\not\here.exe")).is_err());
    }
}
