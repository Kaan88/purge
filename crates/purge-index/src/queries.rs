//! Targeted registry queries driven by harvested anchors (ENGINE_PLAN.md §5.5: "`post_uninstall` mode
//! queries only the harvested anchors"; §5.2 "subtree baselines").
//!
//! Where [`crate::refscan`] walks the whole reference-index scope, these read only the keys the caller
//! names:
//!
//! - [`values_referencing`]: the values of a list of keys that refer to an anchor;
//! - [`keys_named`]: which of a set of names (ProgIDs, CLSIDs, AUMIDs) exist as keys under known parents;
//! - [`subtree`]: a capped capture of one key's subtree (value names and data hashes, subkeys,
//!   LastWriteTime, TrustedInstaller ownership), the raw material of a subtree baseline.
//!
//! None of them follows a registry link, and none treats "could not read" as "absent": every result
//! lists what it could not read, and has an `is_complete` test a caller must pass before concluding that
//! something is gone or unreferenced.
//!
//! # Data hashes
//!
//! [`data_hash`] is the rig's value hash (vm/RIG.md §2): the first 16 hex digits of the SHA-256 of the raw
//! data bytes, held as a `u64` like [`RegData::hash`]. It covers the data only, so a value's type is kept
//! next to it. SHA-256 is implemented in this file because the crate has no hashing dependency; it is
//! checked against the FIPS 180-4 vectors and against hashes recorded by the rig.

use purge_model::FileTime;
use purge_source::registry::RegistrySource;
use purge_source::types::{KeyInfo, RegData, SourceError, SourceResult};

use crate::matcher::RefMatcher;
use crate::refscan::{RefHit, RefScanOptions, Unreadable, sort_names, sort_values, value_hits};

// ---------------------------------------------------------------------------------------------------------
// Data hashes
// ---------------------------------------------------------------------------------------------------------

/// SHA-256 (FIPS 180-4).
mod sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn compress(state: &mut [u32; 8], block: &[u8]) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }

    /// The digest of `data`.
    pub(super) fn digest(data: &[u8]) -> [u8; 32] {
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut blocks = data.chunks_exact(64);
        for block in &mut blocks {
            compress(&mut state, block);
        }
        // Padding: 0x80, zeros, then the bit length as a big-endian u64, to a multiple of 64 bytes.
        let rest = blocks.remainder();
        let mut tail = [0u8; 128];
        tail[..rest.len()].copy_from_slice(rest);
        tail[rest.len()] = 0x80;
        let tail_len = if rest.len() < 56 { 64 } else { 128 };
        let bits = (data.len() as u64).wrapping_mul(8);
        tail[tail_len - 8..tail_len].copy_from_slice(&bits.to_be_bytes());
        for block in tail[..tail_len].chunks_exact(64) {
            compress(&mut state, block);
        }
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(4).zip(state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// The rig's hash of raw value bytes: the first 16 hex digits of their SHA-256, as a number.
pub fn hash_bytes(bytes: &[u8]) -> u64 {
    let digest = sha256::digest(bytes);
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(first)
}

/// The hash of a value's data.
///
/// Computed from the bytes when the source has all of them. For data that is cut short or unknown (a rig
/// snapshot's preview) it is the hash the source recorded, which was taken over the full data; `None`
/// when there is neither.
pub fn data_hash(data: &RegData) -> Option<u64> {
    if data.is_complete() {
        Some(hash_bytes(&data.bytes))
    } else {
        data.hash
    }
}

/// A hash as the 16 lower-case hex digits the rig and the fingerprint write.
pub fn hash_hex(hash: u64) -> String {
    format!("{hash:016x}")
}

// ---------------------------------------------------------------------------------------------------------
// values_referencing
// ---------------------------------------------------------------------------------------------------------

/// The outcome of [`values_referencing`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValuesReferencing {
    /// The referring values, in the order of the key list, values in case-insensitive name order.
    pub hits: Vec<RefHit>,
    /// Keys of the list that are registry links; they were not read.
    pub links: Vec<String>,
    /// Keys that exist (or may exist) but could not be read.
    pub unreadable: Vec<Unreadable>,
    /// Number of keys read.
    pub keys_read: u32,
    /// Number of keys of the list that do not exist.
    pub keys_missing: u32,
}

impl ValuesReferencing {
    /// Whether every listed key was either read or known to be absent (links aside).
    pub fn is_complete(&self) -> bool {
        self.unreadable.is_empty()
    }
}

/// Tests the values of exactly the listed keys (not their subkeys) against the matcher.
///
/// This is the post-uninstall counterpart of the reference scan: the caller passes the keys the
/// pre-uninstall snapshot found references in (or any other keys it derived from anchors) instead of
/// walking the scope again. A key listed twice (in any letter case) is read once. Keys that no longer
/// exist are counted, not reported as errors.
pub fn values_referencing<K: AsRef<str>>(
    reg: &dyn RegistrySource,
    matcher: &RefMatcher,
    keys: &[K],
    options: &RefScanOptions,
) -> ValuesReferencing {
    let mut out = ValuesReferencing::default();
    let mut seen: Vec<String> = Vec::with_capacity(keys.len());
    for key in keys {
        let key = key.as_ref().trim_end_matches('\\');
        let folded = key.to_lowercase();
        if key.is_empty() || seen.contains(&folded) {
            continue;
        }
        seen.push(folded);
        let info = match reg.key_info(key) {
            Ok(info) => info,
            Err(SourceError::NotFound) => {
                out.keys_missing += 1;
                continue;
            }
            Err(error) => {
                out.unreadable.push(Unreadable {
                    key: key.to_string(),
                    error,
                });
                continue;
            }
        };
        if info.is_link {
            out.links.push(key.to_string());
            continue;
        }
        match reg.values(key) {
            Ok(mut values) => {
                out.keys_read += 1;
                sort_values(&mut values);
                for value in &values {
                    out.hits.extend(value_hits(
                        matcher,
                        key,
                        value,
                        info.n_values,
                        info.n_subkeys,
                        options,
                    ));
                }
            }
            Err(SourceError::NotFound) => out.keys_missing += 1,
            Err(error) => out.unreadable.push(Unreadable {
                key: key.to_string(),
                error,
            }),
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------------------
// keys_named
// ---------------------------------------------------------------------------------------------------------

/// A key found by [`keys_named`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedKey {
    /// The parent it was found under, as the caller wrote it.
    pub parent: String,
    /// The name, as the caller wrote it (the registry may spell it in another letter case).
    pub name: String,
    /// The key's path: `parent\name`.
    pub key: String,
    /// The key's metadata. A link is reported like any other key, with [`KeyInfo::is_link`] set.
    pub info: KeyInfo,
}

/// The outcome of [`keys_named`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeysNamed {
    /// The keys that exist, parent by parent in the caller's order, names in case-insensitive order.
    pub found: Vec<NamedKey>,
    /// `parent\name` paths whose existence could not be established (access denied, not captured, …).
    pub unknown: Vec<Unreadable>,
}

impl KeysNamed {
    /// Whether every name was either found or known to be absent under every parent.
    pub fn is_complete(&self) -> bool {
        self.unknown.is_empty()
    }
}

/// Looks each name up as a direct subkey of each parent: ProgIDs under the Classes roots, CLSIDs under
/// `Classes\CLSID`, AUMIDs under `Classes\AppUserModelId`, and so on.
///
/// Each lookup opens one key; the parents' subkey lists (tens of thousands of names under a Classes root)
/// are never enumerated. Empty names and names containing `\` are ignored, since they would address the
/// parent itself or a deeper key. Parents and names repeated in another letter case are looked up once.
pub fn keys_named<P: AsRef<str>, N: AsRef<str>>(
    reg: &dyn RegistrySource,
    parents: &[P],
    names: &[N],
) -> KeysNamed {
    let mut names: Vec<String> = names
        .iter()
        .map(|n| n.as_ref().to_string())
        .filter(|n| !n.is_empty() && !n.contains('\\'))
        .collect();
    sort_names(&mut names);
    names.dedup_by_key(|n| n.to_lowercase());

    let mut out = KeysNamed::default();
    let mut seen_parents: Vec<String> = Vec::with_capacity(parents.len());
    for parent in parents {
        let parent = parent.as_ref().trim_end_matches('\\');
        let folded = parent.to_lowercase();
        if parent.is_empty() || seen_parents.contains(&folded) {
            continue;
        }
        seen_parents.push(folded);
        for name in &names {
            let key = format!("{parent}\\{name}");
            match reg.key_info(&key) {
                Ok(info) => out.found.push(NamedKey {
                    parent: parent.to_string(),
                    name: name.clone(),
                    key,
                    info,
                }),
                Err(SourceError::NotFound) => {}
                Err(error) => out.unknown.push(Unreadable { key, error }),
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------------------
// subtree
// ---------------------------------------------------------------------------------------------------------

/// Hard caps of a [`subtree`] capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubtreeLimits {
    /// Most keys captured, the subtree's own key included.
    pub max_keys: u32,
    /// Most values captured over the whole subtree.
    pub max_values: u32,
    /// Deepest level entered below the key (0 captures the key's own values and the names of its direct
    /// subkeys only).
    pub max_depth: u32,
}

impl Default for SubtreeLimits {
    fn default() -> Self {
        Self {
            max_keys: 2048,
            max_values: 8192,
            max_depth: 24,
        }
    }
}

/// One value of a captured subtree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubtreeValueRec {
    /// Path of the value's key relative to the subtree's key; empty for the key itself.
    pub subkey: String,
    /// The value's name; empty for the default value.
    pub name: String,
    /// The value's registry type.
    pub ty: u32,
    /// Length of the data in bytes.
    pub len: u32,
    /// Hash of the data ([`data_hash`]); `None` when the source has neither the full data nor a recorded
    /// hash.
    pub hash: Option<u64>,
}

impl SubtreeValueRec {
    /// The hash as 16 lower-case hex digits.
    pub fn hash_hex(&self) -> Option<String> {
        self.hash.map(hash_hex)
    }
}

/// A captured subtree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subtree {
    /// The key, as the caller wrote it.
    pub key: String,
    /// The key's LastWriteTime.
    pub lwt: FileTime,
    /// Whether TrustedInstaller owns the key or holds a write ACE on it; `None` when the source cannot
    /// tell.
    pub ti_owned: Option<bool>,
    /// The key is a registry link. Nothing below it was read.
    pub is_link: bool,
    /// Every captured value: the key's own first, then subkey by subkey in the order of
    /// [`Subtree::subkeys`]; within one key in case-insensitive name order.
    pub values: Vec<SubtreeValueRec>,
    /// Every captured subkey as a path relative to the key, depth first, siblings in case-insensitive
    /// order.
    pub subkeys: Vec<String>,
    /// Subkeys (relative paths) that are registry links; they are listed in `subkeys` but not entered.
    pub links: Vec<String>,
    /// Keys of the subtree (full paths) that could not be read.
    pub unreadable: Vec<Unreadable>,
    /// A cap of [`SubtreeLimits`] was hit: values or subkeys are missing from the capture.
    pub truncated: bool,
}

impl Subtree {
    /// Whether the capture holds the whole subtree: no cap was hit, every key was readable, and the key
    /// is not a link. Only a complete capture can prove that a subtree holds nothing foreign.
    pub fn is_complete(&self) -> bool {
        !self.truncated && self.unreadable.is_empty() && !self.is_link
    }

    /// Whether the captured subtree has neither values nor subkeys.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty() && self.subkeys.is_empty()
    }
}

/// Captures the subtree of `key`: value names with their type, length and data hash, the subkeys, the
/// key's LastWriteTime and its TrustedInstaller flag.
///
/// The capture stops at the [`SubtreeLimits`] and then has [`Subtree::truncated`] set; what was captured
/// up to that point is returned. Links are listed, never entered. Fails only when the key itself cannot
/// be opened ([`SourceError::NotFound`] when it does not exist).
pub fn subtree(
    reg: &dyn RegistrySource,
    key: &str,
    limits: &SubtreeLimits,
) -> SourceResult<Subtree> {
    let key = key.trim_end_matches('\\');
    let info = reg.key_info(key)?;
    let mut out = Subtree {
        key: key.to_string(),
        lwt: info.lwt,
        ti_owned: info.ti_owned,
        is_link: info.is_link,
        values: Vec::new(),
        subkeys: Vec::new(),
        links: Vec::new(),
        unreadable: Vec::new(),
        truncated: false,
    };
    if info.is_link {
        return Ok(out);
    }
    if limits.max_keys == 0 {
        out.truncated = true;
        return Ok(out);
    }
    let mut keys_captured = 0u32;
    // (relative path, depth, metadata); the root's metadata is already known.
    let mut stack: Vec<(String, u32, Option<KeyInfo>)> = vec![(String::new(), 0, Some(info))];
    while let Some((rel, depth, known)) = stack.pop() {
        let full = if rel.is_empty() {
            key.to_string()
        } else {
            format!("{key}\\{rel}")
        };
        let info = match known {
            Some(info) => info,
            None => match reg.key_info(&full) {
                Ok(info) => info,
                // Listed by its parent a moment ago: gone in between. Not part of the subtree.
                Err(SourceError::NotFound) => continue,
                Err(error) => {
                    out.subkeys.push(rel);
                    out.unreadable.push(Unreadable { key: full, error });
                    continue;
                }
            },
        };
        if !rel.is_empty() {
            if keys_captured >= limits.max_keys {
                out.truncated = true;
                break;
            }
            out.subkeys.push(rel.clone());
        }
        keys_captured += 1;
        if info.is_link {
            out.links.push(rel);
            continue;
        }

        let mut failed = None;
        match reg.values(&full) {
            Ok(mut values) => {
                sort_values(&mut values);
                for value in values {
                    if out.values.len() >= limits.max_values as usize {
                        out.truncated = true;
                        break;
                    }
                    out.values.push(SubtreeValueRec {
                        subkey: rel.clone(),
                        hash: data_hash(&value.data),
                        ty: value.data.ty,
                        len: value.data.len,
                        name: value.name,
                    });
                }
            }
            Err(SourceError::NotFound) => {}
            Err(error) => failed = Some(error),
        }
        match reg.subkeys(&full) {
            Ok(mut names) => {
                if depth >= limits.max_depth {
                    if !names.is_empty() {
                        out.truncated = true;
                    }
                } else {
                    sort_names(&mut names);
                    for name in names.into_iter().rev() {
                        let child = if rel.is_empty() {
                            name
                        } else {
                            format!("{rel}\\{name}")
                        };
                        stack.push((child, depth + 1, None));
                    }
                }
            }
            Err(SourceError::NotFound) => {}
            Err(error) => failed = failed.or(Some(error)),
        }
        if let Some(error) = failed {
            out.unreadable.push(Unreadable { key: full, error });
        }
        if out.truncated {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::AnchorSet;
    use crate::refscan::RefWhere;
    use purge_source::fixture::Fixture;
    use purge_source::types::{REG_DWORD, REG_SZ};

    const SID: &str = "S-1-5-21-100-200-300-1001";
    const ROOT: &str = r"C:\Program Files\Demo";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            hex(&sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&sha256::digest(&[b'a'; 1000])),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
        // Every padding boundary: lengths around 55/56 and 63/64 must all differ and be stable.
        let mut seen = std::collections::HashSet::new();
        for n in 0..200 {
            assert!(seen.insert(sha256::digest(&vec![0x61; n])));
        }
        assert_eq!(hash_bytes(b"abc"), 0xba78_16bf_8f01_cfea);
        assert_eq!(hash_hex(hash_bytes(b"")), "e3b0c44298fc1c14");
        assert_eq!(hash_hex(0x1f), "000000000000001f");
    }

    #[test]
    fn data_hash_matches_the_rig() {
        // `hello` as REG_SZ is 12 bytes with its terminator; the rig records 964fad5312093c89.
        assert_eq!(
            data_hash(&RegData::from_sz("hello")),
            Some(0x964f_ad53_1209_3c89)
        );
        let mut cut = RegData::from_sz("hel");
        cut.truncated = true;
        cut.hash = Some(7);
        assert_eq!(data_hash(&cut), Some(7));
        assert_eq!(data_hash(&RegData::unknown(3, 16)), None);
    }

    fn demo_matcher() -> RefMatcher {
        let mut set = AnchorSet::new();
        set.add_root(ROOT);
        set.add_progid("Demo.Document");
        RefMatcher::new(&set)
    }

    #[test]
    fn values_referencing_reads_only_listed_keys() {
        let run = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        let link = format!(r"HKU\{SID}\Software\Classes");
        let f = Fixture::builder()
            .sz(run, "Demo", &format!(r#""{ROOT}\demo.exe" --tray"#))
            .sz(run, "Other", r"C:\Program Files\Demo2\x.exe")
            .sz(run, "also", &format!(r"{ROOT}\helper.exe"))
            .sz(
                &format!(r"{run}\Sub"),
                "Deeper",
                &format!(r"{ROOT}\demo.exe"),
            )
            .sz(
                r"HKLM\SOFTWARE\Classes\.demo\OpenWithProgids",
                "Demo.Document",
                "",
            )
            .sz(
                r"HKLM\SOFTWARE\NotListed",
                "x",
                &format!(r"{ROOT}\demo.exe"),
            )
            .sz(r"HKLM\SOFTWARE\Secret", "x", &format!(r"{ROOT}\demo.exe"))
            .denied(r"HKLM\SOFTWARE\Secret")
            .sz(&link, "x", &format!(r"{ROOT}\demo.exe"))
            .link(&link, &format!(r"\REGISTRY\USER\{SID}_Classes"))
            .build();
        let keys = [
            r"HKLM\SOFTWARE\Classes\.demo\OpenWithProgids",
            run,
            r"hklm\software\microsoft\windows\currentversion\RUN\",
            r"HKLM\SOFTWARE\Gone",
            r"HKLM\SOFTWARE\Secret",
            link.as_str(),
        ];
        let out = values_referencing(&f, &demo_matcher(), &keys, &RefScanOptions::default());
        let brief: Vec<(&str, &str, RefWhere)> = out
            .hits
            .iter()
            .map(|h| (h.key.as_str(), h.value_name.as_str(), h.location))
            .collect();
        assert_eq!(
            brief,
            vec![
                (keys[0], "Demo.Document", RefWhere::Name),
                (run, "also", RefWhere::Data),
                (run, "Demo", RefWhere::Data),
            ]
        );
        assert_eq!(
            (out.hits[1].parent_values, out.hits[1].parent_subkeys),
            (3, 1)
        );
        assert_eq!((out.keys_read, out.keys_missing), (2, 1));
        assert_eq!(out.links, vec![link.clone()]);
        assert_eq!(out.unreadable.len(), 1);
        assert_eq!(out.unreadable[0].error, SourceError::AccessDenied);
        assert!(!out.is_complete());

        let ok = values_referencing(&f, &demo_matcher(), &keys[..4], &RefScanOptions::default());
        assert!(ok.is_complete());
        assert_eq!(ok.hits, out.hits);
    }

    #[test]
    fn keys_named_under_known_parents() {
        let machine = r"HKLM\SOFTWARE\Classes";
        let user = format!(r"HKU\{SID}_Classes");
        let aumid = format!(r"{user}\AppUserModelId");
        let f = Fixture::builder()
            .sz(
                &format!(r"{machine}\Demo.Document\shell\open\command"),
                "",
                "x",
            )
            .key(&format!(r"{machine}\Demo.DocumentX"))
            .key(&format!(r"{user}\demo.document"))
            .key(&format!(r"{user}\Demo.Url"))
            .key(&format!(r"{aumid}\Vendor.Demo"))
            .key(&format!(
                r"{machine}\CLSID\{{11111111-2222-3333-4444-555555555555}}"
            ))
            .key(r"HKLM\SOFTWARE\Hidden\Demo.Url")
            .denied(r"HKLM\SOFTWARE\Hidden")
            .registry_coverage(purge_source::fixture::Coverage::default())
            .build();
        let names = [
            "Demo.Url",
            "Demo.Document",
            "DEMO.DOCUMENT",
            "Missing.One",
            "",
            r"shell\open",
        ];
        let out = keys_named(&f, &[machine, user.as_str(), machine], &names);
        let found: Vec<(&str, &str)> = out
            .found
            .iter()
            .map(|k| (k.key.as_str(), k.name.as_str()))
            .collect();
        // `DEMO.DOCUMENT` sorts first among the two spellings and stands for both.
        assert_eq!(
            found,
            vec![
                (r"HKLM\SOFTWARE\Classes\DEMO.DOCUMENT", "DEMO.DOCUMENT"),
                (&*format!(r"{user}\DEMO.DOCUMENT"), "DEMO.DOCUMENT"),
                (&*format!(r"{user}\Demo.Url"), "Demo.Url"),
            ]
        );
        assert_eq!(out.found[0].parent, machine);
        assert_eq!(out.found[0].info.n_subkeys, 1);
        assert!(out.is_complete());

        let out = keys_named(&f, &[aumid.as_str()], &["Vendor.Demo", "Vendor.Other"]);
        assert_eq!(out.found.len(), 1);
        let out = keys_named(
            &f,
            &[format!(r"{machine}\CLSID")],
            &["{11111111-2222-3333-4444-555555555555}"],
        );
        assert_eq!(out.found.len(), 1);

        // "Cannot tell" is not "absent".
        let out = keys_named(&f, &[r"HKLM\SOFTWARE\Hidden"], &["Demo.Url", "Nope"]);
        assert_eq!(
            out.found.len(),
            1,
            "an existing key under a denied parent is still seen"
        );
        assert_eq!(out.unknown.len(), 1);
        assert_eq!(out.unknown[0].key, r"HKLM\SOFTWARE\Hidden\Nope");
        assert!(!out.is_complete());
    }

    fn tree() -> Fixture {
        let k = r"HKLM\SOFTWARE\Classes\Demo.Document";
        Fixture::builder()
            .sz(k, "", "Demo document")
            .dword(k, "EditFlags", 0x10000)
            .sz(
                &format!(r"{k}\shell\open\command"),
                "",
                &format!(r#""{ROOT}\demo.exe" "%1""#),
            )
            .sz(
                &format!(r"{k}\DefaultIcon"),
                "",
                &format!(r"{ROOT}\demo.exe,0"),
            )
            .sz(&format!(r"{k}\shell\Edit"), "b", "2")
            .sz(&format!(r"{k}\shell\Edit"), "A", "1")
            .key_lwt(k, 133_000_000_000_000_000)
            .ti_owned(k, false)
            .build()
    }

    #[test]
    fn subtree_capture() {
        let k = r"HKLM\SOFTWARE\Classes\Demo.Document";
        let f = tree();
        let st = subtree(&f, &format!(r"{k}\"), &SubtreeLimits::default()).unwrap();
        assert!(st.is_complete() && !st.is_empty());
        assert_eq!(st.key, k);
        assert_eq!(st.lwt, FileTime(133_000_000_000_000_000));
        assert_eq!(st.ti_owned, Some(false));
        assert_eq!(
            st.subkeys,
            vec![
                "DefaultIcon",
                "shell",
                r"shell\Edit",
                r"shell\open",
                r"shell\open\command"
            ]
        );
        let values: Vec<(&str, &str, u32)> = st
            .values
            .iter()
            .map(|v| (v.subkey.as_str(), v.name.as_str(), v.ty))
            .collect();
        assert_eq!(
            values,
            vec![
                ("", "", REG_SZ),
                ("", "EditFlags", REG_DWORD),
                ("DefaultIcon", "", REG_SZ),
                (r"shell\Edit", "A", REG_SZ),
                (r"shell\Edit", "b", REG_SZ),
                (r"shell\open\command", "", REG_SZ),
            ]
        );
        assert_eq!(
            st.values[1].hash,
            Some(hash_bytes(&0x10000u32.to_le_bytes()))
        );
        assert_eq!(st.values[1].len, 4);
        assert_eq!(st.values[0].hash_hex().unwrap().len(), 16);
        // The same tree captured twice is identical; a changed value changes exactly its hash.
        assert_eq!(st, subtree(&f, k, &SubtreeLimits::default()).unwrap());
        let mut f2 = f.clone();
        f2.set_value(
            &format!(r"{k}\shell\Edit"),
            "A",
            RegData::from_sz("changed"),
        );
        let st2 = subtree(&f2, k, &SubtreeLimits::default()).unwrap();
        let differing: Vec<usize> = (0..st.values.len())
            .filter(|&i| st.values[i] != st2.values[i])
            .collect();
        assert_eq!(differing, vec![3]);

        assert_eq!(
            subtree(&f, r"HKLM\SOFTWARE\Classes\Nope", &SubtreeLimits::default()),
            Err(SourceError::NotFound)
        );
        let leaf = subtree(
            &f,
            r"HKLM\SOFTWARE\Classes",
            &SubtreeLimits {
                max_depth: 0,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(leaf.truncated && leaf.subkeys.is_empty());
    }

    #[test]
    fn subtree_caps_set_truncated() {
        let k = r"HKLM\SOFTWARE\Classes\Demo.Document";
        let f = tree();
        let full = subtree(&f, k, &SubtreeLimits::default()).unwrap();

        let exact = SubtreeLimits {
            max_keys: 6,
            max_values: 6,
            max_depth: 3,
        };
        assert_eq!(
            subtree(&f, k, &exact).unwrap(),
            full,
            "limits equal to the size do not truncate"
        );

        let keys = subtree(
            &f,
            k,
            &SubtreeLimits {
                max_keys: 3,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(keys.truncated && !keys.is_complete());
        assert_eq!(keys.subkeys, vec!["DefaultIcon", "shell"]);

        let values = subtree(
            &f,
            k,
            &SubtreeLimits {
                max_values: 2,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(values.truncated);
        assert_eq!(values.values, full.values[..2]);

        let depth = subtree(
            &f,
            k,
            &SubtreeLimits {
                max_depth: 1,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(depth.truncated);
        assert_eq!(depth.subkeys, vec!["DefaultIcon", "shell"]);
        assert_eq!(depth.values.len(), 3);

        let depth2 = subtree(
            &f,
            k,
            &SubtreeLimits {
                max_depth: 2,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(depth2.truncated, "shell\\open still has a subkey");
        assert_eq!(depth2.subkeys.len(), 4);

        let none = subtree(
            &f,
            k,
            &SubtreeLimits {
                max_keys: 0,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(none.truncated && none.is_empty());
    }

    #[test]
    fn subtree_links_and_unreadable_keys() {
        let k = r"HKLM\SOFTWARE\Vendor";
        let f = Fixture::builder()
            .sz(&format!(r"{k}\Plain"), "a", "1")
            .sz(&format!(r"{k}\Link\Below"), "a", "1")
            .link(
                &format!(r"{k}\Link"),
                r"\REGISTRY\MACHINE\SOFTWARE\Elsewhere",
            )
            .sz(&format!(r"{k}\Locked\Below"), "a", "1")
            .denied(&format!(r"{k}\Locked"))
            .build();
        let st = subtree(&f, k, &SubtreeLimits::default()).unwrap();
        assert_eq!(st.subkeys, vec!["Link", "Locked", "Plain"]);
        assert_eq!(st.links, vec!["Link"]);
        assert_eq!(
            st.values.len(),
            1,
            "nothing below the link or the locked key: {:?}",
            st.values
        );
        assert_eq!(st.unreadable.len(), 1);
        assert_eq!(st.unreadable[0].key, format!(r"{k}\Locked"));
        assert!(!st.truncated && !st.is_complete());

        let link = subtree(&f, &format!(r"{k}\Link"), &SubtreeLimits::default()).unwrap();
        assert!(link.is_link && link.is_empty() && !link.is_complete());
    }

    /// A snapshot fixture: SZ data is rebuilt from the preview, so the computed hash must equal the hash
    /// the rig recorded; data the snapshot does not hold keeps the recorded hash.
    #[test]
    fn subtree_hashes_equal_snapshot_hashes() {
        let snap = concat!(
            "#purge-snap 1\t2026-11-11T16:05:36Z\tDEMO-PC\tProfessional\t26100.1742\n",
            "#roots\tHKLM\\\\SOFTWARE\n",
            "K\tHKLM\\\\SOFTWARE\\\\Demo\t134388866613378836\t3\t1\n",
            "V\tHKLM\\\\SOFTWARE\\\\Demo\t\t1\t12\t964fad5312093c89\thello\n",
            "V\tHKLM\\\\SOFTWARE\\\\Demo\tPath\t1\t62\t1575a4bb010f1a37\tC:\\\\Program Files\\\\Demo\\\\demo.exe\n",
            "V\tHKLM\\\\SOFTWARE\\\\Demo\tBlob\t3\t16\t00000000deadbeef\t\n",
            "K\tHKLM\\\\SOFTWARE\\\\Demo\\\\Sub\t134388866613378836\t0\t0\n",
        );
        let f = Fixture::from_snap_parts(snap.as_bytes(), None, None).unwrap();
        let st = subtree(&f, r"HKLM\SOFTWARE\Demo", &SubtreeLimits::default()).unwrap();
        assert!(st.is_complete());
        assert_eq!(st.subkeys, vec!["Sub"]);
        let hashes: Vec<(&str, Option<String>)> = st
            .values
            .iter()
            .map(|v| (v.name.as_str(), v.hash_hex()))
            .collect();
        assert_eq!(
            hashes,
            vec![
                ("", Some("964fad5312093c89".to_string())),
                ("Blob", Some("00000000deadbeef".to_string())),
                ("Path", Some("1575a4bb010f1a37".to_string())),
            ]
        );
        for v in &st.values {
            let recorded = f.value(r"HKLM\SOFTWARE\Demo", &v.name).unwrap().hash;
            assert_eq!(v.hash, recorded);
        }
        assert_eq!(st.ti_owned, None);
    }

    /// With `PURGE_RUNS_DIR`: over every VS Code ProgID subtree of the real post-install snapshot, the
    /// hash computed from each complete SZ value equals the hash the rig recorded.
    #[test]
    #[ignore = "needs PURGE_RUNS_DIR with the vscode run"]
    fn real_snapshot_subtree_hashes() {
        let Some(runs) = std::env::var_os("PURGE_RUNS_DIR") else {
            eprintln!("PURGE_RUNS_DIR not set; skipping");
            return;
        };
        let snap = std::path::Path::new(&runs)
            .join("vscode")
            .join("snap-vscode-1.tsv.gz");
        let f = Fixture::from_snap(&snap, None, None).unwrap();
        let classes = r"HKLM\SOFTWARE\Classes";
        let progids: Vec<String> = f
            .subkeys(classes)
            .unwrap()
            .into_iter()
            .filter(|n| n.to_lowercase().starts_with("vscode."))
            .collect();
        assert!(progids.len() > 50, "{} VS Code ProgIDs", progids.len());
        let found = keys_named(&f, &[classes], &progids);
        assert_eq!(found.found.len(), progids.len());
        let (mut checked, mut keys) = (0u32, 0usize);
        for progid in &progids {
            let key = format!(r"{classes}\{progid}");
            let st = subtree(&f, &key, &SubtreeLimits::default()).unwrap();
            assert!(st.is_complete(), "{key}: {:?}", st.unreadable);
            keys += st.subkeys.len() + 1;
            for v in &st.values {
                let full = if v.subkey.is_empty() {
                    key.clone()
                } else {
                    format!(r"{key}\{}", v.subkey)
                };
                let data = f.value(&full, &v.name).unwrap();
                if data.ty == REG_SZ && data.is_complete() {
                    assert_eq!(
                        Some(hash_bytes(&data.bytes)),
                        data.hash,
                        "{full} [{}]",
                        v.name
                    );
                    assert_eq!(v.hash, data.hash);
                    checked += 1;
                }
            }
        }
        eprintln!(
            "{} ProgIDs, {keys} keys, {checked} SZ value hashes equal the snapshot's",
            progids.len()
        );
        assert!(checked > 100);
    }
}
