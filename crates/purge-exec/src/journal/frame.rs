//! Line framing: one record's JSON object with the hash-chain member appended (see the module docs of
//! [`crate::journal`]).

use purge_model::exec::op::Sha256Hex;
use sha2::{Digest, Sha256};

use super::Corruption;

/// The text between a record's last member and the chain digest.
const CHAIN_FIELD: &[u8] = br#","chain":""#;
/// Length of the chain digest in hex digits.
const CHAIN_HEX: usize = 64;
/// Length of `,"chain":"<64 hex>"}`.
pub(super) const SUFFIX_LEN: usize = CHAIN_FIELD.len() + CHAIN_HEX + 2;
/// The chain value before the first line.
pub(super) const CHAIN_SEED: [u8; 32] = [0; 32];

/// `SHA-256(prev || body)`.
pub(super) fn chain_next(prev: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(body);
    hasher.finalize().into()
}

/// Frames `body`, the compact JSON of one record (an object with at least one member, on one line), as a
/// journal line ending in `\n`. Returns the line and the new chain value.
pub(super) fn frame(prev: &[u8; 32], body: &str) -> (Vec<u8>, [u8; 32]) {
    debug_assert!(body.len() > 2 && body.starts_with('{') && body.ends_with('}'));
    debug_assert!(!body.contains('\n'));
    let next = chain_next(prev, body.as_bytes());
    let mut line = Vec::with_capacity(body.len() + SUFFIX_LEN + 1);
    line.extend_from_slice(&body.as_bytes()[..body.len() - 1]);
    line.extend_from_slice(CHAIN_FIELD);
    line.extend_from_slice(Sha256Hex::from(next).to_string().as_bytes());
    line.extend_from_slice(b"\"}\n");
    (line, next)
}

/// Checks one complete line (without its `\n`) against the chain value before it. Returns the record's
/// body (the line without the chain member) and the line's chain value.
pub(super) fn unframe(prev: &[u8; 32], line: &[u8]) -> Result<(Vec<u8>, [u8; 32]), Corruption> {
    if line.len() < SUFFIX_LEN + 2 || line[0] != b'{' {
        return Err(Corruption::NotFramed);
    }
    let (head, suffix) = line.split_at(line.len() - SUFFIX_LEN);
    let digits = &suffix[CHAIN_FIELD.len()..CHAIN_FIELD.len() + CHAIN_HEX];
    if !suffix.starts_with(CHAIN_FIELD) || !suffix.ends_with(b"\"}") {
        return Err(Corruption::NotFramed);
    }
    let stated: Sha256Hex = std::str::from_utf8(digits)
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or(Corruption::NotFramed)?;
    let mut body = Vec::with_capacity(head.len() + 1);
    body.extend_from_slice(head);
    body.push(b'}');
    let computed = chain_next(prev, &body);
    if computed != stated.0 {
        return Err(Corruption::ChainMismatch);
    }
    Ok((body, computed))
}
