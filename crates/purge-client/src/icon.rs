//! Icons of `icon.batch`, decoded: the wire carries `px * px` BGRA pixels in base64
//! (`purge_rpc::methods::Icon`); the UI wants the bytes.

use purge_model::ProgramId;
use purge_rpc::methods::Icon;

/// One program's icon, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramIcon {
    /// The program.
    pub program_id: ProgramId,
    /// Edge length in pixels.
    pub px: u16,
    /// `px * px * 4` bytes, BGRA, rows top to bottom; `None` when the engine could read no icon, or
    /// sent pixels that are not valid base64 of exactly that length (the UI shows its placeholder).
    pub bgra: Option<Vec<u8>>,
}

impl From<Icon> for ProgramIcon {
    fn from(icon: Icon) -> Self {
        let want = usize::from(icon.px) * usize::from(icon.px) * 4;
        let bgra = icon
            .bgra
            .as_deref()
            .and_then(decode_base64)
            .filter(|bytes| bytes.len() == want && want > 0);
        ProgramIcon {
            program_id: icon.program_id,
            px: icon.px,
            bgra,
        }
    }
}

/// Standard base64 (`A-Z a-z 0-9 + /`, `=` padding to a multiple of 4). Anything else, including
/// whitespace, is `None`.
pub(crate) fn decode_base64(text: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    }
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let chunks = bytes.chunks_exact(4);
    let last = chunks.len().saturating_sub(1);
    for (i, chunk) in chunks.enumerate() {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && i != last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &chunk[..4 - pad] {
            n = n << 6 | value(c)?;
        }
        n <<= 6 * pad as u32;
        let three = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&three[..3 - pad]);
    }
    Some(out)
}

/// Standard base64 with padding (the sample engine's icons, and the tests).
#[cfg(test)]
pub(crate) fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, &b| n << 8 | u32::from(b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_and_refuses_junk() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let text = encode_base64(&data);
            assert_eq!(
                decode_base64(&text).as_deref(),
                Some(data.as_slice()),
                "{text}"
            );
        }
        assert_eq!(decode_base64("AAAA/w==").unwrap(), vec![0, 0, 0, 255]);
        for bad in [
            "A", "AAA", "AA=A", "A===", "AA==AAAA", "AA AA", "AA\nA", "*AAA",
        ] {
            assert_eq!(decode_base64(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_fixture_icon_decodes_and_a_wrong_length_is_a_placeholder() {
        let text = include_str!("../../purge-rpc/fixtures/notification.icon.batch.json");
        let batch: purge_rpc::methods::IconBatch = serde_json::from_str(text).unwrap();
        let icons: Vec<ProgramIcon> = batch.icons.into_iter().map(ProgramIcon::from).collect();
        assert_eq!(icons[0].bgra.as_deref(), Some(&[0u8, 0, 0, 255][..]));
        assert_eq!(icons[1].bgra, None);
        let wrong = Icon {
            program_id: icons[0].program_id.clone(),
            px: 2,
            bgra: Some("AAAA/w==".into()),
        };
        assert_eq!(ProgramIcon::from(wrong).bgra, None);
    }
}
