//! Byte-level reading of an uninstall log: header, blocks, raw records and packed strings.
//!
//! Every function takes a slice and checks each length against it before reading, so no input can make
//! it index out of bounds.

use super::{HEADER_SIZE, InnoLogError, LogHeader, MAX_BLOCK_SIZE, MAX_SUPPORTED_VERSION, flags};

/// The id string of a log; a 64-bit install appends [`ID_64BIT_SUFFIX`].
pub(super) const ID: &[u8] = b"Inno Setup Uninstall Log (b)";
/// Suffix of the id string of a 64-bit install.
pub(super) const ID_64BIT_SUFFIX: &[u8] = b" 64-bit";

/// Size of the id string field.
pub(super) const ID_FIELD: usize = 64;
/// Size of each of the `AppId` and `AppName` fields.
pub(super) const NAME_FIELD: usize = 128;
/// Offset of the header's CRC, which covers the bytes before it.
pub(super) const HEADER_CRC_OFFSET: usize = HEADER_SIZE - 4;
/// Size of a block header `{Size, NotSize, Crc}`.
pub(super) const BLOCK_HEADER_SIZE: usize = 12;
/// Size of a record header `{Typ, ExtraData, DataSize}`.
pub(super) const RECORD_HEADER_SIZE: usize = 10;

/// The header with the fields only the reader needs.
pub(super) struct RawHeader {
    /// The public part.
    pub header: LogHeader,
    /// Number of records in the stream.
    pub num_recs: usize,
    /// File offset where the blocks end.
    pub end_offset: usize,
}

/// A record before its data is decoded.
pub(super) struct RawRecord<'a> {
    pub typ: u16,
    pub extra_data: u32,
    pub data: &'a [u8],
}

/// CRC-32 (the common IEEE one) of `bytes`.
pub(super) fn crc32(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

/// Reads a little-endian `u32` at `offset`; `None` when the slice is too short.
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let chunk: [u8; 4] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(chunk))
}

/// Reads a little-endian `u16` at `offset`; `None` when the slice is too short.
fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let chunk: [u8; 2] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(chunk))
}

/// The bytes of a NUL-padded field up to its first NUL.
fn c_str(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..end]
}

/// Decodes single-byte text as Latin-1 (exact for ASCII; the log does not name its code page).
fn decode_ansi(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// Decodes the header's `AppId` or `AppName` field.
///
/// A name with characters outside ASCII is stored as the byte `0x01` followed by UTF-8; anything else
/// (and a marked name that is not valid UTF-8) is read as single-byte text.
fn decode_header_name(field: &[u8]) -> String {
    let bytes = c_str(field);
    match bytes.split_first() {
        Some((1, utf8)) => match std::str::from_utf8(utf8) {
            Ok(text) => text.to_owned(),
            Err(_) => decode_ansi(utf8),
        },
        _ => decode_ansi(bytes),
    }
}

/// Reads and checks the 448-byte header: id string, CRC, version gate, record count, end offset.
pub(super) fn read_header(bytes: &[u8]) -> Result<RawHeader, InnoLogError> {
    let too_short = InnoLogError::TooShort { len: bytes.len() };
    let Some(head) = bytes.get(..HEADER_SIZE) else {
        return Err(too_short);
    };

    let id = c_str(&head[..ID_FIELD]);
    let is_64bit = match id.strip_prefix(ID) {
        Some([]) => false,
        Some(rest) if rest == ID_64BIT_SUFFIX => true,
        _ => return Err(InnoLogError::BadId),
    };

    let field = |offset: usize| u32_at(head, offset).ok_or(too_short.clone());
    let stored = field(HEADER_CRC_OFFSET)?;
    let computed = crc32(&head[..HEADER_CRC_OFFSET]);
    if stored != computed {
        return Err(InnoLogError::HeaderCrc { stored, computed });
    }

    let numbers = ID_FIELD + 2 * NAME_FIELD;
    let version = i32::from_le_bytes(field(numbers)?.to_le_bytes());
    if !(1..=MAX_SUPPORTED_VERSION).contains(&version) {
        return Err(InnoLogError::Unsupported { version });
    }
    let num_recs = i32::from_le_bytes(field(numbers + 4)?.to_le_bytes());
    let end_offset = field(numbers + 8)?;
    let header_flags = field(numbers + 12)?;

    let num_recs =
        usize::try_from(num_recs).map_err(|_| InnoLogError::BadRecordCount { num_recs })?;
    let bad_end = InnoLogError::BadEndOffset {
        end_offset,
        len: bytes.len(),
    };
    let end = usize::try_from(end_offset).map_err(|_| bad_end.clone())?;
    if end < HEADER_SIZE || end > bytes.len() {
        return Err(bad_end);
    }

    Ok(RawHeader {
        header: LogHeader {
            is_64bit,
            app_id: decode_header_name(&head[ID_FIELD..ID_FIELD + NAME_FIELD]),
            app_name: decode_header_name(&head[ID_FIELD + NAME_FIELD..numbers]),
            version,
            flags: header_flags,
        },
        num_recs,
        end_offset: end,
    })
}

/// Reads the blocks between the header and the end offset and returns their bytes, concatenated.
///
/// Block CRCs are checked unless the header says they are not to be ([`flags::HEADER_DONT_CHECK_REC_CRCS`]).
pub(super) fn read_stream(
    bytes: &[u8],
    header: &RawHeader,
    limit: usize,
) -> Result<Vec<u8>, InnoLogError> {
    // `read_header` checked the range; `get` keeps this function safe on its own.
    let body = bytes
        .get(..header.end_offset)
        .ok_or(InnoLogError::TruncatedBlock {
            offset: HEADER_SIZE,
        })?;
    let check_crc = header.header.flags & flags::HEADER_DONT_CHECK_REC_CRCS == 0;

    let mut stream = Vec::new();
    let mut offset = HEADER_SIZE;
    while offset < body.len() {
        let truncated = InnoLogError::TruncatedBlock { offset };
        let size = u32_at(body, offset).ok_or(truncated.clone())?;
        let not_size = u32_at(body, offset + 4).ok_or(truncated.clone())?;
        let stored = u32_at(body, offset + 8).ok_or(truncated.clone())?;
        if not_size != !size {
            return Err(InnoLogError::NotSizeMismatch {
                offset,
                size,
                not_size,
            });
        }
        let len = match usize::try_from(size) {
            Ok(len) if len <= MAX_BLOCK_SIZE => len,
            _ => return Err(InnoLogError::BlockTooLarge { offset, size }),
        };
        let start = offset + BLOCK_HEADER_SIZE;
        let data = body.get(start..start + len).ok_or(truncated)?;
        if check_crc {
            let computed = crc32(data);
            if stored != computed {
                return Err(InnoLogError::BlockCrc {
                    offset,
                    stored,
                    computed,
                });
            }
        }
        if stream.len() + len > limit {
            return Err(InnoLogError::TooLarge { limit });
        }
        stream.extend_from_slice(data);
        offset = start + len;
    }
    Ok(stream)
}

/// Splits the stream into `num_recs` raw records. Returns them and the number of bytes left over.
pub(super) fn read_records(
    stream: &[u8],
    num_recs: usize,
) -> Result<(Vec<RawRecord<'_>>, usize), InnoLogError> {
    // The header's count is not trusted for the allocation: a record takes at least its header.
    let mut records = Vec::with_capacity(num_recs.min(stream.len() / RECORD_HEADER_SIZE));
    let mut offset = 0usize;
    for index in 0..num_recs {
        let truncated = InnoLogError::TruncatedRecord { index };
        let typ = u16_at(stream, offset).ok_or(truncated.clone())?;
        let extra_data = u32_at(stream, offset + 2).ok_or(truncated.clone())?;
        let data_size = u32_at(stream, offset + 6).ok_or(truncated.clone())?;
        let start = offset + RECORD_HEADER_SIZE;
        let data = usize::try_from(data_size)
            .ok()
            .and_then(|len| start.checked_add(len))
            .and_then(|end| stream.get(start..end))
            .ok_or(truncated)?;
        records.push(RawRecord {
            typ,
            extra_data,
            data,
        });
        offset = start + data.len();
    }
    Ok((records, stream.len() - offset))
}

/// Decodes a record's packed string list.
///
/// Empty data is an empty list. Otherwise the list must end with the `0xFF` marker as the data's last
/// byte.
pub(super) fn read_strings(index: usize, data: &[u8]) -> Result<Vec<String>, InnoLogError> {
    let bad = |reason| InnoLogError::BadString { index, reason };
    let mut strings = Vec::new();
    let mut rest = data;
    while let Some((&marker, after)) = rest.split_first() {
        rest = after;
        // (length in bytes, UTF-16?)
        let (length, wide): (u64, bool) = match marker {
            0xFF => {
                return if rest.is_empty() {
                    Ok(strings)
                } else {
                    Err(bad("bytes after the end marker"))
                };
            }
            0xFE => {
                let raw = u32_at(rest, 0).ok_or(bad("length field cut short"))?;
                let raw = i32::from_le_bytes(raw.to_le_bytes());
                rest = &rest[4..];
                (u64::from(raw.unsigned_abs()), raw < 0)
            }
            0xFD => {
                let raw = u16_at(rest, 0).ok_or(bad("length field cut short"))?;
                rest = &rest[2..];
                (u64::from(raw), false)
            }
            literal => (u64::from(literal), false),
        };
        let oversized = InnoLogError::OversizedLength {
            index,
            length,
            available: rest.len(),
        };
        let Ok(len) = usize::try_from(length) else {
            return Err(oversized);
        };
        if len > rest.len() {
            return Err(oversized);
        }
        let (text, after) = rest.split_at(len);
        rest = after;
        strings.push(if wide {
            if len % 2 != 0 {
                return Err(bad("odd UTF-16 byte count"));
            }
            // Pairs of bytes; `chunks` never yields an empty slice and `len` is even.
            let units: Vec<u16> = text
                .chunks(2)
                .filter_map(|pair| Some(u16::from_le_bytes([*pair.first()?, *pair.get(1)?])))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            decode_ansi(text)
        });
    }
    if data.is_empty() {
        Ok(strings)
    } else {
        Err(bad("no end marker"))
    }
}
