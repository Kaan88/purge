//! Test-only writer of synthetic uninstall logs, the inverse of the parser.
//!
//! It follows the same published format description as the reader and exists so that tests can state
//! `parse(write(x)) == x` and build deliberately broken logs.

use super::reader::{HEADER_CRC_OFFSET, ID, ID_64BIT_SUFFIX, ID_FIELD, NAME_FIELD, crc32};
use super::{HEADER_SIZE, LogHeader, LogOp, LogRecord, MAX_BLOCK_SIZE, UninstallLog};

/// How strings are encoded and how the stream is cut into blocks.
#[derive(Debug, Clone, Copy)]
pub(super) struct WriteOptions {
    /// UTF-16LE strings (`0xFE` with a negative length) instead of single-byte ones.
    pub utf16: bool,
    /// Data bytes per block (the last block may be shorter).
    pub block_size: usize,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            utf16: true,
            block_size: MAX_BLOCK_SIZE,
        }
    }
}

/// A record as it goes into the stream: type, `ExtraData`, data bytes.
pub(super) type RawRec = (u16, u32, Vec<u8>);

/// Encodes one string with its length marker.
pub(super) fn encode_string(text: &str, utf16: bool, out: &mut Vec<u8>) {
    if utf16 {
        let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        out.push(0xFE);
        out.extend_from_slice(&(-i32::try_from(bytes.len()).unwrap()).to_le_bytes());
        out.extend_from_slice(&bytes);
    } else {
        // Latin-1, the reader's single-byte decoding.
        let bytes: Vec<u8> = text
            .chars()
            .map(|c| u8::try_from(u32::from(c)).expect("ANSI test strings are Latin-1"))
            .collect();
        match bytes.len() {
            len @ 0..=0xFC => out.push(u8::try_from(len).unwrap()),
            len @ 0xFD..=0xFFFF => {
                out.push(0xFD);
                out.extend_from_slice(&u16::try_from(len).unwrap().to_le_bytes());
            }
            len => {
                out.push(0xFE);
                out.extend_from_slice(&i32::try_from(len).unwrap().to_le_bytes());
            }
        }
        out.extend_from_slice(&bytes);
    }
}

/// Encodes a string list with its end marker.
pub(super) fn encode_strings(strings: &[&str], utf16: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for text in strings {
        encode_string(text, utf16, &mut out);
    }
    out.push(0xFF);
    out
}

/// The strings of a typed record, in file order.
fn strings_of(record: &LogRecord) -> Vec<&str> {
    let mut strings: Vec<&str> = match &record.op {
        LogOp::Run {
            filename,
            parameters,
            working_dir,
            run_once_id,
            verb,
        } => vec![filename, parameters, working_dir, run_once_id, verb],
        LogOp::DeleteDirOrFiles { path }
        | LogOp::DeleteFile { path }
        | LogOp::DeleteGroupOrItem { path }
        | LogOp::DecrementSharedCount { path } => vec![path],
        LogOp::IniDeleteEntry {
            file,
            section,
            entry,
        } => vec![file, section, entry],
        LogOp::IniDeleteSection { file, section } => vec![file, section],
        LogOp::RegDeleteEntireKey { subkey, .. } | LogOp::RegDeleteKeyIfEmpty { subkey, .. } => {
            vec![subkey]
        }
        LogOp::RegClearValue { subkey, value, .. }
        | LogOp::RegDeleteValue { subkey, value, .. } => {
            vec![subkey, value]
        }
        LogOp::MutexCheck { names } => vec![names],
        LogOp::StartInstall {
            computer_name,
            user_name,
            app_dir,
        } => vec![computer_name, user_name, app_dir],
        LogOp::EndInstall
        | LogOp::RefreshFileAssoc
        | LogOp::CompiledCode { .. }
        | LogOp::Raw { .. } => Vec::new(),
    }
    .into_iter()
    .map(String::as_str)
    .collect();
    strings.extend(record.trailing.iter().map(String::as_str));
    strings
}

/// Encodes typed records as raw records.
pub(super) fn encode_records(records: &[LogRecord], utf16: bool) -> Vec<RawRec> {
    records
        .iter()
        .map(|record| {
            let data = match &record.op {
                LogOp::Raw { data, .. } | LogOp::CompiledCode { data } => data.clone(),
                _ => encode_strings(&strings_of(record), utf16),
            };
            (record.op.type_code(), record.extra_data, data)
        })
        .collect()
}

/// Concatenates raw records into the record stream.
pub(super) fn stream_of(records: &[RawRec]) -> Vec<u8> {
    let mut stream = Vec::new();
    for (typ, extra_data, data) in records {
        stream.extend_from_slice(&typ.to_le_bytes());
        stream.extend_from_slice(&extra_data.to_le_bytes());
        stream.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        stream.extend_from_slice(data);
    }
    stream
}

/// Recomputes the header CRC after a test changed header bytes.
pub(super) fn seal_header(bytes: &mut [u8]) {
    let crc = crc32(&bytes[..HEADER_CRC_OFFSET]);
    bytes[HEADER_CRC_OFFSET..HEADER_SIZE].copy_from_slice(&crc.to_le_bytes());
}

/// Offset of the header's `Version` field; `NumRecs`, `EndOffset` and `Flags` follow, 4 bytes each.
pub(super) const VERSION_OFFSET: usize = ID_FIELD + 2 * NAME_FIELD;

/// Writes a whole log file from a header, a record count and a record stream.
pub(super) fn write_file(
    header: &LogHeader,
    num_recs: i32,
    stream: &[u8],
    block_size: usize,
) -> Vec<u8> {
    assert!((1..=MAX_BLOCK_SIZE).contains(&block_size));
    let mut out = vec![0u8; HEADER_SIZE];
    let mut id = ID.to_vec();
    if header.is_64bit {
        id.extend_from_slice(ID_64BIT_SUFFIX);
    }
    out[..id.len()].copy_from_slice(&id);
    let mut put_name = |offset: usize, text: &str| {
        // A name with non-ASCII characters is stored as 0x01 followed by UTF-8.
        let mut bytes = Vec::new();
        if !text.is_ascii() {
            bytes.push(1);
        }
        bytes.extend_from_slice(text.as_bytes());
        assert!(bytes.len() < NAME_FIELD);
        out[offset..offset + bytes.len()].copy_from_slice(&bytes);
    };
    put_name(ID_FIELD, &header.app_id);
    put_name(ID_FIELD + NAME_FIELD, &header.app_name);

    for chunk in stream.chunks(block_size) {
        let size = u32::try_from(chunk.len()).unwrap();
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(!size).to_le_bytes());
        out.extend_from_slice(&crc32(chunk).to_le_bytes());
        out.extend_from_slice(chunk);
    }

    let end_offset = u32::try_from(out.len()).unwrap();
    out[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&header.version.to_le_bytes());
    out[VERSION_OFFSET + 4..VERSION_OFFSET + 8].copy_from_slice(&num_recs.to_le_bytes());
    out[VERSION_OFFSET + 8..VERSION_OFFSET + 12].copy_from_slice(&end_offset.to_le_bytes());
    out[VERSION_OFFSET + 12..VERSION_OFFSET + 16].copy_from_slice(&header.flags.to_le_bytes());
    seal_header(&mut out);
    out
}

/// Writes a log from raw records.
pub(super) fn write_raw(header: &LogHeader, records: &[RawRec], block_size: usize) -> Vec<u8> {
    write_file(
        header,
        i32::try_from(records.len()).unwrap(),
        &stream_of(records),
        block_size,
    )
}

/// Writes a parsed log back to bytes.
pub(super) fn write(log: &UninstallLog, options: WriteOptions) -> Vec<u8> {
    write_raw(
        &log.header,
        &encode_records(&log.records, options.utf16),
        options.block_size,
    )
}
