//! Tests of the uninstall-log parser on synthetic logs, plus an ignored test for real logs.

use std::collections::BTreeMap;

use purge_model::{InnoRecordKind, Target, TypedTarget, View};

use super::reader::{BLOCK_HEADER_SIZE, HEADER_CRC_OFFSET};
use super::writer::{
    VERSION_OFFSET, WriteOptions, encode_records, encode_strings, seal_header, stream_of, write,
    write_file, write_raw,
};
use super::{
    HEADER_SIZE, InnoLogError, LogHeader, LogOp, LogRecord, MAX_BLOCK_SIZE, MAX_SUPPORTED_VERSION,
    RegRoot, UninstallLog, flags, parse, parse_with_limit,
};

const HKCR: u32 = 0x8000_0000;
const HKCU: u32 = 0x8000_0001;
const HKLM: u32 = 0x8000_0002;
const HKU: u32 = 0x8000_0003;
const HKCC: u32 = 0x8000_0005;

fn header(version: i32) -> LogHeader {
    LogHeader {
        is_64bit: false,
        app_id: "{0A1B2C3D-0000-4000-8000-00000000ABCD}".to_owned(),
        app_name: "Sample App".to_owned(),
        version,
        flags: flags::HEADER_ADMIN_INSTALL_MODE | flags::HEADER_WIN64,
    }
}

fn rec(extra_data: u32, op: LogOp) -> LogRecord {
    LogRecord {
        extra_data,
        op,
        trailing: Vec::new(),
    }
}

fn s(text: &str) -> String {
    text.to_owned()
}

/// One record of each known type (three bookkeeping types, thirteen uninstall steps), with a mix of
/// roots, views and flags.
fn sample_records() -> Vec<LogRecord> {
    vec![
        LogRecord {
            extra_data: 0,
            op: LogOp::StartInstall {
                computer_name: s("SAMPLE-PC"),
                user_name: s("sample"),
                app_dir: s(r"C:\Program Files\Sample"),
            },
            trailing: vec![s("\u{ea}\u{9}\u{3}\u{9}")],
        },
        rec(
            0x0700_0200,
            LogOp::CompiledCode {
                data: vec![
                    0xFE, 0x3E, 0x83, 0xFC, 0xFF, b'I', b'F', b'P', b'S', 0x17, 0, 0xFF,
                ],
            },
        ),
        rec(
            flags::RUN_HIDDEN | flags::RUN_SKIP_IF_DOESNT_EXIST,
            LogOp::Run {
                filename: s(r"C:\Program Files\Sample\tool.exe"),
                parameters: s("/unregister"),
                working_dir: s(r"C:\Program Files\Sample"),
                run_once_id: s("unreg"),
                verb: s(""),
            },
        ),
        rec(
            flags::DIR_IS_DIR,
            LogOp::DeleteDirOrFiles {
                path: s(r"C:\Program Files\Sample"),
            },
        ),
        rec(
            flags::DIR_EXTRA | flags::DIR_DELETE_FILES | flags::DIR_DELETE_SUBDIRS_ALSO,
            LogOp::DeleteDirOrFiles {
                path: s(r"C:\Program Files\Sample\cache"),
            },
        ),
        rec(
            flags::FILE_SHARED_FILE | flags::FILE_REGISTERED_SERVER | flags::FILE_DISABLE_FS_REDIR,
            LogOp::DeleteFile {
                path: s(r"C:\Program Files\Sample\sample.dll"),
            },
        ),
        LogRecord {
            extra_data: flags::FILE_EXISTED_BEFORE_INSTALL | flags::FILE_IS_FONT,
            op: LogOp::DeleteFile {
                path: s(r"C:\Windows\Fonts\sample.ttf"),
            },
            trailing: vec![s("Sample Font (TrueType)"), s("sample.ttf")],
        },
        rec(
            0,
            LogOp::DeleteGroupOrItem {
                path: s(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Sample"),
            },
        ),
        rec(
            0,
            LogOp::IniDeleteEntry {
                file: s(r"C:\Program Files\Sample\sample.ini"),
                section: s("Settings"),
                entry: s("Language"),
            },
        ),
        rec(
            flags::INI_SECTION_ONLY_IF_EMPTY,
            LogOp::IniDeleteSection {
                file: s(r"C:\Program Files\Sample\sample.ini"),
                section: s("Settings"),
            },
        ),
        rec(
            HKLM | flags::REG_64BIT_KEY,
            LogOp::RegDeleteEntireKey {
                root: RegRoot::LocalMachine,
                subkey: s(r"SOFTWARE\Classes\SampleFile"),
            },
        ),
        rec(
            HKCU,
            LogOp::RegClearValue {
                root: RegRoot::CurrentUser,
                subkey: s(r"Software\Sample"),
                value: s("LastRun"),
            },
        ),
        rec(
            HKLM,
            LogOp::RegDeleteKeyIfEmpty {
                root: RegRoot::LocalMachine,
                subkey: s(r"SOFTWARE\Sample Vendor"),
            },
        ),
        rec(
            HKCU | flags::REG_64BIT_KEY,
            LogOp::RegDeleteValue {
                root: RegRoot::CurrentUser,
                subkey: s(r"Software\Classes\.smp\OpenWithProgids"),
                value: s("SampleFile"),
            },
        ),
        rec(
            flags::SHARED_COUNT_64BIT_KEY,
            LogOp::DecrementSharedCount {
                path: s(r"C:\Program Files\Common Files\Sample\shared.dll"),
            },
        ),
        rec(0, LogOp::RefreshFileAssoc),
        rec(
            0,
            LogOp::MutexCheck {
                names: s("SampleAppMutex,Global\\SampleAppMutex"),
            },
        ),
        LogRecord {
            extra_data: 0,
            op: LogOp::EndInstall,
            trailing: vec![s("\u{ea}\u{9}\u{3}\u{9}")],
        },
    ]
}

fn sample_log(version: i32) -> UninstallLog {
    UninstallLog {
        header: header(version),
        records: sample_records(),
        warnings: Vec::new(),
    }
}

/// Deterministic xorshift64* generator for the bit-flip sweep.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

#[test]
fn round_trip_all_types_utf16_and_ansi_across_versions() {
    for version in [1, 33, 48, 1000, 1048, 1049, MAX_SUPPORTED_VERSION] {
        for utf16 in [true, false] {
            for is_64bit in [false, true] {
                let mut log = sample_log(version);
                log.header.is_64bit = is_64bit;
                let bytes = write(
                    &log,
                    WriteOptions {
                        utf16,
                        ..WriteOptions::default()
                    },
                );
                assert_eq!(parse(&bytes), Ok(log), "version {version}, utf16 {utf16}");
            }
        }
    }
}

#[test]
fn sample_covers_every_known_type() {
    let codes: Vec<u16> = sample_records().iter().map(|r| r.op.type_code()).collect();
    for code in (0x80..=0x8C).chain([0x10, 0x11, 0x20]) {
        assert!(
            codes.contains(&code),
            "type {code:#x} missing from the sample"
        );
    }
}

#[test]
fn non_ascii_strings_round_trip() {
    let mut log = sample_log(1048);
    log.records = vec![rec(
        0,
        LogOp::DeleteFile {
            path: s("C:\\Users\\Zoë\\AppData\\Local\\Пример\\日本語😀.txt"),
        },
    )];
    assert_eq!(
        parse(&write(&log, WriteOptions::default())),
        Ok(log.clone())
    );

    // Single-byte strings are read as Latin-1.
    log.records = vec![rec(
        0,
        LogOp::DeleteFile {
            path: s("C:\\Users\\Zoë\\café.txt"),
        },
    )];
    let ansi = WriteOptions {
        utf16: false,
        ..WriteOptions::default()
    };
    assert_eq!(parse(&write(&log, ansi)), Ok(log));
}

#[test]
fn all_three_length_markers_decode() {
    let short = "a".repeat(0xFC);
    let medium = "b".repeat(0xFD);
    let long = "c".repeat(0x1_0000);
    let mut log = sample_log(1048);
    log.records = vec![LogRecord {
        extra_data: 0,
        op: LogOp::DeleteFile { path: short },
        trailing: vec![medium, long, String::new()],
    }];
    let ansi = WriteOptions {
        utf16: false,
        ..WriteOptions::default()
    };
    let bytes = write(&log, ansi);
    assert_eq!(parse(&bytes), Ok(log));
}

#[test]
fn records_span_block_boundaries() {
    let log = sample_log(1048);
    let whole = write(&log, WriteOptions::default());
    // Block sizes that cut record headers, length fields and string bodies at every position.
    for block_size in [1, 2, 3, 7, 10, 11, 64, 257, MAX_BLOCK_SIZE] {
        let bytes = write(
            &log,
            WriteOptions {
                utf16: true,
                block_size,
            },
        );
        assert_eq!(parse(&bytes), Ok(log.clone()), "block size {block_size}");
    }
    // The sample is larger than one small block, so the cases above did span blocks.
    assert!(whole.len() > HEADER_SIZE + 2 * 257);

    // A single record larger than a full block.
    let mut big = sample_log(1048);
    big.records = vec![rec(
        0,
        LogOp::DeleteFile {
            path: "x".repeat(3 * MAX_BLOCK_SIZE),
        },
    )];
    let bytes = write(&big, WriteOptions::default());
    assert_eq!(parse(&bytes), Ok(big));
}

#[test]
fn empty_log_parses() {
    let mut log = sample_log(1048);
    log.records.clear();
    let bytes = write(&log, WriteOptions::default());
    assert_eq!(bytes.len(), HEADER_SIZE);
    assert_eq!(parse(&bytes), Ok(log));
}

#[test]
fn flags_and_views_are_surfaced() {
    let log = sample_log(1048);
    let by_code = |code: u16, nth: usize| {
        log.records
            .iter()
            .filter(|r| r.op.type_code() == code)
            .nth(nth)
            .unwrap()
    };
    let dll = by_code(0x82, 0);
    assert!(dll.shared_file() && dll.registered_server() && dll.fs_redirection_disabled());
    assert!(!dll.existed_before_install());
    let font = by_code(0x82, 1);
    assert!(font.existed_before_install() && !font.shared_file() && !font.registered_server());
    assert_eq!(font.extra_data & flags::FILE_IS_FONT, flags::FILE_IS_FONT);

    assert_eq!(by_code(0x86, 0).reg_view(), Some(View::K64));
    assert_eq!(by_code(0x87, 0).reg_view(), Some(View::K32));
    assert_eq!(by_code(0x88, 0).reg_view(), Some(View::K32));
    assert_eq!(by_code(0x89, 0).reg_view(), Some(View::K64));
    assert_eq!(by_code(0x82, 0).reg_view(), None);
    // File flag bits mean something else on other record types.
    assert!(!by_code(0x81, 0).shared_file());
    assert!(!by_code(0x80, 0).fs_redirection_disabled());

    assert!(log.header.is_admin_install());
    assert_eq!(
        RegRoot::from_extra_data(HKCC | flags::REG_64BIT_KEY),
        RegRoot::CurrentConfig
    );
    for root in [HKCR, HKCU, HKLM, HKU, HKCC, 0x8000_0050] {
        assert_eq!(RegRoot::from_extra_data(root).handle(), root);
    }
}

#[test]
fn unknown_type_is_kept_raw_with_a_warning() {
    let records = vec![
        (0x82, 0, encode_strings(&[r"C:\a.txt"], true)),
        (0x8D, 7, vec![1, 2, 3, 0xFE]),
        (0x0001, 0, Vec::new()),
    ];
    let log = parse(&write_raw(&header(1048), &records, MAX_BLOCK_SIZE)).unwrap();
    assert_eq!(log.records.len(), 3);
    assert_eq!(
        log.records[1],
        rec(
            7,
            LogOp::Raw {
                typ: 0x8D,
                data: vec![1, 2, 3, 0xFE],
            }
        )
    );
    assert_eq!(log.raw_count(), 2);
    assert_eq!(log.warnings.len(), 2);
    assert!(log.warnings[0].contains("0x008d"), "{:?}", log.warnings);
    // Raw records round-trip too, and never reach the model.
    let again = parse(&write(&log, WriteOptions::default())).unwrap();
    assert_eq!(again, log);
    assert_eq!(log.model_records().len(), 1);
}

#[test]
fn missing_optional_strings_read_as_empty() {
    // An old-style Run record with only a file name, and a record with no data at all.
    let records = vec![
        (0x80, 0, encode_strings(&[r"C:\a.exe"], false)),
        (0x8B, 0, Vec::new()),
    ];
    let log = parse(&write_raw(&header(48), &records, MAX_BLOCK_SIZE)).unwrap();
    assert_eq!(
        log.records[0].op,
        LogOp::Run {
            filename: s(r"C:\a.exe"),
            parameters: s(""),
            working_dir: s(""),
            run_once_id: s(""),
            verb: s(""),
        }
    );
    assert_eq!(log.records[1].op, LogOp::RefreshFileAssoc);
    assert!(log.warnings.is_empty());
}

#[test]
fn bytes_after_the_last_record_are_a_warning() {
    let mut stream = stream_of(&encode_records(&sample_records(), true));
    stream.extend_from_slice(&[0u8; 5]);
    let count = i32::try_from(sample_records().len()).unwrap();
    let log = parse(&write_file(&header(1048), count, &stream, 100)).unwrap();
    assert_eq!(log.records, sample_records());
    assert_eq!(log.warnings.len(), 1);
    assert!(log.warnings[0].starts_with("5 bytes follow"));
}

// ---- errors ----

fn sample_bytes() -> Vec<u8> {
    write(
        &sample_log(1048),
        WriteOptions {
            utf16: true,
            block_size: 200,
        },
    )
}

#[test]
fn version_above_the_gate_is_unsupported() {
    for version in [MAX_SUPPORTED_VERSION + 1, 2000, i32::MAX, 0, -1] {
        let bytes = write(&sample_log(version), WriteOptions::default());
        assert_eq!(parse(&bytes), Err(InnoLogError::Unsupported { version }));
    }
    let at_gate = write(&sample_log(MAX_SUPPORTED_VERSION), WriteOptions::default());
    assert!(parse(&at_gate).is_ok());
}

#[test]
fn short_file_and_wrong_id() {
    assert_eq!(parse(&[]), Err(InnoLogError::TooShort { len: 0 }));
    let bytes = sample_bytes();
    assert_eq!(
        parse(&bytes[..HEADER_SIZE - 1]),
        Err(InnoLogError::TooShort {
            len: HEADER_SIZE - 1
        })
    );
    let mut wrong = bytes.clone();
    wrong[0] = b'i';
    seal_header(&mut wrong);
    assert_eq!(parse(&wrong), Err(InnoLogError::BadId));
    // Text after the id that is not the 64-bit marker.
    let mut wrong = bytes;
    wrong[28] = b'!';
    seal_header(&mut wrong);
    assert_eq!(parse(&wrong), Err(InnoLogError::BadId));
}

#[test]
fn corrupt_header_crc() {
    let mut bytes = sample_bytes();
    bytes[70] ^= 0x01; // inside AppId
    assert!(matches!(parse(&bytes), Err(InnoLogError::HeaderCrc { .. })));
    let mut bytes = sample_bytes();
    bytes[HEADER_CRC_OFFSET] ^= 0x80;
    assert!(matches!(parse(&bytes), Err(InnoLogError::HeaderCrc { .. })));
}

#[test]
fn corrupt_block_crc() {
    let clean = sample_bytes();
    // A data byte of the first block.
    let mut bytes = clean.clone();
    bytes[HEADER_SIZE + BLOCK_HEADER_SIZE + 3] ^= 0x10;
    assert!(matches!(
        parse(&bytes),
        Err(InnoLogError::BlockCrc {
            offset: HEADER_SIZE,
            ..
        })
    ));
    // The stored CRC of the second block.
    let second = HEADER_SIZE + BLOCK_HEADER_SIZE + 200;
    let mut bytes = clean.clone();
    bytes[second + 8] ^= 0x01;
    assert_eq!(
        parse(&bytes).unwrap_err(),
        InnoLogError::BlockCrc {
            offset: second,
            stored: u32::from_le_bytes(bytes[second + 8..second + 12].try_into().unwrap()),
            computed: u32::from_le_bytes(clean[second + 8..second + 12].try_into().unwrap()),
        }
    );
    // With the header flag that turns block CRC checks off, the same damage is not looked at.
    let flags_at = VERSION_OFFSET + 12;
    bytes[flags_at] |= u8::try_from(flags::HEADER_DONT_CHECK_REC_CRCS).unwrap();
    seal_header(&mut bytes);
    assert_eq!(parse(&bytes).unwrap().records, sample_records());
}

#[test]
fn not_size_mismatch() {
    let mut bytes = sample_bytes();
    bytes[HEADER_SIZE + 4] ^= 0x01;
    assert_eq!(
        parse(&bytes),
        Err(InnoLogError::NotSizeMismatch {
            offset: HEADER_SIZE,
            size: 200,
            not_size: !200u32 ^ 1,
        })
    );
}

#[test]
fn block_larger_than_the_maximum() {
    let mut bytes = sample_bytes();
    let size = u32::try_from(MAX_BLOCK_SIZE + 1).unwrap();
    bytes[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&size.to_le_bytes());
    bytes[HEADER_SIZE + 4..HEADER_SIZE + 8].copy_from_slice(&(!size).to_le_bytes());
    assert_eq!(
        parse(&bytes),
        Err(InnoLogError::BlockTooLarge {
            offset: HEADER_SIZE,
            size,
        })
    );
}

/// Cuts a log to `len` bytes and makes the header agree with the new length.
fn cut_and_seal(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut cut = bytes[..len].to_vec();
    let end = u32::try_from(len).unwrap();
    cut[VERSION_OFFSET + 8..VERSION_OFFSET + 12].copy_from_slice(&end.to_le_bytes());
    seal_header(&mut cut);
    cut
}

#[test]
fn truncated_block() {
    let bytes = sample_bytes();
    let last_block = HEADER_SIZE + ((bytes.len() - HEADER_SIZE - 1) / 212) * 212;

    // Plain truncation: the header's end offset now lies beyond the file.
    assert_eq!(
        parse(&bytes[..bytes.len() - 1]),
        Err(InnoLogError::BadEndOffset {
            end_offset: u32::try_from(bytes.len()).unwrap(),
            len: bytes.len() - 1,
        })
    );
    // The end offset agrees with the file, but the last block's data is cut short.
    assert_eq!(
        parse(&cut_and_seal(&bytes, bytes.len() - 1)),
        Err(InnoLogError::TruncatedBlock { offset: last_block })
    );
    // Cut inside a block header.
    assert_eq!(
        parse(&cut_and_seal(&bytes, HEADER_SIZE + 212 + 5)),
        Err(InnoLogError::TruncatedBlock {
            offset: HEADER_SIZE + 212
        })
    );
    // An end offset inside the header.
    let mut inside = bytes.clone();
    inside[VERSION_OFFSET + 8..VERSION_OFFSET + 12].copy_from_slice(&100u32.to_le_bytes());
    seal_header(&mut inside);
    assert!(matches!(
        parse(&inside),
        Err(InnoLogError::BadEndOffset {
            end_offset: 100,
            ..
        })
    ));
}

#[test]
fn truncated_record_stream() {
    // A whole block removed: blocks are consistent, but the stream ends inside a record.
    let bytes = sample_bytes();
    let whole_blocks = HEADER_SIZE + 2 * 212;
    assert!(whole_blocks < bytes.len());
    let err = parse(&cut_and_seal(&bytes, whole_blocks)).unwrap_err();
    assert!(
        matches!(err, InnoLogError::TruncatedRecord { .. }),
        "{err:?}"
    );

    // The header counts one record more than the stream holds.
    let stream = stream_of(&encode_records(&sample_records(), true));
    let count = i32::try_from(sample_records().len()).unwrap();
    assert_eq!(
        parse(&write_file(&header(1048), count + 1, &stream, 500)),
        Err(InnoLogError::TruncatedRecord {
            index: sample_records().len()
        })
    );
    // A record whose DataSize runs past the stream.
    let mut stream = Vec::new();
    stream.extend_from_slice(&0x82u16.to_le_bytes());
    stream.extend_from_slice(&0u32.to_le_bytes());
    stream.extend_from_slice(&u32::MAX.to_le_bytes());
    stream.extend_from_slice(&[0xFF; 20]);
    assert_eq!(
        parse(&write_file(&header(1048), 1, &stream, 500)),
        Err(InnoLogError::TruncatedRecord { index: 0 })
    );
    // A negative record count.
    assert_eq!(
        parse(&write_file(&header(1048), -1, &[], 500)),
        Err(InnoLogError::BadRecordCount { num_recs: -1 })
    );
    // A huge record count does not allocate for it.
    assert_eq!(
        parse(&write_file(&header(1048), i32::MAX, &[], 500)),
        Err(InnoLogError::TruncatedRecord { index: 0 })
    );
}

#[test]
fn oversized_string_lengths() {
    let parse_data = |data: Vec<u8>| {
        parse(&write_raw(
            &header(1048),
            &[(0x81, 0, encode_strings(&["ok"], true)), (0x82, 0, data)],
            MAX_BLOCK_SIZE,
        ))
    };
    // One-byte length beyond the data.
    assert_eq!(
        parse_data(vec![5, b'a', b'b', 0xFF]),
        Err(InnoLogError::OversizedLength {
            index: 1,
            length: 5,
            available: 3,
        })
    );
    // 16-bit length beyond the data.
    assert_eq!(
        parse_data(vec![0xFD, 0xFF, 0xFF, b'a', 0xFF]),
        Err(InnoLogError::OversizedLength {
            index: 1,
            length: 0xFFFF,
            available: 2,
        })
    );
    // 32-bit ANSI length beyond the data.
    let mut data = vec![0xFE];
    data.extend_from_slice(&i32::MAX.to_le_bytes());
    data.push(0xFF);
    assert_eq!(
        parse_data(data),
        Err(InnoLogError::OversizedLength {
            index: 1,
            length: 0x7FFF_FFFF,
            available: 1,
        })
    );
    // UTF-16 lengths beyond the data, including the most negative value.
    for raw in [-6i32, i32::MIN] {
        let mut data = vec![0xFE];
        data.extend_from_slice(&raw.to_le_bytes());
        data.extend_from_slice(&[b'a', 0, 0xFF]);
        assert_eq!(
            parse_data(data),
            Err(InnoLogError::OversizedLength {
                index: 1,
                length: u64::from(raw.unsigned_abs()),
                available: 3,
            })
        );
    }
}

#[test]
fn malformed_string_lists() {
    let parse_data = |typ: u16, data: Vec<u8>| {
        parse(&write_raw(&header(1048), &[(typ, 0, data)], MAX_BLOCK_SIZE))
    };
    let bad = |reason| Err(InnoLogError::BadString { index: 0, reason });
    assert_eq!(parse_data(0x82, vec![1, b'a']), bad("no end marker"));
    assert_eq!(
        parse_data(0x82, vec![1, b'a', 0xFF, 0]),
        bad("bytes after the end marker")
    );
    assert_eq!(
        parse_data(0x82, vec![0xFD, 1]),
        bad("length field cut short")
    );
    assert_eq!(
        parse_data(0x82, vec![0xFE, 1, 0, 0]),
        bad("length field cut short")
    );
    let mut odd = vec![0xFE];
    odd.extend_from_slice(&(-3i32).to_le_bytes());
    odd.extend_from_slice(&[b'a', 0, b'b', 0xFF]);
    assert_eq!(parse_data(0x82, odd), bad("odd UTF-16 byte count"));

    // Too few strings for the type.
    assert_eq!(
        parse_data(0x89, encode_strings(&["Software\\X"], true)),
        Err(InnoLogError::MissingField {
            index: 0,
            typ: 0x89,
            needed: 2,
            found: 1,
        })
    );
    assert_eq!(
        parse_data(0x82, Vec::new()),
        Err(InnoLogError::MissingField {
            index: 0,
            typ: 0x82,
            needed: 1,
            found: 0,
        })
    );
    // An unpaired surrogate is replaced, not an error.
    let mut lone = vec![0xFE];
    lone.extend_from_slice(&(-4i32).to_le_bytes());
    lone.extend_from_slice(&[0x00, 0xD8, b'a', 0, 0xFF]);
    let log = parse_data(0x82, lone).unwrap();
    assert_eq!(
        log.records[0].op,
        LogOp::DeleteFile {
            path: s("\u{FFFD}a")
        }
    );
}

#[test]
fn decoded_size_is_capped() {
    let bytes = sample_bytes();
    let stream_len = stream_of(&encode_records(&sample_records(), true)).len();
    assert!(parse_with_limit(&bytes, stream_len).is_ok());
    assert_eq!(
        parse_with_limit(&bytes, stream_len - 1),
        Err(InnoLogError::TooLarge {
            limit: stream_len - 1
        })
    );
}

// ---- no-panic sweeps ----

#[test]
fn every_truncation_returns() {
    for block_size in [97, MAX_BLOCK_SIZE] {
        let bytes = write(
            &sample_log(1048),
            WriteOptions {
                utf16: true,
                block_size,
            },
        );
        for len in 0..bytes.len() {
            assert!(
                parse(&bytes[..len]).is_err(),
                "prefix of {len} bytes parsed"
            );
            // The same prefix with a header that agrees with it, so the body is reached.
            if len >= HEADER_SIZE {
                let _ = parse(&cut_and_seal(&bytes, len));
            }
        }
    }
}

#[test]
fn bit_flips_return() {
    let clean = write(
        &sample_log(1048),
        WriteOptions {
            utf16: true,
            block_size: 300,
        },
    );
    // The same log with block CRC checks off and a valid header, so flips reach the record decoder.
    let mut unchecked = clean.clone();
    unchecked[VERSION_OFFSET + 12] |= u8::try_from(flags::HEADER_DONT_CHECK_REC_CRCS).unwrap();
    seal_header(&mut unchecked);

    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let (mut ok, mut err) = (0u32, 0u32);
    for round in 0..1000 {
        let base = if round % 2 == 0 { &clean } else { &unchecked };
        let mut bytes = base.clone();
        let bit = usize::try_from(rng.next() % (bytes.len() as u64 * 8)).unwrap();
        bytes[bit / 8] ^= 1 << (bit % 8);
        // Half of the body flips keep the header valid; header flips are re-sealed every fourth round.
        if round % 4 >= 2 && bit / 8 < HEADER_CRC_OFFSET {
            seal_header(&mut bytes);
        }
        match parse(&bytes) {
            Ok(_) => ok += 1,
            Err(_) => err += 1,
        }
    }
    assert_eq!(ok + err, 1000);
    // Both outcomes occur: flips are caught, and flips inside unchecked string bodies are harmless.
    assert!(ok > 0 && err > 0, "ok {ok}, err {err}");
}

// ---- model mapping ----

#[test]
fn model_mapping() {
    let log = sample_log(1048);
    let model = log.model_records();
    // No model kind: StartInstall, CompiledCode, EndInstall, Run, RefreshFileAssoc and MutexCheck.
    // Not evidence of ownership: the directory that is only removed when empty.
    assert_eq!(model.len(), log.records.len() - 7);

    let find = |kind: InnoRecordKind, nth: usize| {
        model
            .iter()
            .filter(|r| r.kind == kind)
            .nth(nth)
            .unwrap_or_else(|| panic!("no {kind:?} #{nth}"))
    };

    let dll = find(InnoRecordKind::DeleteFile, 0);
    assert_eq!(
        dll.target,
        Target::Path {
            path: s(r"C:\Program Files\Sample\sample.dll")
        }
    );
    assert!(dll.shared && !dll.existed_before && !dll.key_create && !dll.user_hive);
    assert_eq!(dll.view, None);
    let font = find(InnoRecordKind::DeleteFile, 1);
    assert!(font.existed_before && !font.shared);

    let key = find(InnoRecordKind::RegDeleteEntireKey, 0);
    assert_eq!(
        key.target,
        Target::RegKey {
            path: s(r"HKLM\SOFTWARE\Classes\SampleFile")
        }
    );
    assert_eq!(key.view, Some(View::K64));
    assert!(key.key_create && !key.user_hive);

    // 32-bit view of HKLM\SOFTWARE is spelled with the redirection node.
    let vendor = find(InnoRecordKind::RegDeleteKeyIfEmpty, 0);
    assert_eq!(
        vendor.target,
        Target::RegKey {
            path: s(r"HKLM\SOFTWARE\WOW6432Node\Sample Vendor")
        }
    );
    assert_eq!(vendor.view, Some(View::K32));
    assert!(vendor.key_create);
    assert!(TypedTarget::try_from(&vendor.target).is_ok());

    // HKCU records stay unbound, marked for the harvest.
    let cleared = find(InnoRecordKind::RegClearValue, 0);
    assert_eq!(
        cleared.target,
        Target::RegValue {
            path: s(r"HKCU\Software\Sample"),
            name: s("LastRun"),
        }
    );
    assert!(cleared.user_hive && !cleared.key_create);
    let value = find(InnoRecordKind::RegDeleteValue, 0);
    assert_eq!(
        value.target,
        Target::RegValue {
            path: s(r"HKCU\Software\Classes\.smp\OpenWithProgids"),
            name: s("SampleFile"),
        }
    );
    assert!(value.user_hive && !value.key_create);
    assert_eq!(value.view, Some(View::K64));

    let ini = find(InnoRecordKind::IniDeleteEntry, 0);
    assert_eq!(
        ini.target,
        Target::Path {
            path: s(r"C:\Program Files\Sample\sample.ini")
        }
    );
    assert_eq!(find(InnoRecordKind::IniDeleteSection, 0).target, ini.target);
    let counted = find(InnoRecordKind::DecrementSharedCount, 0);
    assert!(matches!(counted.target, Target::Path { .. }));
    assert!(counted.shared, "a reference-counted file is shared");
    // Only the directory the uninstaller deletes with its contents is mapped.
    assert_eq!(
        model
            .iter()
            .filter(|r| r.kind == InnoRecordKind::DeleteDirOrFiles)
            .count(),
        1
    );
    assert_eq!(
        find(InnoRecordKind::DeleteDirOrFiles, 0).target,
        Target::Path {
            path: s(r"C:\Program Files\Sample\cache")
        }
    );
    assert!(matches!(
        find(InnoRecordKind::DeleteGroupOrItem, 0).target,
        Target::Path { .. }
    ));
}

#[test]
fn model_mapping_of_registry_roots() {
    let key = |extra_data: u32, subkey: &str| {
        rec(
            extra_data,
            LogOp::RegDeleteEntireKey {
                root: RegRoot::from_extra_data(extra_data),
                subkey: s(subkey),
            },
        )
        .to_model()
    };
    let path_of = |extra_data: u32, subkey: &str| match key(extra_data, subkey).unwrap().target {
        Target::RegKey { path } => path,
        other => panic!("{other:?}"),
    };

    // HKCR is the machine classes key; its 32-bit view is redirected.
    assert_eq!(
        path_of(HKCR | flags::REG_64BIT_KEY, "SampleFile"),
        r"HKLM\SOFTWARE\Classes\SampleFile"
    );
    assert_eq!(
        path_of(HKCR, r"CLSID\{X}"),
        r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{X}"
    );
    // Class keys other than the redirected ones are shared: the 32-bit view addresses the same key.
    assert_eq!(path_of(HKCR, ".smp"), r"HKLM\SOFTWARE\Classes\.smp");
    assert_eq!(
        path_of(HKCR, r"SampleFile\shell\open\command"),
        r"HKLM\SOFTWARE\Classes\SampleFile\shell\open\command"
    );
    assert_eq!(
        path_of(HKLM, r"Software\Classes\.smp"),
        r"HKLM\Software\Classes\.smp"
    );
    assert_eq!(
        path_of(HKLM, r"software\classes\interface\{X}"),
        r"HKLM\software\WOW6432Node\classes\interface\{X}"
    );
    assert_eq!(
        path_of(HKLM, r"SOFTWARE\ClassesX\Y"),
        r"HKLM\SOFTWARE\WOW6432Node\ClassesX\Y"
    );
    // The view as logged stays on the record.
    assert_eq!(key(HKCR, ".smp").unwrap().view, Some(View::K32));
    // Stray separators are dropped.
    assert_eq!(
        path_of(HKLM | flags::REG_64BIT_KEY, r"\SOFTWARE\Sample\"),
        r"HKLM\SOFTWARE\Sample"
    );
    // The 32-bit view has no meaning outside SOFTWARE.
    assert_eq!(
        path_of(HKLM, r"SYSTEM\CurrentControlSet\Services\X"),
        r"HKLM\SYSTEM\CurrentControlSet\Services\X"
    );
    // HKU with a SID is canonical as written; HKCU is left for the harvest to bind.
    assert_eq!(
        path_of(HKU, r"S-1-5-21-1-2-3-1001\Software\X"),
        r"HKU\S-1-5-21-1-2-3-1001\Software\X"
    );
    let user = key(HKCU, r"Software\X").unwrap();
    assert_eq!(
        user.target,
        Target::RegKey {
            path: s(r"HKCU\Software\X")
        }
    );
    assert!(user.user_hive && user.key_create);
    assert!(
        TypedTarget::try_from(&user.target).is_err(),
        "unbound HKCU must not type-check"
    );

    // No canonical hive, or nothing to address.
    assert_eq!(key(HKCC, r"Software\X"), None);
    assert_eq!(key(0x8000_0050, r"Software\X"), None);
    assert_eq!(key(HKU, ""), None);
    // A root key itself is never a target, least of all a key-create one.
    for root in [HKLM, HKCR, HKCU, HKLM | flags::REG_64BIT_KEY] {
        assert_eq!(key(root, ""), None, "{root:#x}");
        assert_eq!(key(root, "\\"), None, "{root:#x}");
    }
    let empty_path = rec(0, LogOp::DeleteFile { path: s("") });
    assert_eq!(empty_path.to_model(), None);

    // An unknown root is reported at parse time.
    let records = vec![(0x86, 0x8000_0050, encode_strings(&["Software\\X"], true))];
    let log = parse(&write_raw(&header(1048), &records, MAX_BLOCK_SIZE)).unwrap();
    assert_eq!(log.warnings.len(), 1);
    assert!(log.warnings[0].contains("unknown registry root"));
    assert!(log.model_records().is_empty());
}

#[test]
fn bookkeeping_records_are_typed_and_never_fail_the_log() {
    // The shapes real logs have: Unicode and ANSI string lists with a packed timestamp at the end.
    let stamp = [0xEA, 0x07, 9, 0, 3, 0, 9, 0, 13, 0, 49, 0, 29, 0, 100, 2];
    let mut start = encode_strings(&["SAMPLE-PC", "sample", r"C:\Apps\Sample"], true);
    start.pop();
    start.extend_from_slice(&[0xFE, 0xF0, 0xFF, 0xFF, 0xFF]);
    start.extend_from_slice(&stamp);
    start.push(0xFF);
    let records = vec![
        (0x10, 0, start),
        (
            0x20,
            0x0700_0200,
            vec![0xFE, 0x3E, 0x83, 0xFC, 0xFF, 1, 2, 3],
        ),
        (0x82, 0, encode_strings(&[r"C:\Apps\Sample\a.txt"], true)),
        // A string list that cannot be read: an odd UTF-16 byte count, and no end marker.
        (0x11, 0, vec![0xFE, 0xFD, 0xFF, 0xFF, 0xFF, 1, 2, 3]),
        (0x10, 0, vec![5, b'a']),
    ];
    let log = parse(&write_raw(&header(1055), &records, MAX_BLOCK_SIZE)).unwrap();
    assert!(log.warnings.is_empty(), "{:?}", log.warnings);
    assert_eq!(log.raw_count(), 0);
    assert_eq!(
        log.records[0].op,
        LogOp::StartInstall {
            computer_name: s("SAMPLE-PC"),
            user_name: s("sample"),
            app_dir: s(r"C:\Apps\Sample"),
        }
    );
    assert_eq!(log.records[0].trailing.len(), 1);
    assert_eq!(log.records[0].op.type_name(), "StartInstall");
    assert_eq!(
        log.records[1].op,
        LogOp::CompiledCode {
            data: vec![0xFE, 0x3E, 0x83, 0xFC, 0xFF, 1, 2, 3]
        }
    );
    assert_eq!(log.records[3], rec(0, LogOp::EndInstall));
    assert_eq!(
        log.records[4].op,
        LogOp::StartInstall {
            computer_name: s(""),
            user_name: s(""),
            app_dir: s(""),
        }
    );
    // None of them is evidence.
    assert_eq!(log.model_records().len(), 1);
}

#[test]
fn directory_records_map_only_when_the_uninstaller_deletes_the_contents() {
    use flags::{
        DIR_CALL_CHANGE_NOTIFY, DIR_DELETE_FILES, DIR_DELETE_SUBDIRS_ALSO, DIR_DISABLE_FS_REDIR,
        DIR_EXTRA, DIR_IS_DIR,
    };
    let dir = |extra_data: u32, path: &str| {
        let record = rec(extra_data, LogOp::DeleteDirOrFiles { path: s(path) });
        record.to_model().map(|m| match m.target {
            Target::Path { path } => path,
            other => panic!("{other:?}"),
        })
    };
    let app = r"C:\Users\u\Documents\Sample Projects";

    // What the installer logs for a directory it created, a Start Menu group, a `[Dirs]` entry and
    // `Type: dirifempty`: remove the directory if it is empty. Its contents are not the installer's.
    for bits in [
        DIR_IS_DIR,
        DIR_IS_DIR | DIR_DISABLE_FS_REDIR,
        DIR_IS_DIR | DIR_CALL_CHANGE_NOTIFY,
        DIR_IS_DIR | DIR_EXTRA,
        0,
    ] {
        assert_eq!(dir(bits, app), None, "{bits:#x}");
    }
    // The files in a directory but not its subdirectories: a path target cannot say that.
    assert_eq!(dir(DIR_IS_DIR | DIR_DELETE_FILES, app), None);

    // `Type: files` on one file, `Type: filesandordirs` on a file or directory.
    let file = r"C:\Program Files\Sample\log.txt";
    assert_eq!(dir(DIR_EXTRA | DIR_DELETE_FILES, file), Some(s(file)));
    let tree = DIR_EXTRA | DIR_DELETE_FILES | DIR_DELETE_SUBDIRS_ALSO;
    assert_eq!(dir(tree, app), Some(s(app)));
    assert_eq!(
        dir(tree | DIR_IS_DIR | DIR_DISABLE_FS_REDIR, app),
        Some(s(app))
    );

    // A wildcard pattern is not a path.
    for pattern in [
        r"C:\Users\u\AppData\Local\Temp\sample-*",
        r"C:\Program Files\Sample\*",
        r"C:\Program Files\Sample\file?.dll",
        r"\\?\C:\Program Files\Sample\*.winmd",
        r"C:\Users\*\Documents",
    ] {
        assert_eq!(dir(tree, pattern), None, "{pattern}");
        assert_eq!(
            dir(DIR_EXTRA | DIR_DELETE_FILES, pattern),
            None,
            "{pattern}"
        );
    }

    let record = rec(tree, LogOp::DeleteDirOrFiles { path: s(app) });
    assert!(record.dir_deletes_files() && record.dir_deletes_subdirs() && !record.dir_is_dir());
    // The bits mean something else on other record types.
    let file_record = rec(tree | DIR_IS_DIR, LogOp::DeleteFile { path: s(file) });
    assert!(!file_record.dir_deletes_files() && !file_record.dir_is_dir());
}

#[test]
fn extended_length_prefix_is_removed_from_model_paths() {
    let path_of = |path: &str| match rec(0, LogOp::DeleteFile { path: s(path) })
        .to_model()
        .map(|m| m.target)
    {
        Some(Target::Path { path }) => Some(path),
        None => None,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        path_of(r"\\?\C:\Program Files\Sample\a.dll").unwrap(),
        r"C:\Program Files\Sample\a.dll"
    );
    assert_eq!(
        path_of(r"\\?\UNC\server\share\a.dll").unwrap(),
        r"\\server\share\a.dll"
    );
    assert_eq!(path_of(r"\\?\unc\server\share").unwrap(), r"\\server\share");
    // Kept: ordinary paths, and prefixed forms that have no plain spelling.
    for kept in [
        r"C:\Program Files\Sample\a.dll",
        r"\\server\share\a.dll",
        r"\\?\Volume{0a1b2c3d-0000-4000-8000-00000000abcd}\a.dll",
        r"\\?\UNC",
        r"\\?\é:\a",
    ] {
        assert_eq!(path_of(kept).unwrap(), kept);
    }
    // The typed record keeps the path as written.
    let record = rec(
        0,
        LogOp::IniDeleteEntry {
            file: s(r"\\?\C:\Sample\s.ini"),
            section: s("a"),
            entry: s("b"),
        },
    );
    assert_eq!(
        record.to_model().unwrap().target,
        Target::Path {
            path: s(r"C:\Sample\s.ini")
        }
    );
    assert_eq!(path_of(r"\\?\"), Some(s(r"\\?\")));
    assert_eq!(path_of(""), None);
}

#[test]
fn classes_root_records_of_a_non_admin_install_are_not_mapped() {
    let records = vec![
        rec(
            HKCR | flags::REG_64BIT_KEY,
            LogOp::RegDeleteEntireKey {
                root: RegRoot::ClassesRoot,
                subkey: s("SampleFile"),
            },
        ),
        rec(
            HKCR | flags::REG_64BIT_KEY,
            LogOp::RegDeleteValue {
                root: RegRoot::ClassesRoot,
                subkey: s(r".smp\OpenWithProgids"),
                value: s("SampleFile"),
            },
        ),
        rec(
            HKCU | flags::REG_64BIT_KEY,
            LogOp::RegDeleteEntireKey {
                root: RegRoot::CurrentUser,
                subkey: s(r"Software\Classes\SampleFile"),
            },
        ),
    ];
    let mut log = UninstallLog {
        header: header(1048),
        records,
        warnings: Vec::new(),
    };
    assert!(log.header.is_admin_install());
    assert_eq!(log.model_records().len(), 3);

    // Per-user install: only the record that names the user's hive is evidence.
    log.header.flags = flags::HEADER_WIN64 | flags::HEADER_MODERN_STYLE;
    assert!(!log.header.is_admin_install());
    let model = log.model_records();
    assert_eq!(model.len(), 1);
    assert!(model[0].user_hive);
    // Older logs mark an elevated install with the first flag only.
    log.header.flags = flags::HEADER_ADMIN_INSTALLED;
    assert_eq!(log.model_records().len(), 3);
}

#[test]
fn header_names_outside_ascii_are_utf8_behind_a_marker() {
    let mut log = sample_log(1048);
    log.header.app_id = s("HWiNFO\u{ae} 64");
    log.header.app_name = s("Beispiel \u{e4}\u{f6}\u{fc} \u{4f8b}");
    let mut bytes = write(&log, WriteOptions::default());
    assert_eq!(bytes[64], 1, "marker byte");
    assert_eq!(parse(&bytes), Ok(log.clone()));

    // A marked name that is not UTF-8 is still read, byte for byte.
    bytes[65] = 0xFF;
    seal_header(&mut bytes);
    let odd = parse(&bytes).unwrap();
    assert!(odd.header.app_id.starts_with('\u{ff}'));
    // An unmarked name is single-byte text.
    bytes[64] = b'A';
    bytes[65] = 0xE9;
    seal_header(&mut bytes);
    assert!(parse(&bytes).unwrap().header.app_id.starts_with("A\u{e9}"));
}

// ---- real logs ----

/// Parses every `*.dat` file in the directory named by `PURGE_INNO_FIXTURES` (e.g. the `unins000.dat`
/// of Git or VS Code) and prints record counts per type. Each must parse fully, without `Raw` records,
/// and its model records must hold plain paths only.
#[test]
#[ignore = "needs real logs: set PURGE_INNO_FIXTURES to a directory with unins*.dat files"]
fn real_logs_parse_without_raw_records() {
    let Some(dir) = std::env::var_os("PURGE_INNO_FIXTURES") else {
        println!("PURGE_INNO_FIXTURES is not set; nothing to check");
        return;
    };
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.to_string_lossy()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("dat"))
        })
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "no .dat files in {}",
        dir.to_string_lossy()
    );

    for path in paths {
        let bytes = std::fs::read(&path).unwrap();
        let log = parse(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for record in &log.records {
            *counts.entry(record.op.type_name()).or_default() += 1;
        }
        println!(
            "{}: version {}, 64-bit {}, flags {:#x}, app {:?} ({:?}), {} records, {} model records",
            path.display(),
            log.header.version,
            log.header.is_64bit,
            log.header.flags,
            log.header.app_name,
            log.header.app_id,
            log.records.len(),
            log.model_records().len(),
        );
        for (name, count) in &counts {
            println!("  {name:<22} {count}");
        }
        for warning in &log.warnings {
            println!("  warning: {warning}");
        }
        assert_eq!(log.raw_count(), 0, "{}: Raw records", path.display());
        assert!(log.warnings.is_empty(), "{}: warnings", path.display());
        // Every install run is bracketed by the bookkeeping records.
        let count = |name: &str| counts.get(name).copied().unwrap_or(0);
        assert!(count("StartInstall") >= 1, "{}", path.display());
        assert_eq!(
            count("StartInstall"),
            count("EndInstall"),
            "{}",
            path.display()
        );
        assert_eq!(
            count("StartInstall"),
            count("CompiledCode"),
            "{}",
            path.display()
        );
        for record in log.model_records() {
            match &record.target {
                Target::Path { path: target } => {
                    assert!(
                        !target.starts_with(r"\\?\") && !target.contains(['*', '?']),
                        "{}: {target}",
                        path.display()
                    );
                }
                Target::RegKey { path: key } | Target::RegValue { path: key, .. } => {
                    assert!(key.contains('\\'), "{}: root key {key}", path.display());
                    assert_eq!(
                        record.user_hive,
                        key.starts_with(r"HKCU\"),
                        "{}: {key}",
                        path.display()
                    );
                }
                other => panic!("{}: {other:?}", path.display()),
            }
        }
    }
}
