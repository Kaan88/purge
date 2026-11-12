//! Parser for Inno Setup uninstall logs (`unins*.dat`), ENGINE_PLAN.md §6.1.
//!
//! Written from the published description of the format (Inno Setup's `Setup.UninstallLog.pas`, public
//! source by Jordan Russell and Martijn Laan); no Inno Setup code is copied (§11.4).
//!
//! The log is what an Inno Setup uninstaller replays: one record per file, directory, INI entry or
//! registry item the installer registered for removal. Read **before** the uninstall, it is first-class
//! `InstallerManifest` evidence (§5.3).
//!
//! # Format
//!
//! - A 448-byte header: a 64-byte id string, `AppId` and `AppName` (128 bytes each, NUL-padded), then
//!   `Version: i32`, `NumRecs: i32`, `EndOffset: u32`, `Flags: u32`, 27 reserved `i32` and a CRC-32 of
//!   the 444 bytes before it. All integers are little-endian.
//! - From offset 448 to `EndOffset`: blocks `{Size: u32, NotSize: u32, Crc: u32}` followed by `Size`
//!   bytes (at most 4096), with `NotSize == !Size` and `Crc` the CRC-32 of the block's bytes.
//! - The blocks' bytes, concatenated, are a stream of `NumRecs` records
//!   `{Typ: u16, ExtraData: u32, DataSize: u32}` each followed by `DataSize` bytes. A record may span
//!   blocks.
//! - A record's data is a list of strings. Each starts with a marker byte: `0x00..=0xFC` is the length
//!   itself, `0xFD` is followed by a `u16` length, `0xFE` by an `i32` length; `0xFF` ends the list. A
//!   negative `i32` length is the byte count of UTF-16LE text, every other length counts single-byte
//!   (ANSI) characters.
//!
//! # What the parser guarantees
//!
//! [`parse`] is pure: bytes in, [`UninstallLog`] or [`InnoLogError`] out. Every length is checked
//! against the bytes that are there, the decoded stream is capped at [`MAX_DECODED_SIZE`], and no input
//! makes it panic. A header version above [`MAX_SUPPORTED_VERSION`] gives
//! [`InnoLogError::Unsupported`], so the caller can record a warning and fall back to harvest-only
//! (§11.2). A record type the parser does not know is kept as [`LogOp::Raw`] with a warning, never an
//! error. Besides the thirteen uninstall steps (`0x80..=0x8C`) every real log carries bookkeeping
//! records: one `StartInstall` (`0x10`), one `CompiledCode` (`0x20`) and one `EndInstall` (`0x11`) per
//! install run. A log grows with every update of the app, so the same uninstall step usually occurs
//! once per run. Any other inconsistency is an error for the whole log: the data is CRC-protected, so a decode
//! failure means the format differs from what this parser knows, and a half-understood log must not
//! become Tier A evidence.
//!
//! ANSI strings are decoded byte-for-byte as Latin-1, because the log does not name its code page;
//! ASCII text, which is what paths of Unicode-era installers use, is exact.
//!
//! # Model mapping
//!
//! [`UninstallLog::model_records`] turns the typed records into [`InnoRecord`]s. Registry roots become
//! canonical hives. A record under `HKEY_CURRENT_USER` keeps the root `HKCU\…` and sets
//! [`InnoRecord::user_hive`]: the harvest binds it to the installing user's SID. File paths are kept as
//! written, except that the extended-length prefix `\\?\` (which recent Inno Setup versions write) is
//! removed.
//!
//! The mapping is deliberately narrower than the log, because a model record is Tier A evidence that
//! the installer owns its target (§5.3). Left out are: directory records that only remove the directory
//! when it is empty, wildcard patterns, registry records without a key path, and `HKEY_CLASSES_ROOT`
//! records of an install that ran without administrative rights. See [`LogRecord::to_model`] and
//! [`UninstallLog::model_records`].

mod reader;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod writer;

use purge_model::{Hive, InnoRecord, InnoRecordKind, RegKind, Target, TypedTarget, View};

/// Highest header version this parser reads (§6.1). Newer logs give [`InnoLogError::Unsupported`].
pub const MAX_SUPPORTED_VERSION: i32 = 1055;

/// Cap on the size of the decoded record stream (the blocks' bytes, concatenated): 64 MiB.
pub const MAX_DECODED_SIZE: usize = 64 * 1024 * 1024;

/// Size of the log header in bytes.
pub const HEADER_SIZE: usize = 448;

/// Largest number of data bytes in one block.
pub const MAX_BLOCK_SIZE: usize = 4096;

/// Bits of the header's `Flags` and of a record's `ExtraData`, as the log format defines them.
pub mod flags {
    /// Header: the install ran with administrative privileges.
    pub const HEADER_ADMIN_INSTALLED: u32 = 1 << 0;
    /// Header: the blocks' CRCs are not to be checked.
    pub const HEADER_DONT_CHECK_REC_CRCS: u32 = 1 << 1;
    /// Header: the uninstaller uses the modern wizard style.
    pub const HEADER_MODERN_STYLE: u32 = 1 << 2;
    /// Header: the uninstaller always asks for a restart.
    pub const HEADER_ALWAYS_RESTART: u32 = 1 << 3;
    /// Header: the install changed environment variables.
    pub const HEADER_CHANGES_ENVIRONMENT: u32 = 1 << 4;
    /// Header: the install ran on 64-bit Windows.
    pub const HEADER_WIN64: u32 = 1 << 5;
    /// Header: the install ran with Power User privileges.
    pub const HEADER_POWER_USER_INSTALLED: u32 = 1 << 6;
    /// Header: the install ran in administrative install mode (as opposed to per-user).
    pub const HEADER_ADMIN_INSTALL_MODE: u32 = 1 << 7;

    /// `Run`: do not wait for the process.
    pub const RUN_NO_WAIT: u32 = 1;
    /// `Run`: wait until the process is idle.
    pub const RUN_WAIT_UNTIL_IDLE: u32 = 2;
    /// `Run`: start through the shell.
    pub const RUN_SHELL_EXEC: u32 = 4;
    /// `Run`: start minimised.
    pub const RUN_MINIMIZED: u32 = 8;
    /// `Run`: start maximised.
    pub const RUN_MAXIMIZED: u32 = 16;
    /// `Run`: skip when the file does not exist.
    pub const RUN_SKIP_IF_DOESNT_EXIST: u32 = 32;
    /// `Run`: start hidden.
    pub const RUN_HIDDEN: u32 = 64;
    /// `Run`: a shell start that honours the wait flags.
    pub const RUN_SHELL_EXEC_RESPECT_WAIT_FLAGS: u32 = 128;
    /// `Run`: file-system redirection is off (64-bit path).
    pub const RUN_DISABLE_FS_REDIR: u32 = 256;
    /// `Run`: the parameters are not logged.
    pub const RUN_DONT_LOG_PARAMETERS: u32 = 512;
    /// `Run`: the output is logged.
    pub const RUN_LOG_OUTPUT: u32 = 1024;

    /// `DeleteFile`: the file existed before the install.
    pub const FILE_EXISTED_BEFORE_INSTALL: u32 = 1;
    /// `DeleteFile`: an extra file (from `[UninstallDelete]`-like sources).
    pub const FILE_EXTRA: u32 = 2;
    /// `DeleteFile`: a font.
    pub const FILE_IS_FONT: u32 = 4;
    /// `DeleteFile`: a shared file (reference-counted under `SharedDLLs`).
    pub const FILE_SHARED_FILE: u32 = 8;
    /// `DeleteFile`: a registered COM server.
    pub const FILE_REGISTERED_SERVER: u32 = 16;
    /// `DeleteFile`: the shell is told about the change.
    pub const FILE_CALL_CHANGE_NOTIFY: u32 = 32;
    /// `DeleteFile`: a registered type library.
    pub const FILE_REGISTERED_TYPE_LIB: u32 = 64;
    /// `DeleteFile`: delete at restart when in use.
    pub const FILE_RESTART_DELETE: u32 = 128;
    /// `DeleteFile`: clear the read-only attribute first.
    pub const FILE_REMOVE_READ_ONLY: u32 = 256;
    /// `DeleteFile`: no prompt for the shared file.
    pub const FILE_NO_SHARED_FILE_PROMPT: u32 = 512;
    /// `DeleteFile`: the shared count lives in the 64-bit registry view.
    pub const FILE_SHARED_FILE_IN_64BIT_KEY: u32 = 1024;
    /// `DeleteFile`: file-system redirection is off (64-bit path).
    pub const FILE_DISABLE_FS_REDIR: u32 = 2048;
    /// `DeleteFile`: installed into the Global Assembly Cache.
    pub const FILE_GAC_INSTALLED: u32 = 4096;
    /// `DeleteFile`: a per-user font.
    pub const FILE_PER_USER_FONT: u32 = 8192;

    /// `DeleteDirOrFiles`: an extra item.
    pub const DIR_EXTRA: u32 = 1;
    /// `DeleteDirOrFiles`: the path is a directory.
    pub const DIR_IS_DIR: u32 = 2;
    /// `DeleteDirOrFiles`: delete the files in it.
    pub const DIR_DELETE_FILES: u32 = 4;
    /// `DeleteDirOrFiles`: delete subdirectories too.
    pub const DIR_DELETE_SUBDIRS_ALSO: u32 = 8;
    /// `DeleteDirOrFiles`: the shell is told about the change.
    pub const DIR_CALL_CHANGE_NOTIFY: u32 = 16;
    /// `DeleteDirOrFiles`: file-system redirection is off (64-bit path).
    pub const DIR_DISABLE_FS_REDIR: u32 = 32;

    /// `IniDeleteSection`: only when the section is empty.
    pub const INI_SECTION_ONLY_IF_EMPTY: u32 = 1;

    /// Registry records: mask that leaves the root key handle.
    pub const REG_KEY_HANDLE_MASK: u32 = 0x80FF_FFFF;
    /// Registry records: the key is in the 64-bit view.
    pub const REG_64BIT_KEY: u32 = 0x0100_0000;

    /// `DecrementSharedCount`: the count lives in the 64-bit registry view.
    pub const SHARED_COUNT_64BIT_KEY: u32 = 1;
}

/// Why a log could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InnoLogError {
    /// The file is shorter than the header.
    #[error("uninstall log is {len} bytes, shorter than its {HEADER_SIZE}-byte header")]
    TooShort {
        /// The file's length.
        len: usize,
    },
    /// The id string is not an Inno Setup uninstall log's.
    #[error("not an Inno Setup uninstall log (id string does not match)")]
    BadId,
    /// The header's CRC does not match its bytes.
    #[error("header CRC mismatch (stored {stored:#010x}, computed {computed:#010x})")]
    HeaderCrc {
        /// The CRC in the header.
        stored: u32,
        /// The CRC of the header's bytes.
        computed: u32,
    },
    /// The header version is outside what this parser reads (above [`MAX_SUPPORTED_VERSION`], or not
    /// positive). The caller records a warning and continues without the log.
    #[error(
        "uninstall log version {version} is not supported (highest known is {MAX_SUPPORTED_VERSION})"
    )]
    Unsupported {
        /// The header's version.
        version: i32,
    },
    /// The header's record count is negative.
    #[error("header record count {num_recs} is negative")]
    BadRecordCount {
        /// The header's `NumRecs`.
        num_recs: i32,
    },
    /// The header's end offset lies before the end of the header or beyond the end of the file.
    #[error("header end offset {end_offset} is outside the file ({len} bytes)")]
    BadEndOffset {
        /// The header's `EndOffset`.
        end_offset: u32,
        /// The file's length.
        len: usize,
    },
    /// A block header or a block's data runs past the end offset.
    #[error("block at offset {offset} is truncated")]
    TruncatedBlock {
        /// File offset of the block header.
        offset: usize,
    },
    /// A block's `NotSize` is not the complement of its `Size`.
    #[error(
        "block at offset {offset}: NotSize {not_size:#010x} is not the complement of Size {size:#010x}"
    )]
    NotSizeMismatch {
        /// File offset of the block header.
        offset: usize,
        /// The block's `Size`.
        size: u32,
        /// The block's `NotSize`.
        not_size: u32,
    },
    /// A block claims more than [`MAX_BLOCK_SIZE`] bytes.
    #[error("block at offset {offset}: size {size} exceeds {MAX_BLOCK_SIZE}")]
    BlockTooLarge {
        /// File offset of the block header.
        offset: usize,
        /// The block's `Size`.
        size: u32,
    },
    /// A block's CRC does not match its bytes.
    #[error(
        "block at offset {offset}: CRC mismatch (stored {stored:#010x}, computed {computed:#010x})"
    )]
    BlockCrc {
        /// File offset of the block header.
        offset: usize,
        /// The CRC in the block header.
        stored: u32,
        /// The CRC of the block's bytes.
        computed: u32,
    },
    /// The decoded record stream would exceed the size cap.
    #[error("decoded uninstall log exceeds {limit} bytes")]
    TooLarge {
        /// The cap in bytes.
        limit: usize,
    },
    /// The record stream ends inside a record's header or data.
    #[error("record {index}: the record stream ends inside the record")]
    TruncatedRecord {
        /// Zero-based index of the record.
        index: usize,
    },
    /// A string's length is larger than what is left of its record's data.
    #[error(
        "record {index}: string length {length} exceeds the {available} bytes left in the record"
    )]
    OversizedLength {
        /// Zero-based index of the record.
        index: usize,
        /// The length the string claims, in bytes.
        length: u64,
        /// The bytes left in the record's data.
        available: usize,
    },
    /// A record's string list is malformed in another way.
    #[error("record {index}: malformed string data ({reason})")]
    BadString {
        /// Zero-based index of the record.
        index: usize,
        /// What is wrong.
        reason: &'static str,
    },
    /// A record has fewer strings than its type needs.
    #[error("record {index} (type {typ:#06x}) has {found} strings, needs {needed}")]
    MissingField {
        /// Zero-based index of the record.
        index: usize,
        /// The record's type code.
        typ: u16,
        /// How many strings the type needs.
        needed: usize,
        /// How many the record has.
        found: usize,
    },
}

/// The decoded header of an uninstall log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogHeader {
    /// The id string carries the `64-bit` marker (the install used 64-bit install mode).
    pub is_64bit: bool,
    /// The installer's `AppId`, as stored (at most 127 bytes; long ids are stored shortened).
    pub app_id: String,
    /// The app's name.
    pub app_name: String,
    /// The log format version.
    pub version: i32,
    /// The header flags; see the `HEADER_*` constants in [`flags`].
    pub flags: u32,
}

impl LogHeader {
    /// The install ran in administrative install mode, or with administrative privileges (older logs).
    pub fn is_admin_install(&self) -> bool {
        self.flags & (flags::HEADER_ADMIN_INSTALL_MODE | flags::HEADER_ADMIN_INSTALLED) != 0
    }
}

/// The predefined registry root a registry record addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegRoot {
    /// `HKEY_CLASSES_ROOT`.
    ClassesRoot,
    /// `HKEY_CURRENT_USER` (of the installing user).
    CurrentUser,
    /// `HKEY_LOCAL_MACHINE`.
    LocalMachine,
    /// `HKEY_USERS`.
    Users,
    /// `HKEY_CURRENT_CONFIG`.
    CurrentConfig,
    /// Another handle value, kept as found in `ExtraData & REG_KEY_HANDLE_MASK`.
    Other(u32),
}

impl RegRoot {
    /// Reads the root from a registry record's `ExtraData`.
    pub fn from_extra_data(extra_data: u32) -> Self {
        match extra_data & flags::REG_KEY_HANDLE_MASK {
            0x8000_0000 => Self::ClassesRoot,
            0x8000_0001 => Self::CurrentUser,
            0x8000_0002 => Self::LocalMachine,
            0x8000_0003 => Self::Users,
            0x8000_0005 => Self::CurrentConfig,
            other => Self::Other(other),
        }
    }

    /// The handle value as the log stores it.
    pub fn handle(self) -> u32 {
        match self {
            Self::ClassesRoot => 0x8000_0000,
            Self::CurrentUser => 0x8000_0001,
            Self::LocalMachine => 0x8000_0002,
            Self::Users => 0x8000_0003,
            Self::CurrentConfig => 0x8000_0005,
            Self::Other(handle) => handle,
        }
    }
}

/// What one record tells the uninstaller to do, with the strings of its data in their typed places.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogOp {
    /// `0x10`: an install run begins. Bookkeeping, not an uninstall step. The record's remaining
    /// strings (a packed timestamp) are in [`LogRecord::trailing`].
    StartInstall {
        /// The computer the install ran on.
        computer_name: String,
        /// The user who ran the install (account name, no domain).
        user_name: String,
        /// The directory the app was installed into.
        app_dir: String,
    },
    /// `0x11`: an install run ends. Bookkeeping; its strings (a packed timestamp) are in
    /// [`LogRecord::trailing`].
    EndInstall,
    /// `0x20`: the installer's compiled script code and its state, replayed by the uninstaller.
    /// Bookkeeping; the data is binary and kept undecoded.
    CompiledCode {
        /// The record's data bytes.
        data: Vec<u8>,
    },
    /// `0x80`: run a program (`[UninstallRun]`).
    Run {
        /// The file to run.
        filename: String,
        /// Its parameters.
        parameters: String,
        /// Its working directory.
        working_dir: String,
        /// The `RunOnceId`.
        run_once_id: String,
        /// The shell verb.
        verb: String,
    },
    /// `0x81`: delete a directory, or files by pattern.
    DeleteDirOrFiles {
        /// The directory or wildcard path, as written.
        path: String,
    },
    /// `0x82`: delete a file.
    DeleteFile {
        /// The file's path, as written.
        path: String,
    },
    /// `0x83`: delete a Start Menu group or item.
    DeleteGroupOrItem {
        /// The group or item path, as written.
        path: String,
    },
    /// `0x84`: delete an entry of an INI file.
    IniDeleteEntry {
        /// The INI file.
        file: String,
        /// The section.
        section: String,
        /// The entry.
        entry: String,
    },
    /// `0x85`: delete a section of an INI file.
    IniDeleteSection {
        /// The INI file.
        file: String,
        /// The section.
        section: String,
    },
    /// `0x86`: delete a registry key with its subtree.
    RegDeleteEntireKey {
        /// The root key.
        root: RegRoot,
        /// The key path below the root, as written.
        subkey: String,
    },
    /// `0x87`: clear a registry value (set it to empty).
    RegClearValue {
        /// The root key.
        root: RegRoot,
        /// The key path below the root, as written.
        subkey: String,
        /// The value name; empty for the default value.
        value: String,
    },
    /// `0x88`: delete a registry key if it is empty.
    RegDeleteKeyIfEmpty {
        /// The root key.
        root: RegRoot,
        /// The key path below the root, as written.
        subkey: String,
    },
    /// `0x89`: delete a registry value.
    RegDeleteValue {
        /// The root key.
        root: RegRoot,
        /// The key path below the root, as written.
        subkey: String,
        /// The value name; empty for the default value.
        value: String,
    },
    /// `0x8A`: decrement a shared-file count.
    DecrementSharedCount {
        /// The shared file's path, as written.
        path: String,
    },
    /// `0x8B`: refresh the shell's file associations.
    RefreshFileAssoc,
    /// `0x8C`: wait for mutexes to be released.
    MutexCheck {
        /// The mutex names (one comma-separated string).
        names: String,
    },
    /// A record type this parser does not know; its data is kept undecoded.
    Raw {
        /// The record's type code.
        typ: u16,
        /// The record's data bytes.
        data: Vec<u8>,
    },
}

impl LogOp {
    /// The record type code (`0x10`, `0x11`, `0x20`, `0x80..=0x8C`, or the stored code of a
    /// [`LogOp::Raw`]).
    pub fn type_code(&self) -> u16 {
        match self {
            Self::StartInstall { .. } => 0x10,
            Self::EndInstall => 0x11,
            Self::CompiledCode { .. } => 0x20,
            Self::Run { .. } => 0x80,
            Self::DeleteDirOrFiles { .. } => 0x81,
            Self::DeleteFile { .. } => 0x82,
            Self::DeleteGroupOrItem { .. } => 0x83,
            Self::IniDeleteEntry { .. } => 0x84,
            Self::IniDeleteSection { .. } => 0x85,
            Self::RegDeleteEntireKey { .. } => 0x86,
            Self::RegClearValue { .. } => 0x87,
            Self::RegDeleteKeyIfEmpty { .. } => 0x88,
            Self::RegDeleteValue { .. } => 0x89,
            Self::DecrementSharedCount { .. } => 0x8A,
            Self::RefreshFileAssoc => 0x8B,
            Self::MutexCheck { .. } => 0x8C,
            Self::Raw { typ, .. } => *typ,
        }
    }

    /// The record type's name, for reports.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::StartInstall { .. } => "StartInstall",
            Self::EndInstall => "EndInstall",
            Self::CompiledCode { .. } => "CompiledCode",
            Self::Run { .. } => "Run",
            Self::DeleteDirOrFiles { .. } => "DeleteDirOrFiles",
            Self::DeleteFile { .. } => "DeleteFile",
            Self::DeleteGroupOrItem { .. } => "DeleteGroupOrItem",
            Self::IniDeleteEntry { .. } => "IniDeleteEntry",
            Self::IniDeleteSection { .. } => "IniDeleteSection",
            Self::RegDeleteEntireKey { .. } => "RegDeleteEntireKey",
            Self::RegClearValue { .. } => "RegClearValue",
            Self::RegDeleteKeyIfEmpty { .. } => "RegDeleteKeyIfEmpty",
            Self::RegDeleteValue { .. } => "RegDeleteValue",
            Self::DecrementSharedCount { .. } => "DecrementSharedCount",
            Self::RefreshFileAssoc => "RefreshFileAssoc",
            Self::MutexCheck { .. } => "MutexCheck",
            Self::Raw { .. } => "Raw",
        }
    }

    /// The registry root and key path below it, for the four registry record types.
    fn reg_key(&self) -> Option<(RegRoot, &str)> {
        match self {
            Self::RegDeleteEntireKey { root, subkey }
            | Self::RegDeleteKeyIfEmpty { root, subkey }
            | Self::RegClearValue { root, subkey, .. }
            | Self::RegDeleteValue { root, subkey, .. } => Some((*root, subkey)),
            _ => None,
        }
    }
}

/// One record of the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    /// The record's `ExtraData`: per-type flag bits (see [`flags`]) and, for registry records, the root
    /// key handle.
    pub extra_data: u32,
    /// What the record does.
    pub op: LogOp,
    /// Strings of the record's data beyond those its type defines (e.g. a font's name and file after a
    /// `DeleteFile` path). Usually empty.
    pub trailing: Vec<String>,
}

impl LogRecord {
    /// Whether the record is one of the four registry types.
    pub fn is_registry(&self) -> bool {
        self.op.reg_key().is_some()
    }

    /// The registry view of a registry record (`ExtraData & 0x01000000` set means 64-bit); `None` for
    /// every other record.
    pub fn reg_view(&self) -> Option<View> {
        let view = if self.extra_data & flags::REG_64BIT_KEY != 0 {
            View::K64
        } else {
            View::K32
        };
        self.is_registry().then_some(view)
    }

    /// `DeleteFile` only: the file existed before the install.
    pub fn existed_before_install(&self) -> bool {
        self.file_flag(flags::FILE_EXISTED_BEFORE_INSTALL)
    }

    /// `DeleteFile` only: the file is a shared, reference-counted file.
    pub fn shared_file(&self) -> bool {
        self.file_flag(flags::FILE_SHARED_FILE)
    }

    /// `DeleteFile` only: the file is a registered COM server.
    pub fn registered_server(&self) -> bool {
        self.file_flag(flags::FILE_REGISTERED_SERVER)
    }

    /// File-system redirection was off for the path (`Run`, `DeleteFile`, `DeleteDirOrFiles`): a
    /// `System32` path means the native directory, not `SysWOW64`.
    pub fn fs_redirection_disabled(&self) -> bool {
        let bit = match self.op {
            LogOp::Run { .. } => flags::RUN_DISABLE_FS_REDIR,
            LogOp::DeleteFile { .. } => flags::FILE_DISABLE_FS_REDIR,
            LogOp::DeleteDirOrFiles { .. } => flags::DIR_DISABLE_FS_REDIR,
            _ => return false,
        };
        self.extra_data & bit != 0
    }

    fn file_flag(&self, bit: u32) -> bool {
        matches!(self.op, LogOp::DeleteFile { .. }) && self.extra_data & bit != 0
    }

    fn dir_flag(&self, bit: u32) -> bool {
        matches!(self.op, LogOp::DeleteDirOrFiles { .. }) && self.extra_data & bit != 0
    }

    /// `DeleteDirOrFiles` only: the path names a directory (as opposed to a file or a wildcard pattern).
    pub fn dir_is_dir(&self) -> bool {
        self.dir_flag(flags::DIR_IS_DIR)
    }

    /// `DeleteDirOrFiles` only: the uninstaller deletes files (those matching the path, or those in the
    /// directory). Without it the record removes the directory **only when it is empty**: that is what
    /// the installer logs for every directory it created, and it says nothing about the files in it.
    pub fn dir_deletes_files(&self) -> bool {
        self.dir_flag(flags::DIR_DELETE_FILES)
    }

    /// `DeleteDirOrFiles` only: the uninstaller also deletes matching subdirectories with their
    /// contents.
    pub fn dir_deletes_subdirs(&self) -> bool {
        self.dir_flag(flags::DIR_DELETE_SUBDIRS_ALSO)
    }

    /// Maps the record to the model's [`InnoRecord`]. Prefer [`UninstallLog::model_records`], which
    /// also knows the header.
    ///
    /// A model record is evidence that the installer owns the target, so only records that say so are
    /// mapped. `None` for:
    ///
    /// - records the model has no kind for (`StartInstall`, `EndInstall`, `CompiledCode`, `Run`,
    ///   `RefreshFileAssoc`, `MutexCheck`, `Raw`);
    /// - records with an empty path, and registry records with an empty key path (the root key itself);
    /// - registry records under a root with no canonical hive (`HKEY_CURRENT_CONFIG`, unknown handles,
    ///   `HKEY_USERS` itself);
    /// - `DeleteDirOrFiles` records that do not delete files (the directory is removed only when
    ///   empty, so its contents are not the installer's), that delete the files in a directory but not
    ///   its subdirectories (a path target could not say so), or whose path is a wildcard pattern.
    ///
    /// A mapped `DeleteDirOrFiles` record is therefore either one file-system item named by its full
    /// path, or a directory the uninstaller deletes with everything in it
    /// ([`LogRecord::dir_deletes_subdirs`] tells them apart).
    ///
    /// File paths are kept as written, without the extended-length prefix `\\?\`.
    ///
    /// Registry targets: `HKLM` and `HKCR` (as `HKLM\SOFTWARE\Classes`) are written in canonical form
    /// with the record's view; under `SOFTWARE\Classes` the 32-bit view only differs for the keys
    /// Windows redirects there (`CLSID`, `Interface`, …), every other class key is shared and addressed
    /// in the 64-bit view. `HKCU` records keep the root `HKCU\…` with `user_hive` set, unbound;
    /// `HKU\<sid>\…` is kept as written. `key_create` is set exactly for `RegDeleteEntireKey` and
    /// `RegDeleteKeyIfEmpty`, whose target is always the key itself. [`InnoRecord::view`] is the view
    /// as logged.
    ///
    /// `shared` is set for a `DeleteFile` with the shared-file flag and for every
    /// `DecrementSharedCount`.
    pub fn to_model(&self) -> Option<InnoRecord> {
        let path_target = |path: &str| {
            let path = strip_extended_prefix(path);
            (!path.is_empty()).then_some(Target::Path { path })
        };
        let (kind, target) = match &self.op {
            LogOp::DeleteFile { path } => (InnoRecordKind::DeleteFile, path_target(path)?),
            LogOp::DeleteDirOrFiles { path } => {
                let whole_tree = self.dir_deletes_subdirs();
                let one_item = !self.dir_is_dir();
                if !self.dir_deletes_files() || !(whole_tree || one_item) || has_wildcard(path) {
                    return None;
                }
                (InnoRecordKind::DeleteDirOrFiles, path_target(path)?)
            }
            LogOp::DeleteGroupOrItem { path } => {
                (InnoRecordKind::DeleteGroupOrItem, path_target(path)?)
            }
            LogOp::IniDeleteEntry { file, .. } => {
                (InnoRecordKind::IniDeleteEntry, path_target(file)?)
            }
            LogOp::IniDeleteSection { file, .. } => {
                (InnoRecordKind::IniDeleteSection, path_target(file)?)
            }
            LogOp::DecrementSharedCount { path } => {
                (InnoRecordKind::DecrementSharedCount, path_target(path)?)
            }
            LogOp::RegDeleteEntireKey { .. } => (
                InnoRecordKind::RegDeleteEntireKey,
                self.reg_target(RegKind::Key)?,
            ),
            LogOp::RegDeleteKeyIfEmpty { .. } => (
                InnoRecordKind::RegDeleteKeyIfEmpty,
                self.reg_target(RegKind::Key)?,
            ),
            LogOp::RegClearValue { value, .. } => (
                InnoRecordKind::RegClearValue,
                self.reg_target(RegKind::Value {
                    name: value.clone(),
                })?,
            ),
            LogOp::RegDeleteValue { value, .. } => (
                InnoRecordKind::RegDeleteValue,
                self.reg_target(RegKind::Value {
                    name: value.clone(),
                })?,
            ),
            LogOp::StartInstall { .. }
            | LogOp::EndInstall
            | LogOp::CompiledCode { .. }
            | LogOp::Run { .. }
            | LogOp::RefreshFileAssoc
            | LogOp::MutexCheck { .. }
            | LogOp::Raw { .. } => return None,
        };
        let key_create = matches!(
            kind,
            InnoRecordKind::RegDeleteEntireKey | InnoRecordKind::RegDeleteKeyIfEmpty
        ) && matches!(target, Target::RegKey { .. });
        Some(InnoRecord {
            kind,
            target,
            view: self.reg_view(),
            user_hive: matches!(self.op.reg_key(), Some((RegRoot::CurrentUser, _))),
            existed_before: self.existed_before_install(),
            shared: self.shared_file() || matches!(self.op, LogOp::DecrementSharedCount { .. }),
            key_create,
        })
    }

    /// The model target of a registry record.
    fn reg_target(&self, kind: RegKind) -> Option<Target> {
        let (root, subkey) = self.op.reg_key()?;
        let view = self.reg_view()?;
        let subkey = subkey.trim_matches('\\');
        // A record on a root key itself owns nothing that could be attributed.
        if subkey.is_empty() {
            return None;
        }
        let key_path = match root {
            RegRoot::LocalMachine => {
                let view = match strip_segments(subkey, &["SOFTWARE", "Classes"]) {
                    Some(below) => classes_view(view, below),
                    None => view,
                };
                return Some(TypedTarget::new(Hive::Hklm, view, subkey, kind).into());
            }
            // Machine-wide classes: where a write through the merged `HKCR` view lands by default.
            RegRoot::ClassesRoot => {
                let path = format!("SOFTWARE\\Classes\\{subkey}");
                let view = classes_view(view, subkey);
                return Some(TypedTarget::new(Hive::Hklm, view, path, kind).into());
            }
            RegRoot::CurrentUser => format!("HKCU\\{subkey}"),
            RegRoot::Users => format!("HKU\\{subkey}"),
            RegRoot::CurrentConfig | RegRoot::Other(_) => return None,
        };
        Some(match kind {
            RegKind::Value { name } => Target::RegValue {
                path: key_path,
                name,
            },
            _ => Target::RegKey { path: key_path },
        })
    }
}

/// Keys directly under `SOFTWARE\Classes` that WOW64 redirects for 32-bit programs (Microsoft's
/// "Registry Keys Affected by WOW64"). Every other key there is shared between the two views.
const REDIRECTED_CLASS_KEYS: [&str; 5] = [
    "CLSID",
    "DirectShow",
    "Interface",
    "Media Type",
    "MediaFoundation",
];

/// The view that addresses a key under `SOFTWARE\Classes`, given the logged view and the key path
/// below `Classes`: a shared key has one location, which is the 64-bit one.
fn classes_view(view: View, below_classes: &str) -> View {
    let first = below_classes.split('\\').next().unwrap_or_default();
    if REDIRECTED_CLASS_KEYS
        .iter()
        .any(|key| key.eq_ignore_ascii_case(first))
    {
        view
    } else {
        View::K64
    }
}

/// `path` without the leading `segments` (compared without regard to ASCII case); `None` when it does
/// not start with them. The remainder has no leading `\` and is empty when `path` is the prefix itself.
fn strip_segments<'a>(path: &'a str, segments: &[&str]) -> Option<&'a str> {
    let mut rest = path;
    for segment in segments {
        let (first, tail) = rest.split_once('\\').unwrap_or((rest, ""));
        if !first.eq_ignore_ascii_case(segment) {
            return None;
        }
        rest = tail;
    }
    Some(rest)
}

/// A file path without the extended-length prefix: `\\?\C:\x` becomes `C:\x` and `\\?\UNC\srv\share`
/// becomes `\\srv\share`. Other paths, including other `\\?\` forms (volume GUIDs), are kept.
fn strip_extended_prefix(path: &str) -> String {
    let Some(rest) = path.strip_prefix(r"\\?\") else {
        return path.to_owned();
    };
    if let Some(unc) = strip_segments(rest, &["UNC"])
        && !unc.is_empty()
    {
        return format!(r"\\{unc}");
    }
    let mut chars = rest.chars();
    let is_drive =
        chars.next().is_some_and(|c| c.is_ascii_alphabetic()) && chars.next() == Some(':');
    if is_drive {
        rest.to_owned()
    } else {
        path.to_owned()
    }
}

/// Whether a file path is a wildcard pattern (`*` or `?` outside the extended-length prefix).
fn has_wildcard(path: &str) -> bool {
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    path.contains(['*', '?'])
}

/// A parsed uninstall log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallLog {
    /// The header.
    pub header: LogHeader,
    /// The records, in file order (the uninstaller replays them last to first).
    pub records: Vec<LogRecord>,
    /// Things the parser kept but did not understand (unknown record types, unknown registry roots,
    /// bytes after the last record), for the fingerprint's warnings.
    pub warnings: Vec<String>,
}

impl UninstallLog {
    /// The records as model [`InnoRecord`]s, in file order; see [`LogRecord::to_model`] for what is
    /// left out. `HKCU` records are not yet bound to a user.
    ///
    /// When the install ran without administrative rights ([`LogHeader::is_admin_install`] is false),
    /// `HKEY_CLASSES_ROOT` records are left out as well: such an install cannot have created a key in
    /// the machine's classes, so the record may be about the user's classes hive, and mapping it to
    /// `HKLM\SOFTWARE\Classes` could attribute another install's key.
    ///
    /// The log has one set of records per install run (see the module documentation), so the result
    /// usually holds duplicates.
    pub fn model_records(&self) -> Vec<InnoRecord> {
        let admin = self.header.is_admin_install();
        self.records
            .iter()
            .filter(|record| {
                admin || !matches!(record.op.reg_key(), Some((RegRoot::ClassesRoot, _)))
            })
            .filter_map(LogRecord::to_model)
            .collect()
    }

    /// How many records are of an unknown type ([`LogOp::Raw`]).
    pub fn raw_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| matches!(r.op, LogOp::Raw { .. }))
            .count()
    }
}

/// Parses the bytes of an `unins*.dat` file.
///
/// # Errors
///
/// [`InnoLogError::Unsupported`] for a header version above [`MAX_SUPPORTED_VERSION`]; another
/// [`InnoLogError`] when the bytes are not a consistent log (see the module documentation).
pub fn parse(bytes: &[u8]) -> Result<UninstallLog, InnoLogError> {
    parse_with_limit(bytes, MAX_DECODED_SIZE)
}

/// [`parse`] with an explicit cap on the decoded stream size.
fn parse_with_limit(bytes: &[u8], limit: usize) -> Result<UninstallLog, InnoLogError> {
    let raw_header = reader::read_header(bytes)?;
    let stream = reader::read_stream(bytes, &raw_header, limit)?;
    let (raw_records, leftover) = reader::read_records(&stream, raw_header.num_recs)?;

    let mut warnings = Vec::new();
    let mut records = Vec::with_capacity(raw_records.len());
    for (index, raw) in raw_records.iter().enumerate() {
        let record = decode_record(index, raw)?;
        match &record.op {
            LogOp::Raw { typ, data } => warnings.push(format!(
                "record {index}: unknown record type {typ:#06x} ({} data bytes) kept undecoded",
                data.len()
            )),
            op => {
                if let Some((RegRoot::Other(handle), _)) = op.reg_key() {
                    warnings.push(format!(
                        "record {index}: unknown registry root handle {handle:#010x}"
                    ));
                }
            }
        }
        records.push(record);
    }
    if leftover > 0 {
        warnings.push(format!(
            "{leftover} bytes follow the last of the {} records",
            records.len()
        ));
    }
    Ok(UninstallLog {
        header: raw_header.header,
        records,
        warnings,
    })
}

/// Decodes one raw record into its typed form.
fn decode_record(index: usize, raw: &reader::RawRecord<'_>) -> Result<LogRecord, InnoLogError> {
    let typ = raw.typ;
    // Bookkeeping records. Their strings are informational and partly binary, so a string list this
    // parser cannot read is not an error for the log: the fields stay empty.
    match typ {
        0x10 | 0x11 => {
            let mut strings = reader::read_strings(index, raw.data)
                .unwrap_or_default()
                .into_iter();
            let op = if typ == 0x10 {
                LogOp::StartInstall {
                    computer_name: strings.next().unwrap_or_default(),
                    user_name: strings.next().unwrap_or_default(),
                    app_dir: strings.next().unwrap_or_default(),
                }
            } else {
                LogOp::EndInstall
            };
            return Ok(LogRecord {
                extra_data: raw.extra_data,
                op,
                trailing: strings.collect(),
            });
        }
        0x20 => {
            return Ok(LogRecord {
                extra_data: raw.extra_data,
                op: LogOp::CompiledCode {
                    data: raw.data.to_vec(),
                },
                trailing: Vec::new(),
            });
        }
        _ => {}
    }
    if !(0x80..=0x8C).contains(&typ) {
        return Ok(LogRecord {
            extra_data: raw.extra_data,
            op: LogOp::Raw {
                typ,
                data: raw.data.to_vec(),
            },
            trailing: Vec::new(),
        });
    }
    let strings = reader::read_strings(index, raw.data)?;
    let found = strings.len();
    let mut strings = strings.into_iter();
    // The first `needed` strings are required; `next` is only called after the count was checked or
    // for optional strings, where a missing one reads as empty.
    let require = |needed: usize| {
        if found < needed {
            Err(InnoLogError::MissingField {
                index,
                typ,
                needed,
                found,
            })
        } else {
            Ok(())
        }
    };
    let mut next = || strings.next().unwrap_or_default();
    let root = RegRoot::from_extra_data(raw.extra_data);
    let op = match typ {
        0x80 => {
            require(1)?;
            LogOp::Run {
                filename: next(),
                parameters: next(),
                working_dir: next(),
                run_once_id: next(),
                verb: next(),
            }
        }
        0x81 => {
            require(1)?;
            LogOp::DeleteDirOrFiles { path: next() }
        }
        0x82 => {
            require(1)?;
            LogOp::DeleteFile { path: next() }
        }
        0x83 => {
            require(1)?;
            LogOp::DeleteGroupOrItem { path: next() }
        }
        0x84 => {
            require(3)?;
            LogOp::IniDeleteEntry {
                file: next(),
                section: next(),
                entry: next(),
            }
        }
        0x85 => {
            require(2)?;
            LogOp::IniDeleteSection {
                file: next(),
                section: next(),
            }
        }
        0x86 => {
            require(1)?;
            LogOp::RegDeleteEntireKey {
                root,
                subkey: next(),
            }
        }
        0x87 => {
            require(2)?;
            LogOp::RegClearValue {
                root,
                subkey: next(),
                value: next(),
            }
        }
        0x88 => {
            require(1)?;
            LogOp::RegDeleteKeyIfEmpty {
                root,
                subkey: next(),
            }
        }
        0x89 => {
            require(2)?;
            LogOp::RegDeleteValue {
                root,
                subkey: next(),
                value: next(),
            }
        }
        0x8A => {
            require(1)?;
            LogOp::DecrementSharedCount { path: next() }
        }
        0x8B => LogOp::RefreshFileAssoc,
        _ => {
            require(1)?;
            LogOp::MutexCheck { names: next() }
        }
    };
    Ok(LogRecord {
        extra_data: raw.extra_data,
        op,
        trailing: strings.collect(),
    })
}
