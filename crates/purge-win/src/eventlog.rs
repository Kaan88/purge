//! One line to the Application event log (`RegisterEventSourceW`, `ReportEventW`).
//!
//! The broker writes here when a start check fails, because no pipe exists yet to carry the reason
//! (M3 design 3.4), and its timing lines as information events (M3 design 9.1). The source name need
//! not be registered: Windows then files the event under the Application log with a note that the
//! source has no message file, and the line is still the event's one insertion string.
#![cfg(feature = "read")]

use std::ptr;

use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, REPORT_EVENT_TYPE,
    RegisterEventSourceW, ReportEventW,
};

use crate::os::{Win32Error, wide};

/// Writes `line` to the Application log as an error event of `source` with `event_id`.
pub fn report_error(source: &str, event_id: u32, line: &str) -> Result<(), Win32Error> {
    report(source, EVENTLOG_ERROR_TYPE, event_id, line)
}

/// Writes `line` to the Application log as an information event of `source` with `event_id`.
pub fn report_info(source: &str, event_id: u32, line: &str) -> Result<(), Win32Error> {
    report(source, EVENTLOG_INFORMATION_TYPE, event_id, line)
}

fn report(
    source: &str,
    kind: REPORT_EVENT_TYPE,
    event_id: u32,
    line: &str,
) -> Result<(), Win32Error> {
    let source = wide(source);
    let line = wide(line);
    // SAFETY: NUL-terminated source name; a null server name means the local machine.
    let log = unsafe { RegisterEventSourceW(ptr::null(), source.as_ptr()) };
    if log.is_null() {
        return Err(Win32Error::last());
    }
    let strings = [line.as_ptr()];
    // SAFETY: `log` is the handle just registered; one NUL-terminated string; no SID, no raw data.
    let ok = unsafe {
        ReportEventW(
            log,
            kind,
            0,
            event_id,
            ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            ptr::null(),
        )
    };
    let result = if ok == 0 {
        Err(Win32Error::last())
    } else {
        Ok(())
    };
    // SAFETY: `log` came from RegisterEventSourceW and is deregistered once.
    unsafe { DeregisterEventSource(log) };
    result
}
