//! M1B-S-DIAG: the REG-DIAG (Tracing, EventLog sources) and FS-WER scanners, called directly (they are
//! not in the catalog yet). Every source is a fixture; the shared reference walk runs over it as the
//! pipeline runs it.

mod budget;
mod eventlog;
mod tracing;
mod wer;
mod world;
