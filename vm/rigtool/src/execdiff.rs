//! Executed-effects check: escape and collateral (M2-RIG-EXECDIFF).
//!
//! Stub from M2-S0; the owning package fills it.

use crate::err::{Result, bail};

/// `rigtool execdiff`: not implemented yet.
pub fn cmd_execdiff(_args: &[String]) -> Result<()> {
    bail!("execdiff is not implemented yet")
}
