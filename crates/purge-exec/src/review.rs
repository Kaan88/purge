//! What a caller must be able to show the user before it undoes, recovers or retries a session
//! (M3-UNDO).
//!
//! [`undo::preview`](crate::undo::preview) and [`recover::preview`](crate::recover::preview) read the
//! session the way the run itself will, and say which ops the run covers, drawn from the session's own
//! scan copy and journal. The run is then started with the mark of the journal that was read
//! ([`undo::undo_expecting`](crate::undo::undo_expecting),
//! [`recover::resume_expecting`](crate::recover::resume_expecting), ...): when the journal is not the
//! one the dialog described, nothing is done. This module has the two checks both previews share.

use purge_model::exec::op::OpId;

use crate::execute;
use crate::journal::JournalState;
use crate::plan_in::{self, BoundPlan};
use crate::storage::SessionDir;

/// The session's plan, bound again from its own copy of the scan document and its journal (the
/// copy hashes to the journal header's plan hash, and the journalled ids to its selection hash).
///
/// # Errors
///
/// The text of why the plan cannot be bound again.
pub fn bind_session(session: &SessionDir, state: &JournalState) -> Result<BoundPlan, String> {
    let scan = execute::read_scan_copy(session).map_err(|e| e.to_string())?;
    plan_in::rebind_interrupted(&scan, state).map_err(|e| e.to_string())
}

/// Every op of `ops` is an op of the plan, and the journal's intent for it, when it has one, acts on
/// what the bound plan says: the dialog is drawn from the plan's ops, the run acts on the journal's.
///
/// # Errors
///
/// The text of the first op for which they disagree.
pub fn check_intents(plan: &BoundPlan, state: &JournalState, ops: &[OpId]) -> Result<(), String> {
    for op in ops {
        let item = plan
            .item(*op)
            .ok_or_else(|| format!("op {op} is not an item of the plan"))?;
        let journalled = state.op(*op).and_then(|op| op.intent.as_ref());
        if let Some(intent) = journalled
            && item.exec_op.as_ref() != Some(&intent.exec_op)
        {
            return Err(format!(
                "op {op}: the journal and the plan disagree about what it acts on"
            ));
        }
    }
    Ok(())
}
