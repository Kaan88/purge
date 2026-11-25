//! The History and Quarantine pages on the engine and the broker (UI-PAGES2): their models'
//! requests turned into calls, and the answers routed back. It is the same seam as the Programs
//! page's in [`super`]: each call is kept with what its answer is for, and the one broker session
//! is taken from the [`BrokerHub`](super::BrokerHub) as [`Owner::History`] or [`Owner::Vault`].
//!
//! Each page reads `history.index` from the medium engine every time it is shown; nothing on
//! opening a page starts the broker. A page that is left while idle gives its broker back, so the
//! other pages can have it.
//!
//! Launches go through [`Link::launch_for`] (link/flow.rs): the first-elevation explanation
//! first (History's reads say they only read; its restore and rollback do not), then the Windows
//! prompt; its answer comes back in
//! [`Link::pages_launched`].
//!
//! **With sample data** no real broker is started (the flow's sample session stands in), the read
//! calls (`history.get`, `journal.pending`, `quarantine.expiring`) are answered from
//! [`purge_client::sample_history`], and every call that would change the PC (`undo.run`,
//! `journal.resume`, `journal.rollback`, `quarantine.purge`) answers
//! [`purge_client::sample::NOT_LIVE`].

use std::collections::HashMap;

use purge_client::sample::NOT_LIVE;
use purge_client::{Answer, CallId, ClientError, sample_history};
use purge_rpc::methods::{NoParams, PipeCall, StdioCall};
use purge_ui_model::CallError;
use purge_ui_model::broker_link::BrokerLaunch;
use purge_ui_model::history::HistoryCall;
use purge_ui_model::pipeline::{LaunchResult, LaunchState};
use purge_ui_model::vault::VaultCall;

use super::{Link, Owner, call_error, failure, no_session};
use crate::model::{Mode, Model, Page};

/// What a History or Quarantine call in flight is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    HistoryIndex,
    HistoryGet,
    HistoryUndo,
    HistoryRecover,
    HistoryPending,
    VaultIndex,
    VaultUndo,
    VaultExpiring,
    VaultPurge,
}

/// The two pages' share of the link.
#[derive(Default)]
pub struct Pages {
    pending: HashMap<CallId, Call>,
    /// The page the last pump saw, to read a page's list when it is shown.
    shown: Option<Page>,
}

impl Link {
    /// The page shown changed: read its list (and give back an idle broker of the page left).
    /// Then sends what the two models asked for. True when anything was sent.
    pub(super) fn pages_pump(&mut self, model: &mut Model) -> bool {
        let mut busy = false;
        if self.engine.is_some() && self.pages.shown != Some(model.page) {
            let left = self.pages.shown.replace(model.page);
            match left {
                Some(Page::History) if !model.history.page.busy() => {
                    let r = model.history.page.close();
                    model.history.take(r);
                }
                Some(Page::Quarantine) if !model.quarantine.page.busy() => {
                    model.quarantine.flyout = None;
                    let r = model.quarantine.page.close();
                    model.quarantine.take(r);
                }
                _ => {}
            }
            match model.page {
                Page::History => {
                    let r = model.history.page.load();
                    model.history.take(r);
                }
                Page::Quarantine => {
                    let r = model.quarantine.page.load();
                    model.quarantine.take(r);
                }
                _ => {}
            }
        }
        for call in std::mem::take(&mut model.history.out) {
            self.history_call(model, call);
            busy = true;
        }
        for call in std::mem::take(&mut model.quarantine.out) {
            self.vault_call(model, call);
            busy = true;
        }
        busy
    }

    // ---- requests ----------------------------------------------------------------------------

    fn history_call(&mut self, model: &mut Model, call: HistoryCall) {
        let owner = Owner::History;
        match call {
            HistoryCall::ReadIndex => {
                if let Err(e) = self.index(Call::HistoryIndex) {
                    let clock = model.history.tick_clock();
                    let r = model.history.page.on_index(Err(e), &clock);
                    model.history.take(r);
                }
            }
            // The explanation says "only reads" for History's reads, never before a restore or
            // a rollback (the WinUI `LaunchIsReadOnly`).
            HistoryCall::Launch { read_only } => self.launch_for(model, owner, read_only),
            HistoryCall::DropBroker => self.drop_broker(owner),
            HistoryCall::AllowForeground => self.allow_foreground(owner),
            HistoryCall::Get(p) => {
                self.pages_broker_call(model, PipeCall::HistoryGet(p), Call::HistoryGet)
            }
            HistoryCall::Undo(p) => {
                self.pages_broker_call(model, PipeCall::UndoRun(p), Call::HistoryUndo)
            }
            HistoryCall::Resume(p) => {
                self.pages_broker_call(model, PipeCall::JournalResume(p), Call::HistoryRecover)
            }
            HistoryCall::Rollback(p) => {
                self.pages_broker_call(model, PipeCall::JournalRollback(p), Call::HistoryRecover)
            }
            HistoryCall::Pending => self.pages_broker_call(
                model,
                PipeCall::JournalPending(NoParams {}),
                Call::HistoryPending,
            ),
        }
    }

    fn vault_call(&mut self, model: &mut Model, call: VaultCall) {
        let owner = Owner::Vault;
        match call {
            VaultCall::ReadIndex => {
                if let Err(e) = self.index(Call::VaultIndex) {
                    let clock = model.quarantine.tick_clock();
                    model.quarantine.page.on_index(Err(e), &clock);
                    model.quarantine.sync();
                }
            }
            VaultCall::Launch => self.launch_for(model, owner, false),
            VaultCall::DropBroker => self.drop_broker(owner),
            VaultCall::AllowForeground => self.allow_foreground(owner),
            VaultCall::Undo(p) => {
                self.pages_broker_call(model, PipeCall::UndoRun(p), Call::VaultUndo)
            }
            VaultCall::Expiring(p) => {
                self.pages_broker_call(model, PipeCall::QuarantineExpiring(p), Call::VaultExpiring)
            }
            VaultCall::Purge(p) => {
                self.pages_broker_call(model, PipeCall::QuarantinePurge(p), Call::VaultPurge)
            }
        }
    }

    /// `history.index` on the medium engine; the page's answer when there is none to ask. After
    /// an engine failure (`Fallback`) the engine is the sample's, whose made-up cleanups are never
    /// listed: the page gets the engine-failure notice and its list stays empty (review SF5).
    fn index(&mut self, what: Call) -> Result<(), CallError> {
        if let Mode::Fallback(notice) = &self.mode {
            return Err(call_error(ClientError::NotAvailable(notice.clone())));
        }
        let Some(engine) = &self.engine else {
            return Err(no_engine());
        };
        let id = engine.request(StdioCall::HistoryIndex(NoParams {}));
        self.pages.pending.insert(id, what);
        Ok(())
    }

    fn drop_broker(&mut self, owner: Owner) {
        self.broker.close(owner);
    }

    fn allow_foreground(&self, owner: Owner) {
        if let Some(session) = self.broker.session(owner) {
            session.allow_foreground();
        }
    }

    fn pages_broker_call(&mut self, model: &mut Model, call: PipeCall, what: Call) {
        match &self.mode {
            // `--sample`: the sample's reads, every change refused.
            Mode::Sample => {
                let answer = sample_answer(&call);
                self.pages_answer(model, what, answer);
                return;
            }
            // Not started yet, or the engine failed: nothing is sent, and the page says why.
            Mode::Starting | Mode::Fallback(_) => {
                let reason = self.mode.refusal().unwrap_or_default().to_owned();
                let answer = Err(ClientError::NotAvailable(reason));
                self.pages_answer(model, what, answer);
                return;
            }
            Mode::Live => {}
        }
        let owner = match what {
            Call::VaultUndo | Call::VaultExpiring | Call::VaultPurge => Owner::Vault,
            _ => Owner::History,
        };
        match self.broker.session(owner).cloned() {
            Some(session) => {
                let id = session.request(call);
                self.pages.pending.insert(id, what);
            }
            None => self.pages_answer(
                model,
                what,
                Err(ClientError::Link {
                    reason: no_session().message().to_owned(),
                    not_sent: true,
                }),
            ),
        }
    }

    // ---- events ------------------------------------------------------------------------------

    /// A reply for one of these pages: handled, `None`; another's, given back.
    pub(super) fn pages_reply(
        &mut self,
        model: &mut Model,
        call: CallId,
        result: Result<Answer, ClientError>,
    ) -> Option<Result<Answer, ClientError>> {
        match self.pages.pending.remove(&call) {
            Some(what) => {
                self.pages_answer(model, what, result);
                None
            }
            None => Some(result),
        }
    }

    /// A `progress` notification of a call of these pages (the undo's phase).
    pub(super) fn pages_progress(
        &mut self,
        model: &mut Model,
        call: CallId,
        progress: &purge_rpc::methods::Progress,
    ) -> bool {
        match self.pages.pending.get(&call) {
            Some(Call::HistoryUndo) => model.history.page.on_progress(progress),
            Some(Call::VaultUndo) => model.quarantine.page.on_progress(progress),
            Some(_) => {}
            None => return false,
        }
        true
    }

    /// `owner`'s broker link ended (or was taken for another page).
    pub(super) fn pages_broker_closed(&mut self, model: &mut Model, owner: Owner) {
        match owner {
            Owner::History => model.history.page.on_broker_ended(),
            Owner::Vault => model.quarantine.page.on_broker_ended(),
            _ => {}
        }
    }

    /// A launch for one of these pages ended (`Err`: Purge stopped it).
    pub(super) fn pages_launched(
        &mut self,
        model: &mut Model,
        owner: Owner,
        answer: Result<LaunchResult, CallError>,
    ) {
        let launch = match answer {
            Ok(l) => match l.state {
                LaunchState::Started => BrokerLaunch::started(),
                LaunchState::Cancelled if l.declined_explanation => BrokerLaunch::declined(),
                LaunchState::Cancelled => BrokerLaunch::cancelled(l.message),
                _ => BrokerLaunch::failed(l.message),
            },
            Err(_) => BrokerLaunch::cancelled(""),
        };
        match owner {
            Owner::History => {
                let r = model.history.page.on_launch(launch);
                model.history.take(r);
            }
            Owner::Vault => {
                let r = model.quarantine.page.on_launch(launch);
                model.quarantine.take(r);
            }
            _ => {}
        }
    }

    fn pages_answer(&mut self, model: &mut Model, what: Call, result: Result<Answer, ClientError>) {
        let h = &mut model.history;
        let q = &mut model.quarantine;
        match (what, result) {
            (Call::HistoryIndex, Ok(Answer::HistoryIndex(i))) => {
                let clock = h.tick_clock();
                let r = h.page.on_index(Ok(i), &clock);
                h.take(r);
            }
            (Call::HistoryIndex, r) => {
                let clock = h.tick_clock();
                let r = h.page.on_index(Err(failure(r)), &clock);
                h.take(r);
            }
            (Call::HistoryGet, Ok(Answer::HistoryDetail(d))) => {
                let r = h.page.on_items(Ok(d));
                h.take(r);
            }
            (Call::HistoryGet, r) => {
                let r = h.page.on_items(Err(failure(r)));
                h.take(r);
            }
            (Call::HistoryUndo, Ok(Answer::Undo(u))) => {
                let r = h.page.on_undone(Ok(u));
                h.take(r);
            }
            (Call::HistoryUndo, r) => {
                let r = h.page.on_undone(Err(failure(r)));
                h.take(r);
            }
            (Call::HistoryRecover, Ok(Answer::Outcome(o))) => {
                let r = h.page.on_recovered(Ok(o));
                h.take(r);
            }
            (Call::HistoryRecover, r) => {
                let r = h.page.on_recovered(Err(failure(r)));
                h.take(r);
            }
            (Call::HistoryPending, Ok(Answer::Pending(p))) => {
                let r = h.page.on_pending(Ok(p));
                h.take(r);
            }
            (Call::HistoryPending, r) => {
                let r = h.page.on_pending(Err(failure(r)));
                h.take(r);
            }
            (Call::VaultIndex, r) => {
                let clock = q.tick_clock();
                let answer = match r {
                    Ok(Answer::HistoryIndex(i)) => Ok(i),
                    r => Err(failure(r)),
                };
                q.page.on_index(answer, &clock);
                q.sync();
            }
            (Call::VaultUndo, Ok(Answer::Undo(u))) => {
                let r = q.page.on_undone(Ok(u));
                q.take(r);
            }
            (Call::VaultUndo, r) => {
                let r = q.page.on_undone(Err(failure(r)));
                q.take(r);
            }
            (Call::VaultExpiring, r) => {
                let clock = q.tick_clock();
                let answer = match r {
                    Ok(Answer::Expiring(e)) => Ok(e),
                    r => Err(failure(r)),
                };
                let r = q.page.on_expiring(answer, &clock);
                q.take(r);
            }
            (Call::VaultPurge, Ok(Answer::Purge(p))) => {
                let r = q.page.on_purged(Ok(p));
                q.take(r);
            }
            (Call::VaultPurge, r) => {
                let r = q.page.on_purged(Err(failure(r)));
                q.take(r);
            }
        }
    }
}

fn no_engine() -> CallError {
    call_error(ClientError::NotAvailable(
        "Purge's engine is not running.".into(),
    ))
}

/// The sample's answer to a broker call: the reads from the sample's cleanups, every change
/// refused.
fn sample_answer(call: &PipeCall) -> Result<Answer, ClientError> {
    match call {
        PipeCall::HistoryGet(p) => match sample_history::detail(&p.session) {
            Some(d) => Ok(Answer::HistoryDetail(d)),
            None => Err(ClientError::NotAvailable(NOT_LIVE.into())),
        },
        PipeCall::JournalPending(_) => Ok(Answer::Pending(sample_history::pending())),
        PipeCall::QuarantineExpiring(p) => Ok(Answer::Expiring(sample_history::expiring(p))),
        _ => Err(ClientError::NotAvailable(NOT_LIVE.into())),
    }
}

#[cfg(test)]
mod tests;
