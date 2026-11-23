//! The broker's request handler as the binary wires it: every package's methods behind one
//! [`Handler`] (M3-EXEC; the dispatch of `uninstall.*`, `leftovers.*`, `scan.*`, `candidate.*` and
//! `plan.create` is [`Flow`], `quarantine.*` is [`Purger`], `history.get`, `undo.run` and `journal.*`
//! are [`UndoMethods`], `plan.execute` is [`crate::execute`]).
//!
//! Order of the dispatch: the purge methods, then the history, undo and recovery methods, then
//! `plan.execute`, then the flow. `plan.execute` asks [`UndoMethods::check_nothing_pending`] before
//! its dialog: an interrupted session comes first. A `plan.execute` with `delete_after` hands its
//! second step to [`Purger::delete_after_run`] once the run is recorded.

use std::sync::Arc;

use purge_rpc::error::ErrorObject;
use purge_rpc::methods::PipeCall;
use serde_json::Value;

use crate::backend::Backend;
use crate::execute::{self, ExecBackend};
use crate::purge::Purger;
use crate::serve::{Ctx, Handler};
use crate::undo::UndoMethods;
use crate::uninstall::{Flow, FlowHandler, Session};

/// Every method of the broker over its parts.
pub struct BrokerHandler<B: Backend> {
    flow: Flow,
    purge: Purger,
    undo: UndoMethods<B>,
    exec: Arc<dyn ExecBackend>,
}

impl<B: Backend> BrokerHandler<B> {
    /// The handler over its parts.
    pub fn new(
        flow: Flow,
        purge: Purger,
        undo: UndoMethods<B>,
        exec: Arc<dyn ExecBackend>,
    ) -> Self {
        Self {
            flow,
            purge,
            undo,
            exec,
        }
    }
}

impl<B: Backend> BrokerHandler<B> {
    /// Runs one request. Generic over the handler's tables so that a test can wrap this handler in its
    /// own (to keep the plans it made) and still get these methods.
    pub fn dispatch<H: FlowHandler>(
        &self,
        ctx: &Ctx<'_, H>,
        call: PipeCall,
    ) -> Result<Value, ErrorObject> {
        if let Some(result) = self.purge.handle(ctx, &call) {
            return result;
        }
        if UndoMethods::<B>::handles(&call) {
            return self.undo.call(ctx, call);
        }
        if let PipeCall::PlanExecute(params) = call {
            return execute::run(
                ctx,
                &*self.exec,
                &|| self.undo.check_nothing_pending(),
                &|session| self.purge.delete_after_run(ctx, session),
                params,
            );
        }
        self.flow.dispatch(ctx, call)
    }
}

impl<B: Backend> Handler for BrokerHandler<B> {
    type Session = Session;
    type Scan = crate::scan::Scan;
    type Plan = crate::plan::Plan;

    fn call(&self, ctx: &Ctx<'_, Self>, call: PipeCall) -> Result<Value, ErrorObject> {
        self.dispatch(ctx, call)
    }
}
