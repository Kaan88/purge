//! The elevated broker's library half (M3 design 3.3 to 3.6, package M3-BROKER-CORE): start checks,
//! the pipe server and its client check, the in-memory tables, one mutating request at a time, and
//! the rules for when the broker ends. Generic over the transport, the consent dialog, the machine
//! and the request handler; `main.rs` wires the real ones. The methods themselves come with later
//! packages and plug in as a [`serve::Handler`].
//!
//! | Module | What |
//! |---|---|
//! | [`start`] | the start checks of design 3.4 |
//! | [`args`] | `--pipe`, `--parent`, `--parent-ctime` |
//! | [`link`] | the transport trait and the refusal reasons |
//! | [`serve`] | accept and check a client, `engine.hello` first, the request loop, [`serve::Handler`], [`serve::Consent`] |
//! | [`session`] | the session, scan and plan tables and their `gone` |
//! | [`lifetime`] | clock, parent, exit reasons and codes, the consent closer |
//! | [`baseline`] | the local-baseline build as the loop sees it, `engine.hello` from the live machine |
//! | [`consent`] | the consent view model and the dialog, four variants |
//! | [`purge`] | `quarantine.expiring` and `quarantine.purge` through the purge dialog |
//! | [`wire`] | the named pipe, the TaskDialog and the parent handle |
//! | [`timing`] | the timing marks of design 9.1 (gate G12): on four results and in the event log |
//!
//! There is no cargo feature: the scripted fakes of the tests exist only under `cfg(test)`.

// M3-UNDO: `history.get`, `undo.run` and the `journal.*` methods ([`undo::UndoMethods`]) over a
// [`backend::Backend`]; [`live::LiveBackend`] is the real one.
// M3-EXEC: `plan.execute` ([`execute`], the real executor is [`exec_live::LiveExec`]) and the handler that
// puts every package's methods behind one dispatch ([`broker::BrokerHandler`]).
pub mod backend;
pub mod broker;
pub mod exec_live;
#[cfg(test)]
mod exec_tests;
pub mod execute;
pub mod history;
pub mod live;
pub mod live_host;
pub mod recover;
pub mod undo;
#[cfg(test)]
mod undo_tests;

pub mod args;
pub mod baseline;
pub mod consent;
pub mod lifetime;
pub mod link;
pub mod plan;
pub mod purge;
pub mod scan;
pub mod serve;
pub mod session;
pub mod start;
pub mod timing;
pub mod uninstall;
pub mod wire;

#[cfg(test)]
mod flow_tests;
#[cfg(test)]
mod testkit;
#[cfg(test)]
mod timing_tests;
