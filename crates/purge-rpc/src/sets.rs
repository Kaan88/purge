//! Capability sets and transports (M3_DESIGN.md §6.2).
//!
//! | Set | Meaning | stdio engine | broker pipe |
//! |---|---|---|---|
//! | [`CapSet::Read`] | no side effect | yes | yes |
//! | [`CapSet::UserRun`] | starts the user's own uninstaller at the user's level | yes | no |
//! | [`CapSet::Propose`] | builds a plan in memory, no side effect on the machine | no | yes |
//! | [`CapSet::Execute`] | harvest store writes, broker-route uninstallers, everything behind a consent dialog | no | yes |
//!
//! A server is built for a [`Transport`], and the transport alone fixes its [`SetMask`]: there is no public
//! way to make a mask, so no server can be built for stdio with `Execute` or `Propose` in it, nor for the
//! pipe with `UserRun`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One capability set. Every method of the table is in exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CapSet {
    /// No side effect.
    Read,
    /// Starts the user's own uninstaller at the user's level (medium engine only).
    UserRun,
    /// Builds a plan in memory; no side effect on the machine (broker only).
    Propose,
    /// Harvest store writes, broker-route uninstallers and everything behind a consent dialog (broker
    /// only).
    Execute,
}

impl CapSet {
    /// Every set, in table order.
    pub const ALL: [CapSet; 4] = [
        CapSet::Read,
        CapSet::UserRun,
        CapSet::Propose,
        CapSet::Execute,
    ];

    const fn bit(self) -> u8 {
        match self {
            CapSet::Read => 1,
            CapSet::UserRun => 2,
            CapSet::Propose => 4,
            CapSet::Execute => 8,
        }
    }
}

/// The sets one transport may use. Only [`Transport::mask`] makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SetMask(u8);

impl SetMask {
    const fn of(sets: &[CapSet]) -> Self {
        let mut bits = 0;
        let mut i = 0;
        while i < sets.len() {
            bits |= sets[i].bit();
            i += 1;
        }
        Self(bits)
    }

    /// Whether `set` is in the mask.
    pub const fn contains(self, set: CapSet) -> bool {
        self.0 & set.bit() != 0
    }
}

/// A transport of the engine API, and so a server's kind. The MCP server and the CLI are not RPC
/// transports in M3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// `purge-engine --stdio`: the medium engine the UI starts at its own level.
    Stdio,
    /// The elevated broker's named pipe.
    Pipe,
}

/// Most bytes of one line into the broker, without the `\n` (§6.1).
pub const PIPE_IN_LIMIT: usize = 4 * 1024 * 1024;
/// Most bytes of one line into the stdio engine, without the `\n` (§6.1).
pub const STDIO_IN_LIMIT: usize = 64 * 1024;
/// Most bytes of one line a server writes, without the `\n` (§6.1).
pub const OUT_LIMIT: usize = 16 * 1024 * 1024;

impl Transport {
    /// Both transports.
    pub const ALL: [Transport; 2] = [Transport::Stdio, Transport::Pipe];

    /// The sets a server of this transport answers. Fixed here; nothing else makes a mask.
    pub const fn mask(self) -> SetMask {
        match self {
            Transport::Stdio => SetMask::of(&[CapSet::Read, CapSet::UserRun]),
            Transport::Pipe => SetMask::of(&[CapSet::Read, CapSet::Propose, CapSet::Execute]),
        }
    }

    /// Most bytes of one line a server of this transport reads; over it the server closes the transport.
    pub const fn in_limit(self) -> usize {
        match self {
            Transport::Stdio => STDIO_IN_LIMIT,
            Transport::Pipe => PIPE_IN_LIMIT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_follow_the_design_table() {
        let stdio = Transport::Stdio.mask();
        assert!(stdio.contains(CapSet::Read));
        assert!(stdio.contains(CapSet::UserRun));
        assert!(!stdio.contains(CapSet::Propose));
        assert!(!stdio.contains(CapSet::Execute));

        let pipe = Transport::Pipe.mask();
        assert!(pipe.contains(CapSet::Read));
        assert!(!pipe.contains(CapSet::UserRun));
        assert!(pipe.contains(CapSet::Propose));
        assert!(pipe.contains(CapSet::Execute));
    }

    #[test]
    fn limits() {
        assert_eq!(Transport::Pipe.in_limit(), 4 << 20);
        assert_eq!(Transport::Stdio.in_limit(), 64 << 10);
        assert_eq!(OUT_LIMIT, 16 << 20);
    }
}
