//! Evidence scope: which kind of target a piece of evidence may support (ENGINE_PLAN.md §5.2, §5.3).
//!
//! Evidence about a value never proves ownership of the key that holds it, and the other way round. The
//! Safe band needs Tier A evidence whose scope equals the scope of the candidate's target (§5.8.2).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::Target;

/// The kind of target a piece of evidence speaks about.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum Scope {
    /// One registry value, or one segment of a value.
    Value,
    /// A registry key with its subtree.
    Key,
    /// A file or directory.
    Path,
    /// An AppX/MSIX package.
    Package,
}

impl Scope {
    /// Every scope, in declaration order.
    pub const ALL: [Scope; 4] = [Scope::Value, Scope::Key, Scope::Path, Scope::Package];

    /// The scope of a target, i.e. the scope evidence must have to support it.
    ///
    /// `None` for services, tasks and firewall rules: no M1a evidence kind attributes them, and they are
    /// removed through their own APIs (M1b).
    pub fn of(target: &Target) -> Option<Scope> {
        match target {
            Target::Path { .. } => Some(Scope::Path),
            Target::RegKey { .. } => Some(Scope::Key),
            Target::RegValue { .. }
            | Target::RegValueChanged { .. }
            | Target::RegMultiSzSegment { .. } => Some(Scope::Value),
            Target::AppxPackage { .. } => Some(Scope::Package),
            Target::Service { .. } | Target::Task { .. } | Target::FirewallRule { .. } => None,
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Scope::Value => 1,
            Scope::Key => 2,
            Scope::Path => 4,
            Scope::Package => 8,
        }
    }
}

/// A set of scopes: the scopes an evidence kind may be recorded with (the Scope column of §5.3).
///
/// A constant of the model, not part of any document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopeSet(u8);

impl ScopeSet {
    /// Value only.
    pub const VALUE: ScopeSet = ScopeSet::of(&[Scope::Value]);
    /// Key only.
    pub const KEY: ScopeSet = ScopeSet::of(&[Scope::Key]);
    /// Path only.
    pub const PATH: ScopeSet = ScopeSet::of(&[Scope::Path]);
    /// Package only.
    pub const PACKAGE: ScopeSet = ScopeSet::of(&[Scope::Package]);
    /// Path or key.
    pub const PATH_KEY: ScopeSet = ScopeSet::of(&[Scope::Path, Scope::Key]);
    /// Value or key.
    pub const VALUE_KEY: ScopeSet = ScopeSet::of(&[Scope::Value, Scope::Key]);
    /// Path, key or value.
    pub const PATH_KEY_VALUE: ScopeSet = ScopeSet::of(&[Scope::Path, Scope::Key, Scope::Value]);
    /// Every scope ("as recorded" and "any" in §5.3).
    pub const ANY: ScopeSet = ScopeSet::of(&Scope::ALL);

    /// The set holding exactly `scopes`.
    pub const fn of(scopes: &[Scope]) -> ScopeSet {
        let mut bits = 0;
        let mut i = 0;
        while i < scopes.len() {
            bits |= scopes[i].bit();
            i += 1;
        }
        ScopeSet(bits)
    }

    /// Whether `scope` is in the set.
    pub const fn contains(self, scope: Scope) -> bool {
        self.0 & scope.bit() != 0
    }

    /// The scopes of the set, in declaration order.
    pub fn iter(self) -> impl Iterator<Item = Scope> {
        Scope::ALL.into_iter().filter(move |s| self.contains(*s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_of_each_target_type() {
        let p = || "x".to_owned();
        assert_eq!(Scope::of(&Target::Path { path: p() }), Some(Scope::Path));
        assert_eq!(Scope::of(&Target::RegKey { path: p() }), Some(Scope::Key));
        assert_eq!(
            Scope::of(&Target::RegValue {
                path: p(),
                name: p()
            }),
            Some(Scope::Value)
        );
        assert_eq!(
            Scope::of(&Target::RegMultiSzSegment {
                path: p(),
                name: p(),
                segment: p(),
                index: None
            }),
            Some(Scope::Value)
        );
        assert_eq!(
            Scope::of(&Target::AppxPackage { full_name: p() }),
            Some(Scope::Package)
        );
        assert_eq!(Scope::of(&Target::Service { name: p() }), None);
        assert_eq!(Scope::of(&Target::Task { path: p() }), None);
        assert_eq!(Scope::of(&Target::FirewallRule { id: p() }), None);
    }

    #[test]
    fn scope_sets() {
        assert!(ScopeSet::PATH_KEY.contains(Scope::Path));
        assert!(ScopeSet::PATH_KEY.contains(Scope::Key));
        assert!(!ScopeSet::PATH_KEY.contains(Scope::Value));
        assert_eq!(
            ScopeSet::VALUE_KEY.iter().collect::<Vec<_>>(),
            [Scope::Value, Scope::Key]
        );
        assert_eq!(ScopeSet::ANY.iter().count(), 4);
        assert_eq!(ScopeSet::of(&[]).iter().count(), 0);
    }

    #[test]
    fn scope_round_trips() {
        for s in Scope::ALL {
            let v = serde_json::to_value(s).unwrap();
            assert_eq!(serde_json::from_value::<Scope>(v).unwrap(), s);
        }
        assert!(schemars::schema_for!(Scope).as_object().is_some());
    }
}
