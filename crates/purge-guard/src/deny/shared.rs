//! Shared components (`kb/shared-components.json`, ENGINE_PLAN.md §5.10): runtimes that many products
//! install or depend on. They are never leftovers of another app.
//!
//! This is a lookup, not part of [`super::check`]: whether a hit blocks depends on who is asking (the
//! runtime's own uninstall may remove it), so the index and the scanners decide.

use purge_model::Target;
use serde::{Deserialize, Serialize};

use super::pattern::{
    KeyBase, Rel, Seg, glob_match, parse_fs_pattern, parse_key_pattern, relate, split_fold,
};
use super::{RegLogical, key_of};
use crate::canon::{GuardEnv, canon_key, canon_path};
use crate::prefix::fold;

/// One shared component and the places it lives in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedComponent {
    /// Stable identifier, e.g. `webview2`.
    pub id: String,
    /// Display name.
    pub name: String,
    /// File patterns (deny-list pattern syntax); a hit is the item or anything below it.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Key patterns (deny-list pattern syntax); a hit is the key, anything below it, or a value in it.
    #[serde(default)]
    pub keys: Vec<String>,
    /// Globs over package full names or family names.
    #[serde(default)]
    pub packages: Vec<String>,
}

/// The components embedded from `kb/shared-components.json`.
pub fn shared_components() -> Result<Vec<SharedComponent>, serde_json::Error> {
    serde_json::from_str(include_str!("../../../../kb/shared-components.json"))
}

/// The shared components compiled for one `GuardEnv`.
#[derive(Debug, Clone)]
pub struct SharedComponents {
    env: GuardEnv,
    components: Vec<SharedComponent>,
    paths: Vec<(usize, Vec<Seg>)>,
    keys: Vec<(usize, KeyBase, Vec<Seg>)>,
}

impl SharedComponents {
    /// Compiles the embedded components.
    pub fn compile(env: &GuardEnv) -> Result<SharedComponents, String> {
        let components =
            shared_components().map_err(|e| format!("kb/shared-components.json: {e}"))?;
        SharedComponents::with_data(env, components)
    }

    /// Compiles the given components.
    pub fn with_data(
        env: &GuardEnv,
        components: Vec<SharedComponent>,
    ) -> Result<SharedComponents, String> {
        // Patterns are expanded from, and targets canonicalised against, the canonical facts.
        let env = &env.normalised()?;
        let mut paths = Vec::new();
        let mut keys = Vec::new();
        for (index, component) in components.iter().enumerate() {
            for pattern in &component.paths {
                paths.extend(
                    parse_fs_pattern(pattern, env)?
                        .into_iter()
                        .map(|segs| (index, segs)),
                );
            }
            for pattern in &component.keys {
                let (base, segs) = parse_key_pattern(pattern)?;
                keys.push((index, base, segs));
            }
        }
        Ok(SharedComponents {
            env: env.clone(),
            components,
            paths,
            keys,
        })
    }

    /// Every component, in file order.
    pub fn components(&self) -> &[SharedComponent] {
        &self.components
    }

    /// The shared component a target belongs to, if any. The first component in file order wins, so the
    /// file lists the more specific component first. A target that does not canonicalise belongs to none.
    pub fn find(&self, target: &Target) -> Option<&SharedComponent> {
        let hit = |rel: Option<Rel>| matches!(rel, Some(Rel::Exact | Rel::Inside));
        let index = match target {
            Target::Path { path } => {
                let segs = split_fold(&canon_path(path, &self.env, None).ok()?.path);
                self.paths
                    .iter()
                    .filter(|(_, pattern)| hit(relate(pattern, &segs)))
                    .map(|(index, _)| *index)
                    .min()
            }
            Target::AppxPackage { full_name } => {
                let name = fold(full_name);
                self.components
                    .iter()
                    .position(|c| c.packages.iter().any(|glob| glob_match(&fold(glob), &name)))
            }
            other => {
                let key = canon_key(key_of(other)?, None, &self.env, None).ok()?;
                let logical = RegLogical::new(key);
                self.keys
                    .iter()
                    .filter(|(_, base, pattern)| {
                        logical
                            .segs_for(*base)
                            .is_some_and(|segs| hit(relate(pattern, segs)))
                    })
                    .map(|(index, _, _)| *index)
                    .min()
            }
        }?;
        self.components.get(index)
    }
}
