//! A reference to an inventory entry: which app a candidate, fingerprint or run belongs to.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ProgramId;

/// The app something belongs to: its stable id plus the name to show.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct AppRef {
    /// The app's inventory id.
    pub program_id: ProgramId,
    /// The ARP `DisplayName` at the time of the reference (the key name when the entry has none).
    pub display_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn app_ref_round_trips() {
        let v = json!({"program_id": "HKLM|64|Git_is1", "display_name": "Git"});
        let app: AppRef = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(app.program_id.key_name(), "Git_is1");
        assert_eq!(serde_json::to_value(&app).unwrap(), v);
        assert!(
            serde_json::from_value::<AppRef>(json!({"program_id": "Git", "display_name": "Git"}))
                .is_err()
        );
        assert!(schemars::schema_for!(AppRef).as_object().is_some());
    }
}
