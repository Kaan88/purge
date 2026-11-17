//! SYS-BURNDEPS and FS-PKGCACHE tests (M1B-S-BURN). Every source is a fixture:
//! `tests/data/burn/machine.json` holds the dependency records and Package Cache directories of a removed
//! Burn bundle "App Bundle" (`{B0B0...}`, provider key `AppBundle`) and its packages:
//!
//! | package | provider key | product | state |
//! |---|---|---|---|
//! | core | `AppBundle_Core` | `{C0C0...}` | gone |
//! | Python Launcher | `{73831AC2-...}` | the same | installed, kept by nobody else |
//! | VC++ runtime | `Microsoft.VS.VC_RuntimeMinimumVSU_amd64,v14` | `{D0D0...}` | installed (a shared component) |
//! | trap `burn-shared-package` | `PurgeTrapPkg` | `{E0E0...}` | gone; another bundle depends on it since the harvest |
//! | per-user part | `AppBundle_User` (in the user's Classes) | `{F0F0...}` | gone |
//!
//! Each test changes what it needs and records what the harvest would have recorded.

mod burndeps;
mod pkgcache;
mod world;
