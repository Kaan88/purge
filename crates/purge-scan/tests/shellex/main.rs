//! M1B-S-SHELLEX: the COM-SHELLEX scanner, called directly (it is not in the catalog yet). Every
//! source is a fixture; the shared reference walk runs over it as the pipeline runs it.

mod budget;
mod handlers;
#[path = "../shared/l5.rs"]
mod l5;
mod lists;
mod world;
