//! M1B-S-COM: the COM-CLASS and COM-INTERFACE scanners, called directly (they are not in the catalog
//! yet). Every source is a fixture; the shared reference walk runs over it as the pipeline runs it.

mod class;
mod iface;
#[path = "../shared/l5.rs"]
mod l5;
mod other;
mod world;
