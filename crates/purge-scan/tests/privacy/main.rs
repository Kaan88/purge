//! M1B-S-PRIVACY: the REG-PRIVACY scanner, called directly (it is not in the catalog yet). Every source
//! is a fixture; the shared data is read over it as the pipeline reads it, and the real policy bands
//! what the scanner returns.

mod budget;
mod hostile;
mod stores;
mod ufh;
mod world;
