//! Tests of the MSI registry scanners (M1B-S-MSIREG): REG-ARP-MSI, REG-INSTFOLDERS and REG-SHAREDDLLS.
//! Every source is a fixture built in `world.rs`; the scanners are called directly through the sealing
//! driver (they are not in the catalog yet).

mod arp_msi;
mod instfolders;
mod shareddlls;
mod world;
