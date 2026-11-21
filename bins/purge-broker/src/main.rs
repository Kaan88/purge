//! `purge-broker` entry point (M3 design, package M3-S0). Runs the start checks of design 3.4
//! (`purge_broker::start`); after them it is still a stub and exits with code 1.

fn main() -> std::process::ExitCode {
    if let Err(failure) = purge_broker::start::restrict_dll_search() {
        failure.report();
        return std::process::ExitCode::from(failure.exit_code());
    }
    match purge_broker::start::check() {
        Err(failure) => {
            failure.report();
            std::process::ExitCode::from(failure.exit_code())
        }
        Ok(started) => {
            eprintln!(
                "purge-broker: start checks passed (install {}, data root {}); not implemented",
                started.install_dir.display(),
                started.data_root.display()
            );
            std::process::ExitCode::from(1)
        }
    }
}
