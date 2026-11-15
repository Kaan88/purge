# Source this: Windows (gnullvm) cross-build environment for Purge. Does not change the repo.
export PATH="$HOME/.cargo/bin:$HOME/opt/llvm-mingw-20261104-ucrt-ubuntu-22.04-x86_64/bin:$PATH"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER=x86_64-w64-mingw32-clang
export CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_RUSTFLAGS="-C target-feature=+crt-static"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_RUNNER=wine
export WINEDEBUG=-all
export WINEPREFIX="$HOME/purge-target/wineprefix"
