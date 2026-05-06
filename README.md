# dirt

**dirt** is a specialized eBPF-based filesystem monitoring tool designed for Unraid systems. It specifically targets the `shfs` (User Share File System) process to track file operations across user shares and export these events to a Redis database.

## Core Capabilities

1.  **Filesystem Event Interception**:
    *   Monitors `shfs_create`, `shfs_unlink`, and `shfs_rename` operations in the `/usr/libexec/unraid/shfs` binary.
    *   Uses eBPF **uprobes** to capture function arguments (file paths) at entry and **uretprobes** to confirm successful completion (return code 0) before reporting the event.

2.  **Dynamic Function Discovery**:
    *   Since the `shfs` binary is typically stripped, the program dynamically locates function offsets at runtime.
    *   It scans the `.rodata` section for function name strings and then uses the `iced-x86` instruction decoder to find the corresponding function prologues in the `.text` section.

3.  **Intelligent Whitelist Filtering**:
    *   Filtering is performed both in **kernel-space** (for performance) and **user-space** (for final mapping).
    *   It only monitors files belonging to "shares" specified in a `dirt.cfg` configuration file.
    *   For rename operations, an event is captured if either the source or destination share is whitelisted.

4.  **Path and Event Normalization**:
    *   Converts raw filesystem paths into a structured `share` and `relative_path` format.
    *   Maps low-level operations to high-level "database-style" events:
        *   **`upsert`**: Triggered by file creation or a move from a non-monitored share into a monitored one.
        *   **`remove`**: Triggered by file deletion or a move from a monitored share to a non-monitored one.
        *   **`rename`**: Triggered by moves within or between monitored shares.

5.  **Redis Integration**:
    *   Asynchronously pushes JSON-serialized events to a Redis list named `dirt-events` using the `RPUSH` command.
    *   Connects by default to a local Redis instance (`redis://127.0.0.1/`).

6.  **Robust Architecture**:
    *   Built with the **Aya** framework, allowing for a fully Rust-based eBPF stack.
    *   Uses a BPF **Ring Buffer** for efficient kernel-to-user communication.
    *   Employs a thread-safe asynchronous runtime (**Tokio**) in user-space.

## Technical Specifications
*   **Maximum Path Length**: 4096 bytes.
*   **Maximum Share Name Length**: 256 bytes.
*   **Configuration Locations**: Searches `/etc/dirt/dirt.cfg`, `/boot/config/plugins/dirt/dirt.cfg`, and the local executable directory.

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package dirt --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/dirt` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, dirt is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
