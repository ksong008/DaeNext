# DaeNext

DaeNext is a Rust-native proxy daemon workspace. The repository root is the
Cargo workspace; build, test, and fixture paths are rooted here rather than in a
nested language-specific subdirectory.

## Layout

- `crates/`: Rust crates for the daemon, control plane, routing, DNS,
  datapath, outbound protocols, eBPF support, CLI tools, and shared contracts.
- `build/`: shared build helpers used by crate build scripts.
- `scripts/`: repository maintenance and validation scripts.
- `testdata/`: golden fixtures and common test inputs.
- `example.dae`: example runtime configuration.

## Development

Format the workspace:

```bash
cargo fmt --all
```

Check all targets:

```bash
cargo check --workspace --all-targets
```

Run library tests:

```bash
cargo test --workspace --lib
```

Run the service contract tests:

```bash
cargo test -p dae-daemon --test service_contract
```

Build the DaeNext release binary:

```bash
cargo build --release -p dae-cli --bin dae
```

`DaeNext` releases publish the `dae` Rust workspace artifact. The `daed`
product binary is released from the `DaedNext` repository, which consumes this
workspace as its Rust core.
