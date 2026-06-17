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

Run the same gate used by CI and release:

```bash
scripts/release_gate.sh
```

## Release Boundary

Formal release artifacts are defined by the GitHub Actions release workflow.
The current DaeNext workflow publishes the `dae` Rust workspace artifact,
source archive, manifest, and checksums. Local `daed` v2/v3 deb/rpm builds are
allowed for install and smoke testing, but they are not formal release artifacts
unless a release workflow publishes them.

The `daed` product binary release remains owned by the product release workflow
that consumes this workspace as its Rust core.
