# DaeNext

<img src="https://github.com/daeuniverse/dae/blob/main/logo.png" border="0" width="25%">

<p align="left">
    <img src="https://github.com/ksong008/DaeNext/actions/workflows/ci.yml/badge.svg" alt="Rust CI"/>
    <img src="https://custom-icon-badges.herokuapp.com/github/license/ksong008/DaeNext?logo=law&color=orange" alt="License"/>
    <img src="https://custom-icon-badges.herokuapp.com/github/v/release/ksong008/DaeNext?logo=rocket" alt="version">
    <img src="https://custom-icon-badges.herokuapp.com/github/issues-pr-closed/ksong008/DaeNext?color=purple&logo=git-pull-request&logoColor=white"/>
    <img src="https://custom-icon-badges.herokuapp.com/github/last-commit/ksong008/DaeNext?logo=history&logoColor=white" alt="lastcommit"/>
</p>

**_DaeNext_** is the Rust-native dae core workspace.

dae, which means goose, is a high-performance transparent proxy solution. To
keep traffic split fast, dae uses Linux eBPF and transparent proxying so direct
traffic can bypass userspace forwarding while proxied traffic is handled by the
runtime.

DaeNext keeps that architecture while moving the daemon, routing, DNS,
configuration, outbound protocols, native eBPF loader, and shared runtime
contracts into a Rust workspace.

## Features

- [x] Rust-native workspace for the dae core runtime, CLI, daemon, routing, DNS,
  datapath, outbound protocols, and product contracts.
- [x] Native Aya/eBPF datapath support for transparent proxy routing, cgroup
  ownership checks, listener handoff, routing maps, and runtime map diagnostics.
- [x] Real transparent proxy semantics for direct and proxied traffic instead of
  endpoint-only or synthetic routing shortcuts.
- [x] Configuration parsing, materialization, and golden fixture coverage for
  dae-compatible runtime behavior.
- [x] Resident TCP/UDP dataplane workers for policy-based forwarding, health
  checks, latency probing, and group strategy state.
- [x] Support for DNS routing, domain routing map updates, geodata matching, and
  runtime connectivity state.
- [x] Support for common proxy protocols through the Rust outbound stack,
  including TLS, uTLS/BoringSSL paths, HTTP/2, HTTP/3, QUIC, xHTTP, VLESS,
  VMess, Shadowsocks, Trojan, SOCKS, and related transports where implemented.
- [x] Build, release, benchmark, and golden-test tooling rooted at the repository
  top level.

## Getting Started

DaeNext is a Cargo workspace. Build, test, fixture, and release paths are rooted
at the repository root.

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

Build the Rust `dae` binary:

```bash
cargo build --release -p dae-cli --bin dae
```

Run the same gate used by CI and release:

```bash
scripts/release_gate.sh
```

For product-level usage documentation, refer to the upstream dae documentation:
[Quick Start Guide](https://github.com/daeuniverse/dae/blob/main/docs/en/README.md).

## Notes

1. DaeNext is the Rust-native core workspace. Product packaging and the `daed`
   WebUI release remain owned by the product release workflow that consumes this
   workspace as its core.
1. Linux eBPF availability and kernel feature gates matter for resident
   transparent proxy mode. The runtime performs preflight checks before attaching
   production dataplane programs.
1. UDP is stateful in the dataplane through kernel maps and timer-backed cleanup.
   Map capacity should be tuned through profile/load-time configuration and
   occupancy diagnostics, not by changing live BPF map sizes at runtime.
1. Keep behavior-compatible changes aligned with dae's user-facing semantics:
   parser support, admission support, and real wire/proxy behavior are separate
   validation layers.

## How it works

DaeNext follows dae's transparent proxy model:

1. eBPF programs classify traffic, perform direct/proxy split decisions, and
   maintain routing, redirect, process, domain, and UDP state maps.
1. The Rust daemon owns runtime configuration, resident dataplane workers,
   health checks, latency probes, DNS behavior, outbound protocol execution, and
   product-facing contracts.
1. Direct traffic remains on the kernel fast path where possible, while proxied
   traffic is handed to userspace workers with the same policy and protocol
   semantics expected by dae.

For the original product architecture, see upstream dae's
[How it works](https://github.com/daeuniverse/dae/blob/main/docs/en/how-it-works.md).

## Repository Layout

- `crates/`: Rust crates for the daemon, control plane, routing, DNS, datapath,
  outbound protocols, eBPF support, CLI tools, and shared contracts.
- `build/`: shared build helpers used by crate build scripts.
- `scripts/`: repository maintenance and validation scripts.
- `testdata/`: golden fixtures and common test inputs.
- `example.dae`: example runtime configuration.

## TODO

- [ ] Keep Rust-native dataplane behavior aligned with dae's Go/eBPF contract.
- [ ] Continue expanding protocol parity and live evidence coverage.
- [ ] Improve runtime map occupancy diagnostics and profile guidance.
- [ ] Keep product packaging boundaries explicit between this workspace and the
  `daed` product release.

## Contributors

Special thanks goes to the dae community and all contributors. For upstream dae
contribution guidance, see the
[contribution instructions](https://github.com/daeuniverse/dae/blob/main/docs/en/development/contribute.md)
and the
[commit message guide](https://github.com/daeuniverse/dae/blob/main/docs/en/development/commit-msg-guide.md).

## License

[AGPL-3.0-only](./LICENSE)

## Stargazers over time

[![Stargazers over time](https://starchart.cc/ksong008/DaeNext.svg)](https://starchart.cc/ksong008/DaeNext)

## Original Source

This project originates from the dae project:
[https://github.com/daeuniverse/dae](https://github.com/daeuniverse/dae).
