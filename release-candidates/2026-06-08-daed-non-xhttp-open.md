# 2026-06-08 daed non-xHTTP-open release candidate

## Candidate

- Binary source HEAD: `f58a0ea41f3dc89ed57d191e3d14cb4993114492`
- Release binary: `rust/target/release/daed`
- SHA256: `9efc609cd6c925636761f8eea80ca23913bc15da63e37ad1290c3a80afdfdb4a`
- Scope: release-candidate binary that reports all non-xHTTP protocol/source matrix rows open.
- xHTTP scope: excluded from this candidate's non-xHTTP-open conclusion.

## Local Gate Evidence

Commands passed:

- `cargo test -p dae-daemon product_chain_recertification --quiet`
- `cargo test -p dae-daemon product_chain_runner --quiet`
- `cargo test -p dae-daemon --test service_contract --quiet`
- `cargo test -p dae-daemon --test daed_product --quiet`
- `cargo test -p dae-daemon outbound_production_matrix --quiet`
- `cargo test -p dae-daemon c10_go_free --quiet`
- `cargo test -p dae-daemon release_default_switch --quiet`
- `cargo test -p dae-outbound source_shape_registry --quiet`
- `cargo build -p dae-daemon --release`

## Binary Self-Report Summary

The release binary's `service-contract --json` report has:

- `source_shape_registry_contract_ready=true`
- `excluded_stream_wrapper_source_matrix_open=true`
- `excluded_stream_wrapper_source_matrix_complete=true`
- `excluded_stream_wrapper_source_matrix_release_gate_ready=true`
- `excluded_stream_wrapper_source_matrix_c10_ready=false`
- `scoped_expanded_source_matrix_complete=true`
- `scoped_expanded_source_matrix_release_gate_ready=true`
- `scoped_expanded_source_matrix_c10_ready=false`
- `expanded_source_matrix_complete=false`
- `expanded_source_matrix_release_gate_ready=false`
- `expanded_source_matrix_c10_ready=false`
- `protocol_variant_row_count=41`
- `opened_shape_count=41`
- `rawLinksRetained=false`
- `rawBodiesRetained=false`
- `rawStateRetained=false`

Policy-rejected rows remain fail-closed:

- `foreign-abi-outbound-shape`
- `external-oracle-dependent-shape`
- `internal-fallback-dependent-shape`

Excluded xHTTP rows:

- `stream-wrapper-xhttp`
- `xhttp-h3-wrapper`
- `xhttp-extended-settings-wrapper`

## Package Boundary

The release binary's `package-info --json` report still marks the final C10
go-free gate blocked. Remaining admission items are:

- Generated protocol matrix live evidence is not recorded in the default package gate.
- Default-ready benchmark evidence is not recorded.
- Go-free artifact build-chain scan has not passed for the default package.
- Userland FFI/C ABI retirement is not proven for the default path.
- Go oracle/default dependency retirement is not proven for the default path.
- Rust internal fallback normalization is not proven for the default path.
- Final live host evidence is not recorded.
- Rollback artifact validation is not recorded.

This means the candidate is valid for the non-xHTTP protocol/source matrix
opening claim, but not yet for final C10 go-free default package closure.
Stage 4 evidence below records external live-host and rollback-artifact
evidence for this release candidate; it does not change the binary's embedded
`package-info --json` self-report.

## Live Host Step

Live host replacement evidence recorded for this candidate:

- Previous live `/usr/bin/daed` SHA256:
  `9f14b15c7b5b6056f854f677dab3402fb1719b26d5aa1ccba775021f3bb85cf3`
- Installed live `/usr/bin/daed` SHA256:
  `9efc609cd6c925636761f8eea80ca23913bc15da63e37ad1290c3a80afdfdb4a`
- Backup directory:
  `/root/daed-backups/daex-release-candidate-20260608-215317`
- Rollback script:
  `/root/daed-backups/daex-release-candidate-20260608-215317/rollback-to-before.sh`
- Rollback script SHA256:
  `e20be889a89a12fa9783ac1b3a1e87382b190d63b2af19a5e2211df8d359d5f2`
- Candidate `validate -c /etc/daed/ --json`: `status=pass`
- Installed `validate -c /etc/daed/ --json`: `status=pass`
- `systemctl restart daed`: active
- `systemctl reload daed`: active
- `ExecStartPre=/usr/bin/daed validate -c /etc/daed/`: success
- HTTP health after restart and reload: `{"healthCheck":1}`
- WebUI root served after restart and reload: non-empty HTML response
- Main PID after restart and reload: stable
- Native eBPF/tc evidence after restart:
  tcx programs attached on the live interface and `dae0`; one
  `/sys/fs/bpf/dae-native-runtime-*` directory retained for the active process.
- Short post-reload process snapshot:
  `VmRSS=65500 kB`, `RssAnon=44232 kB`, `Threads=13`.
- Journal evidence:
  systemd recorded stop/start and reload entries for `daed.service`.

The rollback script was prepared but not executed; this preserves the installed
candidate while leaving a direct path back to the previous binary. Retained
evidence contains no raw links, credentials, raw webpage bodies, or raw runtime
state.

## Stage 4 Live Host Reload/RSS Evidence

Live host evidence was collected on `10.10.10.2` against the installed
candidate SHA256:

`9efc609cd6c925636761f8eea80ca23913bc15da63e37ad1290c3a80afdfdb4a`

Allocator scope:

- `dae-daemon` default features include `native-ebpf` and `allocator-jemalloc`.
- The installed `/usr/bin/daed` contains jemalloc purge/control strings,
  including `jemalloc_arena_purge`; this confirms the live candidate is not a
  system-allocator build.
- The live service keeps the jemalloc tuning environment explicit with
  `MALLOC_CONF=background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000,narenas:2`.

Reload path audit:

- WebUI/API reload is `POST /api/runtime/reload`; after authentication it
  materializes config, applies runtime log level, refreshes runtime-cycle logs,
  and calls `app.runtime.reload(config, "api-runtime-reload")`.
- `systemctl reload daed` uses `ExecReload=/bin/kill -HUP $MAINPID`; the
  daemon signal thread handles `SIGHUP`/`SIGUSR1`, materializes the persisted
  running runtime, and calls the same `ProductRuntimeManager::reload` path with
  source `signal`.
- `systemctl restart daed` stops the old process and starts a new process, so
  the kernel reclaims the previous address space, allocator state, thread
  stacks, file descriptors, and process-local caches. A restart therefore
  resetting RSS does not disprove a reload-retained RSS issue.

Observed live RSS behavior:

- Baseline before repeated reloads:
  `pid=8228`, `VmRSS=52748 kB`, `RssAnon=34056 kB`, `Threads=12`, `FDs=91`.
- After reload 1 and a 25 second settle window:
  `pid=8228`, `VmRSS=79696 kB`, `RssAnon=61004 kB`, `Threads=15`, `FDs=91`.
- After reload 2 and a 25 second settle window:
  `pid=8228`, `VmRSS=84196 kB`, `RssAnon=65504 kB`, `Threads=15`, `FDs=103`.
- After reload 3 and a 25 second settle window:
  `pid=8228`, `VmRSS=81564 kB`, `RssAnon=62872 kB`, `Threads=13`, `FDs=83`.
- A restart changed the process id and reset process-local allocator/runtime
  state. The post-restart process later returned to a lower baseline before
  reload, then rose again after reload.

Interpretation:

- The reload RSS increase is reproduced for in-process reload on the live
  candidate even with jemalloc enabled.
- The evidence does not show monotonic FD, thread, or BPF runtime directory
  growth. The current signal points to reload-time runtime allocation and
  jemalloc arena/tcache retention inside the same process, not a simple leaked
  file descriptor or unjoined primary worker thread.
- `ResidentProductionRuntime::drop` calls `cleanup()`, and
  `ResidentDataplaneRuntime::shutdown()` sets the stop flag and joins the main
  TCP/UDP/health worker handles. Any remaining investigation should focus on
  reload-time allocation pressure, short-lived per-flow/per-packet tasks,
  jemalloc retained/active pages, and whether post-reload idle reclaim should
  be strengthened or delayed after worker/task quiescence.

Sanitized host evidence files were kept on the live host under:

`/root/daed-live-evidence/20260608-stage4/`
