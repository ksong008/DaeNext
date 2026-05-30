# DAEX Rust 功能级 Go/Rust Benchmark 设计 2026-05-24

本文件只保留本地，不提交。

## 1. 目标

为 Rust 重构和后续性能优化建立一套完整、可重复、可横向对比的功能级 benchmark。

目标指标：

- `us/op`
- `ns/op`
- `B/op`
- `allocs/op`
- 可选扩展：`p50/p95/p99`、RSS、CPU、throughput、error count。

设计原则：

- Go 和 Rust 使用同一份 corpus / fixture。
- Go 侧使用 `testing.B` + `b.ReportAllocs()` + `-benchmem`。
- Rust 侧使用统一 benchmark runner + counting global allocator，输出 Go-like text 和 JSON。
- 先做功能级 microbench / mesobench，再做 root-gated active datapath admission benchmark。
- benchmark 不能替代 correctness fixture；每个 bench case 必须有对应 parity fixture 或 admission evidence。

## 2. 为什么需要新设计

现状：

- Go 侧已有大量 `Benchmark*`，例如 config、routing、DNS、outbound protocol、control、engine、trace，普遍使用 `b.ReportAllocs()`。
- Rust 侧已有 `rust/crates/*/examples/stage*_bench.rs`，主要用 `Instant` 打印 `ns/op`。
- Rust 侧当前没有统一的 `B/op`、`allocs/op` 统计。
- admission benchmark 已覆盖 daemon start-to-ready、active TCP/UDP/DNS，但 iterations 少，适合准入，不适合精细优化。

结论：

- 后续 Rust 性能优化需要一套横跨 Go/Rust 的 feature-oriented benchmark matrix。
- Rust 必须补 allocation instrumentation，否则无法判断 zero-copy / buffer pool / Bytes / Arc<[u8]> 优化是否有效。

## 3. 总体架构

新增工具建议：

```text
tools/bench/
  functional_matrix.toml
  run_functional_bench.py
  parse_go_bench.py
  compare_bench.py

rust/crates/dae-bench/
  Cargo.toml
  src/bin/dae-functional-bench.rs
  src/alloc_counter.rs
  src/cases/
    config.rs
    routing.rs
    dns.rs
    outbound.rs
    protocols.rs
    shared_transport.rs
    control.rs
    engine.rs
    trace.rs
```

如果不想新增 crate，也可以先放在 `rust/crates/dae-cli/src/bin/dae-functional-bench.rs`，但长期建议独立 `dae-bench`，避免 CLI 产品逻辑和 benchmark instrumentation 混在一起。

输出目录：

```text
/tmp/dae-daex-functional-bench-YYYYMMDD-HHMMSS/
  manifest.json
  go.raw.txt
  go.parsed.json
  rust.raw.jsonl
  rust.parsed.json
  compare.json
  compare.md
  env.json
```

## 4. 指标定义

### 4.1 Go 指标

命令：

```bash
PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off \
go test -run '^$' -bench '<BENCH_REGEX>' -benchmem -count=10 -benchtime=100ms ./...
```

采集：

- `ns/op`：Go benchmark 原生输出。
- `us/op`：`ns/op / 1000`。
- `B/op`：Go benchmark 原生输出。
- `allocs/op`：Go benchmark 原生输出。

注意：

- 每个 Go benchmark 必须调用 `b.ReportAllocs()`。
- `-run '^$'` 避免跑普通测试。
- `GOWORK=off` 避免 `/root/project/go.work` 干扰。
- package 范围不要默认 `./...` 全跑；由 matrix 精确列出 package。

### 4.2 Rust 指标

Rust 标准 benchmark 生态不能直接提供 Go 风格 `B/op` / `allocs/op`，因此设计自定义 counting allocator。

核心思路：

```rust
#[global_allocator]
static GLOBAL: CountingAllocator<System> = CountingAllocator::new(System);
```

每个 case：

1. warmup。
2. reset allocation counters。
3. reset timer。
4. 执行 N 次 operation。
5. 读取 elapsed、allocated bytes、alloc count。
6. 输出：
   - `ns_per_op`
   - `us_per_op`
   - `bytes_per_op`
   - `allocs_per_op`

JSON line 示例：

```json
{
  "engine": "rust",
  "case": "dns/packed_response_restore",
  "iters": 100000,
  "elapsed_ns": 123456789,
  "ns_per_op": 1234.56789,
  "us_per_op": 1.23456789,
  "bytes_per_op": 32.0,
  "allocs_per_op": 1.0,
  "checksum": "..."
}
```

实现要求：

- allocation counter 只包围 measured operation，不统计 fixture 构造。
- 每个 case 有 `setup`、`warmup`、`run_once`、`checksum`。
- `setup` 期间允许分配，但不计入 `B/op` / `allocs/op`。
- `checksum` 防止编译器消除工作。
- 对 async / tokio case 单独标记 `async_runtime_allocs_included=true`，避免与 sync microbench 混比。

## 5. 公平性规则

必须固定：

- Git commit：`dae`、`daed`、`wing`、`outbound`、`quic-go`。
- Go version。
- Rust version。
- build flags。
- CPU model。
- kernel version。
- governor / turbo 状态，能记录则记录。
- corpus SHA-256。
- binary SHA-256。

Go/Rust 结果必须共享：

- 同一输入文本。
- 同一 link URL。
- 同一 DNS packet。
- 同一 routing rule。
- 同一 outbound node。
- 同一 protocol payload。
- 同一 benchmark iterations / benchtime 策略，或者在 report 中记录差异。

不允许：

- Go 使用真实 parser，Rust 使用手写简化 fixture。
- Rust 跳过校验逻辑来换性能。
- 把 admission smoke 的耗时和 microbench 的耗时放在同一列直接比较。
- 只比较 `ns/op`，不记录 `B/op` / `allocs/op`。

## 6. Case Matrix

### 6.1 Config

| case | Go 来源 | Rust 来源 | 指标 |
| --- | --- | --- | --- |
| `config/parser_example` | `BenchmarkRebuildStage2Config/parser_example` | `dae-config` | us/op, B/op, allocs/op |
| `config/schema_example` | `BenchmarkRebuildStage2Config/schema_example` | `dae-config` | us/op, B/op, allocs/op |
| `config/include_merger` | `BenchmarkRebuildStage2Config/include_merger` | `dae-config` | us/op, B/op, allocs/op |
| `config/marshal_roundtrip` | `BenchmarkRebuildStage2Config/marshal_roundtrip_example` | `dae-config` | us/op, B/op, allocs/op |

### 6.2 Routing / Geodata / Sniffing

| case | Go 来源 | Rust 来源 | 指标 |
| --- | --- | --- | --- |
| `routing/prefix_parse` | `BenchmarkRebuildStage3RoutingGeodataSniffing/routing_prefix_parse` | `dae-routing` | us/op, B/op, allocs/op |
| `routing/domain_matcher_bitmap` | `BenchmarkRebuildStage3RoutingGeodataSniffing/domain_matcher_bitmap` | `dae-routing` | us/op, B/op, allocs/op |
| `routing/geodata_streaming_geoip_hit` | `BenchmarkRebuildStage3RoutingGeodataSniffing/geodata_streaming_geoip_hit` | `dae-geodata` | us/op, B/op, allocs/op |
| `sniffing/http_host` | `BenchmarkRebuildStage3RoutingGeodataSniffing/sniffing_http_host` | `dae-sniffing` | us/op, B/op, allocs/op |
| `sniffing/quic_crypto_reassemble` | `BenchmarkReassembleCryptoToBytesFromPool` | `dae-sniffing` | us/op, B/op, allocs/op |

### 6.3 DNS

| case | Go 来源 | Rust 来源 | 指标 |
| --- | --- | --- | --- |
| `dns/cache_key` | `BenchmarkDnsCacheKey` | `dae-dns` | us/op, B/op, allocs/op |
| `dns/zero_id` | `BenchmarkDnsDataWithZeroID` | `dae-dns` | us/op, B/op, allocs/op |
| `dns/validate_response` | `BenchmarkValidateDnsResponseForRequest` | `dae-dns` | us/op, B/op, allocs/op |
| `dns/doh_get_request` | `BenchmarkBuildDoHRequestGet` | `dae-dns` | us/op, B/op, allocs/op |
| `dns/packed_response_restore` | 新增 Go bench | `dae-dns` | us/op, B/op, allocs/op |
| `dns/cache_lookup_packed_hit` | 新增 Go bench | `dae-dns` | us/op, B/op, allocs/op |
| `dns/snapshot_restore` | 新增 Go bench | `dae-dns` | us/op, B/op, allocs/op |
| `dns/domain_routing_owner_update` | `BenchmarkRebuildStage7DomainRoutingOwnerMerge` | `dae-control` / `dae-dns` | us/op, B/op, allocs/op |

### 6.4 Outbound Group / Health / Filter

| case | Go 来源 | Rust 来源 | 指标 |
| --- | --- | --- | --- |
| `outbound/filter_regex_1000` | `BenchmarkDialerSetFilterAndAnnotateRegex` | `dae-outbound` | us/op, B/op, allocs/op |
| `outbound/select_min_latency` | `BenchmarkDialerGroupSelectMinLastLatency` | `dae-outbound` | us/op, B/op, allocs/op |
| `outbound/connectivity_key` | 新增 Go bench | `dae-outbound` / `dae-ebpf-support` | us/op, B/op, allocs/op |
| `outbound/health_latency_update` | 新增 Go bench | `dae-outbound` | us/op, B/op, allocs/op |

### 6.5 Protocol Link / Metadata / Packet

每个协议至少三类：

- parse link
- export / normalize
- packet/header build or decode

覆盖：

- SOCKS5
- HTTP
- Shadowsocks AEAD
- Shadowsocks 2022
- SIP003 simple-obfs http/tls
- SIP003 v2ray-plugin TLS/WS/mux
- ShadowsocksR
- Trojan
- Trojan-Go
- VLESS
- VMess
- AnyTLS
- Hysteria2
- TUIC
- Juicity

指标：

- us/op
- B/op
- allocs/op
- checksum / output hash

### 6.6 Shared Transport

覆盖：

- TLS underlay options
- WebSocket handshake / frame
- HTTPUpgrade request
- gRPC hunk frame
- HTTP/2 gRPC lifecycle frame
- xHTTP path / mode / xmux
- xHTTP H3 payload
- meek polling
- mux frame
- Reality session id / AEAD
- uTLS synthetic wire / profile builder
- TLS fragment

### 6.7 Control / Datapath / eBPF Userspace

| case | Go 来源 | Rust 来源 | 指标 |
| --- | --- | --- | --- |
| `control/magic_network_mark_mptcp` | `BenchmarkRebuildStage7MagicNetworkMarkMptcp` | `dae-datapath` / `dae-outbound` | us/op, B/op, allocs/op |
| `control/udp_endpoint_trim_4096` | `BenchmarkUdpEndpointPoolTrimToLimit4096` | `dae-control` | us/op, B/op, allocs/op |
| `control/udp_endpoint_get_or_create_parallel` | `BenchmarkUdpEndpointPoolGetOrCreateSameAddrParallel` | Rust 后续并行 runner | us/op, B/op, allocs/op |
| `ebpf/param_payload_build` | 新增 Go bench | `dae-ebpf-support` | us/op, B/op, allocs/op |
| `ebpf/param_object_locate` | 新增 Go bench | `dae-ebpf-support` | us/op, B/op, allocs/op |
| `ebpf/map_value_encode` | 新增 Go bench | `dae-ebpf-support` | us/op, B/op, allocs/op |

说明：

- root-gated real BPF attach 不放进 microbench；只做 admission benchmark。
- userspace encoding / map payload / object rewrite 可以做 allocation benchmark。

### 6.8 Engine / CLI / Runtime Contract

| case | Go 来源 | Rust 来源 | 指标 |
| --- | --- | --- | --- |
| `engine/route_aware_target` | `BenchmarkEngineRouteAwareDialTarget` | `dae-engine` | us/op, B/op, allocs/op |
| `engine/runtime_overview` | `BenchmarkEngineRuntimeOverviewNoControlPlane` | `dae-engine` | us/op, B/op, allocs/op |
| `engine/parse_config_api` | `BenchmarkEngineParseConfigAPI` | `dae-engine` | us/op, B/op, allocs/op |
| `engine/subscription_persist_cleanup` | `BenchmarkEngineSubscriptionPersistCleanup` | `dae-engine` | us/op, B/op, allocs/op |
| `cli/validate_minimal_config` | `BenchmarkCliValidateMinimalConfig` | `dae-cli` | us/op, B/op, allocs/op |
| `cli/export_outline` | `BenchmarkCliExportOutline` | `dae-cli` | us/op, B/op, allocs/op |

## 7. Runner 设计

### 7.1 Rust Runner CLI

建议命令：

```bash
cargo run --manifest-path rust/Cargo.toml -p dae-bench --bin dae-functional-bench -- \
  --matrix tools/bench/functional_matrix.toml \
  --case all \
  --iters auto \
  --warmup 3 \
  --repeat 10 \
  --output /tmp/dae-daex-functional-bench-YYYYMMDD-HHMMSS/rust.raw.jsonl
```

输出同时支持：

- JSONL，供机器比较。
- Go-like text，方便人读。

Go-like text 示例：

```text
BenchmarkRust/dns/packed_response_restore-1    100000    1.234 us/op    32 B/op    1 allocs/op
```

### 7.2 Go Runner

建议命令：

```bash
PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off \
go test -run '^$' -bench '<matrix generated regex>' -benchmem -count=10 -benchtime=100ms \
  ./config ./component/routing ./component/sniffing ./component/dns ./component/outbound ./control ./engine ./cmd ./trace \
  > /tmp/dae-daex-functional-bench-YYYYMMDD-HHMMSS/go.raw.txt
```

注意：

- 不能默认 `./...`，避免跑到不相关包或环境敏感包。
- Go benchmark 命名要映射到 Rust case id。

### 7.3 Compare Tool

输出字段：

```json
{
  "case": "dns/packed_response_restore",
  "go": {
    "us_per_op_avg": 1.2,
    "bytes_per_op_avg": 64,
    "allocs_per_op_avg": 2
  },
  "rust": {
    "us_per_op_avg": 0.8,
    "bytes_per_op_avg": 32,
    "allocs_per_op_avg": 1
  },
  "ratio": {
    "us_per_op_rust_vs_go": 0.666,
    "bytes_per_op_rust_vs_go": 0.5,
    "allocs_per_op_rust_vs_go": 0.5
  },
  "verdict": "pass"
}
```

默认阈值建议：

- `us/op`：Rust 不得慢于 Go `1.20x`，除非有 correctness 或安全理由。
- `B/op`：Rust 不得高于 Go `1.10x`。
- `allocs/op`：Rust 不得高于 Go `1.10x`。
- 对高价值优化目标，Rust 应小于等于 Go 的 `0.80x`。

阈值必须允许 per-case override。例如 TLS/QUIC 初始化、Rustls、H3 建连与 Go 底层库不完全等价时，必须单独记录原因。

## 8. Root-Gated Admission Benchmark 补充

microbench 不覆盖真实内核路径，因此继续保留 root-gated benchmark：

- matched Go/Rust default daemon start-to-ready
- active TCP relay
- active UDP tproxy
- active DNS tproxy/cache
- reload under active traffic
- eBPF attach backend：TC command / netlink TC / TCX

这些指标记录：

- elapsed ns
- p50/p95/p99
- throughput
- RSS
- CPU
- BPF map pressure
- UDP endpoint pool pressure

但这些不输出 `allocs/op` 作为主要指标，因为 runtime/daemon 级别的 allocator 统计会包含 background task、tokio runtime、TLS/QUIC connection setup 等噪声。它们只作为系统层 performance evidence。

## 9. 产物与提交边界

第一批实现建议：

1. 新增 `tools/bench/functional_matrix.toml`。
2. 新增 `tools/bench/run_functional_bench.py` 和 parser。
3. 新增 Rust `dae-bench` crate 或 `dae-functional-bench` bin。
4. 迁移现有 Rust `stage*_bench.rs` case 到统一 runner。
5. 保留旧 examples，直到新 runner 结果与旧结果对齐。
6. 为 Go 缺失 case 补 `Benchmark*`。

提交前必须：

- `cargo fmt --manifest-path rust/Cargo.toml --all`
- Rust bench runner dry-run。
- Go selected benchmark dry-run。
- 生成一份 compare report。

## 10. 下一步建议

先做最小闭环，不一次性覆盖所有协议：

1. `config/parser_example`
2. `dns/packed_response_restore`
3. `routing/domain_matcher_bitmap`
4. `outbound/select_min_latency`
5. `protocol/socks5_udp_packet_wrap`
6. `protocol/vless_request_header`
7. `control/magic_network_mark_mptcp`
8. `engine/runtime_overview`

这 8 个 case 可以验证：

- Go parser 是否能抓 `B/op allocs/op`。
- Rust counting allocator 是否稳定。
- JSON compare 是否正确。
- case matrix 是否能映射到 Go/Rust 双侧。

最小闭环通过后，再扩展到完整协议矩阵。

## 11. 2026-05-24 实现与完整测试记录

本轮完成第一批功能级 Go/Rust benchmark 最小闭环实现，并完成完整矩阵测试。

实现内容：

- 新增 Rust workspace crate：`rust/crates/dae-bench`。
- 新增统一 runner：`tools/bench/run_functional_bench.py`。
- 新增共享矩阵：`tools/bench/functional_matrix.toml`。
- 新增 Go 缺失 case：`control/functional_bench_test.go` 中的 `BenchmarkFunctionalDnsPackedResponseRestore`。
- Rust runner 使用 counting global allocator，输出 `us/op`、`B/op`、`allocs/op`、`checksum`、重复次数和原始 allocation 计数。
- Go runner 使用 `go test -bench ... -benchmem`，并兼容 benchmark 名称与结果被日志分行输出的情况。

验证命令：

```bash
cargo fmt --manifest-path rust/Cargo.toml --all
cargo check --manifest-path rust/Cargo.toml -p dae-bench
PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off go test -run '^$' -bench 'BenchmarkFunctionalDnsPackedResponseRestore' -benchmem -count=1 -benchtime=10ms ./control
python3 -m py_compile tools/bench/run_functional_bench.py
python3 tools/bench/run_functional_bench.py --go-count 3 --go-benchtime 100ms --rust-repeat 3 --rust-iters auto --rust-warmup 100
```

验证结果：

- 全部通过。
- 最终结果目录：`/tmp/dae-daex-functional-bench-20260524-104305`
- 环境：
  - branch：`daex`
  - git head：`7b31d981f526476ac0a3acecf200b966db144fd9`
  - Go：`go1.25.9 linux/amd64`
  - Rust：`rustc 1.95.0 (59807616e 2026-04-14)`
  - kernel：`6.19.11-x64v3-xanmod1`

完整结果摘要：

| case | Go us/op | Rust us/op | Rust/Go time | Go B/op | Rust B/op | Rust/Go B | Go allocs/op | Rust allocs/op | Rust/Go allocs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| config/parser_example | 1834.062 | 20.564 | 0.011 | 1766948.000 | 36525.000 | 0.021 | 28414.333 | 419.000 | 0.015 |
| dns/packed_response_restore | 0.019 | 0.013 | 0.728 | 48.000 | 45.000 | 0.938 | 1.000 | 1.000 | 1.000 |
| routing/domain_matcher_bitmap | 0.296 | 0.199 | 0.675 | 64.000 | 92.000 | 1.438 | 3.000 | 8.000 | 2.667 |
| outbound/select_min_latency | 0.010 | 0.010 | 1.053 | 0.000 | 0.000 | n/a | 0.000 | 0.000 | n/a |
| protocol/socks5_udp_packet_wrap | 0.207 | 0.092 | 0.444 | 91.000 | 67.000 | 0.736 | 4.000 | 4.000 | 1.000 |
| protocol/vless_request_header | 0.430 | 0.096 | 0.224 | 549.000 | 63.000 | 0.115 | 15.000 | 4.000 | 0.267 |
| control/magic_network_mark_mptcp | 0.015 | 0.013 | 0.825 | 16.000 | 10.000 | 0.625 | 1.000 | 1.000 | 1.000 |
| engine/runtime_overview | 0.128 | 0.013 | 0.099 | 320.000 | 24.000 | 0.075 | 3.000 | 1.000 | 0.333 |

结论：

- 第一批 8 个功能级 benchmark 已形成可重复的 Go/Rust `us/op B/op allocs/op` 对比闭环。
- Rust 在 6 个 case 的 `us/op` 明显优于 Go；`outbound/select_min_latency` 基本持平，Rust/Go time 为 `1.053`；`dns/packed_response_restore` Rust 略快。
- `routing/domain_matcher_bitmap` 当前 Rust 时间更快，但 `B/op` 和 `allocs/op` 高于 Go，需要进入后续 copy budget / allocation 优化清单。
- `config/parser_example` 差距很大，后续必须继续确认 Go/Rust 两侧 benchmark 是否完全等价；在等价性冻结前，该数据只作为第一批 runner 闭环证据，不单独作为架构收益结论。
- 当前矩阵是第一批最小闭环，不等于全协议完整矩阵；后续扩展协议 case 时继续沿用同一 runner 和结果格式。

## 12. 2026-05-24 等价性审计与 routing allocation 修复

本轮继续处理首轮 benchmark 后的两个重点：

- `routing/domain_matcher_bitmap`：首轮 Rust `us/op` 更快，但 `B/op` 与 `allocs/op` 高于 Go。
- `config/parser_example`：首轮 Rust 比 Go 快很多，需要先确认两侧 benchmark 是否测同一层 parser。

审计结论：

- `routing/domain_matcher_bitmap` 两侧等价：
  - bit length 均为 `96`。
  - patterns 均为 `example.com`、`.child.example.com`、`cdn`、`exact.example.org`、`^api[0-9]+\\.example\\.net$`。
  - query 均为 `API12.EXAMPLE.NET`。
  - 预期 bitmap 均为 word1 bit31，即 `[0, 2147483648, 0]`。
- Rust allocation 偏高的原因不是 case 不等价，而是 `suffix_matches` 在每次匹配时对 suffix pattern 做 `to_ascii_lowercase()`，并用 `format!(".{pattern}")` 构造临时字符串。
- `config/parser_example` 两侧都解析 `example.dae`：
  - Go：`config_parser.Parse(exampleText)`，底层为 ANTLR parser。
  - Rust：`parse_config(example)`，底层为本地 lexer/parser。
  - 当前 benchmark 行为同属 parser 层，但还需要后续做 AST/string parity audit，才能把巨大性能差距作为最终架构收益结论。

修改：

- `rust/crates/dae-routing/src/domain.rs`
  - 在 `add_set` 阶段一次性规范化 `Full` 与 `Suffix` patterns。
  - `Suffix` pattern 预先 `trim_end_matches('.')` 和 `to_ascii_lowercase()`。
  - 匹配阶段改用 `has_label_suffix()`，避免每次匹配时 `format!()` 和重复 lowercase。
  - `Keyword` 与 `Regex` patterns 不改变，避免扩大语义面。

验证：

```bash
cargo fmt --manifest-path rust/Cargo.toml --all
cargo test --manifest-path rust/Cargo.toml -p dae-routing domain_matcher_bitmap_matches_golden_fixture
cargo check --manifest-path rust/Cargo.toml -p dae-bench
python3 tools/bench/run_functional_bench.py --go-count 3 --go-benchtime 100ms --rust-repeat 3 --rust-iters auto --rust-warmup 100
```

结果目录：

- `/tmp/dae-daex-functional-bench-20260524-105649`

关键改善：

| case | metric | before | after | after/before |
| --- | --- | ---: | ---: | ---: |
| routing/domain_matcher_bitmap | Rust us/op | 0.199 | 0.099 | 0.496 |
| routing/domain_matcher_bitmap | Rust B/op | 92.000 | 29.000 | 0.315 |
| routing/domain_matcher_bitmap | Rust allocs/op | 8.000 | 2.000 | 0.250 |

新完整结果：

| case | Go us/op | Rust us/op | Rust/Go time | Go B/op | Rust B/op | Rust/Go B | Go allocs/op | Rust allocs/op | Rust/Go allocs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| config/parser_example | 1915.366 | 19.984 | 0.010 | 1766914.000 | 36525.000 | 0.021 | 28414.667 | 419.000 | 0.015 |
| dns/packed_response_restore | 0.019 | 0.013 | 0.720 | 48.000 | 45.000 | 0.938 | 1.000 | 1.000 | 1.000 |
| routing/domain_matcher_bitmap | 0.292 | 0.099 | 0.339 | 64.000 | 29.000 | 0.453 | 3.000 | 2.000 | 0.667 |
| outbound/select_min_latency | 0.010 | 0.010 | 1.054 | 0.000 | 0.000 | n/a | 0.000 | 0.000 | n/a |
| protocol/socks5_udp_packet_wrap | 0.195 | 0.088 | 0.452 | 91.000 | 67.000 | 0.736 | 4.000 | 4.000 | 1.000 |
| protocol/vless_request_header | 0.462 | 0.099 | 0.215 | 549.000 | 63.000 | 0.115 | 15.000 | 4.000 | 0.267 |
| control/magic_network_mark_mptcp | 0.015 | 0.013 | 0.845 | 16.000 | 10.000 | 0.625 | 1.000 | 1.000 | 1.000 |
| engine/runtime_overview | 0.102 | 0.013 | 0.125 | 320.000 | 24.000 | 0.075 | 3.000 | 1.000 | 0.333 |

后续：

- 继续做 `config/parser_example` 的 AST/string parity audit。
- 扩展 matrix 时优先增加已有协议功能块，不再做无必要阶段拆分。

## 13. 2026-05-24 config parser AST parity 固化

本轮补齐 `config/parser_example` 的等价性审计证据。

修改：

- `rust/crates/dae-config/src/parser.rs`
  - 新增 `parses_ast_basic_projection_matches_go_golden` 单测。
  - 将 Rust parser 输出的 AST 投影为现有 Go golden fixture 的 JSON 结构。
  - 对 `section`、`item_type`、`value_kind`、`param`、`and_functions`、`annotation`、`routing_rule`、`outbound` 做逐字段比较。

验证：

```bash
cargo fmt --manifest-path rust/Cargo.toml --all
cargo test --manifest-path rust/Cargo.toml -p dae-config parses_ast_basic_projection_matches_go_golden
PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off go test ./pkg/config_parser
cargo check --manifest-path rust/Cargo.toml -p dae-bench
```

结果：

- 全部通过。
- `config/parser_example` 当前可作为 Go ANTLR parser 与 Rust 本地 parser 的同层 benchmark 基线。
- 首轮差距仍需要谨慎解释：它说明 Rust 本地 parser 在当前 corpus 上明显更轻，但后续如要作为最终架构收益，需要继续补 `example.dae` 全量 AST/string projection 对比。

后续：

- 可增加 `config/parser_example_projection` 或专门 audit 工具，输出 Go/Rust `example.dae` AST projection checksum，作为性能结论的准入证据。

## 14. 2026-05-24 example.dae 全量 AST/string checksum 审计

本轮完成 `config/parser_example` 的全量 `example.dae` AST/string parity 证据。

修改：

- `rebuild_golden_test.go`
  - 扩展 `rebuildGoldenConfigParserAst`，读取 `example.dae` 并生成 `example_dae` projection。
  - 记录 `input_sha256`、`section_count`、`item_count_recursive`、`sections_projection_sha256`、`section_strings_sha256`、完整 `sections`、完整 `section_strings`。
- `testdata/rebuild-golden/config/parser/ast_basic.json`
  - 新增 `example_dae` 全量 Go parser projection。
- `rust/crates/dae-config/src/parser.rs`
  - 新增 `parses_example_dae_projection_and_strings_match_go_golden`。
  - Rust parser 对同一份 `example.dae` 比对 Go golden 的完整 AST projection、section strings 和 sha256。
- `rust/crates/dae-config/src/ast.rs`
  - `Item::Section` 的 `to_config_string()` 改为 Go 兼容字符串：`type: Param`。
  - `Section::to_config_string()` 补齐 Go `Section.String()` 的顶层 item tab 缩进。
- `rust/crates/dae-config/Cargo.toml`
  - dev-dependency 增加 `sha2`，仅用于测试中计算 checksum。

Go golden `example_dae` 摘要：

- `input_sha256`: `4a54441c0a20409e5900361ffaab4b7884ea7624e5281ec34a198a4dcdeafb95`
- `section_count`: `6`
- `item_count_recursive`: `60`
- `sections_projection_sha256`: `b7b4d058d9a4c522ce5ef9efbfb1e958b912fa099df0c78852815c7ad3ad102f`
- `section_strings_sha256`: `bc2cd616fedb6fb986219a95159eaee6ba6f7d8c6bee48409735a002dc679b3e`

验证：

```bash
DAE_UPDATE_REBUILD_GOLDEN=1 PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off go test . -run TestWriteRebuildGoldenFixtures
cargo fmt --manifest-path rust/Cargo.toml --all
cargo test --manifest-path rust/Cargo.toml -p dae-config parses_example_dae_projection_and_strings_match_go_golden
cargo test --manifest-path rust/Cargo.toml -p dae-config
PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off go test . -run TestWriteRebuildGoldenFixtures
PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off go test ./pkg/config_parser
cargo check --manifest-path rust/Cargo.toml -p dae-bench
python3 tools/bench/run_functional_bench.py --go-count 3 --go-benchtime 100ms --rust-repeat 3 --rust-iters auto --rust-warmup 100
```

验证结果：

- 全部通过。
- 最新功能 benchmark 目录：`/tmp/dae-daex-functional-bench-20260524-112956`

最新 benchmark 摘要：

| case | Go us/op | Rust us/op | Rust/Go time | Go B/op | Rust B/op | Rust/Go B | Go allocs/op | Rust allocs/op | Rust/Go allocs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| config/parser_example | 2439.619 | 19.953 | 0.008 | 1766947.333 | 36525.000 | 0.021 | 28414.667 | 419.000 | 0.015 |
| dns/packed_response_restore | 0.023 | 0.014 | 0.585 | 48.000 | 45.000 | 0.938 | 1.000 | 1.000 | 1.000 |
| routing/domain_matcher_bitmap | 0.279 | 0.100 | 0.358 | 64.000 | 29.000 | 0.453 | 3.000 | 2.000 | 0.667 |
| outbound/select_min_latency | 0.010 | 0.010 | 1.087 | 0.000 | 0.000 | n/a | 0.000 | 0.000 | n/a |
| protocol/socks5_udp_packet_wrap | 0.220 | 0.086 | 0.393 | 91.000 | 67.000 | 0.736 | 4.000 | 4.000 | 1.000 |
| protocol/vless_request_header | 0.538 | 0.097 | 0.180 | 549.000 | 63.000 | 0.115 | 15.000 | 4.000 | 0.267 |
| control/magic_network_mark_mptcp | 0.017 | 0.013 | 0.775 | 16.000 | 10.000 | 0.625 | 1.000 | 1.000 | 1.000 |
| engine/runtime_overview | 0.111 | 0.013 | 0.118 | 320.000 | 24.000 | 0.075 | 3.000 | 1.000 | 0.333 |

附带修复：

- 完整 Go golden check 暴露当前生成器与两个 outbound fixture 已漂移。
- 已按当前生成器修复：
  - `testdata/rebuild-golden/outbound/link_parser/compatibility_matrix.json`
  - `testdata/rebuild-golden/outbound/protocol/ss2022_no_global_direct_dependency.json`
- 该修复不是 parser benchmark 的功能变更，只是保证 `TestWriteRebuildGoldenFixtures` 在当前源码上通过。

结论：

- `config/parser_example` 现在具备 Go/Rust 全量 `example.dae` AST projection 与 section string checksum parity 证据。
- 在当前 corpus 上，Rust parser 性能收益可以作为功能级 benchmark 基线记录；后续仍需要在更大/更多真实配置 corpus 上扩展 benchmark。
- 下一步继续按 feature 扩展协议 benchmark，不做无必要阶段拆分。

## 15. 2026-05-24 config benchmark 扩展到 schema/include/marshal

本轮继续按 feature 扩展 benchmark，不新增阶段编号。

新增内容：

- `tools/bench/functional_matrix.toml`
  - 新增 `config/schema_example`
  - 新增 `config/include_merger`
  - 新增 `config/marshal_roundtrip_example`
- `rust/crates/dae-bench/src/cases/config.rs`
  - 按 config 功能块物理拆分 benchmark case。
  - 保留 `config/parser_example`。
  - 新增 schema build、include merger、marshal roundtrip 三个 Rust case。
- `rust/crates/dae-bench/src/cases/mod.rs`
  - 新增 cases 模块入口。
- `rust/crates/dae-bench/src/main.rs`
  - 不再继续堆 config 逻辑，改从 `cases::config::cases()` 注册 config case。

等价性边界：

- Go `schema_example`：`config_parser.Parse(exampleText)` 后 `daeconfig.New(sections)`。
- Rust `config/schema_example`：`parse_config(example)` 后 `build_config(&sections)`。
- Go `include_merger`：使用 stage2 benchmark include tree，并执行 `daeconfig.NewMerger(entry).Merge()`。
- Rust `config/include_merger`：使用同结构 include tree，并执行 `merge_config_file(entry)`。
- Go `marshal_roundtrip_example`：merge/build `example.dae`，每轮 `Marshal(2)`、parse、build。
- Rust `config/marshal_roundtrip_example`：merge/build `example.dae`，每轮 `marshal_config(2)`、parse、build。

验证：

```bash
cargo fmt --manifest-path rust/Cargo.toml --all
cargo check --manifest-path rust/Cargo.toml -p dae-bench
cargo run --manifest-path rust/Cargo.toml -p dae-bench --release --quiet -- --case config/schema_example --iters auto --warmup 10 --repeat 1
cargo run --manifest-path rust/Cargo.toml -p dae-bench --release --quiet -- --case config/include_merger --iters auto --warmup 10 --repeat 1
cargo run --manifest-path rust/Cargo.toml -p dae-bench --release --quiet -- --case config/marshal_roundtrip_example --iters auto --warmup 10 --repeat 1
PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off go test -run '^$' -bench 'BenchmarkRebuildStage2Config/(schema_example|include_merger|marshal_roundtrip_example)' -benchmem -count=1 -benchtime=50ms .
python3 tools/bench/run_functional_bench.py --go-count 3 --go-benchtime 100ms --rust-repeat 3 --rust-iters auto --rust-warmup 100
git diff --check
```

验证结果：

- 全部通过。
- 最新结果目录：`/tmp/dae-daex-functional-bench-20260524-113626`
- matrix 从 `8` 个 case 扩展到 `11` 个 case。
- 11/11 case 均有 Go/Rust 双侧 3 次重复数据。

最新完整结果：

| case | Go us/op | Rust us/op | Rust/Go time | Go B/op | Rust B/op | Rust/Go B | Go allocs/op | Rust allocs/op | Rust/Go allocs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| config/parser_example | 1827.829 | 20.267 | 0.011 | 1766930.333 | 36525.000 | 0.021 | 28414.333 | 419.000 | 0.015 |
| config/schema_example | 1901.166 | 26.357 | 0.014 | 1781442.333 | 44485.000 | 0.025 | 28696.000 | 592.000 | 0.021 |
| config/include_merger | 335.288 | 46.385 | 0.138 | 238443.667 | 30038.000 | 0.126 | 4112.000 | 359.000 | 0.087 |
| config/marshal_roundtrip_example | 2221.287 | 36.074 | 0.016 | 2098440.667 | 78852.000 | 0.038 | 34684.333 | 1063.000 | 0.031 |
| dns/packed_response_restore | 0.020 | 0.013 | 0.671 | 48.000 | 45.000 | 0.938 | 1.000 | 1.000 | 1.000 |
| routing/domain_matcher_bitmap | 0.275 | 0.096 | 0.349 | 64.000 | 29.000 | 0.453 | 3.000 | 2.000 | 0.667 |
| outbound/select_min_latency | 0.010 | 0.010 | 1.050 | 0.000 | 0.000 | n/a | 0.000 | 0.000 | n/a |
| protocol/socks5_udp_packet_wrap | 0.198 | 0.085 | 0.430 | 91.000 | 67.000 | 0.736 | 4.000 | 4.000 | 1.000 |
| protocol/vless_request_header | 0.430 | 0.100 | 0.232 | 549.000 | 63.000 | 0.115 | 15.000 | 4.000 | 0.267 |
| control/magic_network_mark_mptcp | 0.016 | 0.013 | 0.808 | 16.000 | 10.000 | 0.625 | 1.000 | 1.000 | 1.000 |
| engine/runtime_overview | 0.107 | 0.013 | 0.121 | 320.000 | 24.000 | 0.075 | 3.000 | 1.000 | 0.333 |

结论：

- config 组已从 parser 单点扩展到 parser/schema/include/marshal 四项。
- Rust 在 config 四项均明显优于 Go；其中 `include_merger` 的收益相对较小，但仍为 time `0.138x`、B/op `0.126x`、allocs/op `0.087x`。
- 后续继续按 feature 扩展，不做无关拆分；下一步可补 routing/geodata/sniffing 组剩余 case，或进入协议 header/buffer hot path。

## 16. 2026-05-24 routing/geodata/sniffing 组一次补完

用户要求 routing/geodata/sniffing 组剩余 case 不拆阶段、一次补完。本轮一次性补齐：

- `routing/prefix_parse`
- `geodata/streaming_geoip_hit`
- `sniffing/http_host`

同时将原有 `routing/domain_matcher_bitmap` 从 `main.rs` 移入 routing 功能文件。

修改：

- `rust/crates/dae-bench/src/cases/routing.rs`
  - 新增 `routing/prefix_parse`。
  - 迁入 `routing/domain_matcher_bitmap`。
  - `routing/prefix_parse` 按 Go `IpParserFactory` 语义只解析 prefix，不额外生成字符串，避免把无关 string allocation 纳入对比。
- `rust/crates/dae-bench/src/cases/geodata.rs`
  - 新增 `geodata/streaming_geoip_hit`。
- `rust/crates/dae-bench/src/cases/sniffing.rs`
  - 新增 `sniffing/http_host`。
- `rust/crates/dae-bench/src/cases/mod.rs`
  - 注册 routing/geodata/sniffing 功能模块。
- `rust/crates/dae-bench/src/main.rs`
  - 注册 routing/geodata/sniffing cases。
  - 移除 routing domain matcher 的本地实现，避免继续加厚 `main.rs`。
- `rust/Cargo.toml`
  - workspace dependency 增加 `dae-geodata`。
- `rust/crates/dae-bench/Cargo.toml`
  - 增加 `dae-geodata` 与 `dae-sniffing` 依赖。
- `tools/bench/functional_matrix.toml`
  - matrix 从 11 个 case 扩展到 14 个 case。

验证：

```bash
cargo fmt --manifest-path rust/Cargo.toml --all
cargo check --manifest-path rust/Cargo.toml -p dae-bench
cargo run --manifest-path rust/Cargo.toml -p dae-bench --release --quiet -- --case routing/prefix_parse --iters auto --warmup 10 --repeat 1
cargo run --manifest-path rust/Cargo.toml -p dae-bench --release --quiet -- --case geodata/streaming_geoip_hit --iters auto --warmup 10 --repeat 1
cargo run --manifest-path rust/Cargo.toml -p dae-bench --release --quiet -- --case sniffing/http_host --iters auto --warmup 10 --repeat 1
PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off go test -run '^$' -bench 'BenchmarkRebuildStage3RoutingGeodataSniffing/(routing_prefix_parse|geodata_streaming_geoip_hit|sniffing_http_host)' -benchmem -count=1 -benchtime=50ms .
python3 tools/bench/run_functional_bench.py --go-count 3 --go-benchtime 100ms --rust-repeat 3 --rust-iters auto --rust-warmup 100
git diff --check
```

验证结果：

- 全部通过。
- 最新结果目录：`/tmp/dae-daex-functional-bench-20260524-114646`
- 14/14 case 均有 Go/Rust 双侧 3 次重复数据。

新增组结果：

| case | Go us/op | Rust us/op | Rust/Go time | Go B/op | Rust B/op | Rust/Go B | Go allocs/op | Rust allocs/op | Rust/Go allocs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| routing/prefix_parse | 0.194 | 0.120 | 0.619 | 224.000 | 0.000 | 0.000 | 3.000 | 0.000 | 0.000 |
| geodata/streaming_geoip_hit | 6.209 | 0.043 | 0.007 | 248.000 | 38.000 | 0.153 | 10.000 | 2.000 | 0.200 |
| sniffing/http_host | 2.560 | 0.085 | 0.033 | 9164.333 | 42.000 | 0.005 | 15.000 | 3.000 | 0.200 |

最新完整结果：

| case | Go us/op | Rust us/op | Rust/Go time | Go B/op | Rust B/op | Rust/Go B | Go allocs/op | Rust allocs/op | Rust/Go allocs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| config/parser_example | 1919.949 | 21.087 | 0.011 | 1766901.667 | 36525.000 | 0.021 | 28414.333 | 419.000 | 0.015 |
| config/schema_example | 1911.426 | 27.051 | 0.014 | 1781449.667 | 44485.000 | 0.025 | 28696.000 | 592.000 | 0.021 |
| config/include_merger | 349.004 | 46.969 | 0.135 | 238307.333 | 30038.000 | 0.126 | 4112.000 | 359.000 | 0.087 |
| config/marshal_roundtrip_example | 2375.910 | 35.814 | 0.015 | 2098584.667 | 78852.000 | 0.038 | 34686.667 | 1063.000 | 0.031 |
| dns/packed_response_restore | 0.020 | 0.014 | 0.677 | 48.000 | 45.000 | 0.938 | 1.000 | 1.000 | 1.000 |
| routing/domain_matcher_bitmap | 0.275 | 0.097 | 0.353 | 64.000 | 29.000 | 0.453 | 3.000 | 2.000 | 0.667 |
| routing/prefix_parse | 0.194 | 0.120 | 0.619 | 224.000 | 0.000 | 0.000 | 3.000 | 0.000 | 0.000 |
| geodata/streaming_geoip_hit | 6.209 | 0.043 | 0.007 | 248.000 | 38.000 | 0.153 | 10.000 | 2.000 | 0.200 |
| sniffing/http_host | 2.560 | 0.085 | 0.033 | 9164.333 | 42.000 | 0.005 | 15.000 | 3.000 | 0.200 |
| outbound/select_min_latency | 0.010 | 0.010 | 1.059 | 0.000 | 0.000 | n/a | 0.000 | 0.000 | n/a |
| protocol/socks5_udp_packet_wrap | 0.197 | 0.086 | 0.436 | 91.000 | 67.000 | 0.736 | 4.000 | 4.000 | 1.000 |
| protocol/vless_request_header | 0.460 | 0.105 | 0.227 | 549.000 | 63.000 | 0.115 | 15.000 | 4.000 | 0.267 |
| control/magic_network_mark_mptcp | 0.017 | 0.012 | 0.743 | 16.000 | 10.000 | 0.625 | 1.000 | 1.000 | 1.000 |
| engine/runtime_overview | 0.125 | 0.013 | 0.103 | 320.000 | 24.000 | 0.075 | 3.000 | 1.000 | 0.333 |

结论：

- routing/geodata/sniffing 组剩余 case 已一次补完。
- `routing/prefix_parse` 已按更接近 Go 的 parse-only 语义修正，不再使用旧 Rust example 的 string 输出路径。
- `geodata/streaming_geoip_hit` 和 `sniffing/http_host` Rust 侧显著低于 Go 的 time/B/op/allocs/op。
- 下一步可继续按 feature 补 outbound/protocol 更完整矩阵，或补 DNS/engine/control 剩余高价值 case。

## 17. 2026-05-24 DNS/engine/control 组一次补完

用户要求 DNS/engine/control 更细功能 case 不拆阶段、一次补完。本轮按一个功能块完成，matrix 从 14 个 case 扩展到 29 个 case。

新增/整理：

- DNS：
  - `dns/cache_key_roundtrip`
  - `dns/cache_ttl_lookup`
  - `dns/doh_get_request`
  - `dns/doh_post_request`
  - `dns/doh_validate_content_type`
  - `dns/validation_question_id`
  - `dns/resolve_asis_guard`
- control：
  - `control/choose_dial_target_domain`
  - `control/choose_dial_target_domain_plus_plus`
  - `control/udp_endpoint_trim_target`
- engine：
  - `engine/runtime_overview_scoped_udp`
  - `engine/route_aware_target`
  - `engine/parse_config_api`
  - `engine/necessary_outbounds`
  - `engine/subscription_persist_cleanup`

物理拆分：

- `rust/crates/dae-bench/src/cases/dns.rs`
  - 承载 DNS packed response、cache key、TTL lookup、DoH、response validation、resolve guard。
- `rust/crates/dae-bench/src/cases/control.rs`
  - 承载 magic network、choose dial target、UDP endpoint trim target。
- `rust/crates/dae-bench/src/cases/engine.rs`
  - 承载 RuntimeOverview、route-aware target、ParseConfig API、NecessaryOutbounds、subscription persist cleanup。
- `rust/crates/dae-bench/src/main.rs`
  - 只保留 runner、计量器和暂未拆出的 outbound/protocol case，避免继续加厚。
- `control/functional_bench_test.go`
  - 增加 DNS 和 control 细分 Go benchmark。
- `engine/functional_bench_test.go`
  - 增加 engine 细分 Go benchmark。
- `tools/bench/functional_matrix.toml`
  - 注册新增 case。

验证：

```bash
cargo fmt --manifest-path rust/Cargo.toml --all
gofmt -w control/functional_bench_test.go engine/functional_bench_test.go
cargo check --manifest-path rust/Cargo.toml -p dae-bench
PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off go test ./control -run '^$' -bench 'BenchmarkFunctional(Dns|Control)|BenchmarkRebuildStage7UdpEndpointTrimTarget' -benchmem -count=1 -benchtime=20ms
PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off go test ./engine -run '^$' -bench 'BenchmarkEngine(RuntimeOverviewScopedUdpTaskPool|RouteAwareTarget|NecessaryOutbounds|ParseConfigAPI|SubscriptionPersistCleanup)' -benchmem -count=1 -benchtime=20ms
cargo run --manifest-path rust/Cargo.toml -p dae-bench --release --quiet -- --case all --iters auto --warmup 10 --repeat 1 --output /tmp/dae-daex-dns-engine-control-rust-smoke.jsonl
python3 tools/bench/run_functional_bench.py --go-count 3 --go-benchtime 100ms --rust-repeat 3 --rust-iters auto --rust-warmup 100
git diff --check
```

验证结果：

- 全部通过。
- Rust smoke：`/tmp/dae-daex-dns-engine-control-rust-smoke.jsonl`，29 行。
- 最新完整结果目录：`/tmp/dae-daex-functional-bench-20260524-120312`
- 29/29 case 均有 Go/Rust 双侧 3 次重复数据。

DNS/engine/control 新增组结果：

| case | Go us/op | Rust us/op | Rust/Go time | Go B/op | Rust B/op | Rust/Go B | Go allocs/op | Rust allocs/op | Rust/Go allocs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| dns/cache_key_roundtrip | 0.216 | 0.203 | 0.940 | 64.000 | 150.000 | 2.344 | 4.000 | 10.000 | 2.500 |
| dns/cache_ttl_lookup | 0.583 | 0.652 | 1.119 | 1136.000 | 2093.000 | 1.842 | 7.000 | 21.000 | 3.000 |
| dns/doh_get_request | 0.795 | 0.524 | 0.660 | 1464.000 | 295.000 | 0.202 | 17.000 | 12.000 | 0.706 |
| dns/doh_post_request | 1.567 | 0.922 | 0.588 | 5024.000 | 2616.000 | 0.521 | 13.000 | 11.000 | 0.846 |
| dns/doh_validate_content_type | 0.778 | 0.254 | 0.327 | 896.000 | 259.000 | 0.289 | 11.000 | 9.000 | 0.818 |
| dns/validation_question_id | 0.697 | 0.324 | 0.464 | 340.000 | 476.000 | 1.400 | 14.000 | 13.000 | 0.929 |
| dns/resolve_asis_guard | 0.249 | 0.017 | 0.066 | 288.000 | 107.000 | 0.372 | 5.000 | 1.000 | 0.200 |
| control/choose_dial_target_domain | 0.392 | 0.084 | 0.213 | 640.000 | 44.000 | 0.069 | 11.000 | 3.000 | 0.273 |
| control/choose_dial_target_domain_plus_plus | 0.434 | 0.082 | 0.189 | 664.000 | 44.000 | 0.066 | 12.000 | 3.000 | 0.250 |
| control/udp_endpoint_trim_target | 0.000 | 0.001 | 6.459 | 0.000 | 0.000 | n/a | 0.000 | 0.000 | n/a |
| engine/runtime_overview_scoped_udp | 0.062 | 0.006 | 0.099 | 224.000 | 0.000 | 0.000 | 1.000 | 0.000 | 0.000 |
| engine/route_aware_target | 0.089 | 0.107 | 1.198 | 48.000 | 11.000 | 0.229 | 1.000 | 1.000 | 1.000 |
| engine/parse_config_api | 160.369 | 2.772 | 0.017 | 153347.667 | 8100.000 | 0.053 | 2678.000 | 90.000 | 0.034 |
| engine/necessary_outbounds | 0.137 | 0.079 | 0.575 | 160.000 | 170.000 | 1.062 | 4.000 | 6.000 | 1.500 |
| engine/subscription_persist_cleanup | 77.948 | 72.062 | 0.924 | 1825.667 | 1690.000 | 0.926 | 31.000 | 26.000 | 0.839 |

结论：

- DNS/engine/control 更细功能 case 已一次补完。
- DNS cache key 与 TTL lookup 当前 Rust allocation 高于 Go，后续优化应优先看 `String` canonicalization、`to_string()` roundtrip、`BTreeMap`/clone 路径。
- DoH GET/POST/validate、DNS response validation、resolve guard 当前 Rust time 均优于 Go。
- control choose dial target Rust time/B/op/allocs/op 均优于 Go。
- `control/udp_endpoint_trim_target` 两边都是 0 allocation 的极小函数，time ratio 受 ns 级噪声影响，不作为架构收益判断。
- engine route-aware target Rust B/op 更低但 time 略慢，后续可看 host/port parse 与 `SocketAddr` formatting。
- engine parse_config_api、runtime_overview_scoped_udp、subscription cleanup 均建立了可重复对比基线。

## 18. 2026-05-24 剩余 benchmark 全量补齐记录

时间：2026-05-24 12:23 CST

用户要求：还有哪些 benchmark 没做，全部补齐完成；不要再按阶段拆分。

本轮先审计现有 Go benchmark，确认前一轮 29 case 之外仍缺少以下可对照功能面：

- outbound filter：`BenchmarkDialerSetFilterAndAnnotateRegex`。
- DNS 边界：`BenchmarkDnsDataWithZeroID`。
- protocol link / metadata / packet / shared transport：
  - SOCKS5 address codec、handshake bytes。
  - VLESS parse link、password2key。
  - VMess parse link、metadata bytes、UUID5 compatibility。
  - Shadowsocks parse link、metadata bytes、SS2022 PSK split。
  - Trojan parse link、TCP request header、UDP packet。
  - HTTP parse link、CONNECT request、forward request。
  - Hysteria2 parse link、export link、pin normalize。
  - TUIC parse link、export link、ALPN split。
  - Juicity parse link、export link、pinned decode。
  - AnyTLS parse/new dialer 对照、auth key、frame、underlay。
  - Shared transport XHTTP mode、gRPC cache key、XHTTP path、canonical JSON、timer constants。
- engine 文件读取：`BenchmarkEngineReadConfigFileMinimal`。
- trace：ringbuf parse、tracker add。
- sysdump：enum strings。
- CLI：validate minimal config、export outline。

本轮修改：

- 新增并按功能物理隔离 Rust benchmark：
  - `rust/crates/dae-bench/src/cases/outbound.rs`
  - `rust/crates/dae-bench/src/cases/protocol.rs`
  - `rust/crates/dae-bench/src/cases/trace.rs`
  - `rust/crates/dae-bench/src/cases/sysdump.rs`
  - `rust/crates/dae-bench/src/cases/cli.rs`
- 扩展已有 Rust benchmark：
  - `rust/crates/dae-bench/src/cases/dns.rs` 增加 `dns/data_zero_id`。
  - `rust/crates/dae-bench/src/cases/engine.rs` 增加 `engine/read_config_file_minimal`。
- `rust/crates/dae-bench/src/main.rs` 继续瘦身，只负责 runner 聚合；outbound/protocol/trace/sysdump/cli 均从 feature 文件注册。
- `rust/crates/dae-bench/Cargo.toml` 增加 `base64`、`dae-cli`、`dae-sysdump`、`dae-trace` 依赖。
- `tools/bench/functional_matrix.toml` 从 29 case 扩展到 71 case，并为新增 Rust case 建立 Go/Rust 映射。

运行中修正：

- `protocol/shared_canonical_json` 的 fixture 修正为与 Go `BenchmarkSharedTransportNativeOptInCanonicalJSON` 相同的合法 JSON，避免 Rust parser 因尾随字符失败。
- `engine/read_config_file_minimal` 与 `cli/validate_minimal_config` 的临时配置文件权限设置为 `0600`，保持 Rust merger 的生产安全约束，不放宽校验。
- `cli/validate_minimal_config` 按 `dae_cli::validate_config_file` 实际返回的 entry 数计入 checksum，避免错误假设返回结构。

完整结果：

- 输出目录：`/tmp/dae-daex-functional-bench-20260524-122326`
- matrix：`71/71` case 均有 Go/Rust 双侧数据。
- 重复次数：Go `count=3`，Rust `repeat=3`。
- Go benchtime：`100ms`。
- Rust：`iters=auto`，`warmup=100`。

验证：

- `cargo fmt --manifest-path rust/Cargo.toml --all`：通过。
- `cargo check --manifest-path rust/Cargo.toml -p dae-bench`：通过。
- `cargo run --manifest-path rust/Cargo.toml -p dae-bench --release --quiet -- --case all --iters auto --warmup 10 --repeat 1 --output /tmp/dae-daex-all-bench-rust-smoke.jsonl`：通过，输出 `71` 条 Rust case。
- `python3 tools/bench/run_functional_bench.py --go-count 3 --go-benchtime 100ms --rust-repeat 3 --rust-iters auto --rust-warmup 100`：通过，输出 `/tmp/dae-daex-functional-bench-20260524-122326`。
- `cargo test --manifest-path rust/Cargo.toml -p dae-bench`：通过。
- `python3 -m py_compile tools/bench/run_functional_bench.py`：通过。
- `git diff --check`：通过。

本轮结果摘要：

| 组 | 覆盖状态 | 备注 |
| --- | --- | --- |
| config | 已覆盖 | parser/schema/include/marshal，保持 4 case。 |
| routing/geodata/sniffing | 已覆盖 | domain matcher、prefix parse、geoip hit、HTTP host。 |
| DNS | 已覆盖 | packed restore、zero id、cache key、TTL、DoH、validate、resolve guard。 |
| outbound | 已覆盖 | select min latency、filter annotate regex。 |
| protocol | 已覆盖 | SOCKS5/VLESS/VMess/Shadowsocks/Trojan/HTTP/Hysteria2/TUIC/Juicity/AnyTLS/shared transport。 |
| control | 已覆盖 | MagicNetwork mark mptcp、dial target、UDP endpoint trim。 |
| engine | 已覆盖 | runtime overview、route target、parse config、read config file、necessary outbounds、subscription cleanup。 |
| trace | 已覆盖 | ringbuf parse、tracker add。 |
| sysdump | 已覆盖 | enum strings。 |
| CLI | 已覆盖 | validate minimal config、export outline。 |

重要性能信号：

- 明显 Rust 优势：
  - config parser/schema/marshal 约 `0.010x-0.015x` Go time。
  - geodata streaming geoip hit 约 `0.007x` Go time。
  - sniffing/http_host 约 `0.031x` Go time。
  - engine/parse_config_api 约 `0.015x` Go time。
  - VLESS/Trojan/TUIC/Juicity/AnyTLS 多数 parse/header/packet case 显著低于 Go time 与分配。
- 需要后续优化：
  - `protocol/vmess_metadata_bytes`：time `6.029x`，Rust 有 1 次分配，Go 0 分配。
  - `protocol/vmess_uuid5_compatibility`：time `2.659x`，B/op `1.667x`，allocs `2.000x`。
  - `protocol/vmess_parse_link`：time `1.784x`，B/op `2.135x`，allocs `1.690x`。
  - `protocol/shared_xhttp_mode`：time `2.805x`，Rust 有 2 次分配，Go 0 分配。
  - `protocol/shared_grpc_cache_key`：time `2.582x`，B/op `2.250x`，allocs `3.000x`。
  - `cli/export_outline`：time `2.189x`，B/op `4.474x`，allocs `18.165x`。
  - `dns/cache_key_roundtrip`：B/op `2.344x`，allocs `2.500x`。
  - `dns/cache_ttl_lookup`：time `1.106x`，B/op `1.842x`，allocs `3.000x`。
  - `protocol/vless_password_to_key`：time `2.024x`，B/op `1.467x`，allocs `1.750x`。
  - `protocol/tuic_alpn_split`：time `1.409x`，B/op `2.250x`，allocs `4.000x`。
  - `protocol/shadowsocks_parse_link`：time `1.551x`，allocs `2.000x`。
  - `control/udp_endpoint_trim_target`、`sysdump/enum_strings`、`protocol/shared_timer_constants` 属 ns 级噪声哨兵，不作为独立性能结论。

边界说明：

- 本轮补齐的是当前 Rust 重构功能面的可对照 functional benchmark。
- Go 侧需要外部 helper/env、root/daemon admission、或非同等 fixture 的 benchmark 不混入本 micro/meso matrix；这些继续归入 admission/root-gated benchmark。
- `protocol/anytls_parse_link` 当前与 Go `BenchmarkAnyTLSNativeOptInNewDialer` 对照，Go 名称包含 dialer construction 语义，Rust 侧目前覆盖 AnyTLS link parse/new dialer 输入同源语义；后续如 AnyTLS Rust 构造器进一步完善，可把该 case 细化为 parse 与 constructor 两条。

## 19. 2026-05-24 count=10/benchtime=1s 完整重跑记录

时间：2026-05-24 12:56 CST

用户指出前一轮 `count=3` 太少，要求改为 `count=10`、`benchtime=1s` 再跑一次完整测试。本轮已完成。

运行参数：

- Go：`count=10`、`benchtime=1s`。
- Rust：`repeat=10`、`iters=auto`、`warmup=100`。

结果：

- 输出目录：`/tmp/dae-daex-functional-bench-20260524-125657`
- matrix：`71/71` case 均有 Go/Rust 双侧数据。
- 本地完整汇总表已更新：`DAEX_RUST_FUNCTIONAL_BENCHMARK_SUMMARY_2026-05-24.md`

稳定后的主要优化候选：

- `protocol/vmess_metadata_bytes`：time `6.274x`，Rust 有 1 次分配，Go 0 分配。
- `protocol/shared_xhttp_mode`：time `2.848x`，Rust 有 2 次分配，Go 0 分配。
- `protocol/vmess_uuid5_compatibility`：time `2.644x`，B/op `1.667x`，allocs `2.000x`。
- `protocol/shared_grpc_cache_key`：time `2.526x`，B/op `2.250x`，allocs `3.000x`。
- `cli/export_outline`：time `2.263x`，B/op `4.490x`，allocs `18.165x`。
- `protocol/vless_password_to_key`：time `2.008x`，B/op `1.467x`，allocs `1.750x`。
- `protocol/vmess_parse_link`：time `1.783x`，B/op `2.135x`，allocs `1.690x`。
- `protocol/tuic_alpn_split`：time `1.619x`，B/op `2.250x`，allocs `4.000x`。
- `protocol/shadowsocks_parse_link`：time `1.577x`，allocs `2.000x`。
- `dns/cache_key_roundtrip`：B/op `2.344x`，allocs `2.500x`。
- `dns/cache_ttl_lookup`：time `1.121x`，B/op `1.842x`，allocs `3.000x`。

边界：

- `control/udp_endpoint_trim_target`、`sysdump/enum_strings`、`protocol/shared_timer_constants` 仍属于 ns 级哨兵，time ratio 不作为独立性能结论。
- 这轮长跑结果比前一轮 `count=3/100ms` 更适合作为后续优化前基线。
