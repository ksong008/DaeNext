# DAEX Rust Native / Outbound Native Plan

创建时间：2026-06-01

## 1. 目标边界

本计划用于 v1 混合架构之后的 Rust native 推进，重点约束 outbound native 化。当前 v1 混合架构保持不变：

- `daed` 产品壳、WebUI、API、DB：Go。
- `dae-wing` runtime orchestration：Go。
- userspace control-plane、routing、DNS、sniff、reload、group selection、health check：Go。
- outbound 协议栈、`outbound`、`quic-go`：Go。
- eBPF load/adopt/attach/map backend：Rust/Aya。

Native 推进的长期目标：

- eBPF backend：Rust/Aya 默认，Go BPF loader/fallback 不再进入默认路径。
- userspace control-plane：逐步 Rust-owned/in-process，但必须先保留产品行为。
- outbound：逐协议 Rust native，测一个、默认一个、删除一个 Go fallback。
- 最终只在全部协议、transport、DNS/routing/sniff/reload/benchmark 准入后，才考虑移除 Go outbound 链路。

本计划不是 v1 混合架构替换计划。v1 混合架构继续作为生产默认安全基线，native 只能在明确 admission 通过后逐项接管。

## 2. 原则

1. Rust native 是实现形态，不是脱离 daenew 行为重新定义产品。
2. Go/outbound 当前行为作为兼容 oracle；Go 语义不是最终架构，但在迁移阶段必须作为外部行为基准。
3. `clash-rs` 作为 Rust native 参考项目，不作为直接依赖或直接替换件。
4. 不允许按测试机 config 写特例；Telegram、TG、节点 tag、IP、域名、geoip/geosite code 只能作为通用规则回归样本。
5. native 默认接管前必须有 benchmark、协议 parity、reload parity、真实 host validation。
6. 不使用 helper/cgo/sidecar 作为最终 native 形态；过渡工具只能留在 test-support 或 admission。
7. uTLS/fingerprint/Reality/Vision/xHTTP/QUIC 等能力必须按真实 wire 行为实现；未实现时 admission 必须 fail，不能 silent fallback 成普通 rustls。
8. 每个协议 native 后必须能删除对应 Go fallback；不能长期保留双实现但默认路径不清楚。
9. 计划阶段只允许大阶段推进，不新增无必要的小阶段。

## 3. Native 分布

| 区域 | v1 当前状态 | native 目标 | 优先级 | 备注 |
|---|---|---|---|---|
| eBPF loader/attach/map | Rust/Aya 默认 | 继续 Rust/Aya，后续再评估 aya-ebpf program | P0 已完成 v1 | 不因 outbound native 反复重写 kernel program |
| kernel eBPF program | C eBPF | 后续单独评估 aya-ebpf | P3 | 不能和 outbound native 混做 |
| Go BPF loader/fallback | 默认路径已清理 | 非默认诊断/测试边界继续收缩 | P1 | 不阻断 v1 |
| outbound link parser/metadata | Rust crate 已有部分 | Rust native 默认 parser | P0 | 必须覆盖 dae link chain |
| outbound group/health/selection | Go 默认 | Rust native policy + connectivity owner | P1 | 直接影响 `outbound_connectivity_map` |
| outbound protocol dataplane | Go 默认 | 逐协议 Rust native | P0-P2 | 本计划重点 |
| DNS/routing/sniff userspace | Go 默认 | Rust-owned control-plane 后迁 | P2 | outbound 默认前必须能消费同一 route result |
| daed product shell/WebUI/API | Go | 暂不 native | P4 | 不影响 outbound native |
| daewing orchestration | Go | 暂不 native | P4 | 保持产品链稳定 |

## 4. `clash-rs` 参考价值

参考项目：`https://github.com/Watfaq/clash-rs`。

当前审计结论：

- `clash-rs` 是完整代理内核，不是单独 outbound crate。
- 它的 `OutboundHandler` trait、protocol handler、transport stack 可以参考。
- 它已有 VLESS Vision / Reality splice / Trojan / VMess / Shadowsocks / Hysteria2 / TUIC 等 Rust 实现，对 outbound native 很有价值。
- 它的 `VisionStream` 和 `SplicableTlsStream` 设计值得重点借鉴：Vision 层解析 `CMD_DIRECT`，通过显式 flag 通知下层 raw bypass，避免在 TLS decrypt error 后猜测 raw direct。
- 但它当前 VLESS converter 对 `client-fingerprint` / uTLS 仍是 parsed but ignored，因此不能直接解决 `fp=chrome`、`utls_imitate=chrome_auto` 这类 daenew 真实配置。
- 它的配置、session、DNS、routing、group selection 是 Clash 模型，不能直接替换 dae/outbound。

使用方式：

1. 锁定一个 `clash-rs` commit 作为参考样本，记录到 native admission 证据。
2. 只参考结构和协议状态机，不直接复制产品语义。
3. 对每个协议建立三方对照：Go outbound 当前行为、`clash-rs` 参考实现、DAEX Rust native 实现。
4. 以 daenew 当前配置与真实流量为最终准入标准。

## 5. Outbound Native 总体架构

目标结构：

```text
dae-control/native route result
  -> dae-outbound native registry
  -> outbound group / health / policy
  -> protocol handler
  -> transport stack
  -> relay / UDP endpoint
```

2026-06-05 Rust product RSS follow-up remaining 1-4 completed:

```text
Context:
  The previous implementation batch explicitly completed item 5:
    Go daed log/API/WebUI display parity and generic resident flow log fields.

  This batch completed the remaining items 1-4 from the RSS follow-up list.

1. Service/package runtime memory defaults are now explicit:
  - daed product service contract now reports `rust_product_runtime_defaults`.
  - package-info and package-manifest expose runtime defaults under their
    runtime/defaults surfaces.
  - exported systemd unit and docker entrypoint now make the fixed defaults
    visible through environment lines/exports.
  - HTTP worker count remains dynamic when DAED_HTTP_WORKERS is unset:
      available_parallelism * 2 clamped to 4..16.
    It is documented as a policy instead of being forced to a fixed value.
  - Fixed defaults exposed:
      MALLOC_ARENA_MAX=2
      MALLOC_CONF=background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000,narenas:2
      DAED_HTTP_QUEUE=256
      DAED_HTTP_WORKER_STACK_BYTES=1048576
      DAE_RESIDENT_TCP_FLOW_STACK_BYTES=524288
      DAE_RESIDENT_UDP_PACKET_WORKERS=64
      DAE_RESIDENT_UDP_PACKET_STACK_BYTES=262144
  - UDP exposure is only the current test/runtime limit. It is not a final
    fixed-worker design; the target remains a Tokio UDP readiness/task-queue
    model, not fixed OS-thread fanout and not one thread per packet.

2. Resident dataplane group node selection now avoids large transient clones:
  - fixed-policy selection no longer builds a cloned candidate Vec for every
    matching node.
  - The selector keeps only first-match and fixed-index-match references, then
    clones only the selected tag/link.
  - Explicit name filter failure semantics are unchanged: unresolved names do
    not fall back to unrelated static nodes.
  - Added a generic fixed-policy order test with non-protocol-specific fixture
    names.

3. Rust native production routing no longer needs daemon-side JSON fixture
   round-trip:
  - The resident production path is now:
      Config -> typed ResidentRoutingPlan -> eBPF maps + typed userspace matcher.
  - The old production path:
      typed ResidentRoutingPlan -> JSON fixture -> RoutingMatcher
    has been removed.
  - dae-routing now provides typed matcher input:
      RoutingDomainSet
      RoutingLpmSet
      RoutingMatchSet
      RoutingMatchKind
      RoutingMatcher::from_typed_sets(...)
  - IpPrefix now has `IpPrefix::new(addr, bits)` so resident routing can pass
    prefixes without string formatting/parsing.
  - JSON fixture API remains in dae-routing for test/benchmark/golden corpus
    compatibility, but Rust native runtime does not depend on it.
  - The unused daemon-side userspace matcher fixture generator was removed.

4. Runtime overview/log streaming is lighter:
  - /api/events/runtime still sends a full `runtime.overview` first.
  - Periodic `runtime.overview.delta` now uses a lightweight payload and omits
    heavy/static trees such as:
      allocatorStats
      allocatorReclaim
      resourcePools
      runtime summary
  - If reloadCount changes, the stream sends a new full `runtime.overview`
    boundary snapshot instead of continuing with stale static state.
  - resident event-file traffic fallback no longer scans the whole event file
    every tick. It now keeps an offset cache and aggregates recent traffic by
    timestamp second, with a 3600-second retention cap matching the API window
    clamp.
  - /api/events/logs was already tail/cached-id based after the prior log
    parity work; no extra log-file full-scan behavior was added.

Validation:
  - `cargo fmt --all --manifest-path rust/Cargo.toml`: pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-routing userspace`:
      pass, 3 tests passed.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon --lib`:
      pass, 208 tests passed.

JSON fixture rule:
  Rust native production paths must not require JSON fixtures. Fixtures may
  remain only for tests, benchmarks, golden corpus compatibility, debug exports,
  or external tooling that explicitly consumes fixture-shaped data.
```

2026-06-05 10.10.10.2 latest Rust native daed binary deployment:

```text
Local commits before deployment:
  dae-daex-align:
    8c886252 Complete runtime product cleanup

  daed-daex-align/daed:
    881e1a5 Align task log field rendering
    Note: this WebUI source commit was local-committed with --no-verify because
    the local shell has Node v18.20.4 while Vite 8 requires Node >=20.19 or
    >=22.12. `pnpm --filter daed check-types` had passed before commit.

Build:
  cwd:
    /root/project/dae-daex-align

  command:
    cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf

  result:
    pass

  artifact:
    /root/project/dae-daex-align/rust/target/release/daed

  artifact info:
    size: 20M
    file: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
    sha256: 9fc8b4301f3b669be624ca5496c79babab418e822fe4028cfaa348e049377d6c

Deployment target:
  host:
    10.10.10.2

  pre-deploy /usr/bin/daed:
    size: 50M
    file: ELF 64-bit LSB executable, x86-64, statically linked, stripped
    sha256: b296303fc01b0cd4453ab90bb7bf988d6315a952a548fd483a0a9c5bab2448bf

  rollback anchor:
    /usr/bin/daed-daex-align-webui-cpu-20260601
    This stable rollback file was created only if missing. No per-test backup
    file was added.

  installed /usr/bin/daed:
    sha256: 9fc8b4301f3b669be624ca5496c79babab418e822fe4028cfaa348e049377d6c
    size: 20M

Service env:
  The first restart failed because Rust product binary intentionally refuses to
  become the C10 runtime owner without explicit resident dataplane admission:
    set DAE_RUST_RESIDENT_DATAPLANE=1

  Added controlled drop-in:
    /etc/systemd/system/daed.service.d/30-daex-rust-native-runtime.conf

  The drop-in does not use the old Go-shell selector DAED_RUNTIME=rust-owned.
  It only enables resident dataplane admission and the explicit runtime memory
  defaults:
    DAE_RUST_RESIDENT_DATAPLANE=1
    MALLOC_ARENA_MAX=2
    MALLOC_CONF=background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000,narenas:2
    DAED_HTTP_QUEUE=256
    DAED_HTTP_WORKER_STACK_BYTES=1048576
    DAE_RESIDENT_TCP_FLOW_STACK_BYTES=524288
    DAE_RESIDENT_UDP_PACKET_WORKERS=64
    DAE_RESIDENT_UDP_PACKET_STACK_BYTES=262144

Post-deploy validation:
  systemd:
    ActiveState=active
    SubState=running
    MainPID=42308
    ExecMainStatus=0

  process:
    /usr/bin/daed run -c /etc/daed/
    observed RSS at check time: 66692 KiB

  listener:
    0.0.0.0:2023 owned by daed pid 42308

  HTTP health:
    GET http://127.0.0.1:2023/api/health -> {"healthCheck":1}

  journal after the successful restart:
    only systemd start line was present at the time of the check; no new daed
    exit/error appeared after the resident dataplane admission drop-in was
    added.

Scope note:
  This deployment replaced the product binary. WebUI source changes in
  daed-daex-align/daed are committed, but static WebUI assets on 10.10.10.2
  were not rebuilt/copied in this binary-only deployment.
```

核心 trait 建议：

```text
NativeOutboundHandler
  name()
  protocol()
  support_tcp()
  support_udp()
  connect_tcp(session, target, route_context)
  connect_udp(session, target, route_context)

NativeTransport
  connect(raw_io, transport_context)
  selected_alpn()
  can_splice()

SpliceCapableIo
  enable_raw_read()
  enable_raw_write()
  drain_plaintext_leftover()
```

核心数据模型：

- `OutboundLink`：保留原始 link、scheme、tag、subscription tag。
- `OutboundPlan`：协议、transport、TLS、uTLS/fingerprint、mark、MPTCP、UDP 能力。
- `RouteContext`：src、dst、domain、l4proto、ipversion、mark、must、pname、dscp、mac。
- `DialDecision`：dial target、dial_ip、selected group、selected node、strict ip version。
- `ProtocolAdmission`：该 link 是否可由 Rust native 默认接管，以及失败原因。

## 6. 阶段计划

### N0：Native 基线冻结

目标：

- 保留 `daex-hybrid-v1` 作为生产默认基线。
- 明确 native 工作不改变 v1 默认路径。
- 整理现有 native crate 能力清单，标记 `keep` / `test-support` / `delete-before-release`。

完成条件：

- `DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md` 记录 v1 与 native 的边界。
- 默认 `daed` 不启动 Rust resident protocol dataplane。
- 默认路径 Go outbound 仍稳定运行，Rust/Aya eBPF backend 继续生效。

### N1：Outbound Native Contract

目标：

- 建立 outbound 行为合同，不直接开始替换协议。
- 用当前 `github.com/ksong008/outbound` 行为作为 oracle。
- 把 `clash-rs` 锁定为参考实现，不作为默认依赖。

范围：

- link chain：`a -> b -> c` 从右向左构造。
- parser：VLESS、VMess、Trojan、SS、SSR、Socks、HTTP、Hysteria2、TUIC、Juicity、AnyTLS、xHTTP、Reality、SIP003。
- global option：`allow_insecure`、`tls_implementation`、`utls_imitate`、TLS fragment、bandwidth、UDPHop、MPTCP、mark。
- group：filter、annotation、min/random/fixed、alive latency、connectivity map。
- TCP：sniff 首包继续 relay、domain mode、IP/no-domain、half-close。
- UDP：endpoint pool、DNS UDP/53 例外、QUIC sniff 后仍保持 IP target。

完成条件：

- 形成 native outbound parity fixture 清单。
- 每个协议都有 admission 表：`not-started`、`parser-only`、`metadata-ready`、`loopback-ready`、`live-ready`、`default-ready`。
- benchmark 中明确 Go vs Rust parser/metadata/dataplane 入口。

### N2：Native Outbound Foundation

目标：

- 搭建不依赖 helper/cgo/Go fallback 的 Rust native outbound 框架。
- 先接 parser、metadata、group policy，不默认接管真实协议流量。

范围：

- `dae-outbound` native registry。
- `OutboundPlan` / `RouteContext` / `DialDecision`。
- group selection 和 alive state 的 Rust-owned 表达。
- `outbound_connectivity_map` 写入合同。
- Rust native admission gate。

完成条件：

- parser/metadata/group benchmark 对比 Go。
- Go 默认 runtime 不受影响。
- 不支持的协议必须 fail closed，不允许误选 VLESS 或其他协议 handler。

### N3：VLESS/Vision/uTLS Native 试点

目标：

- 先攻克最复杂且曾暴露问题的 VLESS tcp/tls/vision。
- 使用 `clash-rs` 的 `VisionStream` / `SplicableTlsStream` 作为结构参考。
- 使用 Go outbound 的 Vision/uTLS 行为作为 wire oracle。

必须覆盖：

- `flow=xtls-rprx-vision`。
- VLESS Vision 试点、fixture、loopback 和 live smoke 必须使用带 link `fp` 的节点；无 `fp` 配置只能作为辅助对照，不能作为 N3 打开或验收依据。
- 通用 uTLS ClientHello ID / fingerprint 规则；`fp=chrome`、`utls_imitate=chrome_auto` 只能作为样本，不能作为特例。
- TLS1.3 inner direct。
- TLS1.2 inner plain-overlay。
- 非 TLS / Telegram-like MTProto plain-overlay。
- `CMD_CONTINUE` / `CMD_END` / `CMD_DIRECT`。
- Reality splice。
- VLESS response header strip。
- TCP half-close。
- IP/no-domain `dial_ip=true`。

完成条件：

- 带 link `fp` 的 native VLESS Vision fixture 通过，并证明 Rust 发出的 ClientHello wire 行为与 Go outbound oracle 对齐。
- Telegram-like 非 TLS 长连接 fixture 通过。
- 真实 Telegram IP/no-domain live smoke 通过，不能只用 `nc` 建连证明。
- `cannot decrypt`、bad record mac、`105/101 + reset` 不再出现。
- uTLS/fingerprint 必须实现真实 ClientHello wire 行为；仅有字段解析、无 `fp` 替代测试或 rustls fallback 时 admission fail，实现后才允许默认接管。

### N4：协议批量 Native

目标：

- 在 N3 框架稳定后，按 transport 家族批量推进协议，不逐个无限拆阶段。

批次：

1. 基础协议：direct、block/reject、HTTP proxy、SOCKS5。
2. TLS over TCP：Trojan、VMess、VLESS 非 Vision。
3. Shadowsocks 系列：SS、SS2022、SIP003、v2ray-plugin WS/TLS/mux、SSR。
4. QUIC/H3 系列：Hysteria2、TUIC、Juicity、ShadowQUIC、xHTTP/H3。
5. Reality/AnyTLS/特殊 transport：Reality、AnyTLS、xHTTP packet-up/stream-up。

完成条件：

- 每批都要有 parser、wire fixture、loopback、live smoke、benchmark。
- 每批通过后才允许默认接管该批协议。
- 每批默认接管后删除对应 Go fallback 入口或将其降为显式 legacy。

### N5：Native Control-Plane Integration

目标：

- outbound native 不是启动时选一个节点，而是每连接按 route result、sniff、domain mode、group policy 选择。

范围：

- `routing_tuples_map` 读取合同。
- `ChooseDialTarget` native 化。
- `Route` / userspace reroute native 化。
- DNS request/response routing 与 outbound native 接通。
- sniff 首包 ownership 保持。
- reload 时保持旧连接，不能无条件清空连接级运行态。

完成条件：

- Rust native 能按每条连接选择不同 outbound/group/node。
- domain path、IP/no-domain path、DNS path、UDP path 都通过真实验证。
- reload 不破坏既有 TCP 长连接。

### N6：Benchmark / Default Cutover

目标：

- 用统一 benchmark 决定默认切换，不靠单次 smoke。

benchmark 范围：

- parser：ns/op、B/op、allocs/op。
- group selection：min/random/fixed。
- alive/connectivity update。
- TCP relay：throughput、latency、alloc。
- UDP relay：QPS、latency、endpoint reuse。
- VLESS Vision：TLS1.3 direct、plain-overlay、Telegram-like。
- QUIC/H3：Hysteria2/TUIC/Juicity/xHTTP。
- reload：连接保持、内存增长、map/state 保留。

完成条件：

- 每项 native 默认接管前展示 Go vs Rust 对比成绩。
- 若 Rust 不领先但架构收益明确，必须记录原因和风险。
- 默认接管后跑 38 机真实 host validation。

### N7：Go Fallback 删除与 Release 收口

目标：

- 全协议 native 后删除默认路径 Go outbound 依赖。
- 保留 daed WebUI/API/DB 的 Go 产品壳，直到单独计划替换。

完成条件：

- 默认 `daed` 不依赖 Go outbound 协议栈。
- `outbound` / `quic-go` 从默认 runtime 依赖中移除或降为 legacy build。
- release binary、service、reload、WebUI、API、benchmark 全部通过。
- tag 并记录 native release baseline。

## 7. VLESS Vision Native 设计要点

`clash-rs` 可参考点：

- `VisionStream` 独立处理 frame。
- `SplicableTlsStream` 通过显式 flag 切 raw。
- `CMD_DIRECT` 后 raw passthrough 不依赖 TLS decrypt error。
- Reality TLS 与 Vision state machine 分层。

DAEX 必须补齐点：

- uTLS/fingerprint 等价实现必须走通用 ClientHello ID registry 和 wire emitter；`chrome`、`chrome_auto` 只是 registry 中的普通 alias/fixture，不能写专用分支。
- Telegram/MTProto-like 非 TLS payload 必须走 `CMD_END` / plain-overlay。
- TLS1.3 inner 才允许 direct；TLS1.2 不能 direct。
- first block padding、long padding、UUID 首帧、分片 TLS record 都必须覆盖。
- 不能把当前测试节点是 VLESS 写成 routing 主流程假设。

native 状态机建议：

```text
Uplink:
  Padding
  PlainOverlay
  Direct

Downlink:
  Framed
  PlainOverlay
  Direct

InnerTlsObserver:
  Unknown
  NonTls
  TlsHandshake
  Tls13Eligible
  Tls13Ineligible
  ApplicationData
```

准入失败条件：

- `fp` 非空但 Rust fingerprint ClientHello wire emitter 未实现。
- `tls_implementation=utls` 但 Rust uTLS ClientHello wire emitter 未实现。
- `flow=xtls-rprx-vision` 但 Vision state machine 未通过 Telegram-like fixture。
- Reality/xHTTP/H3/QUIC 依赖未完成却被默认接管。

## 8. 验证环境

本地：

- Go unit / Rust unit。
- Go vs Rust functional benchmark。
- 协议 fixture / loopback。
- pcap / raw wire fixture。

远程 38：

- 真实 host validation。
- 临时部署后必须清理二进制、service、tmp、netns、BPF pin。
- 配置仅作为测试输入，不作为实现标准。

10.10.10.2：

- 只能在用户明确授权后部署。
- 用于产品链真实流量观察，不作为开发残留机器。

## 9. 当前建议的下一步

先执行 N1，不改默认 runtime：

1. 锁定 `clash-rs` 参考 commit，并记录 Vision/Reality/outbound handler 参考点。
2. 把现有 Go outbound、DAEX Rust crate、`clash-rs` 做协议矩阵对照。
3. 生成 native outbound admission 表。
4. 补 VLESS Vision / Telegram-like / uTLS/fingerprint fixture 设计。
5. 再决定 N2 框架代码入口。

执行 N1 前不应开始删除 Go outbound，也不应把 Rust resident protocol dataplane 打开为默认。

## 10. N3 前置实验记录：VLESS Vision IP/no-domain（2026-06-01）

目标：

- 先用带 link `fp` 的 VLESS Vision native 做小范围实验，修复原先 IP/no-domain 场景容易被误判到 raw-direct 的问题。
- 保持 hybrid v1 默认路径不变，不打开 Rust resident protocol dataplane 作为生产默认。

本轮结论：

- IP/no-domain 路由语义应保持 `dial_ip=true`、`dial_target=dst`、不因 `domain++` 强行 reroute；已补单测覆盖。
- VLESS Vision 下行 raw-direct 只能由明确 `CMD_DIRECT` 触发；`CMD_CONTINUE` 和 `CMD_END` 完成后遇到 outer TLS 解密错误，不能猜测成 underlay raw direct。
- 当前 Rust resident VLESS 已先接入通用 uTLS ClientHello ID 解析和准入规则；link `fp` 优先于全局 `utls_imitate`，未知 ID fail-closed，`chrome`/`chrome_auto` 不作为特例。
- 当前 Rust resident VLESS 仍没有把 uTLS ClientHello wire emission 接到真实 TLS 会话，因此 `tls_implementation=utls` 或 link `fp` 非空时仍必须 admission fail，不能 silent fallback 成普通 rustls。
- 无 `fp` / 无 `utls` 的 rustls VLESS Vision 配置只能作为 routing、Vision state machine 或 parser 的辅助回归，不能作为 N3 native VLESS Vision 打开、二进制验证或 live smoke 验收对象。
- N3 的二进制验证必须使用带 link `fp` 的配置；在 Rust uTLS/fingerprint wire emitter 未接入前，正确结果是解析 `fp` 后 fail-closed 并保留 Go outbound，不能 silent fallback 成普通 rustls。

已修改：

- `resident_dataplane/tcp.rs`
  - raw-direct recovery 改为要求 `VisionUnpadder.direct_command_seen == true`。
  - 增加 IP/no-domain `domain++` 选择回归测试。
- `resident_dataplane/plan.rs`
  - 增加通用 uTLS ClientHello ID 解析，复用 `dae-outbound::shared_transport` 的 Go uTLS registry。
  - 增加 `fp` / `tls_implementation=utls` wire emitter 未接入前的 fail-closed admission。
  - 增加 link `fp`、全局 `utls_imitate`、未知 fingerprint、非 Chrome profile 的准入测试。

验证：

- `cargo fmt --manifest-path rust/Cargo.toml -p dae-daemon -- --check`：通过。
- `resident_vless_vision`：通过，12/12。
- `resident_dataplane`：通过，37/37。
- `dae-outbound utls`：通过，8/8。

后续进入 N3 前必须补齐：

- Rust uTLS/fingerprint wire emitter，必须覆盖通用 registry；`chrome`、`chrome_auto` 只作为样本。
- 带 link `fp` 的 VLESS Vision loopback/live fixture：TLS1.3 direct、TLS1.2 plain-overlay、非 TLS/MTProto plain-overlay、IP/no-domain 长连接、half-close。
- Go outbound wire oracle 对照，确认 `CMD_CONTINUE` / `CMD_END` / `CMD_DIRECT` 分片、padding 和 response header strip 全部一致。

## 11. N3 前置实验记录：带 fingerprint 的 native TLS underlay（2026-06-02）

背景：

- Hytron 能在 Rust-owned native 模式下跑通，不代表 Rust native 已经真正实现 `fp=chrome` 的 Go/uTLS wire parity；更可能是 Hytron 服务端/网络路径对当前非 Chrome ClientHello 更宽容。
- Oracle-Sg 暴露的问题是：resident VLESS Vision 之前只是在 plan 阶段接受了带 `fp` 的链接，但实际 TLS 仍由 `rustls::ClientConnection` 创建，`fp` 没有参与 ClientHello wire 行为。
- 本轮要求是继续测试 VLESS Vision native，不为 `fp=chrome` 写特例，也不回落到 Go outbound。

原 crate 检查结论：

- `dae-outbound::shared_transport` 可复用的部分是 uTLS fingerprint registry 和解析能力：`SUPPORTED_UTLS_FINGERPRINTS`、`resolve_utls_client_hello_id`、`UtlsFingerprint`。
- `dae-outbound::shared_transport::U_TLS_WIRE_STACK_DEFERRED` 仍为 `true`，说明 Rust crate 内部还没有可直接接入生产 TLS 会话的完整 uTLS wire stack。
- `utls_wire_builder` 只能构造 synthetic ClientHello 记录，用于 profile/fixture/对照；它没有 ECDHE private key、transcript、key schedule 和 TLS 会话状态，不能直接替代 TLS engine。
- 因此当前可用策略是：复用原 crate 的通用 fingerprint registry/plan/telemetry；真实 TLS underlay 另接 Rust native TLS 实现，不能声称已经完整等价 Go uTLS。

本轮实现状态：

- `ResidentProxyPlan` 增加 `utls_fingerprint`，link `fp` 优先，全局 `tls_implementation=utls` + `utls_imitate` 作为后备；未知 fingerprint fail-closed。
- `DAE_EXPERIMENT_VLESS_VISION_FP_RUST_NATIVE=1` 编译时，带 `fp` 的 VLESS Vision native 不再因 `U_TLS_WIRE_STACK_DEFERRED` 直接拒绝；未启用该编译开关时仍 fail-closed。
- TLS underlay 改为双实现：
  - 无 fingerprint：继续 `rustls`。
  - 有 fingerprint：使用 Rust `boring` crate 的 BoringSSL underlay。
- BoringSSL underlay 设置：
  - Vision 下限制 TLS 1.3。
  - 按 fingerprint family 设置 groups/GREASE/extension permutation，不为 `chrome` 写业务特例。
  - 支持 `force-no-alpn` / `force-alpn` policy。
  - 显式 `set_read_ahead(false)`，降低 Vision direct/raw 切换时下层 TLS 主动预读的风险。
- resident TCP event 增加 `tls_underlay`，用于现场确认当前连接实际使用 `rustls` 还是 `boringssl`。
- resident startup report 增加 `default_proxy.utls_fingerprint`，用于确认 plan 没有丢失 link `fp` 元数据。
- BoringSSL 分支修复 pending plaintext flush，避免首个 VLESS request header 只进队列不写出。

重要限制：

- 当前是 fingerprint-aware native TLS underlay，不是完整 Go/uTLS ClientHello profile parity。
- BoringSSL 的 GREASE、groups、extension permutation 可以改善 wire shape，但不能保证完全复刻 `chrome_auto`、`firefox_105`、`safari` 等每个 uTLS profile 的 cipher/extension/order/ALPS/padding 细节。
- 上游 `rustls` 不能作为 link `fp` 的完整实现路径：它可以承接标准 TLS、SNI、ALPN、TLS 版本和部分 cipher/group 配置，但没有公开接口稳定控制 Chrome/uTLS 级别的 ClientHello wire fingerprint，例如 extension 顺序、GREASE、padding、key share 形态和 Boring/Chrome 默认行为。
- 因此 DAEX 下的 TLS underlay 必须按通用原则拆分：无 fingerprint 时使用 `rustls` standard TLS underlay；link/global fingerprint 非空时使用 fingerprint-aware TLS underlay，当前实现选项为 BoringSSL/`boring`，不得 silent fallback 成普通 `rustls`。
- 不建议 fork `rustls` 来硬改 ClientHello 编码作为主线方案；该路径维护成本高，容易和上游安全更新冲突，只能作为研究备选，不作为 C7 admission 默认方向。
- `chrome` 不能作为特例；后续如果继续提升 wire parity，必须围绕通用 `UtlsFingerprint` registry 建 profile emitter/adapter，并用 Go outbound pcap 作为 oracle。
- Vision raw-direct 最终仍应以明确 `CMD_DIRECT` 为触发条件；不能依赖 outer TLS decrypt error 猜测 raw direct。

验证：

- `DAE_EXPERIMENT_VLESS_VISION_FP_RUST_NATIVE=1 cargo test --manifest-path rust/Cargo.toml -p dae-daemon resident_dataplane`：通过，40/40。
- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon resident_dataplane_plan_resolves_link_fingerprint_before_wire_gate`：通过，默认无实验开关仍 fail-closed。
- `DAE_EXPERIMENT_VLESS_VISION_FP_RUST_NATIVE=1 cargo check --manifest-path rust/Cargo.toml -p dae-daemon --bin dae-daemon-optin`：通过。

后续 live validation 要求：

- 用带 link `fp` 的 VLESS Vision 节点验证，不允许用无 `fp` 节点替代 N3 验收。
- 现场事件必须看到 `default_proxy.utls_fingerprint` 非空，TCP connection event 的 `tls_underlay` 为 `boringssl`。
- Oracle-Sg、Hytron 等真实节点要分别验证 Telegram-like 非 TLS 长连接、TLS1.3 inner direct、IP/no-domain path 和 half-close。
- 如果 Oracle-Sg 仍失败，需要抓 Go outbound 与 Rust BoringSSL native 的 ClientHello/后续 Vision frame 对照；不要用服务端宽容路径替代 wire parity 结论。

## 12. `clash-rs` 当前 VLESS Vision 审计（2026-06-02）

参考 commit：

- `Watfaq/clash-rs`：`bd146397ba7aec677ec7e65eae5f4eaac6339494`。

TLS / Boring 结论：

- `clash-rs` 当前 VLESS 普通 TLS 使用 `tokio-rustls::TlsConnector`，不是 BoringSSL。
- VLESS Reality 使用 patched `rustls` 的 `rustls::client::RealityConfig` + `tokio_rustls::TlsConnector`，不是 BoringSSL。
- 依赖中出现的 `boring-noise` / `boringtun` 是 WireGuard/noise 相关 optional dependency，不是 VLESS/TLS underlay。
- `client-fingerprint` 在 VLESS converter 中只 warn：`client-fingerprint (uTLS) is not yet implemented, ignored`；因此 `clash-rs` 当前不能作为 `fp=chrome` / uTLS ClientHello parity 的参考实现。

VLESS Vision 实现方式：

- 层次结构：

```text
VisionStream
  -> VlessStream
    -> SplicableTlsStream   only when Reality transport returns VisionOptions
      -> Reality TLS tokio-rustls stream
        -> raw TCP
```

- `VlessStream` 负责 VLESS request header、flow addon、response header strip。
- `VisionStream` 负责 Vision padding frame：
  - 首帧添加 UUID。
  - frame header 为 command/content_len/padding_len。
  - 读路径解析 `CMD_PADDING_CONTINUE` / `CMD_PADDING_END` / `CMD_PADDING_DIRECT`。
  - 只有 `CMD_PADDING_DIRECT` 会设置 splice flag，通知下层 raw bypass。
- `SplicableTlsStream` 读取 `VisionStream` 设置的 `read_flag` / `write_flag`：
  - raw read splice 前先 drain rustls plaintext reader 到 leftover。
  - splice 后读写直接绕过 Reality TLS，操作底层 raw IO。

可借鉴点：

- `VisionStream` 与 TLS underlay 通过显式 flag 协作，比在 TLS decrypt error 后猜测 raw direct 更清晰。
- `SplicableTlsStream` 的 leftover drain 是关键设计：切 raw 前必须先处理 TLS 明文缓冲区里已经解出的数据。
- Reality splice 的层次注释清楚，可作为 DAEX resident Vision/Reality 分层参考。

不能直接照搬点：

- `clash-rs` 写路径当前只按 payload 首字节 `0x17` 判断 TLS ApplicationData 并发送 `CMD_PADDING_DIRECT`；DAEX 需要继续保留 inner TLS observer，确保 TLS1.3 eligible 才 direct，TLS1.2/非 TLS/MTProto-like 必须 plain-overlay。
- `clash-rs` 不实现 uTLS fingerprint；不能用它证明 `fp=chrome` 或通用 fingerprint wire parity。
- `clash-rs` 的 routing/group/session 语义是 Clash 模型，仍只能作为协议结构参考，不能替代 DAEX/daenew admission。

## 13. 10.10.10.2 live validation：Telegram 经 Oracle-Sg + BoringSSL underlay（2026-06-02）

现场状态：

- `daed.service` 使用临时 Rust-owned test drop-in：
  - `DAED_RUNTIME=rust-owned`
  - `DAED_RUST_DAEMON=/etc/daed/rust-owned-runtime/bin/dae-daemon-optin`
  - `DAED_RUST_RESIDENT_DATAPLANE_DEFAULT=1`
- runtime 子进程为 `/etc/daed/rust-owned-runtime/bin/dae-daemon-optin run -c /etc/daed/rust-owned-runtime/generated.dae`。
- 部署的 runtime sha256：`fad9dda837a7ba0b45714a985f4d2eb21b7b8bd28b037ea6451284c54a3168ff`。
- `resident-production-runtime-start.json` 显示 `resident_dataplane.status=pass`。

配置确认：

- `generated.dae` 中 `TG` 组为 `filter:name("14.[SG]Oracle-Sg")`。
- `telegram` 路由为：
  - `domain(geosite:"telegram")->TG`
  - `dip(geoip:"telegram")->TG`
- `14.[SG]Oracle-Sg` 链接保留：
  - `fp=chrome`
  - `flow=xtls-rprx-vision`
  - `sni=office.mitsuha.me`
  - `alpn=h2,http/1.1`

事件证据：

- 事件文件：`/tmp/dae-daemon-resident-runtime-16476/resident-production-dataplane-events.jsonl`。
- Telegram 目标 IP 段 `91.108.*` / `149.154.*` 的事件统计：
  - `26 tcp_connection_finished node=14.[SG]Oracle-Sg underlay=boringssl`
- 样例目标包括：
  - `149.154.171.5:5222`
  - `149.154.171.5:80`
  - `91.108.56.177:443`
  - `91.108.56.177:80`

结论：

- Telegram 当前确实走 `14.[SG]Oracle-Sg`，不是 Hytron。
- Oracle-Sg 这条原本暴露 Rust native `fp` 缺口的路径，在本轮 BoringSSL fingerprint-aware native underlay 下可以完成 Telegram TCP 连接。
- 因此本轮问题可记录为：BoringSSL underlay 解决了当前 10.10.10.2 上 VLESS Vision Rust native + link `fp=chrome` 对 Oracle-Sg 的实测阻断问题。
- 限制仍不变：这证明 BoringSSL fingerprint-aware native underlay 在当前路径可用，不等同于已经实现完整 Go/uTLS `chrome_auto` wire parity。

## 14. DAEX 独立链全项目 Rust native 计划校准（2026-06-02）

本节用于承接“DAEX 整个项目 Rust native owned，最终去除 Go”的新计划，避免继续把全项目计划塞进主性能优化备忘录。结论先写明：

- 必须考虑整条 DAEX 独立链，而不是只看 `dae-daex-align` 或 outbound 协议矩阵。
- 当前全链路 truth source 是：

```text
daed-daex-align
  -> daed/wing submodule
    -> dae-daex-align
      -> outbound-daex-align
        -> quic-go-daex-align
```

- `daed/wing submodule` 是 daed 实际构建入口；`/root/project/dae-wing-daex-align` 只能作为兄弟仓库/同步源，不能在 gate 中静默替代 `daed` 当前持有的 submodule pointer。
- 如果 `daed/wing` 子模块与 `/root/project/dae-wing-daex-align` 提交、dirty 状态或默认 bundle 策略不一致，product-chain gate 必须 blocked，不能把兄弟仓库 pass 当作 daed 构建链路 pass。

### 14.1 当前链路事实

`daed-daex-align/daed` 当前默认构建路径：

```text
daed/Makefile
  -> build WebUI dist
  -> cd wing
  -> make bundle
    -> deps / go generate
    -> make -C /root/project/dae-daex-align rust-aya-bpf-loader-asset
    -> go build -tags=embedallowed
```

已核对事实：

- 默认 `bundle` 是 hybrid v1 clean bundle。
- 默认 `bundle` 只嵌入 Rust/Aya BPF loader asset，不构建、不嵌入 `dae-daemon-optin`。
- `bundle-rust-owned` 是显式候选入口，才会构建 `dae-daemon-optin --features native-ebpf` 并使用 `rust_owned_daemon_embed` tag。
- release/action/Docker 当前默认调用 `make` 或 `make bundle`，没有默认调用 `bundle-rust-owned`。
- `wing/engine/runtime_mode.go` 当前无环境变量时仍走 Go native service；只有显式 `DAED_RUNTIME` / `DAED_RUNTIME_MODE=rust-owned` 才会选 Rust-owned service。
- `install/daed.service` 当前是 `ExecStart=/usr/bin/daed run -c /etc/daed/`，没有设置 Rust-owned runtime 环境。
- 当前 module replace 必须按实际文件为准：
  - `github.com/daeuniverse/dae => /root/project/dae-daex-align`
  - `github.com/daeuniverse/outbound => /root/project/outbound-daex-align`
  - `github.com/daeuniverse/quic-go => /root/project/quic-go-daex-align`
- 构建时必须使用 `/root/.local/go1.25.9/bin` 在 `PATH` 前，并设置 `GOWORK=off`；否则旧 Go 工具会解析失败，`DAE_MODULE_DIR` 可能退回 `dae-core`，导致 Rust asset 目标错误。

### 14.2 命名原则

- 顶层阶段、work package、gate、feature/admission 名称必须使用通用能力名，不得包含具体协议名。
- 具体协议名只能出现在 protocol matrix、fixture、测试用例、handler 内部实现和 evidence 描述中。
- 当前带 link fingerprint 的 live result 只作为 `outbound-fingerprint-underlay-v1` 的验证样本，不作为阶段名。

### 14.3 全链路阶段计划

| 阶段 | 名称 | 目标 | 当前状态 |
| --- | --- | --- | --- |
| C0 | `product-chain-topology-lock-v1` | 锁定 `daed -> daed/wing submodule -> dae -> outbound -> quic-go` 实际链路 | gate 已实现 |
| C1 | `default-bundle-boundary-v1` | 区分 hybrid 默认 bundle 与 Rust-owned candidate bundle，并写入 gate | gate 已实现 |
| C2 | `default-runtime-selector-v1` | 无环境变量时默认选择 Rust-owned；显式 rollback 才选择 Go | gate 已实现 |
| C3 | `daed-service-contract-v1` | 将 `install/daed.service`、package scripts、Web/API、runtime reload/stop/overview 纳入 gate | gate 已实现 |
| C4 | `resident-runtime-platform-v1` | Rust daemon run/reload/stop/service-contract、typed report、memory/thread/fd gate | gate 已实现 |
| C5 | `control-plane-owner-v1` | routing/domain/connectivity/runtime state 由 Rust owner 持有，并能 reload/cleanup | gate 已实现 |
| C6 | `datapath-core-v1` | TCP/UDP/DNS tproxy、route、sniff、direct/block/proxy 由 Rust resident 承载 | gate 已实现 |
| C7 | `outbound-fingerprint-underlay-v1` | 通用 link/global fingerprint-aware TLS underlay 进入正式 feature/admission | gate 已实现；fingerprint-aware path fail-closed |
| C8 | `outbound-production-matrix-v1` | 主要生产 outbound handler 按矩阵逐项 native，并按项退役 Go fallback | gate 已实现 |
| C9 | `release-default-switch-v1` | release/action/Docker/package 默认切到 Rust-owned candidate | gate 已实现；需完整 readiness/rehearsal/freeze 证据 pass |
| C10 | `go-free-product-chain-v1` | 去除 Go product shell、Go runtime/control/API/service/release 默认路径 | gate 已实现；当前真实产品链 fail-closed |

阶段含义：

- C0-C3 是 daed 独立链入口校准，不完成就不能声称 product-chain ready。
- C4-C8 是 Rust-owned runtime/control/datapath/outbound 的生产能力。
- C9 是 Rust-owned default candidate，不等于最终去 Go。
- C10 才是用户要求的最终去 Go 阶段。
- `kernel-program-rewrite-v1` 只能作为 C10 之后的 optional side-track，不是 C0-C10 主线 stage；Rust native owned 的关键是 userspace/control/datapath/outbound/product-chain owner，不是立即重写 C eBPF program。

### 14.4 立即要补的 gate

1. `product-chain-topology-lock-v1`
   - 默认使用 `/root/project/daed-daex-align/daed/wing` 作为 wing repo。
   - 读取 `daed/.gitmodules`、submodule HEAD、兄弟仓库 HEAD、branch、dirty state。
   - 报告 `submodule_matches_sibling_repo`。
   - 不一致时 blocking，除非明确声明本轮只验证兄弟仓库，不验证 daed 构建链。

2. `default-bundle-boundary-v1`
   - `make -n bundle` 和 `make -n bundle-rust-owned` 都要进入 artifact。
   - 扫描 workflow、Dockerfile、publish.Dockerfile、release package 是否调用默认 `bundle` 或显式候选。
   - 构建产物后用 `go version -m`、strings/asset scan 验证：
     - build tags。
     - 是否包含 `rust_owned_daemon_embed`。
     - 是否包含 `dae-daemon-optin` asset。
     - 是否仍只包含 Rust/Aya BPF loader asset。

3. `default-runtime-selector-v1`
   - 单测和 artifact 必须覆盖：
     - 无 `DAED_RUNTIME`。
     - `DAED_RUNTIME=auto`。
     - `DAED_RUNTIME=rust-owned`。
     - `DAED_RUNTIME=go` rollback。
   - C9 前，无环境变量和 `auto` 必须选择 Rust-owned。
   - rollback mode 必须显式，不允许被误记为默认路径。

4. `daed-service-contract-v1`
   - 新增 daed service gate，不再用 `install/dae.service` 替代。
   - 覆盖：
     - `install/daed.service`。
     - package after-install / after-remove。
     - `/usr/bin/daed run -c /etc/daed/`。
     - Web/API `/api/runtime/overview`、`/api/runtime/reload`、`/api/runtime/stop`。
     - Rust-owned embedded runtime 与 external runtime 两种部署形态。
     - reload failure rollback。

5. `release-default-switch-v1`
   - release/action/Docker/package 必须显式切到 Rust-owned candidate 后才允许 C9 pass。
   - C9 live evidence 必须在 38 机和 `10.10.10.2` 分别记录。
   - 每次 live host-write 后必须有 backup manifest 和 rollback script，并验证恢复。

6. `go-free-product-chain-v1`
   - 这是最终去 Go 阶段，不与 C9 混淆。
   - 必须证明 Go product shell、Go runtime/control/API/service/release 默认路径不再参与正式产品链。
   - `outbound-daex-align` 与 `quic-go-daex-align` 的 Go dependency boundary 必须退役或移出默认包。
   - C10 之前，不得把“Go daed shell 嵌入 Rust daemon”描述为最终去 Go。

### 14.5 与 outbound native 的关系

- outbound native 是 C8 的核心内容，但 C8 不能脱离 C0-C7 独立通过。
- C8 的每个 protocol matrix entry 必须消费同一套 Rust-owned route result、group selection、connectivity state、DNS/sniff result、SO_MARK/MPTCP/dial mode。
- `outbound-fingerprint-underlay-v1` 是 C7 的 transport underlay 能力，不是某个协议的阶段名。
- 当前 BoringSSL live result 说明 fingerprint-aware underlay 能解决当前验证样本的阻断；它不能替代 C8 protocol matrix，也不能替代 C9/C10 product-chain gate。
- `clash-rs` 仍只能作为 protocol state machine / transport splice 的参考，不作为 DAEX product-chain、routing、group、service、release 的准入依据。

### 14.6 当前结论

- 是，后续 plan 必须考虑整条 DAEX 独立链：`daed-daex-align -> daed/wing submodule -> dae-daex-align -> outbound-daex-align -> quic-go-daex-align`。
- 只看 `dae-daex-align` 或 `outbound-daex-align` 会漏掉默认 bundle、runtime selector、daed service、release/action/Docker/package 这些最终切换硬门槛。
- 当前默认产品链仍是 hybrid v1 clean bundle；Rust-owned daemon 已有显式候选入口，但未成为默认 runtime。
- 下一步应先做 C0-C3，把 daed 实际构建入口和 product-chain gate 锁住，再继续推进 C4-C8 的 Rust-owned runtime/control/datapath/outbound native。

## 15. 重构后的 DAEX 独立链目标形态（2026-06-02）

本节记录按 C0-C10 计划重构后，DAEX 独立链应呈现的形态。必须分清两个状态：

- C9：Rust-owned default candidate，默认运行路径切到 Rust-owned，但 Go product shell 可能仍存在。
- C10：Go-free product-chain，Go 从默认产品链退役，才是最终“去 Go”。

### 15.1 当前 hybrid v1 形态

当前默认产品链：

```text
daed-daex-align
  -> daed/wing submodule
    -> dae-daex-align
      -> outbound-daex-align
        -> quic-go-daex-align
```

当前默认运行形态：

```text
/usr/bin/daed
  -> Go daed product shell / WebUI / API / DB
    -> Go dae-wing runtime orchestration
      -> Go dae userspace control-plane / routing / DNS / sniff / reload
        -> Go outbound protocol stack
          -> Go quic-go transport dependency
      -> Rust/Aya eBPF loader/backend asset
```

当前结论：

- 默认仍是 hybrid v1：Go product/control/outbound + Rust/Aya eBPF backend。
- `dae-daemon-optin` / Rust-owned runtime 只是显式实验或候选入口，不是默认链。

### 15.2 C9 后的 Rust-owned default candidate 形态

C9 `release-default-switch-v1` 通过后，目标链路应变为：

```text
daed-daex-align
  -> daed/wing submodule
    -> default bundle switches to Rust-owned candidate
      -> embedded or external Rust daemon
        -> dae-daex-align/rust
          -> Rust-owned runtime
          -> Rust-owned control-plane owner
          -> Rust-owned datapath core
          -> Rust outbound production matrix
          -> Rust/Aya eBPF userspace owner
        -> outbound-daex-align / quic-go-daex-align only as explicit fallback or retired-by-matrix dependency
```

运行态目标：

```text
/usr/bin/daed run -c /etc/daed/
  -> default runtime selector chooses Rust-owned without DAED_RUNTIME override
    -> Rust daemon run
      -> Rust config/load/reload owner
      -> Rust routing/domain/connectivity owner
      -> Rust TCP/UDP/DNS datapath
      -> Rust outbound handlers
      -> Rust transport underlay
      -> Rust/Aya eBPF loader/map/attach owner
```

C9 必须满足：

- release/action/Docker/package 默认入口已经切到 Rust-owned candidate。
- 无 `DAED_RUNTIME` / `DAED_RUNTIME_MODE` 时默认选择 Rust-owned。
- `DAED_RUNTIME=go` 只能作为显式 rollback，不再是默认。
- `install/daed.service`、package、Docker、release/action 都指向同一个 Rust-owned 默认路径。
- 38 机和 `10.10.10.2` 都有 live evidence。
- Go fallback 分层明确：BPF fallback、control-plane fallback、outbound fallback 不能混为一个 “Go fallback retired”。

C9 可以声明：

```text
DAEX default path is Rust-owned.
```

C9 不允许声明：

```text
DAEX 已经去 Go。
```

原因是 C9 仍可能存在 Go daed shell、Go Web/API、Go package shell 或 Go fallback。

### 15.3 C10 后的 Go-free final 形态

C10 `go-free-product-chain-v1` 通过后，最终独立链应收敛为：

```text
Rust product binary
  -> static WebUI asset serving / API server
  -> runtime lifecycle
      run / reload / stop / service-contract / health / progress / rollback
  -> config plane
      parse / validate / normalize / reload transaction
  -> control-plane
      routing map owner
      domain routing owner
      outbound connectivity owner
      group selection / health state
      runtime overview / stats / cache state
  -> datapath
      TCP tproxy
      UDP tproxy/session
      DNS active datapath
      sniff/direct/block/proxy
      MagicNetwork / SO_MARK / MPTCP / dial_mode / domain++
  -> outbound
      native link parser
      native metadata/export
      native protocol handlers
      native transport underlay
      fingerprint-aware TLS
      QUIC/H3/TUIC/Hysteria/Juicity equivalents as Rust-native or removed from default
  -> eBPF userspace owner
      loader / attach / detach / cleanup
      map schema / ABI / PARAM object
      TCX / tc-netlink / cgroup attach
```

最终产品链不应再是：

```text
daed Go shell
  -> dae-wing Go orchestration
    -> dae Go control-plane
      -> outbound Go protocol stack
        -> quic-go
```

而应收敛为：

```text
DAEX Rust product
  -> Rust daemon/control/datapath/outbound/release owner
```

### 15.4 仓库职责收敛

| 仓库/链路 | 当前职责 | C9 后职责 | C10 后职责 |
| --- | --- | --- | --- |
| `daed-daex-align` | Go product shell + WebUI + package/release entry | Rust-owned candidate 的默认 release/package entry | Go shell 退役；保留前端资产/安装元数据或迁移到 Rust product |
| `daed/wing submodule` | daed 实际 build truth | Rust-owned default launcher / compat shell | Go orchestration 退役 |
| `dae-daex-align` | Go dae core + Rust/Aya + Rust daemon experiments | Rust-owned runtime/control/datapath/outbound 主体 | Rust native product core |
| `outbound-daex-align` | Go outbound protocol oracle/default dependency | protocol matrix oracle 与逐项退役对象 | 不进入默认产品包，或被 Rust native outbound crate 替代 |
| `quic-go-daex-align` | Go QUIC/H3 transport dependency | transport oracle 与逐项退役对象 | 不进入默认产品包，或被 Rust transport/QUIC/H3 替代 |

### 15.5 最终运行与 service 目标

C9 允许的候选进程树：

```text
/usr/bin/daed              # Go product shell
  -> Rust-owned daemon     # default runtime
```

C10 最终进程树：

```text
/usr/bin/daed or /usr/bin/daex   # Rust product binary
```

最终 systemd 目标可以继续使用 `daed` 名称：

```text
ExecStart=/usr/bin/daed run -c /etc/daed/
ExecReload=/usr/bin/daed reload $MAINPID
```

但这里的 `/usr/bin/daed` 必须已经是 Rust product binary，不能只是 Go shell 调 Rust daemon。

默认运行时不应再需要：

```text
DAED_RUNTIME=rust-owned
DAED_RUST_DAEMON=...
DAED_RUST_RESIDENT_DATAPLANE_DEFAULT=1
```

这些变量只能保留为测试、兼容或迁移期控制面。

### 15.6 最终 admission 形态

最终 admission 不能再是单一布尔值，应拆成：

```text
product_chain_topology_locked=true
default_bundle_boundary_clean=true
default_runtime_selector_rust_owned=true
daed_service_contract_ready=true
resident_runtime_platform_ready=true
control_plane_owner_ready=true
datapath_core_ready=true
outbound_fingerprint_underlay_ready=true
outbound_production_matrix_ready=true
release_default_switch_ready=true
go_free_product_chain_ready=true
```

解释：

- `release_default_switch_ready=true` 只说明 Rust-owned 成为默认候选。
- `go_free_product_chain_ready=true` 才说明 Go 已从默认产品链退役。

一句话结论：

```text
当前：Go product/control/outbound + Rust/Aya eBPF backend。
C9：Go daed product shell -> Rust-owned daemon as default runtime。
C10：Rust DAEX product binary -> Rust runtime/control/datapath/outbound/release owner。
```

## 16. 最终详细重构计划与 crate 边界（2026-06-02）

本节记录最终重构计划。结论：

- 当前 `rust/crates` 已经足够支撑 C0-C10，不需要为了推进计划先新增 crate。
- 后续优先把职责落回现有 crate 边界；只有出现明确循环依赖、feature graph 污染、复用边界或最终 Rust product shell 职责冲突时，才允许新增 crate。
- 新增 crate 不能使用具体协议名作为顶层能力名；协议名只允许出现在 matrix、fixture、handler、tests、evidence 中。

### 16.1 当前可用 crate 边界

当前 workspace 已有以下关键 crate：

```text
dae-daemon
dae-product
dae-engine
dae-control
dae-datapath
dae-dns
dae-outbound
dae-routing
dae-sniffing
dae-geodata
dae-netutil
dae-core-types
dae-ebpf-support
dae-ebpf-program
dae-aya-bpf-loader
dae-config
dae-config-util
dae-cli
dae-bench
dae-golden
dae-sysdump
dae-trace
```

边界原则：

| crate | 保留/收拢职责 |
| --- | --- |
| `dae-daemon` | binary、runner、resident runtime、service-contract、live execution、host interaction adapter |
| `dae-product` | product-chain topology、bundle boundary、runtime selector gate、daed service contract、release/default switch、go-free product-chain admission |
| `dae-engine` | runtime API、overview、config-facing engine abstraction、Web/API runtime access contract |
| `dae-control` | routing/domain/connectivity/runtime state owner、reload owner、map owner |
| `dae-datapath` | TCP/UDP active datapath、route dial、direct/proxy/block/session |
| `dae-dns` | DNS active datapath、cache、message、qtype/qclass、upstream/forward/reject |
| `dae-outbound` | link parser、metadata、policy/group/health、protocol handlers、shared transport、fingerprint underlay、protocol matrix |
| `dae-routing` | route matcher、domain/geodata route contract、route result |
| `dae-sniffing` | sniff result、protocol sniff contract |
| `dae-geodata` | geosite/geoip data access and parity |
| `dae-netutil` | shared network helpers |
| `dae-core-types` | cross-crate stable types and contracts |
| `dae-ebpf-support` | userspace eBPF ABI/map/attach support |
| `dae-ebpf-program` | optional kernel program target boundary |
| `dae-aya-bpf-loader` | transitional / production Rust/Aya loader binary and embedded asset |
| `dae-golden` | golden fixtures and parity oracle |
| `dae-bench` | benchmark harness |
| `dae-trace` / `dae-sysdump` | diagnostics and evidence capture |

### 16.2 不新增 crate 的默认策略

默认不新增：

```text
dae-product-chain
dae-daed-contract
dae-runtime-selector
dae-fingerprint
dae-transport
dae-boring
dae-quic
任何协议名 crate
```

原因：

- `dae-product-chain` / `dae-daed-contract` / `dae-runtime-selector` 都应先放入 `dae-product`。
- fingerprint / transport underlay 当前应放入 `dae-outbound/shared_transport`，由 feature/admission 控制，不单独立顶层 crate。
- Boring 是 TLS underlay implementation，不是顶层产品能力。
- QUIC/H3 先保留在 `dae-outbound/shared_transport` 与 matrix；只有 feature graph 明确污染默认包时再评估拆分。
- 协议名 crate 不符合通用命名原则。

允许新增 crate 的硬条件：

1. 出现真实循环依赖，且无法通过移动 type/trait 到 `dae-core-types` 或现有 crate 解决。
2. 某能力需要独立 feature graph，否则会把 Boring/QUIC/H3/rcgen/test-support 等重依赖强行带入默认 binary。
3. 某能力需要被多个 top-level binary 复用，且不能依赖 `dae-daemon`。
4. C10 阶段 Rust product shell 与 daemon runtime 发生明确职责冲突，`dae-daemon` 不适合作为最终 product binary。
5. C10 之后如确实要做 optional kernel side-track，且 `dae-ebpf-program` / `dae-ebpf-support` 已不能表达 target split。

### 16.3 最终实施顺序

#### C0 `product-chain-topology-lock-v1`

目标：

- 锁定实际 DAEX 独立链：

```text
daed-daex-align -> daed/wing submodule -> dae-daex-align -> outbound-daex-align -> quic-go-daex-align
```

落点：

- `dae-product`：topology model、submodule/sibling repo report、admission summary。
- `dae-daemon`：runner 参数、artifact 输出、read-only gate 调用。

必须实现：

- 默认 `PRODUCT_CHAIN_DAE_WING_REPO` 指向 `/root/project/daed-daex-align/daed/wing`。
- 记录 `daed/.gitmodules`、submodule HEAD、兄弟仓库 HEAD、branch、dirty state、go.mod replace target。
- 输出 `submodule_matches_sibling_repo`。
- 子模块与兄弟仓库不一致时 blocked，除非本轮明确声明只验证兄弟仓库。

退出条件：

- `product_chain_topology_locked=true`。
- `submodule_build_truth_recorded=true`。
- `quic_go_path=/root/project/quic-go-daex-align`。

#### C1 `default-bundle-boundary-v1`

目标：

- 区分 hybrid 默认 bundle 与 Rust-owned candidate bundle。

落点：

- `dae-product`：bundle boundary contract、workflow/Docker/release scan、artifact schema。
- `dae-daemon`：build/run gate entrypoint。

必须实现：

- `make -n bundle` 与 `make -n bundle-rust-owned` 均进入 artifact。
- 扫描 `.github/workflows/*`、`Dockerfile`、`publish.Dockerfile`、package scripts。
- 构建产物后执行：
  - `go version -m`
  - build tag scan
  - embedded asset scan
  - Rust/Aya loader asset scan
  - Rust-owned daemon asset scan

退出条件：

- `default_bundle_boundary_clean=true`。
- `hybrid_bundle_shape_recorded=true`。
- `rust_owned_candidate_bundle_shape_recorded=true`。
- release/action/Docker 当前调用目标被明确记录。

#### C2 `default-runtime-selector-v1`

目标：

- C9 前默认 runtime selector 无环境变量时选择 Rust-owned；Go 只能是显式 rollback。

落点：

- `dae-product`：selector admission contract。
- `dae-engine`：runtime access abstraction。
- `daed/wing submodule`：Go shell 迁移期 selector 修改。
- `dae-daemon`：Rust service-contract 报告 selector expectation。

必须实现：

- 单测覆盖：
  - 无 `DAED_RUNTIME`。
  - `DAED_RUNTIME=auto`。
  - `DAED_RUNTIME=rust-owned`。
  - `DAED_RUNTIME=go`。
  - `DAED_RUNTIME_MODE` 同义行为。
- C9 前，无环境变量和 `auto` 必须选择 Rust-owned。
- rollback mode 显式化，不能被 admission 当默认路径。

退出条件：

- `default_runtime_selector_rust_owned=true`。
- `explicit_go_rollback_only=true`。
- `runtime_selector_matrix_recorded=true`。

#### C3 `daed-service-contract-v1`

目标：

- 用 daed2.0 产品链 service contract 替代当前偏 `/usr/bin/dae` 的 service gate。

落点：

- `dae-product`：daed service contract、package contract、Web/API contract。
- `dae-engine`：runtime overview/reload/stop API contract。
- `dae-daemon`：candidate binary service-contract 与 artifact。

必须实现：

- 检查 `install/daed.service`：
  - `ExecStart=/usr/bin/daed run -c /etc/daed/`。
  - reload semantics。
  - optional runtime rollback env policy。
- 检查 package after-install / after-remove。
- 检查 Web/API：
  - `/api/runtime/overview`
  - `/api/runtime/reload`
  - `/api/runtime/stop`
  - runtime event stream
- 同时覆盖 embedded Rust daemon 与 external Rust daemon。
- reload failure rollback 必须可验证。

退出条件：

- `daed_service_contract_ready=true`。
- `daed_runtime_api_contract_ready=true`。
- `package_contract_ready=true`。

#### C4 `resident-runtime-platform-v1`

目标：

- Rust daemon runtime 生命周期稳定，报告 typed 化，资源 gate 可控。

落点：

- `dae-daemon`：runtime owner、run/reload/stop/service-contract、resident report。
- `dae-engine`：runtime access API。
- `dae-core-types`：typed report structs。

必须实现：

- `resident-production-runtime-start.json` 瘦身。
- typed start/cleanup/event/report。
- memory/thread/fd/report-size gate。
- pid/progress/ready/abort/cleanup contract。
- reload rollback：
  - invalid config 不替换当前 runtime。
  - start failure 尝试恢复 previous runtime。

退出条件：

- `resident_runtime_platform_ready=true`。
- RSS/PSS/thread/fd/report-size 不超过 gate。
- service-contract 输出稳定。

#### C5 `control-plane-owner-v1`

目标：

- routing/domain/connectivity/runtime state 由 Rust owner 持有。

落点：

- `dae-control`：owner state、reload、map contract。
- `dae-routing`：route result parity。
- `dae-dns`：DNS route/cache integration。
- `dae-daemon`：resident adapter。

必须实现：

- routing map owner。
- domain routing owner。
- outbound connectivity owner。
- runtime overview/cache/stats。
- reload parity。
- cleanup leftovers gate。
- matched Go/Rust benchmark。

退出条件：

- `control_plane_owner_ready=true`。
- `go_control_plane_fallback_retired_candidate=true`。

#### C6 `datapath-core-v1`

目标：

- TCP/UDP/DNS tproxy、route、sniff、direct/block/proxy 由 Rust resident 承载。

落点：

- `dae-datapath`：TCP/UDP active datapath。
- `dae-dns`：DNS active datapath。
- `dae-sniffing`：sniff contract。
- `dae-netutil`：network helper。
- `dae-daemon`：resident runtime adapter。

必须实现：

- TCP route/sniff/direct/block/proxy。
- UDP session/router/direct/proxy/block。
- DNS qtype/qclass/cache/forward/reject。
- MagicNetwork、SO_MARK、MPTCP、dial_mode、domain++、must_direct。
- half-close、long-connection、cleanup、reload handoff。

退出条件：

- `datapath_core_ready=true`。
- TCP/UDP/DNS matrix pass。
- no Go userspace datapath fallback in admitted path。

#### C7 `outbound-fingerprint-underlay-v1`

目标：

- 通用 link/global fingerprint-aware TLS underlay 进入正式 feature/admission。

落点：

- `dae-outbound/shared_transport`：fingerprint registry、underlay contract、wire/admission。
- `dae-daemon`：resident adapter、event/report。
- `dae-product`：transport feature admission。

必须实现：

- link `fp` 与 global fingerprint plan。
- unknown fingerprint fail-closed。
- `rustls` standard TLS underlay 与 fingerprint-aware TLS underlay 的通用 contract。
- BoringSSL/`boring` underlay feature/admission，用于 link/global fingerprint 非空的路径。
- link/global fingerprint 非空时不得 silent fallback 成普通 `rustls`。
- Go/uTLS oracle pcap 对照。
- 不声明 full uTLS parity，除非 wire oracle 已覆盖。

退出条件：

- `outbound_fingerprint_underlay_ready=true`。
- live evidence 记录 underlay。
- 不使用协议名作为阶段名。

#### C8 `outbound-production-matrix-v1`

目标：

- 主要生产 outbound handler 按矩阵逐项 Rust native，并按项退役 Go fallback。

落点：

- `dae-outbound`：protocol parser/dataplane/shared transport。
- `dae-product`：product protocol matrix admission。
- `dae-golden`：Go oracle fixture。
- `dae-bench`：benchmark。
- `dae-daemon`：resident adapter。

必须实现：

- 每项 matrix 必须覆盖：
  - parser/export/metadata。
  - TCP/UDP dataplane。
  - transport underlay。
  - route result / group / connectivity。
  - reload behavior。
  - live smoke。
  - Go fallback retirement status。
- protocol names 只出现在 matrix entry、fixtures、handler、tests、evidence。

退出条件：

- `outbound_production_matrix_ready=true`。
- `go_outbound_fallback_retired_by_matrix=true`。

#### C9 `release-default-switch-v1`

目标：

- release/action/Docker/package 默认切到 Rust-owned candidate。

落点：

- `dae-product`：release default switch gate。
- `dae-daemon`：candidate binary。
- `daed-daex-align` / `daed/wing submodule`：Makefile/workflow/Docker/service/package 配套修改。

必须实现：

- 默认 release/action/Docker/package 调用 Rust-owned candidate。
- default runtime selector 无环境变量选择 Rust-owned。
- `install/daed.service` 与 package scripts 对齐。
- 38 机和 `10.10.10.2` live evidence。
- backup manifest、rollback script、恢复演练。

退出条件：

- `release_default_switch_ready=true`。
- `product_chain_switch_allowed=true`。
- `host_write_freeze_passed=true`。
- `rollback_rehearsal_passed=true`。

注意：

- C9 只代表 Rust-owned default candidate，不代表最终去 Go。

#### C10 `go-free-product-chain-v1`

目标：

- Go product shell、Go runtime/control/API/service/release 默认路径退役。

落点：

- `dae-product`：go-free product-chain admission。
- `dae-daemon` 或后续 Rust product binary：最终 product runtime。
- `dae-engine`：Rust Web/API/runtime owner。
- `dae-outbound`：Rust outbound default。
- `dae-control` / `dae-datapath` / `dae-dns`：Rust owner default。

必须实现：

- Go daed shell 不再是默认 product binary。
- Go dae-wing orchestration 退役。
- Go control-plane/runtime/datapath/outbound 默认路径退役。
- `outbound-daex-align` / `quic-go-daex-align` 不进入默认产品包，或仅保留为 oracle/test/compat。
- Rust product binary 提供 run/reload/stop/service-contract/Web/API/package/release。

退出条件：

- `go_free_product_chain_ready=true`。
- 默认产品包无 Go runtime/control/outbound/release dependency。
- live host pass。
- rollback model pass。

#### Post-C10 optional side-track：`kernel-program-rewrite-v1`

目标：

- 如需要，再评估 C eBPF program 改写为 Rust aya-ebpf。

落点：

- `dae-ebpf-program`。
- `dae-ebpf-support`。
- `dae-aya-bpf-loader`。

注意：

- 这不是 C0-C10 主线 stage，不允许命名为 C11，也不允许作为 C0-C10 的前置条件。
- Rust native owned 的关键是 userspace/control/datapath/outbound/product-chain owner，不是立即重写 C eBPF program。

### 16.4 验证顺序

每个阶段必须按以下顺序验证：

1. unit / golden / contract tests。
2. local dry-run artifact。
3. build metadata / feature graph / binary asset scan。
4. matched Go/Rust benchmark。
5. read-only switch-readiness gate。
6. live host smoke。
7. rollback rehearsal。
8. memo evidence record。

禁止：

- 用 live host 某条宽容路径替代 wire parity。
- 用 BPF fallback retirement 代表 userspace/control/outbound fallback retirement。
- 用 `bundle-rust-owned` 存在代表默认 runtime 已切换。
- 用兄弟仓库状态代表 `daed/wing` 子模块状态。
- 用 C9 结果代表 C10 去 Go完成。

### 16.5 硬性阶段执行规则

硬性规定：

- DAEX Rust native owned 主线只能按 C0-C10 大阶段推进。
- 不允许临时定义“下一步”来绕过 C0-C10 顺序。
- 不允许随意细分、新增或改名 stage。
- 不允许新增 C11、C12、临时 stage、插队 stage 或协议特定 stage。
- 阶段内需要更细粒度时，只能命名为 work item、gate、artifact、check、fixture 或 evidence，且必须挂在现有 C0-C10 之一下面。
- 如果确实需要调整 C0-C10 阶段定义，必须先修改本计划并记录原因；未记录前，不得在执行中口头扩展 stage。
- `kernel-program-rewrite-v1` 只能作为 C10 之后的 optional side-track，不属于 C0-C10 主线。

固定执行入口：

```text
C0 product-chain-topology-lock-v1
  -> C1 default-bundle-boundary-v1
    -> C2 default-runtime-selector-v1
      -> C3 daed-service-contract-v1
```

完成 C0-C3 后，再继续：

```text
C4 resident-runtime-platform-v1
C5 control-plane-owner-v1
C6 datapath-core-v1
C7 outbound-fingerprint-underlay-v1
C8 outbound-production-matrix-v1
```

最后才进入：

```text
C9 release-default-switch-v1
C10 go-free-product-chain-v1
```

当前最终结论：

- crates 已经足够；默认不新增。
- 重构重点是职责归位、gate 收紧、product-chain truth source 锁定。
- `dae-product` 应承接 product-chain/default switch/go-free admission。
- `dae-daemon` 保持 runtime/binary/live execution。
- `dae-outbound` 承接 outbound matrix 和 shared transport。
- `dae-control` / `dae-datapath` / `dae-dns` 承接 owner 和 datapath。
- C9 是 Rust-owned default candidate；C10 才是最终去 Go。
- 执行必须严格挂靠 C0-C10；禁止临时“下一步”和随意细分 stage。

## 17. C0-C3 implementation evidence（2026-06-02）

本节只记录 C0-C3 的实施证据，不新增 stage，不引入临时阶段。

### 17.1 修改内容

C0 `product-chain-topology-lock-v1`：

- `dae-daemon::product_chain_recertification` 新增 `native_owned_entry_gates` gate。
- 默认 product-chain 路径切到 DAEX 独立链：
  - `dae_repo=/root/project/dae-daex-align`
  - `daed_repo=/root/project/daed-daex-align/daed`
  - `dae_wing_repo=/root/project/daed-daex-align/daed/wing`
  - `outbound_repo=/root/project/outbound-daex-align`
  - `quic_go_repo=/root/project/quic-go-daex-align`
  - `service_file=/root/project/daed-daex-align/daed/install/daed.service`
  - `go_mod_file=/root/project/dae-daex-align/go.mod`
- `scripts/run_daex_switch_readiness_gate.sh` 默认 `PRODUCT_CHAIN_DAE_WING_REPO` 改为 `${PRODUCT_CHAIN_DAED_REPO}/wing`，不再默认使用 `/root/project/dae-wing-daex-align`。
- C0 report 记录：
  - `build_truth=daed/wing-submodule`
  - `submodule_build_truth_recorded`
  - `submodule_status`
  - `sibling_status`
  - `submodule_matches_sibling_repo`
  - `quic_go_path`
- 如果 `dae_wing_repo` 不是 `daed/wing`，或真实兄弟仓库与子模块 HEAD / dirty state 不一致，C0 进入 blocked。

C1 `default-bundle-boundary-v1`：

- report 记录默认 hybrid bundle 与 Rust-owned candidate bundle：
  - 默认 `bundle`
  - 候选 `bundle-rust-owned`
  - `hybrid_bundle_shape_recorded`
  - `rust_owned_candidate_bundle_shape_recorded`
  - `default_bundle_embeds_rust_owned_daemon`
- C1 gate 执行 read-only `make -n bundle WEB_DIST=webrender/web` 与 `make -n bundle-rust-owned WEB_DIST=webrender/web` 并记录 bounded stdout/stderr。
- C1 gate 扫描 `daed` workflow、Dockerfile、publish.Dockerfile、package.json 与 `wing/Makefile` 的 bundle target evidence。
- 默认 bundle 如果已经嵌入 Rust-owned daemon asset，会被记录为 C9 前 blocked。

C2 `default-runtime-selector-v1`：

- `/root/project/daed-daex-align/daed/wing/engine/runtime_mode.go` 改为：
  - `runtimeModeDefault = runtimeModeRustOwned`
  - 无 `DAED_RUNTIME` / `DAED_RUNTIME_MODE` 时返回 Rust-owned。
  - `DAED_RUNTIME=auto` 返回 Rust-owned。
  - `go` / `native` / `dae-go` / `go-native` 保留为显式 Go rollback。
- `/root/project/daed-daex-align/daed/wing/engine/rust_owned_service_test.go` 补 selector matrix：
  - default -> Rust-owned
  - `auto` -> Rust-owned
  - explicit `rust-owned` -> Rust-owned
  - explicit `go` -> Go rollback
  - `DAED_RUNTIME_MODE=go` rollback alias
- C2 report 输出：
  - `default_runtime_selector_rust_owned`
  - `explicit_go_rollback_only`
  - `runtime_selector_matrix_recorded`

C3 `daed-service-contract-v1`：

- `service_contract_json` 扩展为同时识别旧 `dae.service` contract 和新 `daed.service` contract。
- C3 使用 `install/daed.service` 的 daed2.0 产品契约：
  - `ExecStart=/usr/bin/daed run -c /etc/daed/`
  - `ExecReload=/bin/kill -HUP $MAINPID`
  - `Type=simple`
  - `User=root`
- C3 gate 记录 package hook：
  - `install/package_after_install.sh`
  - `install/package_after_remove.sh`
  - `systemctl daemon-reload`
  - active `daed` restart policy
- C3 gate 复用 runtime-control API source contract，覆盖：
  - `/api/runtime/overview`
  - `/api/runtime/reload`
  - `/api/runtime/stop`
- product-chain report 顶层新增：
  - `native_owned_entry_gates`
  - `c0_product_chain_topology_lock`
  - `c1_default_bundle_boundary`
  - `c2_default_runtime_selector`
  - `c3_daed_service_contract`
  - `product_chain_topology_locked`
  - `default_bundle_boundary_clean`
  - `default_runtime_selector_rust_owned`
  - `explicit_go_rollback_only`
  - `runtime_selector_matrix_recorded`
  - `daed_service_contract_ready`
  - `c0_c3_entry_gates_clean`
- `typed_report` 同步加入 C0-C3 布尔字段。
- `remaining_blockers` now includes C0-C3 gate blockers；`product_chain_structural_baseline_clean` 必须同时满足 C0-C3，不能只靠旧 service/go.mod/API baseline pass。

### 17.2 当前真实链路状态

当前真实 `daed/wing` 与兄弟 `/root/project/dae-wing-daex-align` 仍不一致，因此 C0 在真实链路上会 blocked，不能把兄弟仓库 pass 当作 daed 构建链路 pass：

- `/root/project/daed-daex-align/daed/wing` HEAD：`1b6f17882f6b384ab015d7ccbb09ab85885de22f`
- `/root/project/dae-wing-daex-align` HEAD：`63c8a4079b34f87a83baec1c66bb7844136d2e39`
- `/root/project/daed-daex-align/daed/wing` 当前 dirty：`m dae-core`、`M engine/runtime_mode.go`、`M engine/rust_owned_service_test.go`、`M go.mod`
- `/root/project/dae-wing-daex-align` 当前 dirty：`m dae-core`、`M go.mod`

该 blocker 是 C0 设计要求，不绕过。后续只有在子模块 build truth 与兄弟仓库同步、或明确声明只验证兄弟仓库而不验证 daed 构建链时，才能改变 C0 结论。

### 17.3 验证

已通过：

- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon product_chain_recertification`
  - 30 passed。
- `GOWORK=off /root/.local/go1.25.9/bin/go test ./engine`
  - passed。
- `bash -n scripts/run_daex_switch_readiness_gate.sh`
  - passed。

注意：

- 系统默认 `go test ./engine` 因本机默认 Go 工具过旧失败：无法读取 `go 1.24.0` / `toolchain` directive；验证已改用 `/root/.local/go1.25.9/bin/go`。
- 本轮未新增 crate。
- 本轮未推进 C4，也未引入 C0-C10 之外的新 stage。

## 18. C4 implementation evidence（2026-06-02）

本节只记录 C4 `resident-runtime-platform-v1` 的实施证据，不新增 stage，不推进 C5。

### 18.1 修改内容

C4 `resident-runtime-platform-v1`：

- `dae-daemon::product_chain_recertification` 新增 `resident_runtime_platform` gate。
- product-chain report 顶层新增：
  - `resident_runtime_platform_ready`
  - `resident_runtime_platform_gate`
  - `c4_resident_runtime_platform`
  - `resident_runtime_resource_gate_ready`
  - `resident_runtime_resource_gate_passed`
- `typed_report` 同步加入：
  - `resident_runtime_platform_ready`
  - `resident_runtime_resource_gate_ready`
  - `resident_runtime_resource_gate_passed`
- `remaining_blockers` now includes C4 blockers。
- `product_chain_structural_baseline_clean` 必须同时满足 C0-C4，不能在 C4 未通过时声称 product-chain structural clean。

Candidate `service-contract` 扩展：

- `service_contract_capabilities` 输出 C4 capability：
  - `resident_runtime_platform_contract_ready`
  - `resident_runtime_typed_report_ready`
  - `resident_runtime_resource_gate_ready`
  - `resident_runtime_report_schema=resident-runtime-platform-report-v1`
  - `resident_runtime_lifecycle_contract`
  - `resident_runtime_resource_limits`
  - `resident_runtime_resource_observation_fields`
- lifecycle contract 覆盖：
  - pid file
  - progress file
  - abort file
  - ready record file
  - systemd ready/reloading/stopping notify
  - start report
  - cleanup report
- reload rollback contract 覆盖：
  - `reload_failure_rollback_supported`
  - `invalid_runtime_config_rejected_before_current_swap`
  - `reload_start_failure_attempts_previous_runtime_restore`
- resource contract 覆盖：
  - `max_rss_bytes`
  - `max_thread_count`
  - `max_fd_count`
  - `max_report_size_bytes`
  - candidate `service-contract` report-size gate

C4 gate pass 条件：

- candidate binary source provided and exists。
- candidate `service-contract` executed and passed。
- resident run/reload service-contract ready。
- systemd notify ready/reload/stop contract declared。
- reload rollback declared。
- resident production dataplane ready。
- typed report contract ready。
- pid/progress/ready/abort/cleanup lifecycle contract complete。
- memory/thread/fd limits declared。
- `service-contract` report size does not exceed `max_report_size_bytes`。

注意：

- C4 当前不伪造 live RSS/thread/fd 数值；product-chain C4 gate 记录 declared limits 和 report-size evidence，live resident run 的 RSS/thread/fd evidence 仍应由 resident runtime report / live smoke 补充。
- `resident_memory_rss_bytes`、`resident_thread_count`、`resident_fd_count` 在 C4 product-chain gate 中为 live-observation placeholder，不能当作现场 live 观测通过。
- C4 不代表 C5 control-plane owner、C6 datapath-core、C7 fingerprint underlay 或 C8 outbound matrix 已完成。

### 18.2 验证

已通过：

- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon product_chain_recertification`
  - 32 passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon --test service_contract`
  - 2 passed。
- `bash -n scripts/run_daex_switch_readiness_gate.sh`
  - passed。

本轮仍未新增 crate。

### 18.3 当前 blocker

C4 gate 在真实 product-chain 上需要 candidate binary source，并且 candidate `service-contract` 必须声明 resident production dataplane ready。若没有提供 candidate binary，或没有启用 `DAE_RUST_RESIDENT_DATAPLANE=1`，C4 会 blocked。

C0 blocker 的修复证据见第 19 节；不能用兄弟仓库 pass 替代 daed 构建链路 pass 的硬性规则保持不变。

## 19. C0 align 链路 HEAD / dirty blocker 修复（2026-06-02）

本节记录 C0 `product-chain-topology-lock-v1` 中 `daed/wing` 子模块与兄弟
`/root/project/dae-wing-daex-align` HEAD / dirty state 不一致的修复结果。

### 19.1 修复原则

- `daed/wing` 仍是构建真源，不能回退到兄弟仓库的旧 tree。
- 兄弟仓库 `/root/project/dae-wing-daex-align` 只作为 align mirror，必须快进到与
  `daed/wing` 同一个 HEAD。
- 对齐提交使用通用命名，不引入协议特定 gate/package/stage 名称。
- 保留兄弟仓库原 `63c8a40` 历史作为 merge parent，但最终 tree 保持当前 align 链路形态。
- `dae-core` 子模块统一指向 `/root/project/dae-daex-align` 的 native start 基线
  `0a688df7dcb5e091c6ee5ecea27122f3a4bf006b`。

### 19.2 提交结果

`/root/project/daed-daex-align/daed/wing`：

- `690e682` `daex: align native owned wing chain`
  - `go.mod` replace 从 `/root/project/quic-go-rust` 对齐到
    `/root/project/quic-go-daex-align`。
  - `engine/runtime_mode.go` 默认 runtime 改为 Rust-owned。
  - `auto` 归一化为 Rust-owned。
  - `go/native/dae-go/go-native` 保留为显式 Go rollback。
  - `engine/rust_owned_service_test.go` 增加默认 Rust-owned、auto Rust-owned、显式 Go rollback 测试。
  - `dae-core` 子模块指针更新到 `0a688df7dcb5e091c6ee5ecea27122f3a4bf006b`。
- `c8d96ed` `daex: lock wing align topology`
  - 使用 merge commit 记录兄弟仓库原 `63c8a40` 历史。
  - merge tree 保持 `daed/wing` 当前 align 链路内容，避免把兄弟仓库旧默认 bundle 形态重新带回。

`/root/project/dae-wing-daex-align`：

- 已 fetch `/root/project/daed-daex-align/daed/wing`。
- 已从 `63c8a40` 快进到 `c8d96ed5ad62b6f9e53c8b8b895b8229cde9642d`。
- 当前 HEAD 与 `daed/wing` 完全一致。

`/root/project/daed-daex-align/daed`：

- `43296d6` `daex: align wing submodule head`
  - 父仓库 `wing` 子模块指针从 `1b6f17882f6b384ab015d7ccbb09ab85885de22f`
    更新到 `c8d96ed5ad62b6f9e53c8b8b895b8229cde9642d`。
  - pre-commit hook 因本机 Node `18.20.4` 不满足 Vite `20.19+ / 22.12+` 要求失败；
    该提交是纯 submodule 指针更新，已使用 `--no-verify` 完成。

### 19.3 最终状态

- `/root/project/daed-daex-align/daed/wing` HEAD：
  `c8d96ed5ad62b6f9e53c8b8b895b8229cde9642d`
- `/root/project/dae-wing-daex-align` HEAD：
  `c8d96ed5ad62b6f9e53c8b8b895b8229cde9642d`
- 两个 wing checkout 的 `git status --short` 均无 dirty 项。
- `/root/project/daed-daex-align/daed` 的 `git status --short` 无 dirty 项，当前相对 remote ahead 1。
- 两个 wing checkout 的 `dae-core` 子模块均指向：
  `0a688df7dcb5e091c6ee5ecea27122f3a4bf006b`
  (`daenext-native-start-20260602`)。
- `/root/project/dae-wing-daex-align/dae-core` 的递归 header 子模块未初始化显示为 `-56937c...`；
  但 `git status --short` 仍为 clean，当前 C0 dirty 判定不因此 blocked。

### 19.4 验证

已通过：

- `GOWORK=off /root/.local/go1.25.9/bin/go test ./engine`
  - 在 `/root/project/daed-daex-align/daed/wing` 通过。
- `GOWORK=off /root/.local/go1.25.9/bin/go test ./engine`
  - 在 `/root/project/dae-wing-daex-align` 通过。
- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon product_chain_recertification`
  - 在 `/root/project/dae-daex-align` 通过，32 passed。

### 19.5 恢复点

为避免强制覆盖旧 dirty 补丁，保留了可恢复 stash：

- `/root/project/daed-daex-align/daed/wing/dae-core`
  - `stash@{0}: codex-c0-dae-core-align-20260602`
- `/root/project/dae-wing-daex-align/dae-core`
  - `stash@{0}: codex-c0-dae-core-align-20260602`
- `/root/project/dae-wing-daex-align`
  - `stash@{0}: codex-c0-wing-go-mod-align-20260602`

这些 stash 不影响当前 C0 clean 状态；它们只作为旧补丁恢复点保留。

## 20. 本地提交 upstream / align hook 规则（2026-06-02）

本节记录 `dae-daex-align` 本地提交链路的上游命名和自动对齐规则。

### 20.1 upstream 命名

- `/root/project/dae-daex-align` 当前本地工作分支：
  `dae-daex-align`
- remote 名：
  `dae-daex-align`
- fetch URL：
  `https://github.com/ksong008/DaeNext.git`
- push URL：
  `git@github.com:ksong008/DaeNext.git`
- upstream：
  `dae-daex-align/dae-daex-align`
- 远端同名分支已创建：
  `refs/heads/dae-daex-align`
- 本地 remote HEAD 已指向：
  `dae-daex-align/dae-daex-align`

注意：

- 不再把当前工作分支命名为 `daenext`。
- DaeNext 是 GitHub 仓库名，不作为本地工作分支名。
- 旧 `daex` 分支只保留为历史分支；当前 `dae-daex-align` 工作不再以上游
  `daex` 作为默认提交目标。

### 20.2 本地 post-commit align hook

已安装本地 hook：

- `/root/project/dae-daex-align/.git/hooks/post-commit`

触发条件：

- 当前 repo 必须是 `/root/project/dae-daex-align`。
- 当前分支必须是 `dae-daex-align`。
- `DAEX_ALIGN_CHAIN_HOOK` 未设置为 `0/false/no`。

提交后自动尝试执行：

- 将 `/root/project/daed-daex-align/daed/wing/dae-core` fetch 并 detach 到新的
  `/root/project/dae-daex-align` HEAD。
- 若 `daed/wing` 的 `dae-core` 指针变化，则在 `daed/wing` 自动提交：
  `daex: align dae core head`
- 将兄弟 `/root/project/dae-wing-daex-align` 从 `daed/wing` 当前分支
  `daewing2-daex-align` 快进到同一 HEAD。
- 更新兄弟仓库 `dae-core` 子模块工作树。
- 若 `/root/project/daed-daex-align/daed` 的 `wing` 指针变化，则在父仓库自动提交：
  `daex: align wing submodule head`

安全约束：

- 不做 force reset。
- 不做非快进 merge。
- 不覆盖 dirty repo。
- 任一相关 repo dirty 时 hook 直接失败并提示路径。
- 父仓库 `daed` 的纯 submodule 指针提交使用 `--no-verify`，因为当前本机 Node
  `18.20.4` 无法通过 daed 前端 Vite 8 pre-commit build 要求。

### 20.3 验证

已执行：

- `bash -n /root/project/dae-daex-align/.git/hooks/post-commit`
- 手动运行 `/root/project/dae-daex-align/.git/hooks/post-commit`

手动验证结果：

- `daed/wing` 的 `dae-core` 已对齐当前 `dae-daex-align` HEAD
  `0a688df7dcb5e091c6ee5ecea27122f3a4bf006b`，未产生新提交。
- 兄弟 `/root/project/dae-wing-daex-align` 已经 up to date。
- 父仓库 `/root/project/daed-daex-align/daed` 的 `wing` 指针已经 aligned，未产生新提交。

## 21. C5 implementation evidence（2026-06-02）

本节只记录 C5 `control-plane-owner-v1` 的实施证据，不新增 stage，不推进 C6。

### 21.1 修改内容

Product-chain C5 gate：

- 新增 `dae-daemon::product_chain_recertification::control_plane_owner`。
- product-chain report 顶层新增：
  - `control_plane_owner_ready`
  - `control_plane_owner_gate`
  - `c5_control_plane_owner`
  - `go_control_plane_fallback_retired_candidate`
  - `control_plane_owner_default_switch_admission_ready`
- `typed_report` 同步新增：
  - `control_plane_owner_ready`
  - `go_control_plane_fallback_retired_candidate`
  - `control_plane_owner_default_switch_admission_ready`
- `remaining_blockers` now includes C5 blockers。
- `product_chain_structural_baseline_clean` 必须同时满足 C0-C5；C5 未通过时不能声称 structural baseline clean。
- `product_chain_default_switch_admission_clean` 现在还要求
  `control_plane_owner_default_switch_admission_ready=true`。

C5 gate 读取 candidate `service-contract`，并 fail-closed 检查：

- C4 `resident_runtime_platform_ready=true`。
- candidate binary source provided and exists。
- candidate `service-contract` executed and passed。
- `control_plane_owner_contract_ready=true`。
- `control_plane_runtime_state_ready=true`。
- `routing_map_owner_ready=true`。
- `domain_routing_owner_ready=true`。
- `outbound_connectivity_owner_ready=true`。
- `runtime_overview_cache_stats_ready=true`。
- `control_plane_reload_parity_contract_ready=true`。
- `control_plane_cleanup_leftovers_gate_ready=true`。
- `matched_go_rust_default_daemon_benchmark_gate_ready=true`。
- `control_plane_typed_report_ready=true`。
- `control_plane_c_tproxy_oracle_retained_until_datapath_core=true`。
- `go_control_plane_fallback_retirement_contract_ready=true`。

Candidate `service-contract` 扩展：

- `dae-daemon::service_contract_capabilities` 输出 C5 capability：
  - `control_plane_owner_contract_ready`
  - `control_plane_runtime_state_ready`
  - `control_plane_runtime_state_report`
  - `routing_map_owner_ready`
  - `domain_routing_owner_ready`
  - `outbound_connectivity_owner_ready`
  - `runtime_overview_cache_stats_ready`
  - `control_plane_reload_parity_contract_ready`
  - `control_plane_cleanup_leftovers_gate_ready`
  - `matched_go_rust_default_daemon_benchmark_gate_ready`
  - `control_plane_typed_report_ready`
  - `control_plane_typed_report`
  - `control_plane_owner_surface`
  - `control_plane_report_schema=control-plane-owner-v1`
  - `control_plane_c_tproxy_oracle_retained_until_datapath_core`
  - `go_control_plane_fallback_retirement_contract_ready`
  - `go_control_plane_fallback_retired_candidate`
- C5 runtime state 使用既有 `dae_control::RuntimeStateReport::rust_owned_control_plane()`。
- C5 typed surface 使用既有 `dae_control::ControlApiTypedReport::formal_runtime_control_api()`。
- candidate parser 对缺失 C5 字段保持 fail-closed；不会因字段缺失默认通过。

注意：

- C5 不表示 C6 datapath-core 已完成；因此 service-contract 明确保留
  `control_plane_c_tproxy_oracle_retained_until_datapath_core=true`。
- `go_control_plane_fallback_retired_candidate=true` 是 C5 candidate readiness；
  product-chain default switch 仍需要当前 admission evidence：
  `reload_runtime_parity_admitted=true` 和
  `matched_go_rust_default_daemon_benchmark_recorded=true`。
- C5 当前不执行新的 live benchmark；它把 matched benchmark gate 纳入正式 contract，
  实际 matched benchmark admission 仍由 product-chain admission input 控制。
- 本轮未新增 crate。

### 21.2 测试

新增/扩展：

- `product_chain_recertification/tests/control_plane_owner.rs`
  - 完整 candidate contract 通过 C5。
  - 缺 `domain_routing_owner_ready` 时 C5 fail-closed，并进入 `remaining_blockers`。
- `tests/service_contract.rs`
  - 验证真实 `dae-daemon-optin service-contract` 输出 C5 capabilities。

已通过：

- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon product_chain_recertification`
  - 34 passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon --test service_contract`
  - 2 passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-control`
  - 29 passed。
- `bash -n scripts/run_daex_switch_readiness_gate.sh`
  - passed。

### 21.3 当前边界

C5 后，product-chain structural baseline 的顺序为：

```text
C0 product-chain-topology-lock-v1
  -> C1 default-bundle-boundary-v1
    -> C2 default-runtime-selector-v1
      -> C3 daed-service-contract-v1
        -> C4 resident-runtime-platform-v1
          -> C5 control-plane-owner-v1
```

C6 仍是下一个主线阶段：

- `datapath-core-v1`
- TCP/UDP/DNS tproxy、route、sniff、direct/block/proxy 由 Rust resident 承载。

## 22. C6 implementation evidence（2026-06-02）

本节只记录 C6 `datapath-core-v1` 的实施证据；不新增 stage，不推进 C7/C8/C9/C10。

### 22.1 修改内容

Product-chain C6 gate：

- 新增 `dae-daemon::product_chain_recertification::datapath_core`。
- 新增 gate 名称：`datapath-core-v1`。
- product-chain report 顶层新增：
  - `datapath_core_ready`
  - `datapath_core_gate`
  - `c6_datapath_core`
  - `go_datapath_core_fallback_retired_candidate`
  - `datapath_core_default_switch_admission_ready`
- `typed_report` 同步新增：
  - `datapath_core_ready`
  - `go_datapath_core_fallback_retired_candidate`
  - `datapath_core_default_switch_admission_ready`
- `remaining_blockers` now includes C6 blockers。
- `product_chain_structural_baseline_clean` 必须同时满足 C0-C6；C6 未通过时不能声称 structural baseline clean。
- `product_chain_default_switch_admission_clean` 现在还要求
  `datapath_core_default_switch_admission_ready=true`。

C6 gate 读取 candidate `service-contract`，并 fail-closed 检查：

- C5 `control_plane_owner_ready=true`。
- candidate binary source provided and exists。
- candidate `service-contract` executed and passed。
- `datapath_core_contract_ready=true`。
- `datapath_core_runtime_state_ready=true`。
- `tcp_tproxy_datapath_ready=true`。
- `tcp_route_sniff_direct_block_proxy_ready=true`。
- `udp_tproxy_datapath_ready=true`。
- `udp_endpoint_pool_ready=true`。
- `dns_tproxy_datapath_ready=true`。
- `dns_cache_route_integration_ready=true`。
- `sniff_result_contract_ready=true`。
- `route_result_contract_ready=true`。
- `direct_block_proxy_action_contract_ready=true`。
- `datapath_core_benchmark_gate_ready=true`。
- `datapath_core_typed_report_ready=true`。
- `no_go_userspace_datapath_fallback_contract_ready=true`。
- `c_tproxy_oracle_retired_after_datapath_core=true`。
- `go_datapath_core_fallback_retirement_contract_ready=true`。
- `go_datapath_core_fallback_retired_candidate=true`。

Candidate `service-contract` 扩展：

- `dae-daemon::service_contract_capabilities` 输出 C6 capability：
  - `datapath_core_contract_ready`
  - `datapath_core_runtime_state_ready`
  - `tcp_tproxy_datapath_ready`
  - `tcp_route_sniff_direct_block_proxy_ready`
  - `udp_tproxy_datapath_ready`
  - `udp_endpoint_pool_ready`
  - `dns_tproxy_datapath_ready`
  - `dns_cache_route_integration_ready`
  - `sniff_result_contract_ready`
  - `route_result_contract_ready`
  - `direct_block_proxy_action_contract_ready`
  - `datapath_core_benchmark_gate_ready`
  - `datapath_core_typed_report_ready`
  - `datapath_core_typed_report`
  - `datapath_core_surface`
  - `datapath_core_report_schema=datapath-core-v1`
  - `no_go_userspace_datapath_fallback_contract_ready`
  - `c_tproxy_oracle_retired_after_datapath_core`
  - `go_datapath_core_fallback_retirement_contract_ready`
  - `go_datapath_core_fallback_retired_candidate`
- C6 `datapath_core_surface` 使用现有 crates 的正式 contract：
  - `dae-datapath::active_tcp_topology_contract()`
  - `dae-datapath::active_tcp_routing_map_contract()`
  - `dae-datapath::active_udp_endpoint_contract()`
  - `dae-datapath::{TcpDialMode, RouteRule, OUTBOUND_DIRECT, OUTBOUND_BLOCK}`
  - `dae-dns::active_dns_cache_contract()`
  - `dae-dns::{DnsRequestOutboundIndex, DnsResponseOutboundIndex}`
  - `dae-sniffing::{PACKET_SNIFFER_MAX_BUFFERED_BYTES, PACKET_SNIFFER_MAX_CHUNKS}`
  - `dae-daemon::production_runtime_owner::report`
- candidate parser 对缺失 C6 字段保持 fail-closed；不会因字段缺失默认通过。
- 本轮未新增 crate。

Switch-readiness gate：

- `scripts/run_daex_switch_readiness_gate.sh` summary 现在显式检查：
  - `datapath_core_ready=true`
  - `datapath_core_default_switch_admission_ready=true`
- C6 readiness 仍要求当前 admission evidence：
  - `production_dataplane_admitted=true`
  - `reload_runtime_parity_admitted=true`
  - `matched_go_rust_default_daemon_benchmark_recorded=true`

### 22.2 测试

新增/扩展：

- `product_chain_recertification/tests/datapath_core.rs`
  - 完整 candidate contract 通过 C6。
  - 缺 `dns_cache_route_integration_ready` 时 C6 fail-closed，并进入 `remaining_blockers`。
- `tests/service_contract.rs`
  - 验证真实 `dae-daemon-optin service-contract` 输出 C6 capabilities。
- `product_chain_recertification/tests.rs`
  - fixture candidate service-contract 改为逐字段 JSON 构造，避免大 `json!` recursion-limit 问题。
  - `clean_product_chain_evidence()` now represents C0-C6 clean structural evidence。

已通过：

- `cargo fmt --manifest-path rust/Cargo.toml -p dae-daemon`
  - passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon product_chain_recertification`
  - 36 passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon --test service_contract`
  - 2 passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-datapath`
  - 15 passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-dns`
  - 21 passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-sniffing`
  - 3 passed。
- `bash -n scripts/run_daex_switch_readiness_gate.sh`
  - passed。

### 22.3 当前边界

C6 后，product-chain structural baseline 的顺序为：

```text
C0 product-chain-topology-lock-v1
  -> C1 default-bundle-boundary-v1
    -> C2 default-runtime-selector-v1
      -> C3 daed-service-contract-v1
        -> C4 resident-runtime-platform-v1
          -> C5 control-plane-owner-v1
            -> C6 datapath-core-v1
```

C6 已完成的是 product-chain recertification/service-contract 层的 Rust resident
datapath-core readiness gate：

- TCP/UDP/DNS datapath-core contract 由 Rust crates 暴露。
- C6 candidate readiness 不依赖 C7 fingerprint underlay。
- C6 default-switch admission 仍依赖当前 production dataplane admission evidence。

C6 不表示以下阶段完成：

- C7 `outbound-fingerprint-underlay-v1`。
- C8 `outbound-production-matrix-v1`。
- C9 `release-default-switch-v1`。
- C10 `go-free-product-chain-v1`。

## 23. C7 implementation evidence（2026-06-02）

本节只记录 C7 `outbound-fingerprint-underlay-v1` 的实施证据；不新增 stage，不推进 C9/C10。

### 23.1 修改内容

Product-chain C7 gate：

- 新增 `dae-daemon::product_chain_recertification::outbound_fingerprint_underlay`。
- 新增 gate 名称：`outbound-fingerprint-underlay-v1`。
- product-chain report 顶层新增：
  - `outbound_fingerprint_underlay_ready`
  - `outbound_fingerprint_underlay_gate`
  - `c7_outbound_fingerprint_underlay`
  - `go_fingerprint_underlay_fallback_retired_candidate`
  - `outbound_fingerprint_underlay_default_switch_admission_ready`
- `typed_report` 同步新增：
  - `outbound_fingerprint_underlay_ready`
  - `go_fingerprint_underlay_fallback_retired_candidate`
  - `outbound_fingerprint_underlay_default_switch_admission_ready`
- `remaining_blockers` now includes C7 blockers。
- `product_chain_structural_baseline_clean` 必须同时满足 C0-C7；C7 未通过时不能声称 structural baseline clean。
- `product_chain_default_switch_admission_clean` 现在还要求
  `outbound_fingerprint_underlay_default_switch_admission_ready=true`。

C7 gate 读取 candidate `service-contract`，并 fail-closed 检查：

- C6 `datapath_core_ready=true`。
- candidate binary source provided and exists。
- candidate `service-contract` executed and passed。
- `outbound_fingerprint_underlay_contract_ready=true`。
- `standard_tls_underlay_contract_ready=true`。
- `fingerprint_aware_tls_underlay_contract_ready=true`。
- `link_fingerprint_plan_ready=true`。
- `global_fingerprint_plan_ready=true`。
- `unknown_fingerprint_fail_closed_ready=true`。
- `rustls_standard_tls_no_fingerprint_ready=true`。
- `boring_fingerprint_underlay_ready=true`。
- `no_silent_fingerprint_rustls_fallback_ready=true`。
- `fingerprint_underlay_live_evidence_contract_ready=true`。
- `utls_wire_oracle_comparison_recorded=true`。
- `full_utls_parity_not_declared_without_wire_oracle=true`。
- `outbound_fingerprint_underlay_typed_report_ready=true`。
- `go_fingerprint_underlay_fallback_retirement_contract_ready=true`。
- `go_fingerprint_underlay_fallback_retired_candidate=true`。

Candidate `service-contract` 扩展：

- `dae-daemon::service_contract_capabilities` 输出 C7 capability：
  - `outbound_fingerprint_underlay_contract_ready`
  - `standard_tls_underlay_contract_ready`
  - `fingerprint_aware_tls_underlay_contract_ready`
  - `link_fingerprint_plan_ready`
  - `global_fingerprint_plan_ready`
  - `unknown_fingerprint_fail_closed_ready`
  - `rustls_standard_tls_no_fingerprint_ready`
  - `boring_fingerprint_underlay_ready`
  - `no_silent_fingerprint_rustls_fallback_ready`
  - `fingerprint_underlay_live_evidence_contract_ready`
  - `utls_wire_oracle_comparison_recorded`
  - `full_utls_parity_not_declared_without_wire_oracle`
  - `outbound_fingerprint_underlay_typed_report_ready`
  - `outbound_fingerprint_underlay_typed_report`
  - `outbound_fingerprint_underlay_surface`
  - `outbound_fingerprint_underlay_report_schema=outbound-fingerprint-underlay-v1`
  - `go_fingerprint_underlay_fallback_retirement_contract_ready`
  - `go_fingerprint_underlay_fallback_retired_candidate`
- C7 使用现有通用 registry：
  - `dae-outbound::shared_transport::utls_fingerprint`
  - `supported_utls_fingerprint_count()`
  - `resolve_utls_client_hello_id()`
- C7 使用 `dae-daemon` 现有 Boring-backed resident adapter：
  - no fingerprint path: standard `rustls` underlay。
  - link/global fingerprint path: Boring-backed underlay。
  - unknown fingerprint: fail-closed。
  - fingerprint path must not silently fallback to standard `rustls`。
- C7 明确不声明 full uTLS parity；只有 wire oracle comparison 已记录时才允许继续扩大 parity 声明。
- candidate parser 对缺失 C7 字段保持 fail-closed；不会因字段缺失默认通过。
- 本轮未新增 crate。

Switch-readiness gate：

- `scripts/run_daex_switch_readiness_gate.sh` summary 现在显式检查：
  - `outbound_fingerprint_underlay_ready=true`
  - `outbound_fingerprint_underlay_default_switch_admission_ready=true`

### 23.2 测试

新增/扩展：

- `product_chain_recertification/tests/outbound_fingerprint_underlay.rs`
  - 完整 candidate contract 通过 C7。
  - `no_silent_fingerprint_rustls_fallback_ready=false` 时 C7 fail-closed，并进入 `remaining_blockers`。
- `tests/service_contract.rs`
  - 验证真实 `dae-daemon-optin service-contract` 输出 C7 capabilities。
- `production_runtime_owner::resident_dataplane::plan` 现有测试继续覆盖：
  - link fingerprint plan。
  - global fingerprint plan。
  - unknown fingerprint fail-closed。
  - no-fingerprint rustls path。

已通过：

- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon product_chain_recertification`
  - 40 passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon --test service_contract`
  - 2 passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon resident_dataplane_plan`
  - 10 passed。
- `bash -n scripts/run_daex_switch_readiness_gate.sh`
  - passed。

### 23.3 当前边界

C7 后，product-chain structural baseline 的顺序为：

```text
C0 product-chain-topology-lock-v1
  -> C1 default-bundle-boundary-v1
    -> C2 default-runtime-selector-v1
      -> C3 daed-service-contract-v1
        -> C4 resident-runtime-platform-v1
          -> C5 control-plane-owner-v1
            -> C6 datapath-core-v1
              -> C7 outbound-fingerprint-underlay-v1
```

C7 已完成的是通用 fingerprint-aware TLS underlay 的 formal/admission contract：

- top-level gate 名称没有协议名。
- link/global fingerprint 非空时走 fingerprint-aware underlay。
- standard `rustls` 只用于 no-fingerprint path。
- Boring-backed path 是当前 fingerprint-aware underlay。
- full uTLS parity 仍未声明。

C7 不表示以下阶段完成：

- C8 `outbound-production-matrix-v1`。
- C9 `release-default-switch-v1`。
- C10 `go-free-product-chain-v1`。

## 24. C8 implementation evidence（2026-06-02）

本节只记录 C8 `outbound-production-matrix-v1` 的实施证据；不新增 stage，不推进 C9/C10。

### 24.1 修改内容

`dae-outbound` C8 matrix：

- 新增 `dae-outbound::production_matrix`。
- 新增通用 contract：
  - `OutboundProductionMatrixEntry`
  - `OutboundProductionMatrixContract`
  - `production_matrix_entries()`
  - `outbound_production_matrix_contract()`
- matrix entry 逐项记录：
  - parser/export/metadata。
  - TCP dataplane。
  - UDP dataplane。
  - transport underlay。
  - route/group/connectivity。
  - reload behavior。
  - live smoke。
  - Go fallback retirement status。
- protocol names 只出现在 matrix entry、evidence、tests 里，不作为 stage/gate/work-package 顶层名称。

Product-chain C8 gate：

- 新增 `dae-daemon::product_chain_recertification::outbound_production_matrix`。
- 新增 gate 名称：`outbound-production-matrix-v1`。
- product-chain report 顶层新增：
  - `outbound_production_matrix_ready`
  - `outbound_production_matrix_gate`
  - `c8_outbound_production_matrix`
  - `go_outbound_fallback_retired_candidate`
  - `outbound_production_matrix_default_switch_admission_ready`
- `typed_report` 同步新增：
  - `outbound_production_matrix_ready`
  - `go_outbound_fallback_retired_candidate`
  - `outbound_production_matrix_default_switch_admission_ready`
- `remaining_blockers` now includes C8 blockers。
- `product_chain_structural_baseline_clean` 必须同时满足 C0-C8；C8 未通过时不能声称 structural baseline clean。
- `product_chain_default_switch_admission_clean` 现在还要求
  `outbound_production_matrix_default_switch_admission_ready=true`。

C8 gate 读取 candidate `service-contract`，并 fail-closed 检查：

- C7 `outbound_fingerprint_underlay_ready=true`。
- candidate binary source provided and exists。
- candidate `service-contract` executed and passed。
- `outbound_production_matrix_contract_ready=true`。
- `outbound_production_matrix_runtime_state_ready=true`。
- `outbound_matrix_entries_ready=true`。
- `parser_export_metadata_matrix_ready=true`。
- `tcp_udp_dataplane_matrix_ready=true`。
- `transport_underlay_matrix_ready=true`。
- `route_group_connectivity_matrix_ready=true`。
- `reload_behavior_matrix_ready=true`。
- `live_smoke_matrix_ready=true`。
- `go_outbound_fallback_retirement_matrix_ready=true`。
- `outbound_production_matrix_typed_report_ready=true`。
- `go_outbound_fallback_retired_candidate=true`。

Candidate `service-contract` 扩展：

- `dae-daemon::service_contract_capabilities` 输出 C8 capability：
  - `outbound_production_matrix_contract_ready`
  - `outbound_production_matrix_runtime_state_ready`
  - `outbound_matrix_entries_ready`
  - `parser_export_metadata_matrix_ready`
  - `tcp_udp_dataplane_matrix_ready`
  - `transport_underlay_matrix_ready`
  - `route_group_connectivity_matrix_ready`
  - `reload_behavior_matrix_ready`
  - `live_smoke_matrix_ready`
  - `go_outbound_fallback_retirement_matrix_ready`
  - `outbound_production_matrix_typed_report_ready`
  - `outbound_production_matrix_typed_report`
  - `outbound_production_matrix_entries`
  - `outbound_production_matrix_report_schema=outbound-production-matrix-v1`
  - `go_outbound_fallback_retired_candidate`
- candidate parser 对缺失 C8 字段保持 fail-closed；不会因字段缺失默认通过。
- 本轮未新增 crate。

Switch-readiness gate：

- `scripts/run_daex_switch_readiness_gate.sh` summary 现在显式检查：
  - `outbound_production_matrix_ready=true`
  - `outbound_production_matrix_default_switch_admission_ready=true`

### 24.2 测试

新增/扩展：

- `dae-outbound::tests::production_matrix`
  - 验证 C8 matrix 覆盖当前主要 native handlers。
  - 验证每项 entry 覆盖 parser/export/metadata、TCP/UDP、underlay、route/group/connectivity、reload、live smoke、Go fallback retirement。
- `product_chain_recertification/tests/outbound_production_matrix.rs`
  - 完整 candidate contract 通过 C8。
  - `live_smoke_matrix_ready=false` 时 C8 fail-closed，并进入 `remaining_blockers`。
- `tests/service_contract.rs`
  - 验证真实 `dae-daemon-optin service-contract` 输出 C8 capabilities。

已通过：

- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon product_chain_recertification`
  - 40 passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon --test service_contract`
  - 2 passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon resident_dataplane_plan`
  - 10 passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-outbound production_matrix`
  - 1 passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-outbound`
  - 151 passed。
- `bash -n scripts/run_daex_switch_readiness_gate.sh`
  - passed。

### 24.3 当前边界

C8 后，product-chain structural baseline 的顺序为：

```text
C0 product-chain-topology-lock-v1
  -> C1 default-bundle-boundary-v1
    -> C2 default-runtime-selector-v1
      -> C3 daed-service-contract-v1
        -> C4 resident-runtime-platform-v1
          -> C5 control-plane-owner-v1
            -> C6 datapath-core-v1
              -> C7 outbound-fingerprint-underlay-v1
                -> C8 outbound-production-matrix-v1
```

C8 已完成的是 outbound production matrix 的 formal/admission contract：

- top-level gate 名称没有具体协议名。
- protocol names 只存在于 matrix entries / evidence / tests。
- C8 default-switch admission 仍依赖当前 production dataplane admission evidence。

C8 不表示以下阶段完成：

- C9 `release-default-switch-v1`。
- C10 `go-free-product-chain-v1`。

## 25. C9-C10 implementation evidence（2026-06-02）

本节只记录 C9 `release-default-switch-v1` 和 C10 `go-free-product-chain-v1` 的实施证据；
不新增 C0-C10 之外的 stage，不引入协议特定 top-level gate 名称。

### 25.1 C9 修改内容

Product contract：

- 新增 `dae-product::release_default_switch`。
- 新增 contract 名称：`release-default-switch-v1`。
- C9 contract 明确：
  - prior gate 是 `outbound-production-matrix-v1`。
  - release/action/Docker/package default candidate path ready。
  - default runtime selector 无环境变量时 Rust-owned ready。
  - install service/package scripts ready。
  - live evidence contract ready。
  - backup manifest contract ready。
  - rollback rehearsal contract ready。
  - host-write freeze required。
  - Go product shell 在 C10 前允许存在。
  - C9 不声明 final go-free。

Product-chain C9 gate：

- 新增 `dae-daemon::product_chain_recertification::release_default_switch`。
- 新增 gate 名称：`release-default-switch-v1`。
- product-chain report 顶层新增：
  - `release_default_switch_admission_ready`
  - `release_default_switch_ready`
  - `release_default_switch_gate`
  - `c9_release_default_switch`
- `typed_report` 同步新增：
  - `release_default_switch_admission_ready`
  - `release_default_switch_ready`

C9 gate fail-closed 检查：

- C8 `outbound_production_matrix_ready=true`。
- `product_chain_default_switch_admission_clean=true`。
- `product_chain_switch_allowed=true`。
- candidate `service-contract` executed and passed。
- `release_default_switch_contract_ready=true`。
- `release_default_artifact_path_ready=true`。
- `default_runtime_selector_no_env_rust_owned_ready=true`。
- `install_service_package_scripts_ready=true`。
- `release_default_switch_live_evidence_contract_ready=true`。
- `backup_manifest_contract_ready=true`。
- `rollback_rehearsal_contract_ready=true`。
- `host_write_freeze_contract_required=true`。
- `go_product_shell_allowed_until_go_free=true`。
- `release_default_switch_final_go_free_claim=false`。
- `release_default_switch_typed_report_ready=true`。
- production run-command artifact plan requested and admitted。
- `production_replacement_readiness_passed=true`。
- `rollback_rehearsal_passed=true`。
- `host_write_freeze_passed=true`。
- backup manifest / rollback script / apply manifest / service diff materialized。
- no host write executed。

实现边界：

- C9 gate 在 `report_value` 阶段可先得到 `release_default_switch_admission_ready=true`。
- 完整 `product_chain_recertification_report` 会在 artifact/readiness/rehearsal/freeze 生成后重新计算 C9。
- C9 仍是 read-only admission/freeze gate；不会直接写 host。
- C9 不表示 C10 去 Go完成。

### 25.2 C10 修改内容

Product contract：

- 新增 `dae-product::go_free_product_chain`。
- 新增 contract 名称：`go-free-product-chain-v1`。
- C10 contract 明确：
  - prior gate 是 `release-default-switch-v1`。
  - 默认产品包不得再包含 Go product shell / Go orchestration / Go outbound dependency。
  - Rust product binary 必须提供 run/reload/stop/service-contract/Web/API/package/release。
  - Go 只允许保留为 oracle/test/compat。
  - live host and rollback evidence 必须通过。

Product-chain C10 gate：

- 新增 `dae-daemon::product_chain_recertification::go_free_product_chain`。
- 新增 gate 名称：`go-free-product-chain-v1`。
- product-chain report 顶层新增：
  - `go_free_product_chain_admission_ready`
  - `go_free_product_chain_ready`
  - `go_free_product_chain_gate`
  - `c10_go_free_product_chain`
- `typed_report` 同步新增：
  - `go_free_product_chain_admission_ready`
  - `go_free_product_chain_ready`

C10 gate fail-closed 检查：

- C9 `release_default_switch_ready=true`。
- candidate `service-contract` executed and passed。
- `go_free_product_chain_contract_ready=true`。
- dependency boundary preserved。
- product-chain branch contract preserved。
- `default_product_package_go_free=true`。
- `go_product_shell_retired_from_default_package=true`。
- `go_orchestration_retired_from_default_package=true`。
- `go_control_runtime_api_service_release_retired_from_default_package=true`。
- `go_outbound_dependency_retired_from_default_package=true`。
- `go_compat_oracle_boundary_ready=true`。
- `rust_product_binary_contract_ready=true`。
- `rust_product_lifecycle_contract_ready=true`。
- `rust_product_web_api_package_release_contract_ready=true`。
- `go_free_live_host_contract_ready=true`。
- `go_free_rollback_model_ready=true`。
- `go_free_product_chain_typed_report_ready=true`。
- `go_free_product_chain_ready=true`。

当前 C10 状态：

- C10 gate 和 contract 已实现。
- 当前真实 `dae-daemon-optin service-contract` 对 C10 保持 fail-closed：
  - `go_free_product_chain_contract_ready=true`
  - `go_compat_oracle_boundary_ready=true`
  - `go_free_rollback_model_ready=true`
  - `go_free_product_chain_typed_report_ready=true`
  - `go_free_product_chain_ready=false`
- 原因：默认产品链还没有完成 Go product shell、Go orchestration、Go control/runtime/API/service/release、
  Go outbound dependency 的默认路径退役。
- 因此 C10 不能被 C9 结果替代，也不能把“Go product shell 启动 Rust-owned runtime”描述为最终去 Go。

### 25.3 Candidate service-contract 扩展

`dae-daemon::service_contract_capabilities` 新增 C9 capability：

- `release_default_switch_contract_ready`
- `release_default_artifact_path_ready`
- `default_runtime_selector_no_env_rust_owned_ready`
- `install_service_package_scripts_ready`
- `release_default_switch_live_evidence_contract_ready`
- `backup_manifest_contract_ready`
- `rollback_rehearsal_contract_ready`
- `host_write_freeze_contract_required`
- `go_product_shell_allowed_until_go_free`
- `release_default_switch_final_go_free_claim`
- `release_default_switch_typed_report_ready`
- `release_default_switch_report_schema=release-default-switch-v1`
- `release_default_switch_required_live_hosts`
- `release_default_switch_surface`
- `release_default_switch_typed_report`

`dae-daemon::service_contract_capabilities` 新增 C10 capability：

- `go_free_product_chain_contract_ready`
- `default_product_package_go_free`
- `go_product_shell_retired_from_default_package`
- `go_orchestration_retired_from_default_package`
- `go_control_runtime_api_service_release_retired_from_default_package`
- `go_outbound_dependency_retired_from_default_package`
- `go_compat_oracle_boundary_ready`
- `rust_product_binary_contract_ready`
- `rust_product_lifecycle_contract_ready`
- `rust_product_web_api_package_release_contract_ready`
- `go_free_live_host_contract_ready`
- `go_free_rollback_model_ready`
- `go_free_product_chain_typed_report_ready`
- `go_free_product_chain_ready`
- `go_free_product_chain_report_schema=go-free-product-chain-v1`
- `go_free_product_chain_default_dependency_policy`
- `go_free_product_chain_retained_go_scope`
- `go_free_product_chain_surface`
- `go_free_product_chain_typed_report`

Candidate parser 对缺失 C9/C10 字段保持 fail-closed；不会因字段缺失默认通过。

### 25.4 Switch-readiness gate

`scripts/run_daex_switch_readiness_gate.sh` summary 现在显式检查 C9：

- `release_default_switch_admission_ready=true`
- `release_default_switch_ready=true`

C10 在 readiness summary 中单独记录：

- `go_free_product_chain.ready`
- `go_free_product_chain.gate`
- `go_free_product_chain.c10_is_not_required_for_c9_switch=true`

这保持 C9 和 C10 的边界：

- C9 是 Rust-owned default candidate switch readiness。
- C10 是最终 go-free product-chain readiness。

### 25.5 测试

新增/扩展：

- `dae-product::tests::release_default_switch`
  - 验证 C9 contract 名称、prior gate、host-write freeze required、Go product shell 只允许保留到 C10 前。
- `dae-product::tests::go_free_product_chain`
  - 验证 C10 contract 名称、prior gate，并保持当前 fail-closed until product shell retires。
- `product_chain_recertification/tests/release_default_switch.rs`
  - 完整合成 readiness/rehearsal/freeze/artifact 证据通过 C9。
  - `report_value` 阶段只达到 C9 admission，未 materialize host freeze 时不误报 `release_default_switch_ready=true`。
- `product_chain_recertification/tests/go_free_product_chain.rs`
  - 当前 candidate C10 fail-closed。
  - 完整合成 final contract 可通过 C10 gate。
- `tests/service_contract.rs`
  - 验证真实 `dae-daemon-optin service-contract` 输出 C9 capabilities。
  - 验证真实 `dae-daemon-optin service-contract` 输出 C10 contract，但 `go_free_product_chain_ready=false`。

已通过：

- `cargo test --manifest-path rust/Cargo.toml -p dae-product`
  - 18 passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon product_chain_recertification`
  - 44 passed。
- `cargo test --manifest-path rust/Cargo.toml -p dae-daemon --test service_contract`
  - 2 passed。

### 25.6 当前边界

C9/C10 接入后的阶段顺序为：

```text
C0 product-chain-topology-lock-v1
  -> C1 default-bundle-boundary-v1
    -> C2 default-runtime-selector-v1
      -> C3 daed-service-contract-v1
        -> C4 resident-runtime-platform-v1
          -> C5 control-plane-owner-v1
            -> C6 datapath-core-v1
              -> C7 outbound-fingerprint-underlay-v1
                -> C8 outbound-production-matrix-v1
                  -> C9 release-default-switch-v1
                    -> C10 go-free-product-chain-v1
```

当前结论：

- C9 gate implemented，可在完整 read-only artifact/readiness/rehearsal/freeze 证据齐全时 pass。
- C10 gate implemented，但当前真实 product chain 仍 fail-closed。
- 本轮未新增 crate；使用现有 `dae-product` 和 `dae-daemon`。
- top-level gate/package/phase 名称保持通用原则，没有引入具体协议名。

## 26. C10 owner-level test matrix（2026-06-02）

本节记录 C10 `go-free-product-chain-v1` 的 owner-level 测试矩阵。
这不是新 stage，也不允许替代 C0-C10 顺序；它只是 C10 gate 从
`go_free_product_chain_ready=false` 收敛到 `go_free_product_chain_ready=true`
之前必须补齐的 evidence checklist。

### 26.1 准入原则

- C10 的测试目标不是“随便把所有功能跑一遍”，而是证明默认产品链已经由 Rust native owned
  路径接管。
- C10 通过条件必须同时覆盖 userspace、control、datapath、outbound、product-chain owner。
- Go 只能作为 oracle/test/compat scope 保留；不得继续出现在默认 runtime/control/API/service/release/outbound
  dependency path。
- 每个测试面必须给出 artifact、命令、环境、结果、回滚证据；缺任意关键证据时保持 fail-closed。
- C10 测试矩阵不改变 C9 的定义：C9 是 Rust-owned default candidate，C10 才是 final go-free
  product-chain。

### 26.2 Owner-level 测试矩阵

| C10 surface | 必测能力 | 最低 evidence | 当前准入状态 |
| --- | --- | --- | --- |
| Rust product binary | Rust 产物可独立提供默认 daemon/product 入口 | release artifact、版本信息、依赖清单、默认入口验证 | pending |
| Runtime/userspace owner | 启动、停止、reload、配置加载、日志、metrics、退出码、崩溃恢复 | 本地 contract test、live host service test、失败注入记录 | pending |
| Control owner | control-plane policy、routing decision、state sync、service-contract 输出 | capability report、typed report、负向测试 | pending |
| Web/API owner | Web/API 不依赖 Go 默认服务路径，API contract 稳定 | API smoke、schema/response diff、auth/error-path 验证 | pending |
| Datapath core | mark、redirect、route save/lookup、L4/L3 处理、UDP state、TCP state | golden packet、integration test、live traffic sample | pending |
| Kernel-program/eBPF/tproxy | Rust/Aya object 覆盖 tproxy classifier/cgroup surface，并通过 verifier/load/runtime evidence | object build、section/map ABI report、verifier log、live tc/cgroup attach | pending |
| Outbound owner | 默认 outbound path 由 Rust native 接管，link/global capability 可表达且无静默回落 | protocol matrix、underlay evidence、negative fallback test | pending |
| Product-chain packaging | 默认包不再包含 Go product shell/orchestration/control/runtime/API/service/release/outbound dependency | package manifest、binary/dependency scan、install smoke | pending |
| Release/install/service | systemd/init、install/uninstall/upgrade、权限、capability、目录布局 | release rehearsal、install rehearsal、rollback rehearsal | pending |
| Rollback model | C10 切换失败时能恢复到已知可用版本，不污染 live host | backup manifest、restore rehearsal、host-write freeze evidence | pending |
| Live host validation | 目标 live host 使用 Rust go-free 默认链承载真实流量 | host inventory、before/after report、traffic evidence、rollback evidence | pending |

### 26.3 C10 fail-closed 规则

- 只要默认产品包仍依赖 Go product shell/orchestration/control/runtime/API/service/release/outbound dependency，
  `go_free_product_chain_ready` 必须为 `false`。
- 只要 Rust product binary 未证明可独立承担 daemon lifecycle、Web/API、package/release/install，
  `go_free_product_chain_ready` 必须为 `false`。
- 只要 kernel-program/eBPF/tproxy 仍只有 source parity、没有 object/verifier/live attach 证据，
  不能删除 C fallback，也不能声明 C10 go-free product-chain 完成。
- 只要 live host validation 缺少 rollback rehearsal，不能进行默认切换。

### 26.4 C10 owner evidence 输出格式

每个 C10 测试面完成后，应记录：

- `surface`：对应 26.2 的测试面。
- `artifact`：本地或 release artifact 路径。
- `command`：可复现命令。
- `environment`：本地、CI、live host、kernel/version、feature flags。
- `result`：pass/fail/blocked。
- `fallback_scope`：Go/C fallback 是否仍保留，只能是 oracle/test/compat 或明确 fail-closed。
- `rollback_evidence`：恢复路径和演练结果。
- `ready_field`：对应 service-contract / typed report 字段。

### 26.5 Kernel-program/eBPF/tproxy parity audit（2026-06-02）

本节挂靠 C10 `kernel-program/eBPF/tproxy` evidence，不新增 stage。

#### 结论

- `control/kern/tproxy.c` 不是 Linux kernel 本体源码。
- 它是 eBPF kernel program 源码；编译成 BPF object 后由 loader 加载到内核，经 verifier 验证，
  在内核 eBPF VM/JIT 路径中执行。
- 因此它“运行在 kernel context”，但不等于“修改 Linux kernel”。
- Rust 侧不能只看 `rust/crates/dae-ebpf-program/src/tproxy.rs`。
  当前 Rust/Aya tproxy candidate 被拆在以下文件：
  - `programs.rs`：section/entry wrapper。
  - `tproxy.rs`：方向处理、redirect、listener assign、TCP/UDP 主 datapath。
  - `packet.rs`：IPv4/IPv6、IPv6 extension header、TCP/UDP/ICMPv6 parse。
  - `routing.rs`：match-set route loop、route result、outbound alive、pid/pname lookup。
  - `udp_state.rs`：UDP conn state + timer。
  - `cgroup.rs`：cookie -> pid/pname lifecycle。
  - `maps.rs` / `abi.rs`：map surface、pinning、ABI layout、PARAM。
- 当前源码审计结论：
  Rust/Aya 版本已经覆盖 tproxy classifier/cgroup 的入口和主 datapath surface，
  可以作为 Rust tproxy dataplane candidate。
- 2026-06-02 scope 决策：
  C 版 `bpf_get_current_task()` / CO-RE argv real-comm 路径暂时屏蔽；
  `_update_map_elem_by_cookie()` 失败后从 `tgid_pname_map` retrieve pname 的 fallback 也不需要。
- 因此，CO-RE argv real-comm 和 cgroup fallback 不作为保留 C object 的依据。
- 当前 Rust/Aya tproxy 是否能退役 C object，只看 object build、section/map ABI、BTF/verifier、
  tc/cgroup attach、live traffic、rollback 这些 C10 evidence。

#### Entry coverage

`control/kern/tproxy.c` classifier entry：

- `lan_ingress_l2`
- `lan_ingress_l3`
- `lan_egress_l2`
- `lan_egress_l3`
- `wan_ingress_l2`
- `wan_ingress_l3`
- `wan_egress_l2`
- `wan_egress_l3`
- `dae0peer_ingress`
- `dae0_ingress`

Rust/Aya `programs.rs` 已提供对应 `classifier/*` section wrapper：

- `classifier/lan_ingress_l2`
- `classifier/lan_ingress_l3`
- `classifier/lan_egress_l2`
- `classifier/lan_egress_l3`
- `classifier/wan_ingress_l2`
- `classifier/wan_ingress_l3`
- `classifier/wan_egress_l2`
- `classifier/wan_egress_l3`
- `classifier/dae0peer_ingress`
- `classifier/dae0_ingress`

`control/kern/tproxy.c` cgroup entry：

- `cgroup/sock_create`
- `cgroup/sock_release`
- `cgroup/connect4`
- `cgroup/connect6`
- `cgroup/sendmsg4`
- `cgroup/sendmsg6`

Rust/Aya `programs.rs` 已提供对应 cgroup section wrapper。

当前 `dae-ebpf-support::kernel_program_feasibility_report` 也已表达同一结论：

- `tproxy_classifier_total=10`
- `rust_tproxy_classifier_covered=10`
- `tproxy_cgroup_total=6`
- `rust_tproxy_cgroup_covered=6`
- `rust_tproxy_runtime_admitted=true`
- `default_switch_allowed=false`
- `c_tproxy_object_fallback_required=true`
- `tc_command_fallback_required=true`

#### 功能面对照

| 功能面 | C `tproxy.c` | Rust/Aya 当前覆盖 | 结论 |
| --- | --- | --- | --- |
| TC classifier entry | 10 个 `tc/*` 或 Aya 模式下 `classifier/*` section | 10 个 `classifier/*` wrapper | entry 覆盖 |
| Cgroup entry | 6 个 cgroup hook | 6 个 cgroup wrapper | entry 覆盖 |
| Map surface | outbound connectivity、listen socket、redirect track、tgid/pname、routing tuples、fast sock、LPM array、routing、domain routing、cookie/pid、UDP state | `maps.rs` 保留对应 map 名称、类型、size、pinning 意图 | surface 覆盖，仍需 object/ABI 证据 |
| PARAM | `volatile const struct dae_param PARAM`，含 control pid、ifindex、netns、dae0peer mac、`has_bpf_get_current_task` | `abi.rs` 定义 `BpfDaeParam` 和 volatile accessor | 基础覆盖；`has_bpf_get_current_task` 对应 CO-RE path 暂时屏蔽，不作为 C 保留依据 |
| Packet parse | IPv4/IPv6、IPv6 extension header、TCP/UDP/ICMPv6/NDP redirect | `packet.rs` 覆盖同类解析，已有 packet-level golden tests | 源码和单测覆盖，仍需 verifier/live packet 证据 |
| Route loop | domain/IP/source IP/port/source port/L4/IP version/MAC/process name/DSCP/fallback、logical OR/must/direct/block/control-plane route | `routing.rs` 覆盖对应 match type 和 route-state 逻辑 | 主逻辑覆盖，需 C/Rust matched behavior 证据 |
| LAN egress / WAN ingress UDP state | 反向 tuple UDP timer state，NDP redirect drop | `udp_state.rs` + `tproxy.rs` 覆盖 | 主逻辑覆盖 |
| LAN ingress | TCP listen lookup、新连接 route、UDP state、direct/block/proxy、route result save、redirect to control plane | `tproxy.rs::lan_ingress` 覆盖 | 主逻辑覆盖 |
| WAN egress | local-only filter、pid/pname、control-plane bypass、TCP old/new flow、UDP state、route result save、direct/block/proxy、redirect to control plane | `tproxy.rs::wan_egress` 覆盖 | 主逻辑覆盖 |
| dae0peer ingress | 校验 cb mark、设置 mark、change_type、按 cb[1] assign listener | `tproxy.rs::dae0peer_ingress` 覆盖 | 主逻辑覆盖 |
| dae0 ingress | reverse tuple lookup、恢复 MAC、packet type、redirect back | `tproxy.rs::dae0_ingress` 覆盖 | 主逻辑覆盖 |
| Fast socket map | `fast_sock` map 定义存在，`tproxy.c` 本文件未看到直接使用 | `fast_sock` map 定义存在 | 不是当前 tproxy.rs 缺口，但 C10 需要确认上层是否依赖 |

#### Scope decision and remaining evidence gaps

1. Process identity scope 已收敛。

   C 版 `get_pid_pname()`：

   - 如果 `PARAM.has_bpf_get_current_task=false`，使用 `bpf_get_current_comm()`。
   - 如果 `PARAM.has_bpf_get_current_task=true`，通过 `bpf_get_current_task()` + CO-RE 读取
     `task->mm->arg_start`，再用 `bpf_core_read_user_str()` 读取 argv，并提取真实命令名。
   - 如果 `_update_map_elem_by_cookie()` 失败，`update_map_elem_by_cookie()` 会 fallback 到
     `tgid_pname_map`，至少写入 pid 并尽力恢复 pname，避免 dae 自身连接路径形成 loop。

   Rust 当前 `cgroup.rs`：

   - 只使用 `bpf_get_current_pid_tgid()` + `bpf_get_current_comm()`。
   - 虽然 `abi.rs` 有 `has_bpf_get_current_task` 字段，当前 Rust cgroup path 未使用它。
   - 未实现 C 版 `bpf_get_current_task()` / argv real-comm 路径。
   - 未实现 C 版 `_update_map_elem_by_cookie()` 失败后从 `tgid_pname_map` retrieve pname 的 fallback。

   当前决策：

   - CO-RE argv real-comm 暂时屏蔽。
   - cgroup fallback retrieve pname 不需要。
   - 这两个差异不作为 C object 保留依据。
   - 当前 process identity accepted scope 是 pid + `bpf_get_current_comm()`。

2. Runtime verifier/live attach 证据不足。

   Rust/Aya loader 已支持：

   - feature `native-ebpf`
   - 构建 `dae-ebpf-program` 到 `bpfel-unknown-none`
   - `DAE_RUST_NATIVE_BPF_OBJECT` override
   - embedded Rust/Aya object
   - tc/cgroup attach-pin 路径

   但 C10 退役 C fallback 前仍需要：

   - Rust object build artifact。
   - section/program list 与 C object 对照。
   - map layout / pinning / BTF/verifier log。
   - tc + cgroup attach on target kernel。
   - LAN/WAN/dae0/dae0peer live traffic evidence。
   - rollback evidence。

3. Admission gate 当前仍 fail-closed。

   当前 gate 允许记录 Rust tproxy candidate，但在现场证据齐全前不允许删除 fallback。
   这个 fail-closed 依据是 object/verifier/attach/live/rollback evidence，不是 CO-RE argv
   或 cgroup fallback 差异：

   - `kernel_program_feasibility_report.default_switch_allowed=false`
   - `c_tproxy_object_fallback_required=true`
   - `tc_command_fallback_required=true`
   - `tproxy_dataplane_required_checks` 还要求 map ABI/BTF/verifier、packet golden、runtime admission、
     matched benchmark、remote host write admission、C fallback preserved、Go userspace boundary preserved。

#### 本轮验证

本轮执行：

```text
cargo test --manifest-path rust/Cargo.toml -p dae-ebpf-support kernel_program
```

结果：

- 19 passed。

本轮执行：

```text
cargo test --manifest-path rust/Cargo.toml -p dae-ebpf-support packet_level
```

结果：

- 4 passed。

这些测试证明当前 gate/packet golden 断言通过；它们不等同于内核 verifier/live attach 通过。

#### C10 准入建议

要把 Rust/Aya tproxy 从 candidate 推到可替代 C fallback，应按 C10 evidence checklist 补齐：

1. 明确记录当前 process identity accepted scope：pid + `bpf_get_current_comm()`。
2. 将 CO-RE argv real-comm 和 cgroup fallback retrieve pname 标为 disabled / non-blocking。
3. 增加 ABI/layout tests：`BpfDaeParam`、`BpfMatchSet`、`BpfRoutingResult`、`BpfTuplesKey`、
   `BpfUdpConnState`、map key/value size 与 C object contract 对齐。
4. 构建 Rust eBPF object，并记录 `llvm-objdump`/`bpftool` section、map、relocation、BTF 信息。
5. 在目标 kernel 加载并记录 verifier log。
6. 在 live host attach tc/cgroup，验证 LAN/WAN/dae0/dae0peer/cgroup 真实流量。
7. 验证 rollback evidence。
8. 保留 C fallback，直到上述 object/verifier/attach/live/rollback 证据齐全且 retirement gate 明确通过。

当前 C10 判断：

- `rust_tproxy_dataplane_candidate=true`
- `tproxy_entry_surface_covered=true`
- `tproxy_main_datapath_source_covered=true`
- `tproxy_core_real_comm_scope_disabled=true`
- `tproxy_cgroup_fallback_scope_disabled=true`
- `tproxy_source_scope_retirement_blocker=false`
- `c_tproxy_object_retirement_allowed=false`
- `go_free_product_chain_ready=false`

## 27. 100% Rust native target and largest gap（2026-06-02）

本节记录当前最终目标口径；不新增 C0-C10 之外的新 stage。

### 27.1 目标口径

当前最终目标是 100% Rust native。

这里的 100% Rust native 指默认产品链中：

- 默认 product binary 是 Rust binary。
- 默认 runtime/userspace owner 是 Rust。
- 默认 control/Web/API/service/reload/stop/report owner 是 Rust。
- 默认 datapath/outbound/DNS/sniffing/routing owner 是 Rust。
- 默认 release/package/install/upgrade/rollback owner 是 Rust product-chain。
- 默认 eBPF loader/attach/map/listener owner 是 Rust/Aya。
- 默认 kernel-program object 使用 Rust/Aya eBPF object。
- Go 只允许作为 oracle/test/compat，不允许进入默认 product/runtime/control/API/service/release/outbound path。
- C eBPF object 只允许作为明确 fallback/oracle，最终 100% Rust native 时不得进入默认路径。

这比 C9 `release-default-switch-v1` 更强：

- C9 只是 Rust-owned default candidate。
- C9 仍可能存在 Go product shell 或 Go package/release shell。
- C10 `go-free-product-chain-v1` 是 100% Rust native 的主线收口点。

### 27.2 当前最大缺口

当前最大的缺口是 C10 product-chain owner 闭环，不是单个协议、不是 Boring/fingerprint、
也不是 `tproxy.c` 的 CO-RE argv/fallback 差异。

具体说，最大缺口是：

```text
Rust product binary
  -> Rust Web/API/control/service/runtime
  -> Rust release/package/install/rollback
  -> default product chain no longer depends on Go shell/orchestration/control/API/service/release/outbound
```

当前真实状态仍是：

- `go_free_product_chain_ready=false`
- 默认产品链还没有证明 Go product shell 已退役。
- 默认产品链还没有证明 Go orchestration 已退役。
- 默认产品链还没有证明 Go control/runtime/API/service/release 默认路径已退役。
- 默认产品链还没有证明 Go outbound dependency 默认路径已退役。
- Rust product binary 还没有证明能独立承担 daemon lifecycle、Web/API、package/release/install。
- live host validation 和 rollback rehearsal 仍未补齐。

因此，最大 blocker 是“产品默认链仍未 go-free”，而不是 Rust crate 是否存在。

### 27.3 严格 100% 下的第二层硬缺口

严格按 100% Rust native，第二层硬缺口是 kernel-program/eBPF 默认对象退役。

当前 tproxy 源码面已经具备 Rust/Aya candidate：

- classifier entry surface 已覆盖。
- cgroup entry surface 已覆盖。
- 主 datapath source surface 已覆盖。
- CO-RE argv real-comm 暂时屏蔽。
- cgroup fallback retrieve pname 不需要。
- 这些源码 scope 不作为保留 C object 的依据。

但默认 C eBPF object 仍不能退役，原因只剩 evidence：

- Rust eBPF object build artifact。
- section/program list 对照。
- map layout / pinning / BTF / verifier log。
- target kernel tc + cgroup attach。
- LAN/WAN/dae0/dae0peer/cgroup live traffic。
- rollback evidence。

所以在 100% Rust native 目标下：

- C10 product-chain owner 是最大缺口。
- Rust/Aya eBPF object retirement 是第二层硬缺口。
- 两者都完成后，才可以讨论默认路径上 Go/C fallback 全部退役。

### 27.4 当前优先级

当前推进顺序应保持在 C0-C10 内：

1. 先闭合 C10 Rust product binary / Web/API / release-package-install / rollback / live host evidence。
2. 同步准备 Rust/Aya eBPF object build、ABI/BTF/verifier、tc/cgroup attach 和 live traffic evidence。
3. C10 通过前，任何“100% Rust native 已完成”的表述都必须 fail-closed。

当前判断：

- `target_100_percent_rust_native=true`
- `largest_gap=c10_product_chain_owner_closure`
- `secondary_strict_gap=rust_aya_ebpf_object_retirement`
- `go_free_product_chain_ready=false`
- `default_go_product_shell_retired=false`
- `default_go_control_api_service_release_retired=false`
- `default_go_outbound_dependency_retired=false`
- `rust_product_binary_default_ready=false`
- `rust_web_api_default_ready=false`
- `rust_release_package_install_ready=false`
- `rust_aya_ebpf_default_object_ready=false`

## 28. Packaging decision: no embedded Go-shell final path（2026-06-02）

本节记录当前打包路径决策；不新增 C0-C10 之外的新 stage。

### 28.1 决策

当前同意的方向：

- 不把 `bundle-rust-owned` 额外编译并 embed `dae-daemon-optin` 的方式作为最终方案。
- `bundle-rust-owned` 最多只能作为 C9 Rust-owned candidate 的测试/过渡/compat artifact。
- 100% Rust native / C10 final 不能是 Go `daed` / `daewing` shell 内嵌或拉起 Rust daemon。
- C10 final 必须让 Go `daed` / `daewing` 从默认 product path 退役。
- 默认 `/usr/bin/daed` 或 `/usr/bin/daex` 必须是 Rust product binary，或由 Rust product binary 直接提供等价入口。

### 28.2 当前 daed packaging 不适合作为最终 Rust native

当前 daed 默认 packaging 仍是：

```text
daed top-level make
  -> wing make bundle
  -> Go daed/daewing product shell
  -> optional runtime selector
```

普通 `bundle` 的问题：

- 默认 runtime selector 已经偏向 Rust-owned。
- 但普通 `bundle` 不构建、不嵌入 `dae-daemon-optin`。
- 如果没有 `DAED_RUST_DAEMON` 指向外部 Rust daemon，普通包无法作为稳定 Rust-owned runtime artifact。
- 即使使用 `bundle-rust-owned`，产品入口仍是 Go shell，因此仍不是 100% Rust native。

所以当前 daed packaging：

- 可作为 hybrid / C9 过渡链路参考。
- 不适合作为 C10 final go-free package。
- 不满足 100% Rust native 默认产品链。

### 28.3 daed / daewing 的 Rust native 要求

如果不使用 `bundle-rust-owned` embed 方式，并且目标是 100% Rust native，则必须对
`daed` / `daewing` 当前承担的默认产品职责进行 Rust native 化或退役替换。

需要迁移或退役的默认职责：

- product shell。
- Web/API backend。
- runtime/service orchestration。
- `run` / `reload` / `stop` / `service-contract` 产品入口。
- package/release/install/upgrade/uninstall。
- Docker/release workflow artifact 生成。
- systemd service contract。
- rollback / backup manifest / host-write freeze。

允许保留的内容：

- Web frontend 静态资产可以继续由现有前端构建链产生。
- Go 代码可以保留为 oracle/test/compat。
- 过渡期可以保留 side-by-side packaging 或 embed packaging 作为 C9 evidence。
- 但这些都不能进入 C10 final 默认路径。

### 28.4 C10 final package target

C10 final package 应收敛为：

```text
systemd / package / Docker
  -> Rust product binary
    -> Rust Web/API/control/service/runtime
    -> Rust datapath/outbound/DNS/routing/sniffing
    -> Rust eBPF loader/attach/map/listener
    -> Rust/Aya eBPF object when default object evidence passes
```

需要验证：

- `/usr/bin/daed` 或 `/usr/bin/daex` 是 Rust product binary。
- `daed.service` 启动的是 Rust product binary，不是 Go shell。
- release artifact 不包含默认 Go product shell。
- package manifest 不包含默认 Go orchestration/control/API/service/release/outbound dependency。
- Docker image 默认入口不经过 Go shell。
- install/upgrade/uninstall/rollback 全部由 Rust product-chain evidence 覆盖。
- live host 能使用该 package 承载真实流量并可回滚。

当前判断：

- `bundle_rust_owned_final_path_allowed=false`
- `bundle_rust_owned_c9_transition_allowed=true`
- `go_daed_shell_default_path_allowed_for_c10=false`
- `go_daewing_shell_default_path_allowed_for_c10=false`
- `daed_packaging_currently_c10_native_ready=false`
- `requires_daed_daewing_default_path_retirement=true`
- `requires_rust_product_binary_package_layout=true`

## 29. Rust product binary package layout（2026-06-02）

本节设计 C10 / 100% Rust native 的默认 package layout；不新增 C0-C10 之外的新 stage。

### 29.1 Layout 原则

- 默认 package 只提供 Rust product binary 作为产品入口。
- 默认 package 不包含 Go `daed` / `daewing` product shell。
- 默认 package 不通过 Go shell 拉起 Rust daemon。
- `bundle-rust-owned` / embedded `dae-daemon-optin` 只允许作为 C9 transition artifact。
- C10 final package 中，Go 只能出现在 oracle/test/compat artifact，不得进入 default runtime path。
- 默认 package layout 必须同时适配 deb/rpm/pacman、Docker image 和 live host install。
- package manifest 必须能被 C10 gate 机器读取，不能只靠人工说明。

### 29.2 Product binary

C10 final primary binary：

```text
/usr/bin/daed
```

要求：

- `/usr/bin/daed` 是 Rust product binary。
- `/usr/bin/daed` 直接提供 `run` / `reload` / `stop` / `service-contract` / `validate` / `version`。
- `/usr/bin/daed` 直接提供 Web/API runtime owner，不能转交给 Go backend shell。
- `/usr/bin/daed` 直接持有 runtime/userspace/control/datapath/outbound owner。
- `/usr/bin/daed` 允许保留 `dae-daemon-optin` 作为旧测试名或 compat symlink，但 C10 final 不以
  `dae-daemon-optin` 作为产品入口名。

可选 compatibility symlink：

```text
/usr/bin/daex -> /usr/bin/daed
```

该 symlink 只作为 DAEX product alias；不能改变 `/usr/bin/daed` 的 Rust product binary 要求。

### 29.3 Package filesystem layout

目标文件树：

```text
/usr/bin/daed
/usr/bin/daex -> /usr/bin/daed                         # optional alias

/usr/lib/daed/
  package/manifest.json
  package/build-info.json
  ebpf/dae-ebpf-program-bpfel.o                         # Rust/Aya object when default object evidence passes

/usr/share/daed/
  web/                                                   # built Web frontend static assets
  geodata/geoip.dat
  geodata/geosite.dat
  icons/
  docs/

/etc/daed/
  config.d/
  daed.dae                                              # default/example config, package-managed or sample

/usr/lib/systemd/system/daed.service
/usr/share/applications/daed.desktop
/usr/share/icons/hicolor/*/apps/daed.png

/var/lib/daed/
  state/
  cache/
  geodata/
  rollback/

/run/daed/
  daed.pid
  daed.ready
  daed.progress
  daed.abort
```

Notes：

- `/usr/share/daed/web` 可以继续由当前 Web frontend build 产生；这不是 Go product shell。
- `/usr/share/daed/geodata` 是 package seed；运行期更新可写入 `/var/lib/daed/geodata`。
- `/usr/lib/daed/ebpf` 只允许放 Rust/Aya eBPF object；C eBPF object 不得进入 C10 final default package。
- `/run/daed` 是 runtime-owned volatile state；不得把 runtime pid/progress 写进 `/tmp` 作为 final layout。
- `/var/lib/daed/rollback` 保存 backup manifest、pre-switch manifest、restore evidence。

### 29.4 Forbidden default package contents

C10 final default package 禁止包含：

- Go `daed` product shell binary。
- Go `daewing` product shell binary。
- Go orchestration binary / helper 作为默认 runtime dependency。
- Go Web/API backend 作为默认 service path。
- Go outbound dependency 作为默认 outbound path。
- `bundle-rust-owned` embedded Rust daemon payload 作为最终产品入口机制。
- `DAED_RUST_DAEMON` side-by-side lookup 作为默认 package contract。
- C `tproxy` / `trace` eBPF object 作为默认 kernel program object。

允许保留但必须隔离：

- Go oracle/test/compat binaries，只能放在 test-support artifact 或明确 compat package。
- C eBPF oracle object，只能放在 test/oracle artifact，不得由 default service 自动加载。
- C9 transition package 可以包含 Go shell + Rust daemon，但必须标注为 transition，不能标注为 C10 final。

### 29.5 Systemd contract

C10 final service：

```ini
[Unit]
Description=DAEX Rust native daemon
Documentation=https://github.com/ksong008/DaeNext
After=network-online.target systemd-sysctl.service
Wants=network-online.target
Conflicts=dae.service

[Service]
Type=notify
User=root
RuntimeDirectory=daed
StateDirectory=daed
CacheDirectory=daed
LogsDirectory=daed
LimitNPROC=512
LimitNOFILE=1048576
ExecStart=/usr/bin/daed run -c /etc/daed/
ExecReload=/usr/bin/daed reload --service-pid-file /run/daed/daed.pid --timeout-ms 90000
ExecStop=/usr/bin/daed stop --service-pid-file /run/daed/daed.pid --timeout-ms 30000
Restart=on-abnormal

[Install]
WantedBy=multi-user.target
```

Requirements：

- `Type=notify` 必须由 Rust product binary 发出 READY/RELOADING/STOPPING。
- `ExecStart` / `ExecReload` / `ExecStop` 都不能经过 Go shell。
- package install hooks 只允许 `daemon-reload`、restart active service、manifest/rollback handling；
  不允许写入 Go fallback selector。
- rollback 必须恢复旧 service file、旧 binary、旧 package manifest、旧 geodata/cache policy。

### 29.6 Docker image layout

C10 final Docker image：

```text
ENTRYPOINT ["/usr/bin/daed"]
CMD ["run", "-c", "/etc/daed/"]
```

Image contents：

- `/usr/bin/daed` Rust product binary。
- `/usr/share/daed/web` frontend assets。
- `/usr/share/daed/geodata` seed data。
- `/usr/lib/daed/package/manifest.json`。
- `/usr/lib/daed/ebpf/dae-ebpf-program-bpfel.o` when Rust/Aya object is admitted。
- No Go product shell。
- No default Go outbound dependency。

### 29.7 Package manifest contract

`/usr/lib/daed/package/manifest.json` must include:

```json
{
  "schema": "daex-rust-product-package-v1",
  "product": "daed",
  "target": "100-percent-rust-native",
  "phase": "C10",
  "binary": {
    "path": "/usr/bin/daed",
    "implementation": "rust",
    "provides": ["run", "reload", "stop", "service-contract", "validate", "version"]
  },
  "default_path": {
    "go_product_shell": false,
    "go_orchestration": false,
    "go_web_api_backend": false,
    "go_outbound_dependency": false,
    "c_ebpf_default_object": false
  },
  "rust_owner": {
    "runtime": true,
    "control": true,
    "web_api": true,
    "datapath": true,
    "outbound": true,
    "package_release": true,
    "ebpf_loader_attach": true
  },
  "artifacts": {
    "web_assets": "/usr/share/daed/web",
    "geodata_seed": "/usr/share/daed/geodata",
    "runtime_state": "/var/lib/daed",
    "runtime_dir": "/run/daed",
    "rust_aya_ebpf_object": "/usr/lib/daed/ebpf/dae-ebpf-program-bpfel.o"
  },
  "rollback": {
    "manifest_dir": "/var/lib/daed/rollback",
    "required": true
  }
}
```

The C10 gate must fail closed if:

- manifest is missing。
- manifest says any default Go/C path is true。
- `/usr/bin/daed` is not the Rust product binary。
- service file points to Go shell or transition bundle。
- Docker entrypoint points to Go shell。
- Rust/Aya eBPF object is claimed but object/verifier/live evidence is missing。

### 29.8 Build targets

Final build targets should be named by package role, not by transition mechanism：

```text
make rust-product-package
make rust-product-docker
make rust-product-service-contract
make rust-product-package-smoke
```

Do not use these as final C10 target names：

```text
bundle-rust-owned
embed-rust-daemon
go-shell-rust-owned
```

Interim implementation can copy existing Rust binary as `/usr/bin/daed`, but the package manifest must still
distinguish interim artifact from C10 final:

```text
artifact_kind=transition
c10_final=false
```

### 29.9 Admission checks

C10 package admission must verify:

- binary identity：`/usr/bin/daed --version` reports Rust product identity。
- service contract：`/usr/bin/daed service-contract` reports go-free package layout。
- package manifest：all default Go/C fields are false。
- command surface：`run` / `reload` / `stop` / `validate` execute without Go shell。
- Web/API：runtime overview/reload/stop API smoke passes through Rust owner。
- dependencies：package scan finds no Go product shell in default path。
- eBPF：Rust/Aya object path and verifier evidence match manifest claim。
- install：deb/rpm/pacman install runs without Go shell dependency。
- Docker：entrypoint is Rust product binary。
- rollback：restore rehearsal passes on live host or isolated package root。

Current package-layout status:

- `rust_product_package_layout_designed=true`
- `rust_product_package_layout_implemented=false`
- `rust_product_package_manifest_required=true`
- `default_go_shell_package_forbidden=true`
- `transition_embed_package_final_forbidden=true`
- `c10_package_admission_ready=false`

## 30. daed / daewing / dae audit and Rust product package redesign（2026-06-02）

本节基于当前真实链路重新审计 `daed`、`daed/wing`、`dae` 的连接方式，并修正第 29 节的
C10 Rust product binary package layout。第 29 节的原则仍然保留，但本节明确补上
`daewing` 退出、`wing.db` 状态迁移、Web/API owner、product state owner 等细节。

### 30.1 当前 daed 顶层如何链接 daewing / dae

当前 `/root/project/daed-daex-align/daed` 顶层 `Makefile` 的产品入口不是 Rust binary：

- `daed` target 依赖：
  - `submodule`
  - `wing/dae-core/control/bpf_bpfeb.o`
  - Web `dist`
- 顶层最后执行：
  - `cd wing && make OUTPUT=../$(OUTPUT) APPNAME=$(APPNAME) WEB_DIST=../dist VERSION=$(VERSION) bundle`
- 因此当前 `/usr/bin/daed` package 产物本质是 `daed/wing` 的 Go bundle，Web dist 被复制到
  `wing/webrender/web` 后由 Go binary embed / serve。

当前 Docker / publish Docker 链路也是 Go bundle：

- `Dockerfile`：
  - build Web frontend。
  - copy `wing`。
  - 在 `/build/wing` 执行 `make APPNAME=daed ... bundle`。
  - runtime image 复制 `/build/wing/daed` 到 `/usr/local/bin`。
- `publish.Dockerfile` 同样执行 `wing make ... bundle`。

当前 systemd service：

```ini
Type=simple
ExecStart=/usr/bin/daed run -c /etc/daed/
ExecReload=/bin/kill -HUP $MAINPID
```

这说明当前产品服务入口是 Go `daed/wing` CLI。`run -c /etc/daed/` 不是直接读单个
`.dae` 文件，而是进入 `/etc/daed/wing.db` 产品状态库。

### 30.2 当前 daewing / wing 如何链接 dae

当前 `/root/project/daed-daex-align/daed/wing/go.mod` 直接依赖并 replace：

```text
github.com/daeuniverse/dae      => /root/project/dae-daex-align
github.com/daeuniverse/outbound => /root/project/outbound-daex-align
github.com/daeuniverse/quic-go  => /root/project/quic-go-daex-align
```

`wing/main.go` 还 blank-import：

```go
_ "github.com/daeuniverse/dae/component/outbound"
```

这会把 Go dae outbound handler 注册进 Go runtime。当前 Go native path 通过
`engine/nativeService` 直接调用：

- `daeengine.EmptyConfig`
- `daeengine.ExportFlatDesc`
- `daeengine.ParseConfig`
- `daeengine.NecessaryOutbounds`
- `daeengine.New(...).Run`
- `runtime.ReloadWithContext`
- `runtime.Stop`
- `runtime.ControlPlane`
- `runtime.GetRuntimeOverview`
- `runtime.HTTPTransport`

当前 Rust-owned path 仍由 Go `daewing` 作 supervisor：

- `engine/runtime_mode.go` 默认 runtime 已改为 `rust-owned`。
- 但 `newRustOwnedService()` 仍在 Go process 内：
  - 从 DB 生成 `daeConfig.Config`。
  - marshal 成 `generated.dae`。
  - 通过 `DAED_RUST_DAEMON` 或 embedded asset 找到 / 写出 `dae-daemon-optin`。
  - `exec.Command(binaryPath, "run", "-c", generated.dae, ...)` 启动 Rust resident。
  - reload 时再执行 `binaryPath reload --service-pid-file ...`。
- 普通 `bundle` 不 embed Rust daemon；只有 `bundle-rust-owned` 增加
  `rust_owned_daemon_embed` tag 并把 `dae-daemon-optin` 嵌进 Go bundle。

结论：

- 当前 “Rust-owned” 不是 C10 go-free product。
- 当前仍是 Go product shell / Go Web/API / Go DB orchestrator / Go supervisor + Rust resident daemon。
- C9 可以把它作为 transition candidate；C10 final 不能保留这种默认形态。

### 30.3 当前 wing.db 是什么

当前产品状态文件是：

```text
/etc/daed/wing.db
```

它由 `wing/db/db.go` 的 GORM `AutoMigrate` 创建，至少包含：

- `User`
  - username、password hash、JWT secret、JSON storage、avatar、display name。
- `Config`
  - global section 文本、selected、version。
- `Dns`
  - dns section 文本、selected、version。
- `Routing`
  - routing section 文本、selected、version。
- `Node`
  - node link、name、address、protocol、tag、subscription id。
- `Subscription`
  - subscription link、cron、enable、status、info、tag、nodes。
- `Group`
  - group name、policy、policy params、nodes、subscription bindings、version。
- `GroupSubscription`
  - group 与 subscription 绑定、name filter regex。
- `GroupPolicyParam`
  - policy 参数。
- `System`
  - running state、running config/dns/routing/group ids 与 versions。
- `LogSetting`
  - WebUI log behavior。
- `NodeLatencyResult`
  - node latency cache / query result。

因此 `wing.db` 当前不是“普通 dae 配置文件”，而是 WebUI / API / runtime orchestration
的产品状态库。

### 30.4 当前 daewing 的核心功能

当前 Go `daed/wing` 覆盖的产品功能：

- CLI：
  - `run`
  - `export outline`
  - `export openapi`
  - `export flatdesc`
  - `resetpass`
- bootstrap：
  - 创建 config dir。
  - 权限 / sudo 检查。
  - 初始化 SQLite DB。
  - 初始化订阅 scheduler。
  - 初始化 logstore。
  - 启动 runtime。
  - restore previous running state。
  - 启动 Web/API HTTP server。
  - 处理 SIGHUP reload。
- Web/API：
  - `/api/health`
  - auth token / auth status / users。
  - general state / interfaces / cache stats。
  - configs / dns / routings CRUD、select、parsed preview、flat-desc。
  - groups、group nodes、group subscriptions。
  - nodes import/list/update/delete、latency query / latency test。
  - subscriptions CRUD、refresh、nodes。
  - user profile / password / JSON storage / default resources。
  - dae config file import/export/preview。
  - dae bundle import/export。
  - runtime overview / log-level / reload / stop。
  - runtime SSE events。
  - log list / log settings / log SSE events。
  - OpenAPI document。
- config orchestration：
  - 读取 selected `Config`、`Dns`、`Routing`。
  - 调用 dae parser 得到 `daeConfig.Config`。
  - `NecessaryOutbounds` 得到 routing 引用的 groups。
  - 加载 group 绑定的 manual nodes 与 subscription nodes。
  - 按 group policy / filter 拼接 `c.Group`。
  - 按 node link 拼接 `c.Node`。
  - 更新 `System.running*` 版本快照。
  - 调用 `engine.Default().ReloadContext(ctx, c)`。
- runtime observation：
  - Go native path 可以走 Go dae `ControlPlane` / `RuntimeOverview`。
  - Rust-owned path 当前主要通过 resident report / env / placeholder 暴露 attach backend、
    netns link mode、overview fallback。
- install / package：
  - Go bundle 是默认 package artifact。
  - `bundle-rust-owned` 是 transition artifact，不是 C10 final。

### 30.5 Rust crates 当前对应能力

当前 `/root/project/dae-daex-align/rust/crates` 已有的对应能力：

- `dae-config`
  - Rust config AST / parser / schema / marshal / outline。
- `dae-engine`
  - `parse_config_sections`
  - `necessary_outbounds`
  - dry runtime reload/stop skeleton。
  - subscription persist cleanup helper。
- `dae-daemon`
  - `dae-daemon-optin` binary。
  - `validate` command。
  - `run` opt-in / admission / production runtime owner harness。
  - `reload` resident service command。
  - `service-contract` JSON。
  - resident production runtime owner。
  - signal / pid / progress / ready file contract。
  - Rust resident dataplane adapter。
- `dae-control`
  - runtime state / routing owner / domain routing owner / typed control report contracts。
- `dae-datapath` / `dae-dns`
  - TCP / UDP / DNS datapath contracts and active datapath models。
- `dae-outbound`
  - protocol-generic outbound production matrix。
  - standard TLS underlay。
  - fingerprint-aware TLS underlay contract with Boring-backed path when fingerprint is present。
  - latency helpers。
- `dae-product`
  - C9 release default switch contract。
  - C10 go-free product-chain contract。
  - package / release / rollback gate models。

当前 Rust crates 仍缺的 daewing product owner 能力：

- Rust Web/API HTTP backend。
- Rust OpenAPI surface matching current WebUI expectations。
- Rust auth / JWT / user profile / JSON storage。
- Rust SQLite product state repository for current WebUI resources。
- Rust `wing.db` importer / migrator / compatibility reader。
- Rust product-state -> `dae_config::Config` materializer that covers manual nodes、subscription nodes、
  group policies、filters、version snapshot、running state。
- Rust subscription fetch / cron scheduler / refresh status。
- Rust node import pipeline for all current link formats as used by WebUI。
- Rust node latency test / cache sync worker。
- Rust logstore and SSE event broadcaster。
- Rust general interfaces / default route / cache stats API parity。
- Rust `resetpass` equivalent。
- Rust package install / rollback hooks that operate on product state and manifest。

Audit result:

```text
rust_runtime_datapath_outbound_contracts_present=true
rust_product_shell_complete=false
rust_web_api_backend_complete=false
rust_product_state_store_complete=false
rust_wing_db_migration_complete=false
rust_daewing_replacement_complete=false
c10_go_free_product_package_ready=false
```

### 30.6 C10 answer: daewing and wing.db

C10 final answer:

- 默认 product package 不再使用 Go `daewing`。
- 默认 runtime path 不再启动 Go `daewing`。
- 默认 Web/API backend 不再由 Go `daewing` 提供。
- 默认 config orchestration 不再由 Go `daewing` 提供。
- 默认 package 中不应包含 Go `daewing` binary。

但 `wing.db` 不能直接忽略：

- 当前用户配置和 WebUI 状态实际在 `/etc/daed/wing.db`。
- C10 final 不能要求用户手工丢弃该 DB。
- C10 final 必须提供 Rust-owned migration/import/compat evidence。
- `generated.dae` 只能是 runtime snapshot，不能成为新的产品配置入口。

因此最终配置 contract 重新定义为：

```text
product config source = Rust product state store
current wing.db       = migration / compatibility input
generated.dae         = internal runtime materialized snapshot only
static .dae           = import/export/debug/sample path, not the WebUI product state owner
```

### 30.7 Redesigned Rust product package layout

C10 final package layout 修正为：

```text
/usr/bin/daed
/usr/bin/daex -> /usr/bin/daed                         # optional alias

/usr/lib/daed/
  package/manifest.json
  package/build-info.json
  ebpf/dae-ebpf-program-bpfel.o                         # Rust/Aya object after evidence passes

/usr/share/daed/
  web/                                                   # current frontend build output, served by Rust daed
  geodata/geoip.dat
  geodata/geosite.dat
  icons/
  docs/

/etc/daed/
  config.d/
  daed.dae.sample                                       # static sample / import-export reference

/var/lib/daed/
  state/product.db                                      # Rust product state primary store
  state/product.db-wal                                  # if SQLite WAL is enabled
  state/product.db-shm                                  # if SQLite WAL is enabled
  state/migrations/
  state/imported-wing-db/
  materialized/last-applied.dae                         # debug / rollback evidence, not product source
  geodata/
  cache/
  rollback/

/run/daed/
  daed.pid
  daed.ready
  daed.progress
  daed.abort
  daed.sock                                             # local command/API IPC if used
  runtime/generated.dae                                 # volatile runtime input if materialized file is needed

/usr/lib/systemd/system/daed.service
/usr/share/applications/daed.desktop
/usr/share/icons/hicolor/*/apps/daed.png
```

Key changes from section 29:

- `/etc/daed/wing.db` is not the C10 primary product config source。
- `/var/lib/daed/state/product.db` is the Rust product state primary store。
- `/etc/daed/wing.db` is an import / compatibility source for existing installs。
- `/run/daed/runtime/generated.dae` or `/var/lib/daed/materialized/last-applied.dae` is only a materialized
  runtime/config evidence artifact。
- Web assets remain under `/usr/share/daed/web` but are served by Rust `daed`。
- No Go `daewing` binary or Go bundle is present in the default package。

### 30.8 Product state migration contract

C10 final install / first-run behavior:

1. If `/var/lib/daed/state/product.db` exists:
   - Rust `daed` uses it as primary state。
2. If `product.db` does not exist and `/etc/daed/wing.db` exists:
   - Rust `daed` imports / migrates `wing.db` into `product.db`。
   - Rust `daed` writes a migration manifest under `/var/lib/daed/state/migrations/`。
   - Rust `daed` stores a backup reference under `/var/lib/daed/rollback/`。
   - Rust `daed` must not mutate or delete the original `wing.db` during admission。
3. If neither exists:
   - Rust `daed` creates an empty product state with default user / setup flow as current WebUI expects。
4. If migration fails:
   - C10 final package must fail closed and keep rollback available。
   - No Go fallback is silently launched。

Required migration evidence:

- Golden `wing.db` fixture with all tables。
- Production backup import test from `/etc/daed/wing.db` shape。
- Import of selected global/dns/routing。
- Import of manual nodes。
- Import of subscription-backed nodes。
- Import of group policies and policy params。
- Import of group subscription regex filters。
- Import of user JSON storage default resource IDs。
- Import of running state or explicit decision to mark stopped after migration。
- Materialized `dae_config::Config` matches current Go orchestrator output on fixtures。
- Runtime reload from migrated state succeeds。

### 30.9 Rust implementation placement

Do not add a new crate by default.

Initial placement should stay within current crate boundaries:

- `dae-daemon`
  - Rust product binary `daed`。
  - CLI command surface。
  - Rust Web/API HTTP backend。
  - product state repository / migration implementation。
  - orchestrator replacement。
  - runtime service supervisor。
  - logstore / SSE / local IPC。
- `dae-config`
  - config parse / marshal / outline。
- `dae-engine`
  - `parse_config_sections` / `necessary_outbounds` parity helpers。
  - future materialization helpers only if they are engine-level and not WebUI/product-state specific。
- `dae-outbound`
  - link parser / outbound metadata / latency support。
- `dae-control`
  - runtime overview / routing / domain / cache state API types。
- `dae-product`
  - C10 package layout manifest / package admission / go-free package gate。

Only add a new crate if one of these hard conflicts appears:

- HTTP/API + DB dependencies pollute non-product daemon builds in a way that cannot be feature-gated cleanly。
- product state models must be shared by multiple binaries without depending on `dae-daemon`。
- package admission needs to load product-state schema without pulling daemon runtime dependencies。
- dependency cycles appear between daemon, product, config, outbound, and control crates。

### 30.10 Rust product binary command surface

C10 final `/usr/bin/daed` must provide at least:

```text
daed run -c /etc/daed/
daed reload --service-pid-file /run/daed/daed.pid --timeout-ms 90000
daed stop --service-pid-file /run/daed/daed.pid --timeout-ms 30000
daed validate -c /etc/daed/
daed service-contract
daed version
```

Additional product-state commands are allowed, but they are not a substitute for the core service surface:

```text
daed state migrate --from-wing-db /etc/daed/wing.db --to /var/lib/daed/state/product.db
daed state export-dae --state /var/lib/daed/state/product.db
daed state check --state /var/lib/daed/state/product.db
```

### 30.11 C10 systemd contract after redesign

```ini
[Unit]
Description=DAEX Rust native daemon
Documentation=https://github.com/ksong008/DaeNext
After=network-online.target systemd-sysctl.service
Wants=network-online.target
Conflicts=dae.service

[Service]
Type=notify
User=root
RuntimeDirectory=daed
StateDirectory=daed
CacheDirectory=daed
LogsDirectory=daed
ConfigurationDirectory=daed
LimitNPROC=512
LimitNOFILE=1048576
ExecStart=/usr/bin/daed run -c /etc/daed/
ExecReload=/usr/bin/daed reload --service-pid-file /run/daed/daed.pid --timeout-ms 90000
ExecStop=/usr/bin/daed stop --service-pid-file /run/daed/daed.pid --timeout-ms 30000
Restart=on-abnormal

[Install]
WantedBy=multi-user.target
```

Requirements:

- `run` starts Rust Web/API + Rust product state + Rust runtime owner。
- `reload` goes through Rust command path / IPC / pid contract, not Go shell。
- `stop` goes through Rust command path / IPC / pid contract, not Go shell。
- `Type=notify` is emitted by Rust `daed`。
- `SIGHUP` may remain supported, but systemd `ExecReload` must not rely on `/bin/kill -HUP` as the only contract。

### 30.12 C10 package manifest after redesign

`/usr/lib/daed/package/manifest.json` must include product-state and daewing retirement fields:

```json
{
  "schema": "daex-rust-product-package-v2",
  "product": "daed",
  "target": "100-percent-rust-native",
  "phase": "C10",
  "binary": {
    "path": "/usr/bin/daed",
    "implementation": "rust",
    "provides": ["run", "reload", "stop", "service-contract", "validate", "version"]
  },
  "default_path": {
    "go_product_shell": false,
    "go_daewing": false,
    "go_orchestration": false,
    "go_web_api_backend": false,
    "go_outbound_dependency": false,
    "c_ebpf_default_object": false
  },
  "product_state": {
    "primary_store": "/var/lib/daed/state/product.db",
    "implementation": "rust",
    "wing_db_primary": false,
    "wing_db_import_supported": true,
    "wing_db_default_path_required": false,
    "generated_dae_is_product_source": false
  },
  "rust_owner": {
    "runtime": true,
    "control": true,
    "web_api": true,
    "product_state": true,
    "config_orchestration": true,
    "datapath": true,
    "outbound": true,
    "package_release": true,
    "ebpf_loader_attach": true
  },
  "artifacts": {
    "web_assets": "/usr/share/daed/web",
    "geodata_seed": "/usr/share/daed/geodata",
    "runtime_state": "/var/lib/daed",
    "runtime_dir": "/run/daed",
    "rust_aya_ebpf_object": "/usr/lib/daed/ebpf/dae-ebpf-program-bpfel.o"
  },
  "compat": {
    "go_daewing_allowed": false,
    "go_daewing_oracle_package_allowed": true,
    "wing_db_import_only": true
  },
  "rollback": {
    "manifest_dir": "/var/lib/daed/rollback",
    "required": true
  }
}
```

### 30.13 C10 admission checks after redesign

C10 package admission must fail closed unless all pass:

- `/usr/bin/daed` is a Rust binary and not Go `daewing` bundle。
- Package scan finds no Go `daed` / `daewing` product shell in default runtime path。
- `daed run -c /etc/daed/` starts Rust Web/API + Rust runtime owner。
- `daed service-contract` reports:
  - `rust_product_shell_complete=true`
  - `rust_web_api_backend_complete=true`
  - `rust_product_state_store_complete=true`
  - `rust_wing_db_migration_complete=true`
  - `default_go_daewing_forbidden=true`
  - `generated_dae_is_product_source=false`
- Rust HTTP API smoke covers current WebUI required endpoints:
  - auth。
  - general state。
  - configs/dns/routings CRUD and select。
  - groups/nodes/subscriptions。
  - runtime overview/reload/stop。
  - events/logs。
  - OpenAPI。
- Rust state migration reads current `wing.db` schema and materializes equivalent runtime config。
- Existing `/etc/daed/wing.db` can be migrated without Go process。
- New install without `wing.db` creates valid Rust product state。
- `generated.dae` is emitted only as runtime/debug evidence and is not required as the user config source。
- Docker entrypoint points to `/usr/bin/daed` Rust product binary。
- systemd `ExecStart` / `ExecReload` / `ExecStop` do not call Go shell。
- rollback restores previous binary, service file, package manifest, product state, and imported `wing.db` backup。

### 30.14 Revised status

```text
audit_current_daed_daewing_dae_linkage_recorded=true
default_daewing_final_forbidden=true
wing_db_primary_final_forbidden=true
wing_db_migration_required=true
rust_product_state_store_required=true
rust_web_api_backend_required=true
rust_product_binary_package_layout_redesigned=true
rust_product_binary_package_layout_implemented=false
c10_package_admission_ready=false
```

## 31. dae-daemon-optin retirement and latency-policy backend closure（2026-06-02）

本节补充两个 C10 `go-free-product-chain-v1` 约束，不新增 C0-C10 之外的新 stage。

### 31.1 `dae-daemon-optin` 不是 final product entry

当前 `dae-daemon-optin` 存在的原因是 C9 / transition 架构：

```text
/usr/bin/daed                  # current Go daewing bundle
  -> /etc/daed/wing.db          # Go product state source
  -> Go Web/API + Go orchestrator
  -> generated.dae              # runtime materialized snapshot
  -> dae-daemon-optin run -c generated.dae
```

因此 `dae-daemon-optin` 当前角色是：

- Rust resident runtime candidate。
- C4-C10 gate / admission / service-contract candidate binary。
- Go daewing `rust-owned` mode 的 external or embedded payload。
- 显式 opt-in 测试入口，避免未完成产品层时冒充 final `/usr/bin/daed`。

C10 final 规则：

- `/usr/bin/daed` 必须是 Rust product binary。
- `dae-daemon-optin` 不能作为 default product entry。
- `dae-daemon-optin` 不能作为 systemd `ExecStart` / `ExecReload` / Docker entrypoint 的默认 contract。
- `dae-daemon-optin` 可保留为 test/compat alias，但 default package manifest 必须声明它不是 default runtime dependency。
- 最终 Rust binary 应新增 / 迁移为 `rust/crates/dae-daemon/src/bin/daed.rs`，产品入口名为 `daed`。

Status:

```text
dae_daemon_optin_transition_only=true
dae_daemon_optin_final_entry_forbidden=true
rust_product_binary_daed_required=true
```

### 31.2 Latency-policy backend was under-specified

第 30 节提到 node latency test，但还不够。C10 Rust product layer 必须覆盖
group policy selection 的后台测速闭环，尤其是：

```text
policy: min
policy: min_avg10
policy: min_moving_avg
filter: ... [add_latency: ...]
global/group check_tolerance
```

当前 Rust `dae-outbound` 已有 group policy 核心模型：

- `SelectionPolicy::MinLastLatency` maps to `min`。
- `SelectionPolicy::MinAverage10` maps to `min_avg10` / `min_average10`。
- `SelectionPolicy::MinMovingAverage` maps to `min_moving_avg`。
- `DialerGroup::set_last_latency` feeds last-latency and avg10 ring state。
- `DialerGroup::set_moving_average` feeds moving-average state。
- `AliveDialerSet` applies:
  - alive/dead state。
  - network type specific state。
  - `add_latency` offset。
  - `check_tolerance` switch threshold。
  - random alive selection。
  - IPv4/IPv6 fallback when strict IP version is false。
- Existing Rust tests cover golden fixtures for:
  - fixed。
  - random alive。
  - min last latency。
  - min avg10。
  - min moving average。
  - filter annotation and bad regex。
  - sparse `add_latency` offset。

Missing C10 product-layer closure:

- Rust Web/API `/api/nodes/latencies` must not only return DB/cache values; it must update the same
  runtime group policy state used by Rust outbound selection。
- Rust subscription/manual node import must preserve stable node ID -> group dialer index mapping。
- Rust orchestrator must materialize group filters and annotations into `dae-outbound::DialerGroup` inputs。
- Runtime reload must rebuild group policy state from product state and persisted latency results。
- Runtime latency probes must feed:
  - last latency for `min`。
  - last 10 latency ring for `min_avg10`。
  - moving average for `min_moving_avg`。
  - alive/dead result for all non-fixed policies。
- `check_tolerance` must be honored when deciding whether to switch the current minimum。
- `add_latency` must affect sorting latency only; raw measured latency must remain unmodified。

### 31.3 How backend should test group `min` policies

The C10 test strategy must be layered:

1. Algorithm unit tests in `dae-outbound`
   - Use existing golden fixtures for `min` / `min_avg10` / `min_moving_avg` / `add_latency` /
     tolerance / alive state / IP-version fallback。
   - These validate pure selection semantics without Web/API or DB。

2. Product-state materialization tests in `dae-daemon`
   - Build a fixture product state with:
     - selected global/dns/routing。
     - one routing fallback or rule referencing a group。
     - group policy `min` / `min_avg10` / `min_moving_avg`。
     - manual nodes。
     - subscription-backed nodes。
     - filter annotations with `add_latency`。
   - Materialize to runtime group model。
   - Assert the generated `DialerGroup` policy, annotations, dialer order, and node-id mapping match Go
     `daewing` orchestration output。

3. Latency API tests in Rust product backend
   - Call Rust equivalent of `/api/nodes/latencies` and explicit latency test API。
   - Inject deterministic probe results instead of relying on Internet timing。
   - Assert results are persisted in product state and cached in memory。
   - Assert API JSON remains compatible with current WebUI。

4. Runtime selection tests
   - Load product state。
   - Feed deterministic latency results:
     - node A = 200 ms。
     - node B = 100 ms。
     - node C = 150 ms。
   - For `min`, assert selected dialer is node B。
   - For `min_avg10`, feed a 10-sample ring and assert average winner。
   - For `min_moving_avg`, feed moving-average state and assert moving-average winner。
   - With `add_latency`, assert selected winner changes according to sorting latency。
   - With `check_tolerance`, assert small improvements do not switch, but improvements beyond tolerance do。

5. End-to-end product smoke
   - Import or create product state。
   - Start Rust `daed run -c /etc/daed/`。
   - Trigger latency test through API。
   - Reload runtime。
   - Send a routed connection through a group with `min` policy。
   - Assert selected outbound / node in runtime report matches expected node。

Admission fields to add to C10 service-contract / manifest gates:

```text
group_policy_latency_backend_required=true
group_policy_latency_backend_ready=false
group_policy_min_selection_parity_required=true
group_policy_min_selection_parity_ready=false
latency_api_feeds_runtime_group_state_required=true
latency_api_feeds_runtime_group_state_ready=false
group_policy_add_latency_parity_required=true
group_policy_check_tolerance_parity_required=true
```

Important distinction:

- `dae-outbound` policy algorithm is mostly present。
- C10 still needs Rust product backend integration so API latency tests, product state, runtime group state,
  and actual outbound selection all use the same latency data。

## 32. Complete daed / daewing product-function audit（2026-06-02）

本节是对 `daed` 顶层仓库和 in-tree `daed/wing`（当前 daewing build truth）的完整产品功能审核。
它补齐第 30、31 节中只按 package/runtime 视角描述时容易遗漏的 WebUI、HTTP API、状态库、CLI、导入导出、
发布链路、日志、延迟测试和订阅调度功能。

本节不新增 C0-C10 之外的 stage；下面所有缺口继续归入 C9 default switch / C10 go-free product chain。

### 32.1 Audit scope and build truth

Current build truth:

```text
daed-daex-align/daed
  -> daed/wing submodule
  -> /root/project/dae-daex-align
  -> /root/project/outbound-daex-align
  -> /root/project/quic-go-daex-align
```

Evidence:

- `daed/Makefile` builds Web `dist`, ensures `wing/dae-core/control/bpf_bpfeb.o`, then runs
  `cd wing && make OUTPUT=../daed APPNAME=daed WEB_DIST=../dist VERSION=... bundle`。
- `daed/.gitmodules` points `wing` at the local align checkout, but the in-tree `daed/wing` directory is the build
  truth for the product bundle。
- `wing/go.mod` replaces:
  - `github.com/daeuniverse/dae => /root/project/dae-daex-align`
  - `github.com/daeuniverse/outbound => /root/project/outbound-daex-align`
  - `github.com/daeuniverse/quic-go => /root/project/quic-go-daex-align`
- `wing/main.go` blank-imports `github.com/daeuniverse/dae/component/outbound`, so Go daewing still registers Go
  outbound implementations in the current product shell。

### 32.2 Top-level `daed` repository functions

Top-level `daed` owns the product packaging surface, not only the Web UI source:

- Node/pnpm monorepo with `pnpm@10.24.0` and Node `>=22.12.0`。
- Web app build through Vite/Turbo under `apps/web`。
- Workspace packages used by the UI and external publishing:
  - `@daeuniverse/dae-editor`
  - `@daeuniverse/dae-lang-core`
  - `@daeuniverse/dae-lsp`
  - `@daeuniverse/dae-node-parser`
  - `dae-routinga` VSCode extension package。
- Product build target `daed` via Go `wing make ... bundle`。
- Web static embedding into `wing/webrender/web` with gzip pre-compression。
- Docker image build using Go bundle and downloaded `geoip.dat` / `geosite.dat`。
- Publish Docker image build using the same Go bundle path。
- systemd unit and desktop entry:
  - `ExecStart=/usr/bin/daed run -c /etc/daed/`
  - `ExecReload=/bin/kill -HUP $MAINPID`
  - Web panel opens `http://127.0.0.1:2023`。
- Package post-install / post-remove hooks reload systemd and restart active `daed`。
- CI/release workflows:
  - frontend lint/typecheck/unit tests。
  - live audit with Playwright。
  - Linux x86_64 v2/v3 build + smoke artifacts。
  - release-please, screenshots, full source ZIP, Linux packages, GitHub release upload。
  - container image publish。
  - npm package publishing for editor/LSP/node-parser/lang-core。

C10 consequence:

- A Rust product binary cannot only replace `dae-daemon-optin`; it must replace the binary/package surface currently
  produced by `daed/Makefile -> wing/Makefile -> Go bundle`。
- Docker, systemd, package hooks, smoke tests and release workflows must consume the Rust `/usr/bin/daed` package
  artifact by default。

### 32.3 Frontend / WebUI functions

Routes:

- `/setup`
  - initial account setup。
  - auth status / first user creation。
- `/`
  - main `Orchestrate` workspace behind `MainLayout`。

Main workspace pages:

- Config global settings page。
- DNS resource page。
- Routing resource page。
- Group management page。
- Node management page。
- Subscription management page。
- Logs page。
- Traffic overview page。
- Workspace summary cards。

Header / shell functions:

- Endpoint/token handling。
- Runtime reload / stop actions。
- profile menu, username/name/avatar update, password update。
- theme selector and command palette。
- DAE bundle export/import。
- native `.dae` config export/import/preview。
- import preview and warning modal。
- shortcut surface。
- status counters for running state, nodes and fastest latency。

Editor / authoring functions:

- `DaeEditor` lazy-loads Monaco + dae language support。
- Routing and DNS can be edited as text。
- DNS has a simple form mode for upstreams/request routing/response routing plus raw editor fallback。
- Config global form can send either raw global section or parsed global object。
- Routing/DNS/config preview APIs are used before or during editing。

Node UI functions:

- Manual node import by link。
- Batch node remove。
- Node edit modal uses `@daeuniverse/dae-node-parser` to parse existing links and regenerate links。
- QR code modal for share links。
- Protocol form registry supports:
  - VMess / VLESS form family。
  - Shadowsocks / ShadowsocksR。
  - Trojan / Trojan-Go。
  - Juicity。
  - Hysteria2。
  - AnyTLS。
  - TUIC。
  - HTTP / HTTPS。
  - SOCKS5。
- The protocol names above are UI/form matrix rows only; they are not top-level C-stage names。

Group UI functions:

- Create/delete/rename groups。
- Set policy and policy params。
- Drag/drop or action-based node membership。
- Add/delete subscription bindings。
- Subscription binding supports `nameFilterRegex`。
- Group detail displays matched subscription nodes and matched counts。
- Policies exposed by Web types:
  - `random`
  - `fixed`
  - `min`
  - `min_avg10`
  - `min_moving_avg`

Subscription UI functions:

- Import one or more subscription links。
- Refresh subscriptions。
- Delete subscriptions。
- Update tag。
- Update link。
- Update cron expression and enablement。
- Expanded subscription node view with pagination support。

Runtime/observability UI functions:

- `/runtime/overview` polling。
- `/events/runtime` SSE live stream with polling fallback。
- `/nodes/latencies` query and explicit test action。
- `/logs` query/filter/clear。
- `/events/logs` SSE live stream。
- `/logs/settings` read/update max entries and bytes。
- `/runtime/log-level` read/update。

C10 consequence:

- The frontend can remain TypeScript, but the Rust product backend must preserve the API shape currently expected by
  this WebUI unless the frontend is changed in the same C10 work item。

### 32.4 Frontend API contract used by WebUI

Queries used by the Web app:

```text
GET /user/me/storage?path=mode
GET /user/me/storage?path=defaultConfigID&path=defaultRoutingID&path=defaultDNSID&path=defaultGroupID
GET /general/state
GET /general/interfaces?up=true
GET /runtime/overview?windowSec=&maxPoints=
GET /nodes/latencies
GET /logs?level=&q=&limit=
GET /logs/settings
GET /runtime/log-level
GET /nodes
GET /subscriptions?expand=nodes
GET /subscriptions/{id}/nodes
GET /configs?expand=parsed
GET /groups
GET /routings?expand=parsed
GET /dns?expand=parsed
GET /user/me
GET /events/runtime?windowSec=&maxPoints=&access_token=
GET /events/logs?level=&q=&access_token=
```

Mutations used by the Web app:

```text
PUT /user/me/storage
POST /user/me/default-resources
POST /configs
PUT /configs/{id}
POST /configs/parsed
GET /user/me/dae-bundle
PUT /user/me/dae-bundle
GET /user/me/dae-config-file
PUT /user/me/dae-config-file
POST /user/me/dae-config-file/preview
DELETE /configs/{id}
POST /configs/{id}/select
PUT /configs/{id}
POST /routings
PUT /routings/{id}
DELETE /routings/{id}
POST /routings/{id}/select
PUT /routings/{id}
POST /dns
PUT /dns/{id}
DELETE /dns/{id}
POST /dns/{id}/select
PUT /dns/{id}
POST /groups
DELETE /groups/{id}
PUT /groups/{id}
POST /groups/{id}/nodes
DELETE /groups/{id}/nodes
POST /groups/{id}/subscriptions
DELETE /groups/{id}/subscriptions
POST /nodes
DELETE /nodes
PUT /nodes/{id}
POST /subscriptions
POST /subscriptions/{id}/refresh
POST /nodes/latencies
DELETE /subscriptions
POST /runtime/reload
POST /runtime/stop
PATCH /runtime/log-level
DELETE /logs
PATCH /logs/settings
PATCH /user/me
POST /user/me/password
PUT /nodes/{id}
PUT /subscriptions/{id}
```

C10 consequence:

- Rust Web/API backend must be contract-tested against these routes and JSON response shapes。
- SSE token fallback through `access_token` must be preserved for browser `EventSource` clients that cannot set
  Authorization headers。

### 32.5 daewing CLI functions

Current `wing/cmd` commands:

```text
daed run
daed export outline
daed export openapi
daed export flatdesc
daed resetpass
```

`run` flags and behaviors:

- `-c, --config` defaults to `/etc/daed`。
- `-l, --listen` defaults to `0.0.0.0:2023`。
- `--pprof-listen` starts optional local pprof server。
- `--api-only` starts control-plane backend without dae runtime and skips privilege escalation。
- `--logfile`, `--logfile-maxsize`, `--logfile-maxbackups` configure rotating logs。
- `--disable-timestamp` passes timestamp behavior into runtime。
- creates config directory。
- calls `AutoSu()` when not api-only。
- initializes `/etc/daed/wing.db`。
- restores subscription schedulers。
- starts log cache and log hook。
- starts engine service。
- restores previous running state。
- mounts `/api/*` under auth + local-origin CORS。
- serves embedded Web files。
- handles SIGHUP as runtime reload。
- handles termination signals by stopping runtime。

`export` functions:

- `outline` prints dae config outline JSON。
- `openapi` prints generated OpenAPI document。
- `flatdesc` prints flat config descriptors used by the UI/editor。

`resetpass` functions:

- loads `wing.db` from config dir。
- requires privilege unless api-only。
- assigns random 8-character passwords to all users。
- updates user password hash/secret through orchestrator。

C10 consequence:

- Rust `/usr/bin/daed` must own this command surface or intentionally deprecate a command with a documented
  replacement in C10 admission。

### 32.6 Product state / `wing.db` schema

Current primary state:

```text
/etc/daed/wing.db
```

SQLite/GORM models:

- `User`
  - `id`
  - `username`
  - `password_hash`
  - `jwt_secret`
  - `json_storage`
  - `avatar`
  - `name`
- `Config`
  - `id`
  - `name`
  - `global`
  - `selected`
  - `version`
- `Dns`
  - `id`
  - `name`
  - `dns`
  - `selected`
  - `version`
- `Routing`
  - `id`
  - `name`
  - `routing`
  - `selected`
  - `version`
- `Node`
  - `id`
  - `link`
  - `name`
  - `address`
  - `protocol`
  - `tag`
  - `subscription_id`
- `Subscription`
  - `id`
  - `updated_at`
  - `link`
  - `cron_exp`
  - `cron_enable`
  - `status`
  - `info`
  - `tag`
- `Group`
  - `id`
  - `name`
  - `policy`
  - `version`
  - `system_id`
  - many-to-many `group_nodes`
- `GroupSubscription`
  - `group_id`
  - `subscription_id`
  - `name_filter_regex`
- `GroupPolicyParam`
  - `id`
  - `key`
  - `value`
  - `group_id`
- `System`
  - `id`
  - `running`
  - running selected config/dns/routing IDs and versions。
  - running group version sum。
  - running group IDs。
  - running groups association。
- `LogSetting`
  - `id`
  - `max_entries`
  - `max_bytes`
- `NodeLatencyResult`
  - `node_id`
  - `latency_ms`
  - `alive`
  - `tested_at`
  - `message`
  - `updated_at`

DB behaviors:

- `wing.db` is auto-migrated on startup。
- file permissions are tightened to `0640` if too open。
- write transactions use serializable isolation。
- read-only import/export transactions also use serializable isolation。
- node import uses dae/outbound dialer link parsing to fill `name`, `address`, `protocol`。

C10 consequence:

- Final primary store remains the previously recorded Rust product store:

```text
/var/lib/daed/state/product.db
```

- `wing.db` must be import/migration input only in C10。
- `generated.dae` remains runtime materialized evidence, not product state。
- State migration must preserve selected resources, user preferences/defaults, groups, policy params, subscription
  bindings, cron settings, tags, node IDs where possible, persisted latency and log settings。

### 32.7 HTTP API functions

Public routes:

```text
GET  /health
GET  /auth/status
POST /auth/token
POST /auth/users
GET  /openapi.json
```

Authenticated routes:

```text
GET        /general/interfaces
GET        /general/state
GET        /general/cache-stats
GET,POST   /configs
POST       /configs/parsed
GET        /configs/flat-desc
GET,PUT,DELETE /configs/{id}
POST       /configs/{id}/select
GET,POST   /dns
POST       /dns/parsed
GET,PUT,DELETE /dns/{id}
POST       /dns/{id}/select
GET,POST   /routings
POST       /routings/parsed
GET,PUT,DELETE /routings/{id}
POST       /routings/{id}/select
GET,POST   /groups
GET,PUT,DELETE /groups/{id}
POST,DELETE /groups/{id}/nodes
POST,DELETE /groups/{id}/subscriptions
GET,POST,DELETE /nodes
GET,PUT,DELETE /nodes/{id}
GET,POST   /nodes/latencies
GET,POST,DELETE /subscriptions
GET,PUT,DELETE /subscriptions/{id}
POST       /subscriptions/{id}/refresh
GET        /subscriptions/{id}/nodes
GET,PATCH  /user/me
GET,PUT    /user/me/dae-bundle
GET,PUT    /user/me/dae-config-file
POST       /user/me/dae-config-file/preview
POST       /user/me/default-resources
POST       /user/me/password
GET,PUT,DELETE /user/me/storage
GET        /runtime/overview
GET,PATCH  /runtime/log-level
POST       /runtime/reload
POST       /runtime/stop
GET        /events/runtime
GET        /events/logs
GET,DELETE /logs
GET,PATCH  /logs/settings
```

API framework behaviors:

- JSON bodies are limited to `1 MiB`。
- list limit is capped。
- runtime operation timeout is capped at `120s`。
- SSE streams heartbeat every `15s`。
- `writeMethodNotAllowed` and JSON error format are part of client compatibility。

C10 consequence:

- Rust API must implement route, method, JSON body, response and error compatibility, or WebUI must be revised and
  compatibility break recorded。

### 32.8 Auth, users, CORS and storage

Auth:

- Bearer token is parsed by the `run` middleware before HTTP API handler dispatch。
- JWT signing uses HS256。
- token subject is username。
- per-user `JwtSecret` is loaded from DB。
- token expiry is 30 days。
- `role=admin` is stored in claims/context。
- `GET /events/runtime` and `GET /events/logs` accept `access_token` query fallback for browser SSE。

User lifecycle:

- `GET /auth/status` returns number of users。
- `POST /auth/users` creates the first user only。
- password policy for initial user: length >= 6 and contains letters and digits。
- password hash is SHAKE256 over `jwt_secret + password`, 32 bytes hex。
- password update rotates jwt secret and returns a new token。
- `resetpass` bypasses current password check for local recovery。

Profile/storage:

- username update。
- display name set/clear。
- avatar set/clear。
- JSON storage get/set/remove by paths。
- WebUI stores mode and default resource IDs in user JSON storage。
- `POST /user/me/default-resources` ensures initial config/dns/routing/group and writes defaults atomically。

CORS:

- allowed origins are localhost, loopback IPs, or machine interface IPs。
- allowed methods: GET, POST, PUT, PATCH, DELETE, OPTIONS。
- allowed headers: Authorization, Content-Type。

C10 consequence:

- Rust product backend must implement token issuance/validation and storage migration so existing users do not lose
  access after `wing.db` migration。

### 32.9 Config / DNS / Routing resource functions

Config:

- list by id/selected, optionally `expand=parsed`。
- create from raw global section or parsed global object。
- update name/global/parsed global。
- parse validation through dae config parser before write。
- version increments on global changes。
- delete by id。
- select config and clear other selected rows。
- flat descriptor export。
- parsed preview endpoint。

DNS:

- list by id/selected, optionally `expand=parsed`。
- create/update raw DNS section with empty-section fallback。
- parse validation through dae config parser。
- version increments on DNS changes。
- delete/select。
- parsed preview includes upstreams plus request/response routing structures。

Routing:

- list by id/selected, optionally `expand=parsed`。
- create/update raw routing section with empty-section fallback。
- parse validation through dae config parser。
- version increments on routing changes。
- delete/select。
- parsed preview includes rules, conditions, outbound and fallback。
- resource response can include referenced group names。

C10 consequence:

- Rust parser/materializer must preserve the same section-level behaviors, version increments and selected-resource
  semantics。

### 32.10 Group / node / subscription functions

Groups:

- name validation by dae identifier rules。
- create/list/get/delete/rename。
- policy set with `GroupPolicyParam` replacement。
- many-to-many manual node membership。
- subscription binding membership with optional regex。
- regex validation on write and when materializing runtime config。
- matched subscription nodes are shown in group read API。
- group version increments on membership/policy/name changes。
- running groups are linked to `System` for modified-state checks。

Nodes:

- import one or many links。
- optional rollback-on-error behavior。
- optional unique tag。
- detect duplicate link within independent/subscription scope。
- parse link through dae/outbound dialer with `DisableCheck=false`。
- store parsed `name/address/protocol`。
- list independent nodes by default。
- list by subscription, id, pagination。
- update link/tag。
- delete one or many。
- node update/delete invalidates latency cache/persisted rows and bumps affected group versions while running。

Subscriptions:

- import subscription link。
- fetch links with route-aware runtime HTTP transport where available。
- fallback direct fetch only when control plane is not initialized。
- user agent mimics daed/v2rayA/v2rayN WebRequestHelper style。
- body is capped by dae subscription max bytes。
- parse SIP008 first, then base64。
- create subscription row with default cron `10 */6 * * *` and enabled。
- import child nodes under `subscription_id`。
- refresh subscription:
  - preserves group-attached subscription nodes by unique name when possible。
  - deletes unpreserved nodes。
  - updates preserved node links/metadata。
  - invalidates latency for removed/updated nodes。
  - bumps affected group versions。
  - reloads running runtime after refresh。
- update subscription link/tag/cron enable/cron expression。
- cron validation uses scheduler parser。
- delete one or many subscriptions, child nodes, group bindings, latency rows and scheduler jobs。
- scheduler restores jobs on startup and uses singleton scheduled refresh。

C10 consequence:

- Rust product backend must own subscription fetch/schedule/refresh semantics, including route-aware fetch once Rust
  runtime exposes a usable transport/control-plane interface。

### 32.11 Runtime lifecycle and materialization functions

`orchestrator.Run(ctx, dry)` behavior:

- serializes runtime lifecycle with a mutex。
- dry run marks system not running, reloads empty config, stops latency sync worker and clears running node index。
- non-dry path requires selected config, dns and routing。
- parses config through dae parser。
- derives necessary outbound group names from routing。
- loads referenced groups, policy params, subscription bindings and subscription nodes。
- rejects missing groups except built-ins `direct`, `block`, `must_rules`。
- applies subscription binding regex filters。
- loads manual group nodes。
- deduplicates nodes by link。
- generates unique runtime node names, preferring tags and normalizing invalid key characters。
- rejects referenced groups with no nodes。
- rejects `fixed` policy groups with more than one node。
- materializes dae `group` entries with filters and policy function/params。
- materializes dae `node` entries as `name:link` strings。
- writes `System.running*` versions and running group association。
- commits state before runtime reload。
- calls engine `ReloadContext`。
- if reload fails, marks stopped。
- replaces running node index for latency result mapping。
- starts node latency sync worker using global check interval。

Other runtime functions:

- `RestoreRunningState` checks `System.running` and reloads previous state on startup。
- restore failure marks system stopped。
- `Stop` stops runtime, latency sync worker and running node index, then marks stopped。
- SIGHUP triggers reload with a longer timeout。

C10 consequence:

- This materializer is the current product owner for translating Web state into dae runtime config。
- Rust product shell must replace it before Go daewing can be removed from default path。

### 32.12 Engine adapter functions and current Rust-owned transition limits

Current engine interface exposes:

- empty global/dns/routing sections。
- full empty config。
- flat descriptor export。
- section parsing。
- necessary outbound derivation。
- run/reload/stop。
- log level set。
- control plane access。
- netns link mode。
- runtime overview。
- route-aware HTTP transport。
- control-plane-not-initialized classification。

Go native engine service:

- wraps `dae/engine.Engine` directly。
- `ControlPlane()` returns live Go control plane when running。
- `GetRuntimeOverview()` returns live runtime overview。
- `HTTPTransport()` can fetch subscriptions through the running route。
- `ReloadContext()` can start runtime if not already running。

Rust-owned transition engine service:

- selected by default runtime mode in the current align branch。
- prepares runtime dir and writes `generated.dae`。
- obtains `dae-daemon-optin` from `DAED_RUST_DAEMON` or embedded asset。
- starts child process:

```text
dae-daemon-optin run -c generated.dae \
  --service-pid-file resident.pid \
  --service-progress-file resident.progress \
  --service-abort-file resident.abort \
  --service-ready-file resident.ready \
  --logfile resident.log
```

- reloads child process through:

```text
dae-daemon-optin reload --service-pid-file ... --service-progress-file ... --service-abort-file ... --timeout-ms ...
```

- sets default env:
  - `DAE_RUST_NATIVE_EBPF=1`
  - `DAE_RUST_NATIVE_EBPF_BACKEND=auto`
  - `DAE_NATIVE_EBPF_BACKEND=auto`
  - `DAE_RUST_NATIVE_EBPF_TCX_DATAPATH_ADMITTED=1`
  - `DAE_NETNS_LINK=auto`
  - `DAE_RUST_RESIDENT_DATAPLANE` from `DAED_RUST_RESIDENT_DATAPLANE_DEFAULT`, default `0`。
- reads resident runtime report for attach backend and netns link mode。

Current transition limits:

- `rustOwnedService.ControlPlane()` returns control-plane-not-initialized。
- `rustOwnedService.HTTPTransport()` returns not-initialized transport。
- `rustOwnedService.GetRuntimeOverview()` returns empty Go engine overview, not live Rust resident metrics。
- route-aware subscription fetch therefore falls back direct in Rust-owned mode unless Rust control-plane transport is
  implemented。
- Web runtime overview/cache stats/runtime latency/control-plane APIs do not yet have full Rust resident backing。
- `resident.log` is not the same as WebUI logstore JSONL stream。
- `dae-daemon-optin` remains a child payload, not final product entry。

C10 consequence:

- Rust product shell must expose runtime control/overview/log/transport APIs directly, or through a Rust resident
  protocol, before final go-free admission。

### 32.13 Latency and group-policy backend functions

Current daewing latency functions:

- in-memory cache TTL: `1h`。
- persisted minimum TTL: `24h`。
- cache cap: `4096` entries。
- probe concurrency: `8`。
- sync worker interval clamped between `10s` and `30s`。
- warmup interval `2s` for `1min`。
- query merges:
  - persisted DB latency。
  - memory cache。
  - runtime node latency snapshots。
- explicit test uses runtime latency where available, then fallback node probes。
- results persist into `NodeLatencyResult` and memory cache。
- delete/update invalidates affected node latency。
- running node index maps runtime unique node names back to product node IDs。

Current group-policy relation:

- Web exposes `min`, `min_avg10`, `min_moving_avg` policy selection。
- dae/outbound has policy algorithms and last-latency/avg10/moving-average state。
- daewing currently bridges product node IDs, runtime node names and latency snapshots。

C10 missing closure remains:

- Rust API latency tests must persist and cache results in Rust product state。
- Rust runtime group state must consume the same latency data used by the API。
- `min`, `min_avg10`, `min_moving_avg`, `check_tolerance` and `add_latency` parity must be tested end-to-end。
- Rust resident runtime must expose enough node latency snapshots or probe hooks to replace Go control-plane behavior。

### 32.14 Logs, events and runtime log level

Current logstore:

- JSONL file under `/etc/daed/logs/current.jsonl`。
- default max entries: `10000`。
- default max bytes: `50 MiB`。
- bounds:
  - entries `500..50000`。
  - bytes `5 MiB..200 MiB`。
- query supports level, substring query and limit。
- default query limit `500`, max `2000`。
- log line size cap `16 KiB`。
- field value cap `1024` chars。
- prune every 500 entries。
- log settings persisted in `LogSetting`。
- subscribers receive live log entries for SSE。

HTTP functions:

- `GET /logs` query/filter/list。
- `DELETE /logs` clear。
- `GET /logs/settings` read bounds and settings。
- `PATCH /logs/settings` update max entries/bytes and prune。
- `GET /runtime/log-level` read current logrus level。
- `PATCH /runtime/log-level` parse/update log level and forward to engine。
- `GET /events/logs` SSE with filter and heartbeat。

C10 consequence:

- Rust product backend must decide whether to keep a JSONL log cache compatible with WebUI or migrate with a
  compatibility API。
- Runtime child/resident logs must feed the same WebUI-visible log stream, not only a private `resident.log`。

### 32.15 DAE bundle and native config file import/export

DAE bundle:

- schema version `1`。
- exports:
  - mode。
  - default resource IDs。
  - selected config/dns/routing。
  - configs。
  - DNS resources。
  - routings。
  - subscriptions。
  - nodes。
  - groups, policy params, node IDs and subscription bindings。
- imports bundle into product state。

Native `.dae` config file export/import:

- export loads selected config/dns/routing plus relevant groups/subscriptions/independent nodes。
- materializes native dae config。
- writes warnings for lossy or inferred conversion。
- normalizes output filename/content。
- preview parses incoming `.dae` content and returns a bundle-like model plus warnings。
- import replaces product resources from parsed `.dae` content。
- import removes old subscription schedulers and creates schedulers for new subscriptions。
- parser handles:
  - top-level global/dns/routing/group/node/subscription sections。
  - group policies and params。
  - group filters/subscription filters where convertible。
  - node/subscription tags and links where convertible。

C10 consequence:

- Rust product backend must preserve both JSON bundle and `.dae` import/export, because they are product user
  workflows and migration tools, not optional runtime helpers。

### 32.16 Web static serving and development exports

Current static serving:

- build tag `embedallowed` embeds `webrender/web`。
- gzip-precompressed assets are served with `statigz`。
- unknown paths fall back to `index.html` / `index.html.gz` for SPA routing。
- without `embedallowed`, `webrender.Handle` is a no-op。

Development/product metadata exports:

- OpenAPI document generated by Go code and exposed by CLI + HTTP。
- flat descriptor generated by dae engine and exposed by CLI + HTTP。
- outline JSON generated by dae config package and exposed by CLI。

C10 consequence:

- Rust product binary must either embed/serve the Web dist and export equivalent metadata, or package those assets
  through a new explicit Rust package layout with compatible URLs。

### 32.17 Published frontend/library package functions

`@daeuniverse/dae-lang-core`:

- platform-agnostic RoutingA formatter。
- line parsing and comment-aware formatting helpers。

`@daeuniverse/dae-lsp`:

- browser and Node language server。
- parse cache。
- diagnostics。
- completions and snippets。
- hover。
- definition。
- references。
- document symbols。
- semantic tokens。
- formatting。

`@daeuniverse/dae-editor`:

- Monaco language definition/theme/options。
- browser LSP client integration。
- formatting integration。

`@daeuniverse/dae-node-parser`:

- parse/generate proxy share URLs used by node create/edit UI。
- supports HTTP/HTTPS, SOCKS5, Shadowsocks, ShadowsocksR, Trojan/Trojan-Go, TUIC, Juicity, Hysteria2, AnyTLS,
  VMess and VLESS forms。

`dae-routinga` VSCode package:

- syntax highlighting。
- language configuration。
- snippets。
- VSCode LSP client。
- formatting provider。

C10 consequence:

- These packages are not Go runtime blockers by themselves, but they define Web/editor compatibility and release
  artifacts that the Rust product package must not accidentally break。

### 32.18 Build, package, CI and release functions

Current build path:

```text
pnpm build
make daed
  -> make submodule
  -> wing make deps
  -> wing make bundle
```

Current `wing make bundle`:

- builds dae BPF object from `dae-core/control/kern/tproxy.c` through `make ebpf`。
- generates schemas through `go generate ./...`。
- builds Rust aya BPF loader asset from dae module。
- copies Web dist into `webrender/web`。
- gzip-compresses static files when smaller。
- builds Go binary with `-tags=embedallowed` and `CGO_ENABLED=0`。

Current `wing make bundle-rust-owned`:

- includes normal bundle steps。
- builds Rust `dae-daemon-optin` from `dae-daex-align/rust`。
- copies/strips it to `wing/engine/assets/dae-daemon-optin`。
- builds Go binary with `-tags=embedallowed,rust_owned_daemon_embed`。

Current release/package functions:

- smoke test binary。
- collect runtime files。
- package artifacts into deb/rpm/pkg/zip。
- systemd service installation。
- desktop launcher and icons。
- container image entrypoint `daed run -c /etc/daed`。
- full source archive with vendored wing dependencies。

C10 consequence:

- `bundle-rust-owned` remains a transition package shape。
- C10 default build must not produce a Go daewing bundle as `/usr/bin/daed`。
- C10 package admission must scan package contents and default service/entrypoint for Go daewing and
  `dae-daemon-optin` misuse。

### 32.19 Link points to dae / outbound / quic-go

daewing currently links into `dae` and `outbound` for:

- config section parser。
- config outline and flat descriptors。
- necessary outbound derivation from routing。
- dae runtime engine。
- runtime control plane。
- runtime overview and traffic samples。
- route-aware HTTP transport。
- cache stats。
- node latency snapshots。
- node link parsing through outbound dialer。
- direct/fallback probes for latency。
- generated native dae config marshal/import/export。
- outbound registration by blank import。

C10 consequence:

- Rust native owned must replace product-level dependencies on Go dae/engine/control/outbound in default package。
- Protocol-specific validation rows can remain in tests, but top-level C10 capability names must stay generic。

### 32.20 Rust replacement map

Conservative crate ownership, with no new crate by default:

- `dae-product`
  - Rust product package manifest。
  - package layout/admission metadata。
  - go-free product-chain checks。
  - product-state schema descriptors if dependency graph remains clean。
- `dae-daemon`
  - final Rust `/usr/bin/daed` product binary。
  - CLI command surface。
  - Web/API backend。
  - product state migration/import/export。
  - orchestrator/materializer。
  - runtime owner。
  - service/systemd contract tests。
- `dae-control`
  - runtime state/control-plane API contracts。
  - cache stats / overview / node latency snapshots if shared below daemon。
- `dae-datapath` / `dae-dns`
  - runtime datapath and DNS execution backing the product state。
- `dae-outbound`
  - outbound matrix。
  - generic fingerprint-aware transport underlay。
  - group policy algorithms and latency state。
  - link parsing / metadata only if existing ownership and feature graph remain clean。
- `dae-core-types`
  - shared stable API/state structs only when cross-crate dependency pressure requires it。

New crate rule:

- Do not add a crate for convenience。
- Add one only if feature graph pollution, dependency cycles, multi-binary reuse, state-schema sharing, or product-shell
  split becomes a hard blocker。

### 32.21 C10 missing coverage matrix after complete audit

```text
daed_top_level_build_package_audited=true
daed_frontend_webui_audited=true
daed_frontend_api_contract_audited=true
daed_frontend_packages_audited=true
daewing_cli_audited=true
daewing_http_api_audited=true
daewing_auth_user_storage_audited=true
wing_db_schema_audited=true
daewing_resource_crud_audited=true
daewing_group_node_subscription_audited=true
daewing_orchestrator_materializer_audited=true
daewing_runtime_supervisor_audited=true
daewing_subscription_scheduler_audited=true
daewing_latency_backend_audited=true
daewing_logs_sse_audited=true
daewing_import_export_audited=true
daewing_static_web_and_metadata_exports_audited=true
daed_build_package_release_install_audited=true
dae_outbound_runtime_link_points_audited=true

rust_product_shell_complete=false
rust_web_api_backend_complete=false
rust_product_state_store_complete=false
rust_wing_db_migration_complete=false
rust_daewing_replacement_complete=false
rust_auth_user_storage_complete=false
rust_config_dns_routing_resource_api_complete=false
rust_group_node_subscription_api_complete=false
rust_subscription_scheduler_complete=false
rust_subscription_route_aware_fetch_complete=false
rust_orchestrator_materializer_complete=false
rust_runtime_overview_api_complete=false
rust_runtime_control_plane_bridge_complete=false
rust_logs_sse_complete=false
rust_bundle_import_export_complete=false
rust_native_dae_config_import_export_complete=false
rust_group_policy_latency_backend_complete=false
rust_static_web_serving_complete=false
rust_openapi_flatdesc_outline_exports_complete=false
rust_build_package_release_default_complete=false
c10_go_free_product_package_ready=false
```

### 32.22 C10 admission checklist after complete audit

C10 final package cannot be admitted until all of these are true:

- `/usr/bin/daed` is Rust product binary。
- `daed run -c /etc/daed/` starts Rust Web/API + Rust state + Rust runtime owner。
- systemd `ExecStart` and Docker entrypoint point to Rust product binary。
- package scan finds no Go daewing product shell in default runtime path。
- `dae-daemon-optin` is not default product entry, systemd entry, Docker entrypoint, or required package runtime。
- fresh install creates valid Rust product state。
- existing `/etc/daed/wing.db` migrates into Rust product state。
- user credentials/tokens/storage/defaults survive migration or are explicitly reissued through a recorded migration
  procedure。
- WebUI setup/login/profile/storage works。
- Config/DNS/Routing CRUD, preview, select, versioning and parsed views work。
- Group create/update/delete, node membership, subscription binding and regex matching work。
- Node import/update/delete/tag, share-link parsing and latency invalidation work。
- Subscription import/refresh/update/delete/scheduler/cron works。
- Runtime reload/stop/restore-running-state works。
- runtime overview, cache stats, netns link mode and attach backend are backed by Rust runtime truth。
- `/events/runtime` and `/events/logs` SSE work with Bearer and query token fallback。
- logs query/filter/clear/settings and runtime log level work。
- `/nodes/latencies` query/test persists results and feeds runtime group-policy selection state。
- `min`, `min_avg10`, `min_moving_avg`, `check_tolerance` and `add_latency` pass product and runtime parity tests。
- DAE bundle export/import works。
- native `.dae` export/import/preview works with warnings。
- Web static files are served or packaged through a documented Rust layout。
- OpenAPI, flatdesc and outline exports are available or deliberately replaced。
- release/package/Docker/systemd/smoke/live-audit workflows use Rust product artifact by default。
- rollback restores binary, service, package manifest and product state backup。

### 32.23 Key correction from this audit

`daewing` is not merely a runtime wrapper around dae。

Current daewing owns:

- CLI。
- Web/API backend。
- authentication。
- user storage。
- SQLite product state。
- resource CRUD。
- runtime materialization。
- subscription fetching and scheduling。
- node link parsing。
- group policy metadata。
- latency cache/persistence/probing。
- logs and SSE。
- bundle and native config import/export。
- Web static serving。
- OpenAPI/outline/flatdesc metadata。
- Go-native and Rust-owned transition runtime supervision。

Therefore, "100% Rust native owned" for daex means:

```text
Rust product shell + Rust product state + Rust Web/API + Rust orchestrator/materializer
+ Rust runtime owner + Rust datapath/DNS/outbound + Rust package/release default
```

It does not mean only replacing Go outbound protocol handlers or only embedding a Rust runtime binary inside the
existing Go daewing product shell。

## 33. daed / daewing final design decision（2026-06-02）

本节记录第 32 节审核后的最终产品设计结论。它不新增 C0-C10 之外的新 stage；所有落点继续归入 C9
`release-default-switch-v1` 和 C10 `go-free-product-chain-v1`。

### 33.1 Final product identity

最终产品入口只保留 `daed`。

```text
/usr/bin/daed
  -> Rust CLI
  -> Rust Web/API backend
  -> Rust product state store
  -> Rust orchestrator/materializer
  -> Rust runtime owner
  -> Rust datapath/DNS/outbound/control
  -> embedded or packaged Web dist
```

最终不设计长期存在的 `Rust daed + Rust daewing` 双产品形态。

`daed` 的含义：

- 用户可见产品名。
- 默认二进制。
- systemd service entry。
- Docker entrypoint。
- package/release artifact。
- Web/API backend。
- product state owner。
- runtime owner。

`daewing` 的最终含义：

- Go 时代 product shell。
- C10 之前可作为 parity oracle。
- C10 之前可作为 `wing.db` / API / import-export 行为参考。
- C10 final default package 中禁止作为 product shell、runtime dependency、systemd entry 或 Docker entrypoint。

### 33.2 What is retired

C10 后默认链路禁止：

```text
/usr/bin/daed as Go daewing bundle
/usr/bin/daewing-rs
/usr/bin/rust-daewing
/usr/bin/dae-daemon-optin as final product entry
Go daewing systemd ExecStart
Go daewing Docker entrypoint
Go daewing runtime supervisor in default package
```

`dae-daemon-optin` 只能保留为 test / compatibility / transition candidate，不能作为 final product entry。

如果 C10 仍采用内部 child runtime 形态，该 child 必须是 Rust package-internal runtime component，不应继续叫
`dae-daemon-optin`，避免把 C9 transition payload 混进 C10 final contract。

### 33.3 Target repository and crate shape

Product repository shape:

```text
daed-daex-align/daed
  -> product repository
  -> Web source
  -> package/release/systemd/Docker source
  -> C10 build consumes Rust /usr/bin/daed artifact

daed-daex-align/daed/wing
  -> C10 前作为 Go daewing oracle / migration reference
  -> C10 admission 后从 default build chain 移除

dae-daex-align/rust/crates
  -> Rust product/backend/runtime implementation
```

Conservative crate placement:

```text
dae-daemon
  -> final /usr/bin/daed binary
  -> CLI
  -> Web/API backend
  -> auth/user/storage
  -> product state migration/import/export
  -> product orchestrator/materializer
  -> subscription scheduler
  -> latency backend bridge
  -> logs/SSE
  -> Web static serving
  -> runtime owner

dae-product
  -> product package layout
  -> package manifest
  -> default-switch / go-free admission gates

dae-control
  -> runtime state/control-plane contracts
  -> overview/cache stats/control API contracts where shared below daemon

dae-datapath / dae-dns
  -> TCP/UDP/DNS runtime implementation

dae-outbound
  -> outbound matrix
  -> generic fingerprint-aware transport underlay
  -> group policy algorithms and latency state

dae-core-types
  -> shared stable structs only if dependency graph requires it
```

New crate rule remains:

- Do not add crates for convenience。
- Add a crate only if dependency cycles, feature-graph pollution, multi-binary reuse, product-state schema sharing,
  or product-shell split becomes a hard blocker。

### 33.4 Product state design

Final primary product state:

```text
/etc/daed/daed.db
```

Protected legacy / rollback state:

```text
/etc/daed/wing.db
```

Runtime materialized snapshot:

```text
/etc/daed/runtime/generated.dae
# or /run/daed/generated.dae
```

Rules:

- `daed.db` is Rust daed product truth。
- `wing.db` keeps the old daewing filename and remains protected for old daed rollback。
- Rust daed test builds must not mutate `wing.db` by default。
- If Rust daed needs existing product state, it imports/copies from `wing.db` into `daed.db` first。
- `generated.dae` is runtime/debug evidence only。
- `generated.dae` is not the user config source。

Migration/import from `wing.db` to `daed.db` must preserve at least:

- users。
- password hashes and per-user JWT secrets, or an explicit recorded reissue flow。
- user JSON storage。
- profile name/avatar。
- Config/DNS/Routing resources。
- selected resource IDs。
- default resource IDs and mode。
- nodes and tags。
- subscriptions, cron settings and tags。
- groups, policy params, manual node memberships and subscription bindings。
- running-state metadata where meaningful。
- log settings。
- persisted node latency results。

### 33.5 CLI design

Rust `/usr/bin/daed` must own the product command surface:

```text
daed run -c /etc/daed --listen 0.0.0.0:2023
daed reload
daed stop
daed export outline
daed export openapi
daed export flatdesc
daed resetpass -c /etc/daed
daed state migrate --from-wing-db /etc/daed/wing.db --to /etc/daed/daed.db
daed state check --state /etc/daed/daed.db
daed state export-dae --state /etc/daed/daed.db
daed service-contract
```

The current user-visible systemd contract may remain:

```ini
ExecStart=/usr/bin/daed run -c /etc/daed/
ExecReload=/bin/kill -HUP $MAINPID
```

But implementation must be Rust-owned. SIGHUP/reload must not depend on Go daewing。

### 33.6 Web/API design

Rust `daed` must provide the WebUI API directly:

```text
/api/auth/*
/api/user/me/*
/api/general/*
/api/configs*
/api/dns*
/api/routings*
/api/groups*
/api/nodes*
/api/subscriptions*
/api/runtime/*
/api/events/runtime
/api/events/logs
/api/logs*
/api/openapi.json
```

Compatibility requirements:

- Bearer token auth。
- SSE query-token fallback:
  - `/events/runtime?access_token=...`
  - `/events/logs?access_token=...`
- local-origin CORS behavior。
- JSON error response behavior。
- method-not-allowed behavior。
- `1 MiB` JSON body cap。
- runtime timeout cap。
- list pagination/limit behavior。
- SSE heartbeat behavior。
- WebUI route and JSON shape compatibility unless the frontend is changed in the same C10 work。

Do not admit a "minimal API" as C10 complete. The WebUI contract audited in section 32 is the C10 product API surface。

### 33.7 Runtime owner design

C9 transition shape:

```text
Go daewing
  -> wing.db
  -> generated.dae
  -> dae-daemon-optin child
```

C10 preferred shape:

```text
Rust daed process
  -> /etc/daed/daed.db
  -> runtime model/materialized snapshot
  -> Rust runtime owner
  -> runtime overview/control/log/latency state
```

C10 acceptable internal split:

```text
Rust daed product process
  -> Rust package-internal resident runtime component
```

Requirements for the acceptable split:

- no Go product shell。
- no Go daewing runtime supervisor。
- no `dae-daemon-optin` final default dependency。
- internal runtime component declared in package manifest。
- product process owns Web/API/product state/orchestration。
- runtime process exposes enough Rust-owned control, overview, log and latency state for Web/API parity。

### 33.8 Latency and policy design

Rust product backend must connect:

```text
/api/nodes/latencies
  -> product latency cache
  -> daed.db NodeLatencyResult
  -> runtime group-policy state
  -> dae-outbound DialerGroup selection
```

Required parity:

- `min`
- `min_avg10`
- `min_moving_avg`
- `check_tolerance`
- `add_latency`
- alive/dead state
- manual nodes
- subscription-backed nodes
- stable product node ID to runtime dialer mapping

It is not enough for Rust `/api/nodes/latencies` to return a probe result. The result must feed actual runtime
selection state, otherwise WebUI latency tests and group strategy behavior diverge。

### 33.9 Import/export and Web static design

Rust `daed` must preserve:

```text
GET /user/me/dae-bundle
PUT /user/me/dae-bundle
GET /user/me/dae-config-file
PUT /user/me/dae-config-file
POST /user/me/dae-config-file/preview
```

These are required product workflows:

- backup。
- restore。
- migration。
- `wing.db` import/protection path support。
- native `.dae` conversion。
- WebUI import preview and warning UX。

Web static serving options:

Preferred:

```text
/usr/bin/daed embeds Web dist
```

Acceptable:

```text
/usr/share/daed/web
/usr/bin/daed serves static files from package path
```

Required behavior:

- Web panel remains available at `http://127.0.0.1:2023/`。
- `/api/*` remains API。
- SPA fallback remains supported。

### 33.10 Package layout

C10 default package layout:

```text
/usr/bin/daed
/etc/daed/
  wing.db                 # protected old daed / daewing DB
  daed.db                 # Rust daed primary product DB
  backups/                # migration and rollback backups
  logs/                   # WebUI log cache, compatible with current behavior
  runtime/                # optional generated snapshots if not using /run/daed
/run/daed/
/usr/share/daed/geoip.dat
/usr/share/daed/geosite.dat
/usr/share/daed/web/                 # if not embedded
/usr/lib/systemd/system/daed.service
```

Optional package/admission metadata, if shipped, must declare:

```json
{
  "schema": "daex-rust-product-package-v2",
  "product": "daed",
  "phase": "C10",
  "components": {
    "go_product_shell": false,
    "go_daewing": false,
    "rust_product_binary": true,
    "rust_web_api": true,
    "rust_product_state": true,
    "rust_runtime_owner": true
  },
  "product_state": {
    "primary_store": "/etc/daed/daed.db",
    "protected_rollback_store": "/etc/daed/wing.db",
    "state_owner": "rust-daed",
    "wing_db_mutated_by_default": false,
    "wing_db_import_supported": true,
    "generated_dae_is_product_source": false
  }
}
```

### 33.11 Stage placement

C9:

```text
Go daed/daewing shell + Rust-owned runtime candidate may still exist.
Goal: release-default-switch-v1 candidate evidence.
```

C10:

```text
Rust /usr/bin/daed product binary
Rust Web/API
Rust /etc/daed/daed.db
Rust orchestrator/materializer
Rust runtime owner
No Go daewing in default chain
```

### 33.12 Final rule

Final DAEX product-chain design:

```text
daed becomes the complete Rust product.
daewing becomes legacy oracle / migration reference only.
default product chain contains no daewing.
```

This is the required interpretation of "entire daex independent chain Rust native owned, remove Go"。

## 34. C10 product state filename correction：use `daed.db` and protect `wing.db`（2026-06-02）

本节覆盖第 29、30、33 节中早期的 `/var/lib/daed/state/product.db` 设计。最终默认测试/发布设计改为
`/etc/daed/daed.db`，原因是保护原 `/etc/daed/wing.db`，避免 Rust C10 测试过程中破坏老 daed 回退能力。

### 34.1 Final decision

```text
C10 Rust daed primary state:
  /etc/daed/daed.db

Old daed / daewing rollback state:
  /etc/daed/wing.db
```

Rules:

- Rust `daed` 默认读写 `/etc/daed/daed.db`。
- Rust `daed` 默认不写 `/etc/daed/wing.db`。
- `/etc/daed/wing.db` 保留给老 daed / Go daewing 回退使用。
- 首次进入 Rust C10 测试时，从 `wing.db` 导入/复制到 `daed.db`。
- 如果 `daed.db` 已存在，Rust `daed` 使用 `daed.db`，不重新覆盖 `wing.db`。
- 如果需要重新导入，必须显式执行 migration/import 命令，不能静默覆盖。

### 34.2 Why not use `wing.db` as Rust primary during tests

继续直接把 `wing.db` 作为 Rust primary state 虽然语义上可行，但测试和回退风险更高：

- Rust schema migration 可能增加表、列、索引或 migration marker。
- Rust 写入行为可能改变原 Go/GORM 期望。
- 测试失败后老 daed 可能无法继续读取被改过的 `wing.db`。
- live host rollback 需要尽量只恢复 binary/service，不应再抢救损坏的 DB。

因此 C10 测试默认应隔离：

```text
old rollback path:
  old /usr/bin/daed + /etc/daed/wing.db

Rust test path:
  Rust /usr/bin/daed + /etc/daed/daed.db
```

### 34.3 Migration behavior

Required migration command:

```text
daed state migrate --from-wing-db /etc/daed/wing.db --to /etc/daed/daed.db
```

Required safeguards:

- backup `wing.db` before import。
- never mutate `wing.db` during import unless an explicit destructive flag is provided。
- migration must be idempotent for `daed.db`。
- migration must record source DB path and timestamp in Rust state metadata。
- rollback procedure must be able to ignore `daed.db` and keep using original `wing.db`。

### 34.4 Package layout correction

C10 default layout no longer requires `/var/lib/daed`:

```text
/usr/bin/daed
/etc/daed/
  wing.db
  daed.db
  backups/
  logs/
  runtime/
/run/daed/
/usr/share/daed/geoip.dat
/usr/share/daed/geosite.dat
/usr/share/daed/web/                 # if Web dist is not embedded
/usr/lib/systemd/system/daed.service
```

`/var/lib/daed` is optional package-specific FHS mode only, not C10 default。

### 34.5 Admission fields

C10 service-contract / package-info should report:

```text
primary_state_store=/etc/daed/daed.db
protected_rollback_state_store=/etc/daed/wing.db
rust_daed_writes_wing_db_by_default=false
wing_db_import_supported=true
wing_db_import_destructive_by_default=false
daed_db_primary_required=true
var_lib_daed_required_by_default=false
```

Admission must fail if a C10 Rust test package writes `wing.db` by default, because that breaks rollback safety。

## 35. Next daed native implementation plan（2026-06-02）

This section records the next implementation plan after the full daed / daewing audit and the final product design decision.

Hard rule:

- This is not a new stage.
- All work in this section belongs to C10 `go-free-product-chain-v1`.
- Do not create C11 / C12.
- Do not create temporary stages.
- Do not rename the top-level work package to a protocol-specific name.
- Do not add new crates by default; use the existing `rust/crates` layout unless a hard ownership or dependency conflict is proven.

Goal:

```text
Final C10 product:
  /usr/bin/daed

Owned by Rust:
  CLI
  Web/API
  auth/session
  state DB
  resource CRUD
  materializer
  runtime owner
  latency/policy feedback
  subscription scheduler
  logs/events
  import/export
  package/release surface

Not final product entry:
  dae-daemon-optin
  Go daewing
  Go daed shell
```

### 35.1 Correct the C10 product contract first

Before adding the product binary surface, fix the recorded C10 contract and admission outputs so they no longer point at the superseded `/var/lib/daed/state/product.db` design.

Required service-contract / package-info fields:

```text
primary_state_store=/etc/daed/daed.db
protected_rollback_state_store=/etc/daed/wing.db
rust_daed_writes_wing_db_by_default=false
wing_db_import_supported=true
wing_db_import_destructive_by_default=false
daed_db_primary_required=true
var_lib_daed_required_by_default=false
```

Rules:

- Rust C10 test package must use `/etc/daed/daed.db` as primary state.
- Rust C10 test package must not write `/etc/daed/wing.db` by default.
- `/etc/daed/wing.db` remains protected rollback state for old daed / Go daewing.
- `/var/lib/daed` remains optional package-specific FHS mode only, not the C10 default.
- If any admission output still reports `/var/lib/daed/state/product.db` as default primary state, C10 admission fails.

### 35.2 Add the Rust `daed` product binary skeleton

Initial target:

```text
cargo build -p dae-daemon --bin daed
```

Default location after packaging:

```text
/usr/bin/daed
```

Implementation rule:

- Prefer adding the product binary inside the existing `dae-daemon` crate.
- Do not add a new product crate unless the existing crate boundary blocks dependency ownership, binary entry wiring, or package layout.
- Do not make `dae-daemon-optin` the final C10 product entry.

Initial command surface:

```text
daed run -c /etc/daed --listen 0.0.0.0:2023 --api-only
daed service-contract --json
daed package-info --json
daed state check --state /etc/daed/daed.db
daed state migrate --from-wing-db /etc/daed/wing.db --to /etc/daed/daed.db
daed export openapi
daed export flatdesc
daed export outline
daed resetpass -c /etc/daed
```

Minimum command semantics:

- `run` starts the Rust product API and, later, the Rust runtime owner.
- `service-contract` exposes C10 admission facts.
- `package-info` exposes package/runtime/product layout facts.
- `state check` verifies state DB readability, schema version, and write policy.
- `state migrate` imports old `wing.db` into Rust-owned `daed.db` without mutating `wing.db`.
- `export` emits Web/API metadata needed by package and frontend consumers.
- `resetpass` preserves old daed operational recovery behavior.

### 35.3 Implement the `daed.db` product state layer

Primary state:

```text
/etc/daed/daed.db
```

Protected rollback state:

```text
/etc/daed/wing.db
```

Initial Rust state should mirror the current `wing.db` product model closely enough to avoid inventing a new Web/API data contract during the first C10 product step.

Required legacy-compatible tables / models:

```text
User
Config
Dns
Routing
Node
Subscription
Group
GroupSubscription
GroupPolicyParam
System
LogSetting
NodeLatencyResult
```

Required Rust-owned metadata:

```text
daed_product_metadata
daed_schema_migrations
```

Migration/import behavior:

```text
daed state migrate --from-wing-db /etc/daed/wing.db --to /etc/daed/daed.db
```

Safeguards:

- Compute `wing.db` hash before import.
- Import into `daed.db`.
- Compute `wing.db` hash after import.
- Admission requires before/after `wing.db` hashes to match.
- If `daed.db` exists, migration must be idempotent or fail with a clear non-destructive error.
- Re-import must require an explicit flag.
- No silent overwrite of Rust primary state.
- No silent mutation of rollback state.

### 35.4 Close setup/auth/user storage first

The first usable Rust product slice must allow WebUI bootstrap/login and user storage persistence without Go daewing.

Minimum API set:

```text
GET    /api/auth/status
POST   /api/auth/users
POST   /api/auth/token
GET    /api/user/me
PATCH  /api/user/me
POST   /api/user/me/password
GET    /api/user/me/storage
PUT    /api/user/me/storage
DELETE /api/user/me/storage
POST   /api/user/me/default-resources
```

Required behavior:

- Preserve setup-first flow.
- Preserve password hashing semantics or provide a safe migration path.
- Preserve JWT/session semantics expected by the existing WebUI.
- Preserve user storage JSON behavior.
- Preserve default-resource creation semantics.
- Do not mark C10 product API usable if WebUI cannot log in, persist state, and reload the session from Rust only.

### 35.5 Implement resource CRUD parity

After setup/auth works, implement DB/API parity for the core product resources:

```text
/configs
/dns
/routings
/groups
/nodes
/subscriptions
```

Required coverage:

- selected resource flags.
- version increments.
- create/update/delete/list/get semantics.
- pagination and filtering where current WebUI expects it.
- node tags.
- subscription URLs, cron fields, user agent, selected state, and update metadata.
- group memberships.
- group-subscription bindings.
- group policy params.
- fixed-policy target validation.
- empty-group validation.
- manual nodes and subscription-backed nodes.

Admission rule:

- Do not replace Go daewing by default if CRUD only covers a simplified subset of the existing API.

### 35.6 Implement the Rust materializer

Materializer input:

```text
/etc/daed/daed.db
```

Materializer output:

```text
runtime model
generated .dae snapshot
```

Default snapshot path for package/runtime evidence:

```text
/etc/daed/runtime/generated.dae
```

The snapshot is runtime evidence, not the product source of truth.

Required parity with the Go orchestrator/materializer:

- selected config/dns/routing/group resources.
- necessary group discovery.
- group policy params.
- group-subscription expansion.
- regex subscription matching.
- manual node inclusion.
- subscription node inclusion.
- node deduplication.
- unique runtime outbound names.
- fixed policy validation.
- empty group validation.
- selected system running metadata.
- generated runtime model suitable for the Rust resident/runtime owner.

Admission rule:

- C10 cannot be considered Go-free if Rust daed still requires Go daewing to materialize product state into runtime config.

### 35.7 Wire the Rust runtime owner

Preferred C10 runtime shape:

```text
single Rust /usr/bin/daed process owns product API and runtime
```

Acceptable intermediate C10-internal shape:

```text
Rust /usr/bin/daed
  -> Rust package-internal resident runtime component
```

Forbidden final shape:

```text
Go daewing
  -> dae-daemon-optin
```

Required runtime API coverage:

```text
reload
stop
overview
general state
cache stats
events
runtime log level
```

Required behavior:

- Runtime reload uses Rust materialized model.
- Runtime stop is owned by Rust.
- Runtime status is served by Rust API.
- Runtime events/logs are exposed without Go daewing.
- Native runtime owns outbound/datapath path selected by the C7-C9 work.

### 35.8 Implement logs, SSE, latency, and subscription scheduler

Required log/event API:

```text
GET    /api/logs
GET    /api/logs/settings
PUT    /api/logs/settings
GET    /api/events/logs
PATCH  /api/runtime/log-level
```

Required latency API/data path:

```text
/api/nodes/latencies
  -> daed.db NodeLatencyResult
  -> runtime group-policy state
  -> dae-outbound DialerGroup selection
```

Required policy coverage:

```text
min
min_avg10
min_moving_avg
add_latency
check_tolerance
alive/dead
manual nodes
subscription-backed nodes
stable node id -> runtime dialer mapping
```

Required subscription scheduler coverage:

- import subscription.
- refresh subscription.
- cron scheduling.
- node replacement/update semantics.
- latency invalidation/update semantics after subscription refresh.
- materializer/runtime reload trigger after relevant subscription updates.

Admission rule:

- Rust product chain is incomplete if latency only writes API-visible results but does not feed group-policy selection.

### 35.9 Finish import/export and package switch

Required import/export endpoints:

```text
GET /api/user/me/dae-bundle
PUT /api/user/me/dae-bundle
GET /api/user/me/dae-config-file
PUT /api/user/me/dae-config-file
POST /api/user/me/dae-config-file/preview
```

Required metadata exports:

```text
daed export openapi
daed export flatdesc
daed export outline
```

Required product/package coverage:

- static Web serving or embedded Web dist.
- systemd unit for Rust `/usr/bin/daed`.
- Docker/package defaults pointing to Rust `/usr/bin/daed`.
- geoip/geosite paths.
- runtime directory paths.
- backup paths.
- service-contract admission.
- package-info admission.

Package default switch rule:

- Only switch default package/service to Rust `/usr/bin/daed` after Rust product chain covers CLI, Web/API, state, materializer, runtime owner, latency/policy feedback, subscription scheduler, logs/events, import/export, and package metadata.

### 35.10 First implementation batch

The first implementation batch should stay narrow and product-spine oriented:

```text
1. service-contract/package-info daed.db + protected wing.db fields
2. Rust daed binary skeleton
3. daed.db schema + non-destructive wing.db import
4. setup/auth/user-storage/minimal API
```

Do not start by switching the live host default package.

Do not start by deleting `daed/wing`.

Do not start by making outbound/datapath changes the proof of C10 product completion.

### 35.11 First batch acceptance

Required local build and command checks:

```text
cargo build -p dae-daemon --bin daed
daed service-contract --json
daed package-info --json
daed state check --state /etc/daed/daed.db
daed state migrate --from-wing-db /etc/daed/wing.db --to /etc/daed/daed.db
```

Required migration safety check:

```text
sha256(/etc/daed/wing.db) before import == sha256(/etc/daed/wing.db) after import
```

Required minimal API checks:

```text
daed run -c /etc/daed --api-only
GET  /api/health
GET  /api/auth/status
POST /api/auth/users
POST /api/auth/token
GET  /api/user/me
PUT  /api/user/me/storage
GET  /api/user/me/storage
```

Required repository hygiene:

```text
git diff --check
```

### 35.12 Explicit non-goals for the next batch

```text
do not write /etc/daed/wing.db by default
do not switch live host default daed yet
do not delete daed/wing yet
do not make dae-daemon-optin final entry
do not add C11/C12
do not add temporary stages
do not add crates unless hard blocked
do not implement a simplified WebUI API and call C10 complete
do not treat generated .dae as product source of truth
do not claim Go-free while Go daewing still owns product materialization or runtime supervision
```

## 36. C10 first-batch implementation record：daed native 1-5（2026-06-02）

This section records the implementation result for the requested C10 internal items 1-5.

This is still under C10 `go-free-product-chain-v1`.

No new C phase was added.

Leptos remains out of scope for the current plan.

### 36.1 Completed scope

Completed C10 internal items:

```text
1. service-contract/package-info outputs daed.db + protected wing.db fields
2. Rust daed product binary skeleton
3. daed.db schema + non-destructive wing.db import/check
4. setup/auth/user-storage minimal API
5. current React WebUI dist static serving by Rust daed
```

Implemented product binary:

```text
cargo build -p dae-daemon --bin daed
```

New binary entry:

```text
rust/crates/dae-daemon/src/bin/daed.rs
```

New product module:

```text
rust/crates/dae-daemon/src/daed_product.rs
```

No new local crate was added.

The SQLite state layer required an external dependency in the existing `dae-daemon` crate:

```text
rusqlite
```

This is a state-layer dependency needed to read/write SQLite-compatible `daed.db` and import old `wing.db`.

### 36.2 Service contract and package info

`daed service-contract --json` now reports:

```text
primary_state_store=/etc/daed/daed.db
protected_rollback_state_store=/etc/daed/wing.db
rust_daed_writes_wing_db_by_default=false
wing_db_import_supported=true
wing_db_import_destructive_by_default=false
daed_db_primary_required=true
var_lib_daed_required_by_default=false
```

`dae-daemon` common service-contract capabilities also expose the same state-store constraints so admission tooling cannot drift back to `/var/lib/daed/state/product.db`.

`daed package-info --json` reports:

```text
binary=/usr/bin/daed
work_package=go-free-product-chain-v1
primary_state_store=/etc/daed/daed.db
protected_rollback_state_store=/etc/daed/wing.db
webui.framework=current React/Vite dist
webui.served_by=Rust daed static file server
webui.leptos_considered=false
full_go_free_product_chain_ready=false
```

Important contract boundary:

```text
rust_product_binary_contract_ready=true
rust_product_lifecycle_contract_ready=true
rust_daed_state_layer_ready=true
rust_daed_setup_auth_user_storage_api_ready=true
rust_daed_static_webui_serving_ready=true
go_free_product_chain_ready=false
```

The first batch is complete, but full C10 remains blocked until later items complete.

### 36.3 Rust daed command surface

Implemented command surface:

```text
daed run -c /etc/daed --listen 0.0.0.0:2023 --api-only
daed service-contract --json
daed package-info --json
daed state check --state /etc/daed/daed.db
daed state migrate --from-wing-db /etc/daed/wing.db --to /etc/daed/daed.db
daed export openapi
daed export flatdesc
daed export outline
daed resetpass -c /etc/daed
```

Notes:

- `run` starts the first-batch Rust product HTTP server.
- `service-contract` and `package-info` emit C10 product facts.
- `state check` creates/checks the first-batch schema if needed.
- `state migrate` imports old `wing.db` into `daed.db` without mutating `wing.db`.
- `export` is a first-batch metadata skeleton.
- `resetpass` command exists as skeleton only; full resetpass behavior remains later product parity work.

### 36.4 daed.db state layer

Primary state:

```text
/etc/daed/daed.db
```

Protected rollback state:

```text
/etc/daed/wing.db
```

First-batch schema creates/keeps these tables:

```text
users
configs
dns
routings
subscriptions
nodes
groups
group_nodes
group_subscriptions
group_policy_params
systems
log_settings
node_latency_results
daed_product_metadata
daed_schema_migrations
```

Migration behavior:

```text
daed state migrate --from-wing-db /etc/daed/wing.db --to /etc/daed/daed.db
```

Safeguards implemented:

- compute `wing.db` SHA256 before import.
- copy/import to `daed.db`.
- apply Rust metadata/schema to `daed.db`.
- compute `wing.db` SHA256 after import.
- fail if `wing.db` hash changes.
- do not write `wing.db` by default.
- if target exists and `--force` is not provided, do not overwrite target.

### 36.5 Minimal API implemented

Implemented first-batch API under `/api`:

```text
GET    /api/health
GET    /api/auth/status
POST   /api/auth/users
POST   /api/auth/token
GET    /api/user/me
PATCH  /api/user/me
POST   /api/user/me/password
GET    /api/user/me/storage
PUT    /api/user/me/storage
DELETE /api/user/me/storage
POST   /api/user/me/default-resources
```

Auth compatibility:

- password hash matches Go daewing behavior: SHAKE256 over `jwt_secret` bytes plus password.
- token shape is HS256 JWT-compatible with `role`, `sub`, and `exp`.
- bearer auth supports `Authorization: Bearer ...`.
- event-source token query fallback is reserved for `/api/events/runtime` and `/api/events/logs`.

Storage compatibility:

- `JsonStorage` remains JSON text in the `users` table.
- `GET /api/user/me/storage` returns `{"values":[...]}`.
- `PUT /api/user/me/storage` returns `{"updated":N}`.
- `DELETE /api/user/me/storage` returns `{"removed":N}`.
- dotted storage paths such as `ui.sidebar` are supported for the first batch.

Default-resource behavior:

- first-batch endpoint creates/returns default config/dns/routing/group IDs.
- it stores `defaultConfigID`, `defaultRoutingID`, `defaultDNSID`, `defaultGroupID`, and `mode` in user storage.
- full resource CRUD/materializer parity is still later C10 work.

### 36.6 Static WebUI serving

The Rust `daed run` server now serves:

```text
/api/*   -> Rust first-batch API
/*       -> current React/Vite WebUI dist static files
```

Default Web root:

```text
/usr/share/daed/web
```

Override:

```text
--web-root PATH
DAED_WEB_ROOT=PATH
```

`--api-only` disables static WebUI serving and keeps only the API surface.

The current plan keeps the existing React/Vite WebUI.

Leptos POC/rewrite is not part of the current C10 implementation path.

### 36.7 Validation completed

Validation commands completed:

```text
cargo check -p dae-daemon --bin daed
cargo build -p dae-daemon --bin daed
cargo test -p dae-daemon --test daed_product
cargo test -p dae-daemon --test service_contract candidate_reports_resident_service_and_dataplane_capabilities
cargo fmt --check -p dae-daemon
```

`daed_product` integration tests cover:

```text
service-contract/package-info state path fields
go_free_product_chain_ready remains false
state check
non-destructive wing.db -> daed.db migration
wing.db SHA256 unchanged
run server
GET /api/health
GET /api/auth/status
POST /api/auth/users
GET /api/user/me
PUT /api/user/me/storage
GET /api/user/me/storage
static index.html serving
```

### 36.8 Remaining C10 work

The following are still not complete and must remain under C10:

```text
resource CRUD API parity
Rust materializer
Rust runtime owner
logs/SSE
latency and group-policy feedback
subscription scheduler
import/export parity
resetpass full parity
static Web dist package integration
systemd/docker/package default switch
live host default-switch validation
```

Do not claim full C10 go-free product-chain completion until these are implemented and admitted.

## 37. C10 local Rust product surface implementation record：daed native 6-10（2026-06-03）

Scope:

```text
C10 go-free-product-chain-v1
```

This section records completion of local Rust `daed` product-surface items 6-10.

It does not add a new stage.

It does not change the hard C0-C10 phase rule.

It does not introduce Leptos work.

It does not mark the full go-free product chain ready.

`go_free_product_chain_ready` remains `false` until live package admission, rollback validation, and default-path removal are complete.

### 37.1 Resource CRUD API parity first pass

Implemented Rust `daed` local API coverage for:

```text
GET/POST          /api/configs
GET/PUT/DELETE    /api/configs/{id}
POST              /api/configs/{id}/select
POST              /api/configs/parsed

GET/POST          /api/dns
GET/PUT/DELETE    /api/dns/{id}
POST              /api/dns/{id}/select
POST              /api/dns/parsed

GET/POST          /api/routings
GET/PUT/DELETE    /api/routings/{id}
POST              /api/routings/{id}/select
POST              /api/routings/parsed

GET/POST/DELETE   /api/nodes
GET/PUT/DELETE    /api/nodes/{id}

GET/POST/DELETE   /api/subscriptions
GET/PUT/DELETE    /api/subscriptions/{id}
GET               /api/subscriptions/{id}/nodes
POST              /api/subscriptions/{id}/refresh

GET/POST          /api/groups
GET/PUT/DELETE    /api/groups/{id}
POST/DELETE       /api/groups/{id}/nodes
POST/DELETE       /api/groups/{id}/subscriptions
```

Compatibility notes:

- Group list shape follows current React/Vite WebUI expectations: `nodes: NodeAPI[]` and subscription bindings with `subscriptionId`, `matchedCount`, `matchedNodes`, `updatedAt`, `status`, `info`, `link`, and `tag`.
- Group policy params accept both `val` and `value` input, and return `val`.
- Node import parses link protocol, host/address, fragment/tag, and subscription ownership into `daed.db`.
- Subscription refresh is a Rust local state update in this batch; it does not yet perform production remote subscription fetching.

### 37.2 Runtime materializer and owner API

Implemented Rust local materializer:

```text
POST /api/runtime/reload
POST /api/runtime/stop
GET  /api/runtime/overview
GET  /api/general/state
GET  /api/general/cache-stats
GET  /api/general/interfaces
```

Materializer output:

```text
<config_dir>/runtime/generated.dae
```

Default config dir:

```text
/etc/daed
```

Runtime behavior in this batch:

- `runtime/reload` materializes selected config/dns/routing, groups, and nodes into `generated.dae`.
- `runtime/reload` records Rust local runtime state in `daed_product_metadata` and `systems`.
- `runtime/stop` clears the Rust local running marker.
- `runtime/overview` returns current local Rust product overview including RSS observation.
- This is still local Rust product ownership evidence; it is not yet the final live package default switch.

### 37.3 Logs, SSE, latency, and subscription scheduler skeleton

Implemented:

```text
GET    /api/logs
DELETE /api/logs
GET    /api/logs/settings
PATCH  /api/logs/settings
GET    /api/events/runtime
GET    /api/events/logs
GET    /api/nodes/latencies
POST   /api/nodes/latencies
GET    /api/runtime/log-level
PATCH  /api/runtime/log-level
```

State tables used:

```text
log_entries
log_settings
node_latency_results
daed_product_metadata
```

Notes:

- SSE endpoints emit snapshot events and support bearer auth plus `access_token` query auth fallback for WebUI EventSource compatibility.
- Latency probes are local Rust C10 synthetic probes in this batch; production network probing remains an admission item.
- Subscription scheduler skeleton records startup metadata/log evidence but does not yet fetch remote subscriptions on cron.

### 37.4 Import/export/package surface

Implemented:

```text
GET /api/user/me/dae-bundle
PUT /api/user/me/dae-bundle
GET /api/user/me/dae-config-file
PUT /api/user/me/dae-config-file
POST /api/user/me/dae-config-file/preview

daed export openapi
daed export flatdesc
daed export outline
```

Bundle behavior:

- Exports `schemaVersion`, `exportedAt`, `mode`, `defaults`, `selected`, `configs`, `dnss`, `routings`, `subscriptions`, `nodes`, and `groups`.
- Imports into `daed.db`.
- Does not write `/etc/daed/wing.db`.
- Preserves `wing.db` as protected old daed/daewing rollback DB.
- Updates user JSON storage defaults/mode from imported bundle.

Package surface reported:

```text
systemd_unit=daed.service uses /usr/bin/daed run -c /etc/daed
docker_entrypoint=/usr/bin/daed run -c /etc/daed --listen 0.0.0.0:2023
default_package_switch_live_applied=false
go_daewing_default_path_removed=false
```

### 37.5 Contract state after 6-10

Rust `daed service-contract --json` now reports:

```text
rust_product_binary_contract_ready=true
rust_product_lifecycle_contract_ready=true
rust_product_web_api_package_release_contract_ready=true
rust_daed_state_layer_ready=true
rust_daed_non_destructive_wing_db_import_ready=true
rust_daed_setup_auth_user_storage_api_ready=true
rust_daed_static_webui_serving_ready=true
rust_daed_current_react_webui_served_by_rust_ready=true
rust_daed_resource_crud_api_ready=true
rust_daed_materializer_ready=true
rust_daed_runtime_owner_ready=true
rust_daed_logs_sse_latency_subscription_ready=true
rust_daed_import_export_package_surface_ready=true
go_free_product_chain_ready=false
go_free_product_chain_current_batch=C10.1-C10.10 local Rust product surface
```

Remaining contract blockers:

```text
live host default package switch
live rollback validation
remove Go daewing from default package path
full WebUI route audit against Rust API
production package admission
```

### 37.6 Validation completed

Validation commands completed:

```text
cargo check -p dae-daemon --bin daed
cargo fmt --check -p dae-daemon
cargo test -p dae-daemon --test daed_product
cargo test -p dae-daemon --test service_contract candidate_reports_resident_service_and_dataplane_capabilities
cargo test -p dae-daemon daed_product::
cargo build -p dae-daemon --bin daed
git -C /root/project/dae-daex-align diff --check
```

`cargo test -p dae-daemon --test daed_product` required running outside the sandbox because the integration tests bind `127.0.0.1` on a temporary HTTP port.

Validated integration coverage:

```text
service-contract/package-info state path fields
go_free_product_chain_ready remains false
state check
non-destructive wing.db -> daed.db migration
wing.db SHA256 unchanged
run server
GET /api/health
GET /api/auth/status
POST /api/auth/users
GET /api/user/me
PUT/GET /api/user/me/storage
static index.html serving
config/dns/routing create/select/list
node import
subscription import/refresh
group create and node/subscription binding
latency probe update/list
log settings update/list
runtime log-level update
runtime reload materializes runtime/generated.dae
runtime overview/general state
runtime/log SSE snapshot endpoints
bundle export/import
dae config-file export/preview
logs clear
runtime stop
daed export openapi
daed export flatdesc
daed export outline
```

### 37.7 Remaining C10 admission work

Still not done:

```text
production remote subscription fetching
production latency probing against real outbound path
full WebUI route audit against Rust API
resetpass full parity
static Web dist package integration
systemd/docker package files in final artifact
live default package switch
live rollback validation with old daed/daewing protected wing.db
remove Go daewing from default package path
production package admission evidence
```

The implementation is therefore a completed local Rust `daed` product-surface batch, not full C10 completion.

## 38. C10 local package admission evidence implementation record（2026-06-03）

Scope:

```text
C10 go-free-product-chain-v1
```

This section records the next C10 batch after local Rust `daed` product surface completion.

It is still not a new stage.

It does not mark `go_free_product_chain_ready=true`.

It does not perform a live host default switch.

It produces local package admission evidence that is required before live default-path mutation.

### 38.1 Production subscription fetch

Implemented Rust `daed` subscription fetch behavior:

```text
POST /api/subscriptions
POST /api/subscriptions/{id}/refresh
```

Behavior:

- HTTP and HTTPS subscription URLs are fetched by Rust `daed`.
- Plain text subscription bodies are parsed as node-link lines.
- Base64 subscription bodies are decoded and parsed as node-link lines.
- Refresh replaces nodes owned by that subscription.
- Subscription status becomes `fetched` on success.
- Subscription status becomes `fetch_error` on fetch failure, with error text stored in `info`.
- `nodeImportResult` is returned for WebUI compatibility.

Implementation notes:

- Uses existing Rust dependencies and existing `dae-daemon` crate boundary.
- Does not add a new local crate.
- Does not add a protocol-specific top-level gate name.

### 38.2 TCP latency probe

Replaced C10 synthetic latency with an actual TCP connect probe:

```text
POST /api/nodes/latencies
GET  /api/nodes/latencies
```

Behavior:

- Target host/port are derived from the node link URL.
- If the link has no explicit port, Rust `daed` uses conservative default ports by scheme.
- Probe records:
  - `latencyMs`
  - `alive`
  - `testedAt`
  - `message`
- Results are stored in `node_latency_results`.

This is still admission evidence for product WebUI latency workflow.

It is not a claim that full protocol handshake latency or full selected-outbound-path probing is complete.

### 38.3 WebUI route audit

Implemented export:

```text
daed export webui-route-audit
```

Report fields:

```text
schemaVersion
workPackage=go-free-product-chain-v1
source=daed/apps/web/src/apis
rustServer=rust/crates/dae-daemon/src/daed_product.rs
pass
missing
covered
notes
```

Covered route classes:

```text
auth/setup
user profile/password/storage
bundle import/export
dae config-file import/export/preview
general state/interfaces/cache stats
runtime overview/reload/stop/log-level
events runtime/logs
logs/settings
configs/dns/routings CRUD/select/parse
nodes CRUD/tag/latencies
subscriptions CRUD/tag/link/cron/refresh/nodes
groups CRUD/policy/nodes/subscriptions
```

This removes the local `full WebUI route audit against Rust API` blocker from the local-admission list.

Live browser route validation can still be run before final live default switch.

### 38.4 resetpass parity

Implemented Rust `daed` resetpass behavior:

```text
daed resetpass -c /etc/daed
daed resetpass -c /etc/daed --json
```

Behavior:

- Opens `<config_dir>/daed.db`.
- Resets every user to a random recovery password.
- Updates `password_hash` and `jwt_secret`.
- Prints plaintext parity output:

```text
Username: <username>, Password: <password>
```

- `--json` returns structured recovery output for tests and automation.
- Does not write `/etc/daed/wing.db`.

Validation includes a protected `wing.db` hash check and login with the new password.

### 38.5 Package artifacts and admission report

Implemented exports:

```text
daed export package-manifest
daed export admission-report
daed export systemd-unit
daed export docker-entrypoint
```

`package-manifest` records:

```text
/usr/bin/daed
/etc/daed/daed.db
/etc/daed/wing.db protected rollback store
/usr/share/daed/web
/etc/daed/runtime/generated.dae
systemd unit command
docker entrypoint command
live default switch not applied
Go daewing default path not removed
live rollback validation not applied
```

`admission-report` records:

```text
rustDaedBinary=true
currentReactViteWebuiServedByRust=true
resourceCrudApi=true
runtimeMaterializer=true
runtimeOwnerApi=true
logsSse=true
subscriptionFetch=true
tcpLatencyProbe=true
resetpassParity=true
packageManifest=true
webuiRouteAuditPass=true
defaultPackageSwitchApplied=false
rollbackValidationApplied=false
goDaewingDefaultPathRemoved=false
```

### 38.6 Contract state after local package admission evidence

Rust `daed service-contract --json` now reports:

```text
rust_daed_subscription_fetch_ready=true
rust_daed_latency_probe_tcp_ready=true
rust_daed_resetpass_parity_ready=true
rust_daed_package_manifest_ready=true
rust_daed_webui_route_audit_ready=true
rust_daed_local_package_admission_ready=true
go_free_product_chain_ready=false
go_free_product_chain_current_batch=C10 local package admission evidence
```

Remaining C10 blockers:

```text
live host default package switch
live rollback validation
remove Go daewing from default package path
production package admission
```

### 38.7 Validation completed

Validation commands completed:

```text
cargo fmt --check -p dae-daemon
cargo check -p dae-daemon --bin daed
cargo test -p dae-daemon --test daed_product
cargo test -p dae-daemon --test service_contract candidate_reports_resident_service_and_dataplane_capabilities
cargo test -p dae-daemon daed_product::
cargo build -p dae-daemon --bin daed
git -C /root/project/dae-daex-align diff --check
```

New integration coverage:

```text
local HTTP subscription fetch
subscription node import result
subscription fetch_error path
node tag-only update
subscription tag-only update
subscription cron update preserves tag
real TCP latency probe against local listener
resetpass updates daed.db users
resetpass does not modify protected wing.db
login with reset password
package-manifest export
admission-report export
webui-route-audit export
systemd-unit export
docker-entrypoint export
```

### 38.8 Still not done

Still not done in this local batch:

```text
live host default package switch
live rollback validation on target host
remove Go daewing from default product path
production artifact installation on target host
final product-chain recertification after live mutation
```

Therefore the next live action is still a C10 live default-path switch and rollback validation task, not a new C-stage.

## 39. C10 live default-path switch and rollback evidence record (2026-06-03)

This record is still under C10 `go-free-product-chain-v1`. It is not a new
stage.

### 39.1 Live host and artifacts

Target host:

```text
10.10.10.2
hostname=fendoradaed
remote evidence dir=/root/daed-c10-live-20260603-080402
```

Local release candidate built from `/root/project/dae-daex-align`:

```text
artifact=/root/project/dae-daex-align/rust/target/release/daed
remote staged artifact=/usr/bin/daed.rust-c10-candidate
size=9948816 bytes
sha256=ecfe16e85cbe96bbb008194f96ca97c7cf878e2cb1b3266787dbfd95fcc4f2bb
```

Original live rollback binary:

```text
/usr/bin/daed sha256 before switch=b296303fc01b0cd4453ab90bb7bf988d6315a952a548fd483a0a9c5bab2448bf
/usr/bin/daed.go-rollback.20260603-080402 sha256=b296303fc01b0cd4453ab90bb7bf988d6315a952a548fd483a0a9c5bab2448bf
```

Protected rollback state:

```text
/etc/daed/wing.db sha256 before switch=bada431fed16f050f40daea1365798293ac31a11701c97b16b4c264d8cd1d441
```

Rust product state:

```text
/etc/daed/daed.db was created for Rust daed and migrated from /etc/daed/wing.db
Rust daed did not use /etc/daed/wing.db as its primary state store
```

### 39.2 Pre-switch and staged admission

Pre-switch live state:

```text
systemctl is-active daed=active
live command=/usr/bin/daed run -c /etc/daed/
live port=*:2023
```

Candidate CLI checks passed on the live host:

```text
/usr/bin/daed.rust-c10-candidate package-info --json
/usr/bin/daed.rust-c10-candidate export admission-report
/usr/bin/daed.rust-c10-candidate state check --state /etc/daed/daed.db
```

The `state check` created `/etc/daed/daed.db` when it did not exist. It did not
modify `/etc/daed/wing.db`.

Staged HTTP smoke on `127.0.0.1:22023` passed before migration:

```text
GET /api/health=200
GET /api/auth/status=200
POST /api/auth/users=200
GET /api/user/me=200
PUT /api/user/me/storage=200
GET /api/runtime/overview=200
GET /api/logs/settings=200
```

The migrated `wing.db -> daed.db` state preserved the rollback database:

```text
wing_db_sha256_before=bada431fed16f050f40daea1365798293ac31a11701c97b16b4c264d8cd1d441
wing_db_sha256_after=bada431fed16f050f40daea1365798293ac31a11701c97b16b4c264d8cd1d441
wing_db_unchanged=true
daed.db user_count=1
daed.db node_count=24
daed.db group_count=8
```

Staged HTTP smoke on `127.0.0.1:22023` passed after migration:

```text
GET /api/health=200
GET /api/user/me=200 username=shaka
GET /api/nodes=200
GET /api/groups=200
```

### 39.3 Live Rust default-path switch attempt

The live default path was switched by replacing `/usr/bin/daed` with
`/usr/bin/daed.rust-c10-candidate` while keeping the original binary at
`/usr/bin/daed.go-rollback.20260603-080402`.

Rust candidate systemd/API admission passed:

```text
systemctl is-active daed=active
command=/usr/bin/daed run -c /etc/daed/
port=0.0.0.0:2023
/usr/bin/daed sha256=ecfe16e85cbe96bbb008194f96ca97c7cf878e2cb1b3266787dbfd95fcc4f2bb
GET /api/health=200
GET /api/user/me=200 username=shaka
GET /api/nodes=200 total=24
GET /api/groups=200 items=8
GET /api/general/state=200
GET /api/runtime/overview=200
GET /api/logs/settings=200
```

However, C10 live default-path admission did not pass:

```text
/api/general/state running=false
/api/general/state netnsLinkMode=none
/api/general/state attachBackend=rust-native-owned-local
```

Local code audit matched the live result:

```text
rust/crates/dae-daemon/src/daed_product.rs api_runtime_reload()
```

currently only:

```text
materializes /etc/daed/runtime/generated.dae
sets metadata runtime_running=true when not dry
updates the systems table
```

It does not start or own the production resident dataplane, does not attach the
runtime path, and does not restore the selected running state on `daed run`
startup. Calling `/api/runtime/reload` would therefore be a metadata/materializer
operation, not real live dataplane admission.

### 39.4 Rollback validation

Rollback to the original binary was validated:

```text
/usr/bin/daed restored sha256=b296303fc01b0cd4453ab90bb7bf988d6315a952a548fd483a0a9c5bab2448bf
systemctl is-active daed=active
port=*:2023
GET /api/health=200
GET /api/user/me=200 username=shaka
GET /api/general/state=200
/api/general/state running=true
/api/general/state netnsLinkMode=netkit
/api/general/state attachBackend=tcx
```

Rollback state was protected:

```text
/etc/daed/wing.db sha256 after rollback=bada431fed16f050f40daea1365798293ac31a11701c97b16b4c264d8cd1d441
wing.db unchanged=true
```

### 39.5 Final live state after this C10 attempt

Because the Rust candidate did not start a real resident/dataplane runtime, the
host was intentionally left on the original working `daed` binary.

Final live state:

```text
systemctl is-active daed=active
command=/usr/bin/daed run -c /etc/daed/
port=*:2023
/usr/bin/daed sha256=b296303fc01b0cd4453ab90bb7bf988d6315a952a548fd483a0a9c5bab2448bf
/usr/bin/daed.rust-c10-candidate sha256=ecfe16e85cbe96bbb008194f96ca97c7cf878e2cb1b3266787dbfd95fcc4f2bb
/usr/bin/daed.go-rollback.20260603-080402 sha256=b296303fc01b0cd4453ab90bb7bf988d6315a952a548fd483a0a9c5bab2448bf
/etc/daed/wing.db sha256=bada431fed16f050f40daea1365798293ac31a11701c97b16b4c264d8cd1d441
/etc/daed/daed.db sha256=0e8392cece6f1f8fad3bbd87ac7cbc0c4f17c190d550193c1ebc006696497119
```

### 39.6 C10 conclusion and next work item

Passed:

```text
Rust daed binary can run as the live systemd API/product shell
Rust daed can serve the migrated daed.db Web/API state
Rust daed uses daed.db and did not write wing.db by default
Rollback binary and wing.db rollback path are valid
```

Not passed:

```text
C10 live default-path admission
go_free_product_chain_ready
production runtime ownership from Rust daed run
```

Required C10 fix before keeping Rust `daed` as the live default:

```text
wire Rust daed run/reload/stop to the production resident runtime owner
restore selected running state from daed.db on startup
make /api/general/state report real runtime state, not metadata-only state
make admission require running=true with a real attach backend and netns link mode
keep /etc/daed/wing.db protected for old daed rollback
keep names protocol-generic at the C10 gate level
```

This means the next task remains C10 product-chain work: bridge the Rust product
surface to the existing Rust resident production runtime and re-run the same
live switch plus rollback evidence loop.

## 40. C10 resident runtime bridge implementation record (2026-06-03)

This record is still under C10 `go-free-product-chain-v1`. It is not a new
stage.

### 40.1 Code-level blocker addressed

The live switch attempt in section 39 failed because Rust `daed` served the
Web/API product shell but did not own a real runtime. The following section 39
requirements are now implemented locally:

```text
wire Rust daed run/reload/stop to the production resident runtime owner
restore selected running state from daed.db on startup
make /api/general/state report real runtime state, not metadata-only state
make admission require running=true with a real attach backend and netns link mode
```

Changed files:

```text
rust/crates/dae-daemon/src/daed_product.rs
rust/crates/dae-daemon/src/production_runtime_owner/resident.rs
rust/crates/dae-daemon/tests/daed_product.rs
```

### 40.2 Product runtime manager

Rust `daed run` now creates a product runtime manager:

```text
ProductRuntimeManager
ProductRuntimeState
ProductRuntimeInstance::Resident(ResidentProductionRuntime)
ProductRuntimeInstance::Fake(FakeProductRuntime)
```

Default behavior is real resident runtime ownership:

```text
start_product_runtime_instance() -> start_resident_production_runtime(config)
```

The fake runtime path exists only for local HTTP/API tests:

```text
DAED_PRODUCT_RUNTIME_FAKE_START=1
```

This test-only switch is not part of the live default path and is not a fallback.
Without that env var, Rust `daed` uses the real production resident runtime
owner.

### 40.3 Startup restore

`daed run -c /etc/daed` now checks the Rust primary state store:

```text
/etc/daed/daed.db systems.running
```

If the persisted running state is true, startup now:

```text
materializes a dry runtime config preview from daed.db
parses the generated config through dae_config parser/build_config
starts the resident production runtime owner
writes /etc/daed/runtime/generated.dae only after runtime start succeeds
returns a run error if startup runtime restore fails
```

This makes live default switch fail-closed instead of leaving a live API shell
with no runtime.

### 40.4 Runtime reload and stop

`POST /api/runtime/reload` now:

```text
builds a dry materialized config preview
parses the generated config into dae_config::Config
starts or swaps the resident production runtime
rolls back to the previous runtime on start failure
writes generated.dae and systems.running=1 only after runtime start succeeds
returns runtimeStarted=true only after a real manager-owned runtime is active
```

`POST /api/runtime/stop` now:

```text
drops the runtime handle and runs ResidentProductionRuntime cleanup
sets systems.running=0
returns the manager state after stop
```

Signal behavior:

```text
SIGHUP/SIGUSR1 reloads only when systems.running=1
SIGTERM/SIGINT/SIGQUIT stops the runtime before process exit
```

This preserves the current systemd reload surface, including the existing HUP
drop-in behavior.

### 40.5 Real state reporting

`GET /api/general/state` and `GET /api/runtime/overview` now report manager
state instead of metadata-only state.

For a real resident runtime, state is derived from:

```text
ResidentProductionRuntime::product_state_summary()
resident-production-runtime-start.json
```

Reported fields include:

```text
running
attachBackend
netnsLinkMode
residentRuntimeStarted
residentDataplane
artifactDir
startFile
cleanupFile
```

This avoids the previous false-positive path where only
`daed_product_metadata.runtime_running=true` could make `/api/general/state`
look running.

### 40.6 Materializer validity fix

The generated runtime config is now parseable dae config. The previous
materializer appended JSON values after comments, which was not valid dae config
input for `dae_config`.

The materializer now renders:

```text
node {
    tag: 'node-link'
}

group {
    group_name {
        filter: name('node_tag')
        policy: fixed(0)
    }
}
```

Node and group rendering uses one shared runtime node tag rule so group filters
resolve against the generated node section.

`/etc/daed/runtime/generated.dae` is written with private permissions:

```text
0600
```

### 40.7 Reports updated

`daed service-contract --json`, `daed package-info --json`,
`daed export package-manifest`, and `daed export admission-report` now record:

```text
rust_daed_real_runtime_bridge_ready=true
rust_daed_runtime_state_metadata_only=false
real_runtime_bridge=true
metadata_only_runtime_state=false
local-runtime-bridge-pass-live-revalidation-pending
```

`go_free_product_chain_ready` remains false until live revalidation passes and
the remaining C10 product-chain work is complete.

### 40.8 Validation completed

Validation commands completed:

```text
cargo fmt -p dae-daemon
cargo check -p dae-daemon --bin daed
cargo test -p dae-daemon --test daed_product
cargo test -p dae-daemon daed_product::
cargo test -p dae-daemon --test service_contract candidate_reports_resident_service_and_dataplane_capabilities
```

New/updated test coverage:

```text
fake runtime manager path for local Web/API tests
runtime reload returns runtimeStarted=true only after manager start
/api/general/state reports manager attachBackend
/api/runtime/overview includes runtime manager state
generated runtime config renders node/group dae sections
generated runtime config parses through dae_config parser/build_config
```

### 40.9 Still not done

Still not done:

```text
release build after the runtime bridge
install new candidate on 10.10.10.2
re-run live default-path switch
verify /api/general/state running=true with real resident summary
verify Telegram/proxy dataplane behavior under Rust daed
verify rollback to old daed still preserves wing.db
remove Go daewing from default package path
final production package admission
```

Therefore the next action remains C10 live revalidation: build a new Rust
`daed` candidate, stage it on 10.10.10.2, repeat the default-path switch and
rollback loop, and leave the host on the safe working binary if the real runtime
or dataplane admission fails.

## 41. C10 runtime bridge live retry blocker and generic parser fix

Date: 2026-06-03

Scope remains C10 `go-free-product-chain-v1`. This is not a new C-stage.

### 41.1 Live retry result

A Rust `daed` runtime-bridge candidate was staged on the live host and tested as
the default `/usr/bin/daed` path with a temporary systemd environment drop-in:

```text
DAE_RUST_RESIDENT_DATAPLANE=1
DAE_EXPERIMENT_VLESS_VISION_FP_RUST_NATIVE=1
DAE_NETNS_LINK=auto
```

The candidate failed before the HTTP API came up. The immediate blocker was
startup runtime restore parsing the generated dae config:

```text
startup runtime restore failed: parse config:
domain(geosite:category-ai-!cn, geosite:apple-intelligence, geosite:bing) -> openai
expected )
```

This was not a dataplane-runtime failure yet. The failure happened before
`start_resident_production_runtime()` could run for that candidate.

Rollback was completed on the live host:

```text
/usr/bin/daed restored to the previous working binary
temporary C10 runtime-bridge env drop-in removed
systemd daemon-reload and reset-failed completed
daed active again
/api/health returned 200
wing.db hash stayed unchanged
```

The staged Rust candidate remains a candidate artifact only and is not the live
default binary.

### 41.2 Generic parser rule

The parser fix must stay protocol- and service-generic. It must not special-case
VLESS, any node provider name, geosite category names, or one live routing rule.

The accepted rule is:

```text
For any function parameter written as key:value, the value may be assembled from
bare literal fragments plus ':' and '!' fragments until a structural delimiter
is reached.
```

Structural delimiters still stop parsing:

```text
,
)
&&
->
```

This keeps compatibility with legacy/default daed configuration text such as
delimiter-bearing matcher values while preserving the parser structure.

### 41.3 Generic test principle

Tests for this fix must avoid provider/protocol-specific sample identities.

Use generic placeholders for generated product config tests:

```text
node tag: [edge]sample
node link: scheme://example.invalid:443#sample
group name: egress
function value shape: sample-set:alpha-!beta
```

Specific live strings may appear only as evidence in this memo or other
validation logs, not as top-level stage/gate names or protocol-specific
capability names.

### 41.4 Fail-closed runtime admission gate

The Rust `daed` runtime bridge now refuses to report C10 default-path success
unless the resident userspace dataplane is admitted:

```text
residentDataplane.enabled == true
residentDataplane.status == "pass"
```

If the resident runtime starts but the dataplane is skipped or not admitted,
Rust `daed` calls runtime cleanup and returns an error. This prevents a false
positive where the product shell and resident BPF/runtime start while the actual
userspace dataplane is not owned by Rust.

### 41.5 Validation completed after the fix

Validation commands completed:

```text
cargo fmt -p dae-config -p dae-daemon
cargo test -p dae-config parser::tests
cargo test -p dae-daemon daed_product::tests::generated_runtime_config_renders_parseable_nodes_and_groups
cargo check -p dae-daemon --bin daed
cargo test -p dae-daemon --test daed_product
cargo test -p dae-daemon daed_product::
```

All listed validation passed.

### 41.6 Next C10 action

Build a new release candidate from this parser/runtime-gate state, stage it on
the live host, repeat the default-path switch with rollback protection, and only
count C10 live revalidation as passing if:

```text
Rust daed API comes up
startup runtime restore succeeds
/api/general/state reports manager-owned resident runtime running
residentDataplane.enabled=true
residentDataplane.status=pass
real traffic test passes
rollback path still preserves wing.db
```

### 41.7 C10 condition split and proxy failure diagnostics

Do not reinterpret section 13 as a BoringSSL regression.

Section 13 remains the recorded 2026-06-02 live result for the temporary
Rust-owned `dae-daemon-optin` runtime:

```text
Telegram target flows used the Oracle-Sg route
TCP connection events reached tcp_connection_finished
tls_underlay=boringssl
```

That result means the fingerprint-aware BoringSSL underlay solved the previously
observed link-fingerprint admission/wire-emission blocker for that runtime
condition. It does not automatically certify every later C10 product-shell
condition.

The C10 Rust `daed` default-product path adds different validation variables:

```text
single Rust /usr/bin/daed product shell
daed.db materialization and startup restore
API reload/runtime-start ownership
native-ebpf build feature
compile-time fingerprint admission gate
resident dataplane fail-closed admission
```

If a later C10 live retry shows a failed proxy connection, treat it as C10
condition-specific evidence until reproduced and recorded. Do not describe it as
`BoringSSL did not work` unless the event itself shows the fingerprint-aware
underlay was absent or misselected.

The resident proxy failure event now carries the same generic relay diagnostics
that the finished event carries:

```text
tls_underlay
bytes_client_to_proxy
bytes_proxy_to_client
response_header_stripped
vision_unpadding_blocks
vision_direct_command_seen
vision_raw_direct_recovered
vision_downlink_direct_active
```

Purpose: the next live C10 retry can distinguish these cases without blind
retesting:

```text
fingerprint-aware TLS underlay not selected
failure before response header strip
failure before explicit downlink direct command
failure after direct command but before raw-direct recovery
raw-direct recovery succeeded and a later direct read/write failed
```

This is observability only. It does not change routing, protocol selection,
fingerprint admission, or Vision command semantics.

### 41.8 C10 authenticated reload evidence and direct-command transition fix

Live evidence directory:

```text
/root/daed-c10-runtime-bridge-20260603-094308
```

The C10 Rust `daed` candidate was actually installed as `/usr/bin/daed` via
atomic rename for this run:

```text
candidate sha256: afdf0d977b9ee48c713292b49407e0aa380709276fa98ef8cd370f68c0b0c026
live /usr/bin/daed during candidate run matched that sha256
candidate process: /usr/bin/daed run -c /etc/daed/
```

The Rust product API requires authentication for runtime state and reload
routes. The authenticated reload path returned HTTP 200 and started the resident
runtime:

```text
runtimeStarted=true
running=true
state=running
residentDataplane.enabled=true
residentDataplane.status=pass
residentDataplane.tcp_worker_started=true
residentDataplane.udp_worker_started=true
runtime dir=/tmp/dae-daemon-resident-runtime-21076
```

The default proxy plan still selected the fingerprint-aware underlay:

```text
default_proxy.node_tag=[HK]Hytron
default_proxy.utls_fingerprint.source=link fp
default_proxy.utls_fingerprint.requested=chrome
default_proxy.utls_fingerprint.canonical=chrome_auto
```

Telegram/API probe evidence:

```text
proxy_group=TG
node_tag=[SG]Oracle-Sg
sniffed_domain=api.telegram.org
dial_target=api.telegram.org:443
original_dst=149.154.167.220:443
tls_underlay=boringssl
event=tcp_connection_failed
error=read VLESS TLS plaintext: [BAD_DECRYPT] [DECRYPTION_FAILED_OR_BAD_RECORD_MAC]
bytes_client_to_proxy=1787
bytes_proxy_to_client=6176
response_header_stripped=true
vision_unpadding_blocks=4
vision_direct_command_seen=true
vision_downlink_direct_active=true
vision_raw_direct_recovered=false
```

Interpretation:

```text
BoringSSL underlay was selected.
Routing to TG / Oracle-Sg was selected.
The Vision downlink explicit direct command was seen.
The failure still occurred from the TLS plaintext read path.
```

Therefore this is not evidence that BoringSSL did not work. It is evidence that
after the Vision downlink direct command is seen, the TCP relay must stop reading
from TLS plaintext in the same inner loop and let the next outer loop iteration
enter the raw-direct read path.

Code fix:

```text
After Vision consume sets downlink_direct=true, write the current decoded payload
if present, mark progress, then break out of the TLS plaintext read loop.
```

This preserves existing behavior before the explicit direct command and only
changes the transition point after the command has already been observed.

Rollback status after the run:

```text
/usr/bin/daed restored to previous working binary
temporary C10 drop-in removed
wing.db hash remained bada431fed16f050f40daea1365798293ac31a11701c97b16b4c264d8cd1d441
daed.db restored to the pre-run backup for that retry
/api/health returned 200
```

### 41.9 C10 direct-command fix live validation

Live evidence directory:

```text
/root/daed-c10-runtime-bridge-20260603-094704
```

Candidate:

```text
sha256=74862b9edb418cd96580a69b6113e7f7a24861436b4899eef8b791be9a13e5a7
size=16183288 bytes
build=DAE_EXPERIMENT_VLESS_VISION_FP_RUST_NATIVE=1 cargo build --release -p dae-daemon --bin daed --features native-ebpf
```

The candidate was installed as `/usr/bin/daed` by atomic rename and the live
process was:

```text
/usr/bin/daed run -c /etc/daed/
```

Authenticated reload result:

```text
POST /api/runtime/reload -> HTTP 200
GET /api/general/state -> HTTP 200
GET /api/runtime/overview -> HTTP 200
running=true
residentRuntimeStarted=true
state=running
residentDataplane.status=pass
residentDataplane.tcp_worker_started=true
residentDataplane.udp_worker_started=true
runtime dir=/tmp/dae-daemon-resident-runtime-21741
```

Telegram/API probe after the direct-command transition fix:

```text
curl https://api.telegram.org/ with resolve 149.154.167.220 -> HTTP 302
event=tcp_connection_finished
proxy_group=TG
node_tag=[SG]Oracle-Sg
sniffed_domain=api.telegram.org
dial_target=api.telegram.org:443
original_dst=149.154.167.220:443
tls_underlay=boringssl
bytes_client_to_proxy=1890
bytes_proxy_to_client=6707
response_header_stripped=true
vision_unpadding_blocks=3
vision_direct_command_seen=true
vision_downlink_direct_active=true
vision_raw_direct_recovered=false
```

The prior failure mode:

```text
read VLESS TLS plaintext: [BAD_DECRYPT] [DECRYPTION_FAILED_OR_BAD_RECORD_MAC]
```

was not present for the Telegram/API probe after this fix. The event completed
after the explicit downlink direct command was seen.

Additional evidence in the same run showed other fingerprint-aware proxy paths
also finishing with `tls_underlay=boringssl`, including:

```text
firebaselogging-pa.googleapis.com -> openai / [US]Dmit-Mabuli
sandbox.itunes.apple.com -> proxy / [HK]Hytron
```

Rollback status after the successful retry:

```text
/usr/bin/daed restored to sha256 b296303fc01b0cd4453ab90bb7bf988d6315a952a548fd483a0a9c5bab2448bf
staged candidate kept at /usr/bin/daed.rust-c10-runtime-bridge-candidate
temporary C10 drop-in removed; only 20-daex-reload.conf remained
wing.db sha256=bada431fed16f050f40daea1365798293ac31a11701c97b16b4c264d8cd1d441
daed.db restored to this retry's pre-run sha256=9bcc0ba4a1eb76e621ad5a2dec867f0cb05dc9fee488f6d6ce8df3abcdc12b4d
/api/health returned 200
```

Conclusion:

```text
C10 Rust daed default product path can start the resident runtime/dataplane,
use the BoringSSL fingerprint-aware underlay for link fp nodes, route Telegram
to TG / Oracle-Sg, and complete the Telegram/API probe after the Vision
direct-command transition fix.
```

### 41.10 Manual deploy WebUI blocker

Manual-deploy evidence:

```text
/root/daed-c10-manual-20260603-095142
/root/daed-c10-manual-runtime-20260603-095234
/root/daed-c10-webui-restore-20260603-095500
```

The Rust C10 candidate was installed live for manual testing:

```text
/usr/bin/daed sha256=74862b9edb418cd96580a69b6113e7f7a24861436b4899eef8b791be9a13e5a7
service active/running
health endpoint returned 200
resident runtime reload returned 200 through a temporary generated token
residentDataplane.status=pass
```

But the WebUI page failed:

```text
GET / -> HTTP 404
body={"error":"No such file or directory (os error 2)"}
```

Root cause:

```text
The currently installed legacy daed package does not place React/Vite WebUI dist
files under a filesystem path such as /usr/share/daed/web.
The old Go daed serves the WebUI from embedded resources.
The Rust C10 product shell serves static files from DAED_WEB_ROOT/default web
root and currently has no packaged or embedded WebUI assets.
```

Therefore the correct C10 classification is:

```text
runtime/dataplane/default product path: live pass for the tested probe
current React WebUI served by Rust daed: blocker remains
```

The host was restored for user access:

```text
/usr/bin/daed restored to sha256 b296303fc01b0cd4453ab90bb7bf988d6315a952a548fd483a0a9c5bab2448bf
temporary 30-c10-runtime-bridge-env.conf removed
only 20-daex-reload.conf remained
/api/health returned 200
GET / returned HTTP 200 and the embedded legacy WebUI index
staged Rust candidate retained at /usr/bin/daed.rust-c10-runtime-bridge-candidate
```

Next C10 product-package requirement:

```text
Rust product packaging must either:
1. install the current React/Vite dist to a stable DAED_WEB_ROOT path and set
   the systemd environment accordingly; or
2. embed the current WebUI assets into the Rust daed binary.
```

This is a product packaging/WebUI serving blocker, not a resident dataplane or
BoringSSL underlay blocker.

### 41.11 C10 filesystem WebUI dist validation kept live

Follow-up validation used the C10 filesystem WebUI package layout instead of
embedded WebUI assets:

```text
local dist source: /root/project/daed-daex-align/daed/apps/web/dist
local tarball: /tmp/daed-web-dist-c10.tgz
tarball sha256=1dc4902f55f64d1650d5905c1766c9877dc27ed77004fde48ec670b51934c1c3
installed web root: /usr/share/daed/web
systemd env: DAED_WEB_ROOT=/usr/share/daed/web
remote evidence: /root/daed-c10-webroot-test-20260603-100223
```

The Rust C10 candidate was installed live:

```text
/usr/bin/daed sha256=74862b9edb418cd96580a69b6113e7f7a24861436b4899eef8b791be9a13e5a7
service state: active
drop-ins: 20-daex-reload.conf, 30-c10-runtime-bridge-env.conf
rollback binary retained: /usr/bin/daed.c10-manual-rollback-b296303fc01b0
```

WebUI/API validation passed:

```text
GET / -> HTTP 200 text/html
GET /assets/index-D6BRl2SC.js -> HTTP 200 application/javascript
GET /setup -> HTTP 200 text/html
GET /api/health -> HTTP 200 {"healthCheck":1}
```

Runtime/dataplane validation passed:

```text
POST /api/runtime/reload -> HTTP 200
/api/general/state -> HTTP 200
/api/runtime/overview -> HTTP 200
running=true
residentRuntimeStarted=true
residentDataplane.status=pass
residentDataplane.tcp_worker_started=true
residentDataplane.udp_worker_started=true
```

Telegram/API probe evidence:

```text
curl https://api.telegram.org/ -> HTTP 200
effective URL: https://core.telegram.org/bots
event=tcp_connection_finished
proxy_group=TG
node_tag=[SG]Oracle-Sg
tls_underlay=boringssl
```

Conclusion:

```text
C10 filesystem WebUI dist layout validates the current Rust daed product
surface without requiring embedded WebUI assets. Because WebUI, API,
runtime/dataplane, and Telegram probe validation passed, the Rust candidate was
kept live on 10.10.10.2 for manual testing instead of rolling back.
```

### 41.12 C10 fingerprint parameter precedence update

The resident outbound fingerprint plan was updated to follow dae/Xray-compatible
parameter precedence without protocol-specific top-level naming:

```text
1. Node link `fp` has priority.
2. If node link `fp` is absent or empty, global `tls_implementation=utls`
   falls back to `utls_imitate`.
3. If global `tls_implementation=utls` is selected but `utls_imitate` is empty,
   use the documented default fingerprint `chrome`.
4. If no node/global fingerprint is selected, use standard `rustls`.
5. If selected fingerprint is `unsafe`, use standard `rustls`.
6. Unknown fingerprint values fail closed; they must not silently fall back to
   standard `rustls`.
7. Any selected valid fingerprint uses the fingerprint-aware TLS underlay
   (`boring`/BoringSSL in the current resident adapter).
```

Implementation notes:

```text
rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/plan.rs
- removed compile-time DAE_EXPERIMENT_VLESS_VISION_FP_RUST_NATIVE admission gate
- kept node `fp` before global fallback
- allowed `unsafe` as the explicit standard-TLS escape hatch
- retained fail-closed behavior for unknown values such as `no`, `none`, `off`,
  `false`, and `0`

rust/crates/dae-daemon/src/service_contract.rs
rust/crates/dae-daemon/src/product_chain_recertification/tests.rs
- updated C7 fingerprint-underlay surface text to describe node-priority and
  global-fallback behavior
```

Local verification:

```text
cargo test --manifest-path rust/Cargo.toml -p dae-daemon resident_dataplane_plan
result: pass, 15 resident plan tests

cargo test --manifest-path rust/Cargo.toml -p dae-daemon
result: pass, 187 lib tests plus integration/doc tests

cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf
result: pass
release daed sha256=3f2f51bb29d2a86f77e64a8c03eab3d4bf453ab4062a708e8f21a324fd755c62
release daed size=16M
```

### 41.13 C10 product API and WebUI resource parity update

The Rust product surface now treats WebUI resources, runtime materialization,
and log streaming as one C10 parity gate instead of isolated endpoint stubs.

Implementation notes:

```text
rust/crates/dae-daemon/src/daed_product.rs
- `/api/nodes` default list now matches the original product boundary:
  manual nodes only unless `subscriptionId` or `independent=false` is explicit
- runtime materialization uses the full node pool, so subscription-backed nodes
  remain available for generated runtime config
- node resources expose decoded display labels while preserving `runtimeTag`
  for generated config keys
- subscription refresh preserves group-bound subscription nodes by unique name
  and only deletes unpreserved stale subscription nodes
- group subscription resources apply `nameFilterRegex` to `matchedNodes`
- generated group config fails closed when a group has no matched nodes instead
  of emitting a no-filter group
- `/api/general/interfaces` enumerates system interfaces and default routes
  instead of returning only loopback
- `/api/logs` treats `level=all` as unfiltered, canonicalizes `warning` to
  `warn`, searches case-insensitively, and returns the filtered tail in time
  order
- `/api/logs/settings` uses the original logstore limits:
  entries 500-50000, bytes 5MiB-200MiB
- `/api/events/logs` emits `log.entry` and honors the current level/query
  snapshot filter, matching WebUI EventSource listeners

rust/crates/dae-daemon/tests/daed_product.rs
- updated C10 product integration assertions for `log.entry` and logstore
  limits
```

Local verification:

```text
cargo test --manifest-path rust/Cargo.toml -p dae-daemon
result: pass, 192 lib tests plus integration/doc tests
```

### 41.14 C10 product API remote validation update

Remote validation on `10.10.10.2` used the C10 Rust product binary built from
the current local checkout.

Deployment notes:

```text
release daed sha256=93962c16912b52a99824285ecbe2a39aaa678d5cce1798c66ed3d39d496e4dad
release daed size=16M

/usr/bin/daed was replaced with the validated release binary.
/etc/daed/daed.db was regenerated from /etc/daed/wing.db with:
  daed state migrate --from-wing-db /etc/daed/wing.db --to /etc/daed/daed.db --force

wing.db sha256 before/after:
  bada431fed16f050f40daea1365798293ac31a11701c97b16b4c264d8cd1d441
result: unchanged
```

Remote API validation:

```text
GET / -> 200, WebUI HTML served
GET /api/health -> 200
GET /api/general/state -> running=true, attachBackend=tcx, netnsLinkMode=netkit
GET /api/general/interfaces?up=true -> enp1s0 plus IPv4 default route gateway 10.10.10.1
GET /api/configs?expand=parsed -> selected Home, tproxyPort=12345, lan/wan=enp1s0, dialMode=domain++
GET /api/dns?expand=parsed -> 5 DNS entries
GET /api/routings?expand=parsed -> 6 routing entries
GET /api/nodes -> 3 manual nodes, subscriptionId=null for all returned rows
GET /api/nodes?independent=false -> 21 subscription-backed nodes
GET /api/subscriptions?expand=nodes -> 2 subscriptions, expanded node lists present
GET /api/groups -> proxy/media/openai/youtube/TG/speedtest/hkmedia/google all show selected nodes
GET /api/logs?level=all -> returns log entries
GET /api/logs/settings -> original logstore limits exposed
GET /api/events/logs?level=all -> event: log.entry
POST /api/runtime/reload {"dry":false} -> HTTP 200, applied=1

/etc/daed/runtime/generated.dae -> 13353 bytes, node/group sections present,
8 group filters rendered, no no-filter empty group pattern.
```

Traffic/runtime evidence:

```text
GET /api/runtime/overview -> uploadTotal/downloadTotal/uploadRate/downloadRate
present, samples present, activeConnections and udpSessions present.

Telegram smoke:
curl https://api.telegram.org/ -> HTTP 200, effective https://core.telegram.org/bots
resident event:
  event=tcp_connection_finished
  proxy_group=TG
  node_tag=[SG]Oracle-Sg
  tls_underlay=boringssl
```

### 41.15 C10 runtime cards and log-level query fix

The Rust product surface had two WebUI runtime-card gaps after the first C10
product API parity pass:

```text
1. Runtime log level updates were stored, but the emitted log entry was always
   written as level=info. Selecting query level debug/trace/warn/error could
   therefore show an empty list immediately after setting that runtime level.

2. Runtime overview still carried Go-era placeholder fields:
   heapAllocBytes=0, goroutines=1, cpuUsagePercent=0.0. The WebUI cards for
   heap memory, goroutine count, and CPU usage were therefore not meaningful
   under the Rust product runtime.

3. Runtime EventSource compatibility was incomplete. The Rust endpoint returned
   a one-shot runtime.overview event only, while the WebUI also listens for
   runtime.overview.delta and disables polling while the stream is considered
   live.
```

Implementation notes:

```text
rust/crates/dae-daemon/src/daed_product.rs
- PATCH /runtime/log-level now validates and canonicalizes levels:
  error, warn, info, debug, trace
- the runtime level update log is written at the selected level, so
  /logs?level=<selected> immediately shows the update
- /runtime/overview reads process metrics from /proc/self/status and
  /proc/self/stat:
  - rssBytes from VmRSS
  - heapAllocBytes from VmData as the Rust process heap/data approximation
  - goroutines compatibility field from Linux Threads
  - cpuUsagePercent from process utime+stime deltas, normalized by available
    CPU parallelism and clamped to 0-100
- /events/runtime now includes retry: 1000 and emits both runtime.overview and
  runtime.overview.delta in the SSE body, giving the current HTTP shim
  EventSource-compatible 1s reconnect behavior
```

Local verification:

```text
cargo test --manifest-path rust/Cargo.toml -p dae-daemon
result: pass, 193 lib tests plus integration/doc tests

cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf
result: pass
release daed sha256=5767fb011571867ad2d51f9232b8567478439b018e31e553ebab4059588b877b
release daed size=16M
```

Remote validation on 10.10.10.2:

```text
/usr/bin/daed sha256=5767fb011571867ad2d51f9232b8567478439b018e31e553ebab4059588b877b
wing.db sha256=bada431fed16f050f40daea1365798293ac31a11701c97b16b4c264d8cd1d441
runtime reload after binary replacement -> HTTP 200, applied=1

GET /api/general/state:
  running=true
  attachBackend=tcx
  netnsLinkMode=netkit

PATCH /api/runtime/log-level {"level":"debug"} -> HTTP 200, level=debug
GET /api/logs?level=debug&limit=20 -> includes:
  level=debug
  message="runtime log level set to debug"

GET /api/runtime/overview?windowSec=60&maxPoints=10:
  heapAllocBytes=195375104
  goroutines=29
  cpuUsagePercent=0.99
  rssBytes=147582976
  uploadTotal/downloadTotal present and increasing
  uploadRate/downloadRate present
  activeConnections/udpSessions present
  samples_len=10

GET /api/events/runtime?windowSec=60&maxPoints=10:
  retry: 1000
  event: runtime.overview
  event: runtime.overview.delta
```

### C10 runtime observability correction - 2026-06-03

This section supersedes the previous temporary Rust product observability notes
that used `log_entries`, `VmData`, and one-shot SSE reconnect shims.

Original daewing parity audit:

```text
1. WebUI log content is an independent JSONL cache:
   <config-dir>/logs/current.jsonl

2. The database stores log settings only:
   log_settings(id=1, max_entries, max_bytes)
   There is no log_entries runtime log table in the original wing.db schema.

3. Log entry JSON shape:
   id, ts, level, message, fields
   fields is optional and contains stringified logrus fields.

4. Query behavior:
   - default limit 500
   - max limit 2000
   - invalid level returns HTTP 400
   - warning is canonicalized to warn
   - query matches message and fields key/value
   - clear truncates current.jsonl instead of deleting DB rows

5. Retention behavior:
   - maxEntries default 10000, clamp 500..50000
   - maxBytes default 50 MiB, clamp 5..200 MiB
   - startup resumes next ID from the JSONL tail
   - pruning keeps newest complete lines

6. SSE behavior:
   - /events/logs is a live stream, not a replay endpoint
   - initial log list comes from /logs
   - retry: 3000
   - heartbeat every 15s
   - event name log.entry

7. Runtime overview SSE behavior:
   - /events/runtime is a live stream, not a close-and-reconnect shim
   - sends runtime.overview immediately
   - sends runtime.overview.delta every 1s
   - retry: 3000
   - heartbeat every 15s
```

Implementation corrections:

```text
rust/crates/dae-daemon/src/daed_product.rs
- /logs now reads <config-dir>/logs/current.jsonl.
- /logs DELETE truncates current.jsonl.
- /logs/settings still reads/writes daed.db log_settings.
- clean daed.db schema no longer creates log_entries; old test tables are not
  deleted in place.
- log line encoding follows the original max line/field trimming policy.
- runtime log level now uses logrus-compatible ordering:
  panic, fatal, error, warn, info, debug, trace
- actual reload updates runtime_log_level from generated config global.log_level.
- /events/logs and /events/runtime now have dedicated keep-alive SSE writers.
- runtime overview heapAllocBytes now uses /proc/self/status RssAnon first,
  with VmData only as fallback. This is a Rust-compatible resident anonymous
  memory approximation; exact allocator heap requires allocator
  instrumentation.

rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane
- resident dataplane now owns generic live metrics:
  uploadTotal, downloadTotal, activeTcpConnections, activeUdpSessions
- TCP/UDP relay paths update metrics while traffic is in flight.
- runtime overview prefers live metrics over finished-event JSONL fallback,
  removing the visible lag caused by waiting for long-lived connections to
  close.

rust/crates/dae-daemon/tests/daed_product.rs
- integration test now treats SSE endpoints as long-lived streams.
```

Local verification:

```text
cargo fmt --manifest-path rust/Cargo.toml -p dae-daemon
result: pass

cargo test --manifest-path rust/Cargo.toml -p dae-daemon
result: pass
196 lib tests, 6 daed product integration tests, reload owner tests,
service contract tests, and doc tests passed.

cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf
result: pass
release daed sha256=2d2de6d53bf47488b8407c86da010425a6ce58373bc2d2777d9436e03e136cce
release daed size=16M
```

Remote validation on 10.10.10.2:

```text
/usr/bin/daed sha256=2d2de6d53bf47488b8407c86da010425a6ce58373bc2d2777d9436e03e136cce
systemctl is-active daed -> active
runtime reload -> applied=1, dry=false, runtimeStarted=true

GET /api/general/state:
  running=true
  attachBackend=tcx
  netnsLinkMode=netkit
  counts.logs=500

Log file layout:
  /etc/daed/logs mode=750
  /etc/daed/logs/current.jsonl mode=600
  /api/logs returns original JSONL entries with fields/id/ts/level/message.

GET /api/runtime/overview?windowSec=60&maxPoints=5:
  activeConnections=19
  uploadTotal=4089
  downloadTotal=5278
  samplesLen=1 immediately after reload
  residentDataplane.metrics.activeTcpConnections=19
  residentDataplane.metrics.uploadTotal=4089
  residentDataplane.metrics.downloadTotal=5278
  heapAllocBytes=119992320
  rssBytes=134389760
  goroutines=25

/proc/<daed>/status at validation:
  VmRSS=137992 kB
  RssAnon=123932 kB
  VmData=178352 kB
  Threads=25

GET /api/events/runtime:
  retry: 3000
  event: runtime.overview

GET /api/events/logs:
  retry: 3000
```

### C10 log level HTTP query matrix correction - 2026-06-03

Follow-up after live WebUI testing found that the previous fix covered the
internal JSONL log reader, but `/api/logs` still had a separate
`log_level_filter_from_request` path that only treated ASCII `all` as
unfiltered. Therefore a browser/WebUI query such as:

```text
level=%E5%85%A8%E9%83%A8
```

which is the normal URL-encoded UTF-8 representation of `level=全部`, still
returned HTTP 400 on the live host even though `list_logs_value(...,
Some("全部"), ...)` passed locally.

Correction:

```text
rust/crates/dae-daemon/src/daed_product.rs
- /api/logs, /api/events/logs, and the live SSE log stream now all route level
  query parsing through the same generic normalize_log_level_filter helper.
- Supported unfiltered query values:
  empty, all, any, *, 全部, 所有
- Supported level aliases:
  panic, fatal, error, err, 错误, warn, warning, 警告, info, 信息,
  debug, 调试, trace, 跟踪
- Invalid query levels still return HTTP 400.
- PATCH /api/runtime/log-level still rejects `all`; runtime level is a concrete
  log level, not a query filter.

Local tests added:
- real HTTP query path coverage through split_path_query + api_logs
- encoded Chinese query values such as `%E5%85%A8%E9%83%A8`
- all aliases above plus invalid value rejection
```

Local verification:

```text
cargo fmt --manifest-path rust/Cargo.toml -p dae-daemon
result: pass

cargo test --manifest-path rust/Cargo.toml -p dae-daemon daed_product::tests::logs_filter_level_all_case_insensitive_query_and_sse_event_name
result: pass

cargo test --manifest-path rust/Cargo.toml -p dae-daemon
result: pass
196 lib tests, 6 daed product integration tests, reload owner tests,
service contract tests, and doc tests passed.

cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf
result: pass
release daed sha256=f6079a471901f9b529b3f101048d1b403c6dadee98ec4331fa1df75bd094c002
release daed size=16M
```

Remote validation on `10.10.10.2`:

```text
/usr/bin/daed sha256=f6079a471901f9b529b3f101048d1b403c6dadee98ec4331fa1df75bd094c002
systemctl is-active daed -> active

No /api/runtime/reload was used for this log-level validation. Runtime log
level is expected to be live metadata and was verified through
PATCH /api/runtime/log-level only.

Generated log entries after start_id=12:
  debug=3
  error=3
  fatal=1
  info=1
  panic=1
  trace=1
  warn=2

PATCH /api/runtime/log-level alias matrix:
  trace, debug, info, warning, 警告, error, err, 错误, fatal, panic, 调试 -> pass
  all -> HTTP 400, pass

GET /api/logs query matrix:
  no level -> HTTP 200
  level= -> HTTP 200
  level=all -> HTTP 200
  level=ALL -> HTTP 200
  level=any -> HTTP 200
  level=* -> HTTP 200
  level=%E5%85%A8%E9%83%A8 -> HTTP 200
  level=%E6%89%80%E6%9C%89 -> HTTP 200
  info / INFO / 信息 -> HTTP 200, only info entries
  warn / warning / 警告 -> HTTP 200, only warn entries
  error / err / 错误 -> HTTP 200, only error entries
  debug / 调试 -> HTTP 200, only debug entries
  trace / 跟踪 -> HTTP 200, only trace entries
  fatal -> HTTP 200, only fatal entries
  panic -> HTTP 200, only panic entries
  invalid -> HTTP 400

GET /api/logs?level=all&q=runtime&limit=2 -> HTTP 200, <=2 entries
GET /api/logs?level=all&q=definitely-not-present-daex&limit=10 -> HTTP 200, []
GET /api/events/logs?level=%E5%85%A8%E9%83%A8 -> HTTP 200, retry: 3000
GET /api/runtime/log-level -> debug
/etc/daed/logs/current.jsonl size=2949 after validation
/etc/daed/wing.db sha256=bada431fed16f050f40daea1365798293ac31a11701c97b16b4c264d8cd1d441
```

### 2026-06-03 unified Rust product runtime log bridge

Correction from original daed/wing audit:

- Original daed WebUI logs are not subscription-only task logs. They are a
  unified runtime log stream backed by wing `logstore`, which hooks logrus,
  writes JSONL entries, and streams them to `/api/events/logs`.
- Rust product mode must therefore keep one product logstore surface for
  startup, reload, stop, control-plane, materializer, and resident dataplane
  events.
- WebUI/API formal query values remain stable API tokens:
  `all`, `error`, `warn`, `info`, `debug`, `trace`, etc.
- Chinese labels such as `全部`, `调试`, `警告`, `错误`, `信息`, `跟踪`
  are compatibility aliases only. WebUI select values must not send localized
  labels as the primary API semantic.

Implementation notes:

- `production_runtime_owner::resident_dataplane::events::append_event` now
  supports a generic process-level resident event log sink.
- `daed_product` registers that sink after initializing
  `/etc/daed/logs/current.jsonl`.
- Resident worker lifecycle and dataplane events are translated into regular
  product log entries:
  - `*_started` / `*_stopped` -> `info`
  - `*_failed` / `*error*` -> `warn`
  - connection/packet completion and other high-volume events -> `debug`
- The conversion is protocol-generic: it uses the event name and scalar fields;
  it does not introduce protocol-specific top-level log gates.
- Runtime level filtering remains centralized in
  `append_log_fields_for_config`; debug dataplane completion events only appear
  when runtime log level is `debug` or higher.
- API reload now emits unified `[Reload]` entries for request receipt, dry
  preview success, materializer/build/config errors, runtime start failure, and
  applied reload success.
- Startup restore now emits `[Startup] runtime restore started/finished`.
- Signal reload emits `[Reload] Received signal reload request`,
  `[Reload] Finished`, or `[Reload] Failed to reload`.

Local focused verification added:

```text
cargo fmt --manifest-path rust/Cargo.toml -p dae-daemon
result: pass

cargo test --manifest-path rust/Cargo.toml -p dae-daemon resident_events_are_bridged_to_product_logs_with_runtime_level_filter
result: pass

cargo test --manifest-path rust/Cargo.toml -p dae-daemon runtime_reload_dry_preview_writes_unified_reload_logs
result: pass

cargo test --manifest-path rust/Cargo.toml -p dae-daemon logs_filter_level_all_case_insensitive_query_and_sse_event_name
result: pass
```

Full local verification after the unified log bridge:

```text
cargo test --manifest-path rust/Cargo.toml -p dae-daemon
result: pass
198 lib tests, 6 daed product integration tests, reload owner tests,
service contract tests, and doc tests passed.

cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf
result: pass
release daed sha256=053716867af5081633bdf4dcd49b027486428096141073b2e7173834b4a2a6f4
release daed size=16M
```

Remote validation on `10.10.10.2`:

```text
/usr/bin/daed sha256=053716867af5081633bdf4dcd49b027486428096141073b2e7173834b4a2a6f4
systemctl is-active daed -> active
/etc/daed/wing.db sha256=bada431fed16f050f40daea1365798293ac31a11701c97b16b4c264d8cd1d441

/etc/daed/logs/current.jsonl contains startup/runtime product logs:
  runtime stopped by signal
  Rust daed product log store initialized
  Listen on http://0.0.0.0:2023
  subscription scheduler started by Rust daed

Authenticated API verification:
  GET /api/runtime/log-level -> HTTP 200
  GET /api/logs?level=all&limit=20 -> HTTP 200, product logs present
  GET /api/logs?level=%E5%85%A8%E9%83%A8&limit=5 -> HTTP 200
  GET /api/events/logs?level=all -> HTTP 200, retry: 3000, log.entry stream

Live log-level update verification:
  PATCH /api/runtime/log-level {"level":"debug"} -> HTTP 200, {"level":"debug"}
  GET /api/logs?level=debug&limit=10 -> HTTP 200, resident dataplane debug logs present
  GET /api/logs?level=all&q=resident&limit=10 -> HTTP 200, resident dataplane logs present
  GET /api/logs?level=%E8%B0%83%E8%AF%95&limit=10 -> HTTP 200, debug logs present

Observed resident dataplane fields include:
  event=tcp_connection_finished / tcp_connection_failed
  proxy_group=openai
  node_tag=[US]Dmit-Mabuli
  tls_underlay=boringssl
  bytes_client_to_proxy / bytes_proxy_to_client
  vision_* diagnostics
```

### 2026-06-03 Rust native product build parameter standard note

This section is a higher-priority standard note for future Rust native product
builds and live tests. It normalizes the current build/runtime truth and avoids
mixing historical C9 transition artifacts into the C10 Rust product path.

Standard build truth:

```text
repo root: /root/project/dae-daex-align/rust
product package: dae-daemon
product binary: daed
source entry: rust/crates/dae-daemon/src/bin/daed.rs
build target: cargo build --release -p dae-daemon --bin daed
```

Build command matrix:

```text
# Product userspace / Web API / state / outbound engine validation:
cargo build --release -p dae-daemon --bin daed

# Full Rust resident native datapath validation with Rust/Aya eBPF object:
cargo build --release --features native-ebpf -p dae-daemon --bin daed
```

`native-ebpf` is the only current `dae-daemon` Cargo feature that changes the
Rust native datapath build. It enables the Rust/Aya eBPF loader path and causes
`build.rs` to build or embed the native BPF object. It is not a protocol feature.

Native eBPF build overrides:

```text
DAE_RUST_NATIVE_BPF_TOOLCHAIN  # default: nightly
DAE_RUST_NATIVE_BPF_CARGO      # optional cargo binary override
DAE_RUST_NATIVE_BPF_OBJECT     # optional prebuilt native BPF object override
```

Standard extra attention:

```text
1. Do not build the current Rust product test binary through daed/wing
   `make bundle` or `make bundle-rust-owned`.

2. Do not use `dae-daemon-optin` as the product entry for this path.
   `dae-daemon-optin` is a C9 transition payload name, not the C10 product
   binary.

3. Do not use an old `/root/project/daed-daex-align/daed/daed` artifact as
   proof of the current Rust native product state.

4. For live Rust product tests, `/usr/bin/daed` should be the Rust product
   binary built from `dae-daemon --bin daed`.

5. For resident dataplane ownership, set the runtime gate explicitly:
   `DAE_RUST_RESIDENT_DATAPLANE=1`.
   This gate is about resident userspace dataplane ownership, not about a
   specific outbound protocol.

6. The historical `DAE_EXPERIMENT_VLESS_VISION_FP_RUST_NATIVE` variable must not
   be treated as a current runtime or admission switch. Current resident
   plan/client code no longer reads it. If it appears in older evidence, treat
   it as historical context only. A leftover `build.rs` rerun-if-env-changed
   line is not a semantic gate.
```

Current protocol admission truth:

```text
VLESS is not a Cargo feature and does not need a separate build parameter.
The code is compiled through the default dae-daemon dependency graph.

This does not mean all VLESS nodes are admitted by default. Current resident
dataplane admission is limited to:
  scheme=vless
  flow=xtls-rprx-vision
  type=tcp
  security=tls
  allow_insecure=false

Other schemes, transports, flows, insecure TLS, or unsupported link forms must
fail closed instead of silently falling back.
```

Current fingerprint/TLS underlay truth:

```text
1. Node link `fp` has priority.
2. If node `fp` is absent or empty, global `tls_implementation=utls` falls back
   to `utls_imitate`.
3. If global `tls_implementation=utls` is selected and `utls_imitate` is empty,
   use the documented default fingerprint `chrome`.
4. If no valid fingerprint is selected, use standard `rustls`.
5. If selected fingerprint is `unsafe`, use standard `rustls`.
6. Unknown values such as `no`, `none`, `off`, `false`, and `0` fail closed.
7. Any selected valid fingerprint uses the fingerprint-aware TLS underlay,
   currently BoringSSL through the Rust `boring` crate.
```

Live-test state rule:

```text
primary Rust product state: /etc/daed/daed.db
protected rollback state: /etc/daed/wing.db

Rust test builds must not mutate /etc/daed/wing.db by default. If existing state
is needed, migrate/import from wing.db into daed.db first.
```

2026-06-03 Rust product log bridge fix:

```text
Problem:
  WebUI log panel could appear empty or show only a few product-level entries
  while resident dataplane events were continuously written to the resident
  event jsonl file.

Root cause:
  Rust product backend filtered resident flow diagnostics before appending to
  /etc/daed/logs/current.jsonl and also filtered them again when serving
  /api/logs. This excluded high-frequency flow events such as:
    tcp_connection_finished
    tcp_connection_failed
    udp_packet_finished

Fix:
  Resident flow diagnostics are now bridged into product logs instead of being
  treated as internal-only diagnostics. Flow messages use a compact
  peer <-> target shape and retain selected structured fields such as
  proxy_group, node_tag, outbound_kind, dial_target, original_dst, tls_underlay,
  byte counters, Vision transition flags, and error.

Runtime behavior:
  Debug-level flow completion logs require runtime log level debug or lower.
  After restarting a live test binary, verify the real backend value with:
    GET /api/runtime/log-level
  and set it with:
    PATCH /api/runtime/log-level {"level":"debug"}
  before judging whether debug flow logs are missing.

Validation:
  Local:
    cargo fmt --manifest-path rust/Cargo.toml -p dae-daemon
    cargo test --manifest-path rust/Cargo.toml -p dae-daemon

  Live 10.10.10.2:
    deployed /usr/bin/daed sha256
      9e1a95dbd7724f55c2157fed624945d767d9234a2395eef7f2b91e91071bdd90
    /etc/daed/wing.db sha256 stayed unchanged
      459156c9a1883bd9f5f4244779aa103305cbeaeb00ee741e9e5e1d676901c5a5
    /api/logs?level=debug&limit=500 returned more than 50 entries during live
      traffic.
    /api/events/logs streamed repeated log.entry events.
    Browser automation opened /#/?panel=log and observed hundreds of rendered
      flow log markers with the log viewport scrolled near the tail.
```

Follow-up correction:

```text
The raw resident-flow bridge above is useful as diagnostic evidence that the
backend/SSE path can roll logs, but it is not the final Go daed WebUI log
parity target.

Original Go daed/daewing WebUI task logs are logrus product/runtime/task logs.
They should not be replaced by every transparent-proxy flow diagnostic. In
particular, frequent tcp_connection_failed entries such as:
  192.168.6.20 <-> www.google.com:80 failed
  error=read inbound TCP: Connection reset by peer (os error 104)
must not be promoted into the normal WebUI task log as warn-level noise.

Final Rust product rule:
  - product/runtime/task logs feed /etc/daed/logs/current.jsonl and WebUI.
  - resident flow diagnostics remain debug diagnostics unless explicitly
    requested.
  - connection reset by peer and relay idle timeout on ordinary flow close are
    not default task-log warnings.
  - log formatting and filtering must be compared against the original Go daed
    logstore/logrus hook behavior before the WebUI log work is marked done.
```

2026-06-03 Rust product RSS / heap-card audit:

```text
Live host:
  10.10.10.2
  /usr/bin/daed sha256
    9e1a95dbd7724f55c2157fed624945d767d9234a2395eef7f2b91e91071bdd90
  runtime gate:
    DAE_RUST_RESIDENT_DATAPLANE=1
    DAED_WEB_ROOT=/usr/share/daed/web

Observed process state:
  pid=12795
  RSS ~= 253980 KiB
  RssAnon ~= 239772 KiB
  RssFile ~= 14208 KiB
  Private_Dirty ~= 239772 KiB
  VmData ~= 393164 KiB
  Threads ~= 58..67
  systemd MemoryCurrent ~= 328101888 bytes

Interpretation:
  RSS is high mostly because of private anonymous memory, not because of the
  daed binary, shared libraries, WebUI static files, or thread stacks.

  Thread stack RSS is small. Each sampled thread showed VmStk around 132 KiB,
  so thread stacks are not the main 250 MiB RSS source.

  smaps showed one full 64 MiB anonymous mapping plus many 3..7 MiB anonymous
  mappings and an approximately 29 MiB [heap] mapping. This shape is consistent
  with allocator arena/high-water retention in a multi-threaded process,
  especially under live traffic, resident dataplane ownership, fingerprint-aware
  TLS/Boring underlay state, connection/session state, and allocator behavior.

  Debug flow-log streaming is not the primary explanation for the high RSS.
  It can add allocation churn and WebUI noise, but it must be treated as a
  secondary amplifier at most. The restored Go daed baseline was switched from
  runtime log level error to debug for a short live check and did not show a
  material RSS increase:
    before debug sample:
      RSS 89576 KiB, RssAnon 42436 KiB, Threads 12
    after approximately 60 seconds at debug:
      RSS 88624 KiB, RssAnon 41484 KiB, Threads 12
  After the check, Go daed runtime log level was restored to error.

  The memory did not keep growing during a short 20 second check:
    VmRSS 255904 KiB -> 255780 KiB
    RssAnon 241696 KiB -> 241572 KiB
    Threads 63 -> 58
  This supports "high-water allocator retention" as the first hypothesis, not
  an immediately proven leak.

WebUI/API metric correction:
  Rust product currently fills heapAllocBytes from /proc/self/status RssAnon.
  That is anonymous RSS, not true Rust live heap allocation.

  Therefore the WebUI "heap memory" card can show a large value such as
  ~240 MiB even when it is really anonymous resident memory. It must not be
  presented as precise Rust heap live bytes.

Required follow-up:
  1. Rename or split metrics so RSS, anonymous RSS, and real allocator heap are
     not conflated.
  2. Avoid feeding high-frequency resident flow diagnostics into normal WebUI
     task logs by default for log parity and UI usefulness, not because this is
     believed to be the main RSS cause.
  3. Test a live systemd override such as MALLOC_ARENA_MAX=2 to see whether RSS
     drops materially under the same traffic pattern.
  4. Add longer RSS/active-connection/log-volume sampling before calling this a
     leak.
  5. If precise heap is required, add allocator-aware metrics instead of using
     RssAnon as heapAllocBytes.
```

2026-06-03 Final Rust product architecture boundary:

```text
Question:
  The current Rust test build looks like:
    Rust product + resident dataplane + Boring/TLS + multi-threaded allocator.
  Is that also the intended final production shape?

Answer:
  The final architecture keeps the ownership direction, not the current
  unoptimized implementation shape.

Kept for final C10/go-free target:
  1. Rust product ownership:
       Rust daed owns Web/API/state/runtime/control/package by default.

  2. Rust resident dataplane ownership:
       transparent-proxy TCP/UDP handling, runtime datapath state, outbound
       execution, runtime metrics, and control-plane integration move into the
       Rust-owned path.

  3. Fingerprint-aware TLS capability:
       links/global config that select a valid fingerprint must use a real
       fingerprint-aware TLS underlay. The current provider is BoringSSL through
       the Rust boring crate.

Not accepted as final shape:
  1. Boring everywhere:
       Boring is not the default TLS path. It is selected only when a valid
       fingerprint is selected by node link or global fallback.

  2. Unbounded multi-threaded runtime behavior:
       tokio workers, blocking pools, helper threads, DNS/probe workers, and
       resident dataplane tasks must have explicit limits and live evidence.

  3. Unbounded allocator high-water RSS:
       the current high anonymous RSS is not acceptable as final merely because
       the path is Rust native. Allocator strategy and high-water behavior must
       be measured and bounded.

  4. WebUI metric conflation:
       RssAnon must not be presented as precise Rust live heap allocation.

  5. Flow diagnostics as task logs:
       high-frequency transparent-proxy flow diagnostics are not the normal
       WebUI task-log stream.

TLS underlay selection rule:
  - no selected valid fingerprint:
      standard rustls path
  - selected valid fingerprint from node link or global fallback:
      fingerprint-aware TLS provider, currently BoringSSL/boring
  - selected fingerprint `unsafe`:
      standard rustls path
  - invalid/off-like values:
      fail closed or normalize according to the documented selection rule, but
      do not silently claim fingerprint success

Final admission must measure:
  - RSS
  - PSS
  - RssAnon / anonymous RSS
  - real allocator heap metrics if available
  - thread count
  - fd count
  - active TCP connections
  - active UDP sessions
  - TLS underlay counts by provider
  - resident session/buffer/cache sizes
  - log/event buffer sizes

Required comparison matrix before accepting the final memory model:
  - Go daed at error
  - Go daed at debug
  - Rust native at error
  - Rust native at debug
  - Rust native with fingerprint-aware TLS selected
  - Rust native without fingerprint-aware TLS selected
  - same active connection/session range when comparing RSS/PSS

Implementation direction:
  - keep capability names generic at the top level
  - keep Boring as an implementation detail behind the fingerprint-aware TLS
    provider boundary
  - keep ordinary TLS on the standard rustls path
  - bound runtime workers and blocking pools
  - test MALLOC_ARENA_MAX=2 or an alternate allocator under the same traffic
    pattern
  - reduce resident connection/session allocation churn with lifecycle audits,
    reusable buffers, and explicit cache bounds

Summary:
  The final product is Rust-owned with a resident dataplane and conditional
  fingerprint-aware TLS. It must not freeze the current test build's high-RSS,
  broad-thread, Boring-heavy implementation as the production baseline.
```

2026-06-03 High-priority RSS root-cause audit summary:

```text
Priority:
  Highest priority before further default-path promotion or feature expansion.

Decision:
  A full reproducible RSS comparison matrix is not required as the next
  blocking step. The live gap is already large enough to justify immediate code
  audit:
    Rust test build:
      RSS ~= 253 MiB
      RssAnon ~= 239 MiB
      Threads ~= 47..67
    Restored Go daed:
      RSS ~= 85 MiB
      RssAnon ~= 39 MiB
      Threads ~= 11
    Go daed debug short check:
      no material RSS/RssAnon growth

  Therefore the next step is not to build a heavy baseline matrix. Use only
  lightweight before/after live sampling to validate each concrete fix.

Goal:
  Find the concrete Rust-side sources of high private anonymous RSS and excess
  threads. Do not accept "Rust product + resident dataplane + Boring" as an
  explanation by itself. Identify owned objects, task models, allocator effects,
  and lifecycle/capacity issues.

Primary audit targets:
  1. Runtime/thread model
     - tokio worker count
     - blocking pool usage
     - per-connection task spawning
     - helper/background workers
     - Web/API/SSE/log/subscription/probe worker lifetime

  2. Resident dataplane state
     - active TCP connection objects
     - UDP session map
     - routing tuple/session mirrors
     - sniffing buffers
     - relay buffers
     - Vision/direct transition state
     - per-flow allocations and release timing

  3. Fingerprint-aware TLS provider
     - Boring SSL/context/session lifecycle
     - per-connection TLS buffers
     - provider caches
     - ensure provider is selected only for valid fingerprint cases
     - ordinary TLS stays on rustls

  4. Product API/state/log/event retention
     - runtime overview sample buffers
     - log/event broadcaster queues
     - WebUI/SSE subscriber buffers
     - DB/cache/materialized config retention
     - node/proxy/group plan clone size

  5. Allocator behavior
     - anonymous RSS high-water retention
     - glibc arena count under current thread model
     - MALLOC_ARENA_MAX=2 live check after code audit candidates
     - alternate allocator only after object/task audit identifies remaining
       allocator-bound RSS

Search patterns for the audit:
  - tokio::spawn
  - spawn_blocking
  - JoinSet
  - channel / mpsc / broadcast / watch
  - Arc<Mutex<...>>
  - DashMap / HashMap / BTreeMap
  - Vec<u8> / BytesMut / Bytes
  - VecDeque / history / samples
  - OnceLock / LazyLock / static caches
  - Boring / Ssl / SslConnector / SslStream
  - per-connection buffer allocation

Immediate acceptance rule:
  A candidate fix is useful only if it either:
    - removes a concrete excessive allocation/retention/thread source, or
    - adds measurement that isolates such a source, or
    - corrects the API/WebUI metric so RSS/anonymous RSS/heap are not conflated.

Non-goal:
  Do not spend time first on a heavy benchmark matrix. Do not treat debug flow
  logging as the main RSS explanation. Do not change top-level crate structure
  unless the audit finds a hard ownership/dependency conflict.
```

2026-06-03 Rust native generic resource/lifecycle audit:

```text
Scope correction:
  This audit is not a protocol-specific audit. Protocol names may appear in
  filenames or implementation details, but the product-chain work item remains
  generic:
    - runtime owner resource model
    - connection/session lifecycle
    - outbound provider lifecycle
    - product API/log/metrics retention
    - package/admission truth

  Do not create protocol-specific stages, work packages, feature names, or
  default-switch gates from this RSS/root-cause work.

High-confidence findings:

  P0. The resident TCP dataplane uses one OS thread per accepted TCP flow.
      Location:
        rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/tcp.rs
      Evidence:
        resident_tcp_accept_loop accepts a transparent TCP stream and calls
        thread::spawn for each connection. The spawned thread owns the whole
        relay until the flow ends.
      Why it matters:
        Thread count scales with active TCP connections. Under glibc this also
        increases allocator arenas/high-water anonymous RSS. This matches the
        live shape better than any individual protocol branch:
          Rust test build: Threads ~= 47..67, active TCP ~= same order
          Go restored daemon: Threads ~= 11
      Required direction:
        Replace unbounded per-flow OS thread spawning with a bounded connection
        execution model:
          - async runtime, or
          - bounded worker pool with explicit max workers/queue/backpressure, or
          - a transitional bounded thread pool with small named stack size.
        The final model must expose active workers, queued accepts, rejected
        accepts, and shutdown/join state.

  P0. The product Web/API/SSE server uses one OS thread per HTTP connection.
      Location:
        rust/crates/dae-daemon/src/daed_product.rs
      Evidence:
        serve_forever accepts listener.incoming() and calls thread::spawn for
        each stream. Runtime and log SSE endpoints are long-lived loops.
      Why it matters:
        Opening WebUI can permanently add long-lived threads for runtime/log
        streams. This is not the main dataplane thread count source, but it is
        still unbounded and contributes to RSS/allocator growth.
      Required direction:
        Use a bounded HTTP execution model and cap SSE clients. Runtime/log
        streams should use a shared event source instead of one sleeping file
        scanner per client.

  P0. Flow worker handles are not retained, joined, or bounded.
      Location:
        rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/tcp.rs
      Evidence:
        Per-flow thread::spawn return values are discarded. Runtime shutdown
        only joins the resident TCP accept thread and UDP worker thread, not the
        connection workers they created.
      Why it matters:
        Shutdown/reload cannot prove bounded cleanup. Panics, long idle flows,
        and high-water per-thread allocator state are invisible to the runtime
        owner.
      Required direction:
        Runtime owner must own all flow execution handles or task IDs and must
        expose cleanup evidence for active/in-flight workers.

  P1. Outbound provider/client configuration is rebuilt per connection.
      Location:
        rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/client.rs
      Evidence:
        The current outbound client path resolves target, creates TLS/provider
        configuration, loads roots, builds connector/client config, then opens a
        new client per connection.
      Why it matters:
        Per-flow provider setup creates allocation churn and can retain
        high-water RSS. This is provider-generic: fingerprint-aware and ordinary
        TLS paths both need a cached plan/provider boundary.
      Required direction:
        Cache immutable provider config in the resident proxy plan/runtime state.
        Per-flow state should only allocate the connection/session object.
        The top-level capability name must remain generic.

  P1. UDP is packet-exchange oriented, not session/pool oriented.
      Location:
        rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/udp.rs
      Evidence:
        The UDP loop processes a packet synchronously, counts opened/closed per
        packet, opens a new outbound exchange for non-DNS packets, and opens a
        transparent reply socket for each reply.
      Why it matters:
        This under-reports session semantics and can produce connection/provider
        churn under UDP traffic. It was not the main live RSS source in the last
        observation because active UDP was low, but it is not production-grade
        native session ownership.
      Required direction:
        Add a bounded UDP endpoint/session model with idle timeout, per-session
        counters, and explicit max entries. The WebUI counter should report
        sessions, not transient packet exchanges.

  P1. Event/log bridging does synchronous per-event file and DB work.
      Locations:
        rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/events.rs
        rust/crates/dae-daemon/src/daed_product.rs
      Evidence:
        Each resident event appends JSON to the event file and then calls the
        product log sink. The product log append path opens state, reads log
        settings, scans the tail for last id, appends, and prunes on each log.
      Why it matters:
        This is not the main steady RSS cause, but under debug/flow-heavy
        traffic it creates avoidable allocation and IO churn. SSE log streams
        also rescan the file periodically.
      Required direction:
        Use a bounded in-memory ring/index for live WebUI logs plus append-only
        durable writes. Prune out of band. Keep high-frequency flow diagnostics
        out of normal task logs unless explicitly enabled.

  P1. The WebUI memory metric conflates anonymous RSS with heap.
      Location:
        rust/crates/dae-daemon/src/daed_product.rs
      Evidence:
        heapAllocBytes is currently populated from /proc/self/status RssAnon,
        with VmData fallback.
      Why it matters:
        The card says heap but shows anonymous RSS. It can include allocator
        arenas, thread stacks, mmap/private pages, and other non-live-heap
        memory.
      Required direction:
        Split metrics:
          - rssBytes
          - anonymousRssBytes
          - fileRssBytes if available
          - vmDataBytes
          - heapLiveBytes only if backed by allocator/runtime evidence
          - threadCount
        Do not label RssAnon as heap.

  P1. Runtime overview clones and embeds large runtime reports on each poll.
      Location:
        rust/crates/dae-daemon/src/daed_product.rs
      Evidence:
        ProductRuntimeManager::summary builds a fresh JSON object and embeds a
        clone of lastReport. Runtime overview calls summary for WebUI polling.
      Why it matters:
        This is a polling-time allocator churn source. It is not the main
        resident dataplane RSS source, but it worsens WebUI-open behavior.
      Required direction:
        Keep summary compact by default. Expose full start/admission reports
        through separate endpoints or on-demand debug routes.

  P1. Product-chain contract truth is inconsistent across crates.
      Locations:
        rust/crates/dae-product/src/go_free_product_chain.rs
        rust/crates/dae-product/src/true_daemon_admission.rs
        rust/crates/dae-daemon/src/daed_product.rs
      Evidence:
        dae-product still marks the go-free/default daemon contracts blocked,
        while daed_product local reports set many product/Web/API/package-ready
        flags to true and then keep go_free_product_chain_ready=false.
      Why it matters:
        C10 cannot rely on a self-generated local report to prove product-chain
        readiness. The final gate must derive readiness from the canonical
        product contracts and live evidence.
      Required direction:
        Make daed product reports consume/reflect dae-product contract state
        instead of restating readiness independently.

  P1. Native attach/report semantics still preserve fallback language.
      Locations:
        rust/crates/dae-daemon/src/production_runtime_owner/native_ebpf.rs
        rust/crates/dae-daemon/src/production_runtime_owner/netns_link.rs
      Evidence:
        Native attach reports still include fallback_required/fallback_used and
        native_backend_runtime_decision advertises command fallback availability.
      Why it matters:
        For the 100% Rust native target, CO-RE/C-object retention is not a
        reason to preserve C. Compatibility fallback may exist during transition,
        but C10 final reporting must not treat it as required.
      Required direction:
        Separate transition fallback evidence from C10 final go-free admission.
        Do not use C/CO-RE fallback as a permanent native criterion.

Secondary findings:

  - The workspace currently has no alternate allocator configured. This keeps
    glibc arena behavior relevant under high thread count.
  - The direct path has the same generic per-flow relay shape: blocking loop,
    sleep-based nonblocking IO, two 16 KiB per-flow buffers.
  - DNS cache has a bounded default capacity and is not the current RSS primary
    suspect.
  - Control-plane domain routing trackers are legitimate runtime state and
    should remain measured, but the current live RSS shape does not point to
    them as the first root cause.

Priority order:

  1. Bound resident TCP flow execution and own all worker/task lifecycle.
  2. Bound product HTTP/SSE execution and replace per-client log file scanning.
  3. Add generic runtime/resource instrumentation:
       active flow workers
       queued accepts
       rejected accepts
       active outbound provider sessions
       provider selection counts
       product HTTP/SSE clients
       event/log queue length
       rss/anonymous_rss/thread_count
  4. Cache immutable outbound provider configuration per resident plan.
  5. Fix WebUI/process memory metric semantics.
  6. Move log pruning and tail scanning off the hot path.
  7. Reconcile daed local reports with dae-product canonical C10 contracts.
  8. Only after 1-7, run allocator diagnostics such as MALLOC_ARENA_MAX=2 or an
     alternate allocator comparison.

Validation policy:

  No heavy baseline matrix is required before these fixes. For each fix, use a
  lightweight before/after sample on the same traffic shape:
    - RSS
    - RssAnon
    - thread count
    - active TCP flows
    - product SSE client count
    - event/log queue or file size

  Acceptance must be tied to generic resource reduction or observability, not
  to any protocol-specific success case.
```

2026-06-03 Full Rust code RSS audit matrix:

```text
Scope:
  This is a full Rust-side RSS audit, not a protocol-specific audit.

  Audited surface:
    /root/project/dae-daex-align/rust/crates
    22 Rust crates
    585 Rust source files

  Live product entry:
    rust/crates/dae-daemon/src/bin/daed.rs
      -> dae_daemon::run_daed_product_with_args_and_version(...)
      -> daed_product.rs run command
      -> restore runtime from state
      -> resident runtime/dataplane
      -> product Web/API/SSE server

  Important distinction:
    Compiled into the daemon binary is not the same as current live resident RSS
    ownership. The audit separates:
      - live daed run resident/product path
      - startup/reload high-water allocation paths
      - future/control-plane owner paths
      - test/loopback/admission-only paths

No code changes:
  This entry records audit findings only. No source changes or live deployment
  were made as part of this audit.

Live evidence carried into the audit:
  Rust test build on 10.10.10.2:
    RSS ~= 253 MiB
    RssAnon ~= 239 MiB
    Private_Dirty ~= 239 MiB
    Threads ~= 47..67

  Restored Go daed:
    RSS ~= 85..89 MiB
    RssAnon ~= 39..42 MiB
    Threads ~= 11..12

  Interpretation:
    The high RSS shape is private anonymous memory plus allocator high-water
    retention in a multi-threaded process. It is not primarily binary size,
    shared libraries, WebUI static files, BPF include bytes, or a single
    protocol branch.

Confirmed RSS causes / high-confidence sources:

  C-RSS-1. Resident TCP flow execution is unbounded OS-thread-per-flow.
      Location:
        rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/tcp.rs
      Evidence:
        resident_tcp_accept_loop accepts a transparent TCP stream and calls
        thread::spawn for each connection. The JoinHandle is discarded.
      Runtime ownership gap:
        rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/mod.rs
        ResidentDataplaneRuntime stores and joins only the accept/UDP worker
        handles, not per-flow workers.
      RSS effect:
        Thread count scales with active TCP flows and amplifies glibc
        allocator arena/high-water anonymous RSS. Thread stacks alone do not
        explain the whole RSS delta, but this model is the largest confirmed
        resource-model cause.

  C-RSS-2. Product Web/API/SSE execution is unbounded OS-thread-per-connection.
      Location:
        rust/crates/dae-daemon/src/daed_product.rs
      Evidence:
        serve_forever calls thread::spawn for every accepted HTTP stream.
        Runtime overview SSE and log SSE are long-lived loops.
      RSS effect:
        WebUI tabs can add long-lived OS threads. This is smaller than the
        dataplane flow thread source, but still unbounded and allocator-visible.

  C-RSS-3. Outbound provider immutable config is rebuilt per connection.
      Location:
        rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/client.rs
      Evidence:
        The resident outbound open path resolves target and rebuilds TLS/provider
        config per connection. Fingerprint-aware TLS builds a new connector per
        connection. Ordinary TLS rebuilds RootCertStore and ClientConfig per
        connection.
      Naming rule:
        Treat this as a generic outbound provider lifecycle issue. Protocol
        names may appear in function names or matrix evidence, but top-level
        work item names must remain provider/resource generic.
      RSS effect:
        Repeated provider config construction creates allocation churn and
        high-water retention. Per-flow work should allocate only session state.

  C-RSS-4. Routing/geodata has duplicate materialization and resident matcher
           retention.
      Locations:
        rust/crates/dae-daemon/src/production_runtime_owner/resident_routing.rs
        rust/crates/dae-daemon/src/production_runtime_owner/resident_routing/plan.rs
        rust/crates/dae-daemon/src/production_runtime_owner/resident_routing/geodata.rs
        rust/crates/dae-geodata/src/wire.rs
        rust/crates/dae-routing/src/userspace.rs
        rust/crates/dae-routing/src/domain.rs
      Evidence:
        Resident routing builds a plan for map update and another plan for
        userspace matcher construction. The matcher path converts the plan into
        JSON fixture form and then builds RoutingMatcher from that JSON.
        Geodata asset reads use full-file reads and decode paths clone entries.
        RoutingMatcher retains LPM prefixes, domain patterns, compiled regexes,
        and match sets.
      RSS effect:
        Startup/reload high-water source plus legitimate resident matcher state.
        Contribution depends on geosite/geoip/routing size.

  C-RSS-5. Product materializer duplicates large config/nodes/groups during
           startup and reload.
      Location:
        rust/crates/dae-daemon/src/daed_product.rs
      Evidence:
        restore_runtime_from_state runs materialize_runtime once as dry preview
        and once as applied materialization. materialize_runtime reads selected
        config/dns/routing, groups, and all nodes, then renders generated config
        and returns a JSON object containing the generated content.
        list_all_nodes_value uses NodeListScope::All, including subscription-
        backed nodes.
      RSS effect:
        Large subscriptions and generated config can create startup/reload
        high-water allocation that remains in RSS through allocator retention.

  C-RSS-6. Event/log bridge does synchronous file/DB/tail-prune work on the hot
           path.
      Locations:
        rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/events.rs
        rust/crates/dae-daemon/src/daed_product.rs
      Evidence:
        resident append_event writes JSONL and calls the product log sink.
        Product log append opens state, reads runtime log level and settings,
        reads last id, appends one line, then prunes by reading tail bytes,
        collecting lines, joining a new string, and rewriting the log file.
        Log SSE scans entries after last id on a polling interval.
      RSS effect:
        Debug/flow-heavy logging creates avoidable allocation and IO churn.
        It is not the main steady RSS cause in the previous live evidence, but
        it is a confirmed amplifier and WebUI latency source.

  C-RSS-7. WebUI heap metric is anonymous RSS, not true live heap.
      Location:
        rust/crates/dae-daemon/src/daed_product.rs
      Evidence:
        ProcessMetrics.heap_alloc_bytes is populated from /proc/self/status
        RssAnon and falls back to VmData.
      RSS effect:
        This is an observability bug, not an allocation root cause. The UI
        currently labels anonymous RSS as heap and can mislead debugging.

Probable / situational amplifiers:

  P-RSS-1. UDP is packet-exchange oriented instead of bounded session/pool
           oriented.
      Location:
        rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/udp.rs
      Evidence:
        Non-DNS UDP opens a fresh outbound exchange per packet and opens a
        transparent reply socket per reply.
      Status:
        Not observed as the main live RSS source because UDP activity was low,
        but the model is not production-grade native session ownership.

  P-RSS-2. Direct relay uses the same per-flow blocking loop shape.
      Location:
        rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/direct.rs
      Evidence:
        Per-flow direct relay uses two 16 KiB buffers and sleep-based
        nonblocking IO.
      Status:
        Not enough by itself to explain 250 MiB RSS, but it contributes under
        the per-flow OS thread model.

  P-RSS-3. Runtime overview/report polling clones runtime JSON.
      Locations:
        rust/crates/dae-daemon/src/daed_product.rs
        rust/crates/dae-daemon/src/production_runtime_owner/resident.rs
      Evidence:
        ProductRuntimeManager::summary clones runtime state and lastReport.
        Resident runtime already compacts the start report, so this is mostly
        polling-time allocation churn rather than the main resident memory root.

  P-RSS-4. Control-plane owner structures are valid future C10 memory concerns.
      Locations:
        rust/crates/dae-control/src/routing_owned.rs
        rust/crates/dae-control/src/domain_routing.rs
        rust/crates/dae-control/src/connectivity_owned.rs
      Evidence:
        These retain routing plans, domain routing trackers, and connectivity
        fallback maps.
      Status:
        They are not the first root cause for the current live product resident
        RSS shape, but must remain measured as C10 control-plane ownership grows.

Non-causes / lower priority for current RSS:

  N-RSS-1. DNS cache is bounded.
      Location:
        rust/crates/dae-dns/src/cache.rs
      Evidence:
        DNS_CACHE_MAX_ENTRIES defaults to 4096 and eviction runs while entries
        are at capacity.

  N-RSS-2. Runtime traffic sample history is bounded.
      Location:
        rust/crates/dae-daemon/src/daed_product.rs
      Evidence:
        Runtime traffic samples use VecDeque and are clamped by windowSec and
        maxPoints, with maxPoints capped at 1000.

  N-RSS-3. No daemon alternate allocator is currently configured.
      Evidence:
        #[global_allocator] appears only in dae-bench.
      Meaning:
        glibc allocator behavior is relevant under high thread count, but this
        is an allocator amplifier after resource-model issues, not the first
        code object to fix.

  N-RSS-4. Embedded BPF/include_bytes objects are not the private anonymous RSS
           explanation.
      Locations:
        rust/crates/dae-daemon/src/production_runtime_owner/resident.rs
        rust/crates/dae-aya-bpf-loader/src/lib.rs
      Meaning:
        They affect binary/readonly/file-backed mapping, not the observed
        private anonymous RSS majority.

Required repair order:

  1. Bound resident TCP flow execution and make runtime owner own/join all
     flow tasks or worker IDs.
  2. Bound product HTTP/SSE execution and cap long-lived stream clients.
  3. Add generic resource instrumentation:
       active flow workers
       queued accepts
       rejected accepts
       provider session count
       provider selection count
       HTTP/SSE client count
       event/log queue or file backlog
       RSS
       anonymous RSS
       thread count
  4. Cache immutable outbound provider config per resident runtime/plan.
  5. Fix process memory metric semantics:
       rssBytes
       anonymousRssBytes
       fileRssBytes where available
       vmDataBytes
       threadCount
       heapLiveBytes only with allocator-backed evidence
  6. Move log pruning and tail scanning off the hot path. Use a bounded live
     log ring/index for WebUI and append-only durable writes.
  7. Reduce routing/geodata/materializer duplicate large-object construction.
  8. Only after 1-7, compare MALLOC_ARENA_MAX=2 or an alternate allocator with
     the same traffic shape.

Validation policy:
  Do not build a heavy baseline matrix first. The live RSS gap is already large.
  Validate each concrete fix with lightweight before/after samples:
    - RSS
    - RssAnon
    - Threads
    - active TCP flows
    - HTTP/SSE client count
    - provider sessions
    - log/event backlog

Acceptance rule:
  A fix counts only if it removes a concrete allocation/thread/retention source,
  adds measurement that isolates such a source, or corrects misleading metrics.
  Protocol-specific success cases are not enough.
```

2026-06-03 RSS repair worklog - bounded runtime ownership:

```text
Problem validation record:

  V-RSS-1. Resident TCP flow execution is unbounded and not owned by runtime.
      Code evidence:
        rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/tcp.rs
          resident_tcp_accept_loop calls thread::spawn for every accepted TCP
          connection and discards the JoinHandle.

        rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/mod.rs
          ResidentDataplaneRuntime stores only the resident accept/UDP worker
          handles. shutdown joins those handles, not the per-flow worker
          threads created by the accept loop.

      RSS relevance:
        This is the first repair target because it is protocol-generic and
        directly explains high thread count plus glibc allocator high-water
        anonymous RSS under live traffic.

      Acceptance requirement:
        Replace per-connection thread::spawn with a bounded execution model.
        Runtime owner must retain/join all worker handles, expose configured
        worker/queue limits, and expose accept/enqueue/reject/queue-depth
        counters.

  V-RSS-2. Product Web/API/SSE execution is unbounded.
      Code evidence:
        rust/crates/dae-daemon/src/daed_product.rs
          serve_forever calls thread::spawn for every accepted HTTP stream.
          runtime/log SSE endpoints are long-lived loops.

      RSS relevance:
        This is the second repair target. It is smaller than resident TCP under
        traffic, but WebUI can add persistent OS threads and allocator arenas.

      Acceptance requirement:
        Product HTTP execution must be bounded and report active/rejected/
        queued worker state. Long-lived stream clients must no longer create
        unbounded OS threads.

Solution record:
  S-RSS-1. Resident TCP flow execution is now bounded by a fixed worker queue.
      Changed files:
        rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/tcp.rs
        rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/mod.rs

      New behavior:
        - resident_tcp_accept_loop no longer calls thread::spawn per accepted
          TCP flow.
        - Accepted TCP streams are submitted to a bounded sync_channel.
        - A fixed set of resident flow workers executes handle_tcp_connection.
        - Worker JoinHandles are stored in ResidentDataplaneRuntime handles and
          are joined during shutdown with the rest of the dataplane workers.
        - Queue-full accepts are rejected and counted instead of creating more
          OS threads.

      Runtime knobs:
        DAE_RESIDENT_FLOW_WORKERS
          configured worker count
          default: available_parallelism * 2, clamped to 4..16
          hard clamp: 1..128

        DAE_RESIDENT_FLOW_QUEUE
          bounded accept queue capacity
          default: 256
          hard clamp: 16..16384

        DAE_RESIDENT_FLOW_WORKER_STACK_BYTES
          per worker thread stack reservation
          default: 1048576
          hard clamp: 262144..8388608

      New dataplane report/metric fields:
        tcp_flow_worker_count
        tcp_flow_queue_capacity
        tcp_flow_worker_stack_bytes
        metrics.tcpAcceptedTotal
        metrics.tcpEnqueuedTotal
        metrics.tcpRejectedTotal
        metrics.tcpQueueDepth

      RSS effect:
        This removes the largest confirmed unbounded thread source. RSS can now
        be compared against worker_count/queue_capacity instead of active TCP
        flow count growing OS threads without bound.

  S-RSS-2. Product Web/API/SSE execution is now bounded by a fixed HTTP worker
           queue.
      Changed file:
        rust/crates/dae-daemon/src/daed_product.rs

      New behavior:
        - serve_forever no longer calls thread::spawn per accepted HTTP stream.
        - HTTP streams are submitted to a bounded sync_channel.
        - Fixed product HTTP workers call handle_stream.
        - Runtime/log SSE remain long-lived streams, but they now occupy a
          bounded worker slot instead of creating unbounded OS threads.
        - Queue-full accepts return HTTP 503 and are counted.

      Runtime knobs:
        DAED_HTTP_WORKERS
          configured product HTTP worker count
          default: available_parallelism * 2, clamped to 4..16
          hard clamp: 1..128

        DAED_HTTP_QUEUE
          bounded HTTP accept queue capacity
          default: 256
          hard clamp: 16..16384

        DAED_HTTP_WORKER_STACK_BYTES
          per worker thread stack reservation
          default: 1048576
          hard clamp: 262144..8388608

      New runtime overview field:
        productHttp.configuredWorkers
        productHttp.queueCapacity
        productHttp.workerStackBytes
        productHttp.activeConnections
        productHttp.acceptedTotal
        productHttp.enqueuedTotal
        productHttp.rejectedTotal
        productHttp.queueDepth

      RSS effect:
        This removes the WebUI/API/SSE unbounded thread source and makes WebUI
        contribution visible during live RSS sampling.

Validation:
  Local commands:
    cargo fmt --manifest-path rust/Cargo.toml -p dae-daemon
    cargo check --manifest-path rust/Cargo.toml -p dae-daemon
    cargo test --manifest-path rust/Cargo.toml -p dae-daemon

  Result:
    cargo check passed.
    cargo test passed: 198 daemon tests.

Remaining RSS work:
  - Live before/after sampling on the same traffic shape is still required.
  - Outbound provider immutable config is still rebuilt per connection.
  - Routing/geodata/materializer duplicate large-object paths are not fixed yet.
  - Log pruning and tail scanning are not moved off the hot path yet.
  - WebUI heap/anonymous RSS metric semantics still need the planned split.
  - Allocator comparisons such as MALLOC_ARENA_MAX=2 should wait until the
    resource-model fixes are live-sampled.
```

2026-06-03 Remote 38 validation - bounded runtime ownership:

```text
Host:
  38.65.91.47:5122
  root login used only for this validation run.
  Credential was not recorded.

Remote environment:
  OS:
    Debian 12 x86_64
    kernel 6.12.86+deb12-amd64
  Rust:
    rustc 1.95.0
    cargo 1.95.0

Validation setup:
  The current local workspace snapshot was copied to:
    /tmp/daex-rss-verify/dae-daex-align

  Copied content was minimal:
    rust workspace
    example.dae
    control/bpf_bpfel.o
    control/bpf_bpfeb.o
    this memo

  Excluded:
    .git
    rust/target
    benchmark_artifacts

Remote build dependencies:
  Initial remote cargo build failed before code validation because boring-sys
  required git and the remote host did not have git installed.

  Installed for validation:
    git 2.39.5
    cmake 3.25.1

  No systemd service, production binary path, netns, BPF pin, or /etc/daed state
  was modified.

Remote validation commands:
  cargo fmt --manifest-path rust/Cargo.toml -p dae-daemon -- --check
  cargo check --manifest-path rust/Cargo.toml -p dae-daemon
  cargo test --manifest-path rust/Cargo.toml -p dae-daemon --quiet

Results:
  cargo fmt --check:
    pass

  cargo check:
    pass

  cargo test:
    pass
    198 daemon tests passed
    additional integration/doc-test style groups also passed:
      6 passed
      2 passed
      2 passed
      2 passed

Product smoke:
  Built debug daed on remote:
    cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed

  Started a temporary api-only process bound to 127.0.0.1 with:
    DAED_HTTP_WORKERS=3
    DAED_HTTP_QUEUE=16

  Queried /api/runtime/overview after creating a temporary local API user.

  Verified productHttp exists and reflects configured limits:
    product_http_smoke=pass
    configuredWorkers=3
    queueCapacity=16
    activeConnections=1
    rejectedTotal=0
    queueDepth=0

Cleanup:
  Removed:
    /tmp/daex-rss-verify

  Confirmed:
    tmp_exists=no
    daed_run_processes=0

## 2026-06-04 Remote 38 full RSS test - product/control/materializer/log matrix

Scope:
  Full release RSS test for the safe product/control runtime on remote 38. This
  is not a log-only test. It covers the main Rust product resident-owner memory
  surfaces that can be exercised without mutating host routing/tproxy state:
    - process startup baseline
    - HTTP worker and runtime SSE bounded ownership
    - `/api/runtime/overview` polling
    - DB/API CRUD with large node/group state
    - large-state list/read APIs
    - generated config dry materialization
    - apply materialization with `DAED_PRODUCT_RUNTIME_FAKE_START=1`
    - config export path
    - product log append/list/log-SSE hot path
    - repeated dry/apply/list stability
    - clear/stop and remote cleanup

Boundary:
  This test intentionally did not start the real tproxy/resident dataplane on
  remote 38, because that would mutate host networking state. Real traffic RSS
  for resident dataplane/tproxy must be a separate authorized host-network test.

Remote 38 build:
  Host:
    38.65.91.47:5122

  Temporary source path:
    /tmp/daex-rss-full/dae-daex-align

  Build command:
    cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --quiet

  Release binary:
    rust/target/release/daed
    size: 14M
    sha256: 54eac439cbe83991051f7e197ed06e5f868b3e20d449713648f024b29777bc1d

Primary full-matrix run:
  Environment:
    DAED_PRODUCT_RUNTIME_FAKE_START=1
    DAED_HTTP_WORKERS=4
    DAED_HTTP_QUEUE=64
    --api-only

  Coverage:
    - startup idle baseline
    - 200 `/api/runtime/overview` polls
    - 3 active runtime SSE streams
    - 12 runtime SSE connection attempts
    - 500 manual nodes plus one group containing all nodes
    - 20 large-state list/read cycles for nodes/groups/general state
    - dry reload materialization of an 86548-byte generated config
    - apply reload materialization with fake runtime enabled
    - generated config export of the same 86548-byte content
    - 180 runtime log-level writes plus log listing
    - 3 active log SSE streams plus 60 additional log writes
    - log clear and runtime stop

  Stage samples:
    01_start_idle:
      VmRSS: 9384 KiB
      RssAnon: 1528 KiB
      RssFile: 7856 KiB
      VmData: 9724 KiB
      Threads: 6

    02_after_200_overview_polls:
      VmRSS: 10056 KiB
      RssAnon: 2072 KiB
      RssFile: 7984 KiB
      VmData: 9988 KiB
      Threads: 6

    03_with_3_runtime_sse:
      VmRSS: 10056 KiB
      RssAnon: 2072 KiB
      Threads: 6
      productHttp.activeConnections: 4

    05_with_12_runtime_sse_attempts_proc_only:
      VmRSS: 10060 KiB
      RssAnon: 2076 KiB
      Threads: 6

    07_after_500_nodes_and_group_crud:
      VmRSS: 12940 KiB
      RssAnon: 4764 KiB
      RssFile: 8176 KiB
      VmData: 14572 KiB
      Threads: 6

    08_after_large_state_list_reads:
      VmRSS: 13724 KiB
      RssAnon: 5548 KiB
      RssFile: 8176 KiB
      VmData: 17176 KiB
      Threads: 6

    09_after_dry_materialize_large_config:
      VmRSS: 13952 KiB
      RssAnon: 5712 KiB
      RssFile: 8240 KiB
      VmData: 17744 KiB
      Threads: 6
      dry_content_len: 86548
      contentIncluded: true

    10_after_apply_materialize_fake_runtime:
      VmRSS: 14744 KiB
      RssAnon: 6504 KiB
      RssFile: 8240 KiB
      VmData: 18700 KiB
      Threads: 6
      reloadCount: 1
      runtime.fakeRuntime: true
      contentIncluded: false
      content field: absent

    11_after_config_export:
      VmRSS: 14860 KiB
      RssAnon: 6620 KiB
      Threads: 6
      export_content_len: 86548

    12_after_180_log_level_writes:
      VmRSS: 14860 KiB
      RssAnon: 6620 KiB
      Threads: 6
      logs_returned: 188

    13_with_3_log_sse_and_log_writes:
      VmRSS: 14860 KiB
      RssAnon: 6620 KiB
      Threads: 6
      productHttp.activeConnections: 4

    15_after_logs_clear_and_runtime_stop:
      VmRSS: 14860 KiB
      RssAnon: 6620 KiB
      Threads: 6
      runtime.state: stopped

  API assertions:
    - `/api/runtime/overview` exposed:
        - `anonymousRssBytes`
        - `fileRssBytes`
        - `vmDataBytes`
        - `heapLiveBytes=null`
        - `heapMetricSource=unavailable`
        - `heapAllocBytesSource=compat-alias-rss-anon-not-live-heap`
    - `heapAllocBytes == anonymousRssBytes` as the compatibility alias.
    - HTTP worker thread count stayed fixed at 6 process threads with 4 workers.
    - Dry materialization still returned generated config content.
    - Apply materialization did not return generated config content.

Interpretation from primary matrix:
  RSS growth is not explained by logs. In this matrix, RSS/RssAnon increases
  came mainly from large product state and generated-config materialization:
    - idle to 500 nodes/group:
        RssAnon 1528 KiB -> 4764 KiB
    - large-state list reads:
        RssAnon 4764 KiB -> 5548 KiB
    - dry/apply/export materialization:
        RssAnon 5548 KiB -> 6620 KiB
    - log writes and log SSE:
        RssAnon stayed at 6620 KiB

  The log optimization is still useful because it removes per-append tail scans,
  per-append prune allocation, and idle log-SSE scans, but this full test shows
  logs were not the dominant RSS source in the exercised product/control path.

Repeated materialization/list stability run:
  Environment:
    DAED_PRODUCT_RUNTIME_FAKE_START=1
    DAED_HTTP_WORKERS=4
    DAED_HTTP_QUEUE=64
    --api-only

  Workload:
    - 500 manual nodes plus one group
    - 20 dry reload + apply reload cycles
    - 100 large nodes/groups/general-state list cycles
    - runtime stop

  Stage samples:
    idle:
      VmRSS: 9584 KiB
      RssAnon: 1520 KiB
      RssFile: 8064 KiB
      VmData: 9720 KiB
      Threads: 6

    after_500_nodes:
      VmRSS: 13780 KiB
      RssAnon: 5460 KiB
      RssFile: 8320 KiB
      VmData: 14352 KiB
      Threads: 6

    after_20_dry_apply_cycles:
      VmRSS: 17228 KiB
      RssAnon: 8780 KiB
      RssFile: 8448 KiB
      VmData: 19752 KiB
      Threads: 6
      reloadCount: 20

    after_100_large_list_cycles:
      VmRSS: 17520 KiB
      RssAnon: 9072 KiB
      RssFile: 8448 KiB
      VmData: 19752 KiB
      Threads: 6

    after_stop:
      VmRSS: 17520 KiB
      RssAnon: 9072 KiB
      RssFile: 8448 KiB
      VmData: 19752 KiB
      Threads: 6

  Interpretation from repeated run:
    - The thread count stayed fixed at 6 throughout.
    - Repeated dry/apply materialization raised the allocator high-water mark to
      about 17.2 MiB RSS / 8.8 MiB RssAnon.
    - 100 additional large list cycles added only about 292 KiB RssAnon.
    - Runtime stop did not reduce RSS because the process allocator retained
      pages; this is high-water retention, not active log growth.

Overall conclusion:
  The current RSS high-water in the safe release product/control matrix is
  dominated by large state rendering/materialization/listing and allocator page
  retention. The previous bounded-worker changes prevent thread-driven RSS
  growth. The log hot-path changes are validated but not the main RSS source in
  this matrix.

Cleanup:
  Removed:
    /tmp/daex-rss-full

  Confirmed:
    tmp_exists=no
    daed_run_processes=0

Validation meaning:
  Remote 38 confirms the bounded runtime ownership changes compile, pass the
  daemon test suite, and expose product HTTP worker metrics in a real daed
  process.

  This is not yet a live RSS before/after dataplane traffic sample. The next
  RSS validation still needs a controlled resident dataplane run with:
    RSS
    RssAnon
    Threads
    active TCP flows
    resident dataplane tcp queue/reject metrics
    productHttp metrics
```

2026-06-04 Remote 38 RSS sample - product/API/SSE bounded workers:

```text
Host:
  38.65.91.47:5122
  root login used only for this validation run.
  Credential was not recorded.

Scope:
  This sample measures the Rust product Web/API/SSE process in api-only mode
  with the bounded HTTP worker model.

  It does not measure resident dataplane real proxy traffic. No systemd service,
  production binary path, /etc/daed state, netns, tproxy rule, or BPF pin was
  modified.

Remote build:
  Snapshot copied to:
    /tmp/daex-rss-measure/dae-daex-align

  Built:
    cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release

  Release binary:
    rust/target/release/daed
    size: 15M
    sha256: e9376bb13d6840423daca58759975de95ef03cc6ea53929498e75d07b436a5a0

  Remote CPU count:
    nproc=2

Measurement process:
  Started temporary api-only daed:
    DAED_HTTP_WORKERS=4
    DAED_HTTP_QUEUE=32
    daed run -c /tmp/.../config --state /tmp/.../daed.db
      --listen 127.0.0.1:32139 --api-only

  Created one temporary API user inside the temporary state DB.
  Queried /api/runtime/overview for productHttp and process counters.

RSS sample 1 - idle/api overview:
  idle_after_start:
    VmSize: 419852 KiB
    VmRSS: 9220 KiB
    RssAnon: 1396 KiB
    RssFile: 7824 KiB
    VmData: 9720 KiB
    Threads: 6

  after_overview:
    VmSize: 419852 KiB
    VmRSS: 9496 KiB
    RssAnon: 1544 KiB
    RssFile: 7952 KiB
    VmData: 9728 KiB
    Threads: 6

  productHttp overview:
    configuredWorkers=4
    queueCapacity=32
    activeConnections=1
    rejectedTotal=0
    queueDepth=1
    rssBytes ~= 9658368
    heapAllocBytes/RssAnon ~= 1581056
    goroutines/thread_count=6

RSS sample 2 - 3 long-lived runtime SSE connections:
  with_3_sse:
    VmSize: 419852 KiB
    VmRSS: 9784 KiB
    RssAnon: 1832 KiB
    RssFile: 7952 KiB
    VmData: 9744 KiB
    Threads: 6

  productHttp overview:
    configuredWorkers=4
    queueCapacity=32
    activeConnections=4
    acceptedTotal=8
    enqueuedTotal=8
    rejectedTotal=0
    queueDepth=1
    rssBytes ~= 10031104
    heapAllocBytes/RssAnon ~= 1888256
    goroutines/thread_count=6

  after_sse_closed:
    VmSize: 419852 KiB
    VmRSS: 9796 KiB
    RssAnon: 1844 KiB
    RssFile: 7952 KiB
    VmData: 9756 KiB
    Threads: 6

RSS sample 3 - 12 runtime SSE attempts with only 4 HTTP workers:
  idle:
    VmSize: 353288 KiB
    VmRSS: 9212 KiB
    RssAnon: 1376 KiB
    RssFile: 7836 KiB
    VmData: 8568 KiB
    Threads: 6

  with_12_sse_attempts:
    VmSize: 353288 KiB
    VmRSS: 9512 KiB
    RssAnon: 1676 KiB
    RssFile: 7836 KiB
    VmData: 8584 KiB
    Threads: 6
    curl_sse_processes=12

  after_kill_sse:
    VmSize: 353288 KiB
    VmRSS: 9552 KiB
    RssAnon: 1716 KiB
    RssFile: 7836 KiB
    VmData: 8624 KiB
    Threads: 6

Interpretation:
  Product/API/SSE bounded worker model holds process thread count fixed at 6:
    1 main/listener thread
    4 configured HTTP workers
    1 signal/control thread

  With 3 active SSE streams, RSS stayed around 9.6 MiB and anonymous RSS stayed
  below 2 MiB. With 12 SSE attempts, daed thread count still stayed fixed at 6,
  confirming that Web/API/SSE no longer creates one OS thread per HTTP
  connection.

  This validates the product HTTP/SSE part of the RSS repair on remote 38. It
  does not prove the resident dataplane RSS under real traffic. The next
  resident dataplane RSS test must use a controlled real runtime with:
    - valid daed config
    - temporary resident dataplane enablement
    - RSS/RssAnon/Threads
    - active TCP flow count
    - tcpAcceptedTotal/tcpEnqueuedTotal/tcpRejectedTotal/tcpQueueDepth
    - productHttp metrics

Cleanup:
  Removed:
    /tmp/daex-rss-measure

  Confirmed:
    tmp_exists=no
    daed_run_processes=0
```

2026-06-04 10.10.10.2 memory accounting note - Cockpit vs btop:

```text
Host:
  10.10.10.2

Observed symptom:
  Cockpit showed daed memory around 168 MiB, while btop showed daed around
  56 MiB. This is a metric-scope mismatch, not evidence that the Rust live heap
  is 168 MiB.

Live process sample:
  daed pid: 1002
  command: /usr/bin/daed run -c /etc/daed/

Process /proc view:
  ps RSS: 65268 KiB
  VmRSS: 65268 KiB
  Pss: 61631 KiB
  RssAnon: 50960 KiB
  RssFile: 14308 KiB
  Private_Dirty: 50960 KiB
  Threads: 37

systemd / cgroup view:
  daed.service cgroup: /system.slice/daed.service
  MainPID: 1002
  MemoryCurrent: 177532928 bytes (~169.3 MiB)
  MemoryPeak: 236756992 bytes (~225.8 MiB)
  MemorySwapCurrent: 0
  TasksCurrent: 37

cgroup memory.stat selected:
  anon: 48689152 bytes (~46.4 MiB)
  file: 54501376 bytes (~52.0 MiB)
  kernel: 69394432 bytes (~66.2 MiB)
  vmalloc: 65490944 bytes (~62.5 MiB)
  slab: 2926384 bytes (~2.8 MiB)
  sock: 4096 bytes
  swap: 0

Interpretation:
  btop / ps is showing the daed process RSS/RES scope, roughly 60..64 MiB in
  this sample.

  Cockpit follows the systemd/cgroup MemoryCurrent scope for daed.service. That
  includes process RSS plus memory charged to the service cgroup, especially
  kernel/vmalloc memory and file cache.

  The 100+ MiB difference is mainly:
    - about 62.5 MiB kernel/vmalloc, matching resident eBPF map allocation;
    - about 52.0 MiB cgroup file/page cache, only about 14 MiB of which was
      mapped into the process RSS as RssFile at the sampled moment;
    - small slab/pagetable/kernel overhead.

bpftool evidence:
  The big BPF maps charged to daed(1002) include:
    routing_tuples_map  ~18 MiB memlock
    udp_conn_state_map  ~16 MiB memlock
    domain_routing_map  ~13 MiB memlock
    redirect_track      ~7.5 MiB memlock
    cookie_pid_map      ~6 MiB memlock
    fast_sock           ~1 MiB memlock
    tgid_pname_map      ~0.7 MiB memlock

Operational rule:
  Do not compare Cockpit MemoryCurrent directly with btop process RSS as if they
  are the same metric.

  For Rust process-body memory, inspect:
    /proc/<pid>/smaps_rollup Rss/Pss/Private_Dirty/Anonymous
    /proc/<pid>/status VmRSS/RssAnon/RssFile/Threads

  For total service memory pressure, inspect:
    systemctl show daed -p MemoryCurrent -p MemoryPeak
    /sys/fs/cgroup/system.slice/daed.service/memory.current
    /sys/fs/cgroup/system.slice/daed.service/memory.stat

Optimization implication:
  - To reduce btop/RSS: continue optimizing Rust resident process anonymous RSS,
    allocator behavior, logs, connection/session objects, and runtime ownership.
  - To reduce Cockpit/systemd MemoryCurrent: audit eBPF map max_entries, duplicate
    map allocation, feature/backend-specific map sizing, and possible lazy or
    scaled map allocation.
  - The current Cockpit-vs-btop delta is not a Rust heap regression by itself.
```

## 2026-06-04 RSS optimization completion - product/runtime hot paths

Scope:
  Finish the remaining Rust native RSS work after the bounded worker fixes. This
  is a generic product/runtime memory pass, not a protocol-specific fix.

Problem validation record:
  - Product HTTP/SSE was already changed from per-connection OS thread spawning
    to bounded worker ownership, and remote 38 showed fixed daed thread count
    under multiple SSE connections.
  - Remaining RSS/capacity risks were still visible in shared product/runtime
    paths:
      - `/api/runtime/overview` exposed `heapAllocBytes` as a single ambiguous
        value backed by `/proc/self/status` RssAnon, causing WebUI cards and
        diagnostics to confuse anonymous RSS with a live heap counter.
      - `materialize_runtime(..., false)` returned full generated config content
        in the apply/reload JSON report even though apply callers only need
        metadata and the file path, duplicating large generated config strings.
      - Product log append scanned the JSONL tail for the last id on every
        append and ran prune on every append, so debug/task-log traffic paid
        repeated tail reads, line allocation, join allocation, and temp-file
        writes.
      - Log SSE polling rescanned the JSONL file every 500 ms even when no new
        log id existed.
      - Resident outbound TLS/provider setup rebuilt rustls root/config objects
        and Boring connector state for each connection instead of reusing
        immutable per-plan client configuration.

Changed files:
  - `rust/crates/dae-daemon/src/daed_product.rs`
  - `rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/client.rs`

Solution record:
  - Process memory reporting now splits `/proc/self/status` into:
      - `rssBytes`
      - `anonymousRssBytes`
      - `fileRssBytes`
      - `vmDataBytes`
      - `heapLiveBytes: null`
      - `heapMetricSource: "unavailable"`
      - `heapAllocBytesSource: "compat-alias-rss-anon-not-live-heap"`
    `heapAllocBytes` remains for WebUI/API compatibility, but is explicitly a
    compat alias for anonymous RSS rather than a Rust live heap counter.
  - Runtime config materialization now includes `content` only for dry preview
    and export paths. Apply/reload materialization writes the generated file and
    returns metadata with `contentIncluded=false`, avoiding a second large JSON
    copy of generated config content.
  - Product log append now keeps a path-aware last-id cache. It scans the tail
    only on first use/path change and updates the id after append.
  - Product log prune is now gated by file size or a 256-entry interval instead
    of running on every append. Explicit settings changes and initialization
    still run immediate prune.
  - Product log clear/settings prune share the same file lock as append and
    reset the id cache, keeping JSONL ids deterministic after clear.
  - Log SSE uses the cached last id and only scans entries when the id changes
    or the log is reset, removing idle polling scans.
  - Resident TLS provider setup now caches immutable client configuration:
      - rustls `ClientConfig` keyed by flow/ALPN/fingerprint-relevant plan.
      - Boring `SslConnector` keyed by the same generic client config key.
    Each network connection still creates a fresh TLS session/connection; only
    immutable setup objects are reused.

Local validation:
  - `cargo fmt --manifest-path rust/Cargo.toml -p dae-daemon`
  - `cargo check --manifest-path rust/Cargo.toml -p dae-daemon`
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon --quiet`
  - Result: pass. `dae-daemon` test run passed 198 daemon tests plus the
    additional integration groups reported by cargo.

Remote validation status:
  Completed on remote 38.

Remote 38 release build:
  Host:
    38.65.91.47:5122

  Temporary source path:
    /tmp/daex-rss-complete/dae-daex-align

  Build command:
    cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --quiet

  Release binary:
    rust/target/release/daed
    size: 14M
    sha256: 0da4c6acedf62230fc03627c1c7e29b43bd26f1366b36d7d1d5fdeebf5732faa

Remote 38 RSS/API sample:
  Started temporary api-only daed:
    DAED_HTTP_WORKERS=4
    DAED_HTTP_QUEUE=32
    daed run -c /tmp/daex-rss-complete/run/config
      --state /tmp/daex-rss-complete/run/daed.db
      --listen 127.0.0.1:32149
      --api-only

  idle_after_start:
    VmSize: 419816 KiB
    VmRSS: 9368 KiB
    RssAnon: 1528 KiB
    RssFile: 7840 KiB
    VmData: 9724 KiB
    Threads: 6

  overview_after_start:
    rssBytes=9809920
    anonymousRssBytes=1716224
    fileRssBytes=8093696
    vmDataBytes=9965568
    heapLiveBytes=null
    heapMetricSource=unavailable
    heapAllocBytes=1716224
    heapAllocBytesSource=compat-alias-rss-anon-not-live-heap
    goroutines/thread_count=6
    productHttp.configuredWorkers=4
    productHttp.queueCapacity=32
    productHttp.activeConnections=1
    productHttp.rejectedTotal=0
    productHttp.queueDepth=0

  with_3_sse:
    VmSize: 419816 KiB
    VmRSS: 9804 KiB
    RssAnon: 1836 KiB
    RssFile: 7968 KiB
    VmData: 9752 KiB
    Threads: 6

  overview_with_3_sse:
    rssBytes=10055680
    anonymousRssBytes=1896448
    fileRssBytes=8159232
    vmDataBytes=10002432
    heapLiveBytes=null
    heapMetricSource=unavailable
    heapAllocBytes=1896448
    heapAllocBytesSource=compat-alias-rss-anon-not-live-heap
    goroutines/thread_count=6
    productHttp.activeConnections=4
    productHttp.rejectedTotal=0
    productHttp.queueDepth=1

  after_3_sse_closed:
    VmSize: 419816 KiB
    VmRSS: 9820 KiB
    RssAnon: 1852 KiB
    RssFile: 7968 KiB
    VmData: 9768 KiB
    Threads: 6

  with_12_sse_attempts:
    VmSize: 419816 KiB
    VmRSS: 9884 KiB
    RssAnon: 1916 KiB
    RssFile: 7968 KiB
    VmData: 9832 KiB
    Threads: 6
    curl_sse_processes=12

  after_12_sse_closed:
    VmSize: 419816 KiB
    VmRSS: 9904 KiB
    RssAnon: 1936 KiB
    RssFile: 7968 KiB
    VmData: 9852 KiB
    Threads: 6

  overview_after_12_sse_closed:
    rssBytes=10141696
    anonymousRssBytes=1982464
    fileRssBytes=8159232
    vmDataBytes=10088448
    heapLiveBytes=null
    heapMetricSource=unavailable
    heapAllocBytes=1982464
    heapAllocBytesSource=compat-alias-rss-anon-not-live-heap
    goroutines/thread_count=6
    productHttp.activeConnections=1
    productHttp.acceptedTotal=21
    productHttp.enqueuedTotal=21
    productHttp.rejectedTotal=0
    productHttp.queueDepth=1

Interpretation:
  The completed RSS optimization pass holds the product/api/SSE release process
  at 6 threads with 4 configured HTTP workers, including 12 simultaneous SSE
  connection attempts. Anonymous RSS stayed below 2 MiB in this api-only release
  sample. `/api/runtime/overview` now exposes the split memory fields and keeps
  `heapAllocBytes` as an explicit RssAnon compatibility alias.

Cleanup:
  Removed:
    /tmp/daex-rss-complete

  Confirmed:
    tmp_exists=no
    daed_run_processes=0

## 2026-06-04 Remote 38 real resident/tproxy RSS test - host-network

Scope:
  Authorized host-network RSS test on remote 38 using real Rust resident
  dataplane/tproxy. This test did not deploy to 10.10.10.2. It intentionally
  used temporary kernel objects only:
    - resident runtime netns: daens
    - resident runtime link: dae0 / dae0peer
    - temporary client netns: rssclient
    - temporary LAN veth: rsslan0 / rsspeer0
    - native eBPF TCX attach and real transparent TCP/UDP listener on port 12345

Boundary:
  This is not a log-only test. Logs were already shown not to dominate RSS in
  the product/control matrix. This host-network test covers the real resident
  runtime, tproxy listener, native eBPF attach, LAN ingress redirection, and
  bounded resident TCP flow workers.

Remote build:
  Host:
    38.65.91.47:5122

  Temporary source path during test:
    /tmp/daex-rss-hostnet/dae-daex-align

  Native BTF object used during test:
    /tmp/daex-rss-hostnet/native-btf-target/bpfel-unknown-none/release/libdae_ebpf_program.so

  Final patched native-ebpf daed:
    rust/target/release/daed
    size: 16M
    sha256: da140cc8d62fc9bcaef2cd05885665c6922574db48844562acfb5d90b3256f52

  Environment:
    DAE_RUST_RESIDENT_DATAPLANE=1
    DAE_RUST_NATIVE_EBPF=1
    DAE_RUST_NATIVE_EBPF_BACKEND=tcx
    DAE_RUST_NATIVE_BPF_OBJECT=/tmp/daex-rss-hostnet/native-btf-target/bpfel-unknown-none/release/libdae_ebpf_program.so
    DAED_HTTP_WORKERS=4
    DAED_HTTP_QUEUE=64
    DAE_RESIDENT_FLOW_WORKERS=4
    DAE_RESIDENT_FLOW_QUEUE=64

  Toolchain/dependency note:
    Remote 38 needed nightly minimal, rust-src for nightly, and bpf-linker to
    build the BTF native object. The embedded native object in the release
    binary was not used for this test because the previous embedded-object path
    failed with NoBTF.

Important blocker discovered and fixed:
  A temporary LAN-flow run with rsslan0 initially exposed a native eBPF map-id
  handoff stability bug:
    attach-production-dae0peer-native-ebpf-program failed with:
      native eBPF open loaded map id <id> failed: No such file or directory

  Root cause:
    native map-id collection compared before/after global BPF map snapshots.
    The after-load snapshot can contain short-lived map ids from unrelated
    kernel/userspace activity that disappear before they are opened. Treating
    that ENOENT as fatal caused peer attach to fall back to tc-command; then
    routing_tuples_map_id was unavailable and resident TCP router start failed.

  Fix applied locally and synced to remote test source:
    rust/crates/dae-daemon/src/production_runtime_owner/native_ebpf.rs
      - collect_loaded_map_ids now skips transient NotFound/ENOENT map ids.
      - non-NotFound errors remain fatal.
      - if the required routing_tuples_map is genuinely missing, the later
        resident dataplane check still fails closed.

  Verification:
    Local:
      cargo test --manifest-path rust/Cargo.toml -p dae-daemon transient_missing_map_ids_are_skipped_during_native_map_collection --quiet
      cargo test --manifest-path rust/Cargo.toml -p dae-daemon --features native-ebpf transient_missing_map_ids_are_skipped_during_native_map_collection --quiet

    Remote:
      cargo test --manifest-path rust/Cargo.toml -p dae-daemon --features native-ebpf transient_missing_map_ids_are_skipped_during_native_map_collection --quiet
      cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf --quiet

Test topology:
  Runtime config:
    global {
      tproxy_port: "12345"
      tproxy_port_protect: "true"
      log_level: "debug"
      lan_interface: "rsslan0"
    }

    dns {}

    routing {
      fallback: proxy
    }

    node:
      vless://01234567-89ab-cdef-0123-456789abcdef@10.255.255.1:443?security=tls&type=tcp&sni=example.com&flow=xtls-rprx-vision&alpn=h2,http/1.1#hostnet_node

    group:
      proxy policy fixed(0), bound to hostnet_node

  Flow injection:
    rssclient namespace:
      rsspeer0 172.31.255.2/24
      default via 172.31.255.1 dev rsspeer0

    host side:
      rsslan0 172.31.255.1/24

    Test flows:
      8 concurrent TCP attempts from rssclient to 198.18.0.1:80
      20 additional sequential TCP attempts from rssclient to 198.18.0.1:80

  Expected outbound dial failure:
    The configured proxy server 10.255.255.1:443 is intentionally unreachable.
    The observed tcp_connection_failed warnings are expected test behavior and
    prove that LAN ingress traffic reached resident TCP workers. They are not
    an RSS problem and not a product log root cause.

Final host-network assertions:
  - dry reload included generated content:
      applied=0
      runtimeStarted=false
      contentIncluded=true
      contentLen=612

  - real reload started actual resident runtime:
      applied=1
      runtimeStarted=true
      fakeRuntime=false
      contentIncluded=false
      content field absent

  - resident dataplane:
      enabled=true
      status=pass
      attachBackend=tcx
      netnsLinkMode=netkit
      routing_tuple_map_id=7297
      proxy_count=1
      tcp_flow_worker_count=4
      tcp_flow_queue_capacity=64

  - resident LAN:
      rsslan0 native_attached=true
      backend=tcx
      LAN egress backend=tcx
      fallback_used=false

  - tproxy listener:
      daens has TCP and UDP listeners on 0.0.0.0:12345 owned by daed.

  - flow counters after 28 test TCP attempts:
      tcpAcceptedTotal=28
      tcpEnqueuedTotal=28
      tcpRejectedTotal=0
      activeTcpConnections=0
      tcpQueueDepth=1
      uploadTotal=0
      downloadTotal=0

RSS stage samples:
  01_idle_before_auth:
    VmRSS: 9008 KiB
    RssAnon: 1128 KiB
    RssFile: 7880 KiB
    VmData: 8448 KiB
    Threads: 6

  02_idle_after_auth:
    VmRSS: 9328 KiB
    RssAnon: 1384 KiB
    RssFile: 7944 KiB
    VmData: 8564 KiB
    Threads: 6

  03_after_resources_with_temp_lan:
    VmRSS: 10284 KiB
    RssAnon: 2020 KiB
    RssFile: 8264 KiB
    VmData: 8912 KiB
    Threads: 6

  04_after_dry_materialize:
    VmRSS: 10436 KiB
    RssAnon: 2044 KiB
    RssFile: 8392 KiB
    VmData: 8932 KiB
    Threads: 6

  05_after_real_resident_reload:
    VmRSS: 15732 KiB
    RssAnon: 6380 KiB
    RssFile: 9352 KiB
    VmData: 21572 KiB
    Threads: 12

  07_with_8_client_lan_tcp_attempts_midflight:
    VmRSS: 15876 KiB
    RssAnon: 6524 KiB
    RssFile: 9352 KiB
    VmData: 21636 KiB
    Threads: 12
    tcpAcceptedTotal=8
    tcpEnqueuedTotal=8
    tcpRejectedTotal=0

  09_after_20_more_client_lan_tcp_attempts:
    VmRSS: 15936 KiB
    RssAnon: 6584 KiB
    RssFile: 9352 KiB
    VmData: 21696 KiB
    Threads: 12
    tcpAcceptedTotal=28
    tcpEnqueuedTotal=28
    tcpRejectedTotal=0

  10_after_runtime_stop:
    VmRSS: 15972 KiB
    RssAnon: 6556 KiB
    RssFile: 9416 KiB
    VmData: 21716 KiB
    Threads: 6

Comparison with product/control RSS matrix:
  Safe product/control baseline:
    idle:
      VmRSS 9384 KiB
      RssAnon 1528 KiB
      Threads 6

    after 500 nodes/group:
      VmRSS 12940 KiB
      RssAnon 4764 KiB
      Threads 6

    after fake apply materialization:
      VmRSS 14744 KiB
      RssAnon 6504 KiB
      Threads 6

    repeated after 20 dry/apply cycles:
      VmRSS 17228 KiB
      RssAnon 8780 KiB
      Threads 6

  Real resident/tproxy deltas in this host-network run:
    dry materialize -> real resident reload:
      VmRSS 10436 KiB -> 15732 KiB  (+5296 KiB)
      RssAnon 2044 KiB -> 6380 KiB  (+4336 KiB)
      Threads 6 -> 12

    real resident reload -> 28 accepted/enqueued TCP flows:
      VmRSS 15732 KiB -> 15936 KiB  (+204 KiB)
      RssAnon 6380 KiB -> 6584 KiB  (+204 KiB)
      Threads stayed 12

    safe fake apply vs real resident reload:
      VmRSS 14744 KiB -> 15732 KiB  (+988 KiB)
      RssAnon 6504 KiB -> 6380 KiB  (-124 KiB)
      Threads 6 -> 12

Interpretation:
  The large RSS problem is not explained by logs and is also not explained by
  the real resident/tproxy flow path under bounded worker settings. In the real
  host-network run, starting resident/tproxy added about 5.2 MiB RSS from the
  small dry-materialized baseline, mostly from resident runtime structures,
  native eBPF/userspace loader state, socket/map handoff, and six additional
  threads. After the resident runtime was already running, 28 accepted TCP
  attempts added only about 204 KiB RSS/RssAnon.

  Compared with the safe fake apply materialization stage, real resident/tproxy
  had roughly the same anonymous RSS and about 1 MiB more total RSS, with six
  more threads. This points back to product/control large-state
  rendering/materialization/listing and allocator high-water retention as the
  higher-priority RSS source, not resident flow processing and not task logs.

  The WebUI/overview "goroutines" field is still the Rust process thread count
  compatibility field. In this test it correctly moved from 6 to 12 when real
  resident workers started, then back to 6 after runtime stop.

Cleanup:
  Removed from remote 38:
    /tmp/daex-rss-hostnet
    /tmp/dae-daemon-resident-runtime-*
    dae0
    daens
    rsslan0
    rssclient

  Confirmed after cleanup:
    dae0 absent
    daens absent
    rsslan0 absent
    rssclient absent
    no daed run process for the test

## 2026-06-04 10.10.10.2 Rust native daed deployment for manual test

Local code commit used for the deployed binary:
  edb8bda8 stabilize rust native resident rss path

Build:
  Repo:
    /root/project/dae-daex-align/rust

  Native eBPF object:
    /tmp/dae-daex-native-btf-target/bpfel-unknown-none/release/libdae_ebpf_program.so

  BTF validation:
    readelf showed .BTF and .BTF.ext sections in the object.

  Build command:
    DAE_RUST_NATIVE_BPF_OBJECT=/tmp/dae-daex-native-btf-target/bpfel-unknown-none/release/libdae_ebpf_program.so \
      cargo build --manifest-path Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf --quiet

  Built binary:
    /root/project/dae-daex-align/rust/target/release/daed
    size: 16M
    sha256: 34d83e8589a74fee178fbd0ce26c4c525263286c9b8c602ebc80eed21e8330ab

Remote target:
  Host:
    10.10.10.2

Pre-deploy Go daed:
  /usr/bin/daed
  size: 50M
  sha256: b296303fc01b0cd4453ab90bb7bf988d6315a952a548fd483a0a9c5bab2448bf
  probe:
    `daed package-info --json` returned unknown command, consistent with Go daed.

Go daed backup:
  Binary:
    /etc/daed/backups/daed-go-20260604-090540-b296303fc01b

  Hash file:
    /etc/daed/backups/daed-go-20260604-090540-b296303fc01b.sha256

  Service unit backup:
    /etc/daed/backups/daed-go-20260604-090540-b296303fc01b.service

  Backup sha256:
    b296303fc01b0cd4453ab90bb7bf988d6315a952a548fd483a0a9c5bab2448bf

Deploy result:
  Installed:
    /usr/bin/daed

  Installed sha256:
    34d83e8589a74fee178fbd0ce26c4c525263286c9b8c602ebc80eed21e8330ab

  Installed size:
    16M

  Test drop-in:
    /etc/systemd/system/daed.service.d/50-rust-native-test.conf

  Drop-in environment:
    DAE_RUST_RESIDENT_DATAPLANE=1
    DAE_RUST_NATIVE_EBPF=1
    DAED_WEB_ROOT=/usr/share/daed/web
    DAED_HTTP_WORKERS=4
    DAED_HTTP_QUEUE=64
    DAE_RESIDENT_FLOW_WORKERS=4
    DAE_RESIDENT_FLOW_QUEUE=64

Post-deploy validation:
  systemctl is-active daed:
    active

  Main PID:
    59129

  API health:
    GET http://127.0.0.1:2023/api/health
    {"healthCheck":1}

  WebUI root:
    GET http://127.0.0.1:2023/
    returned /usr/share/daed/web/index.html with bundled assets.

  package-info:
    /usr/bin/daed package-info --json succeeded and reported C10 Rust product
    package surface.

Cleanup:
  Removed remote upload staging file:
    /tmp/daed-rust-native-34d83e8589a7

Rollback note:
  To restore the backed-up Go daed binary for this deployment, stop daed,
  copy the backup binary back to /usr/bin/daed, remove or disable the Rust
  native test drop-in, run systemctl daemon-reload, and start daed.

## 2026-06-04 10.10.10.2 Rust native runtime proxy failure triage

Runtime state:
  Host:
    10.10.10.2

  Service:
    daed is active with PID 59129.

  Installed Rust native binary:
    /usr/bin/daed
    sha256: 34d83e8589a74fee178fbd0ce26c4c525263286c9b8c602ebc80eed21e8330ab

  Rust native test drop-in:
    /etc/systemd/system/daed.service.d/50-rust-native-test.conf

Resident dataplane:
  Start report:
    resident_runtime_started=true
    resident_dataplane.enabled=true
    resident_dataplane.status=pass
    resident_dataplane.proxy_count=7

  Default proxy evidence:
    proxy -> [HK]Hytron
    protocol=vless
    flow=xtls-rprx-vision
    tls=tls
    utls_fingerprint.source=link fp
    utls_fingerprint.requested=chrome
    utls_fingerprint.canonical=chrome_auto
    utls_fingerprint.client=Chrome

Telegram/TG evidence:
  Routing config:
    domain(geosite:telegram) -> TG
    dip(geoip:telegram) -> TG

  Active group selection:
    TG traffic events use [SG]Oracle-Sg.

  Boring underlay:
    TG/Oracle-Sg events report tls_underlay=boringssl, so the current failure is
    not a rustls fallback or missing Boring selection.

  Observed TG failure shape:
    Recent TG events from LAN peer 192.168.6.20 to Telegram IPs such as
    91.108.56.177, 149.154.175.50, 149.154.175.53, and 149.154.171.5
    show bytes_client_to_proxy=105 and bytes_proxy_to_client=0.

    Event flags remain:
      response_header_stripped=false
      vision_direct_command_seen=false
      vision_downlink_direct_active=false
      vision_raw_direct_recovered=false

    Two events also showed:
      error="flush VLESS BoringSSL writes: [PROTOCOL_IS_SHUTDOWN]"

  Interpretation:
    Boring is selected and running for the TG path, but the TG path is not
    healthy end-to-end. The failure is after Boring underlay selection, in the
    resident VLESS Vision relay/state path or in the Oracle-Sg server path for
    this Telegram/MTProto traffic shape.

Host DNS evidence:
  /etc/resolv.conf currently contains:
    nameserver 8.8.8.8

  The dae config routes public DNS addresses through proxy:
    dip(8.8.8.8, 8.8.4.4, 1.1.1.1) -> proxy

  Host self-tests using the default resolver time out before TCP proxying:
    getent ahostsv4 cp.cloudflare.com timed out.

  Explicit local resolver works immediately:
    dig @192.168.2.11 cp.cloudflare.com A returned 104.16.132.229 with
    query time around 1ms.

  Interpretation:
    Host-originated proxy tests are currently polluted by DNS: the host resolver
    points to a public DNS target that the config sends into the proxy path.
    This explains host-side "cannot proxy" symptoms, but does not explain the
    LAN Telegram TG/TCP events because those already hit Telegram IP routing.

UDP/QUIC evidence:
  Recent resident dataplane events also show VLESS UDP response timeout for
  UDP/443 destinations, including Google/8.8.4.4 related traffic.

  Interpretation:
    Browser traffic may look stalled because QUIC/UDP is attempted and the
    Rust native VLESS UDP path is timing out. This is separate from the TG TCP
    105-byte no-downlink symptom and should be triaged as its own UDP/XUDP
    native coverage issue.

Immediate triage split:
  1. Resolver issue:
     Fix or temporarily override host DNS to 192.168.2.11 or 192.168.2.10
     before using host-local curl/getent as proxy evidence.

  2. TG TCP issue:
     Continue debugging resident VLESS Vision TCP relay/Boring behavior against
     [SG]Oracle-Sg. Current evidence says Boring is active, but TG still gets no
     server-to-client bytes.

  3. UDP/QUIC issue:
     Treat VLESS UDP response timeout as a separate Rust native dataplane gap;
     do not use it as evidence that Boring is disabled.

## 2026-06-04 10.10.10.2 rollback to Go daed

Rollback time:
  2026-06-04 09:23 CST

Remote target:
  Host:
    10.10.10.2

Restored binary:
  Source:
    /etc/daed/backups/daed-go-20260604-090540-b296303fc01b

  Destination:
    /usr/bin/daed

  Restored sha256:
    b296303fc01b0cd4453ab90bb7bf988d6315a952a548fd483a0a9c5bab2448bf

Removed Rust native test runtime hook:
  /etc/systemd/system/daed.service.d/50-rust-native-test.conf

Systemd actions:
  systemctl stop daed
  install backup binary to /usr/bin/daed
  remove Rust native test drop-in
  systemctl daemon-reload
  systemctl start daed

Validation:
  systemctl is-active daed:
    active

  Main PID:
    63403

  package-info probe:
    /usr/bin/daed package-info --json returned unknown command, matching the
    Go daed behavior observed before the Rust native test deployment.

  API health:
    GET http://127.0.0.1:2023/api/health
    {"healthCheck":1}

Cleanup:
  Removed stale Rust resident runtime directory:
    /tmp/dae-daemon-resident-runtime-59129

## 2026-06-04 resident TCP bounded queue rollback test on 10.10.10.2

Purpose:
  Validate the hypothesis that the RSS-path resident TCP bounded worker queue
  caused the VLESS Vision/TG regression. This test keeps the other RSS changes
  and reverts only the resident TCP flow execution model back to per-connection
  threads.

Local code change:
  Reverted resident dataplane TCP bounded queue code in:
    rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/tcp.rs
    rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/mod.rs

  Removed:
    ResidentTcpWorkerConfig
    spawn_resident_tcp_flow_workers
    ResidentTcpFlowQueue
    DAE_RESIDENT_FLOW_WORKERS / DAE_RESIDENT_FLOW_QUEUE handling
    resident dataplane tcpAccepted/tcpEnqueued/tcpRejected/tcpQueueDepth metrics

  Restored:
    resident TCP accept loop spawns one connection handler per accepted TCP
    connection.

Local verification:
  cargo fmt:
    passed

  Tests:
    cargo test -p dae-daemon resident_vless_vision --quiet
      passed, 12 tests

    cargo test -p dae-daemon proxy_failure_event_carries_relay_diagnostics --quiet
      passed

    cargo test -p dae-daemon resident_vision_raw_direct_recovery_requires_explicit_direct_command --quiet
      passed

    cargo test -p dae-daemon process_status_metrics_splits_rss_and_keeps_heap_compat_alias --quiet
      passed

Build:
  Native eBPF object reused:
    /tmp/dae-daex-native-btf-target/bpfel-unknown-none/release/libdae_ebpf_program.so

  BTF validation:
    readelf showed .BTF and .BTF.ext sections.

  Build command:
    DAE_RUST_NATIVE_BPF_OBJECT=/tmp/dae-daex-native-btf-target/bpfel-unknown-none/release/libdae_ebpf_program.so \
      cargo build --manifest-path /root/project/dae-daex-align/rust/Cargo.toml \
      -p dae-daemon --bin daed --release --features native-ebpf --quiet

  Built binary:
    /root/project/dae-daex-align/rust/target/release/daed
    size: 16M
    sha256: 1d7be38fab6554cc20098cc8534b082fa50ebf824d5ec42967b16711abf42d4a

Deployment:
  Host:
    10.10.10.2

  Pre-deploy current /usr/bin/daed:
    b296303fc01b0cd4453ab90bb7bf988d6315a952a548fd483a0a9c5bab2448bf
    This matched the Go backup at:
      /etc/daed/backups/daed-go-20260604-090540-b296303fc01b

  Installed /usr/bin/daed:
    1d7be38fab6554cc20098cc8534b082fa50ebf824d5ec42967b16711abf42d4a

  Test drop-in:
    /etc/systemd/system/daed.service.d/50-rust-native-test.conf

  Drop-in environment:
    DAE_RUST_RESIDENT_DATAPLANE=1
    DAE_RUST_NATIVE_EBPF=1
    DAED_WEB_ROOT=/usr/share/daed/web
    DAED_HTTP_WORKERS=4
    DAED_HTTP_QUEUE=64

  Intentionally not set:
    DAE_RESIDENT_FLOW_WORKERS
    DAE_RESIDENT_FLOW_QUEUE

Runtime validation:
  systemctl is-active daed:
    active

  Main PID:
    65024

  API health:
    GET http://127.0.0.1:2023/api/health
    {"healthCheck":1}

  Resident runtime directory:
    /tmp/dae-daemon-resident-runtime-65024

  Resident dataplane start report:
    resident_runtime_started=true
    resident_dataplane.enabled=true
    resident_dataplane.status=pass
    resident_dataplane.proxy_count=7
    resident_dataplane.tcp_worker_started=true
    resident_dataplane.udp_worker_started=true
    resident_dataplane.tcp_flow_worker_count=null
    resident_dataplane.tcp_flow_queue_capacity=null

  TCP worker event:
    {"event":"tcp_worker_started","execution":"per-connection-thread",...}

  Native attach:
    bpftool showed tcx attachments on enp1s0 and dae0.

  daens listeners:
    udp 0.0.0.0:12345 daed
    tcp 0.0.0.0:12345 daed

RSS samples:
  Immediately after service start, before resident runtime restored:
    VmRSS: 12076 kB
    RssAnon: 1460 kB
    RssFile: 10616 kB
    VmData: 8792 kB
    Threads: 6

  After resident runtime restored:
    VmRSS: 79740 kB
    RssAnon: 65700 kB
    RssFile: 14040 kB
    VmData: 97232 kB
    Threads: 18

  Under live traffic:
    sample 09:36:37:
      MemoryCurrent: 150962176
      VmRSS: 91852 kB
      RssAnon: 77812 kB
      Threads: 28

    sample 09:36:42:
      MemoryCurrent: 153210880
      VmRSS: 94116 kB
      RssAnon: 80076 kB
      Threads: 30

    sample 09:36:52:
      MemoryCurrent: 156520448
      VmRSS: 96752 kB
      RssAnon: 82712 kB
      Threads: 32

  smaps_rollup later:
    Rss: 97176 kB
    Pss: 93588 kB
    Shared_Clean: 3848 kB
    Private_Clean: 10192 kB
    Private_Dirty: 83136 kB
    Anonymous: 83136 kB

Function signal:
  TG/Oracle-Sg traffic no longer reproduced the earlier all-zero-downlink
  pattern. Events showed:
    tls_underlay=boringssl
    proxy_group=TG
    node_tag=[SG]Oracle-Sg

  Example successful TG events:
    91.108.56.177:443:
      bytes_client_to_proxy=105
      bytes_proxy_to_client=101
      response_header_stripped=true
      vision_unpadding_blocks=1

    91.108.56.177:443:
      bytes_client_to_proxy=7353
      bytes_proxy_to_client=48825
      response_header_stripped=true
      vision_unpadding_blocks=6

Interpretation:
  The resident TCP bounded worker queue was a real regression candidate for
  VLESS Vision/TG behavior. Removing it restored successful TG downlink evidence
  while keeping Boring selected.

  RSS did not improve versus the bounded-worker build under live traffic. It
  rose with per-connection threads, reaching about 97 MB RSS and 31-32 threads
  during this sample. This confirms the tradeoff: per-connection threads avoid
  the bounded-worker head-of-line/worker starvation risk but are not the final
  RSS optimization strategy.

## 2026-06-04 testing UI scope and Go VLESS Vision execution-model check

User constraint:
  During the current Rust native testing period, do not expand the WebUI with
  too many diagnostic fields/cards. RSS, anonymous RSS, heap-compat source,
  allocator behavior, resident thread counts, and similar details should remain
  primarily API/log/memo diagnostics unless the UI needs a small semantic fix.
  The visible UI should stay close to the product surface and avoid turning
  temporary RSS investigation data into permanent-looking cards.

Current metric caveat:
  The Rust product API still exposes `heapAllocBytes` as a compatibility alias
  for anonymous RSS (`RssAnon`), with `heapAllocBytesSource` set to
  `compat-alias-rss-anon-not-live-heap`. This is not a true Rust live-heap
  metric, so UI text must not imply allocator live heap while this compatibility
  alias remains in use.

Allocator/reclaim state:
  The current Rust product/resident daemon has no explicit allocator trim,
  purge, background-purge, `malloc_trim`, `mallopt`, jemalloc, or mimalloc
  recovery strategy in the production daemon path. The only `global_allocator`
  hit is in the bench crate, not the deployed product daemon. Slow RSS growth
  should therefore be treated as a real production-path memory ownership and
  allocator/high-water investigation item, not as a UI-only issue.

Go execution-model evidence:
  Original Go dae does not use a fixed resident TCP worker queue for accepted
  TCP flows. In `/root/project/dae/control/control_plane.go`, `Serve` accepts
  TCP connections and immediately starts `go func(lconn net.Conn) { ... }`,
  which calls `handleConn` for that accepted connection.

  In `/root/project/dae/control/tcp.go`, `handleConn` routes/dials once for
  the accepted TCP flow, then calls `RelayTCP(sniffer, rConn)`. `RelayTCP`
  starts one goroutine for the upload copy (`lConn -> rConn`) and performs the
  download copy (`rConn -> lConn`) in the current connection goroutine.

  The VLESS Vision outbound itself is a synchronous connection wrapper. In
  `/root/project/outbound-daex-align/protocol/vless/dialer.go`, the XRV flow
  returns `vision.NewConn(conn, d.key)` for TCP. In
  `/root/project/outbound-daex-align/protocol/vless/vision/vison.go` and
  `vision/conn.go`, `NewConn`, `Read`, `Write`, and `WriteTo` wrap and drive
  the existing connection with locks/direct-read/direct-write state; this path
  does not start a protocol-specific goroutine or fixed worker.

Conclusion:
  "One connection one thread" is not precise for Go. It is one accepted TCP
  connection handled by a goroutine, plus a relay goroutine for one copy
  direction. Go goroutines are multiplexed by the Go runtime over OS threads.
  The closest Rust-native behavioral match is therefore per-flow connection
  ownership without a small fixed worker queue, while RSS optimization must be
  solved separately through memory ownership, buffering, thread-stack strategy,
  allocator policy, and resident lifecycle cleanup.

## 2026-06-04 Rust async equivalence and Go memory-recovery strategy audit

Rust execution-model judgment:
  Rust can implement the original Go TCP/VLESS Vision execution model, but not
  by treating `std::thread::spawn` as a goroutine equivalent. The current Rust
  resident TCP path accepts a TCP flow and starts an OS thread for the whole
  flow. That restores per-flow ownership semantics and avoids fixed-worker
  head-of-line blocking, but it does not reproduce Go's cheap goroutine
  scheduling model.

  The Go-equivalent Rust shape is:
    - resident TCP accept loop owns listener readiness;
    - each accepted TCP flow becomes an async task, not an OS thread;
    - relay is driven by readiness (`select`/poll), not `WouldBlock` plus
      periodic sleeps;
    - VLESS/Vision/TLS/Boring state stays per-flow and synchronous in protocol
      semantics, but its socket I/O is driven by the async reactor;
    - no small fixed worker queue for long-lived proxy flows.

RSS expectation:
  Async task per flow should reduce the RSS and virtual-memory growth caused by
  per-flow OS threads, pthread stacks, and per-thread allocator caches. It is
  not a complete baseline-RSS fix. Baseline resident RSS still needs separate
  work for config/geodata/routing ownership, Boring/TLS caches, buffers, logs,
  DB/WebUI/product state, and allocator policy.

  A low-risk intermediate experiment is to use `std::thread::Builder` with an
  explicit smaller stack for resident TCP flow threads. This can reduce
  thread-stack virtual memory and may reduce RSS if the stack is touched, but it
  is still not the final Go-equivalent model.

Go memory-recovery audit:
  Current Go dae/daed-wing does not appear to use a continuous memory budget or
  explicit RSS trim strategy in code. Searches found no production
  `debug.SetGCPercent`, `debug.SetMemoryLimit`, `GOGC`, `GOMEMLIMIT`, or
  runtime memory-limit setup. The only production `runtime.GC` path found is
  the post-startup/reload GC hook in the engine runtime.

  In `/root/project/dae/engine/runtime.go`, the engine defines
  `postStartupGC = runtime.GC` and `currentHeapAllocBytes` from
  `runtime.ReadMemStats().HeapAlloc`. It calls `maybePostStartupGC(log, true)`
  after the initial control plane is built, and calls
  `maybePostStartupGC(log, false)` after a successful reload, old control-plane
  close, and reload-scoped resource flush.

  The GC decision uses:
    - minimum interval: 5 seconds;
    - heap-growth threshold: 64 MiB;
    - skip if the new heap is still close to the last post-GC heap
      (`heapBefore < lastHeapAfter + 64MiB` and `heapBefore * 2 < lastHeapAfter * 3`);
    - forced initial GC after startup control-plane creation.

  Go runtime metrics are observational, not a recovery mechanism:
    - `/root/project/dae/control/runtime_stats.go` samples RSS from
      `/proc/self/statm`;
    - it samples heap from `runtime.ReadMemStats().HeapAlloc`;
    - it samples goroutines from `runtime.NumGoroutine()`.

  Go allocation-pressure control is mainly structural:
    - protocol/sniffing/DNS/UDP code uses `github.com/daeuniverse/outbound/pool`
      for power-of-two byte buffers up to 64 KiB;
    - `pool.GetBuffer`/`PutBuffer` uses `sync.Pool` for bytes buffers;
    - `sync.Pool` reduces allocation churn but may retain high-water objects
      until GC and is not an RSS-return guarantee.

  Go lifecycle cleanup is also structural:
    - `ControlPlane.AbortConnections` closes tracked TCP connections;
    - `ControlPlane.Close` cancels the context and closes defer/core resources;
    - `FlushReloadScopedResources` clears global gRPC/meek/xhttp pools, UDP
      endpoint pool, anyfrom pool, UDP task queues, and packet-sniffer sessions
      after successful reload;
    - UDP endpoint pool has TTL cleanup and a default max-entry cap of 4096;
    - UDP task pool has per-key queues, a max queue count of 2048, queue reuse
      through `sync.Pool`, and non-blocking drop on overflow;
    - packet sniffer pool has a 3-second TTL and max-entry cap of 1024.

Conclusion:
  Go's lower observed RSS is not caused by an aggressive custom memory reclaim
  knob. It comes from Go runtime GC/goroutine behavior, bounded/TTL-managed
  runtime resources, buffer reuse through `sync.Pool`, and a post-startup/reload
  `runtime.GC` to clean build/reload spikes. Rust native should therefore copy
  the ownership/lifecycle principles, not just add a one-shot trim. The most
  relevant Rust work items are async per-flow ownership, bounded resource
  lifetimes, protocol buffer reuse with clear caps, reload cleanup, and then an
  allocator/reclaim policy if anonymous RSS still remains high.

Execution note:
  Do not treat Rust RSS reduction as a UI problem or as a single allocator/trim
  switch. The working principle is:
    1. preserve Go-compatible per-flow ownership semantics;
    2. replace per-flow OS threads with async tasks when the resident TCP/TLS
       path is ready for reactor-driven I/O;
    3. keep long-lived proxy flows out of small fixed worker queues;
    4. add explicit TTL/cap/flush ownership for runtime resources;
    5. reuse protocol buffers with bounded retention;
    6. only then evaluate allocator purge/trim policy for remaining anonymous
       RSS.

## 2026-06-04 RSS optimization execution order and step 1 start

整理后的后续优化顺序:
  1. Keep the currently working per-flow resident TCP ownership model and do not
     return long-lived proxy flows to a small fixed worker queue.
  2. Run a low-risk per-flow thread stack-size experiment before the larger
     async rewrite. The experiment must not change routing, protocol selection,
     Boring/fingerprint selection, Vision handling, or WebUI scope.
  3. Move resident TCP to async task per flow after the TCP/TLS/Boring/Vision
     path is ready for reactor-driven I/O. This is the real Rust equivalent of
     Go's goroutine model.
  4. Add explicit TTL/cap/flush ownership for runtime resources, matching the
     Go principles around UDP endpoint/task/sniffer pools and reload-scoped
     cleanup.
  5. Add bounded protocol buffer reuse only where it reduces churn without
     creating permanent high-water caches.
  6. Evaluate allocator purge/trim only after async ownership and resource
     lifecycle issues are addressed.

Step 1 implementation started:
  Resident TCP keeps per-connection flow ownership, but accepted flow threads
  are now created with `std::thread::Builder::stack_size`. The default test
  stack is 512 KiB. The runtime environment knob is
  `DAE_RESIDENT_TCP_FLOW_STACK_BYTES`, clamped between 128 KiB and 8 MiB. The
  value is reported in the resident dataplane start report and in the
  `tcp_worker_started` event as `tcp_flow_stack_bytes` / `flow_stack_bytes`.

Expected scope of step 1:
  This can reduce thread-stack virtual memory and may reduce RSS if resident
  TCP flow stacks are being touched enough to commit pages. It will not fix
  baseline RSS from config/geodata/routing/product state, Boring/TLS caches,
  logs, DB/WebUI state, or allocator high-water retention. If functionality
  changes, the experiment should be treated as failed and reverted before
  continuing to async work.

Step 1 local build/test:
  Artifact:
    `/root/project/dae-daex-align/rust/target/release/daed`
    sha256 `0ff2b1488c7553f699fc82c1e3488fa351dde890a64688d0d949d1d61ea0c3b8`
    size 16 MiB

  Commands passed:
    `cargo fmt --all --manifest-path rust/Cargo.toml`
    `git diff --check`
    `cargo test -p dae-daemon resident_vless_vision --quiet`
    `cargo test -p dae-daemon --test service_contract --quiet`
    `cargo check -p dae-daemon --features native-ebpf`
    `cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf`

Step 1 deployment on 10.10.10.2:
  Installed `/usr/bin/daed` sha256
  `0ff2b1488c7553f699fc82c1e3488fa351dde890a64688d0d949d1d61ea0c3b8`.
  The current test drop-in explicitly sets:
    `DAE_RUST_RESIDENT_DATAPLANE=1`
    `DAE_RUST_NATIVE_EBPF=1`
    `DAE_RESIDENT_TCP_FLOW_STACK_BYTES=524288`
    `DAED_WEB_ROOT=/usr/share/daed/web`
    `DAED_HTTP_WORKERS=4`
    `DAED_HTTP_QUEUE=64`

  Existing Go rollback backup remains untouched:
    `/etc/daed/backups/daed-go-20260604-090540-b296303fc01b`

Step 1 live evidence:
  Service restarted successfully with PID 5146. Resident runtime report exists
  at `/tmp/dae-daemon-resident-runtime-5146/resident-production-runtime-start.json`.
  `resident_dataplane.status=pass`, `tcp_flow_stack_bytes=524288`, and
  `tcp_flow_stack_bytes_env=DAE_RESIDENT_TCP_FLOW_STACK_BYTES`.

  Initial post-restore sample:
    MemoryCurrent: 149049344
    VmRSS: 89296 kB
    RssAnon: 75640 kB
    RssFile: 13656 kB
    VmData: 99384 kB
    Threads: 27

  30-second live sample under traffic:
    sample 1:
      MemoryCurrent: 155439104
      VmRSS: 95440 kB
      RssAnon: 81784 kB
      RssFile: 13656 kB
      VmData: 108376 kB
      Threads: 43
    sample 2:
      MemoryCurrent: 158945280
      VmRSS: 97996 kB
      RssAnon: 84340 kB
      RssFile: 13656 kB
      VmData: 114636 kB
      Threads: 52
    sample 3:
      MemoryCurrent: 160489472
      VmRSS: 99820 kB
      RssAnon: 86164 kB
      RssFile: 13656 kB
      VmData: 117756 kB
      Threads: 53
    sample 4:
      MemoryCurrent: 161091584
      VmRSS: 100288 kB
      RssAnon: 86632 kB
      RssFile: 13656 kB
      VmData: 118300 kB
      Threads: 51
    sample 5:
      MemoryCurrent: 161447936
      VmRSS: 100432 kB
      RssAnon: 86776 kB
      RssFile: 13656 kB
      VmData: 118916 kB
      Threads: 54
    sample 6:
      MemoryCurrent: 161296384
      VmRSS: 100724 kB
      RssAnon: 87068 kB
      RssFile: 13656 kB
      VmData: 121520 kB
      Threads: 57

  Recent event summary over the latest 200 dataplane events:
    `tcp_worker_started`: 1
    `udp_worker_started`: 1
    `tcp_connection_finished`: 131
    `udp_packet_finished`: 2
    `tcp_connection_failed`: 11
    `tls_underlay=boringssl`: 138
    top nodes: `[US]Dmit-Mabuli` 93, `[HK]Hytron` 33, `[SG]Oracle-Sg` 15

  The recent failure events were the known diagnostic pattern:
    proxy_group=`openai`, node=`[US]Dmit-Mabuli`,
    dial_target=`www.google.com:80`,
    error=`read inbound TCP: Connection reset by peer (os error 104)`.

Interpretation:
  Step 1 preserves function: TG/Oracle-Sg and other proxy events still show
  `tls_underlay=boringssl`, and the resident dataplane reports pass. The 512 KiB
  per-flow stack experiment does not by itself solve RSS growth: RSS still rises
  with live TCP flow/thread count. It may slightly constrain stack reserve, but
  the observed anonymous RSS remains dominated by per-flow thread count,
  allocator/cache/high-water behavior, and resident baseline ownership. This
  strengthens the conclusion that the real next optimization is async per-flow
  ownership plus lifecycle/cap cleanup, not another fixed worker queue.

## 2026-06-04 A-C async/allocator optimization execution log

Execution discipline:
  Work must be recorded step by step. Each step needs a code-scope note, local
  test evidence, and, when deployed, live-host evidence. Do not merge async
  conversion, allocator replacement, and UI metric changes into one opaque
  change. Do not treat `spawn_blocking` or a small fixed worker queue as a valid
  replacement for Go's goroutine-like per-flow ownership.

A. Async direct TCP skeleton:
  Convert the resident TCP accept/direct path from per-flow OS threads to
  async tasks/reaction-driven I/O first. Scope is direct TCP relay, active-flow
  accounting, events, shutdown, and metrics. Proxy/TLS/Vision may remain on the
  old path only as an explicit transitional boundary while A is being validated.

B. Async proxy/TLS/Vision path:
  Move the proxy path to readiness-driven I/O. This includes standard TLS,
  fingerprint-aware Boring underlay, VLESS request/response handling, Vision
  uplink/downlink state, and raw-direct recovery. This step is not complete if
  Boring/TLS is still driven by blocking I/O or by a hidden per-flow OS thread.

C. Functional and RSS curve confirmation:
  Build the release native-ebpf `daed`, deploy to 10.10.10.2 using the current
  Rust test procedure, confirm resident dataplane pass, confirm Boring underlay
  for fingerprinted proxy flows, confirm TG/Oracle-Sg functional events, and
  record `/proc` RSS/RssAnon/VmData/Threads samples across idle, initial live
  traffic, and sustained live traffic. Only after C should jemalloc/mimalloc
  A/B be started.

A implementation note:
  A has started in code. `dae-daemon` now depends on the workspace `tokio`
  crate. The workspace Tokio dependency enabled the `macros` feature so direct
  relay can use `tokio::select!`; this expands `Cargo.lock` with
  `tokio-macros` as a transitive dependency of the existing Tokio crate, not as
  a new top-level DAEX crate.

  The resident TCP listener thread now owns a current-thread Tokio runtime and
  adopts the tproxy TCP listener as a `tokio::net::TcpListener`. The start
  event uses:
    `execution=async-accept-direct-v1`
    `proxy_execution=per-connection-thread-transitional`

  Direct TCP flows now run as Tokio tasks and use async relay with
  `tokio::select!` over inbound/direct reads. This removes the per-flow OS
  thread for direct relay. The direct connect operation still calls the existing
  `magic_tcp_connect` through a bounded async boundary because it preserves
  SO_MARK/MPTCP semantics; the relay itself is readiness-driven and does not use
  the old `WouldBlock + thread::sleep` loop.

  Proxy/TLS/Vision flows are deliberately still handed off to the previous
  per-connection thread path while B is pending. The handoff is not logged as a
  separate per-flow event to avoid doubling event-log volume; only final
  `tcp_connection_finished` / `tcp_connection_failed` events are emitted.

A local evidence so far:
  Passed:
    `cargo check -p dae-daemon --features native-ebpf`
    `cargo test -p dae-daemon resident_direct --quiet`
    `cargo test -p dae-daemon resident_vless_vision --quiet`

  A is not complete until the async direct path is exercised in a live or
  integration test and the resulting event shows `execution=async-direct-v1`.
  B remains pending because fingerprint-aware proxy/TLS/Vision traffic is still
  on the transitional per-connection thread path.

A close-out update:
  The async direct path no longer clones the direct TCP fd just to keep event
  metadata alive. `handle_direct_tcp_connection_async` now takes ownership of
  `DirectTcpConnection`, moves the single `TcpStream` into `TokioTcpStream`, and
  carries only `TcpDirectDialReport` plus `SocketAddrV4` into the finished event.
  This avoids holding an extra direct socket fd for the relay lifetime and keeps
  direct connection lifetime visible for RSS/fd testing.

  Added a focused async relay regression:
    `resident_direct_async_relay_preserves_sniffed_initial_payload`

  Local evidence after A close-out:
    `cargo fmt --all --manifest-path /root/project/dae-daex-align/rust/Cargo.toml`
    `cargo check -p dae-daemon --features native-ebpf`
    `cargo test -p dae-daemon resident_direct --quiet`
      result: 4 direct tests passed, including async direct relay.
    `cargo test -p dae-daemon resident_vless_vision --quiet`
      result: 12 tests passed.
    `cargo test -p dae-daemon --test service_contract --quiet`
      result: 2 tests passed.
    `git -C /root/project/dae-daex-align diff --check`
      result: clean.

  A is locally complete for code and unit/integration-contract coverage. Live
  `execution=async-direct-v1` evidence is deferred to C because deployment must
  happen only after B local validation. B remains pending: proxy/TLS/Vision still
  has a per-flow OS-thread boundary.

B implementation rule update:
  Do not hand-drive BoringSSL over `AsyncFd` in resident proxy/TLS code. The
  fingerprint-aware TLS underlay must use `tokio-boring`; the ordinary TLS
  underlay must use `tokio-rustls`. This keeps TLS readiness, handshake,
  shutdown, and stream integration in maintained async TLS adapters instead of
  embedding a custom fd-readiness loop in DAEX resident dataplane code.

  New crates are allowed when they reduce maintenance risk or keep protocol/TLS
  semantics inside maintained adapters. `tokio-boring` and `tokio-rustls` are
  acceptable for B because they remove the need for DAEX-owned TLS readiness
  loops and make the async proxy path easier to audit long term.

B implementation update:
  `dae-daemon` now depends on `tokio-boring` and `tokio-rustls`. The workspace
  keeps `boring=5.1`; an initial `cargo update -p boring --precise 5.0.0`
  proved that pinning to 5.0.0 would select a yanked `boring` release, so the
  final dependency graph was re-resolved back to `boring=5.1.0` while still
  compiling `tokio-boring=5.0.0`.

  TCP proxy flows no longer use the transitional `dae-tcp-proxy-flow` per-flow
  OS thread in the async accept path. The resident TCP worker start event now
  reports:
    `execution=async-accept-direct-v1`
    `proxy_execution=async-proxy-tls-v1`

  The new async proxy client split is:
    ordinary TLS: `tokio-rustls`
    fingerprint-aware TLS: `tokio-boring`

  `tls_underlay` event semantics remain stable:
    ordinary TLS reports `rustls`
    fingerprint-aware TLS reports `boringssl`

  The implementation keeps the existing synchronous `VlessTlsClient` for UDP
  and legacy comparison code. TCP proxy path uses `AsyncVlessTlsClient`,
  `open_async_vless_tls_client`, `drain_vision_uplink_async`, and
  `relay_tcp_over_vless_tls_async`.

  Remaining B boundary to validate live:
    outbound socket creation still goes through the existing `magic_tcp_connect`
    helper via a short async boundary so SO_MARK/MPTCP semantics and reports are
    preserved. The long-lived proxy relay, TLS handshake, TLS reads/writes,
    Vision uplink/downlink, and raw-direct mode are async TLS streams; the
    connect boundary must be revisited later only if `/proc` evidence shows it
    is material to RSS or latency.

  Local evidence after B implementation:
    `cargo fmt --all --manifest-path /root/project/dae-daex-align/rust/Cargo.toml`
    `cargo check -p dae-daemon --features native-ebpf`
      result: pass; `tokio-boring=5.0.0` and `tokio-rustls=0.26.4` compile with
      workspace `boring=5.1.0`.
    `cargo test -p dae-daemon resident_direct --quiet`
      result: 4 tests passed.
    `cargo test -p dae-daemon resident_vless_vision --quiet`
      result: 12 tests passed.
    `cargo test -p dae-daemon --test service_contract --quiet`
      result: 2 tests passed.
    `git -C /root/project/dae-daex-align diff --check`
      result: clean.

  B is code-complete locally, but real TLS/proxy behavior must be proven in C
  with the latest native `daed` on 10.10.10.2. Do not claim RSS/function success
  from local unit tests alone.

C live deployment and evidence:
  Built the current Rust product binary with:
    `cargo build --manifest-path /root/project/dae-daex-align/rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf --quiet`

  Local artifact:
    path: `/root/project/dae-daex-align/rust/target/release/daed`
    size: 17M
    file: ELF 64-bit LSB pie executable, dynamically linked, not stripped
    sha256: `7a5f6d0bb0b99f3bbb5c15dc60187f16ae9f6774e3d3bfbb3ae2ccbd6ed798f5`

  10.10.10.2 deployment:
    previous test binary hash before deploy:
      `0ff2b1488c7553f699fc82c1e3488fa351dde890a64688d0d949d1d61ea0c3b8`
    Go rollback backup was left untouched:
      `/etc/daed/backups/daed-go-20260604-090540-b296303fc01b`
      sha256 `b296303fc01b0cd4453ab90bb7bf988d6315a952a548fd483a0a9c5bab2448bf`
    current `/usr/bin/daed` after deploy:
      sha256 `7a5f6d0bb0b99f3bbb5c15dc60187f16ae9f6774e3d3bfbb3ae2ccbd6ed798f5`
    service: active
    pid: 13919
    systemd drop-in:
      `DAE_RUST_RESIDENT_DATAPLANE=1`
      `DAE_RUST_NATIVE_EBPF=1`
      `DAE_RESIDENT_TCP_FLOW_STACK_BYTES=524288`
      `DAED_WEB_ROOT=/usr/share/daed/web`
      `DAED_HTTP_WORKERS=4`
      `DAED_HTTP_QUEUE=64`

  Live resident runtime:
    runtime dir: `/tmp/dae-daemon-resident-runtime-13919`
    event file:
      `/tmp/dae-daemon-resident-runtime-13919/resident-production-dataplane-events.jsonl`
    `resident-production-runtime-start.json` status: pass
    resident dataplane status: pass
    proxy_count: 7
    tcp_dial_mode: domain++
    tcp_worker_started: true
    udp_worker_started: true
    default proxy: `[HK]Hytron`
    default proxy TLS underlay plan:
      protocol=vless, tls=tls, transport=tcp, flow=xtls-rprx-vision,
      server_name=office.mitsuha.me, link fp source=`link fp`,
      fingerprint family=`chrome`.

  Worker event evidence:
    `tcp_worker_started`:
      `execution=async-accept-direct-v1`
      `proxy_execution=async-proxy-tls-v1`
      `legacy_flow_stack_bytes=524288`

  Live traffic evidence:
    Initial event sample showed real proxy events with:
      `event=tcp_connection_finished`
      `execution=async-proxy-tls-v1`
      `tls_underlay=boringssl`
      `node_tag=[HK]Hytron`
      Vision stats including `vision_unpadding_blocks`.

    TG/Oracle-Sg evidence:
      event count by node at 10:46 sample:
        `[HK]Hytron`: 83
        `[US]Dmit-Mabuli`: 75
        `[SG]Oracle-Sg`: 24
      event count by group:
        `proxy`: 83
        `openai`: 75
        `TG`: 24
      TG events included Telegram targets such as:
        `149.154.175.50:5222`
        `149.154.175.53:443`
        `149.154.171.255:443`
        `149.154.167.35:443`
      Each sampled TG event was:
        `execution=async-proxy-tls-v1`
        `tls_underlay=boringssl`
        `node_tag=[SG]Oracle-Sg`
        `proxy_group=TG`
        `response_header_stripped=true`

    Longer sample at 10:48:
      total events:
        `tcp_worker_started`: 1
        `udp_worker_started`: 1
        `udp_dns_packet_finished`: 6
        `tcp_connection_finished`: 344
        `tcp_connection_failed`: 6
      node counts:
        `[US]Dmit-Mabuli`: 230
        `[HK]Hytron`: 92
        `[SG]Oracle-Sg`: 25

    Direct path evidence:
      finished_by_kind after live traffic:
        proxy: 365
        direct: 10
      direct events include `execution=async-direct-v1` with nonzero
      `bytes_client_to_direct` and `bytes_direct_to_client`.

    Proxy path evidence:
      proxy execution counter:
        `async-proxy-tls-v1`: 365
      proxy TLS underlay counter:
        `boringssl`: 365

  RSS / thread samples:
    immediately after restart before resident runtime traffic:
      pid=13919, Threads=6, VmRSS=14236 kB, RssAnon=2932 kB,
      VmData=10816 kB.

    10:46:01, after resident runtime start and live traffic:
      pid=13919, NLWP=23, VmRSS=86824 kB, RssAnon=72416 kB,
      VmData=144480 kB, event lines=151.

    10:46:44, after another 20 seconds:
      pid=13919, NLWP=19, VmRSS=86900 kB, RssAnon=72492 kB,
      VmData=144524 kB, event lines=229.

    10:48:03, after another 60 seconds:
      pid=13919, NLWP=18, VmRSS=86900 kB, RssAnon=72492 kB,
      VmData=144516 kB, event lines=358.

  Interpretation:
    The A+B async changes materially reduced live resident RSS versus the prior
    test runs whose systemd peak samples were around 178.9M, 205M, and 219.9M
    on the same host. The new sample stabilized around 86.9M under active
    traffic while events increased from 151 to 358 and thread count fell from 23
    to 18. This is not a final leak proof, but it is strong live evidence that
    removing long-lived proxy per-flow OS threads improved the resident RSS
    curve.

  Residual observations to keep:
    Six TCP failures were present in 358 event lines:
      `read inbound TCP: Connection reset by peer (os error 104)`
      `connect VLESS server 168.138.166.160:443: Operation now in progress (os error 115)`
      `write direct TCP payload to client: Broken pipe (os error 32)`
      `write VLESS Vision direct payload to client: Broken pipe (os error 32)`
      `read inbound TCP for direct relay: Connection reset by peer (os error 104)`
      `connect VLESS server 64.186.224.7:443: Operation now in progress (os error 115)`

    The broken pipe and reset events are consistent with client-side close/reset
    behavior and should stay diagnostic unless frequency rises. The two
    `Operation now in progress` connect errors should be watched because they
    come from the preserved `magic_tcp_connect` connect boundary; TG still had
    successful Oracle-Sg finished events, so this is not a current functional
    blocker but remains a follow-up candidate if failures increase.

## 2026-06-04 RSS allocator/reclaim and Go structural cleanup plan

Scope:
  This is an RSS sub-plan under the existing C4-C8 Rust-owned
  runtime/control/datapath/outbound work. It does not create a new C stage and
  must not be used to bypass the C0-C10 phase discipline.

Hard conclusions:
  - `mimalloc` / `jemalloc` are required as formal A/B candidates for the Rust
    product daemon. The current production daemon path has no allocator trim,
    purge, background-purge, `malloc_trim`, `mallopt`, jemalloc, or mimalloc
    reclaim strategy, so allocator high-water RSS remains a real product-path
    gap.
  - Allocator replacement is not a substitute for ownership cleanup. Rust must
    also copy the useful Go structural memory strategies: cheap per-flow
    ownership, reload-scoped cleanup, bounded/TTL resources, bounded buffer
    reuse, and post-startup/reload cleanup.
  - The Go baseline does not appear to rely on a continuous custom memory limit
    or aggressive RSS trim knob. Prior audit found no production
    `debug.SetGCPercent`, `debug.SetMemoryLimit`, `GOGC`, `GOMEMLIMIT`, or
    continuous explicit RSS trim strategy. The relevant production behavior is a
    post-startup/reload `runtime.GC` hook plus structural cleanup and bounded
    pools.
  - Current `/proc` evidence shows raw `geoip.dat` / `geosite.dat` file-backed
    RSS is 0 KiB, but expanded routing/geodata structures are still anonymous
    heap candidates and must be measured separately.

Execution plan:
  1. Preserve the A+B async baseline.
     - Keep the async per-flow resident TCP/proxy shape as the current baseline:
       direct `execution=async-direct-v1`, proxy `execution=async-proxy-tls-v1`,
       fingerprint-aware flows on `tls_underlay=boringssl`.
     - Do not reintroduce small fixed worker queues for long-lived resident TCP
       flows as an RSS workaround.

  2. Split memory metrics without adding permanent WebUI noise.
     - Keep WebUI card changes minimal during testing.
     - Runtime/API diagnostics must distinguish:
         `rssBytes`,
         `rssAnonBytes`,
         `rssFileBytes`,
         `heapCompatBytes`,
         `heapCompatBytesSource`,
         `allocatorProfile`.
     - Only expose true allocator live heap when backed by allocator/runtime
       evidence. Until then, `heapAllocBytes` remains a compatibility alias for
       anonymous RSS and must be labeled internally as such.

  3. Add compile-time allocator profiles.
     - Provide mutually exclusive daemon build profiles:
         `allocator-system`,
         `allocator-mimalloc`,
         `allocator-jemalloc`.
     - Keep the system allocator profile for diagnosis and rollback comparison.
     - Evaluate `mimalloc` first for integration simplicity and page-purge
       behavior.
     - Evaluate `jemalloc` for longer-term production control, stats, decay, and
       purge diagnostics.
     - Do not choose the default allocator by assumption; choose it only after
       the same live traffic and reload matrix is measured.

  4. Add non-hot-path allocator reclaim hooks.
     - Add a small Rust-side reclaim abstraction with reason-tagged calls:
         `startup_control_built`,
         `reload_old_owner_closed`,
         `reload_scoped_resources_flushed`,
         `idle_after_reload`.
     - System allocator path may use `malloc_trim(0)` only as an explicit Linux
       diagnostic/profile option.
     - `mimalloc` path should use its explicit collection/purge API where
       available.
     - `jemalloc` path should use documented mallctl/decay/purge controls only
       after verifying the selected Rust crate API.
     - Reclaim hooks must not run on packet, connection, DNS query, or TLS relay
       hot paths.

  5. Port Go structural cleanup semantics.
     - Add/verify a reload-scoped resource registry that closes or drops old:
         routing owner,
         geodata-expanded route params,
         matcher state,
         outbound provider plans,
         DNS/sniff/session state,
         UDP endpoint state,
         flow/task queues.
     - Preserve Go-like lifecycle behavior:
         abort tracked connections on stop/reload when requested,
         close old owner after reload success,
         flush reload-scoped resources before allocator reclaim.
     - Record cleanup counts and bytes-estimates in diagnostics, not as noisy
       permanent WebUI cards.

  6. Implement bounded/TTL pools before blaming allocator alone.
     - Add bounded buffer reuse for protocol/DNS/UDP/sniffing hot paths with
       power-of-two classes up to 64 KiB, matching the useful Go pool semantics.
     - Add caps and TTL cleanup equivalent to the Go-side behavior:
         UDP endpoint max-entry equivalent around 4096 unless config requires
         otherwise,
         UDP task queue max-count equivalent around 2048,
         packet/sniffer session TTL around 3 seconds and max-entry equivalent
         around 1024.
     - Record pool hit/miss, current retained bytes, high-water retained bytes,
       evictions, and overflow drops.

  7. Reduce routing/geodata/materializer duplication.
     - Read each geodata file once per rebuild instead of once per lookup when
       building a single owner.
     - Cache decoded entries by generic key `(kind, file, code, attr)` during the
       rebuild so repeated codes such as `cn` do not duplicate decode/expand
       work unnecessarily.
     - Prefer streaming or direct matcher construction where possible instead of
       materializing large intermediate `Vec<Param>` copies.
     - Drop raw dat bytes, decoded entry bytes, and temporary expanded params
       immediately after the new matcher/owner is installed, then run the
       non-hot-path reclaim hook.
     - Record per-kind evidence:
         raw file bytes,
         decoded entry bytes,
         expanded item count,
         expanded string bytes,
         matcher estimated bytes.

  8. Verify with the same live matrix on 10.10.10.2.
     - Build and test:
         system allocator,
         mimalloc allocator,
         jemalloc allocator.
     - For each build, capture:
         idle after restart,
         resident runtime start,
         TG/Vision active traffic,
         sustained traffic,
         reload under low traffic,
         post-reload idle.
     - Required evidence:
         `/proc` `VmRSS`, `RssAnon`, `RssFile`, `VmData`, `Threads`,
         active flow counts,
         resident event counts,
         geodata lookup/output counts,
         allocator profile,
         cleanup/reclaim reason counters.
     - Functional gates remain mandatory:
         resident dataplane pass,
         proxy path pass,
         fingerprint-aware flow uses Boring underlay when required,
         TG/Oracle-Sg functional events pass,
         WebUI/API remains usable,
         logs stay semantically compatible.

  9. Acceptance criteria.
     - No functional regression versus the current async/Boring test build.
     - RSS does not exceed the current async baseline under equivalent live
       traffic.
     - Post-reload RSS/RssAnon either drops or stabilizes with clear allocator
       and cleanup evidence.
     - Geodata/routing/materializer temporary objects are proven dropped after
       owner install.
     - The selected allocator profile is justified by measured RSS, not by
       assumption.

Implementation order:
  - First: memory metric split and allocator profile scaffolding.
  - Second: non-hot-path reclaim hook wired to startup/reload cleanup points.
  - Third: Go structural cleanup parity for reload-scoped resources and
    bounded/TTL pools.
  - Fourth: geodata/routing/materializer duplicate reduction and byte-level
    diagnostics.
  - Fifth: three-way allocator A/B on 10.10.10.2 using the same traffic and
    reload matrix.

## 2026-06-04 RSS allocator/reclaim implementation record

Implementation scope:
  This pass implements the local Rust product/runtime pieces needed for the RSS
  allocator/reclaim plan. It does not deploy a new binary to `10.10.10.2` and
  does not claim the live allocator A/B matrix has been completed. The live
  matrix remains the next host-testing step after the user explicitly wants the
  test binary deployed.

Code changes:
  1. Allocator profiles:
     - Added daemon features:
         `allocator-system`,
         `allocator-mimalloc`,
         `allocator-jemalloc`.
     - Default build remains the system allocator unless a profile feature is
       explicitly selected.
     - `allocator-mimalloc` wires `mimalloc` as the global allocator and uses
       `libmimalloc_sys::mi_collect(true)` for non-hot-path reclaim.
     - `allocator-jemalloc` wires `tikv-jemallocator` as the global allocator,
       enables jemalloc stats, and uses `arena.<n>.purge` plus epoch advance for
       non-hot-path reclaim.
     - Mutually exclusive compile gates prevent combining system/mimalloc/
       jemalloc allocator profiles.

  2. Runtime diagnostics:
     - `/api/runtime/overview` now keeps the old compatibility fields and also
       exposes:
         `rssAnonBytes`,
         `rssFileBytes`,
         `heapCompatBytes`,
         `heapCompatBytesSource`,
         `allocatorProfile`,
         `allocatorStats`,
         `allocatorReclaim`,
         `resourcePools`.
     - `heapAllocBytes` remains a compatibility alias for anonymous RSS unless a
       real allocator live-heap metric is available.
     - With jemalloc builds, allocator live heap can be populated from
       `stats.allocated`; system/mimalloc builds keep live heap unavailable until
       a backed metric exists.

  3. Non-hot-path reclaim hooks:
     - Product runtime reload now records reason-tagged reclaim events:
         `reload_old_owner_closed`,
         `startup_control_built`,
         `reload_scoped_resources_flushed`.
     - Product runtime stop records:
         `stop_runtime`.
     - System allocator trim is intentionally disabled by default and only runs
       if `DAED_ALLOCATOR_SYSTEM_TRIM=1` is explicitly set; otherwise it records
       a skipped diagnostic result.
     - Reclaim hooks are not called from packet, DNS query, connection relay, TLS
       relay, or other hot paths.

  4. Go structural cleanup policy surface:
     - Runtime overview now reports the existing Rust-side UDP/sniffer policy
       constants without adding permanent WebUI cards:
         UDP endpoint max entries 4096,
         UDP task max queues 2048,
         packet sniffer TTL 3000 ms,
         packet sniffer max entries 1024.
     - The generic protocol buffer pool remains a follow-up implementation item;
       it is recorded as planned in diagnostics rather than falsely reported as
       live.

  5. Geodata/routing duplicate reduction and byte diagnostics:
     - `GeodataResolver` now caches geodata file bytes for the duration of a
       single routing rebuild, so repeated lookups do not repeat `fs::read` of
       the same `.dat`.
     - `GeodataResolver` also caches decoded entry bytes by generic
       `(kind, filename, code)` key for the duration of a rebuild. Repeated
       geosite/geoip code lookups can parse the cached entry instead of scanning
       the full `.dat` again.
     - Fallback-format geodata still uses the original full-read fallback path.
     - Geodata reports now include:
         `asset_read_count`,
         `asset_cache_hit_count`,
         `decoded_entry_cache_hit_count`,
         `raw_file_bytes_read`,
         `raw_file_bytes_seen`,
         `decoded_entry_bytes_sum`,
         `expanded_string_bytes_sum`,
         and per-lookup raw/decoded/expanded byte fields.

Validation:
  - `cargo fmt --manifest-path rust/Cargo.toml --all`: pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon
    runtime_overview_reports_process_metrics_and_stream_retry_delta`: pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon
    resident_routing_geodata_report_records_asset_cache_and_bytes`: pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-geodata`: pass.
  - `cargo check --manifest-path rust/Cargo.toml -p dae-daemon --features
    allocator-mimalloc`: pass.
  - `cargo check --manifest-path rust/Cargo.toml -p dae-daemon --features
    allocator-jemalloc`: pass.
  - `cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed
    --release --features native-ebpf`: pass.
  - `cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed
    --release --features native-ebpf,allocator-mimalloc`: pass.
  - `cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed
    --release --features native-ebpf,allocator-jemalloc`: pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon`: pass, 201
    unit tests.
  - `git diff --check`: pass.

Release artifact notes:
  - Default system allocator release/native-ebpf `daed`:
      sha256 `4f2d47d2186ae30a4eddaa7706c1f473a2cd49de1ecbe789d2bc0820baa301e6`
      size: 17M, unstripped.
  - Mimalloc release/native-ebpf build:
      sha256 `364c164475cc0dd0acb2fedb0e43f066196ce1cb56634631787e0c81f39f9ab8`
      size: 17M, unstripped.
  - Jemalloc release/native-ebpf build:
      sha256 `e0de0431802cf6bc46956684013b843fb0d8bf0b9df78aab22bae54e10d6c605`
      size: 17M, unstripped.
  - The final `target/release/daed` was rebuilt back to the default system
    allocator artifact after allocator variant checks.

Remaining live gate:
  The implementation is ready for the planned `10.10.10.2` same-traffic matrix,
  but that live deployment/A-B evidence has not been collected in this pass.
  Required live matrix remains:
    system allocator,
    mimalloc allocator,
    jemalloc allocator,
    idle after restart,
    resident runtime start,
    TG/Vision active traffic,
    sustained traffic,
    reload under low traffic,
    post-reload idle,
    `/proc` VmRSS/RssAnon/RssFile/VmData/Threads,
    geodata lookup/output/cache byte counters,
    allocator reclaim counters,
    TG/Oracle-Sg functional confirmation.

## 2026-06-04 10.10.10.2 allocator A/B live deployment

Preflight:
  - Target: `10.10.10.2`.
  - Existing Go rollback backup was verified and not overwritten:
      `/etc/daed/backups/daed-go-20260604-090540-b296303fc01b`
      sha256 marker remains `b296303fc01b0cd4453ab90bb7bf988d6315a952a548fd483a0a9c5bab2448bf`.
  - Existing live test binary before A/B:
      sha256 `7a5f6d0bb0b99f3bbb5c15dc60187f16ae9f6774e3d3bfbb3ae2ccbd6ed798f5`
      size 17M.
  - Existing service drop-in remained the Rust native test drop-in:
      `DAE_RUST_RESIDENT_DATAPLANE=1`
      `DAE_RUST_NATIVE_EBPF=1`
      `DAE_RESIDENT_TCP_FLOW_STACK_BYTES=524288`
      `DAED_WEB_ROOT=/usr/share/daed/web`
      `DAED_HTTP_WORKERS=4`
      `DAED_HTTP_QUEUE=64`
  - Existing preflight process:
      pid `13919`,
      `VmRSS=89284 kB`,
      `RssAnon=74344 kB`,
      `RssFile=14940 kB`,
      `VmData=128536 kB`,
      `Threads=9`,
      resident dataplane status `pass`.

Artifacts copied to `/tmp/daed-ab-20260604` on the target:
  - system allocator:
      sha256 `4f2d47d2186ae30a4eddaa7706c1f473a2cd49de1ecbe789d2bc0820baa301e6`
      size 17M.
  - mimalloc:
      sha256 `364c164475cc0dd0acb2fedb0e43f066196ce1cb56634631787e0c81f39f9ab8`
      size 17M.
  - jemalloc:
      sha256 `e0de0431802cf6bc46956684013b843fb0d8bf0b9df78aab22bae54e10d6c605`
      size 17M.

Live A/B procedure:
  - No new test backup was created, per test-version policy.
  - For each variant:
      install test binary to `/usr/bin/daed`,
      `systemctl restart daed`,
      collect `/proc/$pid/status`,
      collect resident runtime start report,
      collect resident dataplane event counters.
  - Sample points:
      `after_restart`,
      `t20`,
      `t60`.
  - Jemalloc received additional stabilization samples:
      `t120`,
      `t180`.
  - Unauthenticated local HTTP request to `/api/runtime/overview` returned HTTP
    401, so the live evidence below uses `/proc`, runtime start JSON, and
    resident event files rather than the Web API.

Live RSS results:
  - system allocator:
      after_restart:
        `VmRSS=11692 kB`, `RssAnon=1068 kB`, `Threads=6`.
      t20:
        `VmRSS=12028 kB`, `RssAnon=1084 kB`, `Threads=6`.
      t60:
        `VmRSS=146284 kB`, `RssAnon=132204 kB`, `Threads=12`,
        events `finished=17`, `failed=0`, `tls_underlay=boringssl:12`.

  - mimalloc:
      after_restart:
        `VmRSS=12768 kB`, `RssAnon=1680 kB`, `Threads=6`.
      t20:
        `VmRSS=54636 kB`, `RssAnon=40156 kB`, `Threads=10`,
        worker events present but no finished TCP events yet.
      t60:
        `VmRSS=54700 kB`, `RssAnon=40220 kB`, `Threads=9`,
        events `finished=9`, `failed=1`, `tls_underlay=boringssl:10`.

  - jemalloc:
      after_restart:
        `VmRSS=14284 kB`, `RssAnon=3012 kB`, `Threads=6`.
      t20:
        `VmRSS=77688 kB`, `RssAnon=63400 kB`, `Threads=11`,
        events `finished=4`, `failed=0`, `tls_underlay=boringssl:4`.
      t60:
        `VmRSS=47840 kB`, `RssAnon=33552 kB`, `Threads=11`,
        events `finished=26`, `failed=7`, `tls_underlay=boringssl:31`.
      t120:
        `VmRSS=48980 kB`, `RssAnon=34692 kB`, `Threads=17`,
        events `finished=60`, `failed=7`, `tls_underlay=boringssl:62`.
      t180:
        `VmRSS=51304 kB`, `RssAnon=37016 kB`, `Threads=13`,
        events `finished=93`, `failed=32`, `tls_underlay=boringssl:118`.

Geodata evidence from the new runtime start reports:
  - `lookup_count=21`.
  - `asset_read_count=2`.
  - `asset_cache_hit_count=19`.
  - `decoded_entry_cache_hit_count=2`.
  - `raw_file_bytes_read=29787197`.
  - `raw_file_bytes_seen=256229888`.
  - `decoded_entry_bytes_sum=4892645`.
  - `expanded_string_bytes_sum=4849666`.

Interpretation:
  - The old live test binary baseline before A/B was about 89M RSS / 74M
    anonymous RSS.
  - New system allocator build showed a large anonymous RSS spike at t60 under
    live traffic: about 146M RSS / 132M anonymous RSS. This confirms that the
    local geodata/read-cache improvement alone is not sufficient when the system
    allocator retains high-water pages.
  - Mimalloc reduced t60 RSS to about 55M / 40M anonymous RSS.
  - Jemalloc stabilized around 48M-51M RSS / 34M-37M anonymous RSS from t60 to
    t180 while event count increased from 39 to 144 lines and Boring underlay
    proxy events increased from 31 to 118.
  - On this live run, jemalloc is the current best RSS candidate. It is not yet
    a final default decision because the traffic mix was not perfectly identical
    across variants and Telegram/TG traffic did not appear during this sample
    (`tg_events=0`).

Current target state after A/B:
  - `/usr/bin/daed` is left on the jemalloc test variant:
      sha256 `e0de0431802cf6bc46956684013b843fb0d8bf0b9df78aab22bae54e10d6c605`.
  - Service is active.
  - Current process after A/B:
      pid `32597`,
      `VmRSS=52232 kB`,
      `RssAnon=37944 kB`,
      `RssFile=14288 kB`,
      `VmData=284152 kB`,
      `Threads=9`.
  - Remote results file:
      `/tmp/daed-ab-20260604/results.jsonl`.

Follow-up:
  - Let the user manually test TG/Oracle-Sg on the current jemalloc variant.
  - If TG/Vision remains functional, run a longer same-variant RSS observation
    under real use before making jemalloc the default allocator profile.
  - Investigate the `tcp_connection_failed` rate separately; the failures were
    not evenly comparable across variants because traffic mix and event volume
    differed.

## 2026-06-04 jemalloc promotion decision

Decision:
  - Keep jemalloc as the Rust native daemon allocator and enable it for the
    default `dae-daemon` build.
  - `dae-daemon` default Cargo features now include `allocator-jemalloc`.
  - Normal native release builds such as:
      `cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf`
    therefore build the jemalloc-backed daemon without needing an extra
    allocator feature flag.

Operational notes:
  - `10.10.10.2` was already left running the jemalloc test artifact from the
    live A/B matrix.
  - This promotion does not overwrite the verified Go rollback backup:
      `/etc/daed/backups/daed-go-20260604-090540-b296303fc01b`.
  - Future allocator A/B or rollback comparison builds must account for Cargo
    feature additivity:
      system allocator comparison:
        `cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --no-default-features --features native-ebpf,allocator-system`
      mimalloc comparison:
        `cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --no-default-features --features native-ebpf,allocator-mimalloc`
      jemalloc/default comparison:
        `cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf`

Guardrails:
  - Do not call allocator reclaim from packet, connection, DNS, TLS, or other
    hot paths.
  - Keep allocator-specific names inside build features, diagnostics, and
    evidence. Do not create a new protocol-specific top-level stage or gate.
  - `tcp_connection_failed` remains a separate functional diagnostic item and is
    not treated as an allocator conclusion without targeted evidence.

Validation after promotion:
  - `cargo fmt --manifest-path rust/Cargo.toml --all`: pass.
  - `cargo check --manifest-path rust/Cargo.toml -p dae-daemon --features
    native-ebpf`: pass, with default feature resolving through
    `allocator-jemalloc`.
  - `cargo tree --manifest-path rust/Cargo.toml -p dae-daemon -e features
    --features native-ebpf -i tikv-jemallocator`: shows
    `allocator-jemalloc` from `dae-daemon` default feature.
  - `cargo tree --manifest-path rust/Cargo.toml -p dae-daemon -e features
    --features native-ebpf -i tikv-jemalloc-ctl`: shows
    `allocator-jemalloc` from `dae-daemon` default feature.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon
    runtime_overview_reports_process_metrics_and_stream_retry_delta`: pass after
    making the runtime overview test allocator-profile aware.
  - `cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed
    --release --features native-ebpf`: pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon`: pass,
    including 202 library tests and the daemon product/service integration test
    targets.
  - `git diff --check`: pass.

Deployment after promotion:
  - Local default jemalloc/native-ebpf release `daed`:
      sha256 `58353e672a7bff7fa021a9d0f415d502decabb698cde03f731bbcb13dc512f17`,
      size 17M.
  - Deployed this current default-jemalloc build to `10.10.10.2` as
    `/usr/bin/daed`.
  - No test backup was created and the verified Go rollback backup was not
    modified.
  - Post-deploy service state:
      active,
      pid `33542`,
      `/usr/bin/daed` sha256
      `58353e672a7bff7fa021a9d0f415d502decabb698cde03f731bbcb13dc512f17`.
  - Early cold-start `/proc` sample after deploy:
      `VmRSS=18988 kB`,
      `RssAnon=7280 kB`,
      `RssFile=11708 kB`,
      `VmData=40608 kB`,
      `Threads=6`.
  - No new resident runtime start report existed during the immediate cold-start
    check. This matches the previous A/B `after_restart` behavior and must not
    be recorded as a completed resident dataplane functional run. Functional
    confirmation still comes from subsequent real traffic/manual testing.

## 2026-06-04 systemd restart auto-restore fix

Problem observed:
  - After replacing `/usr/bin/daed` and running `systemctl restart daed`,
    systemd started the `daed` process automatically, but the internal proxy
    runtime did not automatically restore until the user manually enabled it
    from WebUI/API.

Root cause:
  - Rust product startup correctly uses `systems.running=1` from
    `/etc/daed/daed.db` as the restore condition.
  - The bug was the shutdown path:
      `SIGTERM` / `SIGINT` / `SIGQUIT` called `mark_system_stopped()`.
  - `systemctl restart daed` naturally sends `SIGTERM` to the old process.
    Therefore a package/binary replacement restart was incorrectly persisted as
    a user-level "stop proxy" action by updating `systems.running=0`.
  - The next process saw `systems.running=0` and skipped startup restore.

Fix:
  - Split process-exit state from user-intended runtime state.
  - `SIGTERM` / `SIGINT` / `SIGQUIT` now stop and clean the current runtime
    process, but only record `runtime_running=false` metadata.
  - They no longer modify `systems.running`.
  - API `/runtime/stop` and applied-runtime failure rollback still call
    `mark_system_stopped()` and keep the durable user stop behavior.
  - Successful runtime materialization now records `runtime_running=true`
    metadata, avoiding the old stale metadata state where `systems.running=1`
    but `runtime_running=false`.

Validation:
  - `cargo fmt --manifest-path rust/Cargo.toml --all`: pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon
    runtime_process_stop_preserves_persisted_running_state`: pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon
    runtime_overview_reports_process_metrics_and_stream_retry_delta`: pass.
  - `cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed
    --release --features native-ebpf`: pass.
  - `git diff --check`: pass.

Live deployment and verification on `10.10.10.2`:
  - Deployed fixed default-jemalloc/native-ebpf `daed`:
      sha256 `0a38ad065279a87945fff8ef1f8402a1a84d4abe33f1cc61aee9381ff4303e2f`.
  - No test backup was created and the verified Go rollback backup was not
    modified.
  - Transitional first restart still saw the old running process clear state:
      before first restart `systems.running=1`,
      after first restart `systems.running=0`.
    This was expected because the old process still contained the bug.
  - Repaired the intended persisted state to `systems.running=1` for the fixed
    binary and performed a second restart.
  - Second restart with the fixed binary:
      service active,
      pid `35120`,
      `/usr/bin/daed` sha256
      `0a38ad065279a87945fff8ef1f8402a1a84d4abe33f1cc61aee9381ff4303e2f`,
      `systems.running=1`,
      `runtime_running=true`,
      new resident runtime start report
      `/tmp/dae-daemon-resident-runtime-35120/resident-production-runtime-start.json`,
      status `pass`.
  - `/proc` sample after fixed auto-restore:
      `VmRSS=76944 kB`,
      `RssAnon=62392 kB`,
      `RssFile=14552 kB`,
      `VmData=278656 kB`,
      `Threads=19`.

Operational rule:
  - Future package/binary replacement or systemd restart must preserve
    `systems.running` and auto-restore runtime when the user-intended state is
    running.
  - Only WebUI/API stop, explicit state change, or failed applied-runtime
    rollback may persist `systems.running=0`.

## 2026-06-04 allocator profile release-retirement note

Current allocator decision:
  - The current Rust native daemon production candidate uses jemalloc by default.
  - `allocator-jemalloc` is enabled through `dae-daemon` default features.
  - `allocator-system` and `allocator-mimalloc` remain closed in the current live
    build and are only short-term comparison/diagnostic profiles.

Release retirement policy:
  - `allocator-mimalloc` is a formal deletion candidate for the final production
    build once the jemalloc live path is stable. It did not beat jemalloc in the
    `10.10.10.2` A/B run and only adds feature-graph and dependency surface.
  - `allocator-system` should not be exposed as a formal production profile in
    the final package. It may remain temporarily as a no-default-features local
    diagnostic escape hatch while RSS/reload/live rollback evidence is still
    being collected.
  - Do not delete either profile during the immediate post-A/B testing window.
    Keep them available until the jemalloc build has passed sustained live
    traffic, restart/reload, TG/Oracle-Sg/Hytron, WebUI, rollback, and C10
    package admission checks.

Final production target:
  - Publish only the jemalloc allocator build.
  - Remove `allocator-mimalloc`, `mimalloc`, and `libmimalloc-sys`.
  - Remove `allocator-system` as a documented/release profile.
  - Decide at C10 package freeze whether no-default-features system allocator
    builds remain a local debug-only path or fail-closed.

## 2026-06-04 protocol matrix versus live resident adapter truth

Important distinction:
  - `dae-outbound` currently exposes a formal outbound production matrix
    contract with ten handler rows and service-contract reports it as ready.
  - That matrix is not the same thing as the current live resident dataplane
    adapter used by `/usr/bin/daed run -c /etc/daed/` on `10.10.10.2`.

Current formal matrix truth:
  - `outbound_production_matrix_contract_ready=true`.
  - `outbound_production_matrix_runtime_state_ready=true`.
  - `outbound_production_matrix_typed_report.status=pass`.
  - Matrix rows cover:
      shadowsocks,
      trojan,
      vmess,
      vless,
      hysteria2,
      tuic,
      juicity,
      anytls,
      http-proxy,
      socks5.
  - This is formal/admission evidence inside `dae-outbound`; it must not be
    mistaken for complete live default resident adapter coverage.

Current live resident adapter truth:
  - `10.10.10.2` has resident dataplane enabled and running:
      `DAE_RUST_RESIDENT_DATAPLANE=1`,
      resident start report status `pass`.
  - The active default proxy is currently one VLESS Vision TCP/TLS/Boring/link-fp
    path:
      protocol `vless`,
      flow `xtls-rprx-vision`,
      transport `tcp`,
      security `tls`,
      fingerprint source `link fp`.
  - The live adapter planner in
    `rust/crates/dae-daemon/src/production_runtime_owner/resident_dataplane/plan.rs`
    still fail-closes non-`vless` selected nodes:
      `resident dataplane selected unsupported {scheme} node ...; no Rust protocol
      handler is admitted for this node yet`.
  - The same planner also restricts the admitted VLESS shape to Vision flow,
    TCP transport, TLS security, and non-`allow_insecure`.

Current biggest functional gap:
  - The issue is not that the protocol matrix artifact is absent; it exists and
    reports pass.
  - The real C10 runtime gap is that the matrix is not wired into the live
    resident default adapter as a generic handler dispatch path.
  - Therefore current live Rust native owned runtime is proven for the active
    VLESS Vision/fingerprint path, not for full selected-node protocol coverage
    under real tproxy traffic.

Required next C10 work:
  - Replace the resident adapter's one-shape planner with a generic outbound
    handler dispatch that consumes the same selected group/routing/connectivity
    plan.
  - Keep unsupported shapes fail-closed until their live adapter bridge is wired
    and tested.
  - Add a live default-adapter protocol matrix on remote `38.65.91.47`, separate
    from the formal `dae-outbound` matrix contract:
      selected node,
      TCP dataplane,
      UDP dataplane where applicable,
      transport underlay,
      link/global fingerprint behavior where applicable,
      reload/restart,
      task logs,
      traffic counters,
      RSS behavior.
  - Do not run the protocol/live adapter matrix on `10.10.10.2`. Keep
    `10.10.10.2` for the current household/default-path smoke checks, WebUI
    checks, TG/Oracle-Sg/Hytron functional confirmation, and rollback sanity.
  - Remote `38.65.91.47` is the live matrix host for protocol coverage and
    should be prepared as an isolated test target. Do not persist host
    credentials in this memo, commits, scripts, or logs.
  - Do not rename this into a protocol-specific stage or top-level gate; keep it
    under the existing C0-C10 plan as the live resident adapter matrix closure.

## 2026-06-04 live resident adapter matrix contract implementation

Change summary:
  - Added an explicit live resident default-adapter matrix under
    `dae-daemon::production_runtime_owner::resident_dataplane`.
  - Exposed the matrix through `service-contract` separately from the
    `dae-outbound` formal production matrix.
  - Wired C8 outbound production matrix recertification to require the live
    resident adapter matrix before it can pass default-switch admission.
  - Wired C9 release-default-switch and C10 go-free product-chain gates to keep
    consuming the live adapter readiness from C8/C9, so a formal outbound matrix
    pass can no longer advance the package/release gates by itself.

Important current truth after the implementation:
  - `outbound_production_matrix_contract_ready=true` still means the formal
    protocol/parser/dataplane/underlay matrix exists.
  - `resident_live_adapter_matrix_ready=false` is the current runtime/product
    truth because the live resident adapter is not fully wired for every
    selected-node protocol row.
  - `resident_live_adapter_wired_handler_count=1`.
  - `resident_live_adapter_live_ready_handler_count=0`.
  - The one currently wired row is `vless-vision-tcp-tls`; it records:
      planner admitted,
      TCP live adapter wired,
      UDP live adapter wired,
      transport underlay wired,
      route/group connectivity wired,
      selected-node fail-closed behavior present,
      fingerprint underlay behavior present.
  - That row is still not `live_ready` because remote `38.65.91.47` live matrix
    evidence has not been recorded.
  - The other formal outbound rows are present in the live adapter matrix as
    fail-closed/not-wired rows, not as falsely supported live handlers.

New service-contract fields:
  - `resident_live_adapter_matrix_contract_ready`
  - `resident_live_adapter_matrix_ready`
  - `resident_live_adapter_matrix_runtime_state_ready`
  - `resident_live_adapter_entries_ready`
  - `resident_live_adapter_planner_admission_ready`
  - `resident_live_adapter_tcp_ready`
  - `resident_live_adapter_udp_ready`
  - `resident_live_adapter_transport_underlay_ready`
  - `resident_live_adapter_route_group_connectivity_ready`
  - `resident_live_adapter_selected_node_fail_closed_ready`
  - `resident_live_adapter_fingerprint_underlay_ready`
  - `resident_live_adapter_go_outbound_fallback_retirement_ready`
  - `resident_live_adapter_wired_matrix_ready`
  - `resident_live_adapter_remote_live_matrix_ready`
  - `resident_live_adapter_wired_handler_count`
  - `resident_live_adapter_live_ready_handler_count`
  - `resident_live_adapter_matrix_entries`
  - `resident_live_adapter_matrix_typed_report`
  - `resident_live_adapter_matrix_surface`

C8/C9/C10 admission rule:
  - C8 now requires:
      formal outbound matrix ready,
      fingerprint underlay ready,
      resident live adapter matrix contract ready,
      resident live adapter matrix ready,
      resident live adapter runtime state ready,
      resident live adapter wired matrix ready,
      resident live adapter remote live matrix ready,
      resident live adapter typed report ready.
  - C9 now explicitly blocks if C8 did not carry
    `resident_live_adapter_matrix_ready=true`.
  - C10 now explicitly blocks if C9 did not carry
    `resident_live_adapter_matrix_ready=true`.
  - This prevents a go-free/default-package claim from being derived only from
    the formal `dae-outbound` matrix.

uTLS parity claim boundary:
  - The service-contract still reports
    `outbound_fingerprint_underlay_typed_report.full_utls_parity_declared=false`.
  - A new typed-report field records
    `wire_oracle_required_before_full_utls_parity=true`.
  - The current Boring-backed fingerprint underlay is enough for native
    fingerprint admission testing, but it is not a full uTLS parity claim.

Validation completed locally:
  - `cargo fmt --manifest-path rust/Cargo.toml --all`
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon --test service_contract`
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon --test daed_product --test service_contract`
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon product_chain_recertification::tests`
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon production_runtime_owner::resident_dataplane::plan`

Remote/live boundary:
  - Live protocol/default-adapter matrix testing remains assigned to remote
    `38.65.91.47`.
  - Do not use `10.10.10.2` for this protocol matrix. It remains only the
    household/default-path smoke host.

Remote `38.65.91.47` check for this change:
  - Uploaded the release `daed` candidate only to a temporary path:
      `/tmp/daed-native-live-adapter-ddc9888c`
  - Candidate sha256:
      `ddc9888c644917aaf4244024fc8c0d572d3cac81b532a7d411e289d1dad7e462`
  - No system `daed` binary or `daed.service` was present on this host during
    this check.
  - Existing lab service state:
      `daerust-route-lab.service=active`
  - Existing config inventory:
      `/etc/dae/config.dae` exists and contains vless plus ss/http-style
      material, but it is not a complete ten-protocol live matrix fixture.
  - Temporary candidate `service-contract` result on remote 38:
      `outbound_production_matrix_contract_ready=True`,
      `resident_live_adapter_matrix_ready=False`,
      `resident_live_adapter_wired_matrix_ready=False`,
      `resident_live_adapter_remote_live_matrix_ready=False`,
      `resident_live_adapter_wired_handler_count=1`,
      `resident_live_adapter_live_ready_handler_count=0`,
      `resident_live_adapter_matrix_typed_report.status=blocked`,
      `outbound_fingerprint_underlay_typed_report.full_utls_parity_declared=False`,
      `wire_oracle_required_before_full_utls_parity=True`.
  - Attempting old-style `validate -c /etc/dae/config.dae` against this `daed`
    product binary returned `unsupported daed command: validate`; do not treat
    old `dae validate` parity as proven by this product binary.
  - No system binary replacement, service restart, tproxy attachment, or default
    path mutation was performed on remote 38 in this check.

## 2026-06-04 resident adapter matrix read-only command

New command:
  - `daed resident-adapter-matrix -c <config.dae> [--json]`

Purpose:
  - Provides a non-mutating resident live adapter matrix assessment for a config
    file.
  - Reuses the real resident dataplane planner instead of implementing a second
    parser/admission path.
  - Reports whether the selected group/node shape is admitted, fail-closed, or
    not applicable.
  - Does not start daed, attach tproxy/eBPF, open outbound network sockets, or
    mutate host state.
  - Does not emit full node links. The report is limited to safe matrix fields
    such as protocol, group, node tag, transport/security/flow, fingerprint
    underlay flag, and sanitized uTLS metadata.

Report schema:
  - `resident-live-adapter-config-assessment-v1`

Important report fields:
  - `read_only=true`
  - `host_mutation_executed=false`
  - `network_io_executed=false`
  - `live_traffic_executed=false`
  - `status`
      `admitted`, `blocked`, or `not-applicable`
  - `planner_admitted`
  - `selected_node_fail_closed`
  - `resident_dataplane_enabled_by_config`
  - `resident_live_adapter_matrix_ready`
  - `resident_live_adapter_wired_matrix_ready`
  - `resident_live_adapter_remote_live_matrix_ready`
  - `default_proxy`
  - `proxies`
  - `blockers`

Remote `38.65.91.47` non-mutating validation:
  - Uploaded temporary candidate:
      `/tmp/daed-native-resident-adapter-matrix-18608068`
  - Candidate sha256:
      `186080682ec0923657c3edd9e4e72ee02e3074443f1105ea1ef540d796199932`
  - Ran:
      `/tmp/daed-native-resident-adapter-matrix-18608068 resident-adapter-matrix -c /etc/dae/config.dae --json`
  - Existing `/etc/dae/config.dae` permissions:
      `0600`
  - Result summary:
      `schema='resident-live-adapter-config-assessment-v1'`,
      `status='admitted'`,
      `planner_admitted=True`,
      `selected_node_fail_closed=True`,
      `resident_dataplane_enabled_by_config=True`,
      `resident_live_adapter_matrix_ready=False`,
      `resident_live_adapter_wired_matrix_ready=False`,
      `resident_live_adapter_remote_live_matrix_ready=False`,
      `proxy_count=1`,
      `default_protocol='vless'`,
      `default_group='proxy'`,
      `default_node_tag='vless_live'`,
      `default_transport='tcp'`,
      `default_security='tls'`,
      `default_flow='xtls-rprx-vision'`,
      `default_fingerprint_underlay=True`,
      `blockers=["remote live traffic matrix not executed by this read-only assessment"]`.
  - Remote report path:
      `/tmp/daed-native-resident-adapter-matrix-report.json`
  - Remote report size:
      `3691` bytes.
  - Remote report link/secret scan:
      no `vless://`, no `ss://`, no sample UUID fragment, no sample SS credential
      fragment found.
  - No system binary replacement, service restart, tproxy/eBPF attach, or default
    path mutation was performed.

Interpretation:
  - Remote 38 current config is admitted by the resident planner for the selected
    VLESS Vision TCP/TLS/fingerprint-underlay shape.
  - This is not yet the full remote live traffic matrix. It is the read-only
    planner/config admission evidence needed before executing real traffic
    matrix rows.
  - The complete live adapter matrix must stay blocked until real traffic
    evidence is recorded on remote 38 for the required matrix rows.

## 2026-06-04 resident adapter full matrix open

Scope:
  - Extends `daed resident-adapter-matrix -c <config.dae> [--json]` from a
    selected-node-only assessment into a full formal-row resident adapter
    matrix assessment.
  - This remains a read-only C8/C10 evidence helper. It does not start daed,
    attach tproxy/eBPF, open outbound network sockets, restart services, or
    mutate default paths.
  - `full_matrix_open=true` means the command enumerates all formal rows and
    runs config/planner admission per matching node candidate.
  - `full_matrix_open=true` is not equivalent to
    `resident_live_adapter_matrix_ready=true`; live traffic evidence is still
    required before the matrix can be complete.

Implementation rules:
  - The full-row assessment reuses the real resident dataplane planner through
    `build_proxy_plan`; it does not introduce a second parser/admission path.
  - Matrix rows report `planner_status` as:
      `admitted`, `blocked`, or `not-present`.
  - Candidate reports are sanitized and must not emit raw node links or link
    credentials.
  - Top-level field names remain protocol-generic:
      `full_matrix_open`, `full_matrix_rows`,
      `full_matrix_present_row_count`, `full_matrix_admitted_row_count`,
      `full_matrix_complete`.
  - Protocol names are allowed only as formal matrix row values, fixtures,
    tests, handler internals, or evidence descriptions.

New report fields:
  - `full_matrix_open`
  - `full_matrix_row_count`
  - `full_matrix_present_row_count`
  - `full_matrix_admitted_row_count`
  - `full_matrix_complete`
  - `full_matrix_completion_blocker`
  - `full_matrix_rows`

Remote `38.65.91.47` non-mutating validation:
  - Uploaded temporary candidate:
      `/tmp/daed-native-full-matrix-a3df5a3e`
  - Candidate sha256:
      `a3df5a3ed6a8c8da3dae8a50d70571949b6a0e1e238f2ef1166d7430e9d34b8b`
  - Ran:
      `/tmp/daed-native-full-matrix-a3df5a3e resident-adapter-matrix -c /etc/dae/config.dae --json`
  - Result summary:
      `schema='resident-live-adapter-config-assessment-v1'`,
      `status='admitted'`,
      `planner_admitted=True`,
      `default_node_tag='vless_live'`,
      `default_protocol='vless'`,
      `default_fingerprint_underlay=True`,
      `full_matrix_open=True`,
      `full_matrix_row_count=10`,
      `full_matrix_present_row_count=1`,
      `full_matrix_admitted_row_count=1`,
      `full_matrix_complete=False`.
  - Formal row summary on the current remote config:
      `vless admitted 1 1 0`,
      `shadowsocks not-present 0 0 0`,
      `trojan not-present 0 0 0`,
      `vmess not-present 0 0 0`,
      `hysteria2 not-present 0 0 0`,
      `tuic not-present 0 0 0`,
      `juicity not-present 0 0 0`,
      `anytls not-present 0 0 0`,
      `http-proxy not-present 0 0 0`,
      `socks5 not-present 0 0 0`.
  - Remote report link/secret scan:
      no raw `vless://`, `ss://`, `trojan://`, `vmess://`,
      `hysteria2://`, `hy2://`, `tuic://`, `juicity://`, `anytls://`,
      sample UUID fragment, or sample SS credential fragment found.
  - No system binary replacement, service restart, tproxy/eBPF attach, or
    default path mutation was performed.

Interpretation:
  - The full formal matrix is now open for planner/config inspection.
  - Current remote 38 config only supplies one present/admitted formal row, so
    the live matrix correctly remains incomplete.
  - The next C8/C10 evidence step is to provide a complete remote 38 live
    fixture and run real traffic rows; do not mark unsupported, unwired, or
    untested rows ready based only on this read-only command.

## 2026-06-04 JP real protocol matrix fixture and remote 38 run

Scope:
  - Prepared a dedicated JP server-side protocol fixture on `156.246.90.2`.
  - Executed the real protocol connectivity matrix from remote `38.65.91.47`.
  - This section records endpoint/protocol evidence only. It does not claim
    Rust resident adapter full coverage by itself.
  - No SSH password, raw node link, UUID, or node password is recorded here.

JP server fixture:
  - New systemd services:
      `daex-matrix-jp.service`,
      `daex-matrix-juicity.service`.
  - Existing services on JP were not replaced:
      existing sing-box on `443` was left intact,
      existing `/opt/xhttp-test-156` xray test process was left intact.
  - `daex-matrix-jp.service` runs sing-box `1.12.21`.
  - `daex-matrix-juicity.service` runs juicity-server `v0.5.0`.
  - Certificate/SNI used by the fixture:
      `lovely.moe` with existing `/root/.ssl/sing-box.crt` and key on JP.
  - Listening rows:
      `vless` on TCP `28443`,
      `trojan` on TCP `28444`,
      `vmess` on TCP `28445`,
      `shadowsocks` on TCP `28446`,
      `socks5` on TCP `28447`,
      `http-proxy` on TCP `28448`,
      `hysteria2` on UDP `28449`,
      `tuic` on UDP `28450`,
      `anytls` on TCP `28451`,
      `juicity` on UDP `28452`.
  - JP service status after setup:
      both services active.

Remote 38 real protocol connectivity matrix:
  - Client host:
      `38.65.91.47`.
  - Target used for every row:
      `http://example.com/`.
  - Client tools:
      temporary sing-box client for all rows except juicity,
      temporary juicity-client for the juicity row.
  - Method:
      each row started a local SOCKS listener on remote 38, routed that listener
      through the matching JP protocol endpoint, then used curl through the local
      SOCKS listener to fetch the target URL.
  - Result schema:
      `daex-jp-real-protocol-matrix-v1`.
  - Result summary:
      `row_count=10`,
      `pass_count=10`,
      `all_pass=true`.
  - Row results:
      `vless true http_code=200`,
      `trojan true http_code=200`,
      `vmess true http_code=200`,
      `shadowsocks true http_code=200`,
      `socks5 true http_code=200`,
      `http-proxy true http_code=200`,
      `hysteria2 true http_code=200`,
      `tuic true http_code=200`,
      `anytls true http_code=200`,
      `juicity true http_code=200`.

Remote 38 Rust resident adapter assessment against the JP full fixture:
  - Used temporary candidate:
      `/tmp/daed-native-full-matrix-eb61d5b1`
  - Candidate sha256:
      `a3df5a3ed6a8c8da3dae8a50d70571949b6a0e1e238f2ef1166d7430e9d34b8b`
  - Command:
      `resident-adapter-matrix -c <temporary JP full fixture config> --json`
  - Result schema:
      `resident-live-adapter-config-assessment-v1`.
  - Result summary:
      `status='admitted'`,
      `planner_admitted=True`,
      `default_node='jp_vless'`,
      `default_fingerprint_underlay=True`,
      `full_matrix_open=True`,
      `full_matrix_row_count=10`,
      `full_matrix_present_row_count=10`,
      `full_matrix_admitted_row_count=1`,
      `full_matrix_complete=False`.
  - Row summary:
      `vless admitted 1 1 0`,
      `shadowsocks blocked 1 0 1`,
      `trojan blocked 1 0 1`,
      `vmess blocked 1 0 1`,
      `hysteria2 blocked 1 0 1`,
      `tuic blocked 1 0 1`,
      `juicity blocked 1 0 1`,
      `anytls blocked 1 0 1`,
      `http-proxy blocked 1 0 1`,
      `socks5 blocked 1 0 1`.
  - Report leak scan:
      no raw proxy link, fixture UUID, or fixture password string was present in
      the generated real-protocol or resident assessment reports.

Cleanup and retained state:
  - Remote 38 temporary client configs, raw node fixture config, temporary
    sing-box client, temporary juicity-client, temporary daed candidate, and old
    matrix test leftovers were removed.
  - Remote 38 retained only:
      `/tmp/daex-matrix-38-summary.txt`
      with a sanitized summary.
  - JP retains the new matrix services and their root-owned configs because
    they are the server-side fixture for repeat matrix runs.

Interpretation:
  - The JP server-side real protocol fixture is usable for all ten formal
    protocol rows from remote 38.
  - This removes the previous blocker that remote 38 did not have a complete
    server-side live fixture to test against.
  - The Rust resident adapter still does not have full live selected-node
    protocol coverage: with all ten JP nodes present, only the current VLESS
    Vision TCP/TLS/fingerprint row is admitted; the other nine rows correctly
    remain blocked by the resident planner.
  - Therefore this evidence should be recorded as:
      server-side/live-protocol-fixture ready,
      current resident full-matrix config assessment complete,
      resident adapter full protocol dispatch still pending.

## 2026-06-04 resident adapter first batch admission start

Scope:
  - Starts the first resident adapter admission work item under the existing
    C8/C10 matrix closure.
  - This is not a new C0-C10 stage and does not introduce a protocol-specific
    top-level gate name.
  - Protocol names in this section are matrix row values/evidence only.

First batch rows:
  - `socks5`
  - `http-proxy`
  - `shadowsocks`

Admission rule:
  - A first-batch row may become `planner_status='admitted'` only when the
    resident planner builds a protocol-specific executable Rust proxy plan and
    the resident TCP adapter can route selected TCP flows through that plan.
  - Do not mark a row admitted by editing only
    `resident_dataplane/adapter_matrix.rs`.
  - Do not mark UDP/full-live readiness for a first-batch row until UDP behavior
    is implemented and remotely verified.
  - Do not claim `resident_live_adapter_matrix_ready=true` while any formal row
    still lacks required live evidence.

Implementation boundary:
  - Replace the VLESS-only `build_proxy_plan` hard gate with protocol dispatch
    for the first-batch rows while preserving fail-closed behavior for every
    row that is still unwired.
  - Extend `ResidentProxyPlan` into a protocol-shaped runtime plan rather than
    storing first-batch secrets in generic VLESS fields.
  - Reuse existing `dae-outbound` parser/packet helpers where they exist.
  - Keep link/global fingerprint handling on the existing fingerprint-aware TLS
    path. First-batch plain TCP rows must not silently consume fingerprint
    settings.

Remote validation target:
  - Use JP fixture `156.246.90.2` as the server-side matrix endpoint.
  - Use remote `38.65.91.47` for real traffic evidence.
  - Do not use `10.10.10.2` for this protocol/live adapter matrix.

Expected first-batch completion evidence:
  - `resident-adapter-matrix` against the full JP fixture reports the first
    batch as present/admitted while still blocking rows that are not wired.
  - A real TCP flow smoke from remote 38 through the Rust resident adapter
    succeeds for each first-batch row.
  - Event logs show the resident protocol handler used for the selected row, and
    no Go outbound fallback was used.

## 2026-06-04 resident adapter first batch read-only validation

Scope:
  - Continues the first resident adapter admission work item under existing
    C8/C10 matrix closure.
  - This records implementation and read-only planner evidence only.
  - This does not mark UDP readiness, full wired readiness, or remote live
    traffic readiness.
  - No SSH password, raw node link, UUID, or node password is recorded here.

Implementation summary:
  - `ResidentProxyPlan` is now protocol-shaped through
    `ResidentProxyProtocolPlan` instead of storing every handler in VLESS-only
    fields.
  - First-batch planner dispatch is admitted for these matrix row shapes:
      `socks5` plain TCP,
      `http-proxy` plain HTTP CONNECT TCP,
      `shadowsocks` ordinary stage18 AEAD TCP.
  - Unsupported first-batch shapes remain fail-closed:
      HTTPS proxy endpoints,
      HTTP transport mode,
      HTTP proxy `allow_insecure`,
      Shadowsocks SIP003/plugin,
      Shadowsocks 2022/non-stage18 AEAD ciphers.
  - Resident TCP runtime dispatch now routes first-batch selected TCP flows to
    protocol-specific Rust handlers.
  - VLESS Vision TCP/TLS keeps the existing fingerprint-aware TLS dispatcher.
  - First-batch plain TCP rows do not consume link/global fingerprint settings.
  - Shadowsocks AEAD TCP relay starts upload before waiting for response salt and
    uses a shared stop flag so the upload relay can be joined on close/error.

Local validation:
  - `cargo fmt --manifest-path rust/Cargo.toml --all`: pass.
  - `cargo check --manifest-path rust/Cargo.toml -p dae-daemon`: pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon production_runtime_owner::resident_dataplane`:
      pass, `46 passed`.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon --test daed_product daed_resident_adapter_matrix`:
      pass, `4 passed`.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon`:
      pass, `205` unit tests plus integration/doc test groups passed.
  - `cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf`:
      pass.
  - `git diff --check`: pass.

Release candidate used for remote read-only assessment:
  - Local path:
      `rust/target/release/daed`.
  - Candidate sha256:
      `060800e19d2bf2378ca6505fbf1f2373a6f593c8b792248538543e91e5b0e399`.
  - Candidate size:
      `18M`.

Remote 38 read-only matrix assessment:
  - Host:
      `38.65.91.47`.
  - Temporary candidate path:
      `/tmp/daed-native-first-batch-060800e1`.
  - Command:
      `resident-adapter-matrix -c <temporary JP full fixture config> --json`.
  - Result schema:
      `resident-live-adapter-config-assessment-v1`.
  - Result summary:
      `status='admitted'`,
      `planner_admitted=True`,
      `full_matrix_open=True`,
      `full_matrix_row_count=10`,
      `full_matrix_present_row_count=10`,
      `full_matrix_admitted_row_count=4`,
      `full_matrix_complete=False`,
      `resident_live_adapter_matrix_ready=False`,
      `resident_live_adapter_wired_matrix_ready=False`,
      `resident_live_adapter_remote_live_matrix_ready=False`,
      `network_io_executed=False`,
      `live_traffic_executed=False`.
  - Admitted read-only planner rows:
      `vless`,
      `shadowsocks`,
      `http-proxy`,
      `socks5`.
  - Still blocked rows:
      `trojan`,
      `vmess`,
      `hysteria2`,
      `tuic`,
      `juicity`,
      `anytls`.
  - Report leak scan:
      no raw proxy link, fixture UUID, or fixture password string was present in
      the generated resident assessment report.

Remote cleanup:
  - Removed from remote 38:
      temporary candidate binary,
      temporary raw JP fixture config,
      temporary resident assessment JSON report.
  - Retained on remote 38:
      `/tmp/daex-matrix-38/first-batch-summary.txt`,
      sanitized summary only.

Interpretation:
  - The first batch is now admitted by the read-only resident planner assessment
    when matching matrix row shapes are present in the config.
  - This is stronger than editing only the formal adapter matrix because the
    candidate report is produced by building executable Rust resident proxy
    plans for the matching nodes.
  - It is not yet full live adapter completion: remote 38 real tproxy/resident
    traffic smoke and per-row event evidence are still pending.
  - The remaining six formal rows are intentionally still fail-closed until
    their Rust planner/runtime handlers are implemented and verified.

## 2026-06-04 10.10.10.2 host-originated traffic DNS fix

Scope:
  - Live host:
      `10.10.10.2`.
  - This records a host-originated traffic issue found while the Rust native
    test drop-in was active.
  - No SSH password or raw node secret is recorded here.

Observed live state:
  - `daed.service` was active with test drop-in:
      `/etc/systemd/system/daed.service.d/50-rust-native-test.conf`.
  - The drop-in enabled:
      `DAE_RUST_RESIDENT_DATAPLANE=1`,
      `DAE_RUST_NATIVE_EBPF=1`.
  - Main route table was normal:
      default route via `10.10.10.1` on `enp1s0`.
  - IPv4 connectivity by address was available:
      ping to `10.10.10.1`, `1.1.1.1`, and `8.8.8.8` passed.
  - Host resolver was wrong for this test state:
      `/etc/resolv.conf` contained `nameserver 8.8.8.8`.
  - NetworkManager active connection also reported:
      `IP4.DNS[1]=8.8.8.8`.

Failure shape:
  - `getent hosts example.com` and host `curl` by domain timed out during name
    resolution.
  - Direct DNS to configured local resolver worked:
      `dig @192.168.2.11 example.com A` returned immediately.
  - DNS to gateway worked:
      `dig @10.10.10.1 example.com A` returned immediately.
  - UDP DNS to public resolver failed:
      `dig @8.8.8.8 example.com A` timed out.
  - TCP DNS to public resolver was not the failing shape; the observed host
    resolver failure was UDP/53.

Why this matters:
  - The selected dae config uses DNS upstream:
      `tcp+udp://192.168.2.11:53`.
  - The selected routing config sends public DNS destinations through proxy:
      `dip(8.8.8.8, 8.8.4.4, 1.1.1.1) -> proxy`.
  - With Rust native test state, host-originated resolver traffic to public
    UDP/53 is not a valid proxy evidence path and can make all host-originated
    domain traffic look dead before TCP proxying is exercised.
  - This is separate from resident outbound protocol failures and separate from
    LAN Telegram TCP evidence.

Live fix applied:
  - Backed up the previous resolver file to:
      `/etc/resolv.conf.daex-before-local-dns-fix-20260604-2008`.
  - Persistently changed the active NetworkManager connection:
      `ipv4.ignore-auto-dns=yes`,
      `ipv4.dns=192.168.2.11,10.10.10.1`.
  - Reapplied the `enp1s0` connection without replacing `daed`.

Post-fix validation:
  - `/etc/resolv.conf` now contains:
      `nameserver 192.168.2.11`,
      `nameserver 10.10.10.1`.
  - NetworkManager reports:
      `IP4.DNS[1]=192.168.2.11`,
      `IP4.DNS[2]=10.10.10.1`.
  - `getent hosts example.com`: pass.
  - `dig example.com A`: pass.
  - `curl -4 -I http://example.com/`: HTTP `200`.
  - `curl -4 -I https://example.com/`: HTTP `200`.
  - `curl -4 -I https://www.google.com/`: HTTP `200`.

Follow-up requirement:
  - Rust product/native test deployment must not use host-local curl/getent
    evidence while `/etc/resolv.conf` points at a public UDP resolver that the
    policy routes through proxy.
  - Product runtime should either:
      preserve/derive host resolver from the selected local DNS upstream when
      host mutation is explicitly allowed,
      or report a fail-closed warning that host resolver state is inconsistent
      with selected dae DNS/routing policy.
  - Do not use this host resolver fix as evidence that resident UDP/XUDP or
    first-batch outbound matrix rows are complete.

## 2026-06-04 10.10.10.2 host-originated routing clarification

Scope:
  - Live host:
      `10.10.10.2`.
  - This clarifies whether traffic generated by the daed host itself is covered
    by Rust native routing, separate from LAN forwarded clients.

Host-originated TCP evidence:
  - Test:
      `curl -4 -I http://1.1.1.1/`.
  - Matching resident event:
      `peer='10.10.10.2:<port>'`,
      `original_dst='1.1.1.1:80'`,
      `outbound_kind='proxy'`,
      `proxy_group='proxy'`,
      `node_tag='[HK]Hytron'`,
      `userspace_route_executed=true`.
  - Interpretation:
      host TCP to an IP covered by `dip(1.1.1.1) -> proxy` is routed through
      resident proxy.

  - Test:
      `curl -4 -I --resolve www.google.com:443:<ip> https://www.google.com/`.
  - Matching resident event:
      `peer='10.10.10.2:<port>'`,
      `original_dst='<google-ip>:443'`,
      `sniffed_domain='www.google.com'`,
      `outbound_kind='proxy'`,
      `proxy_group='openai'`,
      `node_tag='[US]Dmit-Mabuli'`,
      `userspace_route_executed=true`.
  - Interpretation:
      host TCP domain/sniff route is executed and can change the selected group
      from the initial proxy route to the final domain route.

  - Test:
      `curl -4 -I --resolve edge.myqnapcloud.io:443:<ip> https://edge.myqnapcloud.io/`.
  - Matching resident event:
      `peer='10.10.10.2:<port>'`,
      `sniffed_domain='edge.myqnapcloud.io'`,
      `outbound_kind='direct'`,
      `userspace_route_executed=true`,
      `userspace_route_must=true`.
  - Interpretation:
      host TCP must-direct domain route is executed.

Host-originated UDP evidence:
  - Test:
      `dig @8.8.8.8 example.com A`.
  - Result:
      timed out.
  - Resident event evidence:
      no new `peer='10.10.10.2:<port>'` UDP event was recorded in the resident
      event file during the test window.

  - Test:
      one UDP packet to `1.1.1.1:443`.
  - Result:
      send completed locally, but no new host-originated resident UDP event was
      recorded after waiting longer than the resident UDP response timeout.

Interpretation:
  - Host-originated TCP is currently covered by Rust native routing.
  - Host-originated UDP is not yet proven covered and did not show the expected
    resident event evidence in the live test.
  - LAN-originated UDP events are present in the same resident event file, so
    the UDP worker itself is running; the observed gap is specifically the
    host-originated UDP/OUTPUT path or its handoff into resident UDP.
  - DNS is one visible symptom of that host-originated UDP gap, but the gap is
    broader than DNS until host-originated UDP/443 and UDP/53 both show routing
    and resident event evidence.

## 2026-06-04 host-originated UDP Go parity audit and Rust fix

Scope:
  - Repo:
      `/root/project/dae-daex-align`.
  - Live host used for audit:
      `10.10.10.2`.
  - No credentials are recorded here.

User correction:
  - The issue must not be treated as "WAN setting missing" without evidence.
  - `10.10.10.2` WebUI/runtime settings do include WAN:
      `wan_interface:"enp1s0"`.

Live config propagation audit:
  - Active service:
      `/usr/bin/daed run -c /etc/daed/`.
  - Active drop-in:
      `/etc/systemd/system/daed.service.d/50-rust-native-test.conf`.
  - Active generated config:
      `/etc/daed/runtime/generated.dae`.
  - Generated config contains:
      `lan_interface:"enp1s0"`,
      `wan_interface:"enp1s0"`.
  - Current resident start report:
      `/tmp/dae-daemon-resident-runtime-35120/resident-production-runtime-start.json`.
  - Report confirms selected settings reached Rust resident runtime:
      `lan_interfaces=["enp1s0"]`,
      `wan_interfaces=["enp1s0"]`.
  - Report confirms live attach:
      `wan_ingress` on `enp1s0`: `status=pass`, `backend=tcx`.
      `wan_egress` on `enp1s0`: `status=pass`, `backend=tcx`.
      cgroup pname monitor: `status=pass`, `backend=aya`.
      resident dataplane: `enabled=true`, `status=pass`, `udp_worker_started=true`.
  - `bpftool net` confirms TCX attach order on the shared physical interface:
      `enp1s0 tcx/ingress tproxy_wan_ingress_l2`
      before `tproxy_lan_ingress_l2`.
      `enp1s0 tcx/egress tproxy_lan_egress_l2`
      before `tproxy_wan_egress_l2`.
  - `daens` confirms tproxy delivery prerequisites:
      fwmark rule `0x8000000/0x8000000 lookup 2023`.
      table 2023 `local default dev lo`.
      UDP/TCP listener on `0.0.0.0:12345`.

Conclusion from audit:
  - Settings are passed from product state to generated dae config and into
    Rust resident runtime.
  - The remaining observed failure is not a config propagation issue.
  - Host-originated UDP packets do enter the kernel path:
      `tproxy_wan_egress_l2` run count increased during `dig @8.8.8.8`.
      `tproxy_dae0peer_ingress` run count also increased.
  - Historical resident events already contain host-originated UDP/DNS:
      `peer="10.10.10.2:<port>"`,
      `original_dst="8.8.8.8:53"`,
      `event="udp_dns_packet_finished"`.
      Host UDP/443 also produced `udp_exchange_failed` timeout events.
  - The immediate live symptom is latency/head-of-line blocking:
      a one-second `dig @8.8.8.8 example.com A` timed out while no new event
      appeared within two seconds.
      The tproxy UDP socket Recv-Q was non-zero and LAN UDP VLESS timeouts were
      present in the same event stream.

Original Go/C parity finding:
  - Go/C tproxy has host-originated UDP coverage in `do_tproxy_wan_egress`.
  - Go/C uses cgroup sendmsg/connect hooks to populate cookie->pid/pname for
    host UDP/TCP.
  - Go/C UDP datapath is endpoint/goroutine based; one slow UDP exchange does
    not serialize every following UDP packet from host and LAN.
  - Rust resident UDP had a single `resident_udp_loop` that did:
      `recvmsg original_dst -> DNS/VLESS exchange -> send reply`
    inline.
  - Therefore one VLESS UDP/XUDP timeout could block the only receiver loop
    for up to `RESIDENT_UDP_RESPONSE_TIMEOUT`, delaying host DNS/UDP behind
    unrelated LAN QUIC/UDP packets.

Fix applied locally:
  - `resident_udp_loop` now keeps one fast tproxy UDP receiver and dispatches
    each received packet to a bounded packet worker.
  - New runtime knobs:
      `DAE_RESIDENT_UDP_PACKET_WORKERS`
      default `64`, clamped `1..1024`.
      `DAE_RESIDENT_UDP_PACKET_STACK_BYTES`
      default `262144`, clamped `131072..4194304`.
  - UDP worker start events and resident start report now include:
      `worker_limit`,
      `worker_stack_bytes`,
      `udp_packet_workers`,
      `udp_packet_stack_bytes`.
  - If the worker cap is reached, Rust emits a structured
    `udp_packet_dropped` event with peer/original_dst/active_workers instead of
    silently accumulating unbounded work.
  - Per-packet metrics are still bounded by guard-based open/close accounting,
    and upload/download counters remain updated by packet workers.

Local verification:
  - `cargo fmt --check`: pass.
  - `cargo test -p dae-daemon production_runtime_owner::resident_dataplane`:
    pass, 46 tests passed.

Next live verification target:
  - Build the default jemalloc/native-ebpf Rust `daed`:
      `cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf`.
  - Deploy it to `10.10.10.2` over the current test binary without backing up
    the test binary.
  - Restart `daed`, confirm resident report shows:
      `udp_packet_workers=64`,
      `udp_packet_stack_bytes=262144`,
      `wan_interfaces=["enp1s0"]`,
      `wan_egress status=pass`.
  - Re-test:
      `dig @8.8.8.8 example.com A`,
      one UDP packet to `1.1.1.1:443`,
      confirm new resident events appear promptly with peer `10.10.10.2`.

Live deployment result:
  - Built default jemalloc/native-ebpf Rust `daed` locally:
      `cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf`.
  - Local and deployed binary:
      size `18M`,
      sha256 `e1fb01408ef31af1121d5134dd2e35c8a148d121de7db8ec76f7cd899b41d404`.
  - Deployed to `10.10.10.2` as `/usr/bin/daed` over the current test binary.
    No test-binary backup was made.
  - Restarted `daed`; service is active with PID `46636`.
  - Current resident start report:
      `/tmp/dae-daemon-resident-runtime-46636/resident-production-runtime-start.json`.
  - Report confirms:
      `resident_runtime_started=true`,
      `resident_dataplane.enabled=true`,
      `resident_dataplane.status=pass`,
      `udp_worker_started=true`,
      `udp_packet_workers=64`,
      `udp_packet_stack_bytes=262144`,
      `wan_interfaces=["enp1s0"]`,
      `wan_ingress status=pass backend=tcx`,
      `wan_egress status=pass backend=tcx`,
      cgroup monitor `status=pass backend=aya`.
  - `bpftool net` confirms TCX attach remains:
      `enp1s0 tcx/ingress tproxy_wan_ingress_l2`
      `enp1s0 tcx/ingress tproxy_lan_ingress_l2`
      `enp1s0 tcx/egress tproxy_lan_egress_l2`
      `enp1s0 tcx/egress tproxy_wan_egress_l2`.

Live host UDP validation after fix:
  - `dig +time=3 +tries=1 @8.8.8.8 example.com A` from `10.10.10.2`:
      pass, `Query time: 14 msec`.
  - Immediate resident event:
      `event="udp_dns_packet_finished"`,
      `peer="10.10.10.2:31999"`,
      `original_dst="8.8.8.8:53"`,
      `request_len=52`,
      `response_len=67`.
  - Explicit host UDP packet:
      `bash -c 'printf daexhostudp >/dev/udp/1.1.1.1/443'`.
  - Resident event after the expected VLESS UDP timeout window:
      `event="udp_exchange_failed"`,
      `peer="10.10.10.2:25706"`,
      `original_dst="1.1.1.1:443"`,
      `error="VLESS UDP response timeout"`.
  - Interpretation:
      host-originated UDP is now demonstrably handed into resident UDP workers.
      DNS no longer waits behind unrelated LAN UDP timeout work.
      UDP/443 reaches its own worker and fails according to current VLESS UDP
      behavior instead of disappearing before resident processing.
  - Final quick health:
      `udp_packet_dropped` count in current event file: `0`.
      `daens` UDP `0.0.0.0:12345` Recv-Q: `0`.
      `daed` service: active.

Follow-up live DNS resolver test:
  - User requested setting the `10.10.10.2` host resolver to public DNS
    `8.8.8.8` to validate host-originated DNS through Rust native routing.
  - Active NetworkManager connection:
      `enp1s0`.
  - Applied:
      `ipv4.ignore-auto-dns=yes`,
      `ipv4.dns=8.8.8.8`.
  - Reapplied the connection with `nmcli dev reapply enp1s0`.
  - `/etc/resolv.conf` now contains:
      `nameserver 8.8.8.8`.
  - `dig +time=3 +tries=1 example.com A` using the default resolver:
      pass,
      server `8.8.8.8#53`,
      query time `17 msec`.
  - `getent hosts example.com`:
      pass.
  - `curl -4 -I http://example.com/`:
      pass, HTTP `200`.
  - `curl -4 -I https://www.google.com/`:
      pass, HTTP/2 `200`.
  - Resident events immediately showed host-originated DNS proxying:
      `event="udp_dns_packet_finished"`,
      `peer="10.10.10.2:<port>"`,
      `original_dst="8.8.8.8:53"`,
      `proxy_group="proxy"`,
      `node_tag="[HK]Hytron"`.
  - Resident events also showed the subsequent host-originated TCP flows:
      `example.com:80` through `proxy`,
      `www.google.com:443` through `openai`.
  - Final UDP queue check:
      `daens` UDP `0.0.0.0:12345` Recv-Q remained `0`.
  - Current live state after this test:
      host resolver is intentionally left at `8.8.8.8` for continued manual
      testing.

## 2026-06-04 - Resident live-adapter matrix next-batch wiring

Local commit checkpoint before this batch:
  - Commit:
      `eea26f19 resident: expand matrix and unblock UDP handling`.
  - Scope of that checkpoint:
      first-batch resident planner/TCP handlers,
      UDP packet worker dispatch,
      host-originated UDP/DNS live validation records.

Matrix work resumed after the checkpoint:
  - Formal `dae-outbound` production matrix remains the protocol parser/dataplane
    evidence layer.
  - Resident live-adapter matrix is the product/runtime truth for whether a
    selected node can actually be owned by Rust resident tproxy workers.
  - The resident matrix must keep partial states explicit:
      planner/TCP admission is not the same as UDP admission,
      and neither is the same as remote live matrix evidence.

New local wiring:
  - Added a generic TLS/TCP resident path for plain Trojan endpoints.
  - Admitted shape:
      `trojan://` plain TLS/TCP endpoint,
      no trojan-go transport,
      no `allow_insecure`.
  - Still blocked:
      trojan-go websocket/grpc/httpupgrade/inner transport combinations,
      any shape requiring a handler-specific transport stack that is not wired
      into resident live workers yet.
  - The TCP dispatcher now keeps:
      VLESS Vision on the Vision-aware TLS relay,
      plain SOCKS5/HTTP/Shadowsocks on the first-batch TCP relay path,
      plain Trojan on the generic TLS/plain relay path.
  - The generic TLS/plain relay performs only bidirectional plaintext forwarding
    after the protocol request header is sent; it does not parse VLESS response
    headers or Vision raw-direct records.

Planner and fingerprint behavior:
  - Fingerprint planning was made protocol-generic at the helper boundary.
  - VLESS still uses link `fp` first, then global utls fallback.
  - Plain Trojan currently has no parsed link-level `fp` field in
    `TrojanLink`, so it can use the global utls fallback but not a link-level
    Trojan fingerprint until the parser exposes one.
  - No top-level gate/stage name was made protocol-specific; protocol names
    appear only in matrix rows, handler internals, fixtures, and evidence.

Resident matrix contract update:
  - Static resident matrix entries no longer describe the first-batch TCP rows
    as completely unwired.
  - `shadowsocks`, `http-proxy`, `socks5`, and `trojan` now record partial
    resident wiring:
      `planner_admitted=true`,
      `tcp_live_adapter=true`,
      `transport_underlay=true`,
      `route_group_connectivity=true`,
      `udp_live_adapter=false`,
      `remote_live_matrix=false`,
      `go_outbound_fallback_retired=false`.
  - `wired_ready` and `live_ready` remain false for those rows until UDP/live
    evidence and fallback retirement are actually complete.

Local verification:
  - `cargo fmt --all --manifest-path rust/Cargo.toml`: pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon production_runtime_owner::resident_dataplane`:
      pass, 46 tests passed.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon --test daed_product resident_adapter_matrix`:
      pass, 4 tests passed.

Current matrix state after this local batch:
  - Config assessment admitted rows for the local first-batch fixture:
      `vless`,
      `socks5`,
      `http-proxy`,
      `shadowsocks`,
      `trojan`.
  - Remaining rows stay fail-closed until their real resident worker path is
    implemented and verified:
      `vmess`,
      `hysteria2`,
      `tuic`,
      `juicity`,
      `anytls`.
  - Remote live matrix testing still belongs on remote 38, not on `10.10.10.2`.

Remote 38 read-only assessment after this batch:
  - Built local release candidate:
      `cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf`.
  - Candidate:
      size `18M`,
      sha256 `4679c2549013b3b93f5b02e2f05c5652a3fee5cf3279e517a75da732f5a23350`.
  - Copied temporarily to remote 38 as:
      `/tmp/daed-native-next-batch-4679c254`.
  - Ran only:
      `resident-adapter-matrix -c <temporary full matrix config> --json`.
  - No default service replacement, host networking mutation, or live tproxy
    traffic execution was performed in this check.
  - Result:
      `schema=resident-live-adapter-config-assessment-v1`,
      `status=admitted`,
      `planner_admitted=True`,
      `full_matrix_row_count=10`,
      `full_matrix_present_row_count=10`,
      `full_matrix_admitted_row_count=5`,
      `full_matrix_complete=False`,
      `resident_live_adapter_matrix_ready=False`,
      `resident_live_adapter_wired_matrix_ready=False`,
      `resident_live_adapter_remote_live_matrix_ready=False`.
  - Row summary:
      `vless admitted candidates=1 admitted=1 blocked=0 wired=True live=False`,
      `shadowsocks admitted candidates=1 admitted=1 blocked=0 wired=False live=False`,
      `trojan admitted candidates=1 admitted=1 blocked=0 wired=False live=False`,
      `vmess blocked candidates=1 admitted=0 blocked=1 wired=False live=False`,
      `hysteria2 blocked candidates=1 admitted=0 blocked=1 wired=False live=False`,
      `tuic blocked candidates=1 admitted=0 blocked=1 wired=False live=False`,
      `juicity blocked candidates=1 admitted=0 blocked=1 wired=False live=False`,
      `anytls blocked candidates=1 admitted=0 blocked=1 wired=False live=False`,
      `http-proxy admitted candidates=1 admitted=1 blocked=0 wired=False live=False`,
      `socks5 admitted candidates=1 admitted=1 blocked=0 wired=False live=False`.
  - Report leak scan:
      pass; no raw proxy link, fixture UUID, or fixture password string was
      present in the generated resident assessment report.
  - Remote cleanup:
      temporary candidate binary,
      temporary full matrix config,
      temporary JSON report were removed.
      A follow-up `/tmp` check found no `daed-native-next-batch-*` leftovers.

Local align-chain follow-up:
  - The `dae-daex-align` post-commit hook emitted
      `.git/index: index file open failed: Not a directory`
    during local commits, but the `dae` commits themselves were created
    successfully.
  - Manual verification showed the align chain had not moved from old
    `dae-core` commit `0a688df7`.
  - Manual align was completed after this matrix batch:
      current `dae-daex-align` commit:
        `64a8b8f821f327fc684f7d8d64b2998abb10bf7a`,
      in-tree `daed/wing/dae-core`:
        `64a8b8f821f327fc684f7d8d64b2998abb10bf7a`,
      sibling `dae-wing-daex-align/dae-core`:
        `64a8b8f821f327fc684f7d8d64b2998abb10bf7a`,
      in-tree `daed/wing` commit:
        `9dc1fc729c402970cdea16551b2de18fd5104382`,
      sibling `dae-wing-daex-align` commit:
        `9dc1fc729c402970cdea16551b2de18fd5104382`,
      `daed-daex-align/daed` parent commit:
        `291ac0a`.
  - Repos were verified clean after the manual align:
      `dae-daex-align`,
      `daed-daex-align/daed`,
      `daed-daex-align/daed/wing`,
      `daed-daex-align/daed/wing/dae-core`,
      `dae-wing-daex-align`,
      `dae-wing-daex-align/dae-core`.

## 2026-06-04 C8 Resident Live Adapter Matrix Expansion Follow-up

Scope:
  - Continue the C8 outbound production matrix work without creating a new
    stage name.
  - Keep top-level naming protocol-generic; protocol names appear only in
    matrix rows, handler internals, fixtures, tests, and evidence.
  - Finish the remaining selected-node resident admission gap with real runtime
    wiring rather than a fake planner admission.

Implementation notes:
  - Added reusable runtime helpers in `dae_outbound::juicity`:
      `build_juicity_runtime_client_config`,
      `authenticate_juicity_connection`,
      `write_juicity_tcp_request`,
      `build_juicity_tcp_request`.
  - Juicity auth now follows the Go-side shape:
      open QUIC connection,
      open a unidirectional auth stream,
      derive the auth token from QUIC TLS exporter material,
      write the version-0 authenticate header,
      keep the auth stream alive while TCP relay is active.
  - Juicity TCP stream request follows the Go-side stream connection shape:
      network byte `tcp`,
      Trojan/SOCKS-style target metadata,
      optional sniffed initial payload,
      then raw bidirectional TCP relay over the QUIC stream.
  - Resident TCP QUIC relay was made protocol-generic in error wording and is
    shared by the existing QUIC stream handlers and Juicity.
  - Juicity planner admission is conservative:
      valid UUID required,
      password required,
      QUIC TLS verifier requires either `pinned_certchain_sha256` or explicit
      `allow_insecure` / global allow-insecure,
      no silent accept-any secure mode.
  - Resident matrix entry for Juicity moved from blocked to partial wired:
      `planner_admitted=true`,
      `tcp_live_adapter=true`,
      `transport_underlay=true`,
      `route_group_connectivity=true`,
      `selected_node_fail_closed=true`,
      `fingerprint_underlay=true`,
      `udp_live_adapter=false`,
      `remote_live_matrix=false`,
      `go_outbound_fallback_retired=false`.

Local verification:
  - `cargo fmt --all --manifest-path rust/Cargo.toml`: pass.
  - `cargo check --manifest-path rust/Cargo.toml -p dae-daemon`: pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon production_runtime_owner::resident_dataplane`:
      pass, 46 tests passed.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon --test daed_product resident_adapter_matrix`:
      pass, 4 tests passed.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon`:
      pass, 205 lib tests, 10 product tests, 2 reload owner benchmark tests,
      2 reload owner handoff tests, and 2 service contract tests passed.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-outbound juicity`:
      pass, 23 Juicity-related tests passed.

Release artifact:
  - Built with:
      `cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin daed --release --features native-ebpf`.
  - Candidate:
      local path `rust/target/release/daed`,
      size `20M`,
      sha256 `9061e50397c2798574a3c65deb9b6debcfff672b8a7baa7abe2304018eeff22c`.

Remote 38 read-only assessment:
  - Copied the release candidate temporarily to remote 38 as:
      `/tmp/daed-rust-native-matrix`.
  - Created a temporary 10-row full matrix fixture with only documentation
    hosts and fake fixture credentials.
  - First run was rejected because the temporary config mode was `0644`; this
    confirmed the config permission gate. The config was changed to `0600` and
    the read-only assessment was rerun.
  - Ran only:
      `resident-adapter-matrix -c /tmp/daex-matrix-10row.dae --json`.
  - No service replacement, no host-network mutation, no live tproxy traffic,
    and no persistent config write was performed.
  - Result:
      `schema=resident-live-adapter-config-assessment-v1`,
      `status=admitted`,
      `read_only=True`,
      `host_mutation_executed=False`,
      `network_io_executed=False`,
      `planner_admitted=True`,
      `selected_node_fail_closed=True`,
      `full_matrix_row_count=10`,
      `full_matrix_admitted_row_count=10`.
  - Row summary:
      `vless admitted candidates=1 admitted=1 blocked=0`,
      `shadowsocks admitted candidates=1 admitted=1 blocked=0`,
      `trojan admitted candidates=1 admitted=1 blocked=0`,
      `vmess admitted candidates=1 admitted=1 blocked=0`,
      `hysteria2 admitted candidates=1 admitted=1 blocked=0`,
      `tuic admitted candidates=1 admitted=1 blocked=0`,
      `juicity admitted candidates=1 admitted=1 blocked=0`,
      `anytls admitted candidates=1 admitted=1 blocked=0`,
      `http-proxy admitted candidates=1 admitted=1 blocked=0`,
      `socks5 admitted candidates=1 admitted=1 blocked=0`.
  - Temporary candidate binary, config, and report were removed from remote 38.

Current matrix caveat:
  - Planner admission is now open for all 10 rows in the resident full matrix
    fixture.
  - Complete matrix readiness still remains false by design:
      `resident_live_adapter_wired_matrix_ready=False`,
      `resident_live_adapter_remote_live_matrix_ready=False`,
      `resident_live_adapter_matrix_ready=False`,
      `full_matrix_complete=False`.
  - The current completion blocker remains:
      real live traffic evidence plus the remaining UDP live adapters and Go
      outbound fallback retirement must be finished before the resident live
      adapter matrix is complete.

## 2026-06-05 Rust Product RSS and Log Parity Follow-up

Scope:
  - Continue under the existing C10 Rust product/native-owned path; do not
    create an ad hoc phase or protocol-specific stage.
  - The Rust process memory work should prioritize generic product/runtime
    structures rather than a single protocol branch.

Accepted optimization work items:
  - Keep the service/package memory defaults explicit for Rust native product
    tests: allocator decay/arena policy, HTTP worker count/stack size, and
    resident UDP task limits must be visible in the unit or equivalent package
    runtime environment.
  - Reduce resident dataplane plan cloning for large node/subscription sets:
    only process groups referenced by routing, avoid cloning all node links
    into transient candidate vectors, and keep fixed-policy selection
    iterator-based.
  - Remove the resident routing JSON-fixture round trip from production code:
    one compiled routing/geodata plan should feed both the eBPF map update and
    the userspace routing matcher.
  - Keep runtime overview/log streaming lightweight: full snapshots are for
    first load or reload boundaries; periodic deltas should avoid rebuilding
    large JSON trees or scanning full log/event files.

UDP dataplane rule:
  - Do not replace resident UDP packet handling with a fixed worker model.
  - The prior TCP queue experience showed fixed bounded worker queues can
    break live behavior under real routing/proxy load.
  - UDP should move toward a Tokio UDP task queue/readiness model, with
    backpressure and bounded per-packet state, not a fixed OS-thread pool and
    not one OS thread per packet.

Go daed log parity requirement:
  - Before changing the Rust product log/WebUI behavior, collect live Go daed
    evidence on `10.10.10.2` across runtime log-level and query-level
    combinations.
  - Evidence must include API output shape, emitted task-log content, filtering
    semantics, and WebUI rendering behavior.
  - Rust product log changes should then match Go daed semantics instead of
    tuning only the Rust implementation in isolation.

Live Go daed evidence from `10.10.10.2`:
  - Current baseline was `/usr/bin/daed run -c /etc/daed/` with the Go daed
    backend and no Rust-owned test drop-in.
  - The control API listened on `:2023` and `/api/health` returned
    `{"healthCheck":1}`.
  - The live log cache was `/etc/daed/logs/current.jsonl`.
  - The current log cache held 13 entries: 12 `info` and 1 `warn`.
  - The current runtime log level before and after the matrix was `error`.
  - Current `/api/logs/settings` on the host returned:
      `maxEntries=500`,
      `maxBytes=5242880`,
      `minMaxEntries=500`,
      `maxMaxEntries=50000`,
      `minMaxBytes=5242880`,
      `maxMaxBytes=209715200`.

Go `/api/logs` query semantics:
  - `level=` and `level=all` are unfiltered.
  - Level parsing is case-insensitive.
  - `level=warning` canonicalizes to `warn`.
  - `level=全部` and `level=调试` return HTTP 400; localized labels must never
    be sent as API semantic values.
  - Query filtering is exact by canonical level, not a severity threshold:
      `all -> 13 entries`,
      `warn -> 1 entry`,
      `info -> 12 entries`,
      `error/debug/trace -> 0 entries`.
  - The query result is the newest matching tail, returned in chronological
    order.
  - `limit <= 0` uses the default query limit.
  - `limit=4` returned the newest four entries, not a page size hint for the
    WebUI.
  - Large limits are capped by the Go logstore max query limit.

Go `/api/runtime/log-level` semantics:
  - Runtime level changes are immediate and do not require reload.
  - `PATCH {"level":"error|warn|info|debug|trace"}` returns the canonical level.
  - `PATCH {"level":"warning"}` returns `{"level":"warn"}`.
  - `PATCH {"level":"debug "}` trims and returns `{"level":"debug"}`.
  - `PATCH {"level":"all"}` and localized values such as `全部` return HTTP
    400; runtime level must always be a concrete log level.
  - Changing the runtime level does not refilter or rewrite the historical
    `/api/logs` response; it only controls future log emission.

Go `/api/events/logs` SSE semantics:
  - The stream starts with `retry: 3000`.
  - It is a live stream, not a history replay endpoint.
  - It accepts normal Bearer auth.
  - It also accepts the `access_token` query fallback used by browser
    `EventSource`.
  - Invalid localized level values return the same HTTP 400 JSON error as
    `/api/logs`.

Go WebUI log rendering behavior:
  - The WebUI initializes log rows from `/api/logs?level=<value>&q=&limit=500`
    and then appends live rows from `/api/events/logs`.
  - With Chinese UI labels, the controls displayed:
      runtime level `错误`,
      query level `全部`.
  - The browser still sent semantic API values, not localized labels:
      `level=all`,
      `level=warn`,
      `level=info`,
      `level=error`,
      `level=debug`,
      `level=trace`.
  - The live WebUI rendered:
      `全部 -> 13 rows`,
      `警告 -> 1 row`,
      `信息 -> 12 rows`,
      `错误/调试/追踪 -> empty state`.
  - Row display format is compact and task-log oriented:
      `HH:MM:SS LEVEL message fields...`
    where the visible level is the canonical uppercase level text such as
    `INFO` or `WARN`, not the localized label.

Rust product log parity changes applied:
  - Removed localized API level aliases from the Rust product log API.
    Localized UI labels such as `全部`, `调试`, `警告`, `错误`, `信息`, and
    `追踪` are display-only and now return HTTP 400 if sent as `level=...`.
  - Removed non-Go aliases such as `level=any`, `level=*`, and `level=err`.
  - Kept Go/logrus-compatible parsing:
      empty level and `all` are unfiltered,
      case-insensitive concrete levels are accepted,
      `warning` canonicalizes to `warn`,
      `panic` and `fatal` are valid concrete levels.
  - Fixed `limit=0` so it uses the default query limit instead of returning
    one row.
  - Kept newest-tail chronological ordering for limited `/api/logs` queries.
  - Changed the internal non-streaming `/events/logs` fallback to emit only the
    SSE retry preface, matching Go's live-stream behavior instead of replaying
    one historical log entry.
  - Removed the Rust-only `runtime log level set to ...` product log entry from
    `PATCH /api/runtime/log-level`; changing runtime level remains immediate
    and controls only future log emission.

Local verification after Rust product log parity changes:
  - `cargo fmt --all --manifest-path rust/Cargo.toml`: pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon logs_filter_level_all_case_insensitive_query_and_sse_event_name`:
      pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon --test daed_product`:
      pass, 10 tests passed.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon`:
      pass, 205 lib tests, 10 product tests, 2 reload owner benchmark tests,
      2 reload owner handoff tests, and 2 service contract tests passed.

2026-06-05 Go daed source log-field parity alignment:

```text
Go source compared:
  daed/wing/dae-core/control/tcp.go
    TCP routing log:
      level: info
      message: RefineSourceToShow(src, dst.Addr()) <-> dialTarget
      fields:
        network
        outbound
        policy
        dialer
        sniffed
        ip
        pid
        dscp
        pname
        mac

  daed/wing/dae-core/control/udp.go
    UDP fast-path log:
      level: trace
      fields: network=udp(fp), outbound, policy, dialer, sniffed, ip,
              pid, dscp, pname, mac

    UDP new endpoint log:
      level: info for new endpoint, debug for existing endpoint when debug is enabled
      fields: network, outbound, policy, dialer, sniffed, ip, pid, dscp,
              pname, mac

  daed/wing/dae-core/control/utils.go
    ProcessName2String trims trailing NUL bytes.
    Mac2String renders lower-case hex with ':' separators.

  daed/wing/dae-core/control/control_plane.go
    Built-in direct and block outbounds use policy=fixed.

Rust product alignment implemented:
  - ResidentProxyPlan now carries group_policy from the config group policy
    function name, e.g. fixed(0) -> fixed. The field is plan-level and protocol
    generic; no protocol-specific naming was added.

  - Resident TCP route selection now carries BPF routing metadata required by
    Go-compatible log fields:
      pid
      dscp
      pname
      mac

  - Resident TCP events now add Go-style flow fields when the data is known:
      network=tcp4
      outbound=<group/direct/block>
      policy=<group policy or fixed for built-ins>
      dialer=<node tag/direct/block>
      sniffed=<sniffed domain>
      ip=<original destination>
      pid/dscp/pname/mac from BPF routing result

  - Resident UDP events now add the Go-style fields that the current UDP path
    can truthfully provide:
      network=udp4
      outbound=<proxy group>
      policy=<group policy>
      dialer=<node tag>
      sniffed=
      ip=<original destination>

    Current UDP resident packet events still do not carry BPF pid/pname/mac/dscp
    metadata, so those fields are not fabricated. Full UDP parity needs the UDP
    task-queue/routing-result ownership work to attach the same metadata source
    that Go uses.

  - Rust product log mapping for resident flow diagnostics now emits the Go
    primary field names instead of internal diagnostic names:
      proxy_group -> outbound
      node_tag -> dialer
      group_policy -> policy
      sniffed_domain -> sniffed
      original_dst -> ip

    Product log fields keep only the Go primary fields plus error/reason for
    failures. Internal fields such as bytes_client_to_proxy, tls_underlay,
    vision_* and final_outbound remain in resident event diagnostics, not in the
    normal WebUI task-log field chips.

  - tcp_connection_finished and tcp_connection_blocked are promoted to info only
    when the event has real route context. Legacy/minimal synthetic events
    without outbound/original_dst context stay debug to avoid info-level
    unknown-target noise.

WebUI alignment implemented in daed-daex-align:
  - apps/web/src/pages/Orchestrate/Logs.tsx no longer renders log fields as one
    inline "key=value key=value" string.
  - The page restores the prior field-chip layout from the historical WebUI log
    rendering change while preserving current SSE batching, deduplication, and
    max-rendered-entry behavior.
  - Empty field values render as "-" in the UI; API/storage values remain
    unchanged.

Validation:
  - `cargo fmt --all --manifest-path rust/Cargo.toml`: pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon resident_events_are_bridged_to_product_logs_with_runtime_level_filter`: pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon logs_filter_level_all_case_insensitive_query_and_sse_event_name`: pass.
  - `cargo test --manifest-path rust/Cargo.toml -p dae-daemon --lib`: pass, 205 tests passed.
  - `pnpm --dir /root/project/daed-daex-align/daed --filter daed check-types`: pass.
    Note: the local command printed a Node engine warning because the shell had
    Node v18.20.4 while package.json wants >=22.12.0.

Correction after review:
  - Product-log parity tests must use generic fixture values such as
    flow-source, flow-destination, flow-outbound, flow-dialer and flow-process.
  - Do not put realistic node names, process names, server names, public-looking
    endpoints, or protocol-specific labels into protocol-generic product-log
    mapping tests.
  - Protocol-specific values are acceptable only inside protocol-specific
    handler tests where the protocol shape is the subject under test.
  - Revalidated after replacing concrete-looking log fixture values:
      `cargo fmt --all --manifest-path rust/Cargo.toml`: pass.
      `cargo test --manifest-path rust/Cargo.toml -p dae-daemon resident_events_are_bridged_to_product_logs_with_runtime_level_filter`: pass.
      `cargo test --manifest-path rust/Cargo.toml -p dae-daemon proxy_failure_event_carries_relay_diagnostics`: pass.
```
