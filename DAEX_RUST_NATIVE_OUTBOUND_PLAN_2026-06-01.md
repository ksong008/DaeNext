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
| C0 | `product-chain-topology-lock-v1` | 锁定 `daed -> daed/wing submodule -> dae -> outbound -> quic-go` 实际链路 | 待做 |
| C1 | `default-bundle-boundary-v1` | 区分 hybrid 默认 bundle 与 Rust-owned candidate bundle，并写入 gate | 待做 |
| C2 | `default-runtime-selector-v1` | 无环境变量时默认选择 Rust-owned；显式 rollback 才选择 Go | 待做 |
| C3 | `daed-service-contract-v1` | 将 `install/daed.service`、package scripts、Web/API、runtime reload/stop/overview 纳入 gate | 待做 |
| C4 | `resident-runtime-platform-v1` | Rust daemon run/reload/stop/service-contract、typed report、memory/thread/fd gate | 部分已有 |
| C5 | `control-plane-owner-v1` | routing/domain/connectivity/runtime state 由 Rust owner 持有，并能 reload/cleanup | 部分已有 |
| C6 | `datapath-core-v1` | TCP/UDP/DNS tproxy、route、sniff、direct/block/proxy 由 Rust resident 承载 | 部分已有 |
| C7 | `outbound-fingerprint-underlay-v1` | 通用 link/global fingerprint-aware TLS underlay 进入正式 feature/admission | 实验可用，未默认 |
| C8 | `outbound-production-matrix-v1` | 主要生产 outbound handler 按矩阵逐项 native，并按项退役 Go fallback | 待做 |
| C9 | `release-default-switch-v1` | release/action/Docker/package 默认切到 Rust-owned candidate | 待做 |
| C10 | `go-free-product-chain-v1` | 去除 Go product shell、Go runtime/control/API/service/release 默认路径 | 终局，待做 |

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
- BoringSSL underlay feature/admission。
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
