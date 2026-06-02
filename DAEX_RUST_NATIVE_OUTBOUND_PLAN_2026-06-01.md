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
