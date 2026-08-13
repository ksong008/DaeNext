# DaeNext BoringSSL 统一后端评估与迁移计划（2026-08-11）

## 1. 目标与结论边界

目标是在不改变官方协议语义、不降低兼容性、不掩盖性能或资源回退的前提下，
评估并逐步把 DaeNext 生产路径的 TLS、QUIC crypto 和 VLESS Encryption ML-KEM
统一到现有 vendor BoringSSL。

本计划不预设“BoringSSL 一定更快”，也不把删除依赖本身视为成功。最终成功必须
同时满足：协议矩阵、DNS 矩阵、Reality/Vision/Encryption、QUIC 生命周期、
CPU/RSS、交叉编译和 cleanup 全部通过。任何阶段不满足 gate，都停留在当前稳定
hybrid provider，不继续删除 rustls/aws-lc。

当前推荐策略是 **Boring-first staged migration**，不是一次性 Boring-only 切换。

## 2. 当前基线

### 2.1 依赖与 provider

当前生产图包含：

- vendor BoringSSL 5.1，通过 `boring`、`boring-sys`、`tokio-boring`；
- Watfaq rustls 0.23.40 与 tokio-rustls 0.26.4；
- aws-lc-rs 1.17.x / aws-lc-sys 0.43.x；
- Quinn 0.11.9，启用 `runtime-tokio,rustls-aws-lc-rs`；
- pinned `quinn-boring` 0.2.0，仅在有限生产路径使用；
- rcgen 0.13，使用 aws-lc provider 生成 loopback/test certificate。

### 2.2 当前职责

| 后端 | 当前主要生产职责 |
|---|---|
| BoringSSL | uTLS/fingerprint、Reality+fingerprint、Boring TCP TLS、Chrome xHTTP H3 QUIC |
| rustls | 普通 TLS、无 fingerprint Reality、xHTTP H2、DoT/DoH、绝大多数 Quinn QUIC |
| aws-lc | rustls/Quinn crypto provider、VLESS Encryption ML-KEM-768 |

当前 `ResidentTlsProvider` 有四个运行分支：

```text
StandardRustls
RealityRustls
RealityFingerprintBoring
FingerprintAwareBoring
```

大致源码触达面为：rustls/tokio-rustls 86 个 Rust 文件，其中约 49 个属于
production-like 路径；`quinn::crypto::rustls` 19 个文件；Boring 35 个文件；
aws-lc 直接引用 11 个文件。这说明统一是跨模块迁移，不是 Cargo feature 清理。

### 2.3 已有 Boring 能力

- `quinn-boring` 已实现 Quinn crypto trait、QUIC header/packet key、0-RTT 和 key update；
- Chrome xHTTP H3 已使用 `quinn_boring::ClientConfig`；
- Boring Reality FFI、certificate auth 和 fingerprint 模板已经存在；
- vendor BoringSSL 包含 ML-KEM-768/X25519MLKEM768 实现和 bindings；
- v4 compatibility crates 仅重导出 Boring 5.1，不是第二份 BoringSSL 实现。

## 3. 不变契约

迁移期间必须保持：

1. 官方协议 wire format、ALPN、SNI、认证、padding、record 和 error semantics；
2. VLESS Vision DIRECT handoff、XUDP、Encryption 1-RTT/0-RTT 和 ticket 语义；
3. Reality public key、short ID、client version、fake certificate/auth-key 语义；
4. uTLS/fingerprint ClientHello 模板和随机化边界；
5. Hysteria2/TUIC/Juicity congestion、PMTU、port hopping、datagram 和 0-RTT 行为；
6. DNS DoT/DoH2/DoQ/DoH3 的超时、并行、fallback、TC=1、stale refresh 和 cache 契约；
7. webpki、allow-insecure、leaf/SPKI pin、ALPN 和 hostname verification；
8. reload/shutdown 所有 active owner 归零、无 `dae0`/`daens`/BPF leftovers；
9. x86-64-v2/v3 与 arm64 交叉编译、运行时 CPUID dispatch 和现有 CPU contract；
10. 不加入面向用户的临时 provider 环境变量或 WebUI 开关；实验选择只能是
    test-only/build-only gate，并且 evidence 必须显示实际 provider。

## 4. 验收阈值

每个阶段使用同一 binary 口径做至少 3 轮随机交叉 A/B，以中位数为主，保留每轮
JSON。阶段接受条件：

### 4.1 正确性 gate

- 本地 `cargo fmt --check`、相关 crate 全量 lib tests 通过；
- 187 完整协议矩阵 38/38；
- 37 个 UDP-supported case 全部 128/128、512/512；
- VLESS Encryption 12/12；
- Reality/Vision TCP、XUDP、0-RTT 全部通过；
- DNS DoT/DoH2/DoQ/DoH3 direct/proxy matrix 无失败；
- runtimeLastError 为空，cleanup reports 全部 pass；
- active TCP/UDP/pending tasks 为 0，leftovers 为空；
- 远程 JP/Xray/sing-box server 交叉互操作通过。

### 4.2 性能与资源 gate

- CPU-bound TCP 吞吐中位数不得可重复回退超过 2%；
- daemon ticks/GiB 不得可重复上升超过 3%；
- UDP PPS 不得可重复回退超过 3%；
- UDP/DNS p95/p99 不得可重复恶化超过 5%；
- steady RSS 不得增加超过 `max(4 MiB, 5%)`；
- reload 后 RSS、FD、socket、owner 数不得逐轮增长；
- binary size、clean build time、incremental build time必须记录，但简化收益不能抵消
  协议或 hot-path 回退。

阈值附近的结果必须增加轮次，不能用单次波动判定。

## 5. 实施批次

### Batch A：基线、可观测性与统一抽象，不改变 provider

1. 固化当前 hybrid provider 的 Cargo tree、binary size、clean/incremental build time；
2. 保存 187 当前 38 项矩阵、DNS 完整矩阵和协议专项 CPU/RSS/PPS；
3. 为 TLS/QUIC config 建立 protocol-generic typed policy：
   - server name；
   - ALPN；
   - webpki/allow-insecure/pin；
   - session/0-RTT policy；
   - Reality policy；
4. 在 runtime evidence 中记录 `tlsProvider`、`quicCryptoProvider` 和验证策略；
5. 把 provider 选择集中在 factory，不在协议 handler 中继续增加分支；
6. 该批次必须保持 wire/runtime 行为完全不变。

**退出条件：** 源码只做抽象和可观测性，现有完整矩阵与性能基线无回退。

### Batch B：普通 TCP TLS BoringSSL 候选

按风险从低到高迁移 test-only candidate：

1. ordinary TLS：VLESS、VMess、Trojan、HTTP CONNECT；
2. AnyTLS 和 shared H2/WebSocket/HTTPUpgrade carrier；
3. TLS fragment、ALPN、session cache、close-notify；
4. xHTTP H2 endpoint TLS；
5. health/manual HTTP/TCP probe；
6. DNS DoT/DoH2 TCP TLS；
7. 无 fingerprint 的 RealityRustls 改用现有 Reality Boring FFI。

实现要求：

- 一个 Boring connector/cache policy，不按协议复制 connector builder；
- ordinary、insecure、fragmented、fingerprint、Reality 共用 typed verification policy；
- 保持 Vision raw handoff 与 Encryption 外层 TLS record 消费边界；
- 不删除 rustls fallback，先完成同 binary 的 provider A/B；
- 不允许 Boring candidate 失败后静默回退 rustls。

**决策点 B：** 若 TCP、DNS TLS 或 Reality 任一项兼容性失败，或 CPU/吞吐未通过
阈值，停止 Boring-only 方向；保留统一抽象即可。

### Batch C：BoringSSL Quinn 公共层

在迁移具体协议前，建立一个共享 Boring QUIC client config factory：

1. `quinn_boring::ClientConfig` 生命周期和 session cache；
2. system/webpki roots；
3. allow-insecure；
4. leaf/SPKI pin；
5. hostname/SNI；
6. ALPN；
7. handshake data/downcast；
8. 0-RTT/resumption；
9. TLS alert 到 typed runtime error 的映射；
10. QUIC header/packet key update 和 exporter material。

必须用不同 provider 的 server 做交叉互操作，不能只用 Boring client 对 Boring
test server 自证。

**退出条件：** 最小 Quinn Boring client fixture 覆盖验证、pin、ALPN、0-RTT、
key update、peer close、timeout 和 cleanup。

### Batch D：逐协议迁移 QUIC

按以下顺序独立提交和验证：

1. DNS DoQ；
2. DNS DoH3；
3. xHTTP H3 非 Chrome profile，合并现有 Chrome Boring path；
4. Hysteria2；
5. TUIC；
6. Juicity；
7. QUIC health/manual latency probe。

每项必须覆盖：

- TCP-over-QUIC 与 UDP datagram；
- concurrent UDP 128/512；
- congestion controller；
- PMTU、fragmentation、port hopping；
- endpoint reuse/rebuild/remote close；
- 0-RTT、session expiry；
- reload、generation drop、shutdown owner join；
- CPU、RSS、PPS、p99 与原 rustls/aws-lc provider A/B。

只有所有 QUIC consumer 都离开 `quinn::crypto::rustls` 后，才允许移除 Quinn 的
`rustls-aws-lc-rs` feature。

### Batch E：VLESS Encryption ML-KEM 迁移

1. 在小型安全 wrapper 中封装 BoringSSL ML-KEM-768 FFI；
2. 固定 public key、ciphertext、shared-secret 长度；
3. 封装 parse/generate/encap/decap，禁止业务代码直接操作裸指针；
4. private key、seed、shared secret 必须显式清零；
5. 先保留 aws-lc 与 Boring 双实现，仅在测试中运行同向和交叉 KAT；
6. 对照 Xray official server 验证 native/xorpub/random、1-RTT/0-RTT；
7. 验证坏 public key、坏 ciphertext、invalid ticket、partial EOF；
8. 12/12 Encryption 和完整 38 项通过后才能切 production implementation；
9. 不改变 VLESS Encryption record AEAD、padding、ticket 或 wire length。

**退出条件：** Boring ML-KEM 与 aws-lc/Xray wire 互操作完全一致，且性能、RSS、
失败语义不回退。

### Batch F：rcgen 与 test-support 边界

1. 审计所有 runtime/loopback server certificate generation caller；
2. 真实生产客户端不需要的 server fixture 移到 test-support/dev-dependency；
3. 优先使用固定测试证书，避免测试每次生成 key；
4. 若生产确实需要本地 server cert，再用集中式 Boring certificate helper；
5. 不为了清理 dependency 把不安全固定私钥带入生产路径。

目标是先从 production tree 移除 rcgen/aws-lc，而不是强求 Cargo.lock 和 all-targets
立即完全没有它们。

### Batch G：依赖删除与代码收口

依次执行：

1. `quinn` 仅保留 `runtime-tokio`，所有 crypto config 显式来自 quinn-boring；
2. 删除 production `rustls`、`tokio-rustls`；
3. 删除 direct `aws-lc-rs` 和 transitive `aws-lc-sys` production edge；
4. 删除 `AsyncVlessTlsEngine::{Rustls,RealityRustls}`；
5. 合并 rustls/boring 双 cache 和 cleanup report；
6. 清理 Watfaq rustls/tokio-rustls patches；
7. 检查 `cargo tree -p dae-daemon`、`-p dae-outbound`、workspace all-targets；
8. 区分“production graph 已移除”和“dev/all-target lock 仍保留”，禁止误报。

删除必须是迁移结果，不能先删除依赖再补行为。

## 6. 交叉编译与发布验证

统一 Boring 后必须验证：

- 本机 x86_64-v2、x86_64-v3；
- Linux arm64；
- OpenWrt arm64 v2/v3 和 x86_64 v2/v3 当前打包入口；
- Debian/RPM/APK package smoke；
- BoringSSL runtime CPUID dispatch；
- 不加入全局 ADX，保持当前 v3 CPU contract；
- 不启用 fat-LTO 候选之外的隐藏编译差异；
- binary 依赖、ELF、strip、启动、reload、restart、cleanup。

交叉编译必须显式核对 BoringSSL CMake/toolchain target、汇编目标和最终 ELF 架构，
不能只因为 Rust target 正确就认定 BoringSSL 指令集正确。

## 7. 远程验证顺序

1. 本地 unit/contract/live fixture；
2. 187 做改动协议的 targeted A/B；
3. 远程 JP/Xray/sing-box 做 Reality、Vision、Encryption、HY2/TUIC/Juicity 互操作；
4. 38 做 DNS DoT/DoH2/DoQ/DoH3 和压力测试；
5. 回到 187 做同一 candidate 的完整 38 项矩阵；
6. 至少 3 轮随机顺序 baseline/candidate；
7. 最后才做安装包和生产设备替换。

## 8. 提交与回滚策略

- Batch A--G 分批提交，协议迁移每个协议独立 commit；
- 实验 gate 不进入 WebUI/product schema；
- 每个 candidate 必须在 evidence 中显式标注 provider；
- 不允许 runtime silent fallback；
- rustls/aws-lc 删除单独一个提交，便于整体回退；
- 任何性能/兼容 gate 失败，回退该 candidate，不扩大 deadline、buffer、session
  limit 或 RSS budget 掩盖问题；
- 不清理既有用户 build/test 目录，只清理本计划新建且目标明确的 isolated artifact。

## 9. 主要风险

1. `quinn-boring` 为 pinned、passively-maintained provider，扩大生产覆盖会增加自维护责任；
2. BoringSSL 没有稳定 API/ABI，vendor 更新可能影响 FFI；
3. Rustls TLS engine 改为 Boring FFI 会扩大 unsafe boundary；
4. root/pin/hostname 验证稍有偏差就会产生安全或兼容回归；
5. Reality/fingerprint ClientHello 变化可能使节点不可用或改变流量特征；
6. ML-KEM private state 的 layout、zeroization 和 error handling 必须经过专项审计；
7. QUIC crypto provider 变化可能影响 0-RTT、key update、handshake data 和 CPU；
8. “依赖更少”不等于 RSS/吞吐更好，必须以 A/B 数据决定是否继续。

## 10. 最终完成定义

只有同时满足以下条件，才能宣布 BoringSSL 统一完成：

- production Cargo graph 不再包含 rustls/tokio-rustls/aws-lc-rs/aws-lc-sys；
- 所有生产 TLS/QUIC/KEM 路径有唯一 Boring owner；
- 不存在 silent fallback、parser-only provider 或未使用配置；
- 38/38 协议矩阵、DNS 完整矩阵、远程互操作全部通过；
- CPU、吞吐、PPS、p99、RSS 达到验收阈值；
- reload/restart/cleanup 无 owner、socket、FD、RSS 逐轮增长；
- x86_64-v2/v3、arm64 和各安装包构建/运行通过；
- 文档、capability ledger、runtime evidence、dependency contract 全部更新。

在这些条件之前，正确表述只能是“某一批次的 BoringSSL candidate 已验证”，不能
表述为“已统一”或“rustls/aws-lc 已不再需要”。

## 11. 执行验证记录

### 11.1 远程 38 DNS 随机配对重测（2026-08-13）

在远程 `38.65.91.47` 使用同一工作树构建的固定 release 测试程序，完成普通
hybrid baseline 与 Boring TCP TLS/QUIC candidate 的 DNS 随机配对重测。该记录
只证明本批 candidate 在本次 DNS gate 下通过，不表示 BoringSSL 统一已经完成。

固定测试程序：

- baseline SHA-256：
  `f7eb9ae44bdbcccc6ecaf2e28aad9fe1c5a8012c548e5e56fb4da720e0b34a13`；
- candidate SHA-256：
  `c6d6fe9a697cfcd6414178982340ecdb3b33002694f954c13be111cdf7c5b866`；
- candidate features：
  `test-boringssl-tcp-tls,test-boringssl-quic`；
- 运行目标为 x86-64-v3；远端 CPU 为 2 vCPU AMD EPYC Rome。

测试共 9 轮，每轮对 DoT、DoH2、DoQ、DoH3 分别执行 baseline/candidate，且每个
协议每轮独立随机决定 A/B 顺序。每个 case 为 120 请求、并发 16，共 72 个 case、
8640 个请求。结果为 72/72 case pass、8640/8640 请求成功、0 失败。

性能 gate 使用每轮 candidate/baseline 的配对变化中位数；负数表示 candidate
延迟更低：

| 协议 | p95 配对变化中位数 | p99 配对变化中位数 | QPS 配对变化中位数 | p95/p99 超过 5% 的轮次 | 结果 |
|---|---:|---:|---:|---:|---|
| DoT | -0.80% | -0.80% | +0.43% | 0/9、0/9 | pass |
| DoH2 | -0.27% | -0.09% | -0.12% | 2/9、2/9 | pass |
| DoQ | -0.29% | -2.04% | +1.56% | 2/9、3/9 | pass |
| DoH3 | -4.02% | -4.80% | +3.67% | 0/9、1/9 | pass |

上一次观测到的 DoT p99 `+12.56%` 未复现。本次 DoT 9 轮中没有任何一轮 p95
或 p99 恶化超过 5%；baseline/candidate 命中同一上游 IP 的 5 轮中，p99 配对
变化中位数为 `+0.20%`。因此 DoT 不构成可重复的超过 5% 回退。

DoQ 仍有明显公网抖动，单轮 p99 配对变化范围为 `-16.30%` 至 `+17.73%`，但
candidate 有 6/9 轮 p99 更快，9 轮配对中位数改善 2.04%；同上游 IP 的 6 轮
p99 配对中位数改善 5.79%。按本计划的“可重复恶化”口径判定为 pass。

进程 peak RSS 配对变化中位数为 DoT `-0.16%`、DoH2 `-3.20%`、DoQ
`-1.61%`、DoH3 `-0.04%`，未观察到 candidate peak RSS 中位增长。

本地证据保存在被 `.gitignore` 忽略的构建缓存：

- `target/remote38-boring-ab-current/retest-20260813/`
  `REMOTE38-DNS-RETEST-SUMMARY.json`，SHA-256：
  `9a72e3abe26972c30aa27a86783ab36ead0313bebbca324c8bf305b64ce917c8`；
- 同目录 `all-results.json`，SHA-256：
  `61702560834484c3d35ca2f46759449986df63c623b72cf40c50867bec8215fa`；
- 同目录 `REMOTE38-DNS-RETEST-20260813.tar.gz`，SHA-256：
  `a4091ca594ad712fa4ab43bda9b94855d66a8a798ebabdebf4fea94950ef58c3`。

测试未替换远端生产程序。清理后 `/usr/bin/daed` SHA-256 仍为
`30aa1b1d27b790d3608cc425f4d1cb1440323e4fb19cb518f2e32e638c7a93f0`，
`dae`/`daed` 服务均为 inactive，匹配进程、测试 netns、bpffs 残留条目和本次
命名临时目录均为 0。

### 11.2 远程 187 完整协议矩阵（2026-08-13）

在远程 `192.168.2.187` 使用与 11.1 同一批次、同时启用 Boring TCP TLS 与
Boring QUIC 的固定 candidate，完成 38 项协议矩阵。远端为 Debian 12、Linux
6.12.95、4 vCPU AMD Ryzen 9 7945HX、3.8 GiB 内存。远端没有已安装的生产
`daed` 命令或 active `daed` 服务，因此本轮未替换生产程序。

固定程序与矩阵：

- candidate SHA-256：
  `126edf628b0f83786c2485b1564b452f4d0b52eec3135c9f36c54c95df7b5a8d`；
- target：`x86_64-unknown-linux-gnu`，静态 PIE，`x86-64-v3`；
- candidate features：
  `test-boringssl-tcp-tls,test-boringssl-quic`；
- runner SHA-256：
  `3648d03d9e3e9f00dafd80d1ad3c9626dbb0744b16ee85c09ccafb4b1aa1b118`；
- case registry SHA-256：
  `e5455b205deac1d3734249de11f6dd8a8fd7629acbbcf729236dd4c292f3ae92`。

矩阵覆盖 SOCKS5、HTTP CONNECT、Shadowsocks、Shadowsocks 2022、AnyTLS、
Hysteria2、TUIC、Juicity、VMess、VLESS、Reality/Vision、VLESS Encryption、
WebSocket、HTTP Upgrade、gRPC、XHTTP/H2、XHTTP/H3 与 Trojan。其中 VLESS
Encryption 的 TLS/Reality × native/xorpub/random × 1-RTT/0-RTT 12 个组合全部
纳入同一轮测试。

主矩阵结果：

- 38/38 case pass，0 fail；
- 每项均完成 128 次 TCP smoke，以及 upload/download/duplex 各 8 秒，共 114 个
  有效 TCP 吞吐行；
- 37 个支持 UDP 的 case 全部 pass；每项执行 sequential-reuse 128 包和
  concurrent-32 512 包，共 74 行、`23680/23680` 包收到，0 丢包；
- HTTP CONNECT 按协议能力明确标为 `protocol-closed`，不把未执行 UDP 伪装为
  成功；
- 38 项 `runtimeLastError` 全为 null，38 份 resident cleanup report 全为
  `pass`，`leftovers_after_cleanup` 全为空；
- 最慢 resident cleanup 为 XHTTP/H3 的 509 ms，最慢 stop API 返回为
  VMess/gRPC 的 17 ms；
- 并发 UDP p99 中位数为 10.626 ms，单项最大值为 Reality+Encryption random
  1-RTT 的 120.206 ms；该轮是正确性/清理矩阵，不是与 hybrid baseline 的配对
  性能 gate，不能据此单独宣布性能验收完成。

provider evidence：

- 28 个普通 TLS、Reality、Vision、Encryption、XHTTP/H2 case 的关闭证据实际
  清理了 Boring TLS cache entry，合计涉及 28 个 case；对应 rustls cache entry
  case 数为 0；
- 另行运行 4 项短 live provider probe，运行时 executable graph 明确报告：
  Hysteria2、TUIC、Juicity 的 `quicCryptoProvider` 均为 `quinn-boringssl`，
  XHTTP/H3 为 `quinn-boringssl-chrome`；4/4 TCP/UDP smoke 与 cleanup pass，
  UDP 合计 `64/64` 包收到；
- 因此本轮证据不是仅依赖 feature 名或 parser 配置来推断 provider。

清理与宿主状态：

- 每个 case 的 `dae0`、`daens`、transient systemd unit、candidate 进程均在停止后
  消失；测试前后的 bpffs、netns、link 清单差集均为 0 新增、0 删除；
- 预置的 `daerustlab`/`daerust0` 测试拓扑保留，8 个长期夹具服务保持 active，
  且 MainPID 与测试前一致；
- 测试前已存在 `daenext-flow-debug-mx00.service` failed unit，以及 8 组
  `dae-native-runtime-*` BPF pin；测试后清单完全相同，故不把这些历史项误记为
  本轮残留，也未在本轮删除远端既有状态；
- 按操作者要求检查 sudo：远端原已安装 sudo `1.9.13p3-1+deb12u4`，无需重新安装；
  已将 `shaka` 加入 `sudo` 组并在重新登录后验证生效。

本地证据保存在被 `.gitignore` 忽略的构建缓存：

- `target/remote187-boring-matrix-20260813/evidence/`
  `MXB813-REMOTE187-BORING-MATRIX-20260813.tar.gz`，SHA-256：
  `93d38b24a0482728ab5b3659aa0a104dbb8687a539f5396ade97b2c6c5990f6c`；
- 归档包含 38 份详细结果、summary、完整 runner 日志、各 case 的 runtime state、
  cleanup report、provider probe、测试前后状态与严格核验结果，共 301 个条目；
  已通过 `gzip -t`、条目计数和核心内容抽查；
- 归档内 `VERIFICATION.json` SHA-256：
  `746d2c4e628b19b1017835056ab16c543466a5f19a2b837f1ffb76d738984137`；
- 归档内 `QUIC-PROVIDER-PROBE.json` SHA-256：
  `764e816927e91a6504679fba35aa15281697f3734ccf80da85015f31a7a69693`；
- 归档内 `summary.json` SHA-256：
  `72e6bee5380f8c60c11c6c43a7c2104f77b6c1c04a2273a95685c0ba0d87ad00`。

归档不重复包含 47 MB candidate 二进制，只保存其固定哈希和构建特性；candidate
二进制仍保留在本地 `target/remote38-boring-ab-current/daed-candidate-v3` 构建缓存。
该记录证明本批 BoringSSL candidate 的远程 187 正确性、provider 与清理 gate
通过；它与 11.1 的 DNS gate 一样，不等同于第 10 节全部完成条件已经满足。

### 11.3 远程 187 与 2026-08-11 成绩对比（2026-08-13）

本次对比直接读取远端保留的 8.11 原始 `/tmp/mxr9/summary.json`，未使用图片
OCR。8.11 与 8.13 使用完全相同的 38-case registry 和 runner：

- `matrix_cases.py` SHA-256：
  `e5455b205deac1d3734249de11f6dd8a8fd7629acbbcf729236dd4c292f3ae92`；
- `matrix_runner.py` SHA-256：
  `3648d03d9e3e9f00dafd80d1ad3c9626dbb0744b16ee85c09ccafb4b1aa1b118`；
- 两轮均按固定顺序执行 38 项，每项含 128 次 TCP smoke、upload/download/duplex
  各 8 秒、UDP sequential-reuse 128 包和 concurrent-32 512 包。

两轮 binary 与实际 provider 覆盖不同。8.11 使用 remediation binary
`69ed97488b5a15de37a24a0f1aad3e241d4698ec4843f74cf3462e5eafc88a9d`，关闭证据中
仅 3 个 case 有 Boring TLS cache entry，19 个 case 有 rustls cache entry；8.13
candidate 为
`126edf628b0f83786c2485b1564b452f4d0b52eec3135c9f36c54c95df7b5a8d`，28 个 case
有 Boring TLS cache entry，rustls cache case 为 0，并通过 live graph 明确验证
Hysteria2、TUIC、Juicity 和 XHTTP/H3 的 Boring QUIC provider。因此该对比是
hybrid/remediation 与扩大 BoringSSL 覆盖后的 candidate 对比，不是仅隔两天重跑
同一 binary。

功能与生命周期结果持平：

- 两轮均为协议矩阵 38/38、Encryption 12/12、UDP-supported 37/37；
- 两轮 UDP 均为 `23680/23680` 包收到，0 丢包；
- 两轮 38 项 `runtimeLastError` 均为空，cleanup 均 pass，无 `dae0`/`daens`
  leftovers；
- 8.11 成绩图标注 cleanup 最长 408 ms，但远端保留的详细 result JSON 实际最大
  为 XHTTP/H3 的 475 ms；8.13 最大为 XHTTP/H3 的 509 ms，即详细证据口径增加
  7.2%，属于耗时变化，不是 cleanup 正确性回退。

全部 38 个 case、114 个 TCP 行的配对聚合如下。吞吐、PPS 正数更好；CPU、RSS、
p99 负数更好。几何均值用于聚合比例变化，中位数用于观察典型 case：

| 指标 | 8.13 相对 8.11 | 结论 |
|---|---:|---|
| 全部 TCP 吞吐几何均值 | +0.39% | 整体持平 |
| 全部 TCP 吞吐变化中位数 | +0.59% | 整体持平 |
| 全部 TCP CPU 几何均值 | -0.18% | 整体持平，略好 |
| 全部 TCP CPU 变化中位数 | -1.26% | 略好 |
| 各 case 峰值 RSS 几何均值 | -1.91% | 略好 |
| 各 case 峰值 RSS 变化中位数 | -2.08% | 略好 |
| UDP sequential PPS 几何均值 | -5.49% | 有短样本下降信号 |
| UDP concurrent-32 PPS 几何均值 | -1.63% | 基本持平 |
| UDP sequential p99 几何均值 | +1.74% | 基本持平 |
| UDP concurrent-32 p99 几何均值 | +3.30% | 略差，但变化中位数为 -0.56% |

按 TCP 模式拆分，upload 吞吐几何均值 `+2.67%`、CPU `-2.89%`；download 吞吐
`-0.74%`、CPU `+0.47%`；duplex 吞吐 `-0.73%`、CPU `+1.95%`。整体没有一致方向
的超过 5% 回退。

协议族聚合：

| 协议族 | TCP 吞吐几何均值 | CPU 几何均值 | 峰值 RSS 几何均值 | 观察 |
|---|---:|---:|---:|---|
| Hysteria2/TUIC/Juicity | +5.41% | -5.24% | +1.71% | QUIC 主数据面偏好 |
| VLESS Encryption TLS 6 项 | +0.94% | -0.92% | -5.73% | 基本持平，内存改善 |
| VLESS Encryption Reality 6 项 | +2.84% | -2.56% | -3.93% | 整体偏好 |
| 基础 VLESS/Reality/Vision | +1.29% | -0.66% | -2.84% | 稳定 |
| VMess 5 项 | -3.83% | +4.67% | -12.18% | 吞吐/CPU 有下降信号 |
| Trojan 4 项 | -0.36% | +0.16% | +2.54% | 总体持平，内部差异较大 |
| XHTTP H2/H3 | -0.54% | +1.61% | +9.46% | 吞吐稳定，需关注 H3 RSS |

主要正向 case：

- Hysteria2 综合吞吐 `+8.00%`、CPU `-5.94%`；
- TUIC 综合吞吐 `+6.69%`、CPU `-5.74%`，但峰值 RSS `+12.30%`；
- Juicity 综合吞吐 `+1.64%`、CPU `-4.03%`、峰值 RSS `-6.37%`；
- VLESS gRPC TLS 综合吞吐 `+6.17%`、CPU `-9.04%`；
- Reality+Encryption random 0-RTT 综合吞吐 `+7.94%`、CPU `-6.51%`；
- Trojan TCP TLS 综合吞吐 `+9.61%`、CPU `-9.64%`，其中 download 吞吐
  `+24.23%`；
- Trojan gRPC TLS 综合吞吐 `+4.44%`、CPU `-4.31%`。

需要复测的负向信号：

- Trojan WebSocket TLS 综合吞吐 `-9.28%`、CPU `+10.65%`，duplex 吞吐
  `-17.65%`、CPU `+22.38%`；
- VMess TCP 综合吞吐 `-5.53%`、CPU `+13.35%`，duplex CPU `+28.39%`；
- VMess TLS、VMess WebSocket TLS、VMess HTTP Upgrade TLS 综合吞吐分别为
  `-5.15%`、`-5.18%`、`-4.53%`；
- AnyTLS 综合吞吐 `-4.85%`、CPU `+6.77%`；
- SOCKS5 综合吞吐 `-7.27%`，其中 download `-16.61%`；
- XHTTP/H3 吞吐几乎完全复现 8.11，CPU 综合改善 1.08%，但峰值 RSS 从约
  61.6 MiB 增至 76.4 MiB，即 `+23.95%`；
- TUIC、VLESS TLS、VMess WebSocket TLS 的单轮 concurrent UDP p99 分别有
  `+70.62%`、`+124.81%`、`+82.70%` 变化，但绝对样本仅 512 包且均 512/512
  收到，不足以单轮判退。

非 TLS 路径 VMess TCP、SOCKS5 也出现与部分 TLS wrapper 相近的下降，同时
Trojan TCP TLS、QUIC 和多项 Encryption 明显改善，因此不能把单轮负向变化直接
归因于 BoringSSL。两轮每个 case 均只有一个固定顺序样本，5% 左右的差异可能受
CPU 频率、调度、fixture 状态和宿主 steal 影响。

本轮结论：扩大 BoringSSL 实际覆盖后，功能、互操作、UDP 完整性和 cleanup
正确性无回退；整体 TCP、CPU、RSS 持平或略好，QUIC 与 Encryption 偏好。性能
gate 尚不能宣布完成，也没有足够证据否决 candidate。下一步针对 SOCKS5、
VMess TCP/TLS/WebSocket/HTTP Upgrade、AnyTLS、Trojan WebSocket/HTTP Upgrade、
VLESS TLS UDP、TUIC UDP 和 XHTTP/H3 RSS 执行至少 7 轮随机 A/B 配对，以配对
变化中位数应用 5% 阈值。

### 11.4 远程 187 三轮随机 A/B 配对复测（2026-08-13）

根据第 4 节和第 7 节的最低轮数要求，在远程 `192.168.2.187` 对 11.3 的主要
信号执行 3 轮随机 case 顺序、逐 case 随机 baseline/candidate 先后配对复测。
最初拟执行 7 轮；在 17 条记录后停止并按操作者要求收敛到计划规定的最低 3 轮，
固定 seed `20260813`，复用已经完成且双侧通过的 pair，只补齐缺失记录。最终每个
case 均有 3 对，合计 33 对、66 次执行；每次仍包含 128 次 TCP smoke、TCP
upload/download/duplex 各 8 秒、UDP sequential-reuse 128 包和 concurrent-32
512 包。

固定程序与范围：

- baseline 为 8.11 hybrid/remediation binary，SHA-256：
  `69ed97488b5a15de37a24a0f1aad3e241d4698ec4843f74cf3462e5eafc88a9d`；
- candidate 与 11.2 相同，SHA-256：
  `126edf628b0f83786c2485b1564b452f4d0b52eec3135c9f36c54c95df7b5a8d`；
- 复测 case 为 SOCKS5、AnyTLS、TUIC、VMess TCP/TLS/WebSocket/HTTP Upgrade、
  VLESS TLS、VLESS XHTTP/H3、Trojan WebSocket/HTTP Upgrade；
- schedule SHA-256：
  `1269ce27dd8314b4fe9873c60687ce26624a61968d15c35bf436295abd89475d`；
- 最终 paired JSONL SHA-256：
  `45d1affd2f492e38b12de61cde3e8a2e9d9a0fde75940bb0a2f9c0d84901ef5a`；
- 66/66 execution `ok=true`，33/33 pair 完整，runner `status=pass`、退出码 0，
  没有 runtime、UDP 完整性或 cleanup 失败。

运行器预检时曾发现 rejected harness 问题：过深的可读工作目录使 daed 的 Unix
socket path 超过 `SUN_LEN`，同一 case 的新旧 binary 均以
`path must be shorter than SUN_LEN` 退出。这不是 candidate 回归。修复为短路径
`/tmp/mxp813/paired/w/eNNN`，并在每次执行前后显式停止 exact transient unit；
原无效记录独立归档，没有混入最终 66 条结果。

下表使用每一轮同 case candidate/baseline 的配对变化，再取 3 轮中位数。吞吐、
PPS 正数更好；CPU、RSS、p99 负数更好。最后一列为 candidate-first / baseline-first
轮数，用于暴露仅三轮时仍存在的顺序不平衡。

| Case | TCP 综合吞吐 | TCP 综合 CPU | TCP peak RSS | UDP seq PPS | UDP con PPS | UDP con p99 | C/B first |
|---|---:|---:|---:|---:|---:|---:|---:|
| AnyTLS | +1.16% | +0.10% | +0.56% | -2.46% | -22.97% | +66.09% | 2/1 |
| SOCKS5 | +2.47% | +1.11% | -11.00% | -3.00% | -3.65% | +3.87% | 1/2 |
| Trojan HTTP Upgrade | +0.94% | -0.93% | +2.66% | -14.36% | -7.67% | +7.49% | 1/2 |
| Trojan WebSocket | -3.44% | +2.70% | +4.29% | -5.07% | -0.07% | +0.55% | 1/2 |
| TUIC | +1.58% | -2.78% | -9.21% | -2.86% | +2.44% | -3.62% | 0/3 |
| VLESS TLS | -2.06% | +4.10% | -7.93% | +11.97% | -5.55% | +62.99% | 2/1 |
| VLESS XHTTP/H3 | -0.09% | +0.49% | -3.33% | -0.04% | -0.17% | -0.08% | 2/1 |
| VMess HTTP Upgrade | +1.68% | -1.31% | -4.17% | +1.44% | +0.95% | -17.33% | 3/0 |
| VMess TCP | -0.25% | +2.23% | +4.50% | +0.20% | +2.79% | -1.96% | 2/1 |
| VMess TLS | -2.58% | +2.78% | +6.49% | -7.23% | +1.57% | +10.37% | 1/2 |
| VMess WebSocket | +9.97% | +7.13% | -13.54% | -5.74% | -3.28% | +14.10% | 2/1 |

按第 4.2 节的原始阈值，而不是统一 5% 口径判定：TCP 吞吐不得可重复下降超过
2%，ticks/GiB 不得可重复上升超过 3%，UDP PPS 不得可重复下降超过 3%，p99
不得可重复上升超过 5%，RSS 必须同时超过 5% 和 4 MiB 才判退。主要结论：

- **正确性、UDP 完整性与 cleanup gate 通过**：66/66 执行均收到全部 UDP 包，
  runtimeLastError 为空，resident cleanup pass；
- **性能 gate 不通过，candidate 不进入安装包或生产替换**；
- AnyTLS concurrent UDP 是最稳定的 UDP 负向信号：三轮 p99 均恶化，绝对值为
  `4.92 -> 11.55 ms`、`6.81 -> 11.32 ms`、`6.75 -> 8.78 ms`，中位变化
  `+66.09%`；PPS 三轮为 `-28.75%/-22.97%/-2.04%`，中位 `-22.97%`；
- Trojan WebSocket download TCP 是稳定热路径回退：三轮吞吐分别
  `-6.85%/-14.55%/-7.58%`，3/3 均超过 2% 阈值；download ticks/GiB 三轮也
  3/3 恶化超过 3%，变化中位数 `+8.44%`。综合三模式吞吐中位 `-3.44%`；
- VLESS TLS download 吞吐三轮为 `-33.87%/-3.62%/-4.18%`，3/3 超过 2%，
  download CPU 也 3/3 超过 3%；concurrent UDP p99 有 2/3 轮明显恶化、1/3
  轮改善，变化中位数 `+62.99%`，仍需增加轮次区分稳定回归与调度抖动；
- VMess TLS 综合吞吐中位 `-2.58%`、VMess WebSocket 综合 CPU `+7.13%`，并有
  若干 download/duplex/UDP 子项越线；仅三轮且方向并非全部一致，列为阈值附近
  待增加轮次项，不能据此扩大 candidate；
- 11.3 的 SOCKS5 综合吞吐 `-7.27%`、VMess TCP 综合吞吐 `-5.53%`、Trojan
  WebSocket 综合吞吐 `-9.28%` 均有所收敛，但 Trojan WebSocket 的 download
  子模式重复回退仍然成立；
- 11.3 的 XHTTP/H3 peak RSS `+23.95%` 未复现：三轮 peak RSS 变化为
  `+7.56/-3.51/-2.64 MiB`，中位 `-2.64 MiB`，TCP/UDP 主要指标均接近持平；
- TUIC 三轮都是 baseline-first，VMess HTTP Upgrade 三轮都是 candidate-first；
  这两项虽未出现综合回退，但不能用本轮排除顺序偏差。短 UDP daemon tick 为
  0 或 1 个 jiffy 的比例不适合作为强 CPU 证据，分析器对任一侧为 0 的 ratio
  明确 omitted。

清理与宿主状态：

- 测试前后 bpffs、netns、links 均为 0 新增、0 删除；8 个长期 fixture 的
  MainPID/active/substate 差集为 0；
- `dae0=absent`、`daens=absent`、candidate 精确 executable 进程为 0、matrix
  transient unit 为 0、runner unit 为 0；预置 `daerustlab`/`daerust0` 和历史
  BPF pins 保持不变；
- 未替换远端生产程序。

本地证据保存在被 `.gitignore` 忽略的构建缓存：

- `target/remote187-boring-paired-20260813/evidence/`
  `MXP813-REMOTE187-PAIRED-3ROUND-20260813.tar.gz`，SHA-256：
  `1a99cfbea76a81993fa64bdcd0de65ffdb6465adf250378e5122ec2130565f77`；
- 归档不包含 candidate binary，包含固定 binary hashes、66 条 paired JSONL、
  67 个远端工作目录（含 1 个中断半样本目录）、preflight、schedule、runner、
  538 个 paired 文件以及 PRE/POST 宿主证据，共 1142 个条目；已通过 `gzip -t`；
- 派生分析为同目录 `analysis.json` 与 `analysis.md`，分析脚本为
  `target/remote187-boring-paired-20260813/tools/analyze_paired.py`；
- rejected `SUN_LEN` 轮次单独保存为上级目录 `aborted-sunlen.tar.gz`，SHA-256：
  `fd0bf7d5865f8227459e4316d387e005461a164f08f8594673664a32598604d7`。

本轮把 11.3 的单轮疑点推进为三轮证据，但没有满足第 4.2 节性能 gate。下一步应
先对 AnyTLS concurrent UDP、Trojan WebSocket download、VLESS TLS download
做实现级 profiling 与原因定位；修复 candidate 后再执行同口径 targeted A/B，
而不是继续扩大协议范围、打安装包或替换生产设备。

### 11.5 Rustls/AWS-LC 与 BoringSSL 工作流审计（2026-08-13）

本节审计原 Rustls/AWS-LC 路径与当前 staged BoringSSL 路径的配置、握手、会话、
I/O、证书校验和密钥生命周期。结论是：**BoringSSL 统一方向合理，但当前实现尚未
达到与原路径完整等价的工作流，不能据此移除 Rustls/AWS-LC fallback，也不能把
现有 hybrid candidate 的全部性能差异直接归因于 BoringSSL 本身。** 当前根
`Cargo.toml` 中 `quinn` 仍启用 `rustls-aws-lc-rs`，代码中也仍保留 provider
分支，因此当前二进制布局和测量结果不代表最终 Boring-only 形态。

按风险和收益排序，审计发现如下。

1. **高优先级：信任根语义未保持一致。** 原 Rustls 客户端在
   `crates/dae-daemon/src/production_runtime_owner/resident_dataplane/client/config.rs`
   中显式装载 `webpki-roots`；BoringSSL TCP connector 和
   `vendor/quinn-boring/src/client.rs` 则调用 `set_default_verify_paths()`，依赖宿主
   OS 的默认证书目录。与此同时，Hysteria2 的策略仍把该语义标记为
   `BundledWebPki`。当前 OpenWrt/安装包中没有发现与系统 CA bundle 对应的明确
   依赖契约，最小系统上可能出现同一配置在 Rustls 可验证、BoringSSL 无根可用的
   兼容性回归。**正式选择随 DaeNext 内置 Mozilla roots，不依赖或静默合并 OS
   CA bundle。** 配置命名、BoringSSL root store、打包内容、初始化错误和跨发行版
   测试必须统一到该语义。

2. **高优先级：TCP TLS 会话恢复没有延续原工作流。** 当前策略声明
   `ProviderManagedNoEarlyData`，但 BoringSSL 客户端 session cache 默认关闭，应用
   需要保存 `SslSession` 并在后续连接上显式 `set_session()`。现有 Boring TCP、
   XHTTP 和 DNS 路径未实现该过程，而原 Rustls `ClientConfig` 使用内存会话缓存。
   这会增加短连接或频繁重连场景的握手 CPU、时延和网络往返。应增加有界 session
   LRU，key 至少覆盖 SNI、校验策略、ALPN、fingerprint 和 Reality 身份，并在配置
   reload 时清空；继续禁止 early data，避免改变当前安全语义。

3. **中优先级：同步 SSL/BIO 到 Tokio 的 I/O 适配仍不完整。**
   `tokio-boring` 会把每次 `poll_read`/`poll_write` 映射成同步 SSL 调用，因此上层
   read/write 粒度会直接影响 SSL/BIO 调用次数。AnyTLS 持久缓冲 reader 已证明
   调用粒度是实际因素，但尚未消除全部回退。另有
   `crates/dae-daemon/src/production_runtime_owner/resident_dataplane/dns.rs` 的
   `ResidentDnsTlsStream` 未转发 vectored write，而
   `crates/dae-daemon/src/production_runtime_owner/resident_dataplane/dns/tcp_wire.rs`
   已对 2 字节长度和 payload 发起 vectored write，但 wrapper 尚未转发该能力，
   reader 也仍分别读取长度和 payload。后续应先补 partial-write 契约和 wrapper
   转发，再采用有界 plaintext read buffer；不应引入跨 frame 延迟批处理，以免
   增加尾延迟。

4. **中优先级：ML-KEM secret 擦除只覆盖了部分副本。**
   `crates/dae-outbound/src/vless/encryption/boring_mlkem.rs` 会擦除 private key 和
   返回的 `SharedSecret`，但 `crates/dae-outbound/src/vless/encryption/stream.rs`
   随后仍把 secret 复制到普通 `Vec`、`pfs_key` 和 `united_key`，这些副本没有完整
   的 drop-time wipe。应改用 zeroizing buffer，或为完整 stream key state 实现
   一致的销毁清理，避免只擦除源对象而保留派生副本。

以下工作流经代码核对后基本正确，不应在性能修复中无关改动：

- QUIC 强制 TLS 1.3、要求 ALPN，并显式控制 0-RTT；其 session cache key 已包含
  policy namespace 和 SNI；
- Hysteria2 leaf pin、Juicity certificate-chain pin 及 allow-insecure 的映射总体
  符合原有安全语义；
- ML-KEM 固定长度约束以及与 AWS-LC 的双向互操作测试有效；
- Reality 明确以 auth-key verification 替代普通 hostname verification，该差异
  是协议设计，而不是遗漏的证书校验。

现有定向证据进一步限定了优化判断：

- AnyTLS persistent reader 把 concurrent UDP PPS 中位回退从 `-11.54%` 收敛到
  `-5.77%`，p99 恶化从 `+92.83%` 收敛到 `+41.59%`，说明减少 SSL read 次数有效，
  但热点仍稳定存在；证据位于
  `target/remote187-hotspot-fixes-20260813/evidence/README.md`；
- Trojan WebSocket vectored forwarding 修复没有解释 download 回退，不能继续凭
  “额外 TLS record”假设扩大修改；
- DNS 远端复测共 72 cases、36 pairs，`8640/8640` 请求成功，DoT/DoH2 latency
  gate 通过；结果位于
  `target/remote38-boring-ab-current/retest-20260813/REMOTE38-DNS-RETEST-SUMMARY.json`；
- provider 与热点补充证据分别位于
  `target/remote38-boring-ab-current/evidence/PROVIDER-SUMMARY.json` 和
  `target/remote187-hotspot-fixes-20260813/evidence/README.md`。

本节审计结论要求先补内置 roots、TCP session、I/O 适配和 ML-KEM wipe，但不再在
此处规定它们跨阶段的执行顺序。经源码文件级复核后的唯一权威工作包顺序见 12.13；
只有各自功能、安全语义和性能 gate 均通过后，才重新评估删除 Rustls/AWS-LC
fallback。

## 12. 审计后修订执行计划（2026-08-13）

本节根据 11.5 的全仓可达性审计重订计划，**自本节起作为后续执行的权威顺序**。
第 5 节原 Batch A-G 保留为最初方案和历史范围，不再据其批次编号直接推进。

修订原因是：当前 Rustls/AWS-LC 不只承担普通 TLS fallback，还覆盖默认 QUIC、
DNS、健康检查、经代理 HTTPS fetch、订阅更新和 geodata 下载。现有
`test-boringssl-tcp-tls` 与 `test-boringssl-quic` 只替换其中一部分；即使 candidate
通过已有协议矩阵，只要 `quinn` 仍启用 `rustls-aws-lc-rs`，或管理面仍调用
`tokio-rustls`/`rustls::StreamOwned`，都不能称为 Boring-only。

### 12.1 范围账本与完成口径

必须分别维护以下迁移域，不能用其中一域通过代替全局完成：

| 迁移域 | 当前 Rustls/AWS-LC 可达路径 | BoringSSL 状态 |
|---|---|---|
| 通用 TCP TLS | VLESS、VMess、Trojan、AnyTLS、Meek、HTTP CONNECT、Shadowsocks v2ray-plugin、xHTTP H1/H2 endpoint、Reality 无 fingerprint | build-only candidate 已有，尚未通过性能 gate |
| QUIC 协议 | TUIC、Hysteria2、Juicity、xHTTP H3 非 Chrome | build-only candidate 或局部 Chrome path 已有 |
| DNS | DoT、DoH1/2、DoQ、DoH3 direct/proxy | TCP/QUIC candidate 已有，内置 roots 契约已定、统一 loader 待实现 |
| 健康与辅助数据面 | 节点 HTTPS check、resident proxy HTTPS fetch | check 有 candidate；proxy fetch 仍为 Rustls-only |
| 产品管理面 | 订阅 HTTPS、geodata 直接 HTTPS 及经默认代理 HTTPS | Rustls-only |
| 密码与测试支撑 | Quinn AWS-LC provider、Reality Rustls provider、rcgen AWS-LC、ML-KEM 互操作测试 | 生产和 dev edge 尚未分离清退 |

完成口径分为两级：

1. **Production Boring-only：** `daed` 生产 feature 图不包含 `rustls`、
   `tokio-rustls`、`aws-lc-rs` 或 `aws-lc-sys`，所有生产可达 TLS/QUIC/HTTPS 路径
   均通过统一 BoringSSL factory；
2. **Workspace Boring-only：** 在 Production Boring-only 基础上，all-targets 和
   dev/test 图也不再依赖 AWS-LC。若保留 Rustls/AWS-LC 仅用于独立互操作测试，
   必须明确标记为非发布 test crate，不能把它误报为 production dependency。

### 12.2 Phase 0：冻结基线并补全证据

1. 固定 r57 baseline 与当前 hotspot candidate 的源码 revision、feature、binary
   SHA-256、构建参数和远端宿主状态；
2. 生成 `cargo tree` 四份账本：`dae-daemon` production、`dae-outbound`
   production、workspace all-targets、启用两个 BoringSSL test feature 的 candidate；
3. 在 evidence 中强制记录每条连接的 `tlsProvider`、`quicCryptoProvider`、trust
   root 类型、resumed、0-RTT、ALPN 和 verification policy；
4. 对 AnyTLS、Trojan WebSocket、DNS TCP frame、普通短连接 TLS 增加可关闭的
   SSL/BIO call-count、TLS record count、read/write size histogram；
5. 固化 187 的热点定向 A/B、完整协议矩阵以及 38 的 DNS direct/proxy 矩阵。

**退出条件：** 每个测量结果能证明实际 provider 和 binary，且 baseline/candidate
没有混用；profiling 默认关闭时不改变生产行为。

### 12.3 Phase 1：先恢复热点候选所需的 TCP 工作流等价性

该阶段不扩大协议迁移，只修复两个稳定热点 candidate 与原 Rustls/AWS-LC TCP
路径之间会直接影响安全语义或测量结果的确定性差异。DNS framing、QUIC lifecycle
和 ML-KEM wipe 分别作为 Phase 4、Phase 5 和 Phase 3 的进入/退出门禁，不再阻塞
Phase 2 热点归因。

1. 建立 12.3.1 已选定的内置 Mozilla roots 资产和统一 loader，并先接入 Boring
   TCP candidate；QUIC、DNS 和管理面后续只能消费同一 root identity；
2. 建立 daemon 顶层 Boring TLS context/handshake/error 边界，禁止 secure 产品
   TCP client 使用 `SslConnector::builder()` 或 `set_default_verify_paths()`；
3. 为 Boring TCP TLS 实现有界 session LRU 和显式 `SslSession` 恢复，key 覆盖
   SNI、ALPN、verification、fingerprint、Reality 和 protocol namespace；reload
   清空，继续禁止 early data；
4. 保留并验证 `AsyncVlessTlsClient` vectored forwarding、WebSocket 同帧
   header+payload write 和 AnyTLS 有界持久 frame reader；禁止跨 frame 延迟 batching；
5. 用 call-count/record-count 证明热点 candidate 实际改变了预期调用模式，不能仅凭
   吞吐变化认定原因。

**退出条件：** bundled root、TCP context/hostname verification、session resumption、
热点 vectored I/O 和 AnyTLS frame buffering 均有契约测试；OpenWrt 无 CA bundle/
有 CA bundle 场景符合选定语义；reload 后 TCP context/session 不残留。DNS、QUIC 和
ML-KEM 各自在所属 phase 通过前，不得进入对应 production 迁移或依赖清退。

#### 12.3.1 已决策的信任根契约：内置 Mozilla roots

默认验证语义固定如下：

1. DaeNext 发布物内置一份供 BoringSSL 直接装载的 Mozilla server-auth root
   bundle；root 数据不依赖运行时 `/etc/ssl`、`/etc/ca-certificates`、OpenWrt
   `ca-bundle` 或发行版特定路径；
2. root bundle 必须由仓库内可复现的更新流程生成，并记录 Mozilla 上游快照版本、
   生成工具版本、证书数量、源文件 SHA-256 和最终嵌入数据 SHA-256；禁止构建时从
   网络获取未固定内容；
3. Boring TCP TLS、`quinn-boring` QUIC、DNS、health/proxy fetch、订阅和 geodata
   共用同一份 root material 和统一 loader，不允许各模块维护不同副本；
4. secure 模式禁止调用 `set_default_verify_paths()`，也不自动合并 OS roots；安装
   了系统 CA bundle 与未安装时，默认验证结果必须一致；
5. root bundle 缺失、损坏、解析失败或加载数量不符合构建清单时，初始化必须明确
   失败；禁止静默使用空 store、系统 roots 或退化为 `allow-insecure`；
6. Linux、OpenWrt、Deb、RPM 和 APK 发布物都携带同一 root 快照，不把系统
   `ca-bundle` 声明为默认验证的强制运行时依赖；更新 roots 随 DaeNext 发布和安全
   更新进入版本审计；
7. 企业私有 CA 不自动继承宿主 trust store。未来若提供 `ca-file`/`ca-dir`，必须是
   显式用户配置、使用独立 typed policy，并明确“替换”还是“追加”内置 roots；在
   该配置落地前，私有 CA 需求不得通过恢复隐式 OS roots 实现；
8. `allow-insecure`、Reality auth-key verification、leaf pin 和 cert-chain pin
   继续按各自策略工作，不得借由 root loader 改变其验证组合语义。

该契约的最低验收矩阵包括：无 `/etc/ssl` 且未安装 `ca-bundle` 的最小 OpenWrt、
安装了额外私有系统 CA 的 Linux、标准公共 CA、未知 CA、过期证书、hostname
mismatch、空/损坏内置 bundle。最小 OpenWrt 必须能验证公共 CA；Linux 额外系统
CA 默认不得改变结果；所有生产 TLS/QUIC/HTTPS caller 必须报告同一 root bundle
identity 和 SHA-256。

### 12.4 Phase 2：关闭两个稳定热点

只测试仍可重复的 AnyTLS concurrent UDP 和 Trojan WebSocket download；VLESS TLS
因布局/宿主抖动暂作为观察项，不作为本阶段根因假设。

1. 每项至少 5 对随机交叉 A/B；若接近阈值，扩展到 7 对；
2. AnyTLS 必须同时比较 PPS、p99、SSL read/write 次数、TLS record 数和 daemon
   ticks/GiB；
3. Trojan WebSocket 必须分别报告 upload/download/duplex，不能用综合吞吐掩盖
   download 回退；
4. candidate 每次只包含一个可归因变量，拒绝把 QUIC、allocator、LTO 或无关协议
   修改并入同一热点 binary；
5. 复用 11.4 的 wire、完整性、cleanup 和宿主隔离标准。

**退出条件：** AnyTLS concurrent UDP PPS 回退不超过 3%、p99 恶化不超过 5%；
Trojan WebSocket download 吞吐回退不超过 2%、ticks/GiB 恶化不超过 3%，且每项
方向在多数配对中一致。未通过则保留 Rustls TCP production provider，不进入范围
扩张阶段。

### 12.5 Phase 3：完成通用 TCP TLS 与辅助数据面迁移

在 Phase 2 通过后，按共享 TLS factory 的实际调用面逐组迁移：

1. VLESS、VMess、Trojan、HTTP CONNECT；
2. AnyTLS、Meek、shared H2/WebSocket/HTTP Upgrade carrier；
3. Shadowsocks v2ray-plugin、xHTTP H1/H2 endpoint；
4. Reality 无 fingerprint、Vision、fragmented TLS；
5. 在 VLESS Encryption production 验收前完成 ML-KEM shared secret、`pfs_key`、
   `united_key` 和 stream key state 的 drop-time wipe；
6. 节点 HTTPS health check；
7. resident proxy HTTPS fetch。

所有路径必须共用 typed policy、trust-root loader、session cache、timeout/error mapping
和 stream adapter；不得为单协议复制 connector builder，也不得在 BoringSSL 失败时
静默回退 Rustls。

**退出条件：** TCP 协议矩阵、Reality/Vision/Encryption、health check、proxy
fetch 正确性全部通过，ML-KEM secret wipe 有契约证据；按第 4.2 节完成至少 3 对
A/B，无稳定性能回退。

### 12.6 Phase 4：完成 DNS TCP TLS 迁移

1. 迁移 DoT、DoH1、DoH2 的 direct 和 proxy 路径；
2. 保持连接池、并发、fallback、TC=1、stale refresh、deadline 和错误分层；
3. DNS frame 使用 12.12.6/WP7 的同帧 coalesce 和有界 reader；
4. 验证 session resumption、连接复用、远端 close 后重建、reload 清理；
5. 同时覆盖域名上游、IP 上游+显式 SNI、allow-insecure 和 trust-root 缺失。

**退出条件：** 38 的 DNS direct/proxy matrix 全部成功，request 完整性 100%，
p95/p99、CPU、RSS 达到第 4 节 gate。

### 12.7 Phase 5：完成 QUIC 与 DNS QUIC 迁移

共享 `quinn-boring` factory 先通过验证、pin、ALPN、session、0-RTT、key update、
exporter、alert mapping、peer close、timeout 和 cleanup fixture，再按以下顺序迁移：

1. DoQ；
2. DoH3；
3. xHTTP H3 非 Chrome，并与现有 Chrome Boring path 合并；
4. Hysteria2；
5. TUIC；
6. Juicity；
7. QUIC health/manual probe。

每个协议独立提交和 A/B，覆盖 TCP-over-QUIC、UDP datagram、concurrent UDP、
congestion、PMTU、fragmentation、port hopping、session expiry、endpoint rebuild、
remote close、reload 和 owner join。Juicity 还必须验证 TLS exporter 与 cert-chain
pin，Hysteria2 必须验证 WebPKI+leaf pin 组合。

**退出条件：** 所有 production caller 不再构造 `quinn::crypto::rustls` config；
完整 QUIC/DNS/协议矩阵与性能 gate 通过后，才允许从 `quinn` 移除
`rustls-aws-lc-rs`。

### 12.8 Phase 6：迁移产品管理面 HTTPS

1. 把订阅 HTTPS direct exchange 迁移到统一 async Boring HTTPS client；
2. 把 geodata 同步 `rustls::StreamOwned` 下载和下载到文件路径迁移到 BoringSSL，
   保持 redirect、response limit、timeout、临时文件和原子替换语义；
3. 经默认代理的订阅/geodata HTTPS 必须复用 Phase 3 的 proxy fetch/TLS 路径；
4. 把基于 `rustls::CertificateError` 的错误分类改为 provider-neutral typed error；
5. 验证取消、reload/shutdown、坏证书、未知 CA、hostname mismatch、redirect loop、
   partial EOF 和超限响应。

**退出条件：** 订阅和 geodata 的 direct/proxy HTTP(S) 矩阵通过，错误分类和用户可见
结果与原路径等价，管理面无 Rustls production caller。

### 12.9 Phase 7：Production Boring-only 清退

严格按依赖反向可达性执行：

1. 删除 `AsyncVlessTlsEngine::{Rustls,RealityRustls}`、Rustls config cache 和 provider
   selection 分支；
2. 删除 production `rustls`、`tokio-rustls`、`webpki-roots` 依赖；若选内置 roots，
   改为 BoringSSL 可消费的独立 root material，不保留 Rustls 仅为解析证书；
3. `quinn` 只启用 `runtime-tokio`，所有 crypto config 显式来自 `quinn-boring`；
4. 删除 production `aws-lc-rs`/`aws-lc-sys` edge 和 Watfaq Rustls patches；
5. 清理 `dae-cli` 未使用的 Rustls manifest dependency、provider evidence 旧枚举和
   仅兼容命名；
6. 运行 production feature 的 duplicate-symbol、dynamic linkage、binary strings、
   `cargo tree` 和交叉编译审计。

**退出条件：** Production Boring-only 定义成立；x86_64-v2/v3、arm64、OpenWrt、
Deb/RPM/APK 构建和安装 smoke 通过；完整协议、DNS、管理面、性能、资源和 cleanup
gate 全部通过。任何失败都回滚本 phase 的依赖删除，不能恢复静默双 provider。

### 12.10 Phase 8：测试依赖与发布收口

1. 将仍需 Rustls/AWS-LC 的互操作测试移入独立非发布 test crate，或用固定向量和
   外部 fixture 替代；
2. rcgen 仅保留在确有必要的 dev-dependency，优先使用固定测试证书；
3. 评估删除 `dae-outbound` 中不再被生产调用的同步 Rustls dataplane/loopback
   helper，先以调用图和测试替代证明其不可达；
4. 检查 workspace all-targets、Cargo.lock、SBOM、license 和 source package；
5. 记录 Production Boring-only 与 Workspace Boring-only 是否分别达成，禁止把
   Cargo.lock 中的测试依赖误报为生产链接。

**最终完成条件：** 第 10 节原定义全部满足，并额外满足 12.1 的 Production
Boring-only；若项目决定连独立互操作测试也不保留 AWS-LC，则还须满足 Workspace
Boring-only。发布前至少执行 7 对完整随机 A/B，并在 187 与 r57 baseline 上保留
可复验原始证据、binary hash、provider evidence 和完整清理报告。

### 12.11 停止条件与当前下一步

出现以下任一条件立即停止扩大迁移范围：

- 信任根在 OpenWrt/安装包目标上没有可执行的产品契约；
- session resumption、Reality auth、pin、ALPN 或 0-RTT 语义无法与原路径等价；
- Phase 2 任一稳定热点未通过性能 gate；
- DNS、QUIC 或管理面迁移出现无法按 provider-neutral typed error 表达的兼容回退；
- cleanup、RSS、FD、owner 或 key/session state 出现逐轮残留。

因此当前下一步不是立即删除 Rustls/AWS-LC，而是依次执行 Phase 0、Phase 1、
Phase 2。只有两个稳定热点关闭且工作流等价性得到证据后，才进入其余生产路径迁移。

### 12.12 源码核对后的文件级实现域索引（2026-08-13）

本节以 2026-08-13 当前 dirty worktree 为准，细化 12.2 至 12.10 的实际落点。
本节按实现域组织，用于查找文件和契约，**小节编号不表示执行先后**；唯一权威执行
顺序见 12.13。
下表中的“已有”仅表示本地未提交源码已经出现相应实现，不表示已经提交、合入或通过
验收。后续实施必须保留这些本地修改并在其上增量收口，不能按 r57 源码重新实现后覆盖。

#### 12.12.1 当前实现状态账本

| 能力 | 当前源码状态 | 结论 |
|---|---|---|
| 内置 Mozilla roots | 尚无产品 PEM、清单、离线生成工具和统一 loader | 必须最先实现；`webpki-roots` 只有 trust-anchor 元数据，不能直接还原供 BoringSSL `X509Store` 导入的完整 X.509 证书 |
| Boring TCP TLS context | `client/config.rs`、`probe/http_check.rs`、`dns/transport/tls_https.rs` 和 `service_contract/outbound_fingerprint.rs` 仍调用 `SslConnector::builder()` | 不满足无系统 CA 的 OpenWrt 契约；该 API 在 caller 安装自有 store 之前就调用 `set_default_verify_paths()` |
| TCP TLS config/session cache | `client/types.rs` 已有有界 `Arc<SslConnector>` config cache 和 reload clear；没有显式 `SslSession` LRU | 改成 context 与 session 同所有权的 cache entry，不能在旧 connector cache 上外挂进程全局 session map |
| Boring QUIC 公共层 | 本地新增 `shared_transport/boring_quic.rs`，但策略仍名为 `SystemRoots`，vendored `quinn-boring::Config::new()` 仍加载系统 roots | 公共层方向正确，root 构造和策略命名尚未完成 |
| QUIC session cache | 本地已为 `quinn-boring` 增加 `SessionCache::clear`、`SimpleCache`、namespace+SNI key，并在 Hysteria2、TUIC、Juicity、xHTTP H3 注入 generation cache | 标记为“已有，待验证/收口”；owner drop/shutdown clear、DNS DoQ/DoH3 ownership 和默认内部 cache 语义尚未闭环 |
| VLESS/Trojan vectored write | `AsyncVlessTlsClient` 已转发 `poll_write_vectored`/`is_write_vectored`，WebSocket helper 已能发 header+payload slices | 只补 trait contract、partial-write 和 TLS record 证据；现有改动未解释 Trojan WS download 回退，禁止把它预设为根因 |
| AnyTLS frame reader | 本地已有有界持久 `AnyTlsFrameReader`，并接入 `anytls_owner.rs` | 标记为“已有，待验证”；补跨 read 边界、单 read 多帧、保留下帧、上限、EOF 和 profile 证据 |
| DNS TCP framing | `tcp_wire.rs` writer 已对 2 字节长度和 payload 使用 `write_vectored`；`ResidentDnsTlsStream` 未转发 vectored write，reader 仍分两次 `read_exact` | writer 只完成一半；先补 partial-write 契约，再给 read-half/连接增加持久有界 decoder |
| 产品管理面 HTTPS | resident proxy fetch、subscription direct exchange、geodata direct HTTPS 仍为 Rustls；订阅错误分类读取 `rustls::CertificateError` | 必须在统一 typed Boring helper 稳定后分三步迁移，不能直接删除 Rustls 类型 |
| ML-KEM 密钥清理 | `SharedSecret` 和 `VlessEncryptionTicket` 已用 `OPENSSL_cleanse`；`VlessEncryptedStream::united_key` 及若干临时 key/plaintext 未完整清理 | 属于部分完成；继续使用小型本地 secret wrapper，逐个证明生命周期 |
| A/B feature | `test-boringssl-tcp-tls`、`test-boringssl-quic` 仍保留，生产默认分支仍可到 Rustls | 符合当前验证阶段；所有 gate 通过前不翻转默认 provider |

#### 12.12.2 实现域 A：可复现的内置 root 资产

文件落点：

- 新增 `crates/dae-outbound/assets/ca/mozilla-roots.pem`，作为编译期
  `include_bytes!` 的唯一产品 root material；
- 新增 `crates/dae-outbound/assets/ca/mozilla-roots.manifest.json`，至少记录上游
  snapshot/version、生成工具版本、证书数量、输入 SHA-256、规范化 PEM SHA-256；
- 新增 `tools/mozilla-roots/` 下的离线更新/check 工具和 README。工具接收已下载并
  固定 hash 的 Mozilla `certdata.txt` 或等价上游输入，不在普通 build、test 或
  package 阶段联网；
- 新增 `crates/dae-outbound/src/shared_transport/boring_roots.rs`，并由
  `shared_transport/mod.rs` 导出 typed loader 和 root identity。

实现约束：

1. 用 `X509::stack_from_pem` 解析完整证书，用 `X509StoreBuilder::add_cert` 构造
   store；不得把 `webpki-roots::TLS_SERVER_ROOTS` 当作 DER/PEM 证书使用；
2. 不得使用 BoringSSL 测试目录中的 `mozilla_roots.der` 作为产品数据；
3. 用 `OnceLock<Result<BundledMozillaRootStore, String>>` 缓存不可变 store、证书数和
   bundle identity。解析失败也缓存为确定性错误，禁止后续静默换用 OS roots；
4. `boring-v4-compat` 当前重导出同一个 Boring 5.1 package，TCP 和
   `quinn-boring` 可复用同一 `X509Store` 类型。若未来依赖图产生第二个 Boring
   package identity，build gate 必须失败，不能复制两份运行时 loader；
5. manifest 的证书数、规范化 hash 与编译进 binary 的 bytes 必须一致；重复、空、
   非 CA 或损坏条目按生成期/初始化期明确失败。

本步测试与退出条件：

- `cargo test -p dae-outbound boring_roots` 覆盖固定 hash、证书数、空/损坏 PEM、
  duplicate 和 loader 单次初始化；
- 离线 check 工具对未变输入不得产生 diff，对变更输入必须同时更新 PEM 和 manifest；
- source gate 确认 secure 产品客户端 context/factory 没有
  `set_default_verify_paths()`；测试 fixture 或服务端若确有该调用必须单独列账，不能
  被误认成客户端信任根实现；
- 最小 OpenWrt rootfs 无 `/etc/ssl` 时 loader 初始化成功；安装额外 OS 私有 CA 前后
  bundle identity 和验证结果不变。

任一发布目标无法编译嵌入同一 bundle，或证书许可/来源无法审计时，停止后续迁移。

#### 12.12.3 实现域 B：daemon 统一 Boring TLS context/handshake 边界

新增顶层 `crates/dae-daemon/src/boring_tls.rs`，并在 `crates/dae-daemon/src/lib.rs`
注册。resident dataplane 与 `daed_product` 是同级模块，不允许二者相互依赖；该顶层
模块是它们共享的唯一 TCP/HTTPS BoringSSL 边界，root store 继续由
`dae_outbound::shared_transport::boring_roots` 提供。

该模块至少提供：

- typed `BoringTlsClientPolicy`：ALPN、验证模式、SNI/verify name、fingerprint、
  Reality、TLS version 和 protocol namespace；
- `Arc<SslContext>` 构造器、async `tokio_boring::SslStreamBuilder` handshake helper、
  geodata 使用的 sync handshake helper；
- context 与 session 同所有权的通用 entry/session hooks；resident dataplane、DNS、
  health check 和管理面只负责各自 generation/cache owner，不复制 ticket 逻辑；
- DNS name 与 IP literal 分离的 peer-name 设置；
- provider-neutral `TlsClientError`：unknown CA、hostname mismatch、expired、
  not-yet-valid、protocol、I/O、timeout、invalid policy；
- root identity、provider、ALPN、session attempted/reused 和 verification policy evidence。

禁止产品客户端继续使用 `SslConnector::builder()`。统一构造器必须从
`SslContextBuilder::new(SslMethod::tls())` 开始，在 handshake 前安装内置
`X509Store`，并显式复制当前 Boring 5.1 connector 的安全语义：

1. 固定 `SslOptions`、`SslMode`、cipher list、TLS version policy 和
   `SslVerifyMode::PEER`，为每项写 snapshot/contract test，避免 crate 升级时隐式漂移；
2. DNS hostname 同时设置 SNI 和 `verify_param.set_host()`；IP literal 不发送 SNI，
   使用 `verify_param.set_ip()`；两者都设置
   `X509CheckFlags::NO_PARTIAL_WILDCARDS`；
3. `allow-insecure` 只能通过 typed policy 显式关闭 peer verification，不能由 root
   初始化失败触发；Reality/pin/fingerprint callback 顺序必须保持现有语义；
4. 每条连接用 `Ssl::new(context)` 设置 connection-local policy，再通过
   `tokio_boring::SslStreamBuilder::new(ssl, stream).connect()`；同步路径使用同一
   context/policy builder，不复制验证逻辑；
5. context cache key 必须包含所有会改变 ClientHello、验证结果或 session 可复用性的
   字段，并包含 root bundle identity。

该实现域最终覆盖的直接 caller：

- `client/config.rs`、`client/open_client.rs` 和 `client/types.rs`；
- `probe/http_check.rs`；
- `dns/transport/tls_https.rs` 及 `dns/transport/tls_https/proxy.rs`；
- `service_contract/outbound_fingerprint.rs`，把“connector builder 能否成功”改成
  “内置 roots + 产品 context 能否完成初始化”的 readiness check。

调用点按 12.13 分阶段接入：WP2 只切 resident TCP hotspot candidate，health check、
DNS 和管理面分别留到 WP6、WP7、WP9，避免无关 caller 改动进入热点 binary。期间不
翻转 production provider。contract test 必须覆盖公共 CA、未知 CA、hostname
mismatch、IP SAN、过期/尚未生效证书、ALPN mismatch、明确 insecure，以及系统
CA 有/无两种环境。

#### 12.12.4 实现域 C：与 context 绑定的 TCP session LRU

在顶层 `boring_tls.rs` 定义可复用的 `BoringTlsContextEntry`，并在
`client/types.rs` 将 `BORING_CONNECTOR_CACHE` 替换为有界 resident owner cache；
管理面后续复用同一 entry/session hooks，不得另写 session 实现。每个 entry 至少拥有：

- `Arc<SslContext>`；
- 有界 session LRU 及容量/命中/逐出/清空计数；
- 不可变的 typed policy key 和 root bundle identity；
- reload generation 或明确的 owner generation。

具体握手流程固定为：

1. 从完整 policy key 获取同一 context entry；
2. 在新 `Ssl` 的 ex-data 写入 session key，key 至少覆盖 SNI、ALPN、verification、
   roots identity、fingerprint、Reality、TLS version 和 protocol namespace；
3. handshake 前只从该 entry 的 LRU 取 session，并调用 `SslRef::set_session`；该调用
   为 unsafe，安全注释和测试必须证明 session 永远来自同一个 `SslContext`；
4. context 的 `set_new_session_callback` 读取 connection-local key 并写回同一 LRU；
5. set/handshake 证明 ticket 无效后立即 remove；若 LRU 选择编码存储，decode 失败
   也立即 remove。evidence 分别记录 attempted、accepted、reused 和 rejected；
   early data 继续关闭；
6. `clear_resident_tls_config_caches()` 在 workload quiesce 后清空 context entry，
   session 随 entry 一起释放，并分别报告 context/session 数；shutdown/reload 不保留
   process-global ticket。

测试必须证明首次握手不 resumed、第二次同 policy resumed、任一 key 字段变化不串用、
跨 context session 被结构性禁止、坏 ticket 被移除、LRU 有界、reload 后不 resumed。
这些 contract 未通过前不进行热点性能归因。

#### 12.12.5 实现域 D：QUIC roots 和 generation session 生命周期

文件落点为 `vendor/quinn-boring/src/client.rs`、
`vendor/quinn-boring/src/session_cache.rs`、
`crates/dae-outbound/src/shared_transport/boring_quic.rs` 及各 protocol owner。

1. 为 `quinn-boring::ClientConfig` 增加显式 store/context 构造入口，移除 production
   `Config::new()` 对 `set_default_verify_paths()` 的依赖；QUIC TLS 1.3、QUIC method、
   callback、ALPN 和 verify defaults 保持原契约；
2. 把 `BoringQuicVerificationPolicy::SystemRoots` 重命名为
   `BundledMozillaRoots`，同步修改 `system-roots` evidence、plan tests 和 capability
   文案；`PinnedLeafSha256 { require_webpki: true }` 必须先通过同一 bundled store；
   pure pin、cert-chain pin 和 explicit insecure 语义不变；
3. `session_cache_namespace` 增加 root bundle identity；保留 ALPN、verification、
   ClientHello profile、0-RTT policy 和 SNI 隔离；
4. 将 vendored config 的隐式默认 `SimpleCache` 改为 `NoSessionCache`，或让所有
   production factory 必须显式传入 generation cache。禁止出现无人负责 clear 的
   隐式长期 cache；
5. 先把 `SessionCache::clear()` 改为返回 removed count，或增加等价的原子
   size/clear snapshot API；随后让 Hysteria2、TUIC、Juicity 和 xHTTP H3 的 owner
   drop/shutdown 调用它、记录清除数量，并在 owner task join 后释放；
6. 为 `dns/transport/quic.rs`、`dns/transport/quic/proxy.rs` 和
   `dns/upstream_model.rs` 增加 DoQ/DoH3 generation cache ownership，reload、远端
   close、endpoint rebuild 和 shutdown 都有确定清理点；
7. 保持 policy 默认 `zero_rtt=false`；只有已有明确协议契约和 replay 分析的 caller
   才能启用，不因 session cache 可用而自动打开。

测试先运行 `cargo test -p quinn-boring session_cache` 和
`cargo test -p dae-outbound boring_quic`，再覆盖无 `/etc/ssl`、额外 OS 私有 CA 被
忽略、unknown CA、hostname mismatch、pin 组合、namespace 隔离、坏 entry remove、
reload clear 和 0-RTT disabled。QUIC roots 未与 TCP 报告同一 identity 时停止迁移。

#### 12.12.6 实现域 E：vectored I/O 和有界 frame reader

本步按“已有代码优先补契约，再决定是否修改”执行：

1. `client/async_client.rs`：保留现有 `AsyncVlessTlsClient` vectored 转发，增加
   wrapper contract test，分别验证底层支持/不支持 vectored、partial write 和
   `Poll::Pending`；
2. `tcp/stream_helpers.rs` 和 WebSocket tests：证明 header+payload 在底层支持时
   进入一次 vectored call，在 partial write 后没有重复/遗漏；记录 Trojan WS 的
   SSL write/TLS record evidence。若 download 仍回退，回到 profile，不继续猜测；
3. `tcp/proxy_dispatch/anytls.rs`、`runtime/anytls_owner.rs` 和 `tcp/tests.rs`：保留
   现有 `AnyTlsFrameReader`，补 header 跨 read、payload 跨 read、单 read 多帧、解析后
   保留下帧、最大 frame、超限、header/payload EOF 和连续小 UDP frame tests；确认
   buffer 上限仍为 32 KiB 级有界值且不改变 wire/padding/timeout/owner；
4. `dns.rs`：为 `ResidentDnsTlsStream` 补
   `poll_write_vectored`/`is_write_vectored` 转发；
5. `dns/tcp_wire.rs`：为现有 writer 增加自定义 partial writer tests，覆盖只写入
   2 字节 header 的一部分、恰好写完 header、写入部分 payload、zero write、pending
   和错误，证明 remainder offset 正确且只 flush 一次；
6. DNS reader 改为有界持久 decoder。buffer 必须随连接或 read-half 存活，不能作为
   每次调用的局部变量，否则一次 SSL read 预取的下一 frame 会丢失；同步改造
   `dns/transport/tcp_multiplex.rs` 的 reader task、DoT reusable stream 和相应 pool
   entry。普通 inbound DNS TCP 可复用同一 decoder，但不得改变 deadline 和 frame
   上限。

先用 call-count/record-count 证明调用模式变化，再在 187 做单变量 A/B。AnyTLS 和
Trojan WS 必须使用不同 candidate，DNS 改动不得混入两者的热点归因 binary。

#### 12.12.7 实现域 F：管理面 HTTPS

只有实现域 A 至 C 的统一 helper 和 typed error 通过后才执行：

1. 先迁移 `production_runtime_owner/resident_dataplane/tcp/proxy_fetch.rs` 到顶层
   async Boring helper，保持 request/response limit、timeout、shutdown 和经代理
   TCP stream 所有权；
2. 再迁移
   `daed_product/nodes_subscriptions_groups/subscription_refresh/http/direct_exchange.rs`，
   保持 redirect、HTTPS downgrade rejection、ALPN、response cap 和取消语义；
3. 同步修改 `subscription_refresh/fetch_error.rs`，先按 provider-neutral
   `TlsClientError` 分类 unknown CA、hostname mismatch、expired 等，再删除
   `rustls::CertificateError` downcast；
4. 最后迁移 `daed_product/geodata/http.rs` 的同步内存响应和 streaming-to-file 两条
   HTTPS 路径，复用顶层 sync helper，保持 redirect、downgrade rejection、connect/
   read/write timeout、response limit、hash、临时文件、fsync/atomic replacement 和
   partial EOF 语义；
5. 订阅/geodata 经默认代理路径复用第 1 项的 proxy fetch/TLS 边界，禁止再造第二个
   Boring connector。

每个 caller 独立提交/验证。测试覆盖 direct/proxy HTTP(S)、redirect loop、HTTPS 到
HTTP downgrade、unknown CA、hostname mismatch、超限、超时、取消、partial file、
reload/shutdown；产品可见错误分类必须与原 Rustls 路径等价。

#### 12.12.8 实现域 G：ML-KEM 与 stream key 清理

文件落点为 `vless/encryption/boring_mlkem.rs`、`vless/encryption/mod.rs` 和
`vless/encryption/stream.rs`。

1. 保留已有 `SharedSecret`、`VlessEncryptionTicket::drop`；
2. 为固定数组和变长 key 增加小型本地 secret wrapper，内部统一调用
   `OPENSSL_cleanse`，避免仅为少量 buffer 引入宽泛依赖；
3. `VlessEncryptedStream::united_key`、`nfs_key`、栈上 `pfs_key`、ticket plaintext、
   peer PFS plaintext 和完成派生后的中间数组在最后一次使用后立即 cleanse；
4. 审计 AEAD/CTR state 是否复制 key material，能控制的 owner 在 drop 时清理，无法
   控制的第三方类型记录边界和替代证据；
5. 错误/提前返回/取消路径必须与成功路径同样触发 drop。

测试使用 test-only wipe observer/helper 证明各 owner 的 drop/early-return 路径被调用，
禁止读取已释放内存。互操作向量、ticket reuse 和加解密结果必须保持不变。

#### 12.12.9 实现域 H：证据、单变量提交和停止门禁

每个改动域单独保留可回滚提交，不把多个性能变量合并。具体执行顺序由 12.13 固定，
本域只定义所有阶段共同遵守的证据契约。

每个 candidate evidence 至少记录 git revision/dirty patch identity、feature、binary
SHA-256、root bundle SHA-256、provider、session reused、0-RTT、ALPN、宿主状态和原始
结果。性能阶段沿用 12.4 gate；任一正确性、cleanup、root identity 或热点 gate
失败，只回退该单变量提交并停止扩大范围，不删除 Rustls fallback。

#### 12.12.10 实现域 I：依赖和旧分支清退

完成前述 gate 后才执行一次 production provider 翻转：

1. BoringSSL 变为无 feature gate 的 production 路径，Rustls baseline 若仍需保留，
   移入独立非发布 test target；
2. 所有 production QUIC caller 不再创建 `quinn::crypto::rustls` config 后，才从
   workspace `quinn` feature 删除 `rustls-aws-lc-rs`；
3. 按反向可达性删除 `dae-daemon`、`dae-outbound` 的 `rustls`、`tokio-rustls`、
   `webpki-roots`，清理 `dae-cli/Cargo.toml` 当前未使用的 Rustls dependency；
4. 删除旧 cache/provider enum、`system-roots` evidence 和 Watfaq patch 前，先用
   `cargo tree` 分别证明 production、all-targets、dev/test 的剩余 edge；
5. 最后执行 x86_64-v2/v3、arm64、OpenWrt、Deb/RPM/APK build/install smoke、SBOM、
   duplicate-symbol、dynamic linkage 和 binary-string 审计。

本节实施完成的判据不是“源码中出现 BoringSSL”，而是所有 production TLS/QUIC/
HTTPS caller 共享同一 bundled-root identity、typed policy/error 和有界生命周期，
两个稳定热点通过 gate，且 reload/shutdown 后 context、session、owner 和 secret state
均有可复验证据证明已清理。

### 12.13 唯一权威执行顺序与工作包（2026-08-13 修订）

后续实施只按本节顺序推进。12.2 至 12.10 定义阶段目标和退出条件，12.12 定义文件/
契约索引；二者与本节出现理解差异时，以本节的依赖顺序为准。每个工作包独立提交、
独立构建、独立生成 evidence；未经明确列出的文件不得混入该工作包 candidate。

#### WP0：冻结 r57 release baseline 与当前 dirty candidate

- 输入：r57 release baseline（core commit `d31c24c5934f0c351c585576f57b36aecd8a2ae1`
  及已记录 binary SHA-256）、当前 dirty patch、187/38 宿主和已有 evidence；r57 是
  package release `57`，当前 core 仓库没有同名 `r57` Git tag；
- 动作：记录 revision、完整 patch hash、feature、构建参数、binary SHA-256、
  `cargo tree` 四份账本及 provider/root/session/ALPN evidence schema；
- 验收：baseline 与 candidate 可由 hash 唯一识别，profiling 关闭时不改变行为；
- 对应阶段：Phase 0。

#### WP1：内置 Mozilla roots 资产和 loader

- 文件域：12.12.2；
- 动作：加入 PEM、manifest、离线 update/check 工具、`boring_roots.rs` 和 root
  identity；此包只建立资产与 loader，不切换协议 provider；
- 验收：固定证书数/hash、损坏 bundle fail-closed、普通构建不联网、最小 OpenWrt
  无 `/etc/ssl` 可初始化、额外 OS 私有 CA 不改变结果；
- 停止：来源/许可/可复现性或任一发布目标嵌入失败时，不进入 WP2。

#### WP2：统一 TCP context、hostname 和 typed error

- 文件域：12.12.3；
- 动作：新增 daemon 顶层 `boring_tls.rs`，从 `SslContextBuilder` 显式安装 WP1
  store，固定 connector 安全 defaults，统一 DNS name/IP、SNI、hostname verification、
  async/sync handshake 和 `TlsClientError`；
- 范围：只接入 `test-boringssl-tcp-tls` 的 resident TCP hotspot handshake；health
  check、DNS 和管理面 caller 分别留到 WP6、WP7、WP9；
- 验收：公共 CA、unknown CA、hostname mismatch、IP SAN、有效期、ALPN、insecure
  和 OS CA 有/无矩阵通过，secure 产品 client 不调用 `set_default_verify_paths()`。

#### WP3：TCP session resumption 与 reload cleanup

- 文件域：12.12.4；
- 动作：context entry + 有界 session LRU、完整 namespace、`set_session`、new-session
  callback、坏 ticket remove、attempted/reused evidence 和 reload clear report；
- 验收：首次 full handshake、第二次 resumed、key 隔离、LRU 上限、跨 context 禁止、
  reload 后不 resumed、early data disabled；
- 停止：session 与 context 同一所有权无法结构性证明时，不进入热点 A/B。

#### WP4：热点 I/O 契约和观测

- 文件域：12.12.6 中仅 `client/async_client.rs`、`tcp/stream_helpers.rs`、
  `tcp/proxy_dispatch/anytls.rs`、`runtime/anytls_owner.rs` 和 `tcp/tests.rs`；
- 动作：验证现有 VLESS/Trojan vectored forwarding、WebSocket partial write、AnyTLS
  持久 reader 边界，并加入可关闭的 SSL/BIO call/record/size 观测；
- 排除：DNS framing、QUIC、ML-KEM、allocator、LTO 和管理面改动均不得进入热点
  candidate；
- 验收：wire、EOF、frame 上限、partial/Pending、cleanup contract 通过，观测默认
  关闭时结果与基线一致。

#### WP5：187 两个热点单变量 A/B

- 共同基础：WP1-WP4 的 roots/context/session/观测能力；观测在非 profile 轮次关闭；
- AnyTLS candidate：共同基础 + 仅 AnyTLS reader 变量；另保留“共同基础但旧 reader”
  的 Boring internal control，用于证明 reader 的因果贡献；
- Trojan WS：现有 vectored forwarding 只作为已验证契约，不再当作根因 candidate。
  先用共同基础的 profile build 定位稳定差异，只有 call/record/CPU 证据支持时，才
  增加一个单一修复变量及对应 Boring internal control；
- 方法：各至少 5 对随机交叉 A/B，接近阈值扩展到 7 对；两者不得共用一个热点
  candidate 归因；正式 gate 始终对比 r57，internal control 只做因果验证；
- gate：AnyTLS PPS 回退不超过 3%、p99 恶化不超过 5%；Trojan WS download 吞吐
  回退不超过 2%、ticks/GiB 恶化不超过 3%；
- 停止：任一热点未通过，保留 Rustls TCP production provider，不进入 WP6。

#### WP6：通用 TCP TLS、ML-KEM 和辅助数据面

- 文件域：Phase 3 调用面、12.12.8 以及 proxy fetch；
- 顺序：VLESS/VMess/Trojan/HTTP CONNECT；在验收 VLESS Encryption 前完成 ML-KEM
  wipe；随后 AnyTLS/Meek/shared carrier，Shadowsocks/xHTTP H1/H2，Reality/Vision/
  fragmentation，health check，proxy fetch；
- 原则：每组 caller 独立提交和至少 3 对 A/B；不得静默回退 Rustls；
- 验收：完整 TCP、Reality/Vision/VLESS Encryption 和辅助数据面矩阵通过，secret
  drop/early-return wipe 有证据，无稳定性能回退；
- 停止：ML-KEM wipe 未完成时不得宣布 VLESS Encryption production 迁移完成。

#### WP7：DNS TCP framing 和 DoT/DoH1/DoH2

- 文件域：12.12.6 中 `dns.rs`、`dns/tcp_wire.rs`、
  `dns/transport/tcp_multiplex.rs`、DoT reusable stream/pool，以及 DNS TLS caller；
- 动作：补 wrapper vectored forwarding、writer partial contract、随连接/read-half
  存活的有界 decoder，再迁移 direct/proxy DNS TCP TLS；
- 验收：38 direct/proxy matrix、request 完整性 100%、连接复用/重建、TC=1、fallback、
  deadline、session resumption、reload clear、p95/p99/CPU/RSS gate 全部通过。

#### WP8：QUIC roots、session owner 和协议迁移

- 文件域：12.12.5；
- 顺序：先修改 vendored `quinn-boring` 和公共 factory，再补 DoQ/DoH3 generation
  cache ownership，随后按 DoQ、DoH3、xHTTP H3、Hysteria2、TUIC、Juicity、probe
  逐个迁移；
- 验收：TCP/QUIC 报告同一 root identity，pin/exporter/ALPN/0-RTT/session namespace、
  bad-entry remove、owner clear count、endpoint rebuild/reload/shutdown 和完整协议性能
  gate 通过；
- 停止：全部 production caller 停止构造 Rustls QUIC config 前，不删除 Quinn
  `rustls-aws-lc-rs` feature。

#### WP9：管理面 HTTPS

- 文件域：12.12.7；
- 顺序：在 WP6 已迁移 proxy fetch 的基础上，先 subscription direct exchange 与
  typed error classifier，再 geodata sync memory/file 下载，最后 direct/proxy 全矩阵；
- 验收：redirect、downgrade rejection、limit、timeout、cancel、unknown CA、hostname、
  partial EOF、hash、临时文件和 atomic replacement 与原路径等价；
- 停止：产品可见错误无法用 provider-neutral 类型表达时，不清退 Rustls 管理面。

#### WP10：Production Boring-only 翻转与发布

- 文件域：12.12.10；
- 动作：先生成最终 production 反向依赖账本，再一次性翻转默认 provider，删除不可达
  Rustls/AWS-LC production branches/dependencies，保留独立 test baseline（若需要）；
- 验收：production feature 图无 `rustls`、`tokio-rustls`、`aws-lc-rs`、
  `aws-lc-sys`；x86_64-v2/v3、arm64、OpenWrt、Deb/RPM/APK、SBOM、动态链接、符号、
  binary strings、完整协议和至少 7 对最终 r57 A/B 全部通过；
- 回滚：本包失败只回滚 provider 翻转和依赖删除，不恢复隐式双 provider 或系统 roots。

#### WP11：可选 Workspace Boring-only 收口

- 将剩余 Rustls/AWS-LC 互操作测试移入独立非发布 test crate，或改用固定向量/fixture；
- 清理仅 dev/all-targets 可达的 rcgen、Rustls/AWS-LC edge；
- 单独报告是否达到 Workspace Boring-only，不得把 Production Boring-only 与之混淆。

当前可立即开始的工作包是 WP0；WP0 证据冻结后依次执行 WP1、WP2、WP3。直到 WP5
两个热点同时通过前，不开始通用 production 范围扩张、DNS、QUIC 或管理面迁移。

### 12.14 开发分支与提交治理（2026-08-13）

为避免继续污染 `main`，当前 core worktree 已从
`d31c24c5934f0c351c585576f57b36aecd8a2ae1` 创建并切换到本地分支
`work/boringssl-unification`。创建时 `main`、`origin/main` 和新分支均指向同一
commit；所有已有未提交和未跟踪内容原样保留，没有 stash、reset、checkout 覆盖或
提交操作。

创建分支时的 dirty 账本为：

- 68 个已跟踪文件有修改，`git diff --stat` 为 `1847 insertions(+), 513 deletions(-)`；
- 4 个未跟踪入口：`client/policy.rs`、`shared_transport/boring_quic.rs`、
  `vless/encryption/boring_mlkem.rs` 和 `vendor/quinn-boring/`；
- 备忘录 `DAENEXT_BORINGSSL_UNIFICATION_PLAN_2026-08-11.md` 被本地
  `.git/info/exclude` 忽略，不会出现在普通 `git status`、`git diff` 或
  `git add -A` 中；
- 新分支当前还没有独立 commit。仅切换分支不能防止磁盘损坏或误删，WP0 仍须先保存
  完整 patch identity 和文件清单，再建立可审计的 checkpoint。

后续 Git 规则固定如下：

1. `main` 保持跟踪 `origin/main`，不在其上继续 BoringSSL 实验、构建版本或提交；
2. 所有 WP0-WP11 实施均在 `work/boringssl-unification` 或从其派生的单工作包分支上
   进行；不得把 dirty worktree 临时切回 `main` 构建 release；
3. WP0 首先记录 `git diff --binary` SHA-256、未跟踪文件清单、Cargo feature、构建
   参数和已有 evidence，然后建立一个明确标记的 checkpoint commit；该 commit 只
   保存当前候选，不代表通过任何 gate；
4. checkpoint 后按 WP/单变量拆分后续 commit。roots、context/session、AnyTLS、
   Trojan profile/fix、DNS、QUIC、管理面和依赖清退不得合并成一个性能归因 commit；
5. A/B candidate 必须记录 branch、commit、dirty 状态和 binary SHA-256。用于正式
   gate 的 binary 原则上来自 clean commit；确需 dirty profile build 时，必须另存
   patch hash，且不能作为 release candidate；
6. 不强制把本备忘录加入产品源码历史。若需要随分支审计，使用显式
   `git add -f DAENEXT_BORINGSSL_UNIFICATION_PLAN_2026-08-11.md` 单独提交，禁止因
   `git add -A` 未包含它而误判文档已保存；
7. 不在该分支重写或清除已有用户修改；拆分 commit 时先建立完整 checkpoint，再用
   非破坏方式按文件/patch 选择提交。任何 reset、clean 或强制 checkout 都必须先有
   可验证备份并单独批准。

当前分支动作只完成了隔离，没有完成 WP0。下一步仍是冻结 dirty patch 与 evidence，
之后才决定 checkpoint 的具体提交边界。

#### 12.14.1 WP0 dirty checkpoint 身份记录

提交 checkpoint 前记录如下，所有 hash 均在
`work/boringssl-unification@d31c24c5934f0c351c585576f57b36aecd8a2ae1` 生成：

- 已跟踪文件 `git diff --binary` SHA-256：
  `9aa0acae95c13a3385fabc56e2829f8a17e614480b9b988086722d1b1dba7518`；
- 已跟踪修改文件名列表 SHA-256：
  `58cac1fab65676c89fe9540b0212c16d6afb9ea149fc125ec0246365bd5e6e15`；
- 未跟踪入口列表 SHA-256：
  `a39686150e8f40dff623fd03ffe28d15dfed1c1a178400aac09b3df5a19ad0aa`；
- `vendor/quinn-boring/` 共 46 个普通文件，按路径排序后的逐文件 hash 清单 SHA-256：
  `75b8e651d1c988a8e6efe2a8b5b08014ba531b41c24a9e5a1003da8c26f9df70`；
- 三个独立未跟踪源码文件 SHA-256：`client/policy.rs` 为
  `0d3d2d99c33a3faf249ea27d3792e2ce6b8769c118882e873c74b236280ca2e6`，
  `shared_transport/boring_quic.rs` 为
  `1b6150e44078bf8f583b249330476f0adaa6a1527ec018b72ca72de665fe38cd`，
  `vless/encryption/boring_mlkem.rs` 为
  `92d2ac183005c30056cdfe31817a2d83bb056c971cf97882b3c1e0380d8b7035`；
- `git diff --check` 通过；该 checkpoint 尚未执行完整 test/performance gate，提交
  信息必须保持 `wip`/`checkpoint` 语义。

暂存 checkpoint 时发现 `vendor/quinn-boring/` 来自 Cargo 的内部 Git checkout，
其 `.git` 指向本机 `file:///root/.cargo/git/db/...`，若直接提交只会在外层仓库生成
不可移植的 gitlink。为使分支可 clone/checkout，已将其改为普通 vendored 源码：

- 内部 `.git` 元数据移到仓库外
  `/root/quinn-boring-vendor-git-backup-20260813` 备份，不进入产品提交；
- 删除 Cargo 本地标记 `.cargo-ok`，并在 vendored `.gitignore` 中忽略它；
- 外层仓库实际跟踪 33 个 `quinn-boring` 源码/manifest/license/test 文件，而非
  mode `160000` gitlink；
- 因 vendoring 形态和一处上游 README 尾随空白发生变化，最终 staged checkpoint
  hash 以提交后的 tree/commit identity 为准，上述 pre-stage dirty hash 仅用于证明
  创建分支前的原始工作区内容。

checkpoint 已完成：

- commit：`7c3a9ca5adb1ef74da0d2eb5fdf4ec6c5b2e640c`；
- tree：`e951bffaf201ae7583349d86471b0d024b2d0fa5`；
- subject：`wip: checkpoint boringssl unification candidate`；
- 提交规模：104 files changed，8981 insertions，513 deletions；
- 提交后源码工作区干净；该 commit 仅是本地恢复点，不代表 WP1-WP11、正确性或性能
  gate 已通过。
