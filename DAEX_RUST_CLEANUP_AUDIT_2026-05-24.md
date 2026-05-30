# DAEX Rust 清理审计 2026-05-24

本文件只保留本地，不提交。

## 1. 本轮目标

用户确认可以开始清理代码，但当前目标不是把仓库删成纯 Rust 目录，而是先建立清理审计清单，后续按清单逐批处理。

本轮只做审计和计划记录：

- 不删除源码。
- 不移动模块。
- 不改变 `daex` 默认运行链路。
- 不新增阶段编号。
- 不运行验证命令；本轮只写本地计划/审计文件，符合主计划“只更新本地计划书不单独验证”的规则。

## 2. 当前基线

- 仓库：`/root/project/dae`
- 分支：`daex`
- HEAD：`7b31d981f526476ac0a3acecf200b966db144fd9`
- 提交：`7b31d981 daemon: start resident production runtime`
- 工作区：`git status --short --branch` 输出 `## daex`

已确认的 daex 产品链路：

| 组件 | 分支 | 路径 |
| --- | --- | --- |
| dae | `daex` | `/root/project/dae` |
| daed | `daed2-daex-align` | `/root/project/daed-daex-align/daed` |
| dae-wing | `daewing2-daex-align` | `/root/project/daed-daex-align/daed/wing` |
| outbound | `outbound-daex-align` | `/root/project/outbound-daex-align` |
| quic-go | `quic-go-rust` | `/root/project/quic-go` |

## 3. 修改前参考范围

按主计划硬性规定，清理前参考：

- `DAEX_RUST_REBUILD_PLAN_2026-05-16.md`
- `DAENEW_RUST_REBUILD_MEMO_2026-05-16.md`

提取出的约束：

- `outbound native protocol rewrite` 已经纳入 Rust 化范围，但 daed2.0、dae-wing、outbound、quic-go 仍是当前产品链路的一部分，不能为了“只保留 Rust”提前删除对接边界。
- Rust 重构必须保持 `daenew` 行为 parity；Go golden fixture、rebuild golden、协议样例、benchmark 记录仍是回归防线。
- 重要功能必须保留 Go/Rust benchmark 或 latency 观察依据；不能先删 benchmark 再补记录。
- eBPF、tproxy、netns、DNS、reload/runtime、resident service、product-chain recertification 是已验证的切换路径，相关 admission evidence 和 runtime gate 不能盲删。
- 清理步骤必须按功能块处理，不以行数为唯一边界。

## 4. 现状盘点

命令观察：

- `git ls-files rust | wc -l`：`1214`
- `git ls-files 'rust/**/*.rs' | wc -l`：`1193`
- `find rust/crates/dae-cli/src -maxdepth 1 -type f -name 'runtime_stage*.rs' | wc -l`：`126`
- `find rust/crates/dae-cli/src -mindepth 1 -maxdepth 1 -type d -name 'runtime_stage*' | wc -l`：`55`
- `find rust/crates/dae-product/src -maxdepth 1 -type f -name 'stage*.rs' | wc -l`：`158`
- `find rust/crates -path '*/examples/*.rs' -type f | wc -l`：`24`
- `du -sh rust/target`：`47G`

结构结论：

- `rust/target` 是 `.gitignore` 忽略的本机构建产物，不属于源码清理；可按需要用 `cargo clean` 释放空间，但会增加后续构建时间。
- 主要源码膨胀点是 `dae-cli` 的 `runtime_stageNN` gate/runner 文件，以及 `dae-product` 的 stage contract 文件。
- `dae-cli/src/lib.rs` 和 `dae-cli/src/runtime_runner.rs` 仍显式引用大量 `runtime_stageNN` 模块；这些文件不是 dead code，直接删除会破坏 CLI admission surface。
- `dae-product/src/lib.rs` 仍显式导出大量 stage contract；这些 contract 仍是 product-chain/admission 记录的一部分，不能先删。

## 5. KEEP / DROP / REVIEW 分类

### 5.1 必须保留：当前正式链路

KEEP：

- `rust/crates/dae-daemon/src/default_run.rs`
- `rust/crates/dae-daemon/src/runner.rs`
- `rust/crates/dae-daemon/src/production_runtime_owner.rs`
- `rust/crates/dae-daemon/src/production_runtime_owner/*`
- `rust/crates/dae-daemon/src/product_chain_recertification.rs`
- `rust/crates/dae-daemon/src/matched_default_benchmark.rs`
- `rust/crates/dae-daemon/src/production_dataplane_harness.rs`
- `rust/crates/dae-cli/src/runtime_runner.rs`
- `rust/crates/dae-cli/src/runner.rs`
- `rust/crates/dae-cli/src/runtime_host_preflight.rs`
- `rust/crates/dae-cli/src/runtime_live_plan.rs`
- `rust/crates/dae-product/src/product_chain_admission.rs`
- `rust/crates/dae-product/src/true_daemon_admission.rs`
- `rust/crates/dae-product/src/daemon_default.rs`
- `rust/crates/dae-product/src/daemon_live_evidence.rs`
- `rust/crates/dae-product/src/integration.rs`

理由：

- 这些文件对应 resident 默认 daemon、runtime ownership、product-chain recertification、matched benchmark、daed2.0 链路准入和本地/远程切换记录。
- 当前切换准备依赖这些结构化报告，不属于旧阶段残留。

### 5.2 必须保留：协议和 outbound 数据面

KEEP：

- `rust/crates/dae-outbound/src/**`
- `rust/crates/dae-cli/src/outbound_runner/**`
- `rust/crates/dae-cli/src/runtime_stage55_outbound_gate.rs` 到 `runtime_stage146_shared_transport_outbound_recertification_gate.rs`
- `rust/crates/dae-product/src/stage55_*` 到 `stage146_*`
- `component/outbound/*_rebuild_golden_test.go`
- `component/outbound/*`

理由：

- 这些文件覆盖 SOCKS5、HTTP、Shadowsocks、SS2022、SIP003、SSR、Trojan/Trojan-Go、VLESS、VMess、AnyTLS、Hysteria2、TUIC、Juicity、shared transport 等协议准入。
- Go 侧 `component/outbound` 仍是 daenew 行为对照和 rebuild golden 来源。
- 后续可以按协议 feature 合并命名，但不能在没有迁移 fixture/benchmark 前删除。

### 5.3 必须保留：Go parity 和 rebuild golden

KEEP：

- `rebuild_golden_test.go`
- `rebuild_golden_stage8_test.go`
- `cmd/*rebuild_golden_test.go`
- `control/rebuild_golden_test.go`
- `engine/rebuild_golden_test.go`
- `trace/rebuild_golden_test.go`
- `component/outbound/*_rebuild_golden_test.go`
- `testdata/rebuild-golden/**`

理由：

- 这些内容是 Go `daenew` 行为和 Rust 重构行为对齐的证据来源。
- Rust 100% 还原完成前，不能把 Go golden 当作“非 Rust 内容”删掉。

### 5.4 必须保留：BPF / datapath / DNS / runtime active path

KEEP：

- `control/*`
- `engine/*rust_optin*`
- `engine/runtime.go`
- `engine/service.go`
- `rust/crates/dae-control/**`
- `rust/crates/dae-datapath/**`
- `rust/crates/dae-dns/**`
- `rust/crates/dae-ebpf-support/**`
- `rust/crates/dae-engine/**`
- `rust/crates/dae-netutil/**`

理由：

- 当前 verified path 涉及 BPF object、listen socket map、tproxy TCP/UDP、DNS tproxy、reload/runtime parity、resident service cleanup。
- Go 与 Rust 双侧文件目前共同组成切换验证链，不能提前只留 Rust。

### 5.5 可清理但不属于源码：本机构建产物

DROP-LOCAL：

- `rust/target/`

状态：

- 已被 `.gitignore` 忽略。
- 当前体积约 `47G`。

建议：

- 如果需要释放磁盘，可执行 `cd /root/project/dae/rust && cargo clean`。
- 不建议把这一步当作代码清理提交；它只是本机缓存清理。

### 5.6 REVIEW：历史 stage gate 和产品 contract

REVIEW：

- `rust/crates/dae-cli/src/runtime_stage23*` 到 `runtime_stage54*`
- `rust/crates/dae-cli/src/runtime_stage147*` 到 `runtime_stage183*`
- `rust/crates/dae-product/src/stage23*` 到 `stage54*`
- `rust/crates/dae-product/src/stage147*` 到 `stage183*`

理由：

- 这些文件中有一部分已经被后续 stage 关闭或取代，但仍被 `lib.rs` / `runtime_runner.rs` / product tests 引用。
- 直接删会破坏 CLI 子命令、product contract 或 golden fixture。

后续处理方式：

- 先生成 stage 到功能块的映射。
- 把仍有价值的 gate 合并为功能命名模块，例如 `daemon_admission`、`benchmark_admission`、`product_chain_switch`、`runtime_reload_parity`。
- 只删除已经被功能模块吸收且 fixture/benchmark 迁移完成的旧 stage 文件。

### 5.7 REVIEW：benchmark examples

REVIEW：

- `rust/crates/*/examples/stage*_bench.rs`

理由：

- 主计划要求重要功能记录 benchmark 对比数据；这些 examples 仍可能是复现实验数据的入口。
- 可以改名或合并为 feature-oriented benchmark，但不能在未迁移数据前删除。

建议：

- 第一批只做清单，不删。
- 第二批按功能合并为：
  - config benchmark
  - routing/geodata benchmark
  - DNS benchmark
  - control/datapath benchmark
  - outbound protocol benchmark
  - daemon matched benchmark

### 5.8 REVIEW：旧本地 memo

REVIEW-LOCAL：

- `DAERUST_AUDIT_LOCAL.md`
- `DAERUST_AUDIT_LOCAL_2026-05-14.md`
- `DAENEW_DNS_AUDIT_MEMO_2026-05-15.md`
- `PM_MEMO.md`
- `DAENEW_RUST_REBUILD_MEMO_2026-05-16.md`
- `DAEX_RUST_REBUILD_PLAN_2026-05-16.md`

理由：

- 这些文件已在 `.git/info/exclude` 中，本地保留，不影响提交。
- `DAEX_RUST_REBUILD_PLAN_2026-05-16.md` 和 `DAENEW_RUST_REBUILD_MEMO_2026-05-16.md` 仍是当前执行约束来源，不能删除。

## 6. 后续清理准入

每个源码删除或合并批次必须满足：

1. 修改前列出候选文件、功能归属、引用关系和替代模块。
2. `rg` 确认生产路径、CLI runner、product contract、fixture、Makefile、Cargo target 没有遗漏引用。
3. 如果删除 stage gate，必须先把有效断言迁移到 feature-oriented 模块。
4. 如果删除 benchmark example，必须先迁移 benchmark 入口或记录为何不再需要。
5. 如果删除 Go parity/golden 文件，必须证明对应 Rust 行为和 daenew 行为已经有等价 fixture 覆盖。
6. 每批源码修改后再运行对应验证；仅更新本地计划/审计文件时不单独验证。

## 7. 建议批次

### 批次 1：本地产物清理

目标：

- 只清理 `rust/target`。

风险：

- 不影响源码。
- 会导致下次 Rust 构建重新编译。

建议命令：

```bash
cd /root/project/dae/rust
cargo clean
```

### 批次 2：stage gate 到功能块映射

目标：

- 不删文件。
- 生成 `runtime_stageNN` / `stageNN` 到功能块的映射表。

功能块建议：

- daemon default / resident runtime
- product-chain recertification
- matched benchmark
- active TCP/UDP/DNS datapath
- outbound protocol dataplane
- shared transport / TLS / QUIC / H3
- VLESS / VMess residual advanced features
- Trojan-Go advanced features
- Juicity / Hysteria2 / TUIC true dataplane

### 批次 3：合并只承载历史阻断项的 stage

目标：

- 只处理已经被后续成功 gate 明确关闭的旧 blocker gate。
- 先迁移断言，再删除旧 stage 文件。

高风险区：

- `stage147` 到 `stage183` 涉及 benchmark 和默认 daemon admission 的历史收敛，必须逐项确认。

### 批次 4：协议 gate 重命名/合并

目标：

- 把 `stage55` 到 `stage146` 的协议 gate 逐步改为按协议 feature 命名。

边界：

- 不删除协议覆盖。
- 不降低 protocol matrix。
- 不破坏 daed2.0/outbound/quic-go 链路说明。

### 批次 5：测试物理隔离复查

目标：

- 继续按功能块拆测试，不以 800 行为界限。
- 优先处理 `dae-daemon/src/tests.rs`、`dae-daemon/src/product_chain_recertification.rs` 等厚文件。

边界：

- 只按 feature 拆分。
- 不做无意义小文件化。

## 8. 本轮结论

可以清理，但当前清理边界必须是：

```text
保留 daex 当前 Rust 重构正式运行链路
保留 daed2.0 / dae-wing / outbound / quic-go 必要对接链路
保留 Go parity / golden / benchmark 证据
优先清理本地产物和已被功能模块吸收的历史 stage 残留
```

本轮未执行源码删除，下一步建议先做“批次 2：stage gate 到功能块映射”，再决定第一批可安全删除的旧 stage 文件。
