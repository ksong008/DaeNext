# Rust Native Golden Fixtures

本目录保存 Rust-native 实现使用的 golden fixture。

目标：

- 固化当前 Rust-native 兼容行为。
- 让实现读取同一批输入和期望输出。
- 避免按概念重写后偏离现有兼容行为。

执行规则：

- 默认测试只能校验 fixture，不能自动重写 fixture。
- 只有显式设置 `DAE_UPDATE_REBUILD_GOLDEN=1` 时才允许更新 fixture。
- fixture 输出必须稳定排序。
- 修复历史 bug 不能静默改 fixture；需要标记兼容性差异或新增 migration fixture。
- 重要功能后续需要补充 Rust-native benchmark 数据。

当前首批范围：

- `abi/consts/reserved_indices.json`：reserved outbound/DNS index、reload state、tproxy 常量。
- `abi/consts/dial_mode_policy.json`：dial mode 和 group selection policy 字符串。
- `abi/magic_network/mark_mptcp.json`：`common.MagicNetwork` mark/mptcp 透传 ABI。
- `config/fuzzy/basic.json`：`common.FuzzyDecode` 基础兼容输入。

后续会继续补充：

- config parser/schema/marshal/patch/default/outline。
- routing matcher 函数矩阵。
- DNS cache/request/response。
- outbound group/filter/selection/health。
- eBPF map struct layout。
