use std::collections::BTreeSet;

use crate::annotation::Annotation;
use crate::dialer::Dialer;
use crate::policy::SelectionPolicy;
use crate::types::NetworkType;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliveDialerSet {
    pub network_type: NetworkType,
    pub policy: SelectionPolicy,
    pub latency_state_allocated: bool,
    pub latency_offset_allocated: bool,
    alive: Vec<bool>,
    alive_indices: Vec<usize>,
    alive_positions: Vec<Option<usize>>,
    latencies_ms: Vec<Option<i64>>,
    latency_offsets_ms: Vec<i64>,
    latency_order: BTreeSet<(i64, usize)>,
    min_index: Option<usize>,
    min_latency_ms: i64,
    tolerance_ms: i64,
}

impl AliveDialerSet {
    pub fn new(
        network_type: NetworkType,
        policy: SelectionPolicy,
        dialers: &[Dialer],
        annotations: &[Annotation],
        tolerance_ms: i64,
        set_alive: bool,
    ) -> Self {
        let latency_state_allocated = policy.needs_latency_state();
        let latency_offsets_ms: Vec<i64> = annotations
            .iter()
            .map(|annotation| annotation.add_latency_ms)
            .collect();
        let latency_offset_allocated =
            latency_state_allocated && latency_offsets_ms.iter().any(|offset| *offset != 0);
        let min_index = if set_alive && policy.needs_latency_state() && !dialers.is_empty() {
            Some(0)
        } else {
            None
        };
        let alive_indices = if set_alive {
            (0..dialers.len()).collect()
        } else {
            Vec::new()
        };
        let alive_positions = if set_alive {
            (0..dialers.len()).map(Some).collect()
        } else {
            vec![None; dialers.len()]
        };
        Self {
            network_type,
            policy,
            latency_state_allocated,
            latency_offset_allocated,
            alive: vec![set_alive; dialers.len()],
            alive_indices,
            alive_positions,
            latencies_ms: vec![None; dialers.len()],
            latency_offsets_ms,
            latency_order: BTreeSet::new(),
            min_index,
            min_latency_ms: i64::MAX / 4,
            tolerance_ms,
        }
    }

    pub fn notify_latency_change(&mut self, dialers: &[Dialer], index: usize, alive: bool) {
        if index >= self.alive.len() {
            return;
        }
        self.remove_latency_entry(index);
        self.update_alive_index(index, alive);

        let raw_latency = match self.policy {
            SelectionPolicy::MinLastLatency => dialers[index]
                .collection(self.network_type)
                .and_then(|collection| collection.latencies10.last()),
            SelectionPolicy::MinAverage10 => dialers[index]
                .collection(self.network_type)
                .and_then(|collection| collection.latencies10.avg()),
            SelectionPolicy::MinMovingAverage => dialers[index]
                .collection(self.network_type)
                .map(|collection| collection.moving_average_ms)
                .filter(|latency| *latency > 0),
            _ => None,
        };

        let Some(raw_latency) = raw_latency else {
            // 无新延迟样本（如 ring 清空 / moving average 归零）：先清除本 index 的
            // 陈旧延迟，防止上一次检查的延迟重入 latency_order 参与 min 排序；
            // 置 None 后 insert_latency_entry 为 no-op。
            self.latencies_ms[index] = None;
            self.insert_latency_entry(index);
            if self.min_index == Some(index) {
                // The current minimum lost its latency sample: drop it and
                // reselect from the remaining entries, so a stale latency
                // cannot keep masquerading as the minimum.
                self.min_index = None;
                self.recalc_min();
            }
            // 候选保证：min 策略必须始终有一个存活候选。当前节点存活时优先
            // 自己；当前节点死亡（fallback 死亡）时从其余存活节点中选——否则
            // 多个"存活但无延迟样本"节点中一个死亡后，recalc_min 只看有延迟
            // 集合，会再次丢失其余可用节点（NoAliveDialer 回退）。
            self.ensure_min_candidate(alive.then_some(index));
            return;
        };
        self.latencies_ms[index] = Some(raw_latency);
        let sorting_latency = raw_latency.saturating_add(self.latency_offset(index));
        self.insert_latency_entry(index);
        match self.min_index {
            None if alive => {
                self.min_index = Some(index);
                self.min_latency_ms = sorting_latency;
            }
            Some(_)
                if alive
                    && sorting_latency <= self.min_latency_ms.saturating_sub(self.tolerance_ms) =>
            {
                self.min_index = Some(index);
                self.min_latency_ms = sorting_latency;
            }
            Some(current) if current == index => {
                let worsened = !alive || sorting_latency > self.min_latency_ms;
                self.min_latency_ms = sorting_latency;
                if worsened {
                    if !alive {
                        self.min_index = None;
                    }
                    self.recalc_min();
                    if !alive {
                        // 当前 min（有历史延迟）死亡后可能只剩无样本存活节点：
                        // recalc 只看有延迟集合，会再次丢失候选；补候选保证。
                        self.ensure_min_candidate(None);
                    }
                }
            }
            _ => {}
        }
    }

    pub fn get_rand(&self) -> Option<usize> {
        (!self.alive_indices.is_empty())
            .then(|| self.alive_indices[fastrand::usize(..self.alive_indices.len())])
    }

    pub fn get_min_latency(&self) -> Option<(usize, i64)> {
        self.min_index.map(|index| (index, self.min_latency_ms))
    }

    pub fn set_alive(&mut self, index: usize, alive: bool) {
        if index < self.alive.len() {
            self.remove_latency_entry(index);
            self.update_alive_index(index, alive);
            self.insert_latency_entry(index);
            if !alive && self.min_index == Some(index) {
                self.min_index = None;
                self.recalc_min();
            }
            // 死亡清候选 / 复活后都可能缺 min 候选：统一补一次候选保证
            // （有延迟样本时 recalc 选出，无样本时从存活节点兜底）。
            self.ensure_min_candidate(alive.then_some(index));
        }
    }

    /// Min 策略的候选保证：当 `min_index` 无候选且策略需要延迟状态时，
    /// 优先从带延迟样本的集合重算选出；否则从存活节点兜底一个
    /// （`prefer` 优先，其次任意存活节点）。没有存活节点时保持无候选
    /// （`NoAliveDialer` 是正确结果）。`min_latency_ms` 在兜底时不更新，
    /// 真实延迟到达后由正常的 Some 分支接管。
    fn ensure_min_candidate(&mut self, prefer: Option<usize>) {
        if !self.policy.needs_latency_state() || self.min_index.is_some() {
            return;
        }
        if !self.latency_order.is_empty() {
            self.recalc_min();
            return;
        }
        if let Some(prefer) = prefer.filter(|i| *i < self.alive.len() && self.alive[*i]) {
            self.min_index = Some(prefer);
        } else if let Some(&other) = self.alive_indices.first() {
            self.min_index = Some(other);
        }
    }

    pub fn alive_count(&self) -> usize {
        self.alive_indices.len()
    }

    pub fn alive_indexes(&self) -> Vec<usize> {
        self.alive_indices.clone()
    }

    pub fn latency_offset(&self, index: usize) -> i64 {
        self.latency_offsets_ms.get(index).copied().unwrap_or(0)
    }

    pub fn stored_latency_offset_count(&self) -> usize {
        if !self.latency_offset_allocated {
            return 0;
        }
        self.latency_offsets_ms
            .iter()
            .filter(|offset| **offset != 0)
            .count()
    }

    fn update_alive_index(&mut self, index: usize, alive: bool) {
        if self.alive[index] == alive {
            return;
        }
        self.alive[index] = alive;
        if alive {
            self.alive_positions[index] = Some(self.alive_indices.len());
            self.alive_indices.push(index);
            return;
        }
        let Some(position) = self.alive_positions[index].take() else {
            return;
        };
        self.alive_indices.swap_remove(position);
        if let Some(swapped) = self.alive_indices.get(position).copied() {
            self.alive_positions[swapped] = Some(position);
        }
    }

    fn remove_latency_entry(&mut self, index: usize) {
        if let Some(latency) = self.latencies_ms[index] {
            self.latency_order
                .remove(&(latency.saturating_add(self.latency_offset(index)), index));
        }
    }

    fn insert_latency_entry(&mut self, index: usize) {
        if self.alive[index]
            && let Some(latency) = self.latencies_ms[index]
        {
            self.latency_order
                .insert((latency.saturating_add(self.latency_offset(index)), index));
        }
    }

    fn recalc_min(&mut self) {
        if let Some(&(latency, index)) = self.latency_order.first() {
            self.min_index = Some(index);
            self.min_latency_ms = latency;
        } else {
            self.min_index = None;
            self.min_latency_ms = i64::MAX / 4;
        }
    }
}
