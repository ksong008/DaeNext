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
    latencies_ms: Vec<Option<i64>>,
    latency_offsets_ms: Vec<i64>,
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
        Self {
            network_type,
            policy,
            latency_state_allocated,
            latency_offset_allocated,
            alive: vec![set_alive; dialers.len()],
            latencies_ms: vec![None; dialers.len()],
            latency_offsets_ms,
            min_index,
            min_latency_ms: i64::MAX / 4,
            tolerance_ms,
        }
    }

    pub fn notify_latency_change(&mut self, dialers: &[Dialer], index: usize, alive: bool) {
        if index >= self.alive.len() {
            return;
        }
        self.alive[index] = alive;

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
            if alive && self.policy.needs_latency_state() && self.min_index.is_none() {
                self.min_index = Some(index);
            }
            if !alive && self.min_index == Some(index) {
                self.min_index = None;
                self.recalc_min();
            }
            return;
        };
        self.latencies_ms[index] = Some(raw_latency);
        let sorting_latency = raw_latency + self.latency_offset(index);
        match self.min_index {
            None if alive => {
                self.min_index = Some(index);
                self.min_latency_ms = sorting_latency;
            }
            Some(_) if alive && sorting_latency <= self.min_latency_ms - self.tolerance_ms => {
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
                }
            }
            _ => {}
        }
    }

    pub fn get_rand(&mut self) -> Option<usize> {
        let alive_count = self.alive_count();
        if alive_count == 0 {
            return None;
        }
        let mut selected_alive = fastrand::usize(..alive_count);
        for (index, alive) in self.alive.iter().enumerate() {
            if !*alive {
                continue;
            }
            if selected_alive == 0 {
                return Some(index);
            }
            selected_alive -= 1;
        }
        None
    }

    pub fn get_min_latency(&self) -> Option<(usize, i64)> {
        self.min_index.map(|index| (index, self.min_latency_ms))
    }

    pub fn set_alive(&mut self, index: usize, alive: bool) {
        if index < self.alive.len() {
            self.alive[index] = alive;
            if !alive && self.min_index == Some(index) {
                self.min_index = None;
                self.recalc_min();
            }
        }
    }

    pub fn alive_count(&self) -> usize {
        self.alive.iter().filter(|alive| **alive).count()
    }

    pub fn alive_indexes(&self) -> Vec<usize> {
        self.alive
            .iter()
            .enumerate()
            .filter_map(|(index, alive)| (*alive).then_some(index))
            .collect()
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

    fn recalc_min(&mut self) {
        self.min_index = None;
        self.min_latency_ms = i64::MAX / 4;
        for (index, maybe_latency) in self.latencies_ms.iter().enumerate() {
            if !self.alive[index] {
                continue;
            }
            let Some(latency) = maybe_latency else {
                continue;
            };
            let sorting_latency = *latency + self.latency_offset(index);
            if sorting_latency < self.min_latency_ms {
                self.min_index = Some(index);
                self.min_latency_ms = sorting_latency;
            }
        }
    }
}
