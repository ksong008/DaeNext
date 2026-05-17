use std::collections::{BTreeMap, VecDeque};

pub const UDP_TASK_QUEUE_LENGTH: usize = 128;
pub const UDP_TASK_POOL_MAX_QUEUES: usize = 2048;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpTaskPoolModel {
    queues: BTreeMap<String, VecDeque<u64>>,
    dropped: u64,
    queue_length: usize,
    max_queues: usize,
}

impl Default for UdpTaskPoolModel {
    fn default() -> Self {
        Self {
            queues: BTreeMap::new(),
            dropped: 0,
            queue_length: UDP_TASK_QUEUE_LENGTH,
            max_queues: UDP_TASK_POOL_MAX_QUEUES,
        }
    }
}

impl UdpTaskPoolModel {
    pub fn emit_task(&mut self, key: impl Into<String>, task_id: u64) -> bool {
        let key = key.into();
        if !self.queues.contains_key(&key) && self.queues.len() >= self.max_queues {
            self.dropped += 1;
            return false;
        }
        let queue = self.queues.entry(key).or_default();
        if queue.len() >= self.queue_length {
            self.dropped += 1;
            return false;
        }
        queue.push_back(task_id);
        true
    }

    pub fn drain_key(&mut self, key: &str) -> Vec<u64> {
        self.queues
            .remove(key)
            .map(|queue| queue.into_iter().collect())
            .unwrap_or_default()
    }

    pub fn queue_count(&self) -> usize {
        self.queues.len()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}
