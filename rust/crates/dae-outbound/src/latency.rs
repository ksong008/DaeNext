#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LatenciesN {
    values: Vec<i64>,
    head: usize,
    len: usize,
    sum: i64,
}

impl LatenciesN {
    pub fn new(n: usize) -> Self {
        let n = n.max(1);
        Self {
            values: vec![0; n],
            head: 0,
            len: 0,
            sum: 0,
        }
    }

    pub fn append(&mut self, latency_ms: i64) {
        if self.len < self.values.len() {
            let index = (self.head + self.len) % self.values.len();
            self.values[index] = latency_ms;
            self.len += 1;
            self.sum += latency_ms;
            return;
        }
        self.sum -= self.values[self.head];
        self.values[self.head] = latency_ms;
        self.head = (self.head + 1) % self.values.len();
        self.sum += latency_ms;
    }

    pub fn last(&self) -> Option<i64> {
        if self.len == 0 {
            return None;
        }
        let index = (self.head + self.len - 1) % self.values.len();
        Some(self.values[index])
    }

    pub fn avg(&self) -> Option<i64> {
        (self.len > 0).then_some(self.sum / self.len as i64)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}
