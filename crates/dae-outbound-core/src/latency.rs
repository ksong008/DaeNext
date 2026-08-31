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
            self.sum = self.sum.saturating_add(latency_ms);
            return;
        }
        self.sum = self.sum.saturating_sub(self.values[self.head]);
        self.values[self.head] = latency_ms;
        self.head = (self.head + 1) % self.values.len();
        self.sum = self.sum.saturating_add(latency_ms);
    }

    pub fn last(&self) -> Option<i64> {
        if self.len == 0 {
            return None;
        }
        let index = (self.head + self.len - 1) % self.values.len();
        Some(self.values[index])
    }

    pub fn avg(&self) -> Option<i64> {
        if self.len == 0 {
            return None;
        }
        Some(self.sum / self.len as i64)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_average_is_none_without_dividing_by_zero() {
        let latencies = LatenciesN::new(10);

        assert_eq!(latencies.avg(), None);
    }

    #[test]
    fn average_uses_recorded_samples_only() {
        let mut latencies = LatenciesN::new(3);
        latencies.append(10);
        latencies.append(20);

        assert_eq!(latencies.avg(), Some(15));
    }

    #[test]
    fn average_respects_ring_capacity() {
        let mut latencies = LatenciesN::new(2);
        latencies.append(10);
        latencies.append(30);
        latencies.append(50);

        assert_eq!(latencies.avg(), Some(40));
        assert_eq!(latencies.last(), Some(50));
    }

    #[test]
    fn extreme_samples_do_not_overflow_the_sum() {
        let mut latencies = LatenciesN::new(2);
        latencies.append(i64::MAX);
        latencies.append(i64::MAX);
        assert_eq!(latencies.avg(), Some(i64::MAX / 2));

        latencies.append(i64::MIN);
        assert_eq!(latencies.avg(), Some(i64::MIN / 2));
    }
}
