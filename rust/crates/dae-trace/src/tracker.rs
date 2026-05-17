use std::collections::HashMap;

pub const MAX_TRACKED_SKBS: usize = 4096;
pub const MAX_EVENTS_PER_SKB: usize = 64;
pub const MAX_SYMBOLS_PER_SKB: usize = 64;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TraceEventRecord {
    pub pc: u64,
    pub skb: u64,
    pub second_param: u64,
    pub mark: u32,
    pub netns: u32,
    pub ifindex: u32,
    pub pid: u32,
    pub payload_len: u16,
}

impl TraceEventRecord {
    pub fn for_skb(skb: u64) -> Self {
        Self {
            skb,
            ..Self::default()
        }
    }

    pub fn with_payload(skb: u64, payload_len: u16) -> Self {
        Self {
            skb,
            payload_len,
            ..Self::default()
        }
    }
}

#[derive(Debug, Default)]
pub struct SkbTraceTracker {
    events: HashMap<u64, Vec<TraceEventRecord>>,
    sym_names: HashMap<u64, Vec<String>>,
    last_seen: HashMap<u64, u64>,
    sequence: u64,
}

impl SkbTraceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, event: TraceEventRecord, sym_name: impl Into<String>) {
        self.sequence += 1;
        append_capped(
            self.events.entry(event.skb).or_default(),
            event,
            MAX_EVENTS_PER_SKB,
        );
        append_capped(
            self.sym_names.entry(event.skb).or_default(),
            sym_name.into(),
            MAX_SYMBOLS_PER_SKB,
        );
        self.last_seen.insert(event.skb, self.sequence);
        if self.events.len() > MAX_TRACKED_SKBS {
            self.evict_oldest();
        }
    }

    pub fn events(&self, skb: u64) -> &[TraceEventRecord] {
        self.events.get(&skb).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn sym_names(&self, skb: u64) -> &[String] {
        self.sym_names.get(&skb).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn delete(&mut self, skb: u64) {
        self.events.remove(&skb);
        self.sym_names.remove(&skb);
        self.last_seen.remove(&skb);
    }

    pub fn tracked_count(&self) -> usize {
        self.events.len()
    }

    pub fn contains_skb(&self, skb: u64) -> bool {
        self.events.contains_key(&skb)
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .last_seen
            .iter()
            .min_by_key(|(_, sequence)| *sequence)
            .map(|(skb, _)| *skb);
        if let Some(skb) = oldest {
            self.delete(skb);
        }
    }
}

fn append_capped<T>(items: &mut Vec<T>, item: T, limit: usize) {
    if limit == 0 {
        return;
    }
    if items.len() < limit {
        items.push(item);
        return;
    }
    items.remove(0);
    items.push(item);
}
