use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectivityKey {
    pub outbound: u8,
    pub l4proto: u8,
    pub ipversion: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectivityEvent {
    pub key: ConnectivityKey,
    pub alive: bool,
    pub is_init: bool,
    pub dryrun: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConnectivityMap {
    values: HashMap<ConnectivityKey, u32>,
}

impl ConnectivityMap {
    pub fn record(&mut self, event: ConnectivityEvent) -> bool {
        if event.dryrun && !event.is_init {
            return false;
        }
        self.values.insert(event.key, u32::from(event.alive));
        true
    }

    pub fn get(&self, key: ConnectivityKey) -> Option<u32> {
        self.values.get(&key).copied()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}
