use std::collections::HashMap;

use dae_ebpf_support::{ConnectivityEvent, ConnectivityKey};

const KNOWN_L4_COUNT: usize = 3;
const KNOWN_IP_COUNT: usize = 2;
const KNOWN_SLOTS_PER_OUTBOUND: usize = KNOWN_L4_COUNT * KNOWN_IP_COUNT;
const KNOWN_SLOT_COUNT: usize = 256 * KNOWN_SLOTS_PER_OUTBOUND;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectivityStateUpdate {
    pub key: ConnectivityKey,
    pub value: u32,
    pub accepted: bool,
    pub changed: bool,
    pub flush: bool,
    pub len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectivityStateEntry {
    pub key: ConnectivityKey,
    pub value: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OutboundConnectivityOwner {
    map_id: Option<u32>,
    state: OutboundConnectivityState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectivityOwnerUpdate {
    pub map_id: Option<u32>,
    pub state: ConnectivityStateUpdate,
    pub flush: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectivityMapReplay {
    pub map_id: u32,
    pub changed: bool,
    pub entries: Vec<ConnectivityStateEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundConnectivityState {
    known_present: [bool; KNOWN_SLOT_COUNT],
    known_values: [u32; KNOWN_SLOT_COUNT],
    known_len: usize,
    fallback: HashMap<ConnectivityKey, u32>,
}

impl Default for OutboundConnectivityState {
    fn default() -> Self {
        Self {
            known_present: [false; KNOWN_SLOT_COUNT],
            known_values: [0; KNOWN_SLOT_COUNT],
            known_len: 0,
            fallback: HashMap::new(),
        }
    }
}

impl OutboundConnectivityState {
    pub fn preview_update(&self, event: ConnectivityEvent) -> ConnectivityStateUpdate {
        let value = u32::from(event.alive);
        if event.dryrun && !event.is_init {
            return ConnectivityStateUpdate {
                key: event.key,
                value,
                accepted: false,
                changed: false,
                flush: false,
                len: self.len(),
            };
        }

        let (changed, will_insert) = if let Some(slot) = known_slot(event.key) {
            (
                !self.known_present[slot] || self.known_values[slot] != value,
                !self.known_present[slot],
            )
        } else {
            match self.fallback.get(&event.key) {
                Some(previous) => (*previous != value, false),
                None => (true, true),
            }
        };

        ConnectivityStateUpdate {
            key: event.key,
            value,
            accepted: true,
            changed,
            flush: changed,
            len: self.len() + usize::from(will_insert),
        }
    }

    pub fn update(&mut self, event: ConnectivityEvent) -> ConnectivityStateUpdate {
        let update = self.preview_update(event);
        if update.accepted {
            self.apply(event);
        }
        update
    }

    pub fn apply(&mut self, event: ConnectivityEvent) {
        if event.dryrun && !event.is_init {
            return;
        }
        if let Some(slot) = known_slot(event.key) {
            if !self.known_present[slot] {
                self.known_present[slot] = true;
                self.known_len += 1;
            }
            self.known_values[slot] = u32::from(event.alive);
        } else {
            self.fallback.insert(event.key, u32::from(event.alive));
        }
    }

    pub fn get(&self, key: ConnectivityKey) -> Option<u32> {
        if let Some(slot) = known_slot(key) {
            return self.known_present[slot].then_some(self.known_values[slot]);
        }
        self.fallback.get(&key).copied()
    }

    pub fn entries(&self) -> Vec<ConnectivityStateEntry> {
        let mut entries = Vec::with_capacity(self.len());
        for outbound in u8::MIN..=u8::MAX {
            for l4proto in [6, 17, 22] {
                for ipversion in [4, 6] {
                    let key = ConnectivityKey {
                        outbound,
                        l4proto,
                        ipversion,
                    };
                    if let Some(value) = self.get(key) {
                        entries.push(ConnectivityStateEntry { key, value });
                    }
                }
            }
        }

        let mut fallback = self
            .fallback
            .iter()
            .map(|(key, value)| ConnectivityStateEntry {
                key: *key,
                value: *value,
            })
            .collect::<Vec<_>>();
        fallback.sort_by_key(|entry| entry.key);
        entries.extend(fallback);
        entries
    }

    pub fn len(&self) -> usize {
        self.known_len + self.fallback.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl OutboundConnectivityOwner {
    pub fn map_id(&self) -> Option<u32> {
        self.map_id
    }

    pub fn state(&self) -> &OutboundConnectivityState {
        &self.state
    }

    pub fn install_map(&mut self, map_id: u32) -> ConnectivityMapReplay {
        let changed = self.map_id != Some(map_id);
        self.map_id = Some(map_id);
        ConnectivityMapReplay {
            map_id,
            changed,
            entries: if changed {
                self.state.entries()
            } else {
                Vec::new()
            },
        }
    }

    pub fn plan_event(&self, event: ConnectivityEvent) -> ConnectivityOwnerUpdate {
        let state = self.state.preview_update(event);
        ConnectivityOwnerUpdate {
            map_id: self.map_id,
            flush: self.map_id.is_some() && state.flush,
            state,
        }
    }

    pub fn apply_event(&mut self, event: ConnectivityEvent) -> ConnectivityOwnerUpdate {
        let update = self.plan_event(event);
        if update.state.accepted {
            self.state.apply(event);
        }
        update
    }
}

fn known_slot(key: ConnectivityKey) -> Option<usize> {
    let l4 = match key.l4proto {
        6 => 0,
        17 => 1,
        22 => 2,
        _ => return None,
    };
    let ip = match key.ipversion {
        4 => 0,
        6 => 1,
        _ => return None,
    };
    Some(usize::from(key.outbound) * KNOWN_SLOTS_PER_OUTBOUND + l4 * KNOWN_IP_COUNT + ip)
}
