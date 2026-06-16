use std::collections::{HashMap, hash_map::Entry};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use crate::{open_map_fd, update_map_elem_bytes};

const KNOWN_L4_COUNT: usize = 3;
const KNOWN_IP_COUNT: usize = 2;
const KNOWN_SLOTS_PER_OUTBOUND: usize = KNOWN_L4_COUNT * KNOWN_IP_COUNT;
const KNOWN_SLOT_COUNT: usize = 256 * KNOWN_SLOTS_PER_OUTBOUND;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
    known_present: Vec<bool>,
    known_values: Vec<u32>,
    known_len: usize,
    sparse: HashMap<ConnectivityKey, u32>,
}

impl ConnectivityMap {
    pub fn record(&mut self, event: ConnectivityEvent) -> bool {
        let plan = self.preview_update(event);
        if plan.written {
            self.apply(event);
        }
        plan.written
    }

    pub fn preview_update(&self, event: ConnectivityEvent) -> ConnectivityWritePlan {
        let value = u32::from(event.alive);
        if event.dryrun && !event.is_init {
            return ConnectivityWritePlan {
                key: event.key,
                value,
                written: false,
                changed: false,
            };
        }

        let changed = if let Some(slot) = known_slot(event.key) {
            self.known_value(slot) != Some(value)
        } else {
            self.sparse.get(&event.key).copied() != Some(value)
        };

        ConnectivityWritePlan {
            key: event.key,
            value,
            written: changed,
            changed,
        }
    }

    pub fn apply(&mut self, event: ConnectivityEvent) {
        if event.dryrun && !event.is_init {
            return;
        }
        let value = u32::from(event.alive);
        if let Some(slot) = known_slot(event.key) {
            self.ensure_known_capacity();
            if !self.known_present[slot] {
                self.known_present[slot] = true;
                self.known_len += 1;
            }
            self.known_values[slot] = value;
        } else {
            self.sparse.insert(event.key, value);
        }
    }

    pub fn get(&self, key: ConnectivityKey) -> Option<u32> {
        if let Some(slot) = known_slot(key) {
            return self.known_value(slot);
        }
        self.sparse.get(&key).copied()
    }

    pub fn len(&self) -> usize {
        self.known_len + self.sparse.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn known_value(&self, slot: usize) -> Option<u32> {
        self.known_present
            .get(slot)
            .copied()
            .unwrap_or(false)
            .then(|| self.known_values[slot])
    }

    fn ensure_known_capacity(&mut self) {
        if self.known_present.is_empty() {
            self.known_present = vec![false; KNOWN_SLOT_COUNT];
            self.known_values = vec![0; KNOWN_SLOT_COUNT];
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectivityWritePlan {
    pub key: ConnectivityKey,
    pub value: u32,
    pub written: bool,
    pub changed: bool,
}

pub fn connectivity_write_plan(event: ConnectivityEvent) -> ConnectivityWritePlan {
    let written = !(event.dryrun && !event.is_init);
    ConnectivityWritePlan {
        key: event.key,
        value: u32::from(event.alive),
        written,
        changed: written,
    }
}

pub fn update_connectivity_map_by_id(
    map_id: u32,
    event: ConnectivityEvent,
) -> io::Result<ConnectivityWritePlan> {
    let plan = connectivity_write_plan(event);
    if !plan.written {
        return Ok(plan);
    }

    let fd = open_map_fd(map_id)?;
    let key = [plan.key.outbound, plan.key.l4proto, plan.key.ipversion];
    let value = plan.value.to_ne_bytes();
    update_map_elem_bytes(fd.as_raw_fd(), &key, &value)?;
    Ok(plan)
}

#[derive(Debug, Default)]
pub struct ConnectivityMapFdCache {
    maps: HashMap<u32, OwnedFd>,
    states: HashMap<u32, ConnectivityMap>,
}

impl ConnectivityMapFdCache {
    pub fn update_by_id(
        &mut self,
        map_id: u32,
        event: ConnectivityEvent,
    ) -> io::Result<ConnectivityWritePlan> {
        let plan = self.states.get(&map_id).map_or_else(
            || connectivity_write_plan(event),
            |state| state.preview_update(event),
        );
        if !plan.written {
            return Ok(plan);
        }

        let fd = match self.maps.entry(map_id) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(open_map_fd(map_id)?),
        };
        let key = [plan.key.outbound, plan.key.l4proto, plan.key.ipversion];
        let value = plan.value.to_ne_bytes();
        if let Err(err) = update_map_elem_bytes(fd.as_raw_fd(), &key, &value) {
            self.maps.remove(&map_id);
            self.states.remove(&map_id);
            return Err(err);
        }
        self.states.entry(map_id).or_default().apply(event);
        Ok(plan)
    }

    pub fn len(&self) -> usize {
        self.maps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.maps.is_empty()
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
