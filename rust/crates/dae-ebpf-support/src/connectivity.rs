use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use crate::{open_map_fd, update_map_elem_bytes};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectivityWritePlan {
    pub key: ConnectivityKey,
    pub value: u32,
    pub written: bool,
}

pub fn connectivity_write_plan(event: ConnectivityEvent) -> ConnectivityWritePlan {
    ConnectivityWritePlan {
        key: event.key,
        value: u32::from(event.alive),
        written: !(event.dryrun && !event.is_init),
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
}

impl ConnectivityMapFdCache {
    pub fn update_by_id(
        &mut self,
        map_id: u32,
        event: ConnectivityEvent,
    ) -> io::Result<ConnectivityWritePlan> {
        let plan = connectivity_write_plan(event);
        if !plan.written {
            return Ok(plan);
        }

        if !self.maps.contains_key(&map_id) {
            self.maps.insert(map_id, open_map_fd(map_id)?);
        }
        let fd = self
            .maps
            .get(&map_id)
            .expect("connectivity map fd cache inserted map id");
        let key = [plan.key.outbound, plan.key.l4proto, plan.key.ipversion];
        let value = plan.value.to_ne_bytes();
        if let Err(err) = update_map_elem_bytes(fd.as_raw_fd(), &key, &value) {
            self.maps.remove(&map_id);
            return Err(err);
        }
        Ok(plan)
    }

    pub fn len(&self) -> usize {
        self.maps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.maps.is_empty()
    }
}
