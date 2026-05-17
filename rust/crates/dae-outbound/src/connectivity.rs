use std::collections::HashMap;

use crate::types::{IpVersion, L4Proto, NetworkType};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OutboundConnectivityKey {
    pub outbound: u8,
    pub l4proto: L4Proto,
    pub ipversion: IpVersion,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConnectivityMap {
    values: HashMap<OutboundConnectivityKey, u32>,
}

impl ConnectivityMap {
    pub fn record(
        &mut self,
        outbound: u8,
        network_type: NetworkType,
        alive: bool,
        is_init: bool,
        dryrun: bool,
    ) {
        if dryrun && !is_init {
            return;
        }
        let key = OutboundConnectivityKey {
            outbound,
            l4proto: network_type.l4proto,
            ipversion: network_type.ipversion,
        };
        self.values.insert(key, u32::from(alive));
    }

    pub fn get(&self, key: OutboundConnectivityKey) -> Option<u32> {
        self.values.get(&key).copied()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}
