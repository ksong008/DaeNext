use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dae_core_types::OutboundIndex;
use serde_json::Value;

use crate::RoutingError;
use crate::domain::{DomainKey, DomainMatcher};
use crate::prefix::IpPrefix;

const L4_TCP: u8 = 1;
const L4_UDP: u8 = 2;
const IP_VERSION_4: u8 = 1;
const IP_VERSION_6: u8 = 2;

mod model;
pub use self::model::*;
mod fixture;
mod match_set;
mod matcher;
use self::fixture::*;
#[cfg(test)]
mod tests;
