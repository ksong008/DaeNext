use dae_outbound::shared_transport::{
    MasqueQuarterStreamId, decode_http_datagram, encode_http_datagram,
};

use super::*;

mod actor;
mod pool;
mod request;
mod session;
mod tls;

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(in crate::production_runtime_owner::resident_dataplane) use self::tests::{
    ConnectUdpH3TestServer, ConnectUdpH3TestServerConfig,
};

pub(in crate::production_runtime_owner::resident_dataplane) use self::pool::clear_connect_udp_h3_pools;
pub(in crate::production_runtime_owner::resident_dataplane) use self::pool::connect_udp_h3_pool_metrics_snapshot;
pub(in crate::production_runtime_owner::resident_dataplane::udp) use self::session::ConnectUdpH3Session;
