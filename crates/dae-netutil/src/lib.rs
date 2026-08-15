pub mod magic_network;
pub mod route_aware;

pub use magic_network::{
    MAGIC_NETWORK_TYPE, MagicNetwork, MagicNetworkError, encode_magic_network, parse_magic_network,
};
pub use route_aware::{RouteAwareTarget, RouteAwareTargetError, route_aware_dial_target};
