pub mod magic_network;
pub mod route_aware;

pub use magic_network::{
    MAGIC_NETWORK_TYPE, MagicNetwork, MagicNetworkEncoding, MagicNetworkError,
    encode_magic_network, encode_magic_network_with_encoding, magic_network_encoded_len,
    parse_magic_network, write_magic_network_to_slice, write_magic_network_to_vec,
};
pub use route_aware::{RouteAwareTarget, RouteAwareTargetError, route_aware_dial_target};
