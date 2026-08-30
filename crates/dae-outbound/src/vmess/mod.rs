pub use dae_outbound_core::vmess::{contract, metadata, uuid};
pub mod dataplane {
    pub use dae_outbound_stream::vmess::dataplane::*;
}
#[cfg(test)]
mod test_tls_transports;
#[cfg(test)]
mod test_xhttp_h3;

pub use dae_outbound_core::vmess::VMessBodySecurity;
pub use dae_outbound_core::vmess::metadata::{
    VMESS_PACKET_ADDR_MAGIC_ADDRESS, VMessMetadata, VMessMetadataType, VMessNetwork,
    packet_addr_magic_target, parse_packet_addr_payload, put_packet_addr_payload,
};
pub use dae_outbound_stream::vmess::dataplane::*;
pub use dae_outbound_stream::vmess::link::{VMessLink, VMessSourceFormat};
#[cfg(test)]
pub use test_tls_transports::{
    VMessAeadHttpsHttpUpgradeTlsExchangeReport, VMessAeadWssTlsExchangeReport,
    aead_tcp_exchange_over_https_httpupgrade_tls_stream, aead_tcp_exchange_over_wss_tls_stream,
};
#[cfg(test)]
pub use test_xhttp_h3::{VMessAeadXHttpH3ExchangeReport, aead_tcp_exchange_over_xhttp_h3_loopback};
