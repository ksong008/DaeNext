pub mod contract;
pub mod dataplane;
pub mod link;
pub mod metadata;
pub mod uuid;

pub use dataplane::{
    VMESS_AEAD_SECURITY_AES_128_GCM, VMessAeadMuxExchangeReport, VMessAeadMuxRequest,
    VMessAeadPacketAddrUdpExchangeReport, VMessAeadPacketAddrUdpRequest,
    VMessAeadTcpExchangeReport, VMessAeadTcpRequest, VMessAeadUdpOverTcpExchangeReport,
    VMessAeadUdpOverTcpRequest, aead_mux_exchange_over_stream,
    aead_packet_addr_udp_exchange_over_stream, aead_tcp_exchange_over_stream,
    aead_tcp_response_packet, aead_udp_over_tcp_exchange_over_stream,
    read_aead_mux_request_from_stream, read_aead_packet_addr_udp_request_from_stream,
    read_aead_tcp_request_from_stream, read_aead_udp_over_tcp_request_from_stream,
    vmess_cmd_key_from_uuid,
};
pub use link::VMessLink;
pub use metadata::{
    VMESS_PACKET_ADDR_MAGIC_ADDRESS, VMessMetadata, VMessMetadataType, VMessNetwork,
    packet_addr_magic_target, parse_packet_addr_payload, put_packet_addr_payload,
};
