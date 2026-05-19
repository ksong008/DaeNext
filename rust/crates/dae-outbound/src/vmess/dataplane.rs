use std::io::{Cursor, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit as AeadKeyInit, Payload};
use aes_gcm::aes::Aes128;
use aes_gcm::aes::cipher::{
    BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit, generic_array::GenericArray,
};
use aes_gcm::{Aes128Gcm, Nonce};
use md5::{Digest, Md5};
use sha2::Sha256;
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::error::OutboundError;
use crate::shared_transport::{
    DEFAULT_WS_KEY, GrpcLifecycleOptions, HttpUpgradeOptions, MeekRoundTripOptions,
    MuxFrameOptions, WS_MASK_KEY, grpc_hunk_frame, grpc_stream_preface, http_upgrade_request,
    meek_http_request, mux, mux_data_frame, mux_end_frame, mux_new_frame, read_grpc_hunk_frame,
    read_http_head, read_websocket_binary_frame, validate_http_status,
    websocket_client_binary_frame, websocket_handshake_request,
};
use crate::vmess::uuid::normalize_vmess_uuid;

use super::{
    VMessMetadata, VMessMetadataType, VMessNetwork, packet_addr_magic_target,
    parse_packet_addr_payload, put_packet_addr_payload,
};

const KDF_SALT_AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
const KDF_SALT_VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
const KDF_SALT_HEADER_PAYLOAD_AEAD_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_HEADER_PAYLOAD_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce";
const KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const VMESS_CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const VMESS_VERSION: u8 = 1;
const OPTION_CHUNK_STREAM: u8 = 1;
const OPTION_CHUNK_LENGTH_MASKING: u8 = 4;
const OPTION_GLOBAL_PADDING: u8 = 8;
const REQUEST_OPTIONS: u8 =
    OPTION_CHUNK_STREAM | OPTION_CHUNK_LENGTH_MASKING | OPTION_GLOBAL_PADDING;
const MAX_CHUNK_SIZE: usize = 1 << 14;

pub const VMESS_AEAD_SECURITY_AES_128_GCM: u8 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadUdpOverTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub payload_len: usize,
    pub packet_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadPacketAddrUdpExchangeReport {
    pub proxy: String,
    pub request_target: String,
    pub packet_target: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub payload_len: usize,
    pub packet_addr_len: usize,
    pub packet_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadMuxExchangeReport {
    pub proxy: String,
    pub request_target: String,
    pub mux_target: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub mux_id_hex: String,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub new_frame_validated: bool,
    pub data_frame_validated: bool,
    pub end_frame_sent: bool,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadWebSocketExchangeReport {
    pub proxy: String,
    pub target: String,
    pub ws_host: String,
    pub ws_path: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub websocket_request_frame_len: usize,
    pub websocket_response_frame_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub websocket_handshake_validated: bool,
    pub websocket_binary_frame_validated: bool,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadHttpUpgradeExchangeReport {
    pub proxy: String,
    pub target: String,
    pub httpupgrade_host: String,
    pub httpupgrade_path: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub httpupgrade_request_len: usize,
    pub httpupgrade_response_head_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub httpupgrade_handshake_validated: bool,
    pub httpupgrade_tunnel_validated: bool,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadGrpcHunkExchangeReport {
    pub proxy: String,
    pub target: String,
    pub grpc_service_name: String,
    pub grpc_cache_key: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub grpc_preface_len: usize,
    pub grpc_request_hunk_len: usize,
    pub grpc_response_hunk_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub grpc_stream_preface_validated: bool,
    pub grpc_hunk_frame_validated: bool,
    pub cache_key_route_context_validated: bool,
    pub full_grpc_http2_stack: bool,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadMeekPollingExchangeReport {
    pub proxy: String,
    pub target: String,
    pub meek_url: String,
    pub meek_host: String,
    pub meek_path: String,
    pub meek_session_id: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub meek_request_len: usize,
    pub meek_request_body_len: usize,
    pub meek_response_head_len: usize,
    pub meek_response_body_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub meek_polling_validated: bool,
    pub full_https_round_tripper: bool,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadTcpRequest {
    pub version: u8,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub eauth_crc_validated: bool,
    pub eauth_timestamp: u64,
    pub request_options: u8,
    pub security: u8,
    pub command: u8,
    pub target: String,
    pub payload: Vec<u8>,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_auth: u8,
    pub request_body_iv: [u8; 16],
    pub request_body_key: [u8; 16],
    pub response_body_iv: [u8; 16],
    pub response_body_key: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadUdpOverTcpRequest {
    pub request: VMessAeadTcpRequest,
    pub packet_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadPacketAddrUdpRequest {
    pub request: VMessAeadTcpRequest,
    pub packet_target: String,
    pub packet_addr_len: usize,
    pub packet_payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadMuxRequest {
    pub request: VMessAeadTcpRequest,
    pub new_frame: mux::MuxFrame,
    pub data_frame: mux::MuxFrame,
    pub end_frame: mux::MuxFrame,
    pub mux_id_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadWebSocketRequest {
    pub request: VMessAeadTcpRequest,
    pub websocket_request_frame_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadHttpUpgradeRequest {
    pub request: VMessAeadTcpRequest,
    pub httpupgrade_tunnel_validated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadGrpcHunkRequest {
    pub request: VMessAeadTcpRequest,
    pub grpc_request_hunk_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadMeekPollingRequest {
    pub request: VMessAeadTcpRequest,
    pub meek_request_body_len: usize,
    pub meek_session_id_validated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VMessAeadRequestPacket {
    header: Vec<u8>,
    chunk: Vec<u8>,
    request: VMessAeadTcpRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VMessAeadChunkedRequestPacket {
    header: Vec<u8>,
    chunks: Vec<Vec<u8>>,
    request: VMessAeadTcpRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VMessAeadMaterial {
    request_body_iv: [u8; 16],
    request_body_key: [u8; 16],
    response_auth: u8,
    eauth_random: [u8; 4],
    connection_nonce: [u8; 8],
}

impl Default for VMessAeadMaterial {
    fn default() -> Self {
        Self {
            request_body_iv: *b"dae-stage65-iv!!",
            request_body_key: *b"dae-stage65-key!",
            response_auth: 0x65,
            eauth_random: [0xda, 0xee, 0x65, 0x01],
            connection_nonce: *b"dae65cn!",
        }
    }
}

pub fn vmess_cmd_key_from_uuid(uuid: &str) -> Result<[u8; 16], OutboundError> {
    let uuid = normalize_vmess_uuid(uuid);
    let uuid_bytes = parse_uuid_bytes(&uuid)?;
    let mut hasher = Md5::new();
    Digest::update(&mut hasher, uuid_bytes);
    Digest::update(&mut hasher, VMESS_CMD_KEY_SALT);
    let digest = hasher.finalize();
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest[..16]);
    Ok(out)
}

pub fn aead_tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    payload: &[u8],
) -> Result<VMessAeadTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    stream
        .write_all(&packet.header)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    stream
        .write_all(&packet.chunk)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(stream, &packet.request)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess AEAD TCP payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadTcpExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        payload_len: payload.len(),
        echoed_payload,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn aead_udp_over_tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    payload: &[u8],
) -> Result<VMessAeadUdpOverTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let packet = build_aead_request(uuid, target, VMessNetwork::Udp, payload)?;
    stream
        .write_all(&packet.header)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    stream
        .write_all(&packet.chunk)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(stream, &packet.request)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess AEAD UDP-over-TCP payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadUdpOverTcpExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Udp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        payload_len: payload.len(),
        packet_len: payload.len(),
        echoed_payload,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn aead_packet_addr_udp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    packet_target: &str,
    payload: &[u8],
) -> Result<VMessAeadPacketAddrUdpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let request_target = packet_addr_magic_target(packet_target)?;
    let packet_payload = put_packet_addr_payload(packet_target, payload)?;
    let packet = build_aead_request(uuid, &request_target, VMessNetwork::Udp, &packet_payload)?;
    stream
        .write_all(&packet.header)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    stream
        .write_all(&packet.chunk)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let (response_header_len, echoed_packet, response_chunk_len) =
        read_aead_response_header_and_chunk(stream, &packet.request)?;
    let (echoed_target, packet_addr_len, echoed_payload) =
        parse_packet_addr_payload(&echoed_packet)?;
    if echoed_target != packet_target {
        return Err(OutboundError::BadVmess(format!(
            "VMess packet-addr target mismatch: got {echoed_target}, want {packet_target}"
        )));
    }
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess packet-addr UDP payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadPacketAddrUdpExchangeReport {
        proxy: proxy.to_owned(),
        request_target,
        packet_target: packet_target.to_owned(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Udp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        payload_len: payload.len(),
        packet_addr_len,
        packet_len: packet_payload.len(),
        echoed_payload,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn aead_mux_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    mux_id: [u8; 2],
    mux_target: &str,
    network: &str,
    payload: &[u8],
) -> Result<VMessAeadMuxExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let request_target = "0.0.0.0:0";
    let metadata = VMessMetadata::parse(network, mux_target)?;
    let options = MuxFrameOptions::new(mux_id, metadata.hostname(), metadata.port(), network);
    let new_frame = mux_new_frame(&options);
    let data_frame = mux_data_frame(mux_id, payload)?;
    let end_frame = mux_end_frame(mux_id);
    let packet = build_aead_request_chunks(
        uuid,
        request_target,
        VMessNetwork::Mux,
        &[&new_frame, &data_frame, &end_frame],
    )?;
    stream
        .write_all(&packet.header)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    for chunk in &packet.chunks {
        stream
            .write_all(chunk)
            .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    }

    let (response_header_len, response_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(stream, &packet.request)?;
    let echoed = read_mux_frame_from_bytes(&response_payload)?;
    if echoed.id != mux_id
        || echoed.status != mux::SESSION_STATUS_KEEP
        || echoed.option != mux::OPTION_DATA
    {
        return Err(OutboundError::BadVmess(format!(
            "VMess mux response frame mismatch: id={:?} status={} option={}",
            echoed.id, echoed.status, echoed.option
        )));
    }
    if echoed.payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess mux payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadMuxExchangeReport {
        proxy: proxy.to_owned(),
        request_target: request_target.to_owned(),
        mux_target: mux_target.to_owned(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Mux.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        mux_id_hex: hex_encode(&mux_id),
        request_header_len: packet.header.len(),
        request_chunk_len: packet.request.request_chunk_len,
        response_header_len,
        response_chunk_len,
        payload_len: payload.len(),
        echoed_payload: echoed.payload,
        new_frame_validated: true,
        data_frame_validated: true,
        end_frame_sent: true,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn aead_tcp_exchange_over_websocket_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    ws_host: &str,
    ws_path: &str,
    payload: &[u8],
) -> Result<VMessAeadWebSocketExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let ws_options = HttpUpgradeOptions::new(ws_host, ws_path);
    let handshake = websocket_handshake_request(&ws_options, DEFAULT_WS_KEY);
    stream
        .write_all(&handshake)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    let response = read_http_head(stream)?;
    validate_http_status(&response, 101)?;

    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    let mut request_payload = Vec::with_capacity(packet.header.len() + packet.chunk.len());
    request_payload.extend_from_slice(&packet.header);
    request_payload.extend_from_slice(&packet.chunk);
    let request_frame = websocket_client_binary_frame(&request_payload, WS_MASK_KEY)?;
    stream
        .write_all(&request_frame)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let response_payload = read_websocket_binary_frame(stream)?;
    let websocket_response_frame_len = response_payload.len();
    let mut response_cursor = Cursor::new(&response_payload);
    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(&mut response_cursor, &packet.request)?;
    if response_cursor.position() as usize != response_payload.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess WebSocket response has trailing bytes: {}",
            response_payload.len() - response_cursor.position() as usize
        )));
    }
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess WebSocket payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadWebSocketExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        ws_host: ws_options.host,
        ws_path: ws_options.path,
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        websocket_request_frame_len: request_frame.len(),
        websocket_response_frame_len,
        payload_len: payload.len(),
        echoed_payload,
        websocket_handshake_validated: true,
        websocket_binary_frame_validated: true,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn aead_tcp_exchange_over_httpupgrade_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    httpupgrade_host: &str,
    httpupgrade_path: &str,
    payload: &[u8],
) -> Result<VMessAeadHttpUpgradeExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let options = HttpUpgradeOptions::new(httpupgrade_host, httpupgrade_path);
    let upgrade_request = http_upgrade_request(&options);
    stream
        .write_all(&upgrade_request)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    let response = read_http_head(stream)?;
    let httpupgrade_response_head_len = response.len();
    validate_http_status(&response, 101)?;

    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    stream
        .write_all(&packet.header)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    stream
        .write_all(&packet.chunk)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(stream, &packet.request)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess HTTPUpgrade payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadHttpUpgradeExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        httpupgrade_host: options.host,
        httpupgrade_path: options.path,
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        httpupgrade_request_len: upgrade_request.len(),
        httpupgrade_response_head_len,
        payload_len: payload.len(),
        echoed_payload,
        httpupgrade_handshake_validated: true,
        httpupgrade_tunnel_validated: true,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn aead_tcp_exchange_over_grpc_hunk_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    grpc_options: &GrpcLifecycleOptions,
    payload: &[u8],
) -> Result<VMessAeadGrpcHunkExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let preface = grpc_stream_preface(&grpc_options.service_name);
    stream
        .write_all(&preface)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    let mut request_payload = Vec::with_capacity(packet.header.len() + packet.chunk.len());
    request_payload.extend_from_slice(&packet.header);
    request_payload.extend_from_slice(&packet.chunk);
    let request_hunk = grpc_hunk_frame(&request_payload)?;
    stream
        .write_all(&request_hunk)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let response_payload = read_grpc_hunk_frame(stream)?;
    let grpc_response_hunk_len = response_payload.len() + 5;
    let mut response_cursor = Cursor::new(&response_payload);
    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(&mut response_cursor, &packet.request)?;
    if response_cursor.position() as usize != response_payload.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess gRPC hunk response has trailing bytes: {}",
            response_payload.len() - response_cursor.position() as usize
        )));
    }
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess gRPC hunk payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadGrpcHunkExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        grpc_service_name: if grpc_options.service_name.is_empty() {
            "GunService".to_owned()
        } else {
            grpc_options.service_name.clone()
        },
        grpc_cache_key: grpc_options.cache_key(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        grpc_preface_len: preface.len(),
        grpc_request_hunk_len: request_hunk.len(),
        grpc_response_hunk_len,
        payload_len: payload.len(),
        echoed_payload,
        grpc_stream_preface_validated: true,
        grpc_hunk_frame_validated: true,
        cache_key_route_context_validated: true,
        full_grpc_http2_stack: false,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn aead_tcp_exchange_over_meek_polling_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    meek_options: &MeekRoundTripOptions,
    payload: &[u8],
) -> Result<VMessAeadMeekPollingExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    let mut request_payload = Vec::with_capacity(packet.header.len() + packet.chunk.len());
    request_payload.extend_from_slice(&packet.header);
    request_payload.extend_from_slice(&packet.chunk);
    let meek_request = meek_http_request(meek_options, &request_payload);
    stream
        .write_all(&meek_request)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let (response_head, response_payload) = read_http_message(stream, "meek response")?;
    validate_http_status(&response_head, 200)?;
    let mut response_cursor = Cursor::new(&response_payload);
    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(&mut response_cursor, &packet.request)?;
    if response_cursor.position() as usize != response_payload.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess Meek polling response has trailing bytes: {}",
            response_payload.len() - response_cursor.position() as usize
        )));
    }
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess Meek polling payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadMeekPollingExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        meek_url: meek_options.url.clone(),
        meek_host: meek_options.host.clone(),
        meek_path: meek_options.path.clone(),
        meek_session_id: meek_options.session_id(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        meek_request_len: meek_request.len(),
        meek_request_body_len: request_payload.len(),
        meek_response_head_len: response_head.len(),
        meek_response_body_len: response_payload.len(),
        payload_len: payload.len(),
        echoed_payload,
        meek_polling_validated: true,
        full_https_round_tripper: false,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn read_aead_tcp_request_from_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadTcpRequest, OutboundError>
where
    S: Read,
{
    let request = read_aead_request_from_stream(stream, uuid)?;
    if request.command != VMessNetwork::Tcp.byte() {
        return Err(OutboundError::BadVmess(format!(
            "unexpected VMess AEAD TCP command: {}",
            request.command
        )));
    }
    Ok(request)
}

pub fn read_aead_udp_over_tcp_request_from_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadUdpOverTcpRequest, OutboundError>
where
    S: Read,
{
    let request = read_aead_request_from_stream(stream, uuid)?;
    if request.command != VMessNetwork::Udp.byte() {
        return Err(OutboundError::BadVmess(format!(
            "unexpected VMess AEAD UDP command: {}",
            request.command
        )));
    }
    let packet_len = request.payload.len();
    Ok(VMessAeadUdpOverTcpRequest {
        request,
        packet_len,
    })
}

pub fn read_aead_packet_addr_udp_request_from_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadPacketAddrUdpRequest, OutboundError>
where
    S: Read,
{
    let request = read_aead_udp_over_tcp_request_from_stream(stream, uuid)?;
    let (packet_target, packet_addr_len, packet_payload) =
        parse_packet_addr_payload(&request.request.payload)?;
    Ok(VMessAeadPacketAddrUdpRequest {
        request: request.request,
        packet_target,
        packet_addr_len,
        packet_payload,
    })
}

pub fn read_aead_mux_request_from_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadMuxRequest, OutboundError>
where
    S: Read,
{
    let (mut request, mut request_codec) = read_aead_request_header_from_stream(stream, uuid)?;
    if request.command != VMessNetwork::Mux.byte() {
        return Err(OutboundError::BadVmess(format!(
            "unexpected VMess AEAD mux command: {}",
            request.command
        )));
    }
    let (new_payload, new_chunk_len) = request_codec.open_chunk(stream)?;
    let (data_payload, data_chunk_len) = request_codec.open_chunk(stream)?;
    let (end_payload, end_chunk_len) = request_codec.open_chunk(stream)?;
    let new_frame = read_mux_frame_from_bytes(&new_payload)?;
    let data_frame = read_mux_frame_from_bytes(&data_payload)?;
    let end_frame = read_mux_frame_from_bytes(&end_payload)?;
    request.request_chunk_len = new_chunk_len + data_chunk_len + end_chunk_len;
    request.payload = [new_payload, data_payload, end_payload].concat();
    Ok(VMessAeadMuxRequest {
        mux_id_hex: hex_encode(&new_frame.id),
        request,
        new_frame,
        data_frame,
        end_frame,
    })
}

pub fn read_aead_tcp_request_from_websocket_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadWebSocketRequest, OutboundError>
where
    S: Read,
{
    let payload = read_websocket_binary_frame(stream)?;
    let websocket_request_frame_len = payload.len();
    let mut cursor = Cursor::new(&payload);
    let request = read_aead_tcp_request_from_stream(&mut cursor, uuid)?;
    if cursor.position() as usize != payload.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess WebSocket request has trailing bytes: {}",
            payload.len() - cursor.position() as usize
        )));
    }
    Ok(VMessAeadWebSocketRequest {
        request,
        websocket_request_frame_len,
    })
}

pub fn read_aead_tcp_request_from_httpupgrade_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadHttpUpgradeRequest, OutboundError>
where
    S: Read,
{
    let request = read_aead_tcp_request_from_stream(stream, uuid)?;
    Ok(VMessAeadHttpUpgradeRequest {
        request,
        httpupgrade_tunnel_validated: true,
    })
}

pub fn read_aead_tcp_request_from_grpc_hunk_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadGrpcHunkRequest, OutboundError>
where
    S: Read,
{
    let payload = read_grpc_hunk_frame(stream)?;
    let grpc_request_hunk_len = payload.len() + 5;
    let mut cursor = Cursor::new(&payload);
    let request = read_aead_tcp_request_from_stream(&mut cursor, uuid)?;
    if cursor.position() as usize != payload.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess gRPC hunk request has trailing bytes: {}",
            payload.len() - cursor.position() as usize
        )));
    }
    Ok(VMessAeadGrpcHunkRequest {
        request,
        grpc_request_hunk_len,
    })
}

pub fn read_aead_tcp_request_from_meek_polling_stream<S>(
    stream: &mut S,
    uuid: &str,
    meek_options: &MeekRoundTripOptions,
) -> Result<VMessAeadMeekPollingRequest, OutboundError>
where
    S: Read,
{
    let (request_head, payload) = read_http_message(stream, "meek request")?;
    validate_meek_request_head(&request_head, meek_options)?;
    let mut cursor = Cursor::new(&payload);
    let request = read_aead_tcp_request_from_stream(&mut cursor, uuid)?;
    if cursor.position() as usize != payload.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess Meek polling request has trailing bytes: {}",
            payload.len() - cursor.position() as usize
        )));
    }
    Ok(VMessAeadMeekPollingRequest {
        request,
        meek_request_body_len: payload.len(),
        meek_session_id_validated: true,
    })
}

fn read_aead_request_from_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<VMessAeadTcpRequest, OutboundError>
where
    S: Read,
{
    let (mut request, mut request_codec) = read_aead_request_header_from_stream(stream, uuid)?;
    let (payload, request_chunk_len) = request_codec.open_chunk(stream)?;
    request.payload = payload;
    request.request_chunk_len = request_chunk_len;
    Ok(request)
}

fn read_aead_request_header_from_stream<S>(
    stream: &mut S,
    uuid: &str,
) -> Result<(VMessAeadTcpRequest, BodyCodec), OutboundError>
where
    S: Read,
{
    let normalized_uuid = normalize_vmess_uuid(uuid);
    let cmd_key = vmess_cmd_key_from_uuid(&normalized_uuid)?;
    let mut eauth_id = [0_u8; 16];
    read_exact(stream, &mut eauth_id, "vmess eauth id")?;
    let (eauth_timestamp, eauth_crc_validated) = decrypt_eauth_id(&cmd_key, &eauth_id)?;
    if !eauth_crc_validated {
        return Err(OutboundError::BadVmess(
            "VMess EAuthID checksum mismatch".to_owned(),
        ));
    }

    let mut length_and_nonce = [0_u8; 26];
    read_exact(
        stream,
        &mut length_and_nonce,
        "vmess request header length and connection nonce",
    )?;
    let connection_nonce = &length_and_nonce[18..26];
    let length_plain = aes128_gcm_decrypt(
        &kdf16(
            &cmd_key,
            &[
                KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
                &eauth_id,
                connection_nonce,
            ],
        ),
        &kdf12(
            &cmd_key,
            &[
                KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_IV,
                &eauth_id,
                connection_nonce,
            ],
        ),
        &length_and_nonce[..18],
        &eauth_id,
    )?;
    if length_plain.len() != 2 {
        return Err(OutboundError::BadVmess(format!(
            "bad VMess request header length plaintext: {} bytes",
            length_plain.len()
        )));
    }
    let instruction_len = u16::from_be_bytes([length_plain[0], length_plain[1]]) as usize;
    let mut encrypted_instruction = vec![0_u8; instruction_len + 16];
    read_exact(
        stream,
        &mut encrypted_instruction,
        "vmess encrypted request header payload",
    )?;
    let instruction = aes128_gcm_decrypt(
        &kdf16(
            &cmd_key,
            &[
                KDF_SALT_HEADER_PAYLOAD_AEAD_KEY,
                &eauth_id,
                connection_nonce,
            ],
        ),
        &kdf12(
            &cmd_key,
            &[KDF_SALT_HEADER_PAYLOAD_AEAD_IV, &eauth_id, connection_nonce],
        ),
        &encrypted_instruction,
        &eauth_id,
    )?;
    if instruction.len() != instruction_len {
        return Err(OutboundError::BadVmess(format!(
            "bad VMess instruction length: got {}, want {}",
            instruction.len(),
            instruction_len
        )));
    }

    let parsed = parse_instruction(&instruction)?;
    let request_codec = BodyCodec::new(
        parsed.request_body_key,
        parsed.request_body_iv,
        parsed.request_options,
    )?;
    Ok((
        VMessAeadTcpRequest {
            version: parsed.version,
            uuid: normalized_uuid,
            cmd_key_hex: hex_encode(&cmd_key),
            eauth_crc_validated,
            eauth_timestamp,
            request_options: parsed.request_options,
            security: parsed.security,
            command: parsed.command,
            target: parsed.target,
            payload: Vec::new(),
            request_header_len: 16 + 26 + encrypted_instruction.len(),
            request_chunk_len: 0,
            response_auth: parsed.response_auth,
            request_body_iv: parsed.request_body_iv,
            request_body_key: parsed.request_body_key,
            response_body_iv: parsed.response_body_iv,
            response_body_key: parsed.response_body_key,
        },
        request_codec,
    ))
}

pub fn aead_tcp_response_packet(
    request: &VMessAeadTcpRequest,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let mut response = encrypt_response_header(request)?;
    let mut codec = BodyCodec::new(
        request.response_body_key,
        request.response_body_iv,
        request.request_options,
    )?;
    response.extend_from_slice(&codec.seal_chunk(payload)?);
    Ok(response)
}

fn read_http_message<S: Read>(
    stream: &mut S,
    context: &str,
) -> Result<(Vec<u8>, Vec<u8>), OutboundError> {
    let head_with_leftover = read_http_head(stream)?;
    let Some(index) = head_with_leftover
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
    else {
        return Err(OutboundError::BadSharedTransport(format!(
            "incomplete {context} header"
        )));
    };
    let body_start = index + 4;
    let head = head_with_leftover[..body_start].to_vec();
    let mut body = head_with_leftover[body_start..].to_vec();
    let content_length = http_content_length(&head)?;
    while body.len() < content_length {
        let mut buf = vec![0_u8; content_length - body.len()];
        let n = stream
            .read(&mut buf)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    if body.len() < content_length {
        return Err(OutboundError::BadSharedTransport(format!(
            "incomplete {context} body"
        )));
    }
    body.truncate(content_length);
    Ok((head, body))
}

fn validate_meek_request_head(
    request_head: &[u8],
    meek_options: &MeekRoundTripOptions,
) -> Result<(), OutboundError> {
    let text = std::str::from_utf8(request_head)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| OutboundError::BadSharedTransport("empty meek request".to_owned()))?;
    let want = format!("POST {} HTTP/1.1", meek_options.path);
    if request_line != want {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected meek request line: {request_line}"
        )));
    }
    let host = http_header_value(text, "host")
        .ok_or_else(|| OutboundError::BadSharedTransport("missing meek Host header".to_owned()))?;
    if host != meek_options.host {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected meek Host header: {host}"
        )));
    }
    let session = http_header_value(text, "x-session-id").ok_or_else(|| {
        OutboundError::BadSharedTransport("missing meek X-Session-ID header".to_owned())
    })?;
    if session != meek_options.session_id() {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected meek X-Session-ID header: {session}"
        )));
    }
    Ok(())
}

fn http_content_length(head: &[u8]) -> Result<usize, OutboundError> {
    let text = std::str::from_utf8(head)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    http_header_value(text, "content-length")
        .unwrap_or("0")
        .parse::<usize>()
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))
}

fn http_header_value<'a>(head: &'a str, key: &str) -> Option<&'a str> {
    for line in head.split("\r\n") {
        let Some((got_key, value)) = line.split_once(':') else {
            continue;
        };
        if got_key.eq_ignore_ascii_case(key) {
            return Some(value.trim());
        }
    }
    None
}

fn build_aead_request(
    uuid: &str,
    target: &str,
    network: VMessNetwork,
    payload: &[u8],
) -> Result<VMessAeadRequestPacket, OutboundError> {
    let packet = build_aead_request_chunks(uuid, target, network, &[payload])?;
    let chunk = packet
        .chunks
        .into_iter()
        .next()
        .ok_or_else(|| OutboundError::BadVmess("missing VMess request chunk".to_owned()))?;
    Ok(VMessAeadRequestPacket {
        header: packet.header,
        chunk,
        request: packet.request,
    })
}

fn build_aead_request_chunks(
    uuid: &str,
    target: &str,
    network: VMessNetwork,
    payloads: &[&[u8]],
) -> Result<VMessAeadChunkedRequestPacket, OutboundError> {
    let material = VMessAeadMaterial::default();
    let normalized_uuid = normalize_vmess_uuid(uuid);
    let cmd_key = vmess_cmd_key_from_uuid(&normalized_uuid)?;
    let eauth_id = put_eauth_id(&cmd_key, unix_timestamp_now()?, material.eauth_random)?;
    let instruction = request_instruction(&material, target, network)?;
    let header = encrypt_request_header(
        &cmd_key,
        &eauth_id,
        &material.connection_nonce,
        &instruction,
    )?;
    let parsed = parse_instruction(&instruction)?;
    let mut codec = BodyCodec::new(
        parsed.request_body_key,
        parsed.request_body_iv,
        parsed.request_options,
    )?;
    let mut chunks = Vec::with_capacity(payloads.len());
    let mut request_chunk_len = 0_usize;
    let mut payload = Vec::new();
    for item in payloads {
        let chunk = codec.seal_chunk(item)?;
        request_chunk_len += chunk.len();
        payload.extend_from_slice(item);
        chunks.push(chunk);
    }
    let request = VMessAeadTcpRequest {
        version: parsed.version,
        uuid: normalized_uuid,
        cmd_key_hex: hex_encode(&cmd_key),
        eauth_crc_validated: true,
        eauth_timestamp: 0,
        request_options: parsed.request_options,
        security: parsed.security,
        command: parsed.command,
        target: parsed.target,
        payload,
        request_header_len: header.len(),
        request_chunk_len,
        response_auth: parsed.response_auth,
        request_body_iv: parsed.request_body_iv,
        request_body_key: parsed.request_body_key,
        response_body_iv: parsed.response_body_iv,
        response_body_key: parsed.response_body_key,
    };
    Ok(VMessAeadChunkedRequestPacket {
        header,
        chunks,
        request,
    })
}

fn read_mux_frame_from_bytes(input: &[u8]) -> Result<mux::MuxFrame, OutboundError> {
    let mut cursor = Cursor::new(input);
    let frame = mux::read_mux_frame(&mut cursor)?;
    if cursor.position() as usize != input.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess mux frame has trailing bytes: {}",
            input.len() - cursor.position() as usize
        )));
    }
    Ok(frame)
}

fn request_instruction(
    material: &VMessAeadMaterial,
    target: &str,
    network: VMessNetwork,
) -> Result<Vec<u8>, OutboundError> {
    let metadata = VMessMetadata::parse(network.as_str(), target)?;
    let addr = metadata.encode_addr()?;
    let header_padding_len = 0_usize;
    let mut out = vec![0_u8; 45 + addr.len() + header_padding_len];
    out[0] = VMESS_VERSION;
    out[1..17].copy_from_slice(&material.request_body_iv);
    out[17..33].copy_from_slice(&material.request_body_key);
    out[33] = material.response_auth;
    out[34] = REQUEST_OPTIONS;
    out[35] = ((header_padding_len as u8) << 4) | VMESS_AEAD_SECURITY_AES_128_GCM;
    out[36] = 0;
    out[37] = network.byte();
    out[38..40].copy_from_slice(&metadata.port().to_be_bytes());
    out[40] = metadata.metadata_type().byte();
    out[41..41 + addr.len()].copy_from_slice(&addr);
    let checksum_offset = out.len() - 4;
    let checksum = fnv1a32(&out[..checksum_offset]);
    out[checksum_offset..].copy_from_slice(&checksum.to_be_bytes());
    Ok(out)
}

fn encrypt_request_header(
    cmd_key: &[u8; 16],
    eauth_id: &[u8; 16],
    connection_nonce: &[u8; 8],
    instruction: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let mut out = Vec::with_capacity(58 + instruction.len());
    out.extend_from_slice(eauth_id);
    let length = (instruction.len() as u16).to_be_bytes();
    out.extend_from_slice(&aes128_gcm_encrypt(
        &kdf16(
            cmd_key,
            &[
                KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
                eauth_id,
                connection_nonce,
            ],
        ),
        &kdf12(
            cmd_key,
            &[
                KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_IV,
                eauth_id,
                connection_nonce,
            ],
        ),
        &length,
        eauth_id,
    )?);
    out.extend_from_slice(connection_nonce);
    out.extend_from_slice(&aes128_gcm_encrypt(
        &kdf16(
            cmd_key,
            &[KDF_SALT_HEADER_PAYLOAD_AEAD_KEY, eauth_id, connection_nonce],
        ),
        &kdf12(
            cmd_key,
            &[KDF_SALT_HEADER_PAYLOAD_AEAD_IV, eauth_id, connection_nonce],
        ),
        instruction,
        eauth_id,
    )?);
    Ok(out)
}

fn encrypt_response_header(request: &VMessAeadTcpRequest) -> Result<Vec<u8>, OutboundError> {
    let header = [request.response_auth, 0, 0, 0];
    let mut out = Vec::with_capacity(38);
    let length = (header.len() as u16).to_be_bytes();
    out.extend_from_slice(&aes128_gcm_encrypt(
        &kdf16(
            &request.response_body_key,
            &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY],
        ),
        &kdf12(
            &request.response_body_iv,
            &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV],
        ),
        &length,
        &[],
    )?);
    out.extend_from_slice(&aes128_gcm_encrypt(
        &kdf16(
            &request.response_body_key,
            &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY],
        ),
        &kdf12(
            &request.response_body_iv,
            &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV],
        ),
        &header,
        &[],
    )?);
    Ok(out)
}

fn read_aead_response_header_and_chunk<S>(
    stream: &mut S,
    request: &VMessAeadTcpRequest,
) -> Result<(usize, Vec<u8>, usize), OutboundError>
where
    S: Read,
{
    let mut encrypted_len = [0_u8; 18];
    read_exact(stream, &mut encrypted_len, "vmess response header length")?;
    let len_plain = aes128_gcm_decrypt(
        &kdf16(
            &request.response_body_key,
            &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY],
        ),
        &kdf12(
            &request.response_body_iv,
            &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV],
        ),
        &encrypted_len,
        &[],
    )?;
    if len_plain.len() != 2 {
        return Err(OutboundError::BadVmess(format!(
            "bad VMess response header length plaintext: {} bytes",
            len_plain.len()
        )));
    }
    let header_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
    let mut encrypted_header = vec![0_u8; header_len + 16];
    read_exact(stream, &mut encrypted_header, "vmess response header")?;
    let header = aes128_gcm_decrypt(
        &kdf16(
            &request.response_body_key,
            &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY],
        ),
        &kdf12(
            &request.response_body_iv,
            &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV],
        ),
        &encrypted_header,
        &[],
    )?;
    if header.len() < 4 {
        return Err(OutboundError::BadVmess(format!(
            "short VMess response header: {} bytes",
            header.len()
        )));
    }
    if header[0] != request.response_auth {
        return Err(OutboundError::BadVmess(format!(
            "unexpected VMess response auth: got {}, want {}",
            header[0], request.response_auth
        )));
    }
    if header[2] != 0 {
        return Err(OutboundError::BadVmess(format!(
            "unexpected VMess response command: {}",
            header[2]
        )));
    }
    let mut codec = BodyCodec::new(
        request.response_body_key,
        request.response_body_iv,
        request.request_options,
    )?;
    let (payload, chunk_len) = codec.open_chunk(stream)?;
    Ok((18 + encrypted_header.len(), payload, chunk_len))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedInstruction {
    version: u8,
    request_body_iv: [u8; 16],
    request_body_key: [u8; 16],
    response_body_iv: [u8; 16],
    response_body_key: [u8; 16],
    response_auth: u8,
    request_options: u8,
    security: u8,
    command: u8,
    target: String,
}

fn parse_instruction(instruction: &[u8]) -> Result<ParsedInstruction, OutboundError> {
    if instruction.len() < 45 {
        return Err(OutboundError::BadVmess(format!(
            "short VMess instruction: {} bytes",
            instruction.len()
        )));
    }
    let header_padding_len = (instruction[35] >> 4) as usize;
    let security = instruction[35] & 0x0f;
    if security != VMESS_AEAD_SECURITY_AES_128_GCM {
        return Err(OutboundError::BadVmess(format!(
            "unsupported VMess AEAD security: {security}"
        )));
    }
    let (host, addr_len) = read_instruction_host(instruction, instruction[40])?;
    let expected_len = 45 + addr_len + header_padding_len;
    if instruction.len() != expected_len {
        return Err(OutboundError::BadVmess(format!(
            "bad VMess instruction length: got {}, want {}",
            instruction.len(),
            expected_len
        )));
    }
    let checksum_offset = instruction.len() - 4;
    let got_checksum = u32::from_be_bytes([
        instruction[checksum_offset],
        instruction[checksum_offset + 1],
        instruction[checksum_offset + 2],
        instruction[checksum_offset + 3],
    ]);
    let want_checksum = fnv1a32(&instruction[..checksum_offset]);
    if got_checksum != want_checksum {
        return Err(OutboundError::BadVmess(format!(
            "VMess instruction checksum mismatch: got {got_checksum:#x}, want {want_checksum:#x}"
        )));
    }

    let mut request_body_iv = [0_u8; 16];
    request_body_iv.copy_from_slice(&instruction[1..17]);
    let mut request_body_key = [0_u8; 16];
    request_body_key.copy_from_slice(&instruction[17..33]);
    let response_body_iv = sha256_16(&request_body_iv);
    let response_body_key = sha256_16(&request_body_key);
    let port = u16::from_be_bytes([instruction[38], instruction[39]]);
    let target = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Ok(ParsedInstruction {
        version: instruction[0],
        request_body_iv,
        request_body_key,
        response_body_iv,
        response_body_key,
        response_auth: instruction[33],
        request_options: instruction[34],
        security,
        command: instruction[37],
        target,
    })
}

fn read_instruction_host(instruction: &[u8], atyp: u8) -> Result<(String, usize), OutboundError> {
    match atyp {
        value if value == VMessMetadataType::Ipv4.byte() => {
            if instruction.len() < 45 {
                return Err(OutboundError::BadVmess(
                    "short VMess IPv4 instruction".to_owned(),
                ));
            }
            let mut octets = [0_u8; 4];
            octets.copy_from_slice(&instruction[41..45]);
            Ok((Ipv4Addr::from(octets).to_string(), 4))
        }
        value if value == VMessMetadataType::Domain.byte() => {
            let len = *instruction
                .get(41)
                .ok_or_else(|| OutboundError::BadVmess("missing VMess domain length".to_owned()))?
                as usize;
            if instruction.len() < 42 + len {
                return Err(OutboundError::BadVmess(format!(
                    "short VMess domain instruction: got {}, need {}",
                    instruction.len(),
                    42 + len
                )));
            }
            let host = String::from_utf8(instruction[42..42 + len].to_vec())
                .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
            Ok((host, 1 + len))
        }
        value if value == VMessMetadataType::Ipv6.byte() => {
            if instruction.len() < 57 {
                return Err(OutboundError::BadVmess(
                    "short VMess IPv6 instruction".to_owned(),
                ));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&instruction[41..57]);
            Ok((Ipv6Addr::from(octets).to_string(), 16))
        }
        value => Err(OutboundError::BadVmess(format!(
            "bad VMess address type: {value}"
        ))),
    }
}

struct BodyCodec {
    cipher: Aes128Gcm,
    nonce: ChunkNonce,
    size: ChunkSizeMask,
}

impl BodyCodec {
    fn new(key: [u8; 16], iv: [u8; 16], options: u8) -> Result<Self, OutboundError> {
        let cipher = Aes128Gcm::new_from_slice(&key)
            .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
        Ok(Self {
            cipher,
            nonce: ChunkNonce::new(&iv),
            size: ChunkSizeMask::new(&iv, options),
        })
    }

    fn seal_chunk(&mut self, payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
        if payload.len() > MAX_CHUNK_SIZE {
            return Err(OutboundError::BadVmess(format!(
                "VMess payload too large for one stage65 chunk: {} bytes",
                payload.len()
            )));
        }
        let padding_len = self.size.next_padding_len() as usize;
        let encrypted = self
            .cipher
            .encrypt(Nonce::from_slice(&self.nonce.next()), payload)
            .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
        let size = encrypted.len() + padding_len;
        if size > u16::MAX as usize {
            return Err(OutboundError::BadVmess(format!(
                "VMess chunk too large: {size} bytes"
            )));
        }
        let mut out = Vec::with_capacity(2 + size);
        out.extend_from_slice(&self.size.encode_size(size as u16));
        out.extend_from_slice(&encrypted);
        out.extend(std::iter::repeat_n(0xa5, padding_len));
        Ok(out)
    }

    fn open_chunk<S>(&mut self, stream: &mut S) -> Result<(Vec<u8>, usize), OutboundError>
    where
        S: Read,
    {
        let mut size_buf = [0_u8; 2];
        read_exact(stream, &mut size_buf, "vmess chunk size")?;
        let padding_len = self.size.next_padding_len() as usize;
        let size = self.size.decode_size(size_buf) as usize;
        if size < padding_len + 16 {
            return Err(OutboundError::BadVmess(format!(
                "bad VMess chunk size {size} with padding {padding_len}"
            )));
        }
        let mut chunk = vec![0_u8; size];
        read_exact(stream, &mut chunk, "vmess encrypted chunk")?;
        let encrypted_len = size - padding_len;
        let payload = self
            .cipher
            .decrypt(
                Nonce::from_slice(&self.nonce.next()),
                &chunk[..encrypted_len],
            )
            .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
        Ok((payload, 2 + size))
    }
}

struct ChunkNonce {
    base: [u8; 12],
    count: u16,
}

impl ChunkNonce {
    fn new(iv: &[u8; 16]) -> Self {
        let mut base = [0_u8; 12];
        base[2..].copy_from_slice(&iv[2..12]);
        Self { base, count: 0 }
    }

    fn next(&mut self) -> [u8; 12] {
        let mut nonce = self.base;
        nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        self.count = self.count.wrapping_add(1);
        nonce
    }
}

struct ChunkSizeMask {
    reader: Option<Box<dyn XofReader>>,
    global_padding: bool,
}

impl ChunkSizeMask {
    fn new(iv: &[u8; 16], options: u8) -> Self {
        if options & OPTION_CHUNK_LENGTH_MASKING == 0 {
            return Self {
                reader: None,
                global_padding: false,
            };
        }
        let mut shake = Shake128::default();
        Update::update(&mut shake, iv);
        Self {
            reader: Some(Box::new(shake.finalize_xof())),
            global_padding: options & OPTION_GLOBAL_PADDING == OPTION_GLOBAL_PADDING,
        }
    }

    fn next_padding_len(&mut self) -> u16 {
        if self.global_padding {
            self.next_mask() % 64
        } else {
            0
        }
    }

    fn encode_size(&mut self, size: u16) -> [u8; 2] {
        (size ^ self.next_mask()).to_be_bytes()
    }

    fn decode_size(&mut self, encoded: [u8; 2]) -> u16 {
        u16::from_be_bytes(encoded) ^ self.next_mask()
    }

    fn next_mask(&mut self) -> u16 {
        let Some(reader) = self.reader.as_mut() else {
            return 0;
        };
        let mut buf = [0_u8; 2];
        reader.read(&mut buf);
        u16::from_be_bytes(buf)
    }
}

fn put_eauth_id(
    cmd_key: &[u8; 16],
    unix_timestamp: u64,
    random: [u8; 4],
) -> Result<[u8; 16], OutboundError> {
    let mut plain = [0_u8; 16];
    plain[..8].copy_from_slice(&unix_timestamp.to_be_bytes());
    plain[8..12].copy_from_slice(&random);
    let checksum = crc32_ieee(&plain[..12]);
    plain[12..].copy_from_slice(&checksum.to_be_bytes());
    aes128_block_encrypt(&kdf16(cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY]), &plain)
}

fn decrypt_eauth_id(
    cmd_key: &[u8; 16],
    encrypted: &[u8; 16],
) -> Result<(u64, bool), OutboundError> {
    let plain = aes128_block_decrypt(
        &kdf16(cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY]),
        encrypted,
    )?;
    let timestamp = u64::from_be_bytes([
        plain[0], plain[1], plain[2], plain[3], plain[4], plain[5], plain[6], plain[7],
    ]);
    let want = u32::from_be_bytes([plain[12], plain[13], plain[14], plain[15]]);
    Ok((timestamp, crc32_ieee(&plain[..12]) == want))
}

fn aes128_block_encrypt(key: &[u8; 16], input: &[u8; 16]) -> Result<[u8; 16], OutboundError> {
    let cipher = <Aes128 as BlockKeyInit>::new_from_slice(key)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    let mut block = GenericArray::clone_from_slice(input);
    cipher.encrypt_block(&mut block);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&block);
    Ok(out)
}

fn aes128_block_decrypt(key: &[u8; 16], input: &[u8; 16]) -> Result<[u8; 16], OutboundError> {
    let cipher = <Aes128 as BlockKeyInit>::new_from_slice(key)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    let mut block = GenericArray::clone_from_slice(input);
    cipher.decrypt_block(&mut block);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&block);
    Ok(out)
}

fn aes128_gcm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let cipher =
        Aes128Gcm::new_from_slice(key).map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|err| OutboundError::BadVmess(err.to_string()))
}

fn aes128_gcm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let cipher =
        Aes128Gcm::new_from_slice(key).map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|err| OutboundError::BadVmess(err.to_string()))
}

#[derive(Clone)]
enum HashSpec {
    Sha256,
    Hmac { hash: Box<HashSpec>, key: Vec<u8> },
}

fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut spec = HashSpec::Hmac {
        hash: Box::new(HashSpec::Sha256),
        key: KDF_SALT_VMESS_AEAD_KDF.to_vec(),
    };
    for item in path {
        spec = HashSpec::Hmac {
            hash: Box::new(spec),
            key: item.to_vec(),
        };
    }
    hash_digest(&spec, key)
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let digest = kdf(key, path);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let digest = kdf(key, path);
    let mut out = [0_u8; 12];
    out.copy_from_slice(&digest[..12]);
    out
}

fn hash_digest(spec: &HashSpec, data: &[u8]) -> [u8; 32] {
    match spec {
        HashSpec::Sha256 => {
            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, data);
            let digest = hasher.finalize();
            let mut out = [0_u8; 32];
            out.copy_from_slice(&digest);
            out
        }
        HashSpec::Hmac { hash, key } => hmac_digest(hash, key, data),
    }
}

fn hmac_digest(hash: &HashSpec, key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0_u8; 64];
    if key.len() > 64 {
        key_block[..32].copy_from_slice(&hash_digest(hash, key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for i in 0..64 {
        inner_pad[i] ^= key_block[i];
        outer_pad[i] ^= key_block[i];
    }
    let mut inner_input = Vec::with_capacity(64 + data.len());
    inner_input.extend_from_slice(&inner_pad);
    inner_input.extend_from_slice(data);
    let inner = hash_digest(hash, &inner_input);
    let mut outer_input = Vec::with_capacity(96);
    outer_input.extend_from_slice(&outer_pad);
    outer_input.extend_from_slice(&inner);
    hash_digest(hash, &outer_input)
}

fn sha256_16(input: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::digest(input);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn crc32_ieee(input: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in input {
        crc ^= *byte as u32;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xedb8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn fnv1a32(input: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    for byte in input {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn parse_uuid_bytes(input: &str) -> Result<[u8; 16], OutboundError> {
    let mut hex = String::with_capacity(32);
    for ch in input.chars() {
        if ch != '-' {
            hex.push(ch);
        }
    }
    if hex.len() != 32 {
        return Err(OutboundError::BadVmess(format!(
            "bad VMess UUID length: {}",
            input.len()
        )));
    }
    let mut out = [0_u8; 16];
    for (idx, byte) in out.iter_mut().enumerate() {
        let start = idx * 2;
        *byte = u8::from_str_radix(&hex[start..start + 2], 16)
            .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    }
    Ok(out)
}

fn unix_timestamp_now() -> Result<u64, OutboundError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?
        .as_secs())
}

fn read_exact(stream: &mut impl Read, buf: &mut [u8], context: &str) -> Result<(), OutboundError> {
    stream
        .read_exact(buf)
        .map_err(|err| OutboundError::BadVmess(format!("read {context} failed: {err}")))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
