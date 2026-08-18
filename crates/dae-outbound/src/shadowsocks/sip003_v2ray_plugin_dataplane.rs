use std::io::{Cursor, Read, Write};

use crate::error::OutboundError;
use crate::shared_transport::mux::{
    MuxFrame, MuxFrameOptions, OPTION_DATA, OPTION_NONE, SESSION_STATUS_KEEP, SESSION_STATUS_NEW,
    mux_data_frame, mux_new_frame, read_mux_frame,
};
use crate::shared_transport::{
    DEFAULT_WS_KEY, HttpUpgradeOptions, TlsLoopbackMaterial, TlsUnderlayOptions, WS_MASK_KEY,
    read_http_head, read_websocket_binary_frame, websocket_client_binary_frame,
    websocket_handshake_request, websocket_server_binary_frame,
};

use super::{
    AeadStreamCodec, AeadTcpSalts, ShadowsocksAeadTcpExchangeReport, ShadowsocksMetadata,
    cipher_spec, decode_client_initial, encode_client_initial, encode_server_payload,
    read_encrypted_chunk_from_stream,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sip003V2rayPluginOptions {
    pub tls: TlsUnderlayOptions,
    pub ws_host: String,
    pub ws_path: String,
    pub mux: MuxFrameOptions,
    pub tls_passthrough_udp: bool,
    pub ws_passthrough_udp: bool,
    pub mux_passthrough_udp: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sip003V2rayPluginRequest {
    pub mux_new: MuxFrame,
    pub mux_data: MuxFrame,
    pub target: String,
    pub payload: Vec<u8>,
    pub websocket_payload_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sip003V2rayPluginExchangeReport {
    pub plugin_name: &'static str,
    pub tls_enabled: bool,
    pub websocket_enabled: bool,
    pub mux_enabled: bool,
    pub proxy: String,
    pub tls_server_name: String,
    pub selected_alpn: String,
    pub ws_host: String,
    pub ws_path: String,
    pub mux_id_hex: String,
    pub mux_host: String,
    pub mux_port: u16,
    pub mux_network: String,
    pub tls_passthrough_udp: bool,
    pub ws_passthrough_udp: bool,
    pub mux_passthrough_udp: bool,
    pub websocket_handshake_validated: bool,
    pub websocket_binary_frame_validated: bool,
    pub mux_new_frame_validated: bool,
    pub mux_data_frame_validated: bool,
    pub tls_handshake_validated: bool,
    pub certificate_chain_validated: bool,
    pub server_name_validated: bool,
    pub alpn_validated: bool,
    pub websocket_request_frame_len: usize,
    pub mux_request_payload_len: usize,
    pub mux_response_payload_len: usize,
    pub inner: ShadowsocksAeadTcpExchangeReport,
}

impl Sip003V2rayPluginOptions {
    pub fn new(
        tls_server_name: impl Into<String>,
        alpn_protocol: impl Into<String>,
        ws_host: impl Into<String>,
        ws_path: impl Into<String>,
    ) -> Result<Self, OutboundError> {
        let tls = TlsUnderlayOptions::new(tls_server_name, alpn_protocol)?;
        Ok(Self {
            tls,
            ws_host: ws_host.into(),
            ws_path: normalize_ws_path(&ws_path.into()),
            mux: MuxFrameOptions::new([0, 0], "127.0.0.1", 0, "tcp"),
            tls_passthrough_udp: true,
            ws_passthrough_udp: true,
            mux_passthrough_udp: true,
        })
    }
}

// SIP003 dataplane tests keep plugin and Shadowsocks inputs explicit.
#[allow(clippy::too_many_arguments)]
pub fn v2ray_plugin_tls_ws_mux_shadowsocks_aead_exchange_over_stream<S>(
    stream: S,
    material: &TlsLoopbackMaterial,
    options: &Sip003V2rayPluginOptions,
    proxy: &str,
    cipher: &str,
    password: &str,
    target: &str,
    payload: &[u8],
    salts: AeadTcpSalts<'_>,
) -> Result<Sip003V2rayPluginExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let spec = cipher_spec(cipher)?;
    let mut tls = material
        .connect(stream, &options.tls.server_name)
        .map_err(|err| OutboundError::BadShadowsocks(format!("v2ray-plugin tls connect: {err}")))?;

    let ws_options = HttpUpgradeOptions::new(&options.ws_host, &options.ws_path);
    let handshake = websocket_handshake_request(&ws_options, DEFAULT_WS_KEY)?;
    tls.write_all(&handshake)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    tls.flush()
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let response = read_http_head(&mut tls)?;
    crate::shared_transport::validate_websocket_handshake_response(
        &response,
        crate::shared_transport::WS_ACCEPT_SAMPLE,
    )?;

    let target_metadata = ShadowsocksMetadata::parse(target)?;
    let mut request_payload = target_metadata.encode()?;
    request_payload.extend_from_slice(payload);
    let inner_request = encode_client_initial(cipher, password, salts.client, &request_payload)?;
    let mut mux_payload = mux_new_frame(&options.mux)?;
    mux_payload.extend_from_slice(&mux_data_frame(options.mux.id, &inner_request)?);
    let request_frame = websocket_client_binary_frame(&mux_payload, WS_MASK_KEY)?;
    tls.write_all(&request_frame)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    tls.flush()
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;

    let response_payload = read_websocket_binary_frame(&mut tls)?;
    let mux_response_payload_len = response_payload.len();
    let mut response_cursor = Cursor::new(response_payload);
    let response_frame = read_mux_frame(&mut response_cursor)?;
    validate_data_frame(&response_frame, options.mux.id)?;
    let inner_response = response_frame.payload;
    if inner_response.len() < spec.salt_len {
        return Err(OutboundError::BadShadowsocks(
            "v2ray-plugin response missing Shadowsocks server salt".to_owned(),
        ));
    }
    let (server_salt, encrypted) = inner_response.split_at(spec.salt_len);
    let mut decoder = AeadStreamCodec::new(cipher, password, server_salt)?;
    let mut encrypted_reader = Cursor::new(encrypted);
    let echoed_payload = read_encrypted_chunk_from_stream(&mut encrypted_reader, &mut decoder)?;
    let selected_alpn = crate::shared_transport::test_support::selected_tls_alpn(tls.ssl());
    let alpn_validated = selected_alpn == options.tls.alpn_protocol;

    Ok(Sip003V2rayPluginExchangeReport {
        plugin_name: "v2ray-plugin",
        tls_enabled: true,
        websocket_enabled: true,
        mux_enabled: true,
        proxy: proxy.to_owned(),
        tls_server_name: options.tls.server_name.clone(),
        selected_alpn,
        ws_host: ws_options.host,
        ws_path: ws_options.path,
        mux_id_hex: hex_encode(&options.mux.id),
        mux_host: options.mux.host.clone(),
        mux_port: options.mux.port,
        mux_network: options.mux.network.clone(),
        tls_passthrough_udp: options.tls_passthrough_udp,
        ws_passthrough_udp: options.ws_passthrough_udp,
        mux_passthrough_udp: options.mux_passthrough_udp,
        websocket_handshake_validated: true,
        websocket_binary_frame_validated: true,
        mux_new_frame_validated: true,
        mux_data_frame_validated: true,
        tls_handshake_validated: true,
        certificate_chain_validated: true,
        server_name_validated: true,
        alpn_validated,
        websocket_request_frame_len: request_frame.len(),
        mux_request_payload_len: mux_payload.len(),
        mux_response_payload_len,
        inner: ShadowsocksAeadTcpExchangeReport {
            server: proxy.to_owned(),
            target: target_metadata.authority(),
            cipher: spec.cipher.to_owned(),
            client_salt_len: salts.client.len(),
            server_salt_len: server_salt.len(),
            payload_len: payload.len(),
            echoed_payload,
            true_dataplane: true,
        },
    })
}

pub fn read_v2ray_plugin_muxed_shadowsocks_request(
    stream: &mut impl Read,
    cipher: &str,
    password: &str,
) -> Result<Sip003V2rayPluginRequest, OutboundError> {
    let websocket_payload = read_websocket_binary_frame(stream)?;
    let websocket_payload_len = websocket_payload.len();
    let mut cursor = Cursor::new(websocket_payload);
    let mux_new = read_mux_frame(&mut cursor)?;
    validate_new_frame(&mux_new)?;
    let mux_data = read_mux_frame(&mut cursor)?;
    validate_data_frame(&mux_data, mux_new.id)?;
    if cursor.position() as usize != websocket_payload_len {
        return Err(OutboundError::BadShadowsocks(
            "v2ray-plugin mux request has trailing bytes".to_owned(),
        ));
    }
    let (target, payload) = decode_client_initial(cipher, password, &mux_data.payload)?;
    Ok(Sip003V2rayPluginRequest {
        mux_new,
        mux_data,
        target: target.authority(),
        payload,
        websocket_payload_len,
    })
}

pub fn encode_v2ray_plugin_muxed_shadowsocks_response(
    cipher: &str,
    password: &str,
    server_salt: &[u8],
    mux_id: [u8; 2],
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let inner = encode_server_payload(cipher, password, server_salt, payload)?;
    let mux_payload = mux_data_frame(mux_id, &inner)?;
    websocket_server_binary_frame(&mux_payload)
}

fn validate_new_frame(frame: &MuxFrame) -> Result<(), OutboundError> {
    if frame.status != SESSION_STATUS_NEW || frame.option != OPTION_NONE {
        return Err(OutboundError::BadShadowsocks(
            "v2ray-plugin mux new frame status/option mismatch".to_owned(),
        ));
    }
    if frame.payload.is_empty() {
        Ok(())
    } else {
        Err(OutboundError::BadShadowsocks(
            "v2ray-plugin mux new frame must not carry data payload".to_owned(),
        ))
    }
}

fn validate_data_frame(frame: &MuxFrame, expected_id: [u8; 2]) -> Result<(), OutboundError> {
    if frame.id != expected_id {
        return Err(OutboundError::BadShadowsocks(
            "v2ray-plugin mux frame id mismatch".to_owned(),
        ));
    }
    if frame.status != SESSION_STATUS_KEEP || frame.option != OPTION_DATA {
        return Err(OutboundError::BadShadowsocks(
            "v2ray-plugin mux data frame status/option mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn normalize_ws_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_owned();
    }
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
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
