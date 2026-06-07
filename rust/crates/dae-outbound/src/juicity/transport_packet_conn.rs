use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit};
use hkdf::Hkdf;
use sha1::Sha1;

use crate::error::OutboundError;

use super::packet::{
    JUICITY_UNDERLAY_AUTH_IV_LEN, JUICITY_UNDERLAY_AUTH_PSK_LEN,
    build_dialauth_record_for_port_zero,
};

pub const DEFAULT_TRANSPORT_PACKET_CONN_TARGET: &str = "juicity-packet-zero.example:0";
pub const DEFAULT_TRANSPORT_PACKET_CONN_PAYLOAD: &[u8] = b"juicity-transport-packet-ping";
pub const DEFAULT_TRANSPORT_PACKET_CONN_RESPONSE: &[u8] = b"juicity-transport-packet-pong";
pub const JUICITY_TRANSPORT_PACKET_CONN_CIPHER: &str = "chacha20-poly1305";
pub const JUICITY_TRANSPORT_PACKET_CONN_REUSED_INFO_RAW: &str = "juicity-reused-info";
pub const JUICITY_TRANSPORT_PACKET_CONN_NONCE_LEN: usize = 12;
pub const JUICITY_TRANSPORT_PACKET_CONN_TAG_LEN: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityTransportPacketConnOptions {
    pub target: String,
    pub payload: Vec<u8>,
    pub response_payload: Vec<u8>,
    pub iterations: usize,
    pub timeout: Duration,
}

impl Default for JuicityTransportPacketConnOptions {
    fn default() -> Self {
        Self {
            target: DEFAULT_TRANSPORT_PACKET_CONN_TARGET.to_owned(),
            payload: DEFAULT_TRANSPORT_PACKET_CONN_PAYLOAD.to_vec(),
            response_payload: DEFAULT_TRANSPORT_PACKET_CONN_RESPONSE.to_vec(),
            iterations: 1,
            timeout: Duration::from_secs(3),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct JuicityTransportPacketConnReport {
    pub target: String,
    pub local_server_addr: String,
    pub cipher: String,
    pub reused_info_raw: String,
    pub reused_info_len: usize,
    pub hkdf_hash: String,
    pub nonce_len: usize,
    pub tag_len: usize,
    pub underlay_psk_len: usize,
    pub first_iv_len: usize,
    pub first_iv_zero_prefix_valid: bool,
    pub first_packet_uses_dialauth_iv: bool,
    pub generated_salt_count: usize,
    pub generated_salts_zero_prefix_valid: bool,
    pub payload_len: usize,
    pub response_payload_len: usize,
    pub encrypted_packet_len: usize,
    pub encrypted_response_packet_len: usize,
    pub iterations: usize,
    pub elapsed_ns: u128,
    pub ns_per_juicity_transport_packet_conn_roundtrip: f64,
    pub client_packet_sent_count: usize,
    pub server_packet_received_count: usize,
    pub server_decrypt_count: usize,
    pub server_encrypt_count: usize,
    pub client_response_received_count: usize,
    pub client_decrypt_count: usize,
    pub roundtrip_match_count: usize,
    pub transport_packet_conn_crypto_validated: bool,
    pub transport_packet_conn_first_iv_validated: bool,
    pub transport_packet_conn_udp_roundtrip_validated: bool,
    pub juicity_transport_packet_conn_crypto_admitted: bool,
    pub juicity_transport_packet_conn_first_iv_admitted: bool,
    pub juicity_transport_packet_conn_udp_roundtrip_admitted: bool,
    pub juicity_transport_packet_conn_dataplane_admitted: bool,
    pub juicity_stream_packet_conn_dataplane_admitted: bool,
    pub juicity_packet_over_stream_admitted: bool,
    pub juicity_congestion_behavior_admitted: bool,
    pub juicity_true_quic_h3_dataplane_admitted: bool,
}

pub fn run_transport_packet_conn_smoke(
    options: &JuicityTransportPacketConnOptions,
) -> Result<JuicityTransportPacketConnReport, OutboundError> {
    if options.iterations == 0 {
        return Err(bad_transport_packet_conn(
            "Juicity transport packet conn iterations must be greater than zero",
        ));
    }
    if options.payload.is_empty() {
        return Err(bad_transport_packet_conn(
            "Juicity transport packet conn payload cannot be empty",
        ));
    }
    if options.response_payload.is_empty() {
        return Err(bad_transport_packet_conn(
            "Juicity transport packet conn response payload cannot be empty",
        ));
    }

    let dialauth = build_dialauth_record_for_port_zero(&options.target)?;
    let server_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .map_err(|err| bad_transport_packet_conn(format!("bind transport relay server: {err}")))?;
    let server_addr = server_socket
        .local_addr()
        .map_err(|err| bad_transport_packet_conn(format!("server local addr: {err}")))?;
    let client_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .map_err(|err| bad_transport_packet_conn(format!("bind transport relay client: {err}")))?;
    server_socket
        .set_read_timeout(Some(options.timeout))
        .map_err(|err| bad_transport_packet_conn(format!("server read timeout: {err}")))?;
    client_socket
        .set_read_timeout(Some(options.timeout))
        .map_err(|err| bad_transport_packet_conn(format!("client read timeout: {err}")))?;
    server_socket
        .set_write_timeout(Some(options.timeout))
        .map_err(|err| bad_transport_packet_conn(format!("server write timeout: {err}")))?;
    client_socket
        .set_write_timeout(Some(options.timeout))
        .map_err(|err| bad_transport_packet_conn(format!("client write timeout: {err}")))?;

    let expected_packet_len = JUICITY_UNDERLAY_AUTH_IV_LEN
        + options.payload.len()
        + JUICITY_TRANSPORT_PACKET_CONN_TAG_LEN;
    let expected_response_len = JUICITY_UNDERLAY_AUTH_IV_LEN
        + options.response_payload.len()
        + JUICITY_TRANSPORT_PACKET_CONN_TAG_LEN;
    let mut receive_buf = vec![0_u8; expected_packet_len.max(expected_response_len) + 256_usize];
    let mut client_packet_sent_count = 0_usize;
    let mut server_packet_received_count = 0_usize;
    let mut server_decrypt_count = 0_usize;
    let mut server_encrypt_count = 0_usize;
    let mut client_response_received_count = 0_usize;
    let mut client_decrypt_count = 0_usize;
    let mut roundtrip_match_count = 0_usize;
    let mut first_packet_uses_dialauth_iv = false;
    let mut generated_salt_count = 0_usize;
    let mut generated_salts_zero_prefix_valid = true;

    let start = Instant::now();
    for iteration in 0..options.iterations {
        let request_salt = if iteration == 0 {
            first_packet_uses_dialauth_iv = true;
            dialauth.iv
        } else {
            generated_salt_count += 1;
            deterministic_salt(0x31, iteration)
        };
        generated_salts_zero_prefix_valid &=
            request_salt.first().copied() == Some(0) && request_salt.get(1).copied() == Some(0);
        let encrypted_request =
            seal_transport_packet(&dialauth.psk, &request_salt, &options.payload)?;
        if iteration == 0 {
            first_packet_uses_dialauth_iv = encrypted_request.get(..JUICITY_UNDERLAY_AUTH_IV_LEN)
                == Some(dialauth.iv.as_slice());
        }
        client_socket
            .send_to(&encrypted_request, server_addr)
            .map_err(|err| bad_transport_packet_conn(format!("client send request: {err}")))?;
        client_packet_sent_count += 1;

        let (received_len, client_addr) = server_socket
            .recv_from(&mut receive_buf)
            .map_err(|err| bad_transport_packet_conn(format!("server receive request: {err}")))?;
        server_packet_received_count += 1;
        let decrypted_request = open_transport_packet(&dialauth.psk, &receive_buf[..received_len])?;
        if decrypted_request == options.payload {
            server_decrypt_count += 1;
        }

        let response_salt = deterministic_salt(0x71, iteration);
        let encrypted_response =
            seal_transport_packet(&dialauth.psk, &response_salt, &options.response_payload)?;
        server_socket
            .send_to(&encrypted_response, client_addr)
            .map_err(|err| bad_transport_packet_conn(format!("server send response: {err}")))?;
        server_encrypt_count += 1;

        let (response_len, _server_addr) = client_socket
            .recv_from(&mut receive_buf)
            .map_err(|err| bad_transport_packet_conn(format!("client receive response: {err}")))?;
        client_response_received_count += 1;
        let decrypted_response =
            open_transport_packet(&dialauth.psk, &receive_buf[..response_len])?;
        if decrypted_response == options.response_payload {
            client_decrypt_count += 1;
            roundtrip_match_count += 1;
        }
    }
    let elapsed_ns = start.elapsed().as_nanos();

    let transport_packet_conn_crypto_validated = dialauth.psk_nonzero
        && dialauth.iv_zero_prefix_valid
        && first_packet_uses_dialauth_iv
        && generated_salts_zero_prefix_valid
        && expected_packet_len
            == JUICITY_UNDERLAY_AUTH_IV_LEN
                + options.payload.len()
                + JUICITY_TRANSPORT_PACKET_CONN_TAG_LEN;
    let transport_packet_conn_udp_roundtrip_validated = client_packet_sent_count
        == options.iterations
        && server_packet_received_count == options.iterations
        && server_decrypt_count == options.iterations
        && server_encrypt_count == options.iterations
        && client_response_received_count == options.iterations
        && client_decrypt_count == options.iterations
        && roundtrip_match_count == options.iterations;
    let transport_packet_conn_dataplane_admitted =
        transport_packet_conn_crypto_validated && transport_packet_conn_udp_roundtrip_validated;

    Ok(JuicityTransportPacketConnReport {
        target: dialauth.target,
        local_server_addr: server_addr.to_string(),
        cipher: JUICITY_TRANSPORT_PACKET_CONN_CIPHER.to_owned(),
        reused_info_raw: JUICITY_TRANSPORT_PACKET_CONN_REUSED_INFO_RAW.to_owned(),
        reused_info_len: JUICITY_TRANSPORT_PACKET_CONN_REUSED_INFO_RAW.len(),
        hkdf_hash: "sha1".to_owned(),
        nonce_len: JUICITY_TRANSPORT_PACKET_CONN_NONCE_LEN,
        tag_len: JUICITY_TRANSPORT_PACKET_CONN_TAG_LEN,
        underlay_psk_len: dialauth.psk.len(),
        first_iv_len: dialauth.iv.len(),
        first_iv_zero_prefix_valid: dialauth.iv_zero_prefix_valid,
        first_packet_uses_dialauth_iv,
        generated_salt_count,
        generated_salts_zero_prefix_valid,
        payload_len: options.payload.len(),
        response_payload_len: options.response_payload.len(),
        encrypted_packet_len: expected_packet_len,
        encrypted_response_packet_len: expected_response_len,
        iterations: options.iterations,
        elapsed_ns,
        ns_per_juicity_transport_packet_conn_roundtrip: elapsed_ns as f64
            / options.iterations as f64,
        client_packet_sent_count,
        server_packet_received_count,
        server_decrypt_count,
        server_encrypt_count,
        client_response_received_count,
        client_decrypt_count,
        roundtrip_match_count,
        transport_packet_conn_crypto_validated,
        transport_packet_conn_first_iv_validated: first_packet_uses_dialauth_iv,
        transport_packet_conn_udp_roundtrip_validated,
        juicity_transport_packet_conn_crypto_admitted: transport_packet_conn_crypto_validated,
        juicity_transport_packet_conn_first_iv_admitted: first_packet_uses_dialauth_iv,
        juicity_transport_packet_conn_udp_roundtrip_admitted:
            transport_packet_conn_udp_roundtrip_validated,
        juicity_transport_packet_conn_dataplane_admitted: transport_packet_conn_dataplane_admitted,
        juicity_stream_packet_conn_dataplane_admitted: false,
        juicity_packet_over_stream_admitted: false,
        juicity_congestion_behavior_admitted: false,
        juicity_true_quic_h3_dataplane_admitted: false,
    })
}

pub fn seal_transport_packet(
    master_key: &[u8; JUICITY_UNDERLAY_AUTH_PSK_LEN],
    salt: &[u8; JUICITY_UNDERLAY_AUTH_IV_LEN],
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let cipher = transport_packet_cipher(master_key, salt)?;
    let encrypted = cipher
        .encrypt(
            chacha20poly1305::Nonce::from_slice(&[0_u8; JUICITY_TRANSPORT_PACKET_CONN_NONCE_LEN]),
            payload,
        )
        .map_err(|_| bad_transport_packet_conn("transport packet conn encrypt failed"))?;
    let mut out = Vec::with_capacity(salt.len() + encrypted.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&encrypted);
    Ok(out)
}

pub fn open_transport_packet(
    master_key: &[u8; JUICITY_UNDERLAY_AUTH_PSK_LEN],
    packet: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    if packet.len() < JUICITY_UNDERLAY_AUTH_IV_LEN + JUICITY_TRANSPORT_PACKET_CONN_TAG_LEN {
        return Err(bad_transport_packet_conn("transport packet too short"));
    }
    let (salt, encrypted) = packet.split_at(JUICITY_UNDERLAY_AUTH_IV_LEN);
    let salt: &[u8; JUICITY_UNDERLAY_AUTH_IV_LEN] = salt
        .try_into()
        .map_err(|_| bad_transport_packet_conn("transport packet salt length mismatch"))?;
    let cipher = transport_packet_cipher(master_key, salt)?;
    cipher
        .decrypt(
            chacha20poly1305::Nonce::from_slice(&[0_u8; JUICITY_TRANSPORT_PACKET_CONN_NONCE_LEN]),
            encrypted,
        )
        .map_err(|_| bad_transport_packet_conn("transport packet conn decrypt failed"))
}

fn transport_packet_cipher(
    master_key: &[u8; JUICITY_UNDERLAY_AUTH_PSK_LEN],
    salt: &[u8; JUICITY_UNDERLAY_AUTH_IV_LEN],
) -> Result<ChaCha20Poly1305, OutboundError> {
    let hkdf = Hkdf::<Sha1>::new(Some(salt), master_key);
    let mut subkey = [0_u8; JUICITY_UNDERLAY_AUTH_PSK_LEN];
    hkdf.expand(
        JUICITY_TRANSPORT_PACKET_CONN_REUSED_INFO_RAW.as_bytes(),
        &mut subkey,
    )
    .map_err(|_| bad_transport_packet_conn("transport packet conn hkdf failed"))?;
    ChaCha20Poly1305::new_from_slice(&subkey)
        .map_err(|_| bad_transport_packet_conn("transport packet conn bad chacha key"))
}

fn deterministic_salt(seed: u8, iteration: usize) -> [u8; JUICITY_UNDERLAY_AUTH_IV_LEN] {
    let mut salt = [0_u8; JUICITY_UNDERLAY_AUTH_IV_LEN];
    for (offset, byte) in salt[2..].iter_mut().enumerate() {
        *byte = seed
            .wrapping_add((iteration as u8).wrapping_mul(23))
            .wrapping_add((offset as u8).wrapping_mul(11))
            .wrapping_add(5);
    }
    salt
}

fn bad_transport_packet_conn(message: impl Into<String>) -> OutboundError {
    OutboundError::BadJuicity(message.into())
}
