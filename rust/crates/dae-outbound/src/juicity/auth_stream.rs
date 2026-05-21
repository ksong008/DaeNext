use crate::error::OutboundError;

use super::packet::{
    JUICITY_UNDERLAY_AUTH_IV_LEN, JUICITY_UNDERLAY_AUTH_PSK_LEN, JuicityDialAuthRecord,
    build_dialauth_record_for_port_zero,
};

pub const JUICITY_AUTHENTICATE_VERSION0: u8 = 0x00;
pub const JUICITY_AUTHENTICATE_TYPE: u8 = 0x00;
pub const JUICITY_AUTHENTICATE_UUID_LEN: usize = 16;
pub const JUICITY_AUTHENTICATE_TOKEN_LEN: usize = 32;
pub const JUICITY_AUTHENTICATE_HEADER_LEN: usize =
    2 + JUICITY_AUTHENTICATE_UUID_LEN + JUICITY_AUTHENTICATE_TOKEN_LEN;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityAuthenticateHeader {
    pub version: u8,
    pub command_type: u8,
    pub uuid: [u8; JUICITY_AUTHENTICATE_UUID_LEN],
    pub token: [u8; JUICITY_AUTHENTICATE_TOKEN_LEN],
    pub token_source: String,
    pub encoded: Vec<u8>,
}

impl JuicityAuthenticateHeader {
    pub fn layout_valid(&self) -> bool {
        self.encoded.len() == JUICITY_AUTHENTICATE_HEADER_LEN
            && self.encoded.first().copied() == Some(self.version)
            && self.encoded.get(1).copied() == Some(self.command_type)
            && self.encoded[2..2 + JUICITY_AUTHENTICATE_UUID_LEN] == self.uuid
            && self.encoded[2 + JUICITY_AUTHENTICATE_UUID_LEN..] == self.token
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityAuthStreamTranscript {
    pub target: String,
    pub auth_header_len: usize,
    pub dialauth_record_len: usize,
    pub transcript_len: usize,
    pub auth_header_offset: usize,
    pub dialauth_record_offset: usize,
    pub transcript: Vec<u8>,
    pub auth_header_written_first: bool,
    pub dialauth_record_matches_stage120: bool,
    pub dialauth_record_order_valid: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityAuthStreamSmokeReport {
    pub target: String,
    pub authenticate_version: u8,
    pub authenticate_type: u8,
    pub authenticate_uuid_len: usize,
    pub authenticate_token_len: usize,
    pub authenticate_header_len: usize,
    pub authenticate_token_source: String,
    pub authenticate_header_layout_valid: bool,
    pub dialauth_metadata_len: usize,
    pub dialauth_iv_len: usize,
    pub dialauth_psk_len: usize,
    pub dialauth_record_len: usize,
    pub transcript_len: usize,
    pub auth_header_offset: usize,
    pub dialauth_record_offset: usize,
    pub auth_header_written_first: bool,
    pub dialauth_record_matches_stage120: bool,
    pub dialauth_record_order_valid: bool,
    pub juicity_authenticate_header_layout_admitted: bool,
    pub juicity_auth_uni_stream_write_order_admitted: bool,
    pub juicity_dialauth_record_over_auth_stream_admitted: bool,
    pub juicity_auth_token_live_ekm_admitted: bool,
    pub juicity_dialauth_over_h3_admitted: bool,
    pub juicity_transport_packet_conn_dataplane_admitted: bool,
    pub juicity_stream_packet_conn_dataplane_admitted: bool,
    pub juicity_true_quic_h3_dataplane_admitted: bool,
}

pub fn build_authenticate_header(
    uuid: [u8; JUICITY_AUTHENTICATE_UUID_LEN],
    token: [u8; JUICITY_AUTHENTICATE_TOKEN_LEN],
    token_source: impl Into<String>,
) -> JuicityAuthenticateHeader {
    let mut encoded = Vec::with_capacity(JUICITY_AUTHENTICATE_HEADER_LEN);
    encoded.push(JUICITY_AUTHENTICATE_VERSION0);
    encoded.push(JUICITY_AUTHENTICATE_TYPE);
    encoded.extend_from_slice(&uuid);
    encoded.extend_from_slice(&token);
    JuicityAuthenticateHeader {
        version: JUICITY_AUTHENTICATE_VERSION0,
        command_type: JUICITY_AUTHENTICATE_TYPE,
        uuid,
        token,
        token_source: token_source.into(),
        encoded,
    }
}

pub fn build_deterministic_authenticate_header() -> JuicityAuthenticateHeader {
    let mut uuid = [0_u8; JUICITY_AUTHENTICATE_UUID_LEN];
    for (offset, byte) in uuid.iter_mut().enumerate() {
        *byte = deterministic_byte(0x21, offset);
    }
    let mut token = [0_u8; JUICITY_AUTHENTICATE_TOKEN_LEN];
    for (offset, byte) in token.iter_mut().enumerate() {
        *byte = deterministic_byte(0x81, offset);
    }
    build_authenticate_header(uuid, token, "deterministic-fixture-not-live-ekm")
}

pub fn build_auth_stream_transcript(
    header: &JuicityAuthenticateHeader,
    dialauth: &JuicityDialAuthRecord,
) -> JuicityAuthStreamTranscript {
    let mut transcript = Vec::with_capacity(header.encoded.len() + dialauth.packed.len());
    transcript.extend_from_slice(&header.encoded);
    transcript.extend_from_slice(&dialauth.packed);

    let auth_header_offset = 0;
    let dialauth_record_offset = header.encoded.len();
    let auth_header_written_first =
        transcript.get(..header.encoded.len()) == Some(header.encoded.as_slice());
    let dialauth_record_matches_stage120 = transcript
        .get(dialauth_record_offset..dialauth_record_offset + dialauth.packed.len())
        == Some(dialauth.packed.as_slice());
    let dialauth_record_order_valid = dialauth_record_offset == JUICITY_AUTHENTICATE_HEADER_LEN
        && transcript.len() == header.encoded.len() + dialauth.packed.len()
        && dialauth_record_matches_stage120;

    JuicityAuthStreamTranscript {
        target: dialauth.target.clone(),
        auth_header_len: header.encoded.len(),
        dialauth_record_len: dialauth.packed.len(),
        transcript_len: transcript.len(),
        auth_header_offset,
        dialauth_record_offset,
        transcript,
        auth_header_written_first,
        dialauth_record_matches_stage120,
        dialauth_record_order_valid,
    }
}

pub fn auth_stream_smoke(target: &str) -> Result<JuicityAuthStreamSmokeReport, OutboundError> {
    let header = build_deterministic_authenticate_header();
    let dialauth = build_dialauth_record_for_port_zero(target)?;
    let transcript = build_auth_stream_transcript(&header, &dialauth);

    let authenticate_header_layout_admitted = header.layout_valid();
    let auth_uni_stream_write_order_admitted = authenticate_header_layout_admitted
        && transcript.auth_header_offset == 0
        && transcript.auth_header_written_first
        && transcript.dialauth_record_offset == header.encoded.len()
        && transcript.dialauth_record_order_valid;
    let dialauth_record_over_auth_stream_admitted = auth_uni_stream_write_order_admitted
        && transcript.dialauth_record_matches_stage120
        && dialauth.iv_zero_prefix_valid
        && dialauth.packed.len()
            == JUICITY_UNDERLAY_AUTH_IV_LEN + JUICITY_UNDERLAY_AUTH_PSK_LEN + dialauth.metadata_len;

    Ok(JuicityAuthStreamSmokeReport {
        target: dialauth.target,
        authenticate_version: header.version,
        authenticate_type: header.command_type,
        authenticate_uuid_len: header.uuid.len(),
        authenticate_token_len: header.token.len(),
        authenticate_header_len: header.encoded.len(),
        authenticate_token_source: header.token_source,
        authenticate_header_layout_valid: authenticate_header_layout_admitted,
        dialauth_metadata_len: dialauth.metadata_len,
        dialauth_iv_len: dialauth.iv.len(),
        dialauth_psk_len: dialauth.psk.len(),
        dialauth_record_len: dialauth.packed.len(),
        transcript_len: transcript.transcript_len,
        auth_header_offset: transcript.auth_header_offset,
        dialauth_record_offset: transcript.dialauth_record_offset,
        auth_header_written_first: transcript.auth_header_written_first,
        dialauth_record_matches_stage120: transcript.dialauth_record_matches_stage120,
        dialauth_record_order_valid: transcript.dialauth_record_order_valid,
        juicity_authenticate_header_layout_admitted: authenticate_header_layout_admitted,
        juicity_auth_uni_stream_write_order_admitted: auth_uni_stream_write_order_admitted,
        juicity_dialauth_record_over_auth_stream_admitted:
            dialauth_record_over_auth_stream_admitted,
        juicity_auth_token_live_ekm_admitted: false,
        juicity_dialauth_over_h3_admitted: false,
        juicity_transport_packet_conn_dataplane_admitted: false,
        juicity_stream_packet_conn_dataplane_admitted: false,
        juicity_true_quic_h3_dataplane_admitted: false,
    })
}

fn deterministic_byte(seed: u8, offset: usize) -> u8 {
    seed.wrapping_add((offset as u8).wrapping_mul(19))
        .wrapping_add(7)
}
