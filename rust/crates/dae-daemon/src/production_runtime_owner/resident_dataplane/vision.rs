use std::sync::atomic::AtomicBool;

use super::client::{VlessTlsClient, flush_tls_writes};
use super::{
    TLS_RECORD_HEADER_LEN, TLS_RECORD_MAX_PAYLOAD_LEN, VISION_COMMAND_CONTINUE,
    VISION_COMMAND_DIRECT, VISION_COMMAND_END,
};
use tls_parser::{
    TlsExtension, TlsMessage, TlsMessageHandshake, TlsPlaintext, TlsRecordType, TlsVersion,
    parse_tls_client_hello_extension, parse_tls_plaintext, parse_tls_server_hello_extension,
};

const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
#[cfg(test)]
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
#[cfg(test)]
const TLS_EXTENSION_SUPPORTED_VERSIONS: u16 = 0x002b;
#[cfg(test)]
const TLS_VERSION_1_3: u16 = 0x0304;
const TLS13_AES_128_CCM_8_SHA256: u16 = 0x1305;
const VISION_TLS_OBSERVE_LIMIT: usize = 64 * 1024;

pub(super) struct VisionUnpadder {
    pub(super) user_uuid: [u8; 16],
    pub(super) pending: Vec<u8>,
    pub(super) state: VisionUnpadState,
    pub(super) completed_blocks: usize,
    pub(super) direct_command_seen: bool,
}

#[derive(Clone, Debug)]
pub(super) enum VisionUnpadState {
    Initial,
    BlockHeader,
    BlockPayload {
        command: u8,
        remaining_content: usize,
        remaining_padding: usize,
    },
    Raw,
}

impl VisionUnpadder {
    pub(super) fn new(user_uuid: [u8; 16]) -> Self {
        Self {
            user_uuid,
            pending: Vec::new(),
            state: VisionUnpadState::Initial,
            completed_blocks: 0,
            direct_command_seen: false,
        }
    }

    pub(super) fn consume(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        if matches!(self.state, VisionUnpadState::Raw) {
            return Ok(input.to_vec());
        }
        self.pending.extend_from_slice(input);
        let mut out = Vec::new();
        loop {
            match self.state.clone() {
                VisionUnpadState::Initial => {
                    if self.pending.len() < 21 {
                        break;
                    }
                    if self.pending[..16] != self.user_uuid {
                        self.state = VisionUnpadState::Raw;
                        out.extend(self.pending.drain(..));
                        break;
                    }
                    self.pending.drain(..16);
                    self.state = VisionUnpadState::BlockHeader;
                }
                VisionUnpadState::BlockHeader => {
                    if self.pending.len() < 5 {
                        break;
                    }
                    let command = self.pending[0];
                    let remaining_content =
                        u16::from_be_bytes([self.pending[1], self.pending[2]]) as usize;
                    let remaining_padding =
                        u16::from_be_bytes([self.pending[3], self.pending[4]]) as usize;
                    if !matches!(
                        command,
                        VISION_COMMAND_CONTINUE | VISION_COMMAND_END | VISION_COMMAND_DIRECT
                    ) {
                        return Err(format!("unexpected VLESS Vision command: {command}"));
                    }
                    self.pending.drain(..5);
                    self.state = VisionUnpadState::BlockPayload {
                        command,
                        remaining_content,
                        remaining_padding,
                    };
                }
                VisionUnpadState::BlockPayload {
                    command,
                    mut remaining_content,
                    mut remaining_padding,
                } => {
                    if remaining_content > 0 {
                        let take = remaining_content.min(self.pending.len());
                        out.extend(self.pending.drain(..take));
                        remaining_content -= take;
                        self.state = VisionUnpadState::BlockPayload {
                            command,
                            remaining_content,
                            remaining_padding,
                        };
                        if remaining_content > 0 {
                            break;
                        }
                    }
                    if remaining_padding > 0 {
                        let take = remaining_padding.min(self.pending.len());
                        self.pending.drain(..take);
                        remaining_padding -= take;
                        self.state = VisionUnpadState::BlockPayload {
                            command,
                            remaining_content: 0,
                            remaining_padding,
                        };
                        if remaining_padding > 0 {
                            break;
                        }
                    }
                    self.completed_blocks += 1;
                    match command {
                        VISION_COMMAND_CONTINUE => {
                            self.state = VisionUnpadState::BlockHeader;
                        }
                        VISION_COMMAND_END => {
                            self.state = VisionUnpadState::Raw;
                            out.extend(self.pending.drain(..));
                            break;
                        }
                        VISION_COMMAND_DIRECT => {
                            self.direct_command_seen = true;
                            self.state = VisionUnpadState::Raw;
                            out.extend(self.pending.drain(..));
                            break;
                        }
                        _ => unreachable!(),
                    }
                }
                VisionUnpadState::Raw => {
                    out.extend(self.pending.drain(..));
                    break;
                }
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisionTlsDecision {
    Unknown,
    Direct,
    PlainOverlay,
}

#[derive(Clone, Debug)]
pub(super) struct VisionInnerTlsState {
    client_pending: Vec<u8>,
    server_pending: Vec<u8>,
    decision: VisionTlsDecision,
    client_tls_observed: bool,
    client_tls13_advertised: Option<bool>,
}

impl VisionInnerTlsState {
    pub(super) fn new() -> Self {
        Self {
            client_pending: Vec::new(),
            server_pending: Vec::new(),
            decision: VisionTlsDecision::Unknown,
            client_tls_observed: false,
            client_tls13_advertised: None,
        }
    }

    pub(super) fn observe_client_payload(&mut self, payload: &[u8]) -> Result<(), String> {
        let mut advertised = self.client_tls13_advertised;
        let mut observed = self.client_tls_observed;
        observe_tls_records(&mut self.client_pending, payload, |record| {
            if record.hdr.record_type != TlsRecordType::Handshake {
                return;
            }
            for message in &record.msg {
                if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) =
                    message
                {
                    observed = true;
                    advertised = client_hello_advertises_tls13(client_hello.ext);
                }
            }
        })
        .map(|()| {
            self.client_tls_observed = observed;
            self.client_tls13_advertised = advertised;
        })
    }

    pub(super) fn observe_server_payload(&mut self, payload: &[u8]) -> Result<(), String> {
        if self.decision != VisionTlsDecision::Unknown {
            return Ok(());
        }
        let mut decision = self.decision;
        observe_tls_records(&mut self.server_pending, payload, |record| {
            if record.hdr.record_type != TlsRecordType::Handshake {
                return;
            }
            for message in &record.msg {
                if decision != VisionTlsDecision::Unknown {
                    return;
                }
                let TlsMessage::Handshake(handshake) = message else {
                    continue;
                };
                decision = match handshake {
                    TlsMessageHandshake::ServerHello(server_hello) => {
                        let selected_tls13 = server_hello_selects_tls13(server_hello.ext);
                        let cipher_suite = u16::from(server_hello.cipher);
                        server_hello_decision(selected_tls13, cipher_suite)
                    }
                    TlsMessageHandshake::ServerHelloV13Draft18(server_hello) => {
                        let selected_tls13 = server_hello_selects_tls13(server_hello.ext)
                            || server_hello.version == TlsVersion::Tls13Draft18;
                        let cipher_suite = u16::from(server_hello.cipher);
                        server_hello_decision(selected_tls13, cipher_suite)
                    }
                    _ => VisionTlsDecision::Unknown,
                };
            }
        })?;
        self.decision = decision;
        Ok(())
    }

    fn application_data_command(&self) -> Option<u8> {
        match self.decision {
            VisionTlsDecision::Unknown => None,
            VisionTlsDecision::Direct => Some(VISION_COMMAND_DIRECT),
            VisionTlsDecision::PlainOverlay => Some(VISION_COMMAND_END),
        }
    }

    fn client_tls_filter_active(&self) -> bool {
        self.client_tls_observed
            || self
                .client_pending
                .first()
                .is_some_and(|record_type| *record_type == TLS_CONTENT_TYPE_HANDSHAKE)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum VisionUplinkMode {
    Padding,
    PlainOverlay,
    Direct,
}

#[cfg(test)]
fn tls_application_data_records_complete(mut input: &[u8]) -> bool {
    if input.is_empty() {
        return false;
    }
    while !input.is_empty() {
        if input.len() < TLS_RECORD_HEADER_LEN {
            return false;
        }
        if input[0] != 23 || input[1] != 3 || input[2] != 3 {
            return false;
        }
        let len = u16::from_be_bytes([input[3], input[4]]) as usize;
        let record_len = TLS_RECORD_HEADER_LEN + len;
        if input.len() < record_len {
            return false;
        }
        input = &input[record_len..];
    }
    true
}

pub(super) fn drain_vision_uplink(
    pending: &mut Vec<u8>,
    client: &mut VlessTlsClient,
    stop: &AtomicBool,
    user_uuid: [u8; 16],
    uuid_sent: &mut bool,
    first_block: &mut bool,
    mode: &mut VisionUplinkMode,
    tls_state: &mut VisionInnerTlsState,
) -> Result<(), String> {
    if write_pending_after_vision_mode(pending, client, stop, *mode)? {
        return Ok(());
    }

    if *mode == VisionUplinkMode::Padding && *first_block && !pending.is_empty() {
        let payload = std::mem::take(pending);
        tls_state.observe_client_payload(&payload)?;
        let long_padding = looks_like_tls_record_start(&payload);
        let block = vision_padding_block(
            &payload,
            VISION_COMMAND_CONTINUE,
            user_uuid,
            uuid_sent,
            long_padding,
        );
        client.queue_plain(
            &block,
            &format!(
                "queue VLESS Vision uplink {} block",
                vision_command_name(VISION_COMMAND_CONTINUE)
            ),
        )?;
        flush_tls_writes(client, stop)?;
        *first_block = false;
        return Ok(());
    }

    while !pending.is_empty() && *mode == VisionUplinkMode::Padding {
        if !should_continue_vision_tls_filtering(pending, tls_state) {
            let payload = std::mem::take(pending);
            let block =
                vision_padding_block(&payload, VISION_COMMAND_END, user_uuid, uuid_sent, false);
            client.queue_plain(
                &block,
                &format!(
                    "queue VLESS Vision uplink {} block",
                    vision_command_name(VISION_COMMAND_END)
                ),
            )?;
            flush_tls_writes(client, stop)?;
            *mode = VisionUplinkMode::PlainOverlay;
            return Ok(());
        }
        let Some((record_type, record_len)) = peek_complete_tls_record(pending)? else {
            return Ok(());
        };
        let command = match vision_uplink_command(record_type, tls_state) {
            Some(command) => command,
            None => return Ok(()),
        };
        let record = pending.drain(..record_len).collect::<Vec<_>>();
        tls_state.observe_client_payload(&record)?;
        let block = vision_padding_block(&record, command, user_uuid, uuid_sent, true);
        client.queue_plain(
            &block,
            &format!(
                "queue VLESS Vision uplink {} block",
                vision_command_name(command)
            ),
        )?;
        flush_tls_writes(client, stop)?;
        match command {
            VISION_COMMAND_END => *mode = VisionUplinkMode::PlainOverlay,
            VISION_COMMAND_DIRECT => *mode = VisionUplinkMode::Direct,
            _ => {}
        }
    }
    let _ = write_pending_after_vision_mode(pending, client, stop, *mode)?;
    Ok(())
}

fn write_pending_after_vision_mode(
    pending: &mut Vec<u8>,
    client: &mut VlessTlsClient,
    stop: &AtomicBool,
    mode: VisionUplinkMode,
) -> Result<bool, String> {
    match mode {
        VisionUplinkMode::Padding => Ok(false),
        VisionUplinkMode::PlainOverlay => {
            if !pending.is_empty() {
                let tail = std::mem::take(pending);
                client.queue_plain(&tail, "queue pending Vision plain-overlay tail")?;
                flush_tls_writes(client, stop)?;
            }
            Ok(true)
        }
        VisionUplinkMode::Direct => {
            if !pending.is_empty() {
                let tail = std::mem::take(pending);
                client.raw_write_all_nonblocking(
                    &tail,
                    stop,
                    "write VLESS Vision direct uplink payload",
                )?;
            }
            Ok(true)
        }
    }
}

fn looks_like_tls_record_start(pending: &[u8]) -> bool {
    could_be_tls_record_prefix(pending)
}

fn should_continue_vision_tls_filtering(pending: &[u8], tls_state: &VisionInnerTlsState) -> bool {
    tls_state.client_tls_filter_active() && looks_like_tls_record_start(pending)
}

fn could_be_tls_record_prefix(pending: &[u8]) -> bool {
    if pending.is_empty() {
        return true;
    }
    if !matches!(pending[0], 20 | 21 | 22 | 23) {
        return false;
    }
    if pending.len() == 1 {
        return true;
    }
    if pending[1] != 3 {
        return false;
    }
    if pending.len() == 2 {
        return true;
    }
    if !(1..=4).contains(&pending[2]) {
        return false;
    }
    if pending.len() < TLS_RECORD_HEADER_LEN {
        return true;
    }
    let payload_len = u16::from_be_bytes([pending[3], pending[4]]) as usize;
    payload_len <= TLS_RECORD_MAX_PAYLOAD_LEN
}

#[cfg(test)]
fn pop_complete_tls_record(pending: &mut Vec<u8>) -> Result<Option<(u8, Vec<u8>)>, String> {
    let Some((record_type, record_len)) = peek_complete_tls_record(pending)? else {
        return Ok(None);
    };
    let record = pending.drain(..record_len).collect::<Vec<_>>();
    Ok(Some((record_type, record)))
}

fn peek_complete_tls_record(pending: &[u8]) -> Result<Option<(u8, usize)>, String> {
    if pending.len() < TLS_RECORD_HEADER_LEN {
        return Ok(None);
    }
    let record_type = pending[0];
    if !matches!(record_type, 20 | 21 | 22 | 23) {
        return Err(format!(
            "unexpected TLS record type before VLESS Vision uplink overlay switch: {record_type}"
        ));
    }
    if pending[1] != 3 || !(1..=4).contains(&pending[2]) {
        return Err(format!(
            "unexpected TLS record version before VLESS Vision uplink overlay switch: {}.{}",
            pending[1], pending[2]
        ));
    }
    let payload_len = u16::from_be_bytes([pending[3], pending[4]]) as usize;
    if payload_len > TLS_RECORD_MAX_PAYLOAD_LEN {
        return Err(format!(
            "TLS record too large before VLESS Vision uplink overlay switch: {payload_len} bytes"
        ));
    }
    let record_len = TLS_RECORD_HEADER_LEN + payload_len;
    if pending.len() < record_len {
        return Ok(None);
    }
    Ok(Some((record_type, record_len)))
}

fn vision_command_name(command: u8) -> &'static str {
    match command {
        VISION_COMMAND_CONTINUE => "continue",
        VISION_COMMAND_END => "end",
        VISION_COMMAND_DIRECT => "direct",
        _ => "unknown",
    }
}

fn vision_uplink_command(record_type: u8, tls_state: &VisionInnerTlsState) -> Option<u8> {
    if record_type != TLS_CONTENT_TYPE_APPLICATION_DATA {
        return Some(VISION_COMMAND_CONTINUE);
    }
    tls_state.application_data_command()
}

fn observe_tls_records<F>(
    pending: &mut Vec<u8>,
    payload: &[u8],
    mut observe: F,
) -> Result<(), String>
where
    F: FnMut(&TlsPlaintext<'_>),
{
    pending.extend_from_slice(payload);
    if pending.len() > VISION_TLS_OBSERVE_LIMIT {
        pending.clear();
        return Ok(());
    }
    loop {
        let consumed = {
            match parse_tls_plaintext(pending.as_slice()) {
                Ok((remaining, record)) => {
                    let consumed = pending.len() - remaining.len();
                    observe(&record);
                    consumed
                }
                Err(tls_parser::nom::Err::Incomplete(_)) => return Ok(()),
                Err(_) => {
                    pending.clear();
                    return Ok(());
                }
            }
        };
        if consumed == 0 {
            return Ok(());
        }
        pending.drain(..consumed);
    }
}

fn client_hello_advertises_tls13(extensions: Option<&[u8]>) -> Option<bool> {
    parse_supported_versions(extensions, parse_tls_client_hello_extension)
        .map(supported_versions_contains_tls13)
}

fn server_hello_selects_tls13(extensions: Option<&[u8]>) -> bool {
    parse_supported_versions(extensions, parse_tls_server_hello_extension)
        .map(supported_versions_contains_tls13)
        .unwrap_or(false)
}

fn parse_supported_versions<'a, F>(
    extensions: Option<&'a [u8]>,
    mut parse: F,
) -> Option<Vec<TlsVersion>>
where
    F: FnMut(&'a [u8]) -> tls_parser::IResult<&'a [u8], TlsExtension<'a>>,
{
    let mut input = extensions?;
    while !input.is_empty() {
        match parse(input) {
            Ok((_remaining, TlsExtension::SupportedVersions(versions))) => return Some(versions),
            Ok((remaining, _)) if remaining.len() < input.len() => input = remaining,
            _ => return None,
        }
    }
    None
}

fn supported_versions_contains_tls13(versions: Vec<TlsVersion>) -> bool {
    versions
        .into_iter()
        .any(|version| version == TlsVersion::Tls13)
}

fn server_hello_decision(selected_tls13: bool, cipher_suite: u16) -> VisionTlsDecision {
    if selected_tls13 && tls13_cipher_allows_direct(cipher_suite) {
        VisionTlsDecision::Direct
    } else {
        VisionTlsDecision::PlainOverlay
    }
}

fn tls13_cipher_allows_direct(cipher: u16) -> bool {
    (0x1301..=0x1305).contains(&cipher) && cipher != TLS13_AES_128_CCM_8_SHA256
}

pub(super) fn vision_padding_block(
    payload: &[u8],
    command: u8,
    user_uuid: [u8; 16],
    uuid_sent: &mut bool,
    long_padding: bool,
) -> Vec<u8> {
    let padding_len = vision_padding_len(payload.len(), long_padding);
    let mut out = Vec::with_capacity(
        if *uuid_sent { 0 } else { user_uuid.len() } + 5 + payload.len() + padding_len,
    );
    if !*uuid_sent {
        out.extend_from_slice(&user_uuid);
        *uuid_sent = true;
    }
    let content_len = payload.len().min(u16::MAX as usize) as u16;
    out.push(command);
    out.extend_from_slice(&content_len.to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend_from_slice(&payload[..content_len as usize]);
    out.resize(out.len() + padding_len, 0);
    out
}

fn vision_padding_len(content_len: usize, long_padding: bool) -> usize {
    if content_len < 900 && long_padding {
        900 - content_len + fastrand::usize(..500)
    } else {
        fastrand::usize(..256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_vless_vision_unpadder_removes_padding_blocks() {
        let key = [
            0x87, 0xe8, 0x7f, 0x74, 0x76, 0xef, 0x5c, 0x4a, 0x90, 0x46, 0x2e, 0x6b, 0x47, 0xef,
            0x76, 0x0a,
        ];
        let mut block = Vec::from(key);
        block.extend_from_slice(&[VISION_COMMAND_CONTINUE, 0, 4, 0, 3]);
        block.extend_from_slice(b"HTTP");
        block.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        block.extend_from_slice(&[VISION_COMMAND_END, 0, 3, 0, 0]);
        block.extend_from_slice(b"/1.");

        let mut unpadder = VisionUnpadder::new(key);
        assert!(unpadder.consume(&block[..7]).unwrap().is_empty());
        let payload = unpadder.consume(&block[7..]).unwrap();
        assert_eq!(payload, b"HTTP/1.");
        assert_eq!(unpadder.completed_blocks, 2);
        assert!(!unpadder.direct_command_seen);
    }

    #[test]
    fn resident_vless_vision_uplink_end_block_is_wrapped_once() {
        let key = [7_u8; 16];
        let payload = [23, 3, 3, 0, 2, 0xaa, 0xbb];
        assert!(tls_application_data_records_complete(&payload));
        assert!(!tls_application_data_records_complete(&payload[..6]));

        let mut uuid_sent = false;
        let block = vision_padding_block(&payload, VISION_COMMAND_END, key, &mut uuid_sent, false);
        assert!(uuid_sent);
        assert_eq!(&block[..16], &key);
        assert_eq!(block[16], VISION_COMMAND_END);
        assert_eq!(
            u16::from_be_bytes([block[17], block[18]]),
            payload.len() as u16
        );
        let padding_len = u16::from_be_bytes([block[19], block[20]]) as usize;
        assert!(padding_len <= 255);
        assert_eq!(&block[21..21 + payload.len()], &payload);
        assert_eq!(block.len(), 21 + payload.len() + padding_len);

        let second = vision_padding_block(
            &payload,
            VISION_COMMAND_CONTINUE,
            key,
            &mut uuid_sent,
            false,
        );
        assert_eq!(second[0], VISION_COMMAND_CONTINUE);
        let second_padding_len = u16::from_be_bytes([second[3], second[4]]) as usize;
        assert_eq!(&second[5..5 + payload.len()], &payload);
        assert_eq!(second.len(), 5 + payload.len() + second_padding_len);
    }

    #[test]
    fn resident_vless_vision_long_padding_matches_go_floor() {
        let key = [9_u8; 16];
        let payload = [22, 3, 1, 0, 2, 0x01, 0x00];
        let mut uuid_sent = false;

        let block =
            vision_padding_block(&payload, VISION_COMMAND_CONTINUE, key, &mut uuid_sent, true);

        let padding_len = u16::from_be_bytes([block[19], block[20]]) as usize;
        assert!((900 - payload.len()..900 - payload.len() + 500).contains(&padding_len));
    }

    #[test]
    fn resident_vless_vision_uplink_parses_ccs_before_direct_record() {
        let mut pending = vec![20, 3, 3, 0, 1, 1, 23, 3, 3, 0, 2, 0xaa, 0xbb];

        let (ty, record) = pop_complete_tls_record(&mut pending).unwrap().unwrap();
        assert_eq!(ty, 20);
        assert_eq!(record, [20, 3, 3, 0, 1, 1]);

        let (ty, record) = pop_complete_tls_record(&mut pending).unwrap().unwrap();
        assert_eq!(ty, 23);
        assert_eq!(record, [23, 3, 3, 0, 2, 0xaa, 0xbb]);
        assert!(pending.is_empty());
    }

    #[test]
    fn resident_vless_vision_uplink_accepts_client_hello_legacy_record_version() {
        let mut pending = vec![22, 3, 1, 0, 2, 0x01, 0x00];

        let (ty, record) = pop_complete_tls_record(&mut pending).unwrap().unwrap();
        assert_eq!(ty, 22);
        assert_eq!(record, [22, 3, 1, 0, 2, 0x01, 0x00]);
        assert!(pending.is_empty());
    }

    #[test]
    fn resident_vless_vision_tls_prefix_rejects_short_non_tls_mtproto() {
        assert!(!could_be_tls_record_prefix(&[0xef]));
        assert!(!looks_like_tls_record_start(&[0xef, 0xef, 0xef, 0xef]));
        assert!(could_be_tls_record_prefix(&[22]));
        assert!(could_be_tls_record_prefix(&[22, 3, 3]));
        assert!(looks_like_tls_record_start(&[22, 3, 3, 0, 1]));
    }

    #[test]
    fn resident_vless_vision_non_tls_after_first_block_does_not_wait_on_fake_appdata_prefix() {
        let mut state = VisionInnerTlsState::new();
        state
            .observe_client_payload(&[0xee, 0xee, 0xee, 0xee])
            .unwrap();

        assert!(!state.client_tls_filter_active());
        assert!(!should_continue_vision_tls_filtering(
            &[23, 3, 3, 0, 2, 0xaa, 0xbb],
            &state
        ));
    }

    #[test]
    fn resident_vless_vision_observed_tls_allows_application_data_filtering() {
        let mut state = VisionInnerTlsState::new();
        state.client_tls_observed = true;

        assert!(state.client_tls_filter_active());
        assert!(should_continue_vision_tls_filtering(
            &[23, 3, 3, 0, 2, 0xaa, 0xbb],
            &state
        ));
    }

    #[test]
    fn resident_vless_vision_inner_tls_parser_admits_tls13_server_hello() {
        let mut state = VisionInnerTlsState::new();
        let server_hello = tls13_server_hello_record(0x1301, true);

        state.observe_server_payload(&server_hello).unwrap();

        assert_eq!(
            vision_uplink_command(TLS_CONTENT_TYPE_APPLICATION_DATA, &state),
            Some(VISION_COMMAND_DIRECT)
        );
    }

    #[test]
    fn resident_vless_vision_inner_tls_parser_rejects_tls12_server_hello() {
        let mut state = VisionInnerTlsState::new();
        let server_hello = tls13_server_hello_record(0x1301, false);

        state.observe_server_payload(&server_hello).unwrap();

        assert_eq!(
            vision_uplink_command(TLS_CONTENT_TYPE_APPLICATION_DATA, &state),
            Some(VISION_COMMAND_END)
        );
    }

    #[test]
    fn resident_vless_vision_waits_for_native_tls13_decision_before_direct() {
        let state = VisionInnerTlsState::new();

        assert_eq!(
            vision_uplink_command(TLS_CONTENT_TYPE_APPLICATION_DATA, &state),
            None
        );
    }

    fn tls13_server_hello_record(cipher_suite: u16, selected_tls13: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);

        let mut extensions = Vec::new();
        if selected_tls13 {
            extensions.extend_from_slice(&TLS_EXTENSION_SUPPORTED_VERSIONS.to_be_bytes());
            extensions.extend_from_slice(&2_u16.to_be_bytes());
            extensions.extend_from_slice(&TLS_VERSION_1_3.to_be_bytes());
        }
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(TLS_HANDSHAKE_TYPE_SERVER_HELLO);
        handshake.extend_from_slice(&u24_bytes(body.len()));
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(TLS_CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn u24_bytes(len: usize) -> [u8; 3] {
        [
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]
    }
}
