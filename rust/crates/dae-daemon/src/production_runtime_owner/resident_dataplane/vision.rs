use std::io::Write;
use std::sync::atomic::AtomicBool;

use super::client::{VlessTlsClient, flush_tls_writes};
use super::io::write_all_nonblocking;
use super::{
    TLS_RECORD_HEADER_LEN, TLS_RECORD_MAX_PAYLOAD_LEN, VISION_COMMAND_CONTINUE,
    VISION_COMMAND_DIRECT, VISION_COMMAND_END,
};

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

pub(super) fn drain_vision_uplink_until_direct(
    pending: &mut Vec<u8>,
    client: &mut VlessTlsClient,
    stop: &AtomicBool,
    user_uuid: [u8; 16],
    uuid_sent: &mut bool,
    uplink_direct: &mut bool,
) -> Result<(), String> {
    while !pending.is_empty() && !*uplink_direct {
        let Some((record_type, record)) = pop_complete_tls_record(pending)? else {
            return Ok(());
        };
        let command = if record_type == 23 {
            VISION_COMMAND_DIRECT
        } else {
            VISION_COMMAND_CONTINUE
        };
        let block = vision_padding_block(&record, command, user_uuid, uuid_sent);
        client.conn.writer().write_all(&block).map_err(|err| {
            format!(
                "queue VLESS Vision uplink {} block: {err}",
                vision_command_name(command)
            )
        })?;
        flush_tls_writes(client, stop)?;
        if command == VISION_COMMAND_DIRECT {
            *uplink_direct = true;
        }
    }
    if *uplink_direct && !pending.is_empty() {
        let tail = std::mem::take(pending);
        write_all_nonblocking(
            &mut client.tcp,
            &tail,
            stop,
            "write pending VLESS direct tail to TCP",
        )?;
    }
    Ok(())
}

fn pop_complete_tls_record(pending: &mut Vec<u8>) -> Result<Option<(u8, Vec<u8>)>, String> {
    if pending.len() < TLS_RECORD_HEADER_LEN {
        return Ok(None);
    }
    let record_type = pending[0];
    if !matches!(record_type, 20 | 21 | 22 | 23) {
        return Err(format!(
            "unexpected TLS record type before VLESS Vision uplink direct switch: {record_type}"
        ));
    }
    if pending[1] != 3 || pending[2] != 3 {
        return Err(format!(
            "unexpected TLS record version before VLESS Vision uplink direct switch: {}.{}",
            pending[1], pending[2]
        ));
    }
    let payload_len = u16::from_be_bytes([pending[3], pending[4]]) as usize;
    if payload_len > TLS_RECORD_MAX_PAYLOAD_LEN {
        return Err(format!(
            "TLS record too large before VLESS Vision uplink direct switch: {payload_len} bytes"
        ));
    }
    let record_len = TLS_RECORD_HEADER_LEN + payload_len;
    if pending.len() < record_len {
        return Ok(None);
    }
    let record = pending.drain(..record_len).collect::<Vec<_>>();
    Ok(Some((record_type, record)))
}

fn vision_command_name(command: u8) -> &'static str {
    match command {
        VISION_COMMAND_CONTINUE => "continue",
        VISION_COMMAND_END => "end",
        VISION_COMMAND_DIRECT => "direct",
        _ => "unknown",
    }
}

pub(super) fn vision_padding_block(
    payload: &[u8],
    command: u8,
    user_uuid: [u8; 16],
    uuid_sent: &mut bool,
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(if *uuid_sent { 0 } else { user_uuid.len() } + 5 + payload.len());
    if !*uuid_sent {
        out.extend_from_slice(&user_uuid);
        *uuid_sent = true;
    }
    let content_len = payload.len().min(u16::MAX as usize) as u16;
    out.push(command);
    out.extend_from_slice(&content_len.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&payload[..content_len as usize]);
    out
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
    fn resident_vless_vision_uplink_direct_block_is_wrapped_once() {
        let key = [7_u8; 16];
        let payload = [23, 3, 3, 0, 2, 0xaa, 0xbb];
        assert!(tls_application_data_records_complete(&payload));
        assert!(!tls_application_data_records_complete(&payload[..6]));

        let mut uuid_sent = false;
        let block = vision_padding_block(&payload, VISION_COMMAND_DIRECT, key, &mut uuid_sent);
        assert!(uuid_sent);
        assert_eq!(&block[..16], &key);
        assert_eq!(block[16], VISION_COMMAND_DIRECT);
        assert_eq!(
            u16::from_be_bytes([block[17], block[18]]),
            payload.len() as u16
        );
        assert_eq!(u16::from_be_bytes([block[19], block[20]]), 0);
        assert_eq!(&block[21..], &payload);

        let second = vision_padding_block(&payload, VISION_COMMAND_CONTINUE, key, &mut uuid_sent);
        assert_eq!(second[0], VISION_COMMAND_CONTINUE);
        assert_eq!(&second[5..], &payload);
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
}
