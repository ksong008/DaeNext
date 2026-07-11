use std::collections::VecDeque;

use dae_outbound::shared_transport::websocket_client_mask_key;

const WEBSOCKET_FIN: u8 = 0x80;
const WEBSOCKET_MASK: u8 = 0x80;
const WEBSOCKET_OPCODE_CONTINUATION: u8 = 0x0;
const WEBSOCKET_OPCODE_TEXT: u8 = 0x1;
const WEBSOCKET_OPCODE_BINARY: u8 = 0x2;
const WEBSOCKET_OPCODE_CLOSE: u8 = 0x8;
const WEBSOCKET_OPCODE_PING: u8 = 0x9;
const WEBSOCKET_OPCODE_PONG: u8 = 0xa;
const WEBSOCKET_CONTROL_MAX_BYTES: usize = 125;
const WEBSOCKET_MAX_HEADER_BYTES: usize = 14;
const WEBSOCKET_MAX_QUEUED_CONTROL_RESPONSE_BYTES: usize = 64 * 1024;
const WEBSOCKET_RECEIVE_BUFFER_SLACK_BYTES: usize = 64 * 1024;
const WEBSOCKET_MAX_RECEIVE_BUFFER_BYTES: usize = RESIDENT_WEBSOCKET_MAX_MESSAGE_BYTES
    + WEBSOCKET_MAX_HEADER_BYTES
    + WEBSOCKET_RECEIVE_BUFFER_SLACK_BYTES;

pub(crate) const RESIDENT_WEBSOCKET_MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct WebSocketBinaryFrameDecoder {
    pending: Vec<u8>,
    fragmented: Option<Vec<u8>>,
    control_responses: VecDeque<Vec<u8>>,
    control_response_bytes: usize,
    closed: bool,
}

impl WebSocketBinaryFrameDecoder {
    pub(crate) fn push(&mut self, input: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        if self.closed {
            return Ok(Vec::new());
        }
        let pending_len = self
            .pending
            .len()
            .checked_add(input.len())
            .ok_or_else(|| "websocket receive buffer length overflow".to_owned())?;
        if pending_len > WEBSOCKET_MAX_RECEIVE_BUFFER_BYTES {
            return Err(format!(
                "websocket receive buffer exceeds {} bytes",
                WEBSOCKET_MAX_RECEIVE_BUFFER_BYTES
            ));
        }
        self.pending.extend_from_slice(input);

        let mut messages = Vec::new();
        let mut consumed = 0_usize;
        while !self.closed {
            let Some(frame) = parse_frame(&self.pending[consumed..])? else {
                break;
            };
            consumed = consumed
                .checked_add(frame.encoded_len)
                .ok_or_else(|| "websocket consumed length overflow".to_owned())?;
            self.consume_frame(frame, &mut messages)?;
        }
        if consumed != 0 {
            self.pending.drain(..consumed);
        }
        Ok(messages)
    }

    pub(crate) fn take_control_responses(&mut self) -> Vec<Vec<u8>> {
        self.control_response_bytes = 0;
        self.control_responses.drain(..).collect()
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }

    fn consume_frame(
        &mut self,
        frame: ParsedWebSocketFrame,
        messages: &mut Vec<Vec<u8>>,
    ) -> Result<(), String> {
        match frame.opcode {
            WEBSOCKET_OPCODE_BINARY => {
                if self.fragmented.is_some() {
                    return Err(
                        "websocket binary frame started before fragmented message completed"
                            .to_owned(),
                    );
                }
                if frame.fin {
                    messages.push(frame.payload);
                } else {
                    self.fragmented = Some(frame.payload);
                }
            }
            WEBSOCKET_OPCODE_CONTINUATION => {
                let fragmented = self.fragmented.as_mut().ok_or_else(|| {
                    "websocket continuation without fragmented message".to_owned()
                })?;
                let next_len = fragmented
                    .len()
                    .checked_add(frame.payload.len())
                    .ok_or_else(|| "websocket fragmented message length overflow".to_owned())?;
                if next_len > RESIDENT_WEBSOCKET_MAX_MESSAGE_BYTES {
                    return Err(format!(
                        "websocket fragmented message exceeds {} bytes",
                        RESIDENT_WEBSOCKET_MAX_MESSAGE_BYTES
                    ));
                }
                fragmented.extend_from_slice(&frame.payload);
                if frame.fin {
                    messages.push(self.fragmented.take().unwrap_or_default());
                }
            }
            WEBSOCKET_OPCODE_PING => {
                self.queue_control_response(WEBSOCKET_OPCODE_PONG, &frame.payload)?
            }
            WEBSOCKET_OPCODE_PONG => {}
            WEBSOCKET_OPCODE_CLOSE => {
                self.queue_control_response(WEBSOCKET_OPCODE_CLOSE, &frame.payload)?;
                self.closed = true;
                self.fragmented = None;
            }
            WEBSOCKET_OPCODE_TEXT => {
                return Err("text websocket frame is invalid for binary proxy transport".to_owned());
            }
            opcode => return Err(format!("unsupported websocket opcode {opcode}")),
        }
        Ok(())
    }

    fn queue_control_response(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        let response = client_control_frame(opcode, payload);
        let next_bytes = self
            .control_response_bytes
            .checked_add(response.len())
            .ok_or_else(|| "websocket control response queue length overflow".to_owned())?;
        if next_bytes > WEBSOCKET_MAX_QUEUED_CONTROL_RESPONSE_BYTES {
            return Err(format!(
                "websocket control response queue exceeds {} bytes",
                WEBSOCKET_MAX_QUEUED_CONTROL_RESPONSE_BYTES
            ));
        }
        self.control_response_bytes = next_bytes;
        self.control_responses.push_back(response);
        Ok(())
    }
}

struct ParsedWebSocketFrame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
    encoded_len: usize,
}

fn parse_frame(input: &[u8]) -> Result<Option<ParsedWebSocketFrame>, String> {
    if input.len() < 2 {
        return Ok(None);
    }
    if input[0] & 0x70 != 0 {
        return Err("websocket RSV bits require an unsupported extension".to_owned());
    }

    let fin = input[0] & WEBSOCKET_FIN != 0;
    let opcode = input[0] & 0x0f;
    let control = opcode & 0x08 != 0;
    let masked = input[1] & WEBSOCKET_MASK != 0;
    let length_code = input[1] & 0x7f;
    let (payload_len, mut header_len): (usize, usize) = match length_code {
        126 => {
            if input.len() < 4 {
                return Ok(None);
            }
            (u16::from_be_bytes([input[2], input[3]]) as usize, 4)
        }
        127 => {
            if input.len() < 10 {
                return Ok(None);
            }
            if input[2] & 0x80 != 0 {
                return Err("websocket 64-bit length has its reserved bit set".to_owned());
            }
            let encoded =
                u64::from_be_bytes(input[2..10].try_into().map_err(|_| {
                    "websocket 64-bit length header could not be decoded".to_owned()
                })?);
            let decoded = usize::try_from(encoded)
                .map_err(|_| "websocket payload length does not fit this host".to_owned())?;
            (decoded, 10)
        }
        short => (short as usize, 2),
    };

    if control && (!fin || payload_len > WEBSOCKET_CONTROL_MAX_BYTES) {
        return Err(format!(
            "invalid websocket control frame: fin={fin} length={payload_len}"
        ));
    }
    if opcode == WEBSOCKET_OPCODE_CLOSE && payload_len == 1 {
        return Err("websocket close frame cannot contain a one-byte payload".to_owned());
    }
    if payload_len > RESIDENT_WEBSOCKET_MAX_MESSAGE_BYTES {
        return Err(format!(
            "websocket frame exceeds {} bytes",
            RESIDENT_WEBSOCKET_MAX_MESSAGE_BYTES
        ));
    }

    let mask_key = if masked {
        let mask_end = header_len
            .checked_add(4)
            .ok_or_else(|| "websocket mask header length overflow".to_owned())?;
        if input.len() < mask_end {
            return Ok(None);
        }
        let key: [u8; 4] = input[header_len..mask_end]
            .try_into()
            .map_err(|_| "websocket mask key could not be decoded".to_owned())?;
        header_len = mask_end;
        Some(key)
    } else {
        None
    };
    let encoded_len = header_len
        .checked_add(payload_len)
        .ok_or_else(|| "websocket encoded frame length overflow".to_owned())?;
    if input.len() < encoded_len {
        return Ok(None);
    }

    let mut payload = input[header_len..encoded_len].to_vec();
    if let Some(mask_key) = mask_key {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask_key[index % mask_key.len()];
        }
    }
    Ok(Some(ParsedWebSocketFrame {
        fin,
        opcode,
        payload,
        encoded_len,
    }))
}

fn client_control_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    debug_assert!(matches!(
        opcode,
        WEBSOCKET_OPCODE_CLOSE | WEBSOCKET_OPCODE_PONG
    ));
    debug_assert!(payload.len() <= WEBSOCKET_CONTROL_MAX_BYTES);

    let mask_key = websocket_client_mask_key();
    let mut frame = Vec::with_capacity(2 + mask_key.len() + payload.len());
    frame.push(WEBSOCKET_FIN | opcode);
    frame.push(WEBSOCKET_MASK | payload.len() as u8);
    frame.extend_from_slice(&mask_key);
    frame.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask_key[index % mask_key.len()]),
    );
    frame
}
