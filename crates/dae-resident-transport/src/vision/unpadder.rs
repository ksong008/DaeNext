use super::*;
pub struct VisionUnpadder {
    pub user_uuid: [u8; 16],
    pub pending: Vec<u8>,
    pub state: VisionUnpadState,
    pub completed_blocks: usize,
    pub direct_command_seen: bool,
}

#[derive(Clone, Debug)]
pub enum VisionUnpadState {
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
    pub fn new(user_uuid: [u8; 16]) -> Self {
        Self {
            user_uuid,
            pending: Vec::new(),
            state: VisionUnpadState::Initial,
            completed_blocks: 0,
            direct_command_seen: false,
        }
    }

    pub fn consume_shared<'a>(
        &mut self,
        input: std::borrow::Cow<'a, [u8]>,
    ) -> Result<std::borrow::Cow<'a, [u8]>, String> {
        if matches!(self.state, VisionUnpadState::Raw) {
            return Ok(input);
        }
        self.consume(&input).map(std::borrow::Cow::Owned)
    }

    pub fn consume(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        if matches!(self.state, VisionUnpadState::Raw) {
            return Ok(input.to_vec());
        }
        self.pending.extend_from_slice(input);
        let mut out = Vec::new();
        let mut cursor = 0;
        loop {
            match self.state.clone() {
                VisionUnpadState::Initial => {
                    if self.pending.len() - cursor < 21 {
                        break;
                    }
                    if self.pending[cursor..cursor + 16] != self.user_uuid {
                        self.state = VisionUnpadState::Raw;
                        out.extend_from_slice(&self.pending[cursor..]);
                        cursor = self.pending.len();
                        break;
                    }
                    cursor += 16;
                    self.state = VisionUnpadState::BlockHeader;
                }
                VisionUnpadState::BlockHeader => {
                    if self.pending.len() - cursor < 5 {
                        break;
                    }
                    let command = self.pending[cursor];
                    let remaining_content =
                        u16::from_be_bytes([self.pending[cursor + 1], self.pending[cursor + 2]])
                            as usize;
                    let remaining_padding =
                        u16::from_be_bytes([self.pending[cursor + 3], self.pending[cursor + 4]])
                            as usize;
                    if !matches!(
                        command,
                        VISION_COMMAND_CONTINUE | VISION_COMMAND_END | VISION_COMMAND_DIRECT
                    ) {
                        // Keep the invalid header at the front on error, just as
                        // on an incomplete read. A retry must not parse the UUID
                        // or already-consumed blocks as another header.
                        self.pending.drain(..cursor);
                        return Err(format!("unexpected VLESS Vision command: {command}"));
                    }
                    cursor += 5;
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
                        let take = remaining_content.min(self.pending.len() - cursor);
                        out.extend_from_slice(&self.pending[cursor..cursor + take]);
                        cursor += take;
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
                        let take = remaining_padding.min(self.pending.len() - cursor);
                        cursor += take;
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
                            out.extend_from_slice(&self.pending[cursor..]);
                            cursor = self.pending.len();
                            break;
                        }
                        VISION_COMMAND_DIRECT => {
                            self.direct_command_seen = true;
                            self.state = VisionUnpadState::Raw;
                            out.extend_from_slice(&self.pending[cursor..]);
                            cursor = self.pending.len();
                            break;
                        }
                        _ => unreachable!(),
                    }
                }
                VisionUnpadState::Raw => {
                    out.extend_from_slice(&self.pending[cursor..]);
                    cursor = self.pending.len();
                    break;
                }
            }
        }
        // Compact once per read, rather than shifting the suffix after every
        // UUID, block header, content chunk and padding chunk.
        self.pending.drain(..cursor);
        Ok(out)
    }
}
