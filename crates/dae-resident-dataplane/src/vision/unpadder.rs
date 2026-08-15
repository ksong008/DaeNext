use super::*;
pub(crate) struct VisionUnpadder {
    pub(crate) user_uuid: [u8; 16],
    pub(crate) pending: Vec<u8>,
    pub(crate) state: VisionUnpadState,
    pub(crate) completed_blocks: usize,
    pub(crate) direct_command_seen: bool,
}

#[derive(Clone, Debug)]
pub(crate) enum VisionUnpadState {
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
    pub(crate) fn new(user_uuid: [u8; 16]) -> Self {
        Self {
            user_uuid,
            pending: Vec::new(),
            state: VisionUnpadState::Initial,
            completed_blocks: 0,
            direct_command_seen: false,
        }
    }

    pub(crate) fn consume(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
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
                        out.append(&mut self.pending);
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
                            out.append(&mut self.pending);
                            break;
                        }
                        VISION_COMMAND_DIRECT => {
                            self.direct_command_seen = true;
                            self.state = VisionUnpadState::Raw;
                            out.append(&mut self.pending);
                            break;
                        }
                        _ => unreachable!(),
                    }
                }
                VisionUnpadState::Raw => {
                    out.append(&mut self.pending);
                    break;
                }
            }
        }
        Ok(out)
    }
}
