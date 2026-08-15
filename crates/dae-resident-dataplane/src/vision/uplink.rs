use std::collections::VecDeque;

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VisionUplinkWriteMode {
    PlainOverlay,
    DirectPass,
}

#[derive(Debug)]
pub(crate) struct VisionUplinkWrite {
    pub(crate) mode: VisionUplinkWriteMode,
    pub(crate) payload: Vec<u8>,
}

fn queue_vision_write(
    writes: &mut VecDeque<VisionUplinkWrite>,
    mode: VisionUplinkWriteMode,
    payload: Vec<u8>,
) {
    if !payload.is_empty() {
        writes.push_back(VisionUplinkWrite { mode, payload });
    }
}

pub(crate) fn queue_vision_uplink(
    pending: &mut Vec<u8>,
    writes: &mut VecDeque<VisionUplinkWrite>,
    user_uuid: [u8; 16],
    uuid_sent: &mut bool,
    first_block: &mut bool,
    state: &mut VisionUplinkState,
    tls_state: &mut VisionInnerTlsState,
) -> Result<(), String> {
    match *state {
        VisionUplinkState::PlainOverlay => {
            queue_vision_write(
                writes,
                VisionUplinkWriteMode::PlainOverlay,
                std::mem::take(pending),
            );
            return Ok(());
        }
        VisionUplinkState::DirectPass => {
            queue_vision_write(
                writes,
                VisionUplinkWriteMode::DirectPass,
                std::mem::take(pending),
            );
            return Ok(());
        }
        VisionUplinkState::Padding => {}
    }

    if *first_block && !pending.is_empty() {
        let payload = std::mem::take(pending);
        tls_state.observe_client_payload(&payload)?;
        let long_padding = looks_like_tls_record_start(&payload);
        queue_vision_write(
            writes,
            VisionUplinkWriteMode::PlainOverlay,
            vision_padding_block(
                &payload,
                VISION_COMMAND_CONTINUE,
                user_uuid,
                uuid_sent,
                long_padding,
            ),
        );
        *first_block = false;
        return Ok(());
    }

    while !pending.is_empty() && *state == VisionUplinkState::Padding {
        if !should_continue_vision_tls_filtering(pending, tls_state) {
            let payload = std::mem::take(pending);
            queue_vision_write(
                writes,
                VisionUplinkWriteMode::PlainOverlay,
                vision_padding_block(&payload, VISION_COMMAND_END, user_uuid, uuid_sent, false),
            );
            *state = VisionUplinkState::PlainOverlay;
            return Ok(());
        }
        let Some((record_type, record_len)) = peek_complete_tls_record(pending)? else {
            return Ok(());
        };
        // Xray assigns DIRECT/END to the final complete TLS record in one
        // write batch.  Assigning it to the first application record causes
        // any following record from the same socket read to bypass VLESS
        // Encryption too early; the peer then sees that tail before its own
        // Vision direct transition.  A complete prefix followed by a partial
        // record remains padded and is retried when the next read completes it.
        let command =
            if record_type == TLS_CONTENT_TYPE_APPLICATION_DATA && record_len == pending.len() {
                vision_uplink_command(record_type, tls_state)
            } else {
                Some(VISION_COMMAND_CONTINUE)
            };
        let Some(command) = command else {
            return Ok(());
        };
        let record = take_vec_prefix(pending, record_len);
        tls_state.observe_client_payload(&record)?;
        queue_vision_write(
            writes,
            VisionUplinkWriteMode::PlainOverlay,
            vision_padding_block(&record, command, user_uuid, uuid_sent, true),
        );
        match command {
            VISION_COMMAND_END => *state = VisionUplinkState::PlainOverlay,
            VISION_COMMAND_DIRECT => *state = VisionUplinkState::DirectPass,
            _ => {}
        }
    }

    match *state {
        VisionUplinkState::Padding => {}
        VisionUplinkState::PlainOverlay => queue_vision_write(
            writes,
            VisionUplinkWriteMode::PlainOverlay,
            std::mem::take(pending),
        ),
        VisionUplinkState::DirectPass => queue_vision_write(
            writes,
            VisionUplinkWriteMode::DirectPass,
            std::mem::take(pending),
        ),
    }
    Ok(())
}
