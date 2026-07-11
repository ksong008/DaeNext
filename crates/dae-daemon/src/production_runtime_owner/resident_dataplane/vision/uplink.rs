use super::*;

// Vision uplink state is intentionally explicit across padding, UUID, and TLS tracking.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn drain_vision_uplink_async(
    pending: &mut Vec<u8>,
    client: &mut AsyncVlessTlsClient,
    stop: &ResidentStopSignal,
    user_uuid: [u8; 16],
    uuid_sent: &mut bool,
    first_block: &mut bool,
    mode: &mut VisionUplinkMode,
    tls_state: &mut VisionInnerTlsState,
) -> Result<(), String> {
    if write_pending_after_vision_mode_async(pending, client, stop, *mode).await? {
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
        client
            .write_plain_all(
                &block,
                &format!(
                    "write VLESS Vision uplink {} block",
                    vision_command_name(VISION_COMMAND_CONTINUE)
                ),
            )
            .await?;
        *first_block = false;
        return Ok(());
    }

    while !pending.is_empty() && *mode == VisionUplinkMode::Padding {
        if !should_continue_vision_tls_filtering(pending, tls_state) {
            let payload = std::mem::take(pending);
            let block =
                vision_padding_block(&payload, VISION_COMMAND_END, user_uuid, uuid_sent, false);
            client
                .write_plain_all(
                    &block,
                    &format!(
                        "write VLESS Vision uplink {} block",
                        vision_command_name(VISION_COMMAND_END)
                    ),
                )
                .await?;
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
        let record = take_vec_prefix(pending, record_len);
        tls_state.observe_client_payload(&record)?;
        let block = vision_padding_block(&record, command, user_uuid, uuid_sent, true);
        client
            .write_plain_all(
                &block,
                &format!(
                    "write VLESS Vision uplink {} block",
                    vision_command_name(command)
                ),
            )
            .await?;
        match command {
            VISION_COMMAND_END => *mode = VisionUplinkMode::PlainOverlay,
            VISION_COMMAND_DIRECT => *mode = VisionUplinkMode::Direct,
            _ => {}
        }
    }
    let _ = write_pending_after_vision_mode_async(pending, client, stop, *mode).await?;
    Ok(())
}
