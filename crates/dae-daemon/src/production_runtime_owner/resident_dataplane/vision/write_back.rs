use super::*;
pub(crate) async fn write_pending_after_vision_mode_async(
    pending: &mut Vec<u8>,
    client: &mut AsyncVlessTlsClient,
    stop: &AtomicBool,
    mode: VisionUplinkMode,
) -> Result<bool, String> {
    match mode {
        VisionUplinkMode::Padding => Ok(false),
        VisionUplinkMode::PlainOverlay => {
            if !pending.is_empty() {
                let tail = std::mem::take(pending);
                client
                    .write_plain_all(&tail, "write pending Vision plain-overlay tail")
                    .await?;
            }
            Ok(true)
        }
        VisionUplinkMode::Direct => {
            if !pending.is_empty() && !stop.load(Ordering::Relaxed) {
                let tail = std::mem::take(pending);
                client
                    .raw_write_all(&tail, "write VLESS Vision direct uplink payload")
                    .await?;
            }
            Ok(true)
        }
    }
}
