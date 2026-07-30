use std::future::poll_fn;

use super::*;

mod driver;
use self::driver::*;

const VISION_RELAY_COOPERATIVE_BUDGET: usize = 32;

pub(super) async fn relay_tcp_over_vless_vision_duplex(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    client: &mut AsyncVlessTlsClient,
    stop: SharedResidentStopSignal,
    user_uuid: [u8; 16],
    initial_payload: Vec<u8>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<RelayStats, RelayError> {
    let initial_payload_len = initial_payload.len();
    let mut driver = VisionDuplexDriver::new(user_uuid, initial_payload)
        .map_err(|error| RelayError::new(error, &RelayStats::default()))?;
    if initial_payload_len > 0 {
        metrics.add_upload(initial_payload_len);
    }

    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    let close_drain_deadline =
        resident_relay_idle_deadline(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);
    tokio::pin!(close_drain_deadline);
    let mut close_drain_active = false;
    let mut progress_without_yield = 0_usize;

    loop {
        let event = tokio::select! {
            biased;
            _ = stop_listener.cancelled() => return Ok(driver.stats().clone()),
            result = poll_fn(|cx| driver.poll_cycle(cx, inbound, client, metrics)) => {
                result.map_err(|error| RelayError::new(error, driver.stats()))?
            }
            _ = &mut close_drain_deadline, if close_drain_active => {
                return Ok(driver.stats().clone());
            }
            _ = &mut idle_deadline => {
                return Err(RelayError::new(
                    "resident TCP relay idle timeout",
                    driver.stats(),
                ));
            }
        };

        match event {
            VisionDriverEvent::Progress => {
                reset_resident_relay_idle_deadline(
                    idle_deadline.as_mut(),
                    RESIDENT_TCP_IDLE_TIMEOUT,
                );
                if driver.inbound_closed() {
                    if !close_drain_active {
                        close_drain_active = true;
                    }
                    reset_resident_relay_idle_deadline(
                        close_drain_deadline.as_mut(),
                        RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT,
                    );
                }
                progress_without_yield += 1;
                if progress_without_yield >= VISION_RELAY_COOPERATIVE_BUDGET {
                    progress_without_yield = 0;
                    tokio::task::yield_now().await;
                }
            }
            VisionDriverEvent::Complete => return Ok(driver.stats().clone()),
        }
    }
}

#[cfg(test)]
mod tests;
