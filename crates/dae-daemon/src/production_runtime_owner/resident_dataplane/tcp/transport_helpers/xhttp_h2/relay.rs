use super::client_io::{
    read_xhttp_download_data, send_xhttp_packet_up_request, send_xhttp_stream_data,
};
use super::*;
use bytes::Bytes;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_xhttp_packet_up(
    inbound: &mut TokioTcpStream,
    upload: &mut XhttpUploadClient,
    download: &mut XhttpDownloadClient,
    session_id: &str,
    mut seq: u64,
    stop: Arc<AtomicBool>,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut inbound_closed = false;
    let mut response_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut response_stripper = VlessResponseStripper::default();

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        send_xhttp_packet_up_request(
                            upload,
                            session_id,
                            seq,
                            Bytes::copy_from_slice(&inbound_buf[..read]),
                        )
                        .await?;
                        seq = seq.saturating_add(1);
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for xHTTP relay: {err}")),
                }
            }
            data = read_xhttp_download_data(download), if !response_closed => {
                match data? {
                    Some(bytes) => {
                        let payload = response_stripper.consume(&bytes)?;
                        if !payload.is_empty() {
                            inbound
                                .write_all(&payload)
                                .await
                                .map_err(|err| format!("write xHTTP response to inbound: {err}"))?;
                            stats.direct_to_client += payload.len();
                            metrics.add_download(payload.len());
                        }
                        last_activity = Instant::now();
                    }
                    None => {
                        response_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {
                if response_closed || (inbound_closed && response_closed) {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident xHTTP relay idle timeout".to_owned());
                }
            }
        }
    }
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_xhttp_stream(
    inbound: &mut TokioTcpStream,
    upload: &mut XhttpStreamUploadClient,
    download: &mut XhttpDownloadClient,
    stop: Arc<AtomicBool>,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut inbound_closed = false;
    let mut response_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut response_stripper = VlessResponseStripper::default();

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(0) => {
                        send_xhttp_stream_data(upload, Bytes::new(), true).await?;
                        inbound_closed = true;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        send_xhttp_stream_data(
                            upload,
                            Bytes::copy_from_slice(&inbound_buf[..read]),
                            false,
                        )
                        .await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        send_xhttp_stream_data(upload, Bytes::new(), true).await?;
                        inbound_closed = true;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for xHTTP stream relay: {err}")),
                }
            }
            data = read_xhttp_download_data(download), if !response_closed => {
                match data? {
                    Some(bytes) => {
                        let payload = response_stripper.consume(&bytes)?;
                        if !payload.is_empty() {
                            inbound
                                .write_all(&payload)
                                .await
                                .map_err(|err| format!("write xHTTP stream response to inbound: {err}"))?;
                            stats.direct_to_client += payload.len();
                            metrics.add_download(payload.len());
                        }
                        last_activity = Instant::now();
                    }
                    None => {
                        response_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {
                if response_closed || (inbound_closed && response_closed) {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident xHTTP stream relay idle timeout".to_owned());
                }
            }
        }
    }
    Ok(stats)
}
