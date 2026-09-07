use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::*;

const RAW_TCP_RELAY_BUFFER_SIZE: usize = 64 * 1024;
const RAW_TCP_RELAY_INITIAL_BUFFER_SIZE: usize = 16 * 1024;
const RAW_TCP_RELAY_COOPERATIVE_BUDGET: usize = 32;
const RAW_TCP_BUFFER_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Default)]
struct RawTcpRelayDirection {
    buffer: Vec<u8>,
    buffer_last_used: Option<time::Instant>,
    filled: usize,
    written: usize,
    grow_on_next_read: bool,
    source_closed: bool,
    sink_shutdown: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RawTcpDirectionPoll {
    progressed: bool,
    completed_bytes: usize,
    complete: bool,
}

impl RawTcpRelayDirection {
    fn reclaim_deadline(&self) -> Option<time::Instant> {
        if self.filled != 0 || self.buffer.capacity() == 0 {
            return None;
        }
        self.buffer_last_used
            .map(|used| used + RAW_TCP_BUFFER_IDLE_TIMEOUT)
    }

    fn reclaim_if_idle(&mut self, now: time::Instant) {
        if self
            .reclaim_deadline()
            .is_some_and(|deadline| now >= deadline)
        {
            self.buffer = Vec::new();
            self.buffer_last_used = None;
            self.grow_on_next_read = false;
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        source: &mut TokioTcpStream,
        sink: &mut TokioTcpStream,
        buffer_size: usize,
        read_error: &'static str,
        write_error: &'static str,
    ) -> Poll<Result<RawTcpDirectionPoll, String>> {
        let mut state = RawTcpDirectionPoll::default();

        if self.written < self.filled {
            match Pin::new(&mut *sink).poll_write(cx, &self.buffer[self.written..self.filled]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(format!(
                        "{write_error}: {}",
                        io::Error::from(io::ErrorKind::WriteZero)
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    self.written += written;
                    state.progressed = true;
                    if self.written == self.filled {
                        state.completed_bytes = self.filled;
                        self.filled = 0;
                        self.written = 0;
                    }
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(format!("{write_error}: {error}")));
                }
                Poll::Pending => {}
            }
        }

        if self.filled == 0 && !self.source_closed {
            if self.buffer.is_empty() {
                match source.poll_read_ready(cx) {
                    Poll::Pending => {
                        return if state.progressed {
                            Poll::Ready(Ok(state))
                        } else {
                            Poll::Pending
                        };
                    }
                    Poll::Ready(Err(error)) => {
                        return Poll::Ready(Err(format!("{read_error}: {error}")));
                    }
                    Poll::Ready(Ok(_)) => {}
                }
                self.buffer_last_used = Some(time::Instant::now());
                self.buffer
                    .resize(buffer_size.min(RAW_TCP_RELAY_INITIAL_BUFFER_SIZE), 0);
            } else if self.grow_on_next_read && self.buffer.len() < buffer_size {
                let next_size = self.buffer.len().saturating_mul(2).min(buffer_size);
                self.buffer.resize(next_size.max(self.buffer.len()), 0);
                self.grow_on_next_read = false;
            }
            let mut read_buffer = ReadBuf::new(&mut self.buffer);
            match Pin::new(&mut *source).poll_read(cx, &mut read_buffer) {
                Poll::Ready(Ok(())) => {
                    let read = read_buffer.filled().len();
                    state.progressed = true;
                    if read == 0 {
                        self.source_closed = true;
                    } else {
                        self.filled = read;
                        self.grow_on_next_read = read == self.buffer.len();
                    }
                }
                Poll::Ready(Err(error)) if is_graceful_stream_close_error(&error) => {
                    self.source_closed = true;
                    state.progressed = true;
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(format!("{read_error}: {error}")));
                }
                Poll::Pending => {}
            }
        }

        if self.written < self.filled {
            match Pin::new(&mut *sink).poll_write(cx, &self.buffer[self.written..self.filled]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(format!(
                        "{write_error}: {}",
                        io::Error::from(io::ErrorKind::WriteZero)
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    self.written += written;
                    state.progressed = true;
                    if self.written == self.filled {
                        state.completed_bytes = state.completed_bytes.saturating_add(self.filled);
                        self.filled = 0;
                        self.written = 0;
                    }
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(format!("{write_error}: {error}")));
                }
                Poll::Pending => {}
            }
        }

        if self.source_closed && self.filled == 0 && !self.sink_shutdown {
            match Pin::new(&mut *sink).poll_shutdown(cx) {
                Poll::Ready(Ok(())) => {
                    self.sink_shutdown = true;
                    state.progressed = true;
                }
                Poll::Ready(Err(error)) if is_graceful_stream_close_error(&error) => {
                    self.sink_shutdown = true;
                    state.progressed = true;
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(format!("shutdown after {write_error}: {error}")));
                }
                Poll::Pending => {}
            }
        }

        if state.progressed {
            self.buffer_last_used = Some(time::Instant::now());
        }
        state.complete = self.source_closed && self.filled == 0 && self.sink_shutdown;
        if state.progressed || state.complete {
            Poll::Ready(Ok(state))
        } else {
            Poll::Pending
        }
    }
}

struct RawTcpRelayDriver {
    upload: RawTcpRelayDirection,
    download: RawTcpRelayDirection,
    stats: DirectTcpRelayStats,
    buffer_size: usize,
}

impl RawTcpRelayDriver {
    fn with_buffer_size(stats: DirectTcpRelayStats, buffer_size: usize) -> Self {
        Self {
            upload: RawTcpRelayDirection::default(),
            download: RawTcpRelayDirection::default(),
            stats,
            buffer_size: buffer_size.max(1),
        }
    }

    fn poll_cycle(
        &mut self,
        cx: &mut Context<'_>,
        inbound: &mut TokioTcpStream,
        direct: &mut TokioTcpStream,
        metrics: &ResidentDataplaneMetrics,
    ) -> Poll<Result<bool, String>> {
        let upload = match self.upload.poll(
            cx,
            inbound,
            direct,
            self.buffer_size,
            "read inbound TCP for direct relay",
            "write client payload to direct TCP",
        ) {
            Poll::Ready(Ok(state)) => Some(state),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => None,
        };
        let download = match self.download.poll(
            cx,
            direct,
            inbound,
            self.buffer_size,
            "read direct TCP",
            "write direct TCP payload to client",
        ) {
            Poll::Ready(Ok(state)) => Some(state),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => None,
        };

        if let Some(upload) = upload
            && upload.completed_bytes > 0
        {
            self.stats.client_to_direct = self
                .stats
                .client_to_direct
                .saturating_add(upload.completed_bytes);
            metrics.add_upload(upload.completed_bytes);
        }
        if let Some(download) = download
            && download.completed_bytes > 0
        {
            self.stats.direct_to_client = self
                .stats
                .direct_to_client
                .saturating_add(download.completed_bytes);
            metrics.add_download(download.completed_bytes);
        }
        if download.is_some_and(|state| state.complete) {
            return Poll::Ready(Ok(true));
        }
        if upload.is_some_and(|state| state.progressed)
            || download.is_some_and(|state| state.progressed)
        {
            Poll::Ready(Ok(false))
        } else {
            Poll::Pending
        }
    }
}

pub async fn relay_raw_tcp_streams(
    inbound: &mut TokioTcpStream,
    direct: &mut TokioTcpStream,
    stop: SharedResidentStopSignal,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    relay_raw_tcp_streams_with_buffer_size(
        inbound,
        direct,
        stop,
        stats,
        metrics,
        RAW_TCP_RELAY_BUFFER_SIZE,
    )
    .await
}

pub async fn relay_raw_tcp_streams_with_buffer_size(
    inbound: &mut TokioTcpStream,
    direct: &mut TokioTcpStream,
    stop: SharedResidentStopSignal,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    buffer_size: usize,
) -> Result<DirectTcpRelayStats, String> {
    let mut driver = RawTcpRelayDriver::with_buffer_size(stats, buffer_size);
    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);
    let mut progress_without_yield = 0_usize;

    loop {
        // Reclaim each drained direction before polling I/O so a busy opposite
        // direction cannot starve the idle side's timer branch.
        let now = time::Instant::now();
        driver.upload.reclaim_if_idle(now);
        driver.download.reclaim_if_idle(now);
        let buffer_deadline = [
            driver.upload.reclaim_deadline(),
            driver.download.reclaim_deadline(),
        ]
        .into_iter()
        .flatten()
        .min();
        let buffer_timer = time::sleep_until(buffer_deadline.unwrap_or_else(time::Instant::now));
        tokio::pin!(buffer_timer);
        let complete = tokio::select! {
            biased;
            _ = stop_listener.cancelled() => return Ok(driver.stats),
            result = std::future::poll_fn(|cx| driver.poll_cycle(cx, inbound, direct, metrics)) => {
                result?
            }
            _ = &mut buffer_timer, if buffer_deadline.is_some() => {
                let now = time::Instant::now();
                driver.upload.reclaim_if_idle(now);
                driver.download.reclaim_if_idle(now);
                continue;
            }
            _ = &mut idle_deadline => {
                return Err("resident direct TCP relay idle timeout".to_owned());
            }
        };
        if complete {
            return Ok(driver.stats);
        }
        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
        progress_without_yield += 1;
        if progress_without_yield >= RAW_TCP_RELAY_COOPERATIVE_BUDGET {
            progress_without_yield = 0;
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(test)]
mod reclaim_tests {
    use super::*;

    #[tokio::test]
    async fn reclaimed_direction_stays_empty_until_readable_and_preserves_pending_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TokioTcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut source, _) = listener.accept().await.unwrap();
        let mut output = TokioTcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut sink, _) = listener.accept().await.unwrap();
        let mut direction = RawTcpRelayDirection {
            buffer: vec![7; RAW_TCP_RELAY_BUFFER_SIZE],
            buffer_last_used: Some(time::Instant::now() - RAW_TCP_BUFFER_IDLE_TIMEOUT),
            filled: 3,
            ..RawTcpRelayDirection::default()
        };
        direction.reclaim_if_idle(time::Instant::now());
        assert_eq!(direction.buffer.capacity(), RAW_TCP_RELAY_BUFFER_SIZE);
        std::future::poll_fn(|cx| {
            direction.poll(
                cx,
                &mut source,
                &mut sink,
                RAW_TCP_RELAY_BUFFER_SIZE,
                "read",
                "write",
            )
        })
        .await
        .unwrap();
        let mut pending = [0; 3];
        output.read_exact(&mut pending).await.unwrap();
        assert_eq!(pending, [7; 3]);
        direction.buffer_last_used = Some(time::Instant::now() - RAW_TCP_BUFFER_IDLE_TIMEOUT);
        direction.reclaim_if_idle(time::Instant::now());
        assert_eq!(direction.buffer.capacity(), 0);
        assert!(
            time::timeout(
                Duration::from_millis(20),
                std::future::poll_fn(|cx| direction.poll(
                    cx,
                    &mut source,
                    &mut sink,
                    RAW_TCP_RELAY_BUFFER_SIZE,
                    "read",
                    "write"
                ))
            )
            .await
            .is_err()
        );
        assert_eq!(direction.buffer.capacity(), 0);
        client.write_all(b"resumed").await.unwrap();
        std::future::poll_fn(|cx| {
            direction.poll(
                cx,
                &mut source,
                &mut sink,
                RAW_TCP_RELAY_BUFFER_SIZE,
                "read",
                "write",
            )
        })
        .await
        .unwrap();
        let mut resumed = [0; 7];
        output.read_exact(&mut resumed).await.unwrap();
        assert_eq!(&resumed, b"resumed");
    }
}
