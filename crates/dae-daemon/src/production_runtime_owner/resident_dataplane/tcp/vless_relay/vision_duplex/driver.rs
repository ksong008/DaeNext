use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::*;

const VISION_RELAY_BUFFER_SIZE: usize = 16 * 1024;
pub(super) const VISION_PENDING_UPLINK_LIMIT: usize = TLS_RECORD_MAX_PAYLOAD_LEN * 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisionDownlinkState {
    Overlay,
    DirectPass,
}

pub(super) trait VisionProxyIo {
    fn poll_vision_plain_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>>;

    fn poll_vision_plain_write(
        &mut self,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<usize>>;

    fn poll_vision_plain_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    fn poll_vision_plain_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    fn poll_vision_raw_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>>;

    fn poll_vision_raw_write(
        &mut self,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<usize>>;

    fn poll_vision_raw_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    fn poll_vision_raw_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

impl VisionProxyIo for AsyncVlessTlsClient {
    fn poll_vision_plain_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_plain_read(cx, buf)
    }

    fn poll_vision_plain_write(
        &mut self,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_plain_write(cx, payload)
    }

    fn poll_vision_plain_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_plain_flush(cx)
    }

    fn poll_vision_plain_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_plain_shutdown(cx)
    }

    fn poll_vision_raw_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_raw_read(cx, buf)
    }

    fn poll_vision_raw_write(
        &mut self,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_raw_write(cx, payload)
    }

    fn poll_vision_raw_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_raw_flush(cx)
    }

    fn poll_vision_raw_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_raw_shutdown(cx)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum VisionDriverEvent {
    Progress,
    Complete,
}

pub(super) struct VisionDuplexDriver {
    user_uuid: [u8; 16],
    stats: RelayStats,
    response_stripper: VlessResponseStripper,
    unpadder: VisionUnpadder,
    inner_tls: VisionInnerTlsState,
    uplink_state: VisionUplinkState,
    downlink_state: VisionDownlinkState,
    uplink_uuid_sent: bool,
    first_uplink_block: bool,
    pending_uplink_input: Vec<u8>,
    pending_uplink_writes: VecDeque<VisionUplinkWrite>,
    uplink_write_offset: usize,
    uplink_flush_pending: bool,
    pending_downlink: Vec<u8>,
    downlink_write_offset: usize,
    inbound_buffer: [u8; VISION_RELAY_BUFFER_SIZE],
    proxy_buffer: [u8; VISION_RELAY_BUFFER_SIZE],
    inbound_closed: bool,
    proxy_closed: bool,
    proxy_write_shutdown: bool,
}

impl VisionDuplexDriver {
    pub(super) fn new(user_uuid: [u8; 16], initial_payload: Vec<u8>) -> Result<Self, String> {
        let initial_payload_len = initial_payload.len();
        if initial_payload_len > VISION_PENDING_UPLINK_LIMIT {
            return Err(pending_uplink_limit_error(initial_payload_len));
        }
        let mut driver = Self {
            user_uuid,
            stats: RelayStats {
                client_to_proxy: initial_payload_len,
                ..RelayStats::default()
            },
            response_stripper: VlessResponseStripper::default(),
            unpadder: VisionUnpadder::new(user_uuid),
            inner_tls: VisionInnerTlsState::new(),
            uplink_state: VisionUplinkState::Padding,
            downlink_state: VisionDownlinkState::Overlay,
            uplink_uuid_sent: false,
            first_uplink_block: true,
            pending_uplink_input: initial_payload,
            pending_uplink_writes: VecDeque::new(),
            uplink_write_offset: 0,
            uplink_flush_pending: false,
            pending_downlink: Vec::new(),
            downlink_write_offset: 0,
            inbound_buffer: [0; VISION_RELAY_BUFFER_SIZE],
            proxy_buffer: [0; VISION_RELAY_BUFFER_SIZE],
            inbound_closed: false,
            proxy_closed: false,
            proxy_write_shutdown: false,
        };
        driver.queue_uplink()?;
        Ok(driver)
    }

    pub(super) fn stats(&self) -> &RelayStats {
        &self.stats
    }

    pub(super) fn inbound_closed(&self) -> bool {
        self.inbound_closed
    }

    #[cfg(test)]
    pub(super) fn uplink_state(&self) -> VisionUplinkState {
        self.uplink_state
    }

    #[cfg(test)]
    pub(super) fn downlink_direct(&self) -> bool {
        self.downlink_state == VisionDownlinkState::DirectPass
    }

    #[cfg(test)]
    pub(super) fn pending_uplink_input_len(&self) -> usize {
        self.pending_uplink_input.len()
    }

    #[cfg(test)]
    pub(super) fn force_uplink_decision(&mut self, decision: VisionTlsDecision) {
        self.inner_tls.client_tls_observed = true;
        self.inner_tls.decision = decision;
    }

    #[cfg(test)]
    pub(super) fn force_client_tls_filter_active(&mut self) {
        self.inner_tls.client_tls_observed = true;
    }

    fn queue_uplink(&mut self) -> Result<(), String> {
        queue_vision_uplink(
            &mut self.pending_uplink_input,
            &mut self.pending_uplink_writes,
            self.user_uuid,
            &mut self.uplink_uuid_sent,
            &mut self.first_uplink_block,
            &mut self.uplink_state,
            &mut self.inner_tls,
        )
    }

    pub(super) fn poll_cycle<IO, Proxy>(
        &mut self,
        cx: &mut Context<'_>,
        inbound: &mut IO,
        client: &mut Proxy,
        metrics: &ResidentDataplaneMetrics,
    ) -> Poll<Result<VisionDriverEvent, String>>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + ?Sized,
        Proxy: VisionProxyIo + ?Sized,
    {
        let mut progressed = false;

        if self.poll_downlink_write(cx, inbound, metrics)? {
            progressed = true;
        }
        if self.poll_uplink_write(cx, client)? {
            progressed = true;
        }

        if self.proxy_closed && self.pending_downlink.is_empty() {
            match Pin::new(&mut *inbound).poll_shutdown(cx) {
                Poll::Ready(Ok(())) => {
                    return Poll::Ready(Ok(VisionDriverEvent::Complete));
                }
                Poll::Ready(Err(error)) if is_graceful_stream_close_error(&error) => {
                    return Poll::Ready(Ok(VisionDriverEvent::Complete));
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(format!(
                        "shutdown inbound TCP after VLESS Vision response: {error}"
                    )));
                }
                Poll::Pending => {}
            }
        }

        if !self.proxy_closed && self.pending_downlink.is_empty() {
            match self.poll_proxy_read(cx, client) {
                Ok(Poll::Ready(0)) => {
                    self.proxy_closed = true;
                    progressed = true;
                }
                Ok(Poll::Ready(_)) => progressed = true,
                Ok(Poll::Pending) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
        }

        if !self.proxy_closed && !self.inbound_closed && self.pending_uplink_writes.is_empty() {
            match self.poll_inbound_read(cx, inbound, metrics) {
                Ok(Poll::Ready(0)) => {
                    self.inbound_closed = true;
                    self.pending_uplink_input = Vec::new();
                    progressed = true;
                }
                Ok(Poll::Ready(_)) => progressed = true,
                Ok(Poll::Pending) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
        }

        if self.inbound_closed
            && self.pending_uplink_writes.is_empty()
            && !self.proxy_write_shutdown
        {
            let shutdown = match self.uplink_state {
                VisionUplinkState::DirectPass => client.poll_vision_raw_shutdown(cx),
                VisionUplinkState::Padding | VisionUplinkState::PlainOverlay => {
                    client.poll_vision_plain_shutdown(cx)
                }
            };
            match shutdown {
                Poll::Ready(Ok(())) => {
                    self.proxy_write_shutdown = true;
                    progressed = true;
                }
                Poll::Ready(Err(error)) if is_graceful_stream_close_error(&error) => {
                    self.proxy_write_shutdown = true;
                    progressed = true;
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(format!(
                        "shutdown VLESS Vision proxy upload: {error}"
                    )));
                }
                Poll::Pending => {}
            }
        }

        if progressed {
            Poll::Ready(Ok(VisionDriverEvent::Progress))
        } else {
            Poll::Pending
        }
    }

    fn poll_uplink_write<Proxy>(
        &mut self,
        cx: &mut Context<'_>,
        client: &mut Proxy,
    ) -> Result<bool, String>
    where
        Proxy: VisionProxyIo + ?Sized,
    {
        let Some(write) = self.pending_uplink_writes.front() else {
            return Ok(false);
        };
        if self.uplink_write_offset < write.payload.len() {
            let payload = &write.payload[self.uplink_write_offset..];
            let result = match write.mode {
                VisionUplinkWriteMode::PlainOverlay => client.poll_vision_plain_write(cx, payload),
                VisionUplinkWriteMode::DirectPass => client.poll_vision_raw_write(cx, payload),
            };
            return match result {
                Poll::Ready(Ok(0)) => Err(io::Error::from(io::ErrorKind::WriteZero).to_string()),
                Poll::Ready(Ok(written)) => {
                    self.uplink_write_offset += written;
                    if self.uplink_write_offset == write.payload.len() {
                        self.uplink_flush_pending = true;
                    }
                    Ok(true)
                }
                Poll::Ready(Err(error)) => {
                    Err(format!("write VLESS Vision uplink payload: {error}"))
                }
                Poll::Pending => Ok(false),
            };
        }

        if self.uplink_flush_pending {
            let result = match write.mode {
                VisionUplinkWriteMode::PlainOverlay => client.poll_vision_plain_flush(cx),
                VisionUplinkWriteMode::DirectPass => client.poll_vision_raw_flush(cx),
            };
            match result {
                Poll::Ready(Ok(())) => {
                    self.pending_uplink_writes.pop_front();
                    self.uplink_write_offset = 0;
                    self.uplink_flush_pending = false;
                    return Ok(true);
                }
                Poll::Ready(Err(error)) => {
                    return Err(format!("flush VLESS Vision uplink payload: {error}"));
                }
                Poll::Pending => return Ok(false),
            }
        }

        Ok(false)
    }

    fn poll_downlink_write<IO>(
        &mut self,
        cx: &mut Context<'_>,
        inbound: &mut IO,
        metrics: &ResidentDataplaneMetrics,
    ) -> Result<bool, String>
    where
        IO: AsyncWrite + Unpin + ?Sized,
    {
        if self.downlink_write_offset >= self.pending_downlink.len() {
            return Ok(false);
        }
        match Pin::new(inbound).poll_write(cx, &self.pending_downlink[self.downlink_write_offset..])
        {
            Poll::Ready(Ok(0)) => Err(io::Error::from(io::ErrorKind::WriteZero).to_string()),
            Poll::Ready(Ok(written)) => {
                self.downlink_write_offset += written;
                if self.downlink_write_offset == self.pending_downlink.len() {
                    self.stats.proxy_to_client += self.pending_downlink.len();
                    metrics.add_download(self.pending_downlink.len());
                    self.pending_downlink.clear();
                    self.downlink_write_offset = 0;
                }
                Ok(true)
            }
            Poll::Ready(Err(error)) if is_graceful_stream_close_error(&error) => {
                self.proxy_closed = true;
                self.pending_downlink.clear();
                self.downlink_write_offset = 0;
                Ok(true)
            }
            Poll::Ready(Err(error)) => Err(format!(
                "write VLESS Vision payload to inbound TCP: {error}"
            )),
            Poll::Pending => Ok(false),
        }
    }

    fn poll_proxy_read<Proxy>(
        &mut self,
        cx: &mut Context<'_>,
        client: &mut Proxy,
    ) -> Result<Poll<usize>, String>
    where
        Proxy: VisionProxyIo + ?Sized,
    {
        let mut read_buffer = tokio::io::ReadBuf::new(&mut self.proxy_buffer);
        let result = match self.downlink_state {
            VisionDownlinkState::Overlay => client.poll_vision_plain_read(cx, &mut read_buffer),
            VisionDownlinkState::DirectPass => client.poll_vision_raw_read(cx, &mut read_buffer),
        };
        match result {
            Poll::Ready(Ok(())) => {
                let read = read_buffer.filled().len();
                if read == 0 {
                    return Ok(Poll::Ready(0));
                }
                let payload = match self.downlink_state {
                    VisionDownlinkState::Overlay => {
                        let stripped =
                            self.response_stripper.consume(&self.proxy_buffer[..read])?;
                        self.stats.response_header_stripped = self.response_stripper.done;
                        if stripped.is_empty() {
                            Vec::new()
                        } else {
                            let payload = self.unpadder.consume(&stripped)?;
                            self.inner_tls.observe_server_payload(&payload)?;
                            self.stats.vision_unpadding_blocks = self.unpadder.completed_blocks;
                            self.stats.vision_direct_command_seen =
                                self.unpadder.direct_command_seen;
                            if self.unpadder.direct_command_seen {
                                self.downlink_state = VisionDownlinkState::DirectPass;
                                self.stats.vision_downlink_direct_active = true;
                            }
                            self.queue_uplink()?;
                            payload
                        }
                    }
                    VisionDownlinkState::DirectPass => self.proxy_buffer[..read].to_vec(),
                };
                self.pending_downlink = payload;
                self.downlink_write_offset = 0;
                Ok(Poll::Ready(read))
            }
            Poll::Ready(Err(error)) => {
                if self.downlink_state == VisionDownlinkState::Overlay
                    && is_graceful_vless_response_tls_plain_close_error(&error, &self.stats)
                {
                    Ok(Poll::Ready(0))
                } else if self.downlink_state == VisionDownlinkState::DirectPass
                    && is_graceful_stream_close_error(&error)
                {
                    Ok(Poll::Ready(0))
                } else {
                    Err(format!("read VLESS Vision proxy response: {error}"))
                }
            }
            Poll::Pending => Ok(Poll::Pending),
        }
    }

    fn poll_inbound_read<IO>(
        &mut self,
        cx: &mut Context<'_>,
        inbound: &mut IO,
        metrics: &ResidentDataplaneMetrics,
    ) -> Result<Poll<usize>, String>
    where
        IO: AsyncRead + Unpin + ?Sized,
    {
        let mut read_buffer = tokio::io::ReadBuf::new(&mut self.inbound_buffer);
        match Pin::new(inbound).poll_read(cx, &mut read_buffer) {
            Poll::Ready(Ok(())) => {
                let read = read_buffer.filled().len();
                if read == 0 {
                    return Ok(Poll::Ready(0));
                }
                self.pending_uplink_input
                    .extend_from_slice(&self.inbound_buffer[..read]);
                if self.pending_uplink_input.len() > VISION_PENDING_UPLINK_LIMIT {
                    return Err(pending_uplink_limit_error(self.pending_uplink_input.len()));
                }
                self.queue_uplink()?;
                self.stats.client_to_proxy += read;
                metrics.add_upload(read);
                Ok(Poll::Ready(read))
            }
            Poll::Ready(Err(error)) if is_graceful_stream_close_error(&error) => Ok(Poll::Ready(0)),
            Poll::Ready(Err(error)) => Err(format!("read inbound TCP for VLESS Vision: {error}")),
            Poll::Pending => Ok(Poll::Pending),
        }
    }
}

fn pending_uplink_limit_error(bytes: usize) -> String {
    format!("pending Vision uplink payload did not form complete TLS records: {bytes} bytes")
}
