use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use crate::vision::vision_padding_block;
use crate::{VISION_COMMAND_DIRECT, VISION_COMMAND_END};

use super::*;

#[derive(Default)]
struct ScriptedInbound {
    reads: VecDeque<Vec<u8>>,
    read_closed: bool,
    block_writes: bool,
    write_chunk_limit: Option<usize>,
    writes: Vec<u8>,
}

impl AsyncRead for ScriptedInbound {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(mut payload) = self.reads.pop_front() else {
            return if self.read_closed {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            };
        };
        let read = payload.len().min(buf.remaining());
        buf.put_slice(&payload[..read]);
        if read < payload.len() {
            payload.drain(..read);
            self.reads.push_front(payload);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedInbound {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.block_writes {
            return Poll::Pending;
        }
        let written = self
            .write_chunk_limit
            .unwrap_or(payload.len())
            .min(payload.len());
        self.writes.extend_from_slice(&payload[..written]);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyPollEvent {
    PlainWrite,
    PlainFlush,
    RawWrite,
    RawFlush,
}

#[derive(Default)]
struct ScriptedProxy {
    plain_reads: VecDeque<Vec<u8>>,
    raw_reads: VecDeque<Vec<u8>>,
    plain_read_closed: bool,
    raw_read_closed: bool,
    plain_read_error: Option<io::ErrorKind>,
    block_plain_writes: bool,
    block_raw_writes: bool,
    plain_writes: Vec<u8>,
    raw_writes: Vec<u8>,
    raw_read_polls: usize,
    outer_record_handoff_ready: bool,
    outer_record_handoff_sticky: bool,
    outer_record_handoffs_taken: usize,
    events: Vec<ProxyPollEvent>,
}

impl ScriptedProxy {
    fn poll_scripted_read(
        reads: &mut VecDeque<Vec<u8>>,
        closed: bool,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(mut payload) = reads.pop_front() else {
            return if closed {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            };
        };
        let read = payload.len().min(buf.remaining());
        buf.put_slice(&payload[..read]);
        if read < payload.len() {
            payload.drain(..read);
            reads.push_front(payload);
        }
        Poll::Ready(Ok(()))
    }
}

impl VisionProxyIo for ScriptedProxy {
    fn poll_vision_plain_read(
        &mut self,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(kind) = self.plain_read_error.take() {
            return Poll::Ready(Err(io::Error::from(kind)));
        }
        Self::poll_scripted_read(&mut self.plain_reads, self.plain_read_closed, buf)
    }

    fn poll_vision_plain_write(
        &mut self,
        _cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.block_plain_writes {
            return Poll::Pending;
        }
        self.events.push(ProxyPollEvent::PlainWrite);
        self.plain_writes.extend_from_slice(payload);
        Poll::Ready(Ok(payload.len()))
    }

    fn poll_vision_plain_flush(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.events.push(ProxyPollEvent::PlainFlush);
        Poll::Ready(Ok(()))
    }

    fn poll_vision_plain_shutdown(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_vision_raw_read(
        &mut self,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.raw_read_polls += 1;
        Self::poll_scripted_read(&mut self.raw_reads, self.raw_read_closed, buf)
    }

    fn poll_vision_raw_write(
        &mut self,
        _cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.block_raw_writes {
            return Poll::Pending;
        }
        self.events.push(ProxyPollEvent::RawWrite);
        self.raw_writes.extend_from_slice(payload);
        Poll::Ready(Ok(payload.len()))
    }

    fn poll_vision_raw_flush(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.events.push(ProxyPollEvent::RawFlush);
        Poll::Ready(Ok(()))
    }

    fn poll_vision_raw_shutdown(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn take_vision_outer_record_handoff(&mut self) -> bool {
        let ready = self.outer_record_handoff_ready || self.outer_record_handoff_sticky;
        if ready {
            if !self.outer_record_handoff_sticky {
                self.outer_record_handoff_ready = false;
            }
            self.outer_record_handoffs_taken += 1;
        }
        ready
    }
}

#[derive(Default)]
struct WakeCounter {
    count: AtomicUsize,
}

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

fn vision_response(user_uuid: [u8; 16], command: u8, payload: &[u8]) -> Vec<u8> {
    let mut uuid_sent = false;
    let mut response = vec![VLESS_RESPONSE_VERSION, 0];
    response.extend_from_slice(&vision_padding_block(
        payload,
        command,
        user_uuid,
        &mut uuid_sent,
        false,
    ));
    response
}

fn poll_driver(
    driver: &mut VisionDuplexDriver,
    inbound: &mut ScriptedInbound,
    proxy: &mut ScriptedProxy,
    metrics: &ResidentDataplaneMetrics,
) -> Poll<Result<VisionDriverEvent, String>> {
    poll_driver_with_waker(driver, inbound, proxy, metrics, Waker::noop())
}

fn poll_driver_with_waker(
    driver: &mut VisionDuplexDriver,
    inbound: &mut ScriptedInbound,
    proxy: &mut ScriptedProxy,
    metrics: &ResidentDataplaneMetrics,
    waker: &Waker,
) -> Poll<Result<VisionDriverEvent, String>> {
    let mut cx = Context::from_waker(waker);
    driver.poll_cycle(&mut cx, inbound, proxy, metrics)
}

#[test]
fn proxy_upload_backpressure_does_not_block_vision_download() {
    let user_uuid = [0x31; 16];
    let mut driver = VisionDuplexDriver::new(user_uuid, b"blocked upload".to_vec()).unwrap();
    let mut inbound = ScriptedInbound::default();
    let mut proxy = ScriptedProxy {
        block_plain_writes: true,
        plain_reads: VecDeque::from([vision_response(user_uuid, VISION_COMMAND_END, b"download")]),
        ..ScriptedProxy::default()
    };
    let metrics = ResidentDataplaneMetrics::default();

    assert!(matches!(
        poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics),
        Poll::Ready(Ok(VisionDriverEvent::Progress))
    ));
    assert!(proxy.plain_writes.is_empty());
    assert!(matches!(
        poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics),
        Poll::Ready(Ok(VisionDriverEvent::Progress))
    ));
    assert_eq!(inbound.writes, b"download");
    assert!(proxy.plain_writes.is_empty());
}

#[test]
fn blocked_inbound_download_does_not_block_vision_upload() {
    let user_uuid = [0x42; 16];
    let mut driver = VisionDuplexDriver::new(user_uuid, b"first".to_vec()).unwrap();
    let mut inbound = ScriptedInbound {
        reads: VecDeque::from([b"second".to_vec()]),
        block_writes: true,
        ..ScriptedInbound::default()
    };
    let mut proxy = ScriptedProxy {
        plain_reads: VecDeque::from([vision_response(
            user_uuid,
            VISION_COMMAND_END,
            b"blocked download",
        )]),
        ..ScriptedProxy::default()
    };
    let metrics = ResidentDataplaneMetrics::default();

    for _ in 0..8 {
        let _ = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);
    }

    assert!(inbound.writes.is_empty());
    assert!(
        proxy
            .plain_writes
            .windows(b"first".len())
            .any(|window| window == b"first")
    );
    assert!(
        proxy
            .plain_writes
            .windows(b"second".len())
            .any(|window| window == b"second")
    );
    assert_eq!(driver.stats().client_to_proxy, b"firstsecond".len());
    assert_eq!(driver.uplink_state(), VisionUplinkState::PlainOverlay);
}

#[test]
fn downlink_direct_switch_does_not_force_uplink_direct() {
    let user_uuid = [0x53; 16];
    let mut driver = VisionDuplexDriver::new(user_uuid, Vec::new()).unwrap();
    let mut inbound = ScriptedInbound::default();
    let mut proxy = ScriptedProxy {
        plain_reads: VecDeque::from([vision_response(user_uuid, VISION_COMMAND_DIRECT, b"framed")]),
        raw_reads: VecDeque::from([b"raw".to_vec()]),
        outer_record_handoff_ready: true,
        ..ScriptedProxy::default()
    };
    let metrics = ResidentDataplaneMetrics::default();

    for _ in 0..4 {
        let _ = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);
    }

    assert!(driver.downlink_direct());
    assert!(driver.stats().vision_raw_direct_recovered);
    assert!(driver.stats().vision_downlink_direct_active);
    assert_eq!(driver.uplink_state(), VisionUplinkState::Padding);
    assert!(proxy.raw_read_polls > 0);
    assert_eq!(inbound.writes, b"framedraw");
}

#[test]
fn downlink_direct_switch_waits_for_outer_record_handoff() {
    let user_uuid = [0x54; 16];
    let mut driver = VisionDuplexDriver::new(user_uuid, Vec::new()).unwrap();
    let mut inbound = ScriptedInbound::default();
    let mut proxy = ScriptedProxy {
        plain_reads: VecDeque::from([vision_response(user_uuid, VISION_COMMAND_DIRECT, b"framed")]),
        raw_reads: VecDeque::from([b"raw".to_vec()]),
        ..ScriptedProxy::default()
    };
    let metrics = ResidentDataplaneMetrics::default();

    assert!(matches!(
        poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics),
        Poll::Ready(Ok(VisionDriverEvent::Progress))
    ));
    let _ = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);
    assert!(!driver.downlink_direct());
    assert!(!driver.stats().vision_raw_direct_recovered);
    assert!(!driver.stats().vision_downlink_direct_active);
    assert_eq!(proxy.raw_read_polls, 0);
    assert_eq!(inbound.writes, b"framed");

    proxy.outer_record_handoff_ready = true;
    assert!(matches!(
        poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics),
        Poll::Ready(Ok(VisionDriverEvent::Progress))
    ));
    assert!(driver.downlink_direct());
    assert!(driver.stats().vision_raw_direct_recovered);
    assert!(driver.stats().vision_downlink_direct_active);
    assert_eq!(proxy.raw_read_polls, 1);

    for _ in 0..2 {
        let _ = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);
    }
    assert_eq!(inbound.writes, b"framedraw");
}

#[test]
fn downlink_direct_switch_drains_buffered_plaintext_before_raw_tail() {
    let user_uuid = [0x55; 16];
    let mut driver = VisionDuplexDriver::new(user_uuid, Vec::new()).unwrap();
    let mut inbound = ScriptedInbound::default();
    let mut proxy = ScriptedProxy {
        plain_reads: VecDeque::from([
            vision_response(user_uuid, VISION_COMMAND_DIRECT, b"framed"),
            b"buffered".to_vec(),
        ]),
        raw_reads: VecDeque::from([b"raw".to_vec()]),
        outer_record_handoff_ready: true,
        ..ScriptedProxy::default()
    };
    let metrics = ResidentDataplaneMetrics::default();

    for _ in 0..8 {
        let _ = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);
    }

    assert!(driver.downlink_direct());
    assert!(driver.stats().vision_raw_direct_recovered);
    assert!(driver.stats().vision_downlink_direct_active);
    assert!(proxy.raw_read_polls > 0);
    assert_eq!(inbound.writes, b"framedbufferedraw");
}

#[test]
fn overlay_releases_exactly_one_outer_record_after_plaintext_drains() {
    let user_uuid = [0x56; 16];
    let mut driver = VisionDuplexDriver::new(user_uuid, Vec::new()).unwrap();
    let mut inbound = ScriptedInbound::default();
    let mut proxy = ScriptedProxy {
        plain_reads: VecDeque::from([vision_response(user_uuid, VISION_COMMAND_END, b"first")]),
        outer_record_handoff_ready: true,
        ..ScriptedProxy::default()
    };
    let metrics = ResidentDataplaneMetrics::default();

    let _ = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);
    let _ = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);

    assert_eq!(inbound.writes, b"first");
    assert_eq!(proxy.outer_record_handoffs_taken, 1);
    assert!(!proxy.outer_record_handoff_ready);
}

#[test]
fn direct_pass_idle_raw_read_does_not_self_wake() {
    let user_uuid = [0x57; 16];
    let mut driver = VisionDuplexDriver::new(user_uuid, Vec::new()).unwrap();
    let mut inbound = ScriptedInbound::default();
    let mut proxy = ScriptedProxy {
        plain_reads: VecDeque::from([vision_response(user_uuid, VISION_COMMAND_DIRECT, b"framed")]),
        ..ScriptedProxy::default()
    };
    let metrics = ResidentDataplaneMetrics::default();
    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));

    let _ = poll_driver_with_waker(&mut driver, &mut inbound, &mut proxy, &metrics, &waker);
    let _ = poll_driver_with_waker(&mut driver, &mut inbound, &mut proxy, &metrics, &waker);
    proxy.outer_record_handoff_ready = true;

    assert!(matches!(
        poll_driver_with_waker(&mut driver, &mut inbound, &mut proxy, &metrics, &waker,),
        Poll::Pending
    ));
    assert!(driver.downlink_direct());
    assert_eq!(proxy.outer_record_handoffs_taken, 1);
    assert!(!proxy.outer_record_handoff_ready);
    assert_eq!(proxy.raw_read_polls, 1);
    assert_eq!(wake_counter.count.load(Ordering::Relaxed), 0);

    assert!(matches!(
        poll_driver_with_waker(&mut driver, &mut inbound, &mut proxy, &metrics, &waker,),
        Poll::Pending
    ));
    assert_eq!(proxy.raw_read_polls, 2);
    assert_eq!(wake_counter.count.load(Ordering::Relaxed), 0);
}

#[test]
fn sticky_outer_handoff_is_not_reinterpreted_as_a_raw_read_event() {
    let user_uuid = [0x59; 16];
    let mut driver = VisionDuplexDriver::new(user_uuid, Vec::new()).unwrap();
    let mut inbound = ScriptedInbound::default();
    let mut proxy = ScriptedProxy {
        plain_reads: VecDeque::from([vision_response(user_uuid, VISION_COMMAND_DIRECT, b"framed")]),
        outer_record_handoff_sticky: true,
        ..ScriptedProxy::default()
    };
    let metrics = ResidentDataplaneMetrics::default();
    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));

    let _ = poll_driver_with_waker(&mut driver, &mut inbound, &mut proxy, &metrics, &waker);
    let _ = poll_driver_with_waker(&mut driver, &mut inbound, &mut proxy, &metrics, &waker);
    assert!(driver.downlink_direct());
    assert_eq!(proxy.raw_read_polls, 1);
    assert_eq!(wake_counter.count.load(Ordering::Relaxed), 0);

    // A sticky handoff must not make an idle DirectPass socket spin. One raw
    // poll is enough; the driver returns Pending and lets the underlay waker
    // schedule the next cycle.
    assert!(matches!(
        poll_driver_with_waker(&mut driver, &mut inbound, &mut proxy, &metrics, &waker),
        Poll::Pending
    ));
    assert_eq!(proxy.raw_read_polls, 2);
    assert_eq!(wake_counter.count.load(Ordering::Relaxed), 0);
}

#[test]
fn overlay_record_handoff_repolls_socket_without_self_wake() {
    let mut driver = VisionDuplexDriver::new([0x58; 16], Vec::new()).unwrap();
    let mut inbound = ScriptedInbound::default();
    let mut proxy = ScriptedProxy {
        outer_record_handoff_ready: true,
        ..ScriptedProxy::default()
    };
    let metrics = ResidentDataplaneMetrics::default();
    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));

    assert!(matches!(
        poll_driver_with_waker(&mut driver, &mut inbound, &mut proxy, &metrics, &waker),
        Poll::Pending
    ));
    assert_eq!(proxy.outer_record_handoffs_taken, 1);
    assert_eq!(wake_counter.count.load(Ordering::Relaxed), 0);
}

#[test]
fn uplink_direct_flushes_overlay_command_before_raw_tail() {
    let user_uuid = [0x64; 16];
    let mut driver = VisionDuplexDriver::new(user_uuid, Vec::new()).unwrap();
    let mut inbound = ScriptedInbound {
        reads: VecDeque::from([b"first".to_vec()]),
        ..ScriptedInbound::default()
    };
    let mut proxy = ScriptedProxy::default();
    let metrics = ResidentDataplaneMetrics::default();

    for _ in 0..4 {
        let _ = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);
    }
    driver.force_uplink_decision(VisionTlsDecision::Direct);
    inbound.reads.push_back(vec![23, 3, 3, 0, 1, 0xaa]);
    inbound.reads.push_back(b"tail".to_vec());

    for _ in 0..10 {
        let _ = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);
    }

    assert_eq!(driver.uplink_state(), VisionUplinkState::DirectPass);
    assert_eq!(proxy.raw_writes, b"tail");
    let last_plain_flush = proxy
        .events
        .iter()
        .rposition(|event| *event == ProxyPollEvent::PlainFlush)
        .unwrap();
    let first_raw_write = proxy
        .events
        .iter()
        .position(|event| *event == ProxyPollEvent::RawWrite)
        .unwrap();
    assert!(last_plain_flush < first_raw_write);
}

#[test]
fn partial_tls_record_stays_bounded_and_is_not_forwarded_early() {
    let user_uuid = [0x75; 16];
    let mut driver = VisionDuplexDriver::new(user_uuid, b"first".to_vec()).unwrap();
    let mut inbound = ScriptedInbound {
        reads: VecDeque::from([vec![23, 3, 3, 0, 5, 0xaa]]),
        ..ScriptedInbound::default()
    };
    let mut proxy = ScriptedProxy::default();
    let metrics = ResidentDataplaneMetrics::default();

    driver.force_client_tls_filter_active();
    for _ in 0..6 {
        let _ = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);
    }

    assert_eq!(driver.pending_uplink_input_len(), 6);
    assert!(!proxy.raw_writes.contains(&0xaa));
}

#[test]
fn inbound_half_close_keeps_vision_download_alive() {
    let user_uuid = [0x86; 16];
    let mut driver = VisionDuplexDriver::new(user_uuid, Vec::new()).unwrap();
    let mut inbound = ScriptedInbound {
        read_closed: true,
        ..ScriptedInbound::default()
    };
    let mut proxy = ScriptedProxy::default();
    let metrics = ResidentDataplaneMetrics::default();

    assert!(matches!(
        poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics),
        Poll::Ready(Ok(VisionDriverEvent::Progress))
    ));
    assert!(driver.inbound_closed());

    proxy.plain_reads.push_back(vision_response(
        user_uuid,
        VISION_COMMAND_END,
        b"after half close",
    ));
    for _ in 0..3 {
        let _ = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);
    }

    assert_eq!(inbound.writes, b"after half close");
    assert_eq!(driver.stats().proxy_to_client, b"after half close".len());
}

#[test]
fn remote_reset_preserves_partial_stats_in_terminal_error() {
    let user_uuid = [0x97; 16];
    let mut driver = VisionDuplexDriver::new(user_uuid, b"counted".to_vec()).unwrap();
    let mut inbound = ScriptedInbound::default();
    let mut proxy = ScriptedProxy {
        plain_read_error: Some(io::ErrorKind::ConnectionReset),
        ..ScriptedProxy::default()
    };
    let metrics = ResidentDataplaneMetrics::default();

    let result = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);

    assert!(matches!(result, Poll::Ready(Err(error)) if error.contains("proxy response")));
    assert_eq!(driver.stats().client_to_proxy, b"counted".len());
    assert_eq!(driver.stats().proxy_to_client, 0);
}

#[test]
fn download_stats_commit_once_after_the_complete_payload_write() {
    let user_uuid = [0xa7; 16];
    let mut driver = VisionDuplexDriver::new(user_uuid, Vec::new()).unwrap();
    let mut inbound = ScriptedInbound {
        write_chunk_limit: Some(3),
        ..ScriptedInbound::default()
    };
    let mut proxy = ScriptedProxy {
        plain_reads: VecDeque::from([vision_response(user_uuid, VISION_COMMAND_END, b"seven77")]),
        ..ScriptedProxy::default()
    };
    let metrics = ResidentDataplaneMetrics::default();

    let _ = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);
    let _ = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);
    assert_eq!(driver.stats().proxy_to_client, 0);
    let _ = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);
    assert_eq!(driver.stats().proxy_to_client, 0);
    let _ = poll_driver(&mut driver, &mut inbound, &mut proxy, &metrics);

    assert_eq!(inbound.writes, b"seven77");
    assert_eq!(driver.stats().proxy_to_client, b"seven77".len());
}

#[test]
fn initial_vision_payload_rejects_unbounded_retention() {
    let error = VisionDuplexDriver::new(
        [0xa8; 16],
        vec![0; VISION_PENDING_UPLINK_LIMIT.saturating_add(1)],
    )
    .err()
    .expect("oversized initial payload must fail");

    assert!(error.contains("did not form complete TLS records"));
}
