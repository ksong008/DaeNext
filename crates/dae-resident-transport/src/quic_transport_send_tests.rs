use super::*;
use quinn::AsyncUdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Default)]
struct CaptureSocket {
    blocked: AtomicBool,
    sent: Mutex<Vec<(Vec<u8>, Option<usize>)>>,
}
impl quinn::AsyncUdpSocket for CaptureSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        unreachable!()
    }
    fn try_send(&self, tx: &udp::Transmit<'_>) -> io::Result<()> {
        if self.blocked.swap(false, Ordering::SeqCst) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.sent
            .lock()
            .unwrap()
            .push((tx.contents.to_vec(), tx.segment_size));
        Ok(())
    }
    fn poll_recv(
        &self,
        _: &mut Context<'_>,
        _: &mut [IoSliceMut<'_>],
        _: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:1".parse().unwrap())
    }
    fn max_transmit_segments(&self) -> usize {
        64
    }
    fn max_receive_segments(&self) -> usize {
        64
    }
}

#[test]
fn gso_uses_independent_salts_and_a_short_tail_without_replaying_prefix_on_retry() {
    let inner = Arc::new(CaptureSocket::default());
    inner.blocked.store(true, Ordering::SeqCst);
    let socket = Hysteria2SalamanderUdpSocket {
        inner: inner.clone(),
        key: Arc::new(b"test".to_vec()),
        send_state: Mutex::new(SalamanderSendState::new()),
    };
    let payload: Vec<u8> = (0..2705).map(|i| (i % 251) as u8).collect();
    let transmit = udp::Transmit {
        destination: "127.0.0.1:443".parse().unwrap(),
        contents: &payload,
        segment_size: Some(1200),
        src_ip: None,
        ecn: None,
    };
    assert_eq!(
        socket.try_send(&transmit).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(inner.sent.lock().unwrap().is_empty());
    socket.try_send(&transmit).unwrap();
    let sent = inner.sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].1, Some(1208));
    assert_eq!(socket.max_transmit_segments(), 32);
    let mut salts = std::collections::HashSet::new();
    let mut decoded = Vec::new();
    for packet in sent[0].0.chunks(1208) {
        let salt: [u8; 8] = packet[..8].try_into().unwrap();
        assert!(salts.insert(salt));
        let mut data = packet[8..].to_vec();
        salamander_xor_in_place(&mut data, &salamander_hash(&socket.key, &salt));
        decoded.extend_from_slice(&data);
    }
    assert_eq!(decoded, payload);
    assert_eq!(salts.len(), 3);
}
