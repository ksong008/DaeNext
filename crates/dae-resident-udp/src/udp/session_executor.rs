use super::*;

mod identity_cache;
use identity_cache::ProtocolIdentityCache;

#[cfg(test)]
use crate::plan::{ResidentUdpExecutionAgreement, ResidentUdpExecutionDisposition};

#[allow(private_interfaces)]
pub enum UdpSessionExecutor {
    Dns,
    ShadowsocksAead(ShadowsocksAeadDatagramSession),
    Shadowsocks2022(Shadowsocks2022DatagramSession),
    Socks5(Socks5UdpAssociateSession),
    VlessStandard(VlessStandardUdpOverStreamSession),
    VlessVision(VlessXudpStreamSession),
    VlessXhttpH2(VlessXhttpH2UdpSession),
    VlessXhttpH3(VlessXhttpH3UdpSession),
    Trojan(TrojanUdpStreamSession),
    VmessAead(VmessAeadUdpOverTcpSession),
    AnyTls(AnyTlsPacketStreamSession),
    Hysteria2(Hysteria2QuicDatagramSession),
    Tuic(TuicQuicPacketSession),
    Juicity(JuicityQuicStreamPacketSession),
    FailClosed { reason: String },
}

impl UdpSessionExecutor {
    /// Wire-size failures are local to one packet and must be rejected before
    /// touching a shared relay socket or cancelling other DNS transactions.
    pub fn validate_datagram_payload_size(
        binding: &ResidentProxyBinding,
        target: SocketAddr,
        len: usize,
    ) -> Result<(), String> {
        let address = if target.is_ipv4() { 7usize } else { 19 };
        let overhead = match &binding.plan().handler {
            ResidentProxyProtocolPlan::ShadowsocksAeadTcp { salt_len, .. } => {
                salt_len + 16 + address
            }
            ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
                password,
                packet_nonce_len,
                ..
            } => {
                // Session/packet ID (16), type/timestamp/padding length (11),
                // and AEAD tag (16). AES adds an identity header per extra PSK;
                // XChaCha carries a nonce and has no separate identity headers.
                let identities = if *packet_nonce_len == 0 {
                    password
                        .split(':')
                        .count()
                        .saturating_sub(1)
                        .saturating_mul(16)
                } else {
                    0
                };
                16usize
                    .saturating_add(11)
                    .saturating_add(16)
                    .saturating_add(address)
                    .saturating_add(*packet_nonce_len)
                    .saturating_add(identities)
            }
            ResidentProxyProtocolPlan::Socks5Tcp { .. } => 3 + address,
            _ => return Ok(()),
        };
        // Bound the IP datagram of the relay's underlay, whose family can differ
        // from the target encoded in the SOCKS address. IPv4 is the smaller cap.
        let limit = 65507usize.saturating_sub(overhead);
        if len > limit {
            return Err(format!(
                "proxied UDP payload exceeds datagram wire limit: {len} > {limit}"
            ));
        }
        Ok(())
    }

    pub(super) fn execution_stage(&self) -> &'static str {
        match self {
            Self::Hysteria2(session) => session.execution_stage,
            Self::Tuic(session) => session.execution_stage,
            _ => "protocol-exchange",
        }
    }

    pub fn set_runtime_metrics(&mut self, metrics: Arc<ResidentDataplaneMetrics>) {
        if let Self::Shadowsocks2022(session) = self {
            session.set_runtime_metrics(metrics);
        }
    }

    pub fn set_owner_acquisition_deadline(
        &mut self,
        deadline: dae_runtime_control::AbsoluteDeadline,
    ) {
        match self {
            Self::AnyTls(session) => session.set_owner_deadline(deadline),
            Self::Hysteria2(session) => session.set_owner_deadline(deadline),
            Self::Tuic(session) => session.set_owner_deadline(deadline),
            Self::Juicity(session) => session.set_owner_deadline(deadline),
            _ => {}
        }
    }

    pub fn response_buffer_reclaim_deadline(&self, timeout: Duration) -> Option<time::Instant> {
        match self {
            Self::ShadowsocksAead(session) => session.response_buffer_reclaim_deadline(timeout),
            Self::Shadowsocks2022(session) => session.response_buffer_reclaim_deadline(timeout),
            Self::Socks5(session) => session.response_buffer_reclaim_deadline(timeout),
            _ => None,
        }
    }

    pub fn reclaim_response_buffer_if_idle(
        &mut self,
        now: time::Instant,
        timeout: Duration,
    ) -> bool {
        self.response_buffer_reclaim_deadline(timeout)
            .is_some_and(|deadline| now >= deadline)
            && self.reclaim_response_buffer()
    }

    pub fn has_response_buffer(&self) -> bool {
        match self {
            Self::ShadowsocksAead(session) => session.has_response_buffer(),
            Self::Shadowsocks2022(session) => session.has_response_buffer(),
            Self::Socks5(session) => session.has_response_buffer(),
            _ => false,
        }
    }

    pub fn reclaim_response_buffer(&mut self) -> bool {
        match self {
            Self::ShadowsocksAead(session) => session.reclaim_response_buffer(),
            Self::Shadowsocks2022(session) => session.reclaim_response_buffer(),
            Self::Socks5(session) => session.reclaim_response_buffer(),
            _ => false,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn runtime_disposition(&self) -> Option<ResidentUdpExecutionDisposition> {
        match self {
            Self::Dns => None,
            Self::FailClosed { .. } => Some(ResidentUdpExecutionDisposition::PolicyClosed),
            Self::ShadowsocksAead(_)
            | Self::Shadowsocks2022(_)
            | Self::Socks5(_)
            | Self::VlessStandard(_)
            | Self::VlessVision(_)
            | Self::VlessXhttpH2(_)
            | Self::VlessXhttpH3(_)
            | Self::Trojan(_)
            | Self::VmessAead(_)
            | Self::AnyTls(_)
            | Self::Hysteria2(_)
            | Self::Tuic(_)
            | Self::Juicity(_) => Some(ResidentUdpExecutionDisposition::PacketRelay),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn agrees_with(&self, agreement: ResidentUdpExecutionAgreement) -> bool {
        self.runtime_disposition() == Some(agreement.disposition())
            && match self {
                Self::FailClosed { reason } => {
                    agreement.unsupported_reason() == Some(reason.as_str())
                }
                Self::Dns => false,
                _ => agreement.unsupported_reason().is_none(),
            }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn test_shape(&self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::ShadowsocksAead(_) => "shadowsocks-aead",
            Self::Shadowsocks2022(_) => "shadowsocks-2022",
            Self::Socks5(_) => "socks5",
            Self::VlessStandard(_) => "vless-standard",
            Self::VlessVision(_) => "vless-vision",
            Self::VlessXhttpH2(_) => "vless-xhttp-h2",
            Self::VlessXhttpH3(_) => "vless-xhttp-h3",
            Self::Trojan(_) => "trojan",
            Self::VmessAead(_) => "vmess-aead",
            Self::AnyTls(_) => "anytls",
            Self::Hysteria2(_) => "hysteria2",
            Self::Tuic(_) => "tuic",
            Self::Juicity(_) => "juicity",
            Self::FailClosed { .. } => "fail-closed",
        }
    }
}

const UDP_DATAGRAM_RESPONSE_CAPACITY: usize = 64 * 1024;

mod connect_udp;
mod datagram;
mod datagram_batch;
mod dispatch;
mod dns_send;
pub use self::dns_send::{ProxyDnsUdpSend, ProxyDnsUdpSendCompletion};
mod selection;
#[cfg(any(test, feature = "test-support"))]
mod test_support;
mod wait;
pub use self::connect_udp::{
    clear_connect_udp_h2_pools, clear_connect_udp_h3_pools, connect_udp_pool_metrics_snapshot,
};
use self::datagram::*;
#[cfg(any(test, feature = "test-support"))]
pub use self::test_support::{ProxyUdpSessionCheckpoint, exercise_proxy_udp_packet_session};

mod anytls;
mod quic;
mod shadowsocks;
mod socks5;
mod trojan;
mod vless;
mod vless_standard;
use self::anytls::AnyTlsPacketStreamSession;
#[cfg(any(test, feature = "test-support"))]
pub use self::anytls::exercise_anytls_udp_stream_session;
#[cfg(any(test, feature = "test-support"))]
pub use self::quic::exercise_juicity_udp_stream_session;
use self::quic::{
    Hysteria2QuicDatagramSession, JuicityQuicStreamPacketSession, TuicQuicPacketSession,
};
use self::shadowsocks::{Shadowsocks2022DatagramSession, ShadowsocksAeadDatagramSession};
use self::socks5::Socks5UdpAssociateSession;
use self::trojan::TrojanUdpStreamSession;
#[cfg(any(test, feature = "test-support"))]
pub use self::vless::vless_udp_length_frame;
use self::vless::{VlessXhttpH2UdpSession, VlessXhttpH3UdpSession, VlessXudpStreamSession};
use self::vless_standard::VlessStandardUdpOverStreamSession;

#[cfg(test)]
mod datagram_udp_pending_tests {
    use super::*;

    #[test]
    fn datagram_size_preflight_matches_ss2022_wire_encodings() {
        for (cipher, key, nonce_len) in [
            ("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==", 0),
            (
                "2022-blake3-aes-256-gcm",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                0,
            ),
            (
                "2022-blake3-chacha20-poly1305",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                24,
            ),
        ] {
            for identities in [false, true] {
                if nonce_len != 0 && identities {
                    continue;
                }
                let password = if identities {
                    format!("{key}:{key}")
                } else {
                    key.to_owned()
                };
                let plan = super::super::tests::tests::test_udp_proxy(
                    ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
                        cipher: cipher.to_owned(),
                        password: password.clone(),
                        salt_len: if key.len() == 24 { 16 } else { 32 },
                        packet_nonce_len: nonce_len,
                    },
                );
                let binding = ResidentProxyBinding::configuration(Arc::new(plan)).unwrap();
                for target in ["127.0.0.1:53", "[::1]:53"] {
                    let target: SocketAddr = target.parse().unwrap();
                    let mut codec = Ss2022UdpCodec::new(cipher, &password, [1; 8]).unwrap();
                    let nonce = vec![2; nonce_len];
                    let overhead = codec
                        .encode_client_packet(&target.to_string(), &[], 1, Some(&nonce))
                        .unwrap()
                        .wire
                        .len();
                    let limit = 65507 - overhead;
                    let encoded = codec
                        .encode_client_packet(&target.to_string(), &vec![0; limit], 1, Some(&nonce))
                        .unwrap();
                    assert_eq!(encoded.wire.len(), 65507);
                    assert!(
                        UdpSessionExecutor::validate_datagram_payload_size(&binding, target, limit)
                            .is_ok()
                    );
                    assert!(
                        UdpSessionExecutor::validate_datagram_payload_size(
                            &binding,
                            target,
                            limit + 1
                        )
                        .is_err()
                    );
                }
            }
        }
    }

    #[test]
    fn shadowsocks_datagram_pending_result_does_not_forward_empty_reply() {
        let session = ShadowsocksAeadDatagramSession::new(
            "aes-128-gcm".to_owned(),
            "password".to_owned(),
            16,
        );
        let pending = session.pending_response_result();
        assert!(!pending.reply_forwarded);
        assert!(pending.payload_for_test().is_empty());
        assert_eq!(pending.execution_label, "udp-datagram-aead");
        assert_eq!(pending.session_executor, Some("tokio-datagram-relay"));
        assert_eq!(pending.underlay_reuse, Some("udp-socket-reused"));
    }

    #[test]
    fn shadowsocks_2022_datagram_pending_result_does_not_forward_empty_reply() {
        let session = Shadowsocks2022DatagramSession::new(
            "2022-blake3-aes-128-gcm".to_owned(),
            "password".to_owned(),
            16,
        );
        let pending = session.pending_response_result();
        assert!(!pending.reply_forwarded);
        assert!(pending.payload_for_test().is_empty());
        assert_eq!(pending.execution_label, "udp-datagram-aead-2022");
        assert_eq!(pending.session_executor, Some("tokio-datagram-relay"));
        assert_eq!(
            pending.underlay_reuse,
            Some("udp-socket-and-codec-session-reused")
        );
    }

    #[test]
    fn socks5_datagram_pending_result_does_not_forward_empty_reply() {
        let session = Socks5UdpAssociateSession::default();
        let pending = session.pending_response_result();
        assert!(!pending.reply_forwarded);
        assert!(pending.payload_for_test().is_empty());
        assert_eq!(pending.execution_label, "socks5-udp-associate");
        assert_eq!(pending.session_executor, Some("tokio-socks5-udp-associate"));
        assert_eq!(
            pending.underlay_reuse,
            Some("tcp-control-and-udp-relay-reused")
        );
    }
}
