use super::*;

pub(super) enum UdpSessionExecutor {
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
    Tuic(TuicQuicDatagramSession),
    Juicity(JuicityQuicStreamPacketSession),
    FailClosed { reason: String },
}

impl UdpSessionExecutor {
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn set_runtime_metrics(
        &mut self,
        metrics: Arc<ResidentDataplaneMetrics>,
    ) {
        if let Self::Shadowsocks2022(session) = self {
            session.set_runtime_metrics(metrics);
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn set_owner_acquisition_deadline(
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

    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn runtime_disposition(
        &self,
    ) -> Option<ResidentUdpExecutionDisposition> {
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

    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::production_runtime_owner::resident_dataplane::udp) fn agrees_with(
        &self,
        agreement: ResidentUdpExecutionAgreement,
    ) -> bool {
        self.runtime_disposition() == Some(agreement.disposition())
            && match self {
                Self::FailClosed { reason } => {
                    agreement.unsupported_reason() == Some(reason.as_str())
                }
                Self::Dns => false,
                _ => agreement.unsupported_reason().is_none(),
            }
    }
}

const UDP_DATAGRAM_RESPONSE_CAPACITY: usize = 64 * 1024;

mod connect_udp;
mod datagram;
mod dispatch;
mod selection;
mod wait;
pub(in crate::production_runtime_owner::resident_dataplane) use self::connect_udp::{
    clear_connect_udp_h2_pools, clear_connect_udp_h3_pools, connect_udp_pool_metrics_snapshot,
};
use self::datagram::*;

mod anytls;
mod quic;
mod shadowsocks;
mod socks5;
mod trojan;
mod vless;
mod vless_standard;
use self::anytls::AnyTlsPacketStreamSession;
#[cfg(test)]
pub(in crate::production_runtime_owner::resident_dataplane) use self::anytls::exercise_anytls_udp_stream_session;
#[cfg(test)]
pub(in crate::production_runtime_owner::resident_dataplane) use self::quic::exercise_juicity_udp_stream_session;
use self::quic::{
    Hysteria2QuicDatagramSession, JuicityQuicStreamPacketSession, TuicQuicDatagramSession,
};
use self::shadowsocks::{Shadowsocks2022DatagramSession, ShadowsocksAeadDatagramSession};
use self::socks5::Socks5UdpAssociateSession;
use self::trojan::TrojanUdpStreamSession;
#[cfg(test)]
pub(super) use self::vless::vless_udp_length_frame;
use self::vless::{VlessXhttpH2UdpSession, VlessXhttpH3UdpSession, VlessXudpStreamSession};
use self::vless_standard::VlessStandardUdpOverStreamSession;

#[cfg(test)]
mod datagram_udp_pending_tests {
    use super::*;

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
