use super::*;

pub(super) enum UdpSessionExecutor {
    Dns,
    ShadowsocksAead(ShadowsocksAeadDatagramSession),
    Shadowsocks2022(Shadowsocks2022DatagramSession),
    Socks5(Socks5UdpAssociateSession),
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

const UDP_DATAGRAM_RESPONSE_CAPACITY: usize = 64 * 1024;

mod datagram;
mod dispatch;
mod selection;
use self::datagram::*;

mod anytls;
mod quic;
mod shadowsocks;
mod socks5;
mod trojan;
mod vless;
use self::anytls::AnyTlsPacketStreamSession;
use self::quic::{
    Hysteria2QuicDatagramSession, JuicityQuicStreamPacketSession, TuicQuicDatagramSession,
};
use self::shadowsocks::{Shadowsocks2022DatagramSession, ShadowsocksAeadDatagramSession};
use self::socks5::Socks5UdpAssociateSession;
use self::trojan::TrojanUdpStreamSession;
#[cfg(test)]
pub(super) use self::vless::vless_udp_length_frame;
use self::vless::{VlessXhttpH2UdpSession, VlessXhttpH3UdpSession, VlessXudpStreamSession};

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
        assert!(pending.payload.is_empty());
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
        assert!(pending.payload.is_empty());
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
        assert!(pending.payload.is_empty());
        assert_eq!(pending.execution_label, "socks5-udp-associate");
        assert_eq!(pending.session_executor, Some("tokio-socks5-udp-associate"));
        assert_eq!(
            pending.underlay_reuse,
            Some("tcp-control-and-udp-relay-reused")
        );
    }
}
