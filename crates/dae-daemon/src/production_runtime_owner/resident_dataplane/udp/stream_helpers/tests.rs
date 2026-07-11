use super::*;

#[tokio::test(flavor = "current_thread")]
async fn socks5_wildcard_relay_uses_connected_control_peer() {
    let control_peer: SocketAddr = "[2001:db8::7]:1080".parse().unwrap();
    let candidates = socks5_udp_relay_addr_candidates_async("0.0.0.0:5300", control_peer)
        .await
        .unwrap();

    assert_eq!(candidates, vec!["[2001:db8::7]:5300".parse().unwrap()]);
}

#[tokio::test(flavor = "current_thread")]
async fn socks5_explicit_relay_does_not_use_control_peer() {
    let control_peer: SocketAddr = "192.0.2.7:1080".parse().unwrap();
    let candidates = socks5_udp_relay_addr_candidates_async("198.51.100.9:5300", control_peer)
        .await
        .unwrap();

    assert_eq!(candidates, vec!["198.51.100.9:5300".parse().unwrap()]);
}
