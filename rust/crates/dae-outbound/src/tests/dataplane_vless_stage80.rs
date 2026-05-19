use super::*;

#[test]
fn stage80_xhttp_xmux_options_reject_zero_limits() {
    assert!(shared_transport::XHttpXmuxOptions::new(0, 4).is_err());
    assert!(shared_transport::XHttpXmuxOptions::new(2, 0).is_err());
}

#[test]
fn stage80_vless_xhttp_xmux_dataplane_echoes_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "stage80-vless-xhttp-xmux-target.example:443";
    let payload = b"stage80-vless-xhttp-xmux-ping";
    let xmux = shared_transport::XHttpXmuxOptions::new(2, 4).unwrap();
    let options = shared_transport::XHttpLifecycleOptions::new(
        "stage80-vless-xhttp-xmux.example",
        "/dae-stage80-xhttp-xmux",
        "packet-up",
        "tls",
        "h2",
        "dae-stage80-xhttp-xmux",
        80,
    )
    .unwrap()
    .with_xmux(xmux);
    let (proxy, handle) = spawn_vless_xhttp_packet_echo_server(
        key,
        target.to_owned(),
        options.clone(),
        payload.len(),
    );

    let report = vless::tcp_exchange_over_xhttp_packet_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        &key,
        target,
        &options,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert!(!report.full_h2_h3_stack);
    assert!(report.xhttp_xmux_enabled);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.target, target);
    assert_eq!(report.xhttp_host, "stage80-vless-xhttp-xmux.example");
    assert_eq!(report.xhttp_path, "/dae-stage80-xhttp-xmux/");
    assert_eq!(
        report.xhttp_request_path,
        "/dae-stage80-xhttp-xmux/?session=dae-stage80-xhttp-xmux&seq=80"
    );
    assert_eq!(report.xhttp_mode, "packet-up");
    assert_eq!(report.xhttp_alpn, "h2");
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.response_header_len, 2);
    assert_eq!(report.echoed_payload, payload);
    assert!(report.xhttp_packet_up_validated);
    assert_eq!(accepted.request.version, vless::VLESS_VERSION);
    assert_eq!(accepted.request.key, key);
    assert_eq!(accepted.request.addons_len, 0);
    assert_eq!(
        accepted.request.command,
        crate::vmess::VMessNetwork::Tcp.byte()
    );
    assert_eq!(accepted.request.target, target);
    assert_eq!(accepted.request.payload, payload);
    assert!(accepted.xhttp_packet_up_validated);
    assert_eq!(
        accepted.xhttp_request_path,
        "/dae-stage80-xhttp-xmux/?session=dae-stage80-xhttp-xmux&seq=80"
    );
}
