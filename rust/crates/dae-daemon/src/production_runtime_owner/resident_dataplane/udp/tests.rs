#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::super::plan::ResidentProxyProtocolPlan;
    use super::*;

    #[test]
    fn resident_vless_udp_response_parser_handles_vision_payload() {
        let key = [1_u8; 16];
        let frame = xudp_frame(
            SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
            &[0x12, 0x34],
        )
        .unwrap();
        let mut response = vec![0, 0];
        response.extend_from_slice(&key);
        response.push(VISION_COMMAND_CONTINUE);
        response.extend_from_slice(&(frame.len() as u16).to_be_bytes());
        response.extend_from_slice(&3_u16.to_be_bytes());
        response.extend_from_slice(&frame);
        response.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        let payload = parse_vless_udp_response(&response, XTLS_RPRX_VISION, key)
            .unwrap()
            .unwrap();
        assert_eq!(payload, [0x12, 0x34]);
    }

    #[test]
    fn resident_vless_vision_udp_request_uses_xudp_mux_target() {
        let proxy = ResidentProxyPlan {
            graph_id: "resident-graph:test-vless".to_owned(),
            graph_link_hash: "sha256:test-vless".to_owned(),
            redacted_link_source: "vless:<redacted>#vless_live".to_owned(),
            protocol: "vless".to_owned(),
            group_name: "proxy".to_owned(),
            group_policy: "fixed".to_owned(),
            node_tag: "vless_live".to_owned(),
            server_host: "156.246.90.2".to_owned(),
            server_port: 443,
            server_name: "office.example".to_owned(),
            alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            flow: XTLS_RPRX_VISION.to_owned(),
            net: "tcp".to_owned(),
            stream_host: String::new(),
            stream_path: String::new(),
            tls: "tls".to_owned(),
            allow_insecure: false,
            utls_fingerprint: None,
            handler: ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [9_u8; 16] },
            chain_parent: None,
            mark: 0,
            mptcp: false,
        };
        let request = build_vless_udp_request(
            &proxy,
            SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
            &[0xde, 0xad],
        )
        .unwrap();
        assert_eq!(request[0], VLESS_RESPONSE_VERSION);
        assert_eq!(&request[1..17], &[9_u8; 16]);
        assert!(request.windows(16).any(|window| window == [9_u8; 16]));
        assert!(request.windows(2).any(|window| window == [0xde, 0xad]));
    }

    #[test]
    fn resident_udp_dispatch_fails_closed_for_protocol_closed_handler() {
        let proxy = ResidentProxyPlan {
            graph_id: "resident-graph:test-http".to_owned(),
            graph_link_hash: "sha256:test-http".to_owned(),
            redacted_link_source: "http:<redacted>#plain-http-connect".to_owned(),
            protocol: "http-proxy".to_owned(),
            group_name: "proxy".to_owned(),
            group_policy: "fixed".to_owned(),
            node_tag: "plain-http-connect".to_owned(),
            server_host: "127.0.0.1".to_owned(),
            server_port: 8080,
            server_name: String::new(),
            alpn: vec![],
            flow: String::new(),
            net: "tcp".to_owned(),
            stream_host: String::new(),
            stream_path: String::new(),
            tls: String::new(),
            allow_insecure: false,
            utls_fingerprint: None,
            handler: ResidentProxyProtocolPlan::HttpProxyTcp {
                username: String::new(),
                password: String::new(),
                transport: false,
                transport_host: String::new(),
                transport_path: String::new(),
            },
            chain_parent: None,
            mark: 0,
            mptcp: false,
        };
        let err = exchange_proxy_udp(
            &proxy,
            SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
            &[0xde, 0xad],
        )
        .unwrap_err();
        assert!(err.contains("unsupported_udp_handler"));
        assert!(err.contains("no UDP relay semantics"));
        assert!(err.contains("without fallback execution"));
        assert!(err.contains("http-proxy-tcp"));
        assert!(err.contains("http-proxy"));
    }

    #[test]
    fn resident_dns_udp_check_accepts_a_answer() {
        let id = 0x1234;
        let query = build_dns_a_query(id, "connectivitycheck.gstatic.com.").unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&[142, 250, 72, 238]);
        dns_a_response_has_answer(id, &response).unwrap();
    }

    #[test]
    fn resident_dns_udp_check_rejects_response_without_a_answer() {
        let id = 0x3456;
        let query = build_dns_a_query(id, "connectivitycheck.gstatic.com.").unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&28_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u32.to_be_bytes());
        response.extend_from_slice(&16_u16.to_be_bytes());
        response.extend_from_slice(&[0; 16]);
        let err = dns_a_response_has_answer(id, &response).unwrap_err();
        assert!(err.contains("no A answer"));
    }

    #[test]
    fn resident_udp_quic_wire_helpers_roundtrip() {
        let target = "203.0.113.53:5353";
        let payload = b"resident-udp-live-matrix";

        let hy2 = build_hysteria2_udp_message(0x1122_3344, 0x5566, target, payload).unwrap();
        let parsed_hy2 = parse_hysteria2_udp_message(&hy2).unwrap();
        assert_eq!(parsed_hy2.session_id, 0x1122_3344);
        assert_eq!(parsed_hy2.packet_id, 0x5566);
        assert_eq!(parsed_hy2.payload, payload);

        let tuic = build_tuic_packet_frame(7, 9, target, payload).unwrap();
        let parsed_tuic = parse_tuic_packet_frame(&tuic).unwrap();
        assert_eq!(parsed_tuic.assoc_id, 7);
        assert_eq!(parsed_tuic.packet_id, 9);
        assert_eq!(parsed_tuic.payload, payload);

        let juicity_frame = seal_stream_packet_frame(target, payload).unwrap();
        let juicity_request =
            build_juicity_stream_packet_request(target, &juicity_frame.encoded).unwrap();
        assert_eq!(juicity_request[0], 3);
        let (initial_address, initial_metadata_len) =
            Socks5Address::decode(&juicity_request[1..]).unwrap();
        assert_eq!(initial_address.authority(), target);
        let decoded =
            decode_stream_packet_frame(&juicity_request[1 + initial_metadata_len..]).unwrap();
        assert_eq!(decoded.target, target);
        assert_eq!(decoded.payload, payload);
    }
}
