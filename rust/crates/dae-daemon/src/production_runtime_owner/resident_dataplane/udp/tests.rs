#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::super::super::plan::{ResidentProxyPlan, ResidentProxyProtocolPlan};
    use super::super::*;

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
        let mut proxy =
            test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [9_u8; 16] });
        proxy.protocol = "vless".to_owned();
        proxy.flow = XTLS_RPRX_VISION.to_owned();
        proxy.tls = "tls".to_owned();
        let request = build_vless_udp_request(
            &proxy,
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 53),
            &[0xde, 0xad],
        )
        .unwrap();
        assert_eq!(request[0], VLESS_RESPONSE_VERSION);
        assert_eq!(&request[1..17], &[9_u8; 16]);
        assert!(request.windows(16).any(|window| window == [9_u8; 16]));
        assert!(request.windows(2).any(|window| window == [0xde, 0xad]));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resident_udp_executor_fails_closed_for_protocol_closed_handler() {
        let mut proxy = test_udp_proxy(ResidentProxyProtocolPlan::HttpProxyTcp {
            username: String::new(),
            password: String::new(),
            transport: false,
            transport_host: String::new(),
            transport_path: String::new(),
        });
        proxy.protocol = "http-proxy".to_owned();
        let original_dst = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 53);
        let mut executor = UdpSessionExecutor::new_proxy_packet(&proxy);
        let dns = ResidentDnsPlan::asis(proxy.mark);
        let err = executor
            .execute(&dns, &proxy, original_dst, &[0xde, 0xad])
            .await
            .unwrap_err();
        executor.shutdown().await;
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
        let target = "udp-target:5353";
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

    #[test]
    fn resident_udp_session_executor_maps_handlers_to_typed_or_fail_closed() {
        let supported = [
            (
                ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
                    cipher: String::new(),
                    password: String::new(),
                    salt_len: 0,
                },
                UdpExecutorShape::ShadowsocksAead,
            ),
            (
                ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
                    cipher: String::new(),
                    password: String::new(),
                    salt_len: 0,
                    packet_nonce_len: 0,
                },
                UdpExecutorShape::Shadowsocks2022,
            ),
            (
                ResidentProxyProtocolPlan::Socks5Tcp {
                    username: String::new(),
                    password: String::new(),
                },
                UdpExecutorShape::Socks5,
            ),
            (
                ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] },
                UdpExecutorShape::VlessVision,
            ),
            (
                ResidentProxyProtocolPlan::TrojanTcpTls {
                    password: String::new(),
                },
                UdpExecutorShape::Trojan,
            ),
            (
                ResidentProxyProtocolPlan::VmessAeadTcp { id: String::new() },
                UdpExecutorShape::VmessAead,
            ),
            (
                ResidentProxyProtocolPlan::AnyTlsTcpTls {
                    auth: String::new(),
                },
                UdpExecutorShape::AnyTls,
            ),
            (
                ResidentProxyProtocolPlan::Hysteria2QuicTcp {
                    auth: String::new(),
                    pin_sha256: String::new(),
                    max_rx: 0,
                    port_hop_ports: Vec::new(),
                },
                UdpExecutorShape::Hysteria2,
            ),
            (
                ResidentProxyProtocolPlan::TuicQuicTcp {
                    uuid: String::new(),
                    password: String::new(),
                    alpn: Vec::new(),
                    allow_insecure: false,
                },
                UdpExecutorShape::Tuic,
            ),
            (
                ResidentProxyProtocolPlan::JuicityQuicTcp {
                    uuid: String::new(),
                    password: String::new(),
                    allow_insecure: false,
                    pinned_certchain_sha256: String::new(),
                },
                UdpExecutorShape::Juicity,
            ),
        ];
        for (handler, expected) in supported {
            let mut proxy = test_udp_proxy(handler);
            if matches!(
                &proxy.handler,
                ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
            ) {
                proxy.protocol = "vless".to_owned();
                proxy.flow = XTLS_RPRX_VISION.to_owned();
                proxy.tls = "tls".to_owned();
            }
            let executor = UdpSessionExecutor::new_proxy_packet(&proxy);
            assert_eq!(udp_executor_shape(&executor), expected);
        }

        let fail_closed = [
            ResidentProxyProtocolPlan::VlessMuxTcpTls { key: [0; 16] },
            ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp {
                cipher: String::new(),
                password: String::new(),
                salt_len: 0,
                host: String::new(),
                path: String::new(),
            },
            ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp {
                cipher: String::new(),
                password: String::new(),
                salt_len: 0,
                host: String::new(),
            },
            ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp {
                cipher: String::new(),
                password: String::new(),
                salt_len: 0,
                host: String::new(),
                path: String::new(),
            },
            ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp {
                cipher: String::new(),
                password: String::new(),
                salt_len: 0,
                host: String::new(),
                path: String::new(),
            },
            ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp {
                cipher: String::new(),
                password: String::new(),
                obfs_host: String::new(),
                obfs_port: 0,
            },
            ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls {
                password: String::new(),
                inner_cipher: String::new(),
                inner_password: String::new(),
            },
            ResidentProxyProtocolPlan::HttpProxyTcp {
                username: String::new(),
                password: String::new(),
                transport: false,
                transport_host: String::new(),
                transport_path: String::new(),
            },
        ];
        for handler in fail_closed {
            let proxy = test_udp_proxy(handler);
            let executor = UdpSessionExecutor::new_proxy_packet(&proxy);
            assert_eq!(udp_executor_shape(&executor), UdpExecutorShape::FailClosed);
        }

        let vmess_udp_wrappers = [
            ("", ""),
            ("tcp", ""),
            ("tcp", "none"),
            ("websocket", ""),
            ("websocket", "none"),
            ("websocket", "tls"),
            ("httpupgrade", ""),
            ("httpupgrade", "none"),
            ("httpupgrade", "tls"),
            ("grpc", "tls"),
        ];
        for (net, tls) in vmess_udp_wrappers {
            let mut proxy =
                test_udp_proxy(ResidentProxyProtocolPlan::VmessAeadTcp { id: String::new() });
            proxy.net = net.to_owned();
            proxy.tls = tls.to_owned();
            let executor = UdpSessionExecutor::new_proxy_packet(&proxy);
            assert_eq!(udp_executor_shape(&executor), UdpExecutorShape::VmessAead);
        }

        for (net, tls) in [("grpc", ""), ("grpc", "none"), ("websocket", "reality")] {
            let mut proxy =
                test_udp_proxy(ResidentProxyProtocolPlan::VmessAeadTcp { id: String::new() });
            proxy.net = net.to_owned();
            proxy.tls = tls.to_owned();
            let executor = UdpSessionExecutor::new_proxy_packet(&proxy);
            assert_eq!(udp_executor_shape(&executor), UdpExecutorShape::FailClosed);
        }

        let unsupported_vless_udp = [
            ("tcp", ""),
            ("websocket", ""),
            ("httpupgrade", ""),
            ("grpc", ""),
            ("meek", ""),
            ("xhttp", ""),
        ];
        for (net, flow) in unsupported_vless_udp {
            let mut proxy =
                test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] });
            proxy.net = net.to_owned();
            proxy.flow = flow.to_owned();
            let executor = UdpSessionExecutor::new_proxy_packet(&proxy);
            assert_eq!(udp_executor_shape(&executor), UdpExecutorShape::FailClosed);
        }

        for net in ["websocket", "httpupgrade", "grpc"] {
            let mut proxy = test_udp_proxy(ResidentProxyProtocolPlan::TrojanTcpTls {
                password: String::new(),
            });
            proxy.net = net.to_owned();
            let executor = UdpSessionExecutor::new_proxy_packet(&proxy);
            assert_eq!(udp_executor_shape(&executor), UdpExecutorShape::FailClosed);
        }

        let proxy = test_udp_proxy(ResidentProxyProtocolPlan::Socks5Tcp {
            username: String::new(),
            password: String::new(),
        });
        let executor =
            UdpSessionExecutor::new(&proxy, SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 53));
        assert_eq!(udp_executor_shape(&executor), UdpExecutorShape::Dns);
    }

    #[test]
    fn resident_udp_production_sources_do_not_reintroduce_per_packet_fallback_labels() {
        let sources = [
            include_str!("descriptors.rs"),
            include_str!("manager.rs"),
            include_str!("packet_handler.rs"),
            include_str!("probe_dns.rs"),
            include_str!("session_actor.rs"),
            include_str!("session_executor.rs"),
            include_str!("worker.rs"),
        ];
        let forbidden = [
            concat!("manager-owned", "-compatibility"),
            concat!("per-packet", "-underlay"),
            concat!("dae-resident", "-udp-packet"),
            concat!("udp", "_packet_stack"),
            concat!("RESIDENT_UDP", "_PACKET_STACK"),
        ];
        for source in sources {
            for marker in forbidden {
                assert!(!source.contains(marker), "{marker}");
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum UdpExecutorShape {
        Dns,
        ShadowsocksAead,
        Shadowsocks2022,
        Socks5,
        VlessVision,
        Trojan,
        VmessAead,
        AnyTls,
        Hysteria2,
        Tuic,
        Juicity,
        FailClosed,
    }

    fn udp_executor_shape(executor: &UdpSessionExecutor) -> UdpExecutorShape {
        match executor {
            UdpSessionExecutor::Dns => UdpExecutorShape::Dns,
            UdpSessionExecutor::ShadowsocksAead(_) => UdpExecutorShape::ShadowsocksAead,
            UdpSessionExecutor::Shadowsocks2022(_) => UdpExecutorShape::Shadowsocks2022,
            UdpSessionExecutor::Socks5(_) => UdpExecutorShape::Socks5,
            UdpSessionExecutor::VlessVision(_) => UdpExecutorShape::VlessVision,
            UdpSessionExecutor::Trojan(_) => UdpExecutorShape::Trojan,
            UdpSessionExecutor::VmessAead(_) => UdpExecutorShape::VmessAead,
            UdpSessionExecutor::AnyTls(_) => UdpExecutorShape::AnyTls,
            UdpSessionExecutor::Hysteria2(_) => UdpExecutorShape::Hysteria2,
            UdpSessionExecutor::Tuic(_) => UdpExecutorShape::Tuic,
            UdpSessionExecutor::Juicity(_) => UdpExecutorShape::Juicity,
            UdpSessionExecutor::FailClosed { .. } => UdpExecutorShape::FailClosed,
        }
    }

    fn test_udp_proxy(handler: ResidentProxyProtocolPlan) -> ResidentProxyPlan {
        ResidentProxyPlan {
            graph_id: "resident-graph:redacted".to_owned(),
            graph_link_hash: "sha256:redacted".to_owned(),
            redacted_link_source: "source:<redacted>".to_owned(),
            protocol: "redacted".to_owned(),
            group_name: "proxy".to_owned(),
            group_policy: "fixed".to_owned(),
            node_tag: "redacted".to_owned(),
            server_host: String::new(),
            server_port: 0,
            server_name: String::new(),
            alpn: Vec::new(),
            flow: String::new(),
            net: "tcp".to_owned(),
            stream_host: String::new(),
            stream_path: String::new(),
            tls: String::new(),
            allow_insecure: false,
            tls_fragment: None,
            utls_fingerprint: None,
            reality: None,
            handler,
            chain_parent: None,
            mark: 0,
            mptcp: false,
        }
    }
}
