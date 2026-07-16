#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::super::super::plan::{
        ResidentProxyPlan, ResidentProxyProtocolPlan, ResidentXhttpSettingsPlan,
    };
    use super::super::*;

    const XTLS_RPRX_VISION: &str = "xtls-rprx-vision";

    #[test]
    fn resident_vless_udp_response_parser_handles_vision_payload() {
        let key = [1_u8; 16];
        let frame = xudp_new_frame(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)),
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
    fn resident_vless_xudp_frame_encodes_ipv6_destination() {
        let target = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 853);
        let frame = xudp_new_frame(target, &[0xaa]).unwrap();
        let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        let metadata = &frame[2..2 + metadata_len];
        assert_eq!(metadata[0..2], [0, 0]);
        assert_eq!(metadata[2], XUDP_COMMAND_NEW);
        assert_eq!(metadata[3], XUDP_OPTION_DATA);
        assert_eq!(metadata[4], XUDP_NETWORK_UDP);
        assert_eq!(u16::from_be_bytes([metadata[5], metadata[6]]), 853);
        assert_eq!(metadata[7], 3);
        assert_eq!(&metadata[8..24], &Ipv6Addr::LOCALHOST.octets());
    }

    #[test]
    fn resident_vless_xudp_keep_frame_omits_destination() {
        let frame = xudp_keep_frame(&[0xde, 0xad]).unwrap();
        let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        let metadata = &frame[2..2 + metadata_len];
        assert_eq!(metadata, [0, 0, XUDP_COMMAND_KEEP, XUDP_OPTION_DATA]);
        let payload_len_offset = 2 + metadata_len;
        assert_eq!(
            u16::from_be_bytes([frame[payload_len_offset], frame[payload_len_offset + 1]]),
            2
        );
        assert_eq!(&frame[payload_len_offset + 2..], &[0xde, 0xad]);
    }

    #[test]
    fn resident_vless_xudp_response_frame_reports_consumed_len() {
        let first = xudp_keep_frame(&[0x01, 0x02]).unwrap();
        let second = xudp_keep_frame(&[0x03]).unwrap();
        let mut stream = first.clone();
        stream.extend_from_slice(&second);

        let (payload, consumed) = parse_xudp_response_frame(&stream).unwrap().unwrap();
        assert_eq!(payload, [0x01, 0x02]);
        assert_eq!(consumed, first.len());

        let (payload, consumed) = parse_xudp_response_frame(&stream[consumed..])
            .unwrap()
            .unwrap();
        assert_eq!(payload, [0x03]);
        assert_eq!(consumed, second.len());
    }

    #[test]
    fn resident_vless_vision_udp_request_uses_xudp_mux_target() {
        let mut proxy =
            test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [9_u8; 16] });
        proxy.protocol = "vless";
        proxy.flow = XTLS_RPRX_VISION.to_owned();
        proxy.tls = "tls".to_owned();
        let request = build_vless_udp_request(
            &proxy,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 53)),
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
        proxy.protocol = "http-proxy";
        let original_dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 53));
        let mut executor = UdpSessionExecutor::new_proxy_packet(&proxy);
        let dns = ResidentDnsPlan::asis(proxy.mark);
        let err = executor
            .execute(&dns, &proxy, original_dst, &[0xde, 0xad])
            .await
            .unwrap_err();
        executor.shutdown().await;
        assert!(err.contains("unsupported_udp_handler"));
        assert!(err.contains("no UDP relay semantics"));
        assert!(err.contains("without alternate execution"));
        assert!(err.contains("http-connect-udp-protocol-closed"));
        assert!(err.contains("http-proxy"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn manual_udp_probe_reports_every_typed_policy_closed_shape_without_network_wait() {
        let mut proxies = vec![
            test_udp_proxy(ResidentProxyProtocolPlan::HttpProxyTcp {
                username: String::new(),
                password: String::new(),
                transport: false,
                transport_host: String::new(),
                transport_path: String::new(),
            }),
            test_udp_proxy(ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp {
                cipher: String::new(),
                password: String::new(),
                salt_len: 0,
                host: String::new(),
                path: String::new(),
            }),
            test_udp_proxy(ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp {
                cipher: String::new(),
                password: String::new(),
                obfs_host: String::new(),
                obfs_port: 0,
            }),
            test_udp_proxy(ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls {
                password: String::new(),
                inner_cipher: String::new(),
                inner_password: String::new(),
            }),
            test_udp_proxy(ResidentProxyProtocolPlan::VlessMuxTcpTls { key: [0; 16] }),
        ];

        let mut trojan = test_udp_proxy(ResidentProxyProtocolPlan::TrojanTcpTls {
            password: String::new(),
        });
        trojan.net = "unsupported-wrapper".to_owned();
        proxies.push(trojan);

        let mut vless_meek =
            test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] });
        vless_meek.net = "meek".to_owned();
        vless_meek.tls = "tls".to_owned();
        proxies.push(vless_meek);

        let mut vless_unsupported =
            test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] });
        vless_unsupported.net = "websocket".to_owned();
        vless_unsupported.tls = "tls".to_owned();
        vless_unsupported.flow = XTLS_RPRX_VISION.to_owned();
        proxies.push(vless_unsupported);

        let mut vmess_h2 =
            test_udp_proxy(ResidentProxyProtocolPlan::VmessAeadTcp { id: String::new() });
        vmess_h2.net = "h2".to_owned();
        vmess_h2.tls = "tls".to_owned();
        proxies.push(vmess_h2);

        let mut vmess_unsupported =
            test_udp_proxy(ResidentProxyProtocolPlan::VmessAeadTcp { id: String::new() });
        vmess_unsupported.net = "grpc".to_owned();
        vmess_unsupported.tls = "none".to_owned();
        proxies.push(vmess_unsupported);

        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9));
        for proxy in proxies {
            let agreement = proxy.execution_plan().udp.agreement();
            assert!(agreement.policy_closed());
            let graph = proxy.executable_graph_value();
            let components = &graph["runtimeComponents"];
            assert_eq!(
                components["udpExecutionAgreement"]["disposition"],
                agreement.disposition().as_str()
            );
            assert_eq!(components["packetSessionManager"]["status"], "fail-closed");
            assert_eq!(
                components["packetSessionManager"]["executor"],
                agreement.executor_label()
            );
            assert_eq!(components["probeExecutor"]["status"], "admitted");
            assert_eq!(components["probeExecutor"]["udp"]["status"], "fail-closed");
            assert_eq!(
                components["probeExecutor"]["udp"]["unsupportedReason"],
                agreement.unsupported_reason().unwrap()
            );
            let result = probe_resident_proxy_udp_async(&proxy, target, b"probe", false).await;
            assert_eq!(result["status"], "protocol-closed");
            assert_eq!(result["ok"], true);
            assert_eq!(result["protocol_closed"], true);
            assert_eq!(result["relay_available"], false);
            assert_eq!(result["negative_path_ready"], true);
            assert_eq!(
                result["agreement_disposition"],
                agreement.disposition().as_str()
            );
            assert_eq!(result["handler"], agreement.executor_label());
            assert_eq!(result["error"], agreement.unsupported_reason().unwrap());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resident_proxy_udp_bridge_surfaces_executor_errors() {
        let mut proxy = test_udp_proxy(ResidentProxyProtocolPlan::HttpProxyTcp {
            username: String::new(),
            password: String::new(),
            transport: false,
            transport_host: String::new(),
            transport_path: String::new(),
        });
        proxy.protocol = "http-proxy";
        let original_dst = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            proxy.server_port.saturating_add(1),
        ));
        let bridge = open_resident_proxy_udp_bridge_async(Arc::new(proxy), original_dst)
            .await
            .unwrap();
        let client =
            tokio::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap();
        client
            .send_to(&[0xde, 0xad], bridge.local_addr())
            .await
            .unwrap();

        let started = Instant::now();
        let err = loop {
            if let Some(err) = bridge.last_error() {
                break err;
            }
            assert!(started.elapsed() < Duration::from_secs(1));
            time::sleep(RESIDENT_IDLE_SLEEP).await;
        };
        bridge.shutdown().await;

        assert!(err.contains("unsupported_udp_handler"));
        assert!(err.contains("no UDP relay semantics"));
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
        const CONFIGURED_UDP_TARGET_PORT: u16 = 8053;
        let target = format!("udp-target:{CONFIGURED_UDP_TARGET_PORT}");
        let payload = b"resident-udp-live-matrix";

        let hy2 = build_hysteria2_udp_message(0x1122_3344, 0x5566, &target, payload).unwrap();
        let parsed_hy2 = parse_hysteria2_udp_message(&hy2).unwrap();
        assert_eq!(parsed_hy2.session_id, 0x1122_3344);
        assert_eq!(parsed_hy2.packet_id, 0x5566);
        assert_eq!(parsed_hy2.frag_id, 0);
        assert_eq!(parsed_hy2.frag_count, 1);
        assert_eq!(parsed_hy2.payload, payload);

        let tuic = build_tuic_packet_frame(7, 9, &target, payload).unwrap();
        let parsed_tuic = parse_tuic_packet_frame(&tuic).unwrap();
        assert_eq!(parsed_tuic.assoc_id, 7);
        assert_eq!(parsed_tuic.packet_id, 9);
        assert_eq!(parsed_tuic.frag_total, 1);
        assert_eq!(parsed_tuic.frag_id, 0);
        assert_eq!(parsed_tuic.payload, payload);

        let juicity_frame = seal_stream_packet_frame(&target, payload).unwrap();
        let juicity_request =
            build_juicity_stream_packet_request(&target, &juicity_frame.encoded).unwrap();
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
                    tls_identity:
                        dae_outbound::hysteria2::Hysteria2TlsIdentity::from_node_and_global(
                            "fixture.invalid",
                            false,
                            false,
                            "",
                        )
                        .unwrap(),
                    max_rx: 0,
                    obfs: ResidentHysteria2ObfsPlan::none(),
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
                proxy.protocol = "vless";
                proxy.flow = XTLS_RPRX_VISION.to_owned();
                proxy.tls = "tls".to_owned();
            }
            let executor = UdpSessionExecutor::new_proxy_packet(&proxy);
            assert_eq!(udp_executor_shape(&executor), expected);
            assert!(executor.agrees_with(proxy.execution_plan().udp.agreement()));
        }

        let mut vless_xhttp =
            test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] });
        vless_xhttp.protocol = "vless";
        vless_xhttp.net = "xhttp".to_owned();
        vless_xhttp.tls = "tls".to_owned();
        vless_xhttp.flow = String::new();
        let executor = UdpSessionExecutor::new_proxy_packet(&vless_xhttp);
        assert_eq!(
            udp_executor_shape(&executor),
            UdpExecutorShape::VlessXhttpH2
        );
        assert!(executor.agrees_with(vless_xhttp.execution_plan().udp.agreement()));

        vless_xhttp.alpn = vec!["h3".to_owned()];
        let executor = UdpSessionExecutor::new_proxy_packet(&vless_xhttp);
        assert_eq!(
            udp_executor_shape(&executor),
            UdpExecutorShape::VlessXhttpH3
        );
        assert!(executor.agrees_with(vless_xhttp.execution_plan().udp.agreement()));

        let mut vless_udp443 =
            test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] });
        vless_udp443.protocol = "vless";
        vless_udp443.net = "tcp".to_owned();
        vless_udp443.tls = "tls".to_owned();
        vless_udp443.flow = "xtls-rprx-vision-udp443".to_owned();
        let executor = UdpSessionExecutor::new_proxy_packet(&vless_udp443);
        assert_eq!(udp_executor_shape(&executor), UdpExecutorShape::VlessVision);

        for (net, tls) in [
            ("", ""),
            ("tcp", ""),
            ("tcp", "none"),
            ("tcp", "tls"),
            ("tcp", "reality"),
            ("websocket", ""),
            ("websocket", "none"),
            ("websocket", "tls"),
            ("websocket", "reality"),
            ("httpupgrade", ""),
            ("httpupgrade", "none"),
            ("httpupgrade", "tls"),
            ("httpupgrade", "reality"),
            ("grpc", "tls"),
            ("grpc", "reality"),
            ("h2", "tls"),
            ("h2", "reality"),
        ] {
            let mut proxy =
                test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] });
            proxy.protocol = "vless";
            proxy.net = net.to_owned();
            proxy.tls = tls.to_owned();
            proxy.flow = String::new();
            let executor = UdpSessionExecutor::new_proxy_packet(&proxy);
            assert_eq!(
                udp_executor_shape(&executor),
                UdpExecutorShape::VlessStandard
            );
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
            assert!(executor.agrees_with(proxy.execution_plan().udp.agreement()));
        }

        let vmess_udp_wrappers = [
            ("", ""),
            ("tcp", ""),
            ("tcp", "none"),
            ("tcp", "tls"),
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
            assert!(executor.agrees_with(proxy.execution_plan().udp.agreement()));
        }

        for (net, tls) in [("grpc", ""), ("grpc", "none"), ("websocket", "reality")] {
            let mut proxy =
                test_udp_proxy(ResidentProxyProtocolPlan::VmessAeadTcp { id: String::new() });
            proxy.net = net.to_owned();
            proxy.tls = tls.to_owned();
            let executor = UdpSessionExecutor::new_proxy_packet(&proxy);
            assert_eq!(udp_executor_shape(&executor), UdpExecutorShape::FailClosed);
            assert!(executor.agrees_with(proxy.execution_plan().udp.agreement()));
        }

        for (net, tls) in [("grpc", ""), ("grpc", "none"), ("h2", ""), ("h2", "none")] {
            let mut proxy =
                test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] });
            proxy.net = net.to_owned();
            proxy.tls = tls.to_owned();
            proxy.flow = String::new();
            let executor = UdpSessionExecutor::new_proxy_packet(&proxy);
            assert_eq!(udp_executor_shape(&executor), UdpExecutorShape::FailClosed);
            assert!(executor.agrees_with(proxy.execution_plan().udp.agreement()));
        }

        for net in ["websocket", "httpupgrade", "grpc", "h2", "meek"] {
            let mut proxy =
                test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] });
            proxy.net = net.to_owned();
            proxy.tls = "tls".to_owned();
            proxy.flow = "xtls-rprx-vision".to_owned();
            let executor = UdpSessionExecutor::new_proxy_packet(&proxy);
            assert_eq!(udp_executor_shape(&executor), UdpExecutorShape::FailClosed);
            assert!(executor.agrees_with(proxy.execution_plan().udp.agreement()));
        }

        let mut meek =
            test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] });
        meek.net = "meek".to_owned();
        meek.tls = "tls".to_owned();
        meek.flow = String::new();
        let executor = UdpSessionExecutor::new_proxy_packet(&meek);
        assert_eq!(udp_executor_shape(&executor), UdpExecutorShape::FailClosed);
        assert!(executor.agrees_with(meek.execution_plan().udp.agreement()));

        for net in ["websocket", "httpupgrade", "grpc"] {
            let mut proxy = test_udp_proxy(ResidentProxyProtocolPlan::TrojanTcpTls {
                password: String::new(),
            });
            proxy.net = net.to_owned();
            let executor = UdpSessionExecutor::new_proxy_packet(&proxy);
            assert_eq!(udp_executor_shape(&executor), UdpExecutorShape::Trojan);
            assert!(executor.agrees_with(proxy.execution_plan().udp.agreement()));
            assert!(!proxy.executor_contract().udp_policy_closed);
        }

        let mut unsupported_trojan = test_udp_proxy(ResidentProxyProtocolPlan::TrojanTcpTls {
            password: String::new(),
        });
        unsupported_trojan.net = "unsupported-wrapper".to_owned();
        let executor = UdpSessionExecutor::new_proxy_packet(&unsupported_trojan);
        assert_eq!(udp_executor_shape(&executor), UdpExecutorShape::FailClosed);
        assert!(executor.agrees_with(unsupported_trojan.execution_plan().udp.agreement()));
        assert!(unsupported_trojan.executor_contract().udp_policy_closed);

        let proxy = test_udp_proxy(ResidentProxyProtocolPlan::Socks5Tcp {
            username: String::new(),
            password: String::new(),
        });
        let executor = UdpSessionExecutor::new(
            &proxy,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 53)),
        );
        assert_eq!(udp_executor_shape(&executor), UdpExecutorShape::Dns);
    }

    #[test]
    fn resident_vless_standard_udp_uses_udp_over_stream_semantics() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443));
        for (net, tls) in [
            ("", ""),
            ("tcp", ""),
            ("tcp", "none"),
            ("tcp", "tls"),
            ("tcp", "reality"),
            ("websocket", ""),
            ("websocket", "none"),
            ("websocket", "tls"),
            ("websocket", "reality"),
            ("httpupgrade", ""),
            ("httpupgrade", "none"),
            ("httpupgrade", "tls"),
            ("httpupgrade", "reality"),
            ("grpc", "tls"),
            ("grpc", "reality"),
            ("h2", "tls"),
            ("h2", "reality"),
            ("xhttp", "tls"),
            ("xhttp", "reality"),
        ] {
            let mut proxy =
                test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] });
            proxy.protocol = "vless";
            proxy.net = net.to_owned();
            proxy.tls = tls.to_owned();
            proxy.flow = String::new();

            assert_eq!(
                udp_packet_semantics_for_destination(&proxy, target),
                UdpPacketSemantics::UdpOverStream,
                "net={net:?} tls={tls:?}"
            );
            let expected_handler = match (net, tls) {
                ("" | "tcp", "" | "none") => "resident-vless-udp-over-plain-tcp",
                ("" | "tcp", _) => "resident-vless-udp-over-tls",
                ("websocket", "" | "none") => "resident-vless-udp-over-websocket-plain",
                ("websocket", _) => "resident-vless-udp-over-websocket",
                ("httpupgrade", "" | "none") => "resident-vless-udp-over-httpupgrade-plain",
                ("httpupgrade", _) => "resident-vless-udp-over-httpupgrade",
                ("grpc", _) => "resident-vless-udp-over-grpc",
                ("h2", _) => "resident-vless-udp-over-h2",
                ("xhttp", _) => "resident-vless-xhttp-h2-packet",
                _ => unreachable!(),
            };
            assert_eq!(resident_udp_proxy_handler_name(&proxy), expected_handler);
        }

        let proxy = test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] });
        assert_eq!(
            udp_packet_semantics_for_destination(&proxy, target),
            UdpPacketSemantics::UdpOverStream
        );
        assert_eq!(
            udp_packet_semantics_for_destination(
                &proxy,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53))
            ),
            UdpPacketSemantics::Dns
        );
    }

    #[test]
    fn resident_vless_vision_udp_uses_xudp_semantics() {
        for flow in [XTLS_RPRX_VISION, "xtls-rprx-vision-udp443"] {
            let mut proxy =
                test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] });
            proxy.protocol = "vless";
            proxy.net = "tcp".to_owned();
            proxy.tls = "tls".to_owned();
            proxy.flow = flow.to_owned();

            assert_eq!(
                udp_packet_semantics_for_destination(
                    &proxy,
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443))
                ),
                UdpPacketSemantics::Xudp,
                "flow={flow:?}"
            );
            assert_eq!(
                resident_udp_proxy_handler_name(&proxy),
                "resident-vless-xudp"
            );
        }
    }

    #[test]
    fn resident_vless_unsupported_udp_shapes_use_protocol_closed_semantics() {
        for (net, tls, flow) in [
            ("grpc", "", ""),
            ("grpc", "none", ""),
            ("h2", "", ""),
            ("h2", "none", ""),
            ("meek", "tls", ""),
            ("websocket", "tls", XTLS_RPRX_VISION),
            ("httpupgrade", "tls", XTLS_RPRX_VISION),
            ("grpc", "tls", XTLS_RPRX_VISION),
            ("h2", "tls", XTLS_RPRX_VISION),
        ] {
            let mut proxy =
                test_udp_proxy(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] });
            proxy.protocol = "vless";
            proxy.net = net.to_owned();
            proxy.tls = tls.to_owned();
            proxy.flow = flow.to_owned();

            assert_eq!(
                udp_packet_semantics_for_destination(
                    &proxy,
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443))
                ),
                UdpPacketSemantics::ProtocolClosed,
                "net={net:?} tls={tls:?} flow={flow:?}"
            );
            let expected_handler = if net == "meek" && flow.is_empty() {
                "vless-meek-udp-policy-closed"
            } else {
                "vless-transport-udp-policy-closed"
            };
            assert_eq!(resident_udp_proxy_handler_name(&proxy), expected_handler);
        }
    }

    #[test]
    fn resident_vless_standard_udp_frame_prefixes_payload_length() {
        let frame = vless_udp_length_frame(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
        assert_eq!(frame, [0, 4, 0xde, 0xad, 0xbe, 0xef]);
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

    #[test]
    fn resident_dns_fast_path_uses_one_bounded_dispatcher_task() {
        let manager = include_str!("manager.rs");
        let dispatcher = include_str!("manager/dns_dispatcher.rs");
        let production_dispatcher = dispatcher.split("#[cfg(test)]").next().unwrap();

        assert!(!manager.contains("spawn_resident_dns_datagram_handler"));
        assert!(!manager.contains("spawn_forced_resident_dns_proxy_datagram_handler"));
        assert_eq!(production_dispatcher.matches("tokio::spawn").count(), 1);
        assert!(production_dispatcher.contains("FuturesUnordered"));
        assert!(production_dispatcher.contains("mpsc::channel(queue_depth.max(1))"));
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum UdpExecutorShape {
        Dns,
        ShadowsocksAead,
        Shadowsocks2022,
        Socks5,
        VlessVision,
        VlessStandard,
        VlessXhttpH2,
        VlessXhttpH3,
        Trojan,
        VmessAead,
        AnyTls,
        Hysteria2,
        Tuic,
        Juicity,
        ConnectUdpH2,
        ConnectUdpH3,
        FailClosed,
    }

    fn udp_executor_shape(executor: &UdpSessionExecutor) -> UdpExecutorShape {
        match executor {
            UdpSessionExecutor::Dns => UdpExecutorShape::Dns,
            UdpSessionExecutor::ShadowsocksAead(_) => UdpExecutorShape::ShadowsocksAead,
            UdpSessionExecutor::Shadowsocks2022(_) => UdpExecutorShape::Shadowsocks2022,
            UdpSessionExecutor::Socks5(_) => UdpExecutorShape::Socks5,
            UdpSessionExecutor::VlessVision(_) => UdpExecutorShape::VlessVision,
            UdpSessionExecutor::VlessStandard(_) => UdpExecutorShape::VlessStandard,
            UdpSessionExecutor::VlessXhttpH2(_) => UdpExecutorShape::VlessXhttpH2,
            UdpSessionExecutor::VlessXhttpH3(_) => UdpExecutorShape::VlessXhttpH3,
            UdpSessionExecutor::Trojan(_) => UdpExecutorShape::Trojan,
            UdpSessionExecutor::VmessAead(_) => UdpExecutorShape::VmessAead,
            UdpSessionExecutor::AnyTls(_) => UdpExecutorShape::AnyTls,
            UdpSessionExecutor::Hysteria2(_) => UdpExecutorShape::Hysteria2,
            UdpSessionExecutor::Tuic(_) => UdpExecutorShape::Tuic,
            UdpSessionExecutor::Juicity(_) => UdpExecutorShape::Juicity,
            UdpSessionExecutor::ConnectUdpH2(_) => UdpExecutorShape::ConnectUdpH2,
            UdpSessionExecutor::ConnectUdpH3(_) => UdpExecutorShape::ConnectUdpH3,
            UdpSessionExecutor::FailClosed { .. } => UdpExecutorShape::FailClosed,
        }
    }

    fn test_udp_proxy(handler: ResidentProxyProtocolPlan) -> ResidentProxyPlan {
        ResidentProxyPlan {
            graph_id: "resident-graph:redacted".to_owned(),
            graph_link_hash: "sha256:redacted".to_owned(),
            redacted_link_source: "source:<redacted>".to_owned(),
            protocol: "redacted",
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
            xhttp_download: None,
            xhttp_mode: ResidentXhttpMode::PacketUp,
            xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
            xhttp_xmux: None,
            tls: String::new(),
            allow_insecure: false,
            tls_fragment: None,
            utls_fingerprint: None,
            reality: None,
            handler,
            execution: None,
            chain_parent: None,
            mark: 0,
            mptcp: false,
        }
    }

    fn with_plain_socks5_parent(mut child: ResidentProxyPlan) -> ResidentProxyPlan {
        let parent = test_udp_proxy(ResidentProxyProtocolPlan::Socks5Tcp {
            username: String::new(),
            password: String::new(),
        });
        child.chain_parent = Some(Arc::new(parent));
        child
    }

    #[test]
    fn chained_udp_rejects_datagram_child_without_parent_packet_carrier() {
        let proxy =
            with_plain_socks5_parent(test_udp_proxy(ResidentProxyProtocolPlan::Socks5Tcp {
                username: String::new(),
                password: String::new(),
            }));

        assert_eq!(
            udp_executor_shape(&UdpSessionExecutor::new_proxy_packet(&proxy)),
            UdpExecutorShape::FailClosed
        );
        let graph = proxy.executable_graph_value();
        assert_eq!(
            graph["runtimeComponents"]["packetSessionManager"]["status"],
            "fail-closed"
        );
        assert_eq!(
            graph["runtimeComponents"]["packetSessionManager"]["chainCarrier"],
            "unsupported"
        );
        assert_eq!(
            graph["runtimeComponents"]["udpExecutionAgreement"]["policyClosed"],
            true
        );
        assert_eq!(
            graph["runtimeComponents"]["packetSessionManager"]["negativePathReady"],
            true
        );
        assert_eq!(
            graph["runtimeComponents"]["packetSessionManager"]["transientExchangeCompatible"],
            false
        );
        assert_eq!(
            graph["runtimeComponents"]["probeExecutor"]["udp"]["status"],
            "fail-closed"
        );
        assert!(
            graph["runtimeComponents"]["packetSessionManager"]["unsupportedReason"]
                .as_str()
                .is_some_and(|reason| reason.contains("independent packet path"))
        );
    }

    #[test]
    fn chained_udp_admits_vmess_packet_over_parent_stream() {
        let proxy =
            with_plain_socks5_parent(test_udp_proxy(ResidentProxyProtocolPlan::VmessAeadTcp {
                id: "00000000-0000-0000-0000-000000000001".to_owned(),
            }));

        assert_eq!(
            udp_executor_shape(&UdpSessionExecutor::new_proxy_packet(&proxy)),
            UdpExecutorShape::VmessAead
        );
        let graph = proxy.executable_graph_value();
        assert_eq!(
            graph["runtimeComponents"]["packetSessionManager"]["status"],
            "admitted"
        );
        assert_eq!(
            graph["runtimeComponents"]["packetSessionManager"]["chainCarrier"],
            "parent-connect-stream"
        );
        assert_eq!(
            graph["runtimeComponents"]["udpExecutionAgreement"]["policyClosed"],
            false
        );
        assert_eq!(
            graph["runtimeComponents"]["packetSessionManager"]["transientExchangeCompatible"],
            true
        );
    }
}
