use super::*;
pub(crate) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "protocol/socks5_address_codec",
            default_iters: 100_000,
            run: bench_socks5_address_codec,
        },
        BenchCase {
            id: "protocol/socks5_handshake_bytes",
            default_iters: 100_000,
            run: bench_socks5_handshake_bytes,
        },
        BenchCase {
            id: "protocol/socks5_udp_packet_wrap",
            default_iters: 100_000,
            run: bench_socks5_udp_packet_wrap,
        },
        BenchCase {
            id: "protocol/vless_parse_link",
            default_iters: 10_000,
            run: bench_vless_parse_link,
        },
        BenchCase {
            id: "protocol/vless_password_to_key",
            default_iters: 100_000,
            run: bench_vless_password_to_key,
        },
        BenchCase {
            id: "protocol/vless_request_header",
            default_iters: 100_000,
            run: bench_vless_request_header,
        },
        BenchCase {
            id: "protocol/vless_xudp_first_write",
            default_iters: 100_000,
            run: bench_vless_xudp_first_write,
        },
        BenchCase {
            id: "protocol/vmess_parse_link",
            default_iters: 10_000,
            run: bench_vmess_parse_link,
        },
        BenchCase {
            id: "protocol/vmess_metadata_bytes",
            default_iters: 100_000,
            run: bench_vmess_metadata_bytes,
        },
        BenchCase {
            id: "protocol/vmess_uuid5_compatibility",
            default_iters: 100_000,
            run: bench_vmess_uuid5_compatibility,
        },
        BenchCase {
            id: "protocol/vmess_packet_addr_payload",
            default_iters: 100_000,
            run: bench_vmess_packet_addr_payload,
        },
        BenchCase {
            id: "protocol/shadowsocks_parse_link",
            default_iters: 10_000,
            run: bench_shadowsocks_parse_link,
        },
        BenchCase {
            id: "protocol/shadowsocks_metadata_bytes",
            default_iters: 100_000,
            run: bench_shadowsocks_metadata_bytes,
        },
        BenchCase {
            id: "protocol/shadowsocks_ss2022_psk_split",
            default_iters: 100_000,
            run: bench_shadowsocks_ss2022_psk_split,
        },
        BenchCase {
            id: "protocol/trojan_parse_link",
            default_iters: 10_000,
            run: bench_trojan_parse_link,
        },
        BenchCase {
            id: "protocol/trojan_tcp_request_header",
            default_iters: 100_000,
            run: bench_trojan_tcp_request_header,
        },
        BenchCase {
            id: "protocol/trojan_udp_packet",
            default_iters: 100_000,
            run: bench_trojan_udp_packet,
        },
        BenchCase {
            id: "protocol/http_parse_link",
            default_iters: 10_000,
            run: bench_http_parse_link,
        },
        BenchCase {
            id: "protocol/http_connect_request",
            default_iters: 100_000,
            run: bench_http_connect_request,
        },
        BenchCase {
            id: "protocol/http_forward_request",
            default_iters: 100_000,
            run: bench_http_forward_request,
        },
        BenchCase {
            id: "protocol/hysteria2_parse_link",
            default_iters: 10_000,
            run: bench_hysteria2_parse_link,
        },
        BenchCase {
            id: "protocol/hysteria2_export_link",
            default_iters: 100_000,
            run: bench_hysteria2_export_link,
        },
        BenchCase {
            id: "protocol/hysteria2_pin_normalize",
            default_iters: 100_000,
            run: bench_hysteria2_pin_normalize,
        },
        BenchCase {
            id: "protocol/tuic_parse_link",
            default_iters: 10_000,
            run: bench_tuic_parse_link,
        },
        BenchCase {
            id: "protocol/tuic_export_link",
            default_iters: 100_000,
            run: bench_tuic_export_link,
        },
        BenchCase {
            id: "protocol/tuic_alpn_split",
            default_iters: 100_000,
            run: bench_tuic_alpn_split,
        },
        BenchCase {
            id: "protocol/juicity_parse_link",
            default_iters: 10_000,
            run: bench_juicity_parse_link,
        },
        BenchCase {
            id: "protocol/juicity_export_link",
            default_iters: 100_000,
            run: bench_juicity_export_link,
        },
        BenchCase {
            id: "protocol/juicity_pinned_decode",
            default_iters: 100_000,
            run: bench_juicity_pinned_decode,
        },
        BenchCase {
            id: "protocol/anytls_parse_link",
            default_iters: 10_000,
            run: bench_anytls_parse_link,
        },
        BenchCase {
            id: "protocol/anytls_auth_key",
            default_iters: 100_000,
            run: bench_anytls_auth_key,
        },
        BenchCase {
            id: "protocol/anytls_frame",
            default_iters: 100_000,
            run: bench_anytls_frame,
        },
        BenchCase {
            id: "protocol/anytls_underlay",
            default_iters: 100_000,
            run: bench_anytls_underlay,
        },
        BenchCase {
            id: "protocol/shared_xhttp_mode",
            default_iters: 100_000,
            run: bench_shared_xhttp_mode,
        },
        BenchCase {
            id: "protocol/shared_grpc_cache_key",
            default_iters: 100_000,
            run: bench_shared_grpc_cache_key,
        },
        BenchCase {
            id: "protocol/shared_xhttp_path",
            default_iters: 100_000,
            run: bench_shared_xhttp_path,
        },
        BenchCase {
            id: "protocol/shared_canonical_json",
            default_iters: 10_000,
            run: bench_shared_canonical_json,
        },
        BenchCase {
            id: "protocol/shared_timer_constants",
            default_iters: 100_000,
            run: bench_shared_timer_constants,
        },
        BenchCase {
            id: "protocol/masque_parse_link",
            default_iters: 10_000,
            run: bench_masque_parse_link,
        },
        BenchCase {
            id: "protocol/masque_uri_template_expand",
            default_iters: 10_000,
            run: bench_masque_uri_template_expand,
        },
        BenchCase {
            id: "protocol/masque_h2_capsule_roundtrip",
            default_iters: 10_000,
            run: bench_masque_h2_capsule_roundtrip,
        },
        BenchCase {
            id: "protocol/masque_h3_datagram_roundtrip",
            default_iters: 10_000,
            run: bench_masque_h3_datagram_roundtrip,
        },
    ]
}
