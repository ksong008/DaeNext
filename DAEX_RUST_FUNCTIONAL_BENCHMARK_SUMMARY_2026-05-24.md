# DAEX Rust Functional Benchmark 汇总 2026-05-24

本文件只保留本地，不提交。

数据来源：`/tmp/dae-daex-functional-bench-20260524-125657`。

运行参数：Go `count=10`、`benchtime=1s`；Rust `repeat=10`、`iters=auto`、`warmup=100`。

覆盖状态：`71/71` case 均有 Go/Rust 双侧数据。

| 分类 | case | Go us/op | Rust us/op | Rust/Go time | Go B/op | Rust B/op | Rust/Go B | Go allocs/op | Rust allocs/op | Rust/Go allocs |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| config | `config/parser_example` | 1882.746 | 19.210 | 0.010 | 1766852.600 | 36525.000 | 0.021 | 28414.000 | 419.000 | 0.015 |
| config | `config/schema_example` | 1970.548 | 25.232 | 0.013 | 1781419.500 | 44485.000 | 0.025 | 28696.000 | 592.000 | 0.021 |
| config | `config/include_merger` | 325.699 | 45.336 | 0.139 | 238734.000 | 30038.000 | 0.126 | 4112.000 | 359.000 | 0.087 |
| config | `config/marshal_roundtrip_example` | 2262.100 | 33.389 | 0.015 | 2066374.000 | 78852.000 | 0.038 | 34190.200 | 1063.000 | 0.031 |
| dns | `dns/packed_response_restore` | 0.019 | 0.013 | 0.694 | 48.000 | 45.000 | 0.938 | 1.000 | 1.000 | 1.000 |
| dns | `dns/data_zero_id` | 0.012 | 0.012 | 1.010 | 8.000 | 4.000 | 0.500 | 1.000 | 1.000 | 1.000 |
| dns | `dns/cache_key_roundtrip` | 0.218 | 0.205 | 0.938 | 64.000 | 150.000 | 2.344 | 4.000 | 10.000 | 2.500 |
| dns | `dns/cache_ttl_lookup` | 0.577 | 0.647 | 1.121 | 1136.000 | 2093.000 | 1.842 | 7.000 | 21.000 | 3.000 |
| dns | `dns/doh_get_request` | 0.829 | 0.485 | 0.586 | 1464.000 | 295.000 | 0.202 | 17.000 | 12.000 | 0.706 |
| dns | `dns/doh_post_request` | 1.633 | 0.892 | 0.546 | 5024.000 | 2616.000 | 0.521 | 13.000 | 11.000 | 0.846 |
| dns | `dns/doh_validate_content_type` | 0.772 | 0.243 | 0.315 | 896.000 | 259.000 | 0.289 | 11.000 | 9.000 | 0.818 |
| dns | `dns/validation_question_id` | 0.715 | 0.316 | 0.441 | 340.000 | 476.000 | 1.400 | 14.000 | 13.000 | 0.929 |
| dns | `dns/resolve_asis_guard` | 0.254 | 0.017 | 0.065 | 288.000 | 107.000 | 0.372 | 5.000 | 1.000 | 0.200 |
| routing | `routing/domain_matcher_bitmap` | 0.275 | 0.095 | 0.346 | 64.000 | 29.000 | 0.453 | 3.000 | 2.000 | 0.667 |
| routing | `routing/prefix_parse` | 0.182 | 0.119 | 0.653 | 224.000 | 0.000 | 0.000 | 3.000 | 0.000 | 0.000 |
| geodata | `geodata/streaming_geoip_hit` | 6.172 | 0.042 | 0.007 | 248.000 | 38.000 | 0.153 | 10.000 | 2.000 | 0.200 |
| sniffing | `sniffing/http_host` | 2.704 | 0.084 | 0.031 | 9098.100 | 42.000 | 0.005 | 15.000 | 3.000 | 0.200 |
| outbound | `outbound/select_min_latency` | 0.010 | 0.010 | 1.075 | 0.000 | 0.000 | n/a | 0.000 | 0.000 | n/a |
| outbound | `outbound/filter_annotate_regex` | 235.621 | 111.298 | 0.472 | 148378.000 | 193448.000 | 1.304 | 3108.000 | 2323.000 | 0.747 |
| protocol | `protocol/socks5_address_codec` | 0.131 | 0.062 | 0.471 | 228.000 | 35.000 | 0.154 | 7.000 | 3.000 | 0.429 |
| protocol | `protocol/socks5_handshake_bytes` | 0.230 | 0.109 | 0.473 | 120.000 | 82.000 | 0.683 | 6.000 | 6.000 | 1.000 |
| protocol | `protocol/socks5_udp_packet_wrap` | 0.201 | 0.088 | 0.438 | 91.000 | 67.000 | 0.736 | 4.000 | 4.000 | 1.000 |
| protocol | `protocol/vless_parse_link` | 9.887 | 1.267 | 0.128 | 8704.000 | 908.000 | 0.104 | 168.000 | 18.000 | 0.107 |
| protocol | `protocol/vless_password_to_key` | 0.198 | 0.399 | 2.008 | 120.000 | 176.000 | 1.467 | 4.000 | 7.000 | 1.750 |
| protocol | `protocol/vless_request_header` | 0.439 | 0.097 | 0.220 | 549.000 | 63.000 | 0.115 | 15.000 | 4.000 | 0.267 |
| protocol | `protocol/vmess_parse_link` | 1.158 | 2.065 | 1.783 | 1664.000 | 3553.000 | 2.135 | 29.000 | 49.000 | 1.690 |
| protocol | `protocol/vmess_metadata_bytes` | 0.003 | 0.020 | 6.274 | 0.000 | 12.000 | n/a | 0.000 | 1.000 | n/a |
| protocol | `protocol/vmess_uuid5_compatibility` | 0.110 | 0.291 | 2.644 | 72.000 | 120.000 | 1.667 | 2.000 | 4.000 | 2.000 |
| protocol | `protocol/shadowsocks_parse_link` | 0.633 | 0.998 | 1.577 | 480.000 | 471.000 | 0.981 | 5.000 | 10.000 | 2.000 |
| protocol | `protocol/shadowsocks_metadata_bytes` | 0.043 | 0.031 | 0.726 | 40.000 | 24.000 | 0.600 | 2.000 | 2.000 | 1.000 |
| protocol | `protocol/shadowsocks_ss2022_psk_split` | 0.097 | 0.115 | 1.187 | 80.000 | 139.000 | 1.738 | 3.000 | 5.000 | 1.667 |
| protocol | `protocol/trojan_parse_link` | 5.371 | 0.892 | 0.166 | 6224.000 | 475.000 | 0.076 | 87.000 | 17.000 | 0.195 |
| protocol | `protocol/trojan_tcp_request_header` | 0.686 | 0.173 | 0.253 | 1012.000 | 171.000 | 0.169 | 14.000 | 5.000 | 0.357 |
| protocol | `protocol/trojan_udp_packet` | 0.425 | 0.087 | 0.205 | 532.000 | 58.000 | 0.109 | 9.000 | 4.000 | 0.444 |
| protocol | `protocol/http_parse_link` | 0.783 | 0.652 | 0.833 | 1168.000 | 361.000 | 0.309 | 11.000 | 13.000 | 1.182 |
| protocol | `protocol/http_connect_request` | 1.586 | 0.210 | 0.133 | 1585.000 | 395.000 | 0.249 | 18.000 | 10.000 | 0.556 |
| protocol | `protocol/http_forward_request` | 2.618 | 0.318 | 0.122 | 6544.500 | 512.000 | 0.078 | 24.000 | 13.000 | 0.542 |
| protocol | `protocol/hysteria2_parse_link` | 0.790 | 0.470 | 0.596 | 800.000 | 676.000 | 0.845 | 10.000 | 14.000 | 1.400 |
| protocol | `protocol/hysteria2_export_link` | 1.018 | 0.515 | 0.505 | 1184.000 | 1325.000 | 1.119 | 23.000 | 24.000 | 1.043 |
| protocol | `protocol/hysteria2_pin_normalize` | 0.087 | 0.057 | 0.651 | 24.000 | 8.000 | 0.333 | 3.000 | 1.000 | 0.333 |
| protocol | `protocol/tuic_parse_link` | 3.638 | 1.136 | 0.312 | 5328.000 | 536.000 | 0.101 | 59.000 | 17.000 | 0.288 |
| protocol | `protocol/tuic_export_link` | 1.108 | 0.465 | 0.420 | 1168.000 | 884.000 | 0.757 | 24.000 | 22.000 | 0.917 |
| protocol | `protocol/tuic_alpn_split` | 0.042 | 0.069 | 1.619 | 48.000 | 108.000 | 2.250 | 1.000 | 4.000 | 4.000 |
| protocol | `protocol/juicity_parse_link` | 2.809 | 1.029 | 0.366 | 3792.000 | 511.000 | 0.135 | 35.000 | 12.000 | 0.343 |
| protocol | `protocol/juicity_export_link` | 1.212 | 0.427 | 0.352 | 1344.000 | 969.000 | 0.721 | 21.000 | 19.000 | 0.905 |
| protocol | `protocol/juicity_pinned_decode` | 0.047 | 0.046 | 0.978 | 48.000 | 43.000 | 0.896 | 1.000 | 2.000 | 2.000 |
| protocol | `protocol/anytls_parse_link` | 1.192 | 0.543 | 0.455 | 2352.000 | 413.000 | 0.176 | 20.000 | 13.000 | 0.650 |
| protocol | `protocol/anytls_auth_key` | 0.130 | 0.054 | 0.420 | 128.000 | 0.000 | 0.000 | 2.000 | 0.000 | 0.000 |
| protocol | `protocol/anytls_frame` | 0.022 | 0.015 | 0.708 | 80.000 | 66.000 | 0.825 | 1.000 | 1.000 | 1.000 |
| protocol | `protocol/anytls_underlay` | 0.599 | 0.053 | 0.088 | 840.000 | 26.000 | 0.031 | 16.000 | 4.000 | 0.250 |
| protocol | `protocol/shared_xhttp_mode` | 0.011 | 0.032 | 2.848 | 0.000 | 13.000 | n/a | 0.000 | 2.000 | n/a |
| protocol | `protocol/shared_grpc_cache_key` | 0.059 | 0.149 | 2.526 | 64.000 | 144.000 | 2.250 | 2.000 | 6.000 | 3.000 |
| protocol | `protocol/shared_xhttp_path` | 0.061 | 0.043 | 0.705 | 48.000 | 30.000 | 0.625 | 3.000 | 3.000 | 1.000 |
| protocol | `protocol/shared_canonical_json` | 4.696 | 1.307 | 0.278 | 3890.000 | 3756.000 | 0.966 | 74.000 | 31.000 | 0.419 |
| protocol | `protocol/shared_timer_constants` | 0.000 | 0.000 | 1.020 | 0.000 | 0.000 | n/a | 0.000 | 0.000 | n/a |
| control | `control/magic_network_mark_mptcp` | 0.015 | 0.014 | 0.908 | 16.000 | 10.000 | 0.625 | 1.000 | 1.000 | 1.000 |
| control | `control/choose_dial_target_domain` | 0.395 | 0.080 | 0.202 | 640.000 | 44.000 | 0.069 | 11.000 | 3.000 | 0.273 |
| control | `control/choose_dial_target_domain_plus_plus` | 0.426 | 0.082 | 0.194 | 664.000 | 44.000 | 0.066 | 12.000 | 3.000 | 0.250 |
| control | `control/udp_endpoint_trim_target` | 0.000 | 0.001 | 6.258 | 0.000 | 0.000 | n/a | 0.000 | 0.000 | n/a |
| engine | `engine/runtime_overview` | 0.118 | 0.013 | 0.110 | 320.000 | 24.000 | 0.075 | 3.000 | 1.000 | 0.333 |
| engine | `engine/runtime_overview_scoped_udp` | 0.068 | 0.006 | 0.088 | 224.000 | 0.000 | 0.000 | 1.000 | 0.000 | 0.000 |
| engine | `engine/route_aware_target` | 0.092 | 0.108 | 1.174 | 48.000 | 11.000 | 0.229 | 1.000 | 1.000 | 1.000 |
| engine | `engine/parse_config_api` | 165.929 | 2.622 | 0.016 | 153341.000 | 8100.000 | 0.053 | 2678.000 | 90.000 | 0.034 |
| engine | `engine/read_config_file_minimal` | 61.640 | 9.445 | 0.153 | 40776.900 | 4795.000 | 0.118 | 651.000 | 76.000 | 0.117 |
| engine | `engine/necessary_outbounds` | 0.146 | 0.083 | 0.566 | 160.000 | 170.000 | 1.062 | 4.000 | 6.000 | 1.500 |
| engine | `engine/subscription_persist_cleanup` | 73.991 | 73.827 | 0.998 | 1827.100 | 1690.000 | 0.925 | 31.000 | 26.000 | 0.839 |
| trace | `trace/ringbuf_parse` | 0.050 | 0.027 | 0.536 | 8.000 | 5.000 | 0.625 | 1.000 | 1.000 | 1.000 |
| trace | `trace/tracker_add` | 0.503 | 0.103 | 0.206 | 32.000 | 27.984 | 0.875 | 0.000 | 1.080 | n/a |
| sysdump | `sysdump/enum_strings` | 0.001 | 0.002 | 1.827 | 0.000 | 0.000 | n/a | 0.000 | 0.000 | n/a |
| cli | `cli/validate_minimal_config` | 59.446 | 9.375 | 0.158 | 40652.200 | 4675.000 | 0.115 | 651.000 | 76.000 | 0.117 |
| cli | `cli/export_outline` | 35.878 | 81.183 | 2.263 | 47849.600 | 214841.000 | 4.490 | 97.000 | 1762.000 | 18.165 |

## 读取口径

- `Rust/Go time < 1` 表示 Rust 更快；`> 1` 表示 Rust 更慢。
- `Rust/Go B < 1` 表示 Rust 每次操作分配字节更少。
- `Rust/Go allocs < 1` 表示 Rust 每次操作分配次数更少。
- Go 或 Rust 任一侧为 `0` 时，比值可能为 `n/a`；ns 级哨兵 case 不作为独立性能收益判断。
