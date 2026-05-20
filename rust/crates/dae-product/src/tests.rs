use serde_json::Value;

use crate::*;

mod helpers;
use helpers::*;

mod base_contracts;
mod daemon_stage23_27;
mod daemon_stage28_30;
mod daemon_stage31_36;
mod daemon_stage37_40;
mod daemon_stage41_49;
mod daemon_stage50_54;
mod product_protocol_matrix;
mod protocol_https_proxy_82;
mod protocol_socks_http_shadowsocks;
mod protocol_ss2022_tcp_88;
mod protocol_trojan;
mod protocol_trojan_go_grpc_86;
mod protocol_trojan_go_httpupgrade_85;
mod protocol_trojan_go_inner_shadowsocks_87;
mod protocol_trojan_go_wss_84;
mod protocol_trojan_tls_83;
mod protocol_vless;
mod protocol_vless_transport_74_76;
mod protocol_vless_transport_77_79;
mod protocol_vless_transport_80;
mod protocol_vmess_core_65_68;
mod protocol_vmess_shared_69_73;
mod shared_transport_tls_81;
mod true_default_daemon;
