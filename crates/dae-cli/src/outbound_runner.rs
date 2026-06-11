use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use dae_outbound::anytls::{self, AnyTLSLink};
use dae_outbound::http_proxy::{self, HttpConnectOptions, HttpProxyLink, request as http_request};
use dae_outbound::hysteria2::{self, Hysteria2Link};
use dae_outbound::juicity::{self, JuicityLink};
use dae_outbound::parse_link_chain;
use dae_outbound::shadowsocks::{self, ShadowsocksLink, ShadowsocksMetadata};
use dae_outbound::shared_transport;
use dae_outbound::socks5::{self, Socks5Address, handshake, udp_packet};
use dae_outbound::trojan::{self, TrojanLink, TrojanMetadata};
use dae_outbound::tuic::{self, TuicLink};
use dae_outbound::vless::{self, VLESSLink};
use dae_outbound::vmess::{self, VMessLink, VMessMetadata};
use serde_json::json;

use crate::runner::RunnerOutput;

pub(crate) fn run_outbound(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("socks5") => run_socks5(&args[1..]),
        Some("http") => run_http(&args[1..]),
        Some("shadowsocks") | Some("ss") => run_shadowsocks(&args[1..]),
        Some("trojan") | Some("trojan-go") => run_trojan(&args[1..]),
        Some("vmess") => run_vmess(&args[1..]),
        Some("vless") => run_vless(&args[1..]),
        Some("hysteria2") | Some("hy2") => run_hysteria2(&args[1..]),
        Some("tuic") => run_tuic(&args[1..]),
        Some("juicity") => run_juicity(&args[1..]),
        Some("anytls") => run_anytls(&args[1..]),
        Some("transport") | Some("shared-transport") => run_transport(&args[1..]),
        Some(subcommand) => {
            RunnerOutput::usage(format!("unsupported outbound subcommand: {subcommand}"))
        }
        None => RunnerOutput::usage("missing outbound subcommand"),
    }
}

mod args_hex;
mod cmd_anytls;
mod cmd_http;
mod cmd_hysteria2;
mod cmd_juicity;
mod cmd_shadowsocks;
mod cmd_shared_transport;
mod cmd_socks5;
mod cmd_trojan;
mod cmd_tuic;
mod cmd_vless;
mod cmd_vmess;

use args_hex::*;
use cmd_anytls::*;
use cmd_http::*;
use cmd_hysteria2::*;
use cmd_juicity::*;
use cmd_shadowsocks::*;
use cmd_shared_transport::*;
use cmd_socks5::*;
use cmd_trojan::*;
use cmd_tuic::*;
use cmd_vless::*;
use cmd_vmess::*;
