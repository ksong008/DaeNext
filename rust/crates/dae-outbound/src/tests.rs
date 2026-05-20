use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use crate::*;

mod helpers;
use helpers::*;

mod dataplane_base;
mod dataplane_http_stage82;
mod dataplane_trojan;
mod dataplane_trojan_stage83;
mod dataplane_trojan_stage84;
mod dataplane_trojan_stage85;
mod dataplane_vless;
mod dataplane_vless_stage80;
mod dataplane_vmess;
mod group_policy;
mod protocol_modern;
mod protocol_shadowsocks_trojan;
mod protocol_socks_http;
mod protocol_vmess_vless;
mod shared_transport_contract;
mod shared_transport_dataplane;
mod shared_transport_tls_stage81;
