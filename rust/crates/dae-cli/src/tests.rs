use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::*;

mod helpers;
use helpers::*;

mod cli_surface;
mod outbound_modern_transports;
mod outbound_shadowsocks_trojan;
mod outbound_socks_http;
mod outbound_vmess_vless;
mod runtime_admission_31_40;
mod runtime_admission_41_54;
mod runtime_candidate_preflight;
mod runtime_command_inventory;
mod runtime_protocol_55_61;
mod runtime_shared_tls_stage81;
mod runtime_vless_core;
mod runtime_vless_shared_transport;
mod runtime_vless_xhttp_xmux_stage80;
mod runtime_vmess_core_65_68;
mod runtime_vmess_shared_transport_69_73;
mod userspace_active_datapath;
mod validate_export;
