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
mod userspace_active_datapath;
mod validate_export;
