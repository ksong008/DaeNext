use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use dae_outbound::{
    hysteria2::Hysteria2Link,
    juicity::JuicityLink,
    shadowsocks::{ShadowsocksLink, Sip003},
    trojan::TrojanLink,
    tuic::TuicLink,
    vless::VLESSLink,
    vmess::VMessLink,
};
use serde_json::Value;

include!("daed_product/helpers.rs");
include!("daed_product/matrix.rs");
include!("daed_product/contract_cli.rs");
include!("daed_product/api_runtime.rs");
include!("daed_product/export_reset.rs");
include!("daed_product/support.rs");
