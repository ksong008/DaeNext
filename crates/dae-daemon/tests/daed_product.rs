use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine;
use dae_outbound::{
    hysteria2::Hysteria2Link,
    juicity::JuicityLink,
    shadowsocks::{
        ShadowsocksLink, Sip003, aead_cipher_specs,
        ss2022::{CipherConf2022, cipher_confs},
    },
    trojan::TrojanLink,
    tuic::TuicLink,
    vless::VLESSLink,
    vmess::VMessLink,
};
use serde_json::Value;

#[path = "daed_product/helpers.rs"]
mod helpers;
use self::helpers::*;
#[path = "daed_product/api_runtime.rs"]
mod api_runtime;
#[path = "daed_product/contract_cli.rs"]
mod contract_cli;
#[path = "daed_product/export_reset.rs"]
mod export_reset;
#[path = "daed_product/matrix.rs"]
mod matrix;
#[path = "daed_product/support.rs"]
mod support;
use self::support::*;
