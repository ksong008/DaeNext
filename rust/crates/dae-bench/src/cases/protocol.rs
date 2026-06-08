use std::hint::black_box;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose};
use dae_outbound::{
    AnyTLSLink, HttpConnectOptions, HttpProxyLink, Hysteria2Link, JuicityLink, ShadowsocksLink,
    ShadowsocksMetadata, Socks5Address, TrojanLink, TuicLink, VLESSLink, VMessLink, VMessMetadata,
};

use crate::{BenchCase, Measurement, measure};

const UUID: &str = "7c12c745-63a5-433d-9e60-022e469b5bd4";
const SS2022_PSK_128: &str = "MTIzNDU2Nzg5MDEyMzQ1Ng==";

mod registry;
pub(crate) use self::registry::*;
mod socks5;
use self::socks5::*;
mod vmess_vless;
use self::vmess_vless::*;
mod classic_proxy;
use self::classic_proxy::*;
mod modern_quic;
use self::modern_quic::*;
mod anytls;
use self::anytls::*;
mod shared_transport;
use self::shared_transport::*;
mod helpers;
use self::helpers::*;
