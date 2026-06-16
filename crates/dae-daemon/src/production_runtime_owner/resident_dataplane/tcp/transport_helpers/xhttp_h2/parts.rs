use super::*;

mod packet_up;
pub(crate) use self::packet_up::open_xhttp_packet_up_parts;

mod stream;
pub(crate) use self::stream::open_xhttp_stream_parts;

fn xhttp_primary_tls_underlay_name(proxy: &ResidentProxyPlan) -> &'static str {
    if proxy.tls == "reality" {
        "reality"
    } else if proxy.utls_fingerprint.is_some() {
        "boringssl"
    } else {
        "rustls"
    }
}
