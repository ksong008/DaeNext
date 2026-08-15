use super::*;

mod packet_up;
pub(crate) use self::packet_up::open_xhttp_packet_up_parts;

mod stream;
pub(crate) use self::stream::open_xhttp_stream_parts;

fn xhttp_primary_tls_underlay_name(proxy: &ResidentProxyPlan) -> &'static str {
    match proxy.execution_plan().security {
        ResidentSecurityUnderlayPlan::RealityBoring
        | ResidentSecurityUnderlayPlan::RealityFingerprint => "reality",
        ResidentSecurityUnderlayPlan::FingerprintAwareTls => "boringssl",
        ResidentSecurityUnderlayPlan::StandardTls
        | ResidentSecurityUnderlayPlan::InsecureTls
        | ResidentSecurityUnderlayPlan::FragmentedTls => "boringssl",
        _ => "unsupported",
    }
}
