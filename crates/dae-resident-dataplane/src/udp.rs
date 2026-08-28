use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

#[cfg(test)]
use dae_datapath::udp_io::UdpOriginalDstRecvError;
use dae_datapath::udp_io::{UdpBatchReceiver, UdpOriginalDstPacket, UdpPayload, UdpPayloadPool};
#[cfg(test)]
use dae_outbound::shared_transport::GrpcMode;
#[cfg(test)]
use dae_outbound::{
    hysteria2::{Hysteria2UdpMessage, decode_hysteria2_udp_message, encode_hysteria2_udp_message},
    juicity::{decode_stream_packet_frame, seal_stream_packet_frame},
    socks5::Socks5Address,
    tuic::{TuicUdpPacket, decode_tuic_udp_packet, encode_tuic_udp_packet},
};
use dae_resident_core::events::{
    ResidentEventKind, ResidentEventMetadata, admit_event, append_admitted_event,
    append_event_with_metadata,
};
#[cfg(test)]
use dae_resident_plan::{
    ResidentHysteria2ObfsPlan, ResidentProxyProtocolPlan, ResidentXhttpMode, UdpPacketSemantics,
};
use dae_resident_plan::{ResidentProxyBinding, ResidentProxyPlan, resident_udp_chain_admission};
use dae_resident_transport::inherit_quic_endpoint_observation;
use serde_json::json;
use tokio::time;

#[cfg(test)]
use super::plan::share_resident_proxy_groups;
use super::plan::{ResidentProxyGroupPlan, SharedResidentProxyGroupMap};
use super::*;

fn admit_udp_payload(
    payload: &mut UdpPayload,
    admission: &ResidentUdpPayloadAdmission,
) -> Result<(), ResidentUdpPayloadAdmissionError> {
    let permit = admission.try_acquire(payload.len())?;
    let _ = payload.attach_retained_owner(permit);
    Ok(())
}

#[cfg(test)]
use dae_resident_udp::vless_udp_length_frame;
pub(crate) use dae_resident_udp::*;

mod worker;
pub(super) use self::worker::*;
mod manager;
pub(crate) use self::manager::ResidentUdpGenerationPlan;
use self::manager::*;
mod proxy_dns_forwarder;
pub(super) use self::proxy_dns_forwarder::*;
mod probe_dns;
pub(super) use self::probe_dns::*;

#[cfg(test)]
mod tests;
