use std::net::SocketAddr;

use dae_datapath::UdpDirectSocketReport;
use serde_json::{Value, json};

pub(super) use dae_datapath::udp_io::recv_udp_with_original_dst;

pub(super) fn udp_direct_report_json(report: &UdpDirectSocketReport, target: SocketAddr) -> Value {
    json!({
        "requested_mark": report.requested_mark,
        "so_mark": report.so_mark,
        "so_mark_applied": report.so_mark_applied,
        "peer_addr": report.peer_addr,
        "local_addr": report.local_addr,
        "target": target.to_string(),
    })
}
