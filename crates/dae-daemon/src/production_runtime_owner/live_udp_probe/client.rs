use std::net::SocketAddr;

use serde_json::Value;

use crate::production_runtime_owner::command::{CommandSpec, run_observation_command};
use crate::production_runtime_owner::live_tcp_probe::CLIENT_NETNS;

pub(super) fn run_client_active_udp_probe(target: SocketAddr, iterations: u32) -> Value {
    let target_ip = target.ip().to_string();
    let target_port = target.port();
    let socket_family = if target.is_ipv6() {
        "AF_INET6"
    } else {
        "AF_INET"
    };
    let script = format!(
        "import socket,sys\nok=0\nlast=None\ntarget=({target_ip:?},{target_port})\ns=socket.socket(socket.{socket_family}, socket.SOCK_DGRAM)\ns.settimeout(3)\nfor i in range({iterations}):\n    s.sendto(b\"active-udp-tproxy-ping\", target)\n    data,addr=s.recvfrom(128)\n    last=addr\n    if data != b\"active-udp-tproxy-ack\" or addr[:2] != target:\n        print(f\"bad reply data={{data!r}} addr={{addr!r}}\")\n        sys.exit(2)\n    ok += 1\ns.close()\nprint(f\"active-udp-ack-count={{ok}} last-peer={{last[0]}}:{{last[1]}}\")\nsys.exit(0)\n",
        target_ip = target_ip,
        target_port = target_port,
        socket_family = socket_family,
    );
    run_observation_command(CommandSpec::new(
        "ip",
        ["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}
