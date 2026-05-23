use serde_json::Value;

use super::model::{DEFAULT_ACTIVE_UDP_TARGET_IP, DEFAULT_ACTIVE_UDP_TARGET_PORT};
use crate::production_runtime_owner::active_tcp::CLIENT_NETNS;
use crate::production_runtime_owner::command::{CommandSpec, run_observation_command};

pub(super) fn run_client_active_udp_probe(target: &str, iterations: u32) -> Value {
    let script = format!(
        "import socket,sys\nok=0\nlast=None\ns=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.settimeout(3)\nfor i in range({iterations}):\n    s.sendto(b\"stage53-udp-tproxy-ping\", ({target_ip:?},{target_port}))\n    data,addr=s.recvfrom(128)\n    last=addr\n    if data != b\"stage53-udp-tproxy-ack\" or addr != ({target_ip:?},{target_port}):\n        print(f\"bad reply data={{data!r}} addr={{addr!r}}\")\n        sys.exit(2)\n    ok += 1\ns.close()\nprint(f\"stage53-udp-ack-count={{ok}} last-peer={{last[0]}}:{{last[1]}}\")\nsys.exit(0)\n",
        target_ip = target
            .split(':')
            .next()
            .unwrap_or(DEFAULT_ACTIVE_UDP_TARGET_IP),
        target_port = target
            .split(':')
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(DEFAULT_ACTIVE_UDP_TARGET_PORT),
    );
    run_observation_command(CommandSpec::new(
        "ip",
        ["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}
