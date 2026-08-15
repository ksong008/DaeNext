use super::super::super::plan::ResidentProxyBinding;
use super::super::super::tcp::{TcpProxySelection, TcpRouteSelection, TcpRoutingLogMetadata};

pub(super) fn native_tcp_probe_selection(
    binding: ResidentProxyBinding,
    target: &str,
) -> TcpProxySelection {
    let mark = binding.effective_socket_mark();
    let mptcp = binding.plan().mptcp;
    TcpProxySelection {
        mptcp,
        route: TcpRouteSelection {
            initial_outbound: 0,
            final_outbound: 0,
            final_mark: mark,
            userspace_route_executed: false,
            userspace_route_must: false,
            dial_target: target.to_owned(),
            dial_ip: false,
            log_metadata: TcpRoutingLogMetadata {
                pid: 0,
                dscp: 0,
                pname: String::new(),
                mac: String::new(),
            },
        },
        proxy: binding,
    }
}
