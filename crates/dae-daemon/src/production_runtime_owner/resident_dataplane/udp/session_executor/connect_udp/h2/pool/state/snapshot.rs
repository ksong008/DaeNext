use super::*;
use crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::metrics::ConnectUdpPoolEventSnapshot;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h2::pool)
struct ConnectUdpH2PoolSnapshot
{
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h2::pool) accepting_connections:
        usize,
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h2::pool) retiring_connections:
        usize,
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h2::pool) active_sessions:
        usize,
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h2::pool) opening_connections:
        usize,
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h2::pool) stream_capacity:
        usize,
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h2::pool) stream_slots_available:
        usize,
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h2::pool) events:
        ConnectUdpPoolEventSnapshot,
}

impl ConnectUdpH2Pool {
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h2::pool) fn snapshot(
        &self,
    ) -> Result<ConnectUdpH2PoolSnapshot, ()> {
        let state = self.state.lock().map_err(|_| ())?;
        let mut snapshot = ConnectUdpH2PoolSnapshot {
            opening_connections: state.opening,
            events: self.events.snapshot(),
            ..ConnectUdpH2PoolSnapshot::default()
        };
        for client in state
            .clients
            .iter()
            .filter(|client| !client.driver_task.is_finished())
        {
            let active = client.usage.active_sessions.load(Ordering::Acquire);
            let capacity = self
                .sessions_per_connection
                .min(client.sender.current_max_send_streams());
            snapshot.active_sessions = snapshot.active_sessions.saturating_add(active);
            snapshot.stream_capacity = snapshot.stream_capacity.saturating_add(capacity);
            snapshot.stream_slots_available = snapshot
                .stream_slots_available
                .saturating_add(capacity.saturating_sub(active));
            if client.usage.accepting.load(Ordering::Acquire) {
                snapshot.accepting_connections = snapshot.accepting_connections.saturating_add(1);
            } else {
                snapshot.retiring_connections = snapshot.retiring_connections.saturating_add(1);
            }
        }
        Ok(snapshot)
    }
}
