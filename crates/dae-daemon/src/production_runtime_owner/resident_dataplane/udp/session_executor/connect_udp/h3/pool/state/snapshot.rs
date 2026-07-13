use super::*;
use crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::metrics::ConnectUdpPoolEventSnapshot;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3::pool)
struct ConnectUdpH3PoolSnapshot
{
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3::pool) accepting_actors:
        usize,
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3::pool) retiring_actors:
        usize,
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3::pool) active_sessions:
        usize,
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3::pool) opening_actors:
        usize,
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3::pool) command_queue_capacity:
        usize,
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3::pool) command_queue_used:
        usize,
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3::pool) negotiated_datagram_limit_min:
        Option<usize>,
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3::pool) negotiated_datagram_limit_max:
        Option<usize>,
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3::pool) events:
        ConnectUdpPoolEventSnapshot,
}

impl ConnectUdpH3Pool {
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3::pool) fn snapshot(
        &self,
    ) -> Result<ConnectUdpH3PoolSnapshot, ()> {
        let state = self.state.lock().map_err(|_| ())?;
        let mut snapshot = ConnectUdpH3PoolSnapshot {
            opening_actors: state.opening,
            events: self.events.snapshot(),
            ..ConnectUdpH3PoolSnapshot::default()
        };
        for actor in state
            .actors
            .iter()
            .filter(|actor| !actor.task.is_finished())
        {
            let active = actor.usage.active_sessions.load(Ordering::Acquire);
            let queue_capacity = actor.sender.max_capacity();
            let queue_available = actor.sender.capacity();
            snapshot.active_sessions = snapshot.active_sessions.saturating_add(active);
            snapshot.command_queue_capacity = snapshot
                .command_queue_capacity
                .saturating_add(queue_capacity);
            snapshot.command_queue_used = snapshot
                .command_queue_used
                .saturating_add(queue_capacity.saturating_sub(queue_available));
            snapshot.negotiated_datagram_limit_min = Some(
                snapshot
                    .negotiated_datagram_limit_min
                    .map_or(actor.max_datagram_size, |current| {
                        current.min(actor.max_datagram_size)
                    }),
            );
            snapshot.negotiated_datagram_limit_max = Some(
                snapshot
                    .negotiated_datagram_limit_max
                    .map_or(actor.max_datagram_size, |current| {
                        current.max(actor.max_datagram_size)
                    }),
            );
            if actor.admission.is_accepting() {
                snapshot.accepting_actors = snapshot.accepting_actors.saturating_add(1);
            } else {
                snapshot.retiring_actors = snapshot.retiring_actors.saturating_add(1);
            }
        }
        Ok(snapshot)
    }
}
