// UDP worker startup keeps socket, routing, session, shutdown, and metrics ownership explicit.
#![allow(clippy::too_many_arguments)]

use serde_json::Value;

use super::super::{ActiveGenerationSlot, ResidentDataplaneGeneration};
use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn resident_udp_loop_async(
    socket: std::net::UdpSocket,
    active_generation: ActiveGenerationSlot<ResidentDataplaneGeneration>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    active_sessions: Arc<AtomicUsize>,
) -> Value {
    run_resident_udp_session_manager_async(
        socket,
        active_generation,
        stop,
        event_file,
        event_lock,
        active_sessions,
    )
    .await
}
