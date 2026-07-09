use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dae_outbound::NetworkType;

use crate::production_runtime_owner::resident_dataplane::run_resident_group_resuscitation_check;

use super::*;

const UDP_RESUSCITATION_QUEUE_DEPTH: usize = 64;
const UDP_RESUSCITATION_RECV_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Clone)]
pub(super) struct ResidentUdpResuscitatorHandle {
    sender: SyncSender<ResidentUdpResuscitationRequest>,
}

impl ResidentUdpResuscitatorHandle {
    pub(super) fn trigger(&self, outbound: u8, network_type: NetworkType) {
        match self.sender.try_send(ResidentUdpResuscitationRequest {
            outbound,
            network_type,
        }) {
            Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

pub(super) struct ResidentUdpResuscitator {
    handle: ResidentUdpResuscitatorHandle,
    join: Option<JoinHandle<()>>,
}

impl ResidentUdpResuscitator {
    pub(super) fn start(
        proxy_groups: Arc<BTreeMap<u8, ResidentProxyGroupPlan>>,
        stop: Arc<AtomicBool>,
        event_file: PathBuf,
        event_lock: Arc<Mutex<()>>,
        concurrency: usize,
    ) -> Self {
        let (sender, receiver) = mpsc::sync_channel(UDP_RESUSCITATION_QUEUE_DEPTH);
        let join = thread::Builder::new()
            .name("daed-udp-resuscitation".to_owned())
            .spawn(move || {
                run_udp_resuscitation_worker(
                    receiver,
                    proxy_groups,
                    stop,
                    event_file,
                    event_lock,
                    concurrency.max(1),
                )
            })
            .ok();
        Self {
            handle: ResidentUdpResuscitatorHandle { sender },
            join,
        }
    }

    pub(super) fn handle(&self) -> ResidentUdpResuscitatorHandle {
        self.handle.clone()
    }

    pub(super) fn stop(mut self) {
        drop(self.handle);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct ResidentUdpResuscitationRequest {
    outbound: u8,
    network_type: NetworkType,
}

fn run_udp_resuscitation_worker(
    receiver: Receiver<ResidentUdpResuscitationRequest>,
    proxy_groups: Arc<BTreeMap<u8, ResidentProxyGroupPlan>>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    concurrency: usize,
) {
    while !stop.load(Ordering::Relaxed) {
        let request = match receiver.recv_timeout(UDP_RESUSCITATION_RECV_TIMEOUT) {
            Ok(request) => request,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        if !request.network_type.is_data_udp() {
            continue;
        }
        let Some(group) = proxy_groups.get(&request.outbound) else {
            continue;
        };
        if !group.try_begin_resuscitation() {
            continue;
        }
        run_resident_group_resuscitation_check(
            Arc::new(group.clone()),
            Arc::clone(&stop),
            &event_file,
            &event_lock,
            concurrency,
        );
    }
}
