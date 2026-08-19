use std::sync::Arc;

use dae_outbound::NetworkType;

type ResidentDataUdpAvailabilityRecorder = dyn Fn(NetworkType, i64) + Send + Sync;

#[derive(Clone)]
pub struct ResidentDataUdpAvailabilityHandle {
    recorder: Arc<ResidentDataUdpAvailabilityRecorder>,
}

impl ResidentDataUdpAvailabilityHandle {
    pub fn new(recorder: impl Fn(NetworkType, i64) + Send + Sync + 'static) -> Self {
        Self {
            recorder: Arc::new(recorder),
        }
    }

    pub fn record(&self, network_type: NetworkType, checked_at_unix: i64) {
        (self.recorder)(network_type, checked_at_unix);
    }
}
