use super::*;
use std::sync::OnceLock;

pub(crate) struct ControlTransportOwnerAdmission {
    registered_carrier_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl ControlTransportOwnerAdmission {
    pub(super) async fn acquire(
        generation: u64,
        requirements: ControlTransportOwnerRequirements,
    ) -> Result<Self, String> {
        let registered_carrier_permit =
            if generation == 0 && requirements.requires_registered_carrier_scope() {
                Some(acquire_registered_carrier_scope().await?)
            } else {
                None
            };
        Ok(Self {
            registered_carrier_permit,
        })
    }

    pub(super) fn into_registered_carrier_permit(
        self,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.registered_carrier_permit
    }
}

async fn acquire_registered_carrier_scope() -> Result<tokio::sync::OwnedSemaphorePermit, String> {
    static ADMISSION: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    Arc::clone(ADMISSION.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1))))
        .acquire_owned()
        .await
        .map_err(|_| "control transport registered-carrier admission is closed".to_owned())
}
