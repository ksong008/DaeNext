use super::*;

mod admission;
pub(crate) use admission::ControlTransportOwnerAdmission;
mod requirements;
pub(crate) use requirements::ControlTransportOwnerRequirements;
mod shutdown;
pub(crate) use shutdown::ControlTransportOwnerShutdown;
use shutdown::shutdown_control_transport_owner_tasks;
#[cfg(test)]
mod tests;

const CONTROL_TRANSPORT_OWNER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct ControlTransportOwners {
    hysteria2: Option<Hysteria2OwnerRegistryHandle>,
    tuic: Option<TuicOwnerRegistryHandle>,
    juicity: Option<JuicityOwnerRegistryHandle>,
    anytls: Option<AnyTlsOwnerRegistryHandle>,
    h2_carrier: Option<H2CarrierGenerationOwnerHandle>,
    meek: Option<MeekTransportGenerationOwnerHandle>,
    vless_mux: Option<VlessMuxGenerationOwnerHandle>,
    stop: Option<SharedResidentStopSignal>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    registered_carrier_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    stopped: bool,
}

pub(crate) struct ControlTransportOwnerStartError {
    detail: String,
    cleanup: ControlTransportOwnerShutdown,
}

impl std::fmt::Display for ControlTransportOwnerStartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; owner cleanup joined={}, cancelled={}, panicked={}, forced={}",
            self.detail,
            self.cleanup.joined,
            self.cleanup.cancelled,
            self.cleanup.panicked,
            self.cleanup.forced,
        )
    }
}

impl std::fmt::Debug for ControlTransportOwnerStartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlTransportOwnerStartError")
            .field("detail", &self.detail)
            .field("cleanup", &self.cleanup)
            .finish()
    }
}

impl std::error::Error for ControlTransportOwnerStartError {}

impl ControlTransportOwners {
    pub(crate) async fn start(
        runtime: &tokio::runtime::Handle,
        generation: u64,
        runtime_worker_threads: usize,
        requirements: ControlTransportOwnerRequirements,
    ) -> Result<Self, ControlTransportOwnerStartError> {
        let admission = Self::admit(generation, requirements).await?;
        Self::start_admitted(
            runtime,
            generation,
            runtime_worker_threads,
            requirements,
            admission,
        )
        .await
    }

    pub(crate) async fn admit(
        generation: u64,
        requirements: ControlTransportOwnerRequirements,
    ) -> Result<ControlTransportOwnerAdmission, ControlTransportOwnerStartError> {
        ControlTransportOwnerAdmission::acquire(generation, requirements)
            .await
            .map_err(|detail| ControlTransportOwnerStartError {
                detail,
                cleanup: ControlTransportOwnerShutdown::default(),
            })
    }

    pub(crate) async fn start_admitted(
        runtime: &tokio::runtime::Handle,
        generation: u64,
        runtime_worker_threads: usize,
        requirements: ControlTransportOwnerRequirements,
        admission: ControlTransportOwnerAdmission,
    ) -> Result<Self, ControlTransportOwnerStartError> {
        let registered_carrier_permit = admission.into_registered_carrier_permit();
        if requirements.is_empty() {
            return Ok(Self {
                hysteria2: None,
                tuic: None,
                juicity: None,
                anytls: None,
                h2_carrier: None,
                meek: None,
                vless_mux: None,
                stop: None,
                tasks: Vec::new(),
                registered_carrier_permit,
                stopped: false,
            });
        }

        let stop = ResidentStopSignal::shared();
        let mut owners = Self {
            hysteria2: None,
            tuic: None,
            juicity: None,
            anytls: None,
            h2_carrier: None,
            meek: None,
            vless_mux: None,
            stop: Some(Arc::clone(&stop)),
            tasks: Vec::new(),
            registered_carrier_permit,
            stopped: false,
        };

        if requirements.hysteria2 {
            let (handle, task) =
                start_hysteria2_owner_registry_on(runtime, generation, Arc::clone(&stop));
            owners.hysteria2 = Some(handle);
            owners.tasks.push(task);
        }
        if requirements.tuic {
            let (handle, task) =
                start_tuic_owner_registry_on(runtime, generation, Arc::clone(&stop));
            owners.tuic = Some(handle);
            owners.tasks.push(task);
        }
        if requirements.juicity {
            let (handle, task) =
                start_juicity_owner_registry_on(runtime, generation, Arc::clone(&stop));
            owners.juicity = Some(handle);
            owners.tasks.push(task);
        }
        if requirements.anytls {
            let (handle, task) =
                start_anytls_owner_registry_on(runtime, generation, Arc::clone(&stop));
            owners.anytls = Some(handle);
            owners.tasks.push(task);
        }
        if requirements.h2_carrier {
            match start_h2_carrier_generation_owner_on(
                runtime,
                generation,
                Arc::clone(&stop),
                runtime_worker_threads,
            ) {
                Ok((handle, task)) => {
                    owners.h2_carrier = Some(handle);
                    owners.tasks.push(task);
                }
                Err(detail) => return Err(owners.start_error(detail).await),
            }
        }
        if requirements.meek {
            match start_meek_transport_generation_owner_on(
                runtime,
                generation,
                Arc::clone(&stop),
                runtime_worker_threads,
            ) {
                Ok((handle, task)) => {
                    owners.meek = Some(handle);
                    owners.tasks.push(task);
                }
                Err(detail) => return Err(owners.start_error(detail).await),
            }
        }
        if requirements.vless_mux {
            match start_vless_mux_generation_owner_on(
                runtime,
                generation,
                Arc::clone(&stop),
                runtime_worker_threads,
            ) {
                Ok((handle, task)) => {
                    owners.vless_mux = Some(handle);
                    owners.tasks.push(task);
                }
                Err(detail) => return Err(owners.start_error(detail).await),
            }
        }
        Ok(owners)
    }

    pub(crate) fn registries(&self) -> ResidentTransportOwnerRegistries {
        ResidentTransportOwnerRegistries::new(
            self.hysteria2.clone(),
            self.tuic.clone(),
            self.juicity.clone(),
        )
        .with_anytls(self.anytls.clone())
    }

    pub(crate) async fn shutdown(&mut self) -> ControlTransportOwnerShutdown {
        if self.stopped {
            return ControlTransportOwnerShutdown::default();
        }
        self.stopped = true;
        if let Some(stop) = &self.stop {
            stop.store(true, Ordering::Release);
        }
        let shutdown = shutdown_control_transport_owner_tasks(
            &mut self.tasks,
            CONTROL_TRANSPORT_OWNER_SHUTDOWN_TIMEOUT,
        )
        .await;
        self.release_handles();
        shutdown
    }

    async fn start_error(&mut self, detail: String) -> ControlTransportOwnerStartError {
        let cleanup = self.shutdown().await;
        ControlTransportOwnerStartError { detail, cleanup }
    }

    fn release_handles(&mut self) {
        self.hysteria2 = None;
        self.tuic = None;
        self.juicity = None;
        self.anytls = None;
        self.h2_carrier = None;
        self.meek = None;
        self.vless_mux = None;
        self.stop = None;
        self.registered_carrier_permit = None;
    }

    #[cfg(test)]
    pub(crate) fn task_count(&self) -> usize {
        self.tasks.len()
    }
}

impl Drop for ControlTransportOwners {
    fn drop(&mut self) {
        if self.stopped {
            return;
        }
        if let Some(stop) = &self.stop {
            stop.store(true, Ordering::Release);
        }
    }
}
