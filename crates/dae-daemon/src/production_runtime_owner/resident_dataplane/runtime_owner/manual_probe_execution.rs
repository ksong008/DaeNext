use super::super::control_transport_owners::{
    ControlTransportOwnerRequirements, ControlTransportOwners,
};
use super::*;

#[cfg(test)]
mod tests;

const MANUAL_PROBE_RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct ManualProbeExecution {
    plans: BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
    runtime: ManualProbeRuntime,
    owners: ControlTransportOwners,
}

pub(super) struct ManualProbeRuntime {
    runtime: Option<tokio::runtime::Runtime>,
    worker_threads: usize,
}

impl ManualProbeExecution {
    pub(super) fn start(
        config: &Config,
        links: &[String],
        reload_generation: u64,
        concurrency: usize,
    ) -> Result<Self, String> {
        let mut plans = plan::build_resident_manual_probe_plans_for_helper(config, links);
        apply_runtime_generation(&mut plans, reload_generation);
        let resources = ResidentRuntimeResourceConfig::from_config(config);
        let runtime = ManualProbeRuntime::start(&resources, concurrency)?;
        let requirements = ControlTransportOwnerRequirements::from_probe_plans(
            plans.values().filter_map(|plan| plan.as_ref().ok()),
        );
        let owners = match runtime.block_on(ControlTransportOwners::start(
            runtime.handle(),
            reload_generation,
            runtime.worker_threads(),
            requirements,
        )) {
            Ok(owners) => owners,
            Err(error) => {
                return Err(format!("start manual probe transport owners: {error}"));
            }
        };
        Ok(Self {
            plans,
            runtime,
            owners,
        })
    }

    pub(super) fn plans(&self) -> &BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>> {
        &self.plans
    }

    pub(super) fn runtime(&self) -> &tokio::runtime::Runtime {
        self.runtime.runtime()
    }

    pub(super) fn registries(&self) -> ResidentTransportOwnerRegistries {
        self.owners.registries()
    }

    pub(super) fn shutdown(&mut self) -> Result<(), String> {
        if !self.runtime.is_active() {
            return Ok(());
        }
        let shutdown = self.runtime.block_on(self.owners.shutdown());
        let worker_threads = self.runtime.worker_threads();
        self.runtime.shutdown();
        if shutdown.is_clean() {
            Ok(())
        } else {
            Err(format!(
                "manual probe transport owner cleanup degraded: workers={}, joined={}, cancelled={}, panicked={}, forced={}",
                worker_threads,
                shutdown.joined,
                shutdown.cancelled,
                shutdown.panicked,
                shutdown.forced,
            ))
        }
    }
}

impl ManualProbeRuntime {
    pub(super) fn start(
        resources: &ResidentRuntimeResourceConfig,
        concurrency: usize,
    ) -> Result<Self, String> {
        let available_parallelism = thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .max(1);
        let worker_threads = available_parallelism
            .min(resources.tcp_runtime_workers.value().max(1))
            .min(concurrency.max(1))
            .max(1);
        let blocking_threads = available_parallelism.min(worker_threads).max(1);
        let worker_stack_bytes = resources
            .tcp_flow_stack_bytes
            .value()
            .max(RESIDENT_DNS_TRANSPORT_WORKER_STACK_BYTES_MIN);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .max_blocking_threads(blocking_threads)
            .thread_name(crate::production_runtime_owner::RESIDENT_MANUAL_PROBE_TASK_NAME)
            .thread_stack_size(worker_stack_bytes)
            .enable_all()
            .build()
            .map_err(|error| format!("start Tokio manual latency probe runtime: {error}"))?;
        Ok(Self {
            runtime: Some(runtime),
            worker_threads,
        })
    }

    pub(super) fn runtime(&self) -> &tokio::runtime::Runtime {
        self.runtime
            .as_ref()
            .expect("manual probe runtime remains active until explicit shutdown")
    }

    pub(super) fn handle(&self) -> &tokio::runtime::Handle {
        self.runtime().handle()
    }

    pub(super) fn worker_threads(&self) -> usize {
        self.worker_threads
    }

    fn is_active(&self) -> bool {
        self.runtime.is_some()
    }

    pub(super) fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        self.runtime().block_on(future)
    }

    pub(super) fn shutdown(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(MANUAL_PROBE_RUNTIME_SHUTDOWN_TIMEOUT);
        }
    }
}

impl Drop for ManualProbeRuntime {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Drop for ManualProbeExecution {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn apply_runtime_generation(
    plans: &mut BTreeMap<String, Result<plan::ResidentProxyProbePlan, String>>,
    reload_generation: u64,
) {
    for probe_result in plans.values_mut() {
        let binding_error = match probe_result {
            Ok(probe) => probe.apply_runtime_generation(reload_generation).err(),
            Err(_) => None,
        };
        if let Some(error) = binding_error {
            *probe_result = Err(error);
        }
    }
}
