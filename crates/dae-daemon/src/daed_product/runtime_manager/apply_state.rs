use super::*;

#[derive(Clone)]
pub(in crate::daed_product) struct ProductRuntimeApplySnapshot {
    was_running: bool,
    lifecycle_epoch: u64,
    config: Option<Arc<Config>>,
    config_content: Option<Arc<str>>,
    resident_generation: Option<ResidentActiveGenerationSnapshot>,
    transition_identity: Option<RuntimeTransitionIdentity>,
    transition: RuntimeTransitionClass,
    probe_generation: Option<u64>,
    reload_count: u64,
    allocator_publication_id: u64,
    last_report: Option<Arc<Value>>,
}

impl ProductRuntimeApplySnapshot {
    pub(super) fn transition_for_activation(
        &self,
        state: &ProductRuntimeState,
    ) -> Result<RuntimeTransitionClass, String> {
        let same_config = match (&self.config, &state.config) {
            (Some(previous), Some(active)) => Arc::ptr_eq(previous, active),
            (None, None) => true,
            _ => false,
        };
        if self.lifecycle_epoch != state.lifecycle_epoch
            || self.was_running != state.runtime.is_some()
            || self.transition_identity != state.transition_identity
            || !same_config
        {
            return Err("runtime changed between reload snapshot and activation".to_owned());
        }
        Ok(self.transition)
    }
}

impl ProductRuntimeManager {
    pub(in crate::daed_product) fn begin_apply_generation(&self) -> String {
        if let Ok(mut inner) = self.inner().lock() {
            return inner.apply.begin();
        }
        RuntimeApplyState::default().begin()
    }

    pub(in crate::daed_product) fn set_apply_generation_phase(
        &self,
        generation: &str,
        phase: &str,
    ) {
        if let Ok(mut inner) = self.inner().lock() {
            inner.apply.set_phase(generation, phase);
        }
    }

    pub(in crate::daed_product) fn finish_apply_generation(
        &self,
        generation: &str,
        phase: &str,
        failure: Option<(&str, &str)>,
        reconciliation_required: bool,
    ) {
        if let Ok(mut inner) = self.inner().lock()
            && inner.apply.finish(
                generation,
                phase,
                failure.map(|(_, rollback)| rollback),
                reconciliation_required,
            )
        {
            if phase == "committed" && failure.is_none() {
                inner.active_generation = Some(generation.to_owned());
            }
            inner.last_error = failure.map(|(error, _)| error.to_owned());
            inner.last_transition_at = Some(now_text());
        }
    }

    pub(in crate::daed_product) fn commit_runtime_generation_publication(&self) {
        let Ok(inner) = self.inner().lock() else {
            return;
        };
        if let Some(ProductRuntimeInstance::Resident(runtime)) = inner.runtime.as_ref() {
            runtime.commit_generation_publication();
        }
    }

    pub(in crate::daed_product) fn snapshot_for_apply(
        &self,
        prepared: &PreparedProductRuntime,
    ) -> Result<ProductRuntimeApplySnapshot, String> {
        let probe_generation = self.current_probe_generation();
        let inner = self
            .inner()
            .lock()
            .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
        let transition = prepared.transition_from(&inner);
        // Only an in-place generation publication can reactivate the captured Arc. A physical
        // KernelRebind destroys the old runtime and rollback already rebuilds the prior config;
        // pinning its complete router/DNS/protocol graph serves no rollback purpose and retained
        // the old live heap after a successful commit.
        let retain_resident_generation = transition == RuntimeTransitionClass::GenerationSwap;
        Ok(ProductRuntimeApplySnapshot {
            was_running: inner.runtime.is_some(),
            lifecycle_epoch: inner.lifecycle_epoch,
            config: inner.config.clone(),
            config_content: inner.config_content.clone(),
            resident_generation: retain_resident_generation
                .then(|| {
                    inner.runtime.as_ref().and_then(|runtime| match runtime {
                        ProductRuntimeInstance::Resident(runtime) => {
                            runtime.active_generation_snapshot()
                        }
                        ProductRuntimeInstance::Fake(_) => None,
                    })
                })
                .flatten(),
            transition_identity: inner.transition_identity,
            transition,
            probe_generation,
            reload_count: inner.reload_count,
            allocator_publication_id: inner.allocator_publication_id,
            last_report: inner.last_report.clone(),
        })
    }

    pub(in crate::daed_product) fn reconcile_failed_activation(
        &self,
        state: &Path,
        snapshot: &ProductRuntimeApplySnapshot,
    ) -> Result<(), String> {
        let (running, identity) = {
            let inner = self
                .inner()
                .lock()
                .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
            (inner.runtime.is_some(), inner.transition_identity)
        };
        if running != snapshot.was_running {
            return Err("previous runtime is unavailable".to_owned());
        }
        let probe_generation = self.current_probe_generation();
        if running
            && probe_generation != snapshot.probe_generation
            && let Some(product_generation) = self.active_generation()
        {
            super::activation_identity::persist_recovered_runtime_identity(
                state,
                &super::activation_identity::RuntimeActivationIdentity {
                    product_generation,
                    probe_generation,
                },
            )?;
        }
        if identity != snapshot.transition_identity {
            return Err("previous runtime inputs changed during recovery".to_owned());
        }
        Ok(())
    }

    pub(in crate::daed_product) fn restore_after_failed_apply(
        &self,
        snapshot: &ProductRuntimeApplySnapshot,
        latency_seed: &[Value],
        current_geodata_version: i64,
    ) -> Result<bool, String> {
        if matches!(
            snapshot.transition,
            RuntimeTransitionClass::NoChange | RuntimeTransitionClass::ProcessRestart
        ) {
            let _lifecycle = self
                .lifecycle()
                .lock()
                .map_err(|_| "product runtime lifecycle lock poisoned".to_owned())?;
            let mut inner = self
                .inner()
                .lock()
                .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
            inner.config = snapshot.config.clone();
            inner.config_content = snapshot.config_content.clone();
            inner.transition_identity = snapshot.transition_identity;
            inner.reload_count = snapshot.reload_count;
            inner.allocator_publication_id = snapshot.allocator_publication_id;
            inner.last_report = snapshot.last_report.clone();
            return Ok(true);
        }
        if let Some(generation) = snapshot.resident_generation.as_ref() {
            let _lifecycle = self
                .lifecycle()
                .lock()
                .map_err(|_| "product runtime lifecycle lock poisoned".to_owned())?;
            let (same_physical_runtime, restored) = {
                let mut inner = self
                    .inner()
                    .lock()
                    .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
                match inner.runtime.as_mut() {
                    Some(ProductRuntimeInstance::Resident(runtime)) => {
                        let same_physical_runtime = runtime.owns_generation_snapshot(generation);
                        let restored =
                            runtime.restore_active_generation(generation).map(|report| {
                                inner.config = snapshot.config.clone();
                                inner.config_content = snapshot.config_content.clone();
                                inner.transition_identity = snapshot.transition_identity;
                                inner.last_report = Some(Arc::new(report));
                            });
                        (same_physical_runtime, restored)
                    }
                    Some(ProductRuntimeInstance::Fake(_)) | None => (
                        false,
                        Err(
                            "active runtime cannot restore the resident generation snapshot"
                                .to_owned(),
                        ),
                    ),
                }
            };
            if restored.is_ok() {
                return Ok(true);
            }
            if same_physical_runtime {
                return restored.map(|()| true);
            }
        }
        if snapshot.was_running {
            let config = snapshot
                .config
                .clone()
                .ok_or_else(|| "running runtime snapshot has no config".to_owned())?;
            let mut prepared = prepare_product_runtime_candidate(config)?;
            let mut exact = true;
            if let Some(mut identity) = snapshot.transition_identity {
                exact = identity.geodata_input_version == current_geodata_version;
                identity.geodata_input_version = current_geodata_version;
                prepared = prepared.with_transition_identity(identity);
            }
            reload_prepared_product_runtime_with_config_content(
                self.lifecycle(),
                self.inner(),
                prepared,
                snapshot.config_content.clone(),
                "runtime-apply-rollback",
                latency_seed,
                None,
            )?;
            Ok(exact)
        } else {
            self.discard_runtime_without_stop_gate("runtime-apply-rollback")?;
            Ok(true)
        }
    }
}
