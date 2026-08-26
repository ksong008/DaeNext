use super::*;

#[derive(Clone)]
pub(in crate::daed_product) struct ProductRuntimeApplySnapshot {
    was_running: bool,
    config: Option<Arc<Config>>,
    config_content: Option<Arc<str>>,
    resident_generation: Option<ResidentActiveGenerationSnapshot>,
    transition_identity: Option<RuntimeTransitionIdentity>,
}

impl ProductRuntimeManager {
    pub(in crate::daed_product) fn begin_apply_generation(&self) -> String {
        if let Ok(mut inner) = self.inner.lock() {
            return inner.apply.begin();
        }
        RuntimeApplyState::default().begin()
    }

    pub(in crate::daed_product) fn set_apply_generation_phase(
        &self,
        generation: &str,
        phase: &str,
    ) {
        if let Ok(mut inner) = self.inner.lock() {
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
        if let Ok(mut inner) = self.inner.lock()
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
        let Ok(inner) = self.inner.lock() else {
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
        let inner = self
            .inner
            .lock()
            .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
        let transition = match (inner.runtime.as_ref(), inner.config.as_deref()) {
            (Some(_), Some(active)) => classify_runtime_transition(
                active,
                inner.transition_identity,
                prepared.config(),
                prepared.transition_identity(),
            ),
            (None, _) | (Some(_), None) => RuntimeTransitionClass::KernelRebind,
        };
        // Only an in-place generation publication can reactivate the captured Arc. A physical
        // KernelRebind destroys the old runtime and rollback already rebuilds the prior config;
        // pinning its complete router/DNS/protocol graph serves no rollback purpose and retained
        // the old live heap after a successful commit.
        let retain_resident_generation = transition == RuntimeTransitionClass::GenerationSwap;
        Ok(ProductRuntimeApplySnapshot {
            was_running: inner.runtime.is_some(),
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
        })
    }

    pub(in crate::daed_product) fn restore_after_failed_apply(
        &self,
        snapshot: &ProductRuntimeApplySnapshot,
        latency_seed: &[Value],
    ) -> Result<(), String> {
        if let Some(generation) = snapshot.resident_generation.as_ref() {
            let _lifecycle = self
                .lifecycle
                .lock()
                .map_err(|_| "product runtime lifecycle lock poisoned".to_owned())?;
            let (same_physical_runtime, restored) = {
                let mut inner = self
                    .inner
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
                return Ok(());
            }
            if same_physical_runtime {
                return restored;
            }
        }
        if snapshot.was_running {
            let config = snapshot
                .config
                .clone()
                .ok_or_else(|| "running runtime snapshot has no config".to_owned())?;
            let prepared = prepare_product_runtime_candidate(config)?;
            reload_prepared_product_runtime_with_config_content(
                &self.lifecycle,
                &self.inner,
                prepared,
                snapshot.config_content.clone(),
                "runtime-apply-rollback",
                latency_seed,
            )?;
            Ok(())
        } else {
            self.discard_runtime_without_stop_gate("runtime-apply-rollback")?;
            Ok(())
        }
    }
}
