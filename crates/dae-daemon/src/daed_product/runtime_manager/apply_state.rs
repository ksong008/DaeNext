use super::*;

static RUNTIME_APPLY_GENERATION_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Default)]
pub(in crate::daed_product) struct RuntimeApplyState {
    generation: Option<String>,
    phase: Option<String>,
    rollback_result: Option<String>,
    reconciliation_required: bool,
    updated_at: Option<String>,
}

impl RuntimeApplyState {
    pub(super) fn summary(&self) -> Value {
        json!({
            "generationId": self.generation,
            "phase": self.phase,
            "rollbackResult": self.rollback_result,
            "reconciliationRequired": self.reconciliation_required,
            "updatedAt": self.updated_at,
        })
    }
}

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
        let sequence = RUNTIME_APPLY_GENERATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let generation = format!("{}-{timestamp}-{sequence}", std::process::id());
        if let Ok(mut inner) = self.inner.lock() {
            inner.apply.generation = Some(generation.clone());
            inner.apply.phase = Some("prepare".to_owned());
            inner.apply.rollback_result = None;
            inner.apply.reconciliation_required = false;
            inner.apply.updated_at = Some(now_text());
        }
        generation
    }

    pub(in crate::daed_product) fn set_apply_generation_phase(
        &self,
        generation: &str,
        phase: &str,
    ) {
        if let Ok(mut inner) = self.inner.lock()
            && inner.apply.generation.as_deref() == Some(generation)
        {
            inner.apply.phase = Some(phase.to_owned());
            inner.apply.updated_at = Some(now_text());
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
            && inner.apply.generation.as_deref() == Some(generation)
        {
            inner.apply.phase = Some(phase.to_owned());
            inner.apply.rollback_result = failure.map(|(_, rollback)| rollback.to_owned());
            inner.apply.reconciliation_required = reconciliation_required;
            inner.apply.updated_at = Some(now_text());
            if phase == "committed" && failure.is_none() {
                inner.active_generation = Some(generation.to_owned());
            }
            inner.last_error = failure.map(|(error, _)| error.to_owned());
            inner.last_transition_at = Some(now_text());
        }
    }

    pub(in crate::daed_product) fn snapshot_for_apply(
        &self,
    ) -> Result<ProductRuntimeApplySnapshot, String> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
        Ok(ProductRuntimeApplySnapshot {
            was_running: inner.runtime.is_some(),
            config: inner.config.clone(),
            config_content: inner.config_content.clone(),
            resident_generation: inner.runtime.as_ref().and_then(|runtime| match runtime {
                ProductRuntimeInstance::Resident(runtime) => runtime.active_generation_snapshot(),
                ProductRuntimeInstance::Fake(_) => None,
            }),
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
                                inner.last_report = Some(report);
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
            self.stop_and_wait_for_cleanup("runtime-apply-rollback")?;
            Ok(())
        }
    }
}
