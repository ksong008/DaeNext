use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dae_product_core::product_now_text;
use serde_json::{Value, json};

static RUNTIME_APPLY_GENERATION_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Default)]
pub struct RuntimeApplyState {
    generation: Option<String>,
    phase: Option<String>,
    rollback_result: Option<String>,
    reconciliation_required: bool,
    updated_at: Option<String>,
}

impl RuntimeApplyState {
    pub fn begin(&mut self) -> String {
        let sequence = RUNTIME_APPLY_GENERATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let generation = format!("{}-{timestamp}-{sequence}", std::process::id());
        self.generation = Some(generation.clone());
        self.phase = Some("prepare".to_owned());
        self.rollback_result = None;
        self.reconciliation_required = false;
        self.updated_at = Some(product_now_text());
        generation
    }

    pub fn set_phase(&mut self, generation: &str, phase: &str) -> bool {
        if self.generation.as_deref() != Some(generation) {
            return false;
        }
        self.phase = Some(phase.to_owned());
        self.updated_at = Some(product_now_text());
        true
    }

    pub fn finish(
        &mut self,
        generation: &str,
        phase: &str,
        rollback_result: Option<&str>,
        reconciliation_required: bool,
    ) -> bool {
        if self.generation.as_deref() != Some(generation) {
            return false;
        }
        self.phase = Some(phase.to_owned());
        self.rollback_result = rollback_result.map(str::to_owned);
        self.reconciliation_required = reconciliation_required;
        self.updated_at = Some(product_now_text());
        true
    }

    pub fn summary(&self) -> Value {
        json!({
            "generationId": self.generation,
            "phase": self.phase,
            "rollbackResult": self.rollback_result,
            "reconciliationRequired": self.reconciliation_required,
            "updatedAt": self.updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_generation_cannot_overwrite_active_apply_state() {
        let mut state = RuntimeApplyState::default();
        let first = state.begin();
        let second = state.begin();
        assert!(!state.set_phase(&first, "committed"));
        assert!(state.finish(&second, "committed", None, false));
        assert_eq!(state.summary()["phase"], json!("committed"));
    }
}
