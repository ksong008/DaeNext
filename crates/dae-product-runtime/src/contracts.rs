use std::path::Path;

use dae_config::Config;
use dae_product_core::{ProductHttpWorkerConfig, RUNTIME_PROBE_GENERATION_METADATA_KEY};
use dae_product_persistence::{ensure_state_schema, open_state_connection};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};

use crate::{RUNTIME_GENERATION_METADATA_KEY, RuntimeApplyIntent, process_owned_field_changes};

#[derive(Debug)]
pub struct RuntimeStartOutcome {
    pub report: Value,
}

#[derive(Debug, Default)]
pub struct RuntimeOverviewDeltaState {
    pub reload_count: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProductRuntimeLifecycleLogMode {
    StartupRestore,
    ReloadLocalControl,
    ReloadSubscriptionRefresh,
}

impl ProductRuntimeLifecycleLogMode {
    pub const fn source(self) -> &'static str {
        match self {
            Self::StartupRestore => "startup-restore",
            Self::ReloadLocalControl => "local-control",
            Self::ReloadSubscriptionRefresh => "subscription-refresh",
        }
    }

    pub const fn apply_intent(self) -> RuntimeApplyIntent {
        match self {
            Self::StartupRestore => RuntimeApplyIntent::StartupRestore,
            Self::ReloadLocalControl => RuntimeApplyIntent::LocalControlReload,
            Self::ReloadSubscriptionRefresh => RuntimeApplyIntent::SubscriptionRefresh,
        }
    }

    pub const fn is_startup(self) -> bool {
        matches!(self, Self::StartupRestore)
    }

    pub const fn returns_detailed_report(self) -> bool {
        matches!(self, Self::ReloadSubscriptionRefresh)
    }
}

pub fn process_transition_for_config(
    active_http: Option<ProductHttpWorkerConfig>,
    active_process_config: Option<&Config>,
    desired: &Config,
) -> Option<Value> {
    let desired_http = ProductHttpWorkerConfig::from_config(Some(desired));
    let http_transition = active_http
        .filter(|active| *active != desired_http)
        .map(|active| active.transition_json(desired_http));
    let changed_fields = active_process_config
        .map(|active| process_owned_field_changes(active, desired))
        .unwrap_or_default();
    let non_http_fields = changed_fields
        .iter()
        .copied()
        .filter(|field| {
            !matches!(
                *field,
                "http_queue" | "http_workers" | "http_worker_stack_bytes"
            )
        })
        .collect::<Vec<_>>();
    if non_http_fields.is_empty() {
        return http_transition;
    }
    Some(json!({
        "state": "pending-process-transition",
        "owner": "process-runtime-policy",
        "changedFields": changed_fields,
        "httpRuntime": http_transition,
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeActivationIdentity {
    pub product_generation: String,
    pub probe_generation: Option<u64>,
}

pub fn persist_recovered_runtime_identity(
    state: &Path,
    identity: &RuntimeActivationIdentity,
) -> Result<(), String> {
    ensure_state_schema(state)
        .map_err(|error| format!("open runtime state for interface recovery identity: {error}"))?;
    let mut conn = open_state_connection(state)
        .map_err(|error| format!("open runtime state for interface recovery identity: {error}"))?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| format!("begin interface recovery identity commit: {error}"))?;
    let running = tx
        .query_row(
            "SELECT running FROM systems ORDER BY id LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|error| format!("read running runtime state for interface recovery: {error}"))?;
    if running != Some(1) {
        return Err("interface recovery identity commit requires a running runtime".to_owned());
    }
    let persisted_product_generation = tx
        .query_row(
            "SELECT value FROM daed_product_metadata WHERE key = ?1",
            params![RUNTIME_GENERATION_METADATA_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| format!("read interface recovery product generation: {error}"))?;
    if persisted_product_generation.as_deref() != Some(identity.product_generation.as_str()) {
        return Err(format!(
            "interface recovery product generation changed before identity commit: expected {:?}, persisted {:?}",
            identity.product_generation, persisted_product_generation
        ));
    }
    write_probe_generation(&tx, identity.probe_generation)?;
    tx.commit()
        .map_err(|error| format!("commit interface recovery identity: {error}"))
}

pub fn write_probe_generation(
    tx: &rusqlite::Transaction<'_>,
    generation: Option<u64>,
) -> Result<(), String> {
    match generation {
        Some(generation) => tx
            .execute(
                "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
                params![
                    RUNTIME_PROBE_GENERATION_METADATA_KEY,
                    generation.to_string()
                ],
            )
            .map(|_| ())
            .map_err(|error| format!("set runtime probe generation: {error}")),
        None => tx
            .execute(
                "DELETE FROM daed_product_metadata WHERE key = ?1",
                params![RUNTIME_PROBE_GENERATION_METADATA_KEY],
            )
            .map(|_| ())
            .map_err(|error| format!("clear runtime probe generation: {error}")),
    }
}
