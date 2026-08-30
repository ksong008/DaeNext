use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryOwner {
    SubscriptionPersistence,
    RuntimeMaterialization,
    GeodataGeneration,
}

impl RecoveryOwner {
    fn label(self) -> &'static str {
        match self {
            Self::SubscriptionPersistence => "subscription persistence",
            Self::RuntimeMaterialization => "runtime apply",
            Self::GeodataGeneration => "geodata update",
        }
    }
}

pub fn recover_product_durable_state(
    state: &Path,
    config_dir: &Path,
    geodata_dir: &Path,
) -> Result<(), String> {
    let steps = [
        RecoveryOwner::SubscriptionPersistence,
        RecoveryOwner::RuntimeMaterialization,
        RecoveryOwner::GeodataGeneration,
    ];
    for owner in steps {
        let result = match owner {
            RecoveryOwner::SubscriptionPersistence => {
                dae_product_subscription::recover_subscription_persist_transaction(
                    state, config_dir,
                )
                .map_err(|error| error.to_string())
            }
            RecoveryOwner::RuntimeMaterialization => {
                dae_product_runtime::recover_runtime_apply_transaction(state, config_dir)
            }
            RecoveryOwner::GeodataGeneration => {
                dae_product_geodata::recover_geodata_transactions(geodata_dir, state)
                    .map_err(|error| error.to_string())
            }
        };
        result.map_err(|error| format!("recover interrupted {} failed: {error}", owner.label()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn recovery_registry_keeps_dependency_order_explicit() {
        assert_eq!(
            [
                RecoveryOwner::SubscriptionPersistence,
                RecoveryOwner::RuntimeMaterialization,
                RecoveryOwner::GeodataGeneration,
            ]
            .map(RecoveryOwner::label),
            [
                "subscription persistence",
                "runtime apply",
                "geodata update"
            ]
        );
    }

    #[test]
    fn product_recovery_restores_runtime_materialization_from_its_config_scope() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "dae-product-control-recovery-{}-{unique}",
            std::process::id()
        ));
        let config_dir = root.join("config");
        let runtime_dir = config_dir.join("runtime");
        let geodata_dir = config_dir.join("geodata");
        let state = config_dir.join("daed.db");
        fs::create_dir_all(&runtime_dir).expect("create runtime directory");
        fs::create_dir_all(&geodata_dir).expect("create geodata directory");
        dae_product_persistence::ensure_state_schema(&state).expect("create state schema");

        let output = runtime_dir.join("generated.dae");
        let candidate = runtime_dir.join(".generated.dae.recovery.candidate");
        fs::write(&output, b"previous generation").expect("write previous runtime");
        fs::write(&candidate, b"next generation").expect("write candidate runtime");
        let parts = dae_product_runtime::prepare_runtime_apply_transaction(
            &runtime_dir,
            "recovery",
            &output,
            &candidate,
            Some(b"previous generation"),
        )
        .expect("prepare runtime transaction");
        let mut transaction = parts.transaction;
        transaction
            .activate()
            .expect("activate runtime transaction");
        std::mem::forget(transaction);

        recover_product_durable_state(&state, &config_dir, &geodata_dir)
            .expect("recover product durable state");

        assert_eq!(
            fs::read(&output).expect("read recovered runtime"),
            b"previous generation"
        );
        assert!(
            !runtime_dir
                .join(".generated.dae.apply-journal.json")
                .exists()
        );
        assert!(!candidate.exists());
        let _ = fs::remove_dir_all(&root);
    }
}
