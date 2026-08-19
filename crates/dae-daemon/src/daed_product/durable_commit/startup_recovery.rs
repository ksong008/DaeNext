use super::*;

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

pub(in crate::daed_product) fn recover_product_durable_state(
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
                super::super::nodes_subscriptions_groups::recover_subscription_persist_transaction(
                    state, config_dir,
                )
                .map_err(|error| error.to_string())
            }
            RecoveryOwner::RuntimeMaterialization => {
                super::super::runtime_apply::recover_runtime_apply_transaction(state, config_dir)
            }
            RecoveryOwner::GeodataGeneration => {
                super::super::geodata::recover_geodata_transactions(geodata_dir, state)
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
}
