use super::*;

pub(super) use dae_product_control::runtime::RuntimeActivationIdentity;

pub(super) fn persist_recovered_runtime_identity(
    state: &Path,
    identity: &RuntimeActivationIdentity,
) -> Result<(), String> {
    dae_product_control::runtime::persist_recovered_runtime_identity(state, identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_state(scope: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "daed-recovery-identity-{scope}-{}",
            fastrand::u64(..)
        ));
        let state = root.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let conn = open_state_connection(&state).unwrap();
        conn.execute("INSERT INTO systems(running) VALUES(1)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
            params![RUNTIME_GENERATION_METADATA_KEY, "product-generation"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
            params![RUNTIME_PROBE_GENERATION_METADATA_KEY, "6"],
        )
        .unwrap();
        drop(conn);
        (root, state)
    }

    #[test]
    fn interface_recovery_updates_only_the_probe_generation() {
        let (root, state) = recovery_state("commit");
        persist_recovered_runtime_identity(
            &state,
            &RuntimeActivationIdentity {
                product_generation: "product-generation".to_owned(),
                probe_generation: Some(7),
            },
        )
        .unwrap();

        assert_eq!(
            get_metadata(&state, RUNTIME_GENERATION_METADATA_KEY)
                .unwrap()
                .as_deref(),
            Some("product-generation")
        );
        assert_eq!(
            get_metadata(&state, RUNTIME_PROBE_GENERATION_METADATA_KEY)
                .unwrap()
                .as_deref(),
            Some("7")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interface_recovery_rejects_a_stale_product_generation() {
        let (root, state) = recovery_state("stale");
        let error = persist_recovered_runtime_identity(
            &state,
            &RuntimeActivationIdentity {
                product_generation: "superseded-generation".to_owned(),
                probe_generation: Some(7),
            },
        )
        .unwrap_err();

        assert!(error.contains("product generation changed"), "{error}");
        assert_eq!(
            get_metadata(&state, RUNTIME_PROBE_GENERATION_METADATA_KEY)
                .unwrap()
                .as_deref(),
            Some("6")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
