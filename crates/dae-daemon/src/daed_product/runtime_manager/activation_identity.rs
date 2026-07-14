use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RuntimeActivationIdentity {
    pub(super) product_generation: String,
    pub(super) probe_generation: Option<u64>,
}

pub(super) fn persist_recovered_runtime_identity(
    state: &Path,
    identity: &RuntimeActivationIdentity,
) -> Result<(), String> {
    let mut conn = open_state_connection(state)
        .map_err(|err| format!("open runtime state for interface recovery identity: {err}"))?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| format!("begin interface recovery identity commit: {err}"))?;
    let running = tx
        .query_row(
            "SELECT running FROM systems ORDER BY id LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|err| format!("read running runtime state for interface recovery: {err}"))?;
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
        .map_err(|err| format!("read interface recovery product generation: {err}"))?;
    if persisted_product_generation.as_deref() != Some(identity.product_generation.as_str()) {
        return Err(format!(
            "interface recovery product generation changed before identity commit: expected {:?}, persisted {:?}",
            identity.product_generation, persisted_product_generation
        ));
    }
    write_probe_generation(&tx, identity.probe_generation)?;
    tx.commit()
        .map_err(|err| format!("commit interface recovery identity: {err}"))
}

pub(in crate::daed_product) fn write_probe_generation(
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
            .map_err(|err| format!("set runtime probe generation: {err}")),
        None => tx
            .execute(
                "DELETE FROM daed_product_metadata WHERE key = ?1",
                params![RUNTIME_PROBE_GENERATION_METADATA_KEY],
            )
            .map(|_| ())
            .map_err(|err| format!("clear runtime probe generation: {err}")),
    }
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
