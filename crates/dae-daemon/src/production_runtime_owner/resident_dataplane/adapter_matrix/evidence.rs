use super::*;
pub(crate) fn resident_live_matrix_evidence_from_env() -> ResidentLiveMatrixEvidence {
    let Some((env, source)) = resident_live_matrix_evidence_env_value() else {
        return ResidentLiveMatrixEvidence::missing();
    };
    let source = source.trim().to_owned();
    if source.is_empty() {
        return ResidentLiveMatrixEvidence::missing();
    }
    let text = match fs::read_to_string(&source) {
        Ok(text) => text,
        Err(err) => {
            return ResidentLiveMatrixEvidence::invalid(
                env,
                source,
                format!("read remote live matrix evidence: {err}"),
            );
        }
    };
    let root: Value = match serde_json::from_str(&text) {
        Ok(root) => root,
        Err(err) => {
            return ResidentLiveMatrixEvidence::invalid(
                env,
                source,
                format!("parse remote live matrix evidence: {err}"),
            );
        }
    };
    resident_live_matrix_evidence_from_value(env, Some(source), &root)
}

fn resident_live_matrix_evidence_env_value() -> Option<(&'static str, String)> {
    std::env::var(RESIDENT_LIVE_MATRIX_EVIDENCE_ENV)
        .map(|value| (RESIDENT_LIVE_MATRIX_EVIDENCE_ENV, value))
        .or_else(|_| {
            std::env::var(RESIDENT_LIVE_MATRIX_EVIDENCE_LEGACY_ENV)
                .map(|value| (RESIDENT_LIVE_MATRIX_EVIDENCE_LEGACY_ENV, value))
        })
        .ok()
}

pub(crate) fn resident_live_matrix_evidence_from_value(
    env: &'static str,
    source: Option<String>,
    root: &Value,
) -> ResidentLiveMatrixEvidence {
    let source_for_error = source.clone().unwrap_or_else(|| "<inline>".to_owned());
    let schema = root["schema"].as_str().map(str::to_owned);
    let schema_version = root["schemaVersion"].as_i64();
    let candidate_sha256 = root["candidateSha256"].as_str().map(str::to_owned);
    let row_count = root["rowCount"].as_u64().unwrap_or(0) as usize;
    let pass_count = root["passCount"].as_u64().unwrap_or(0) as usize;
    let all_pass = root["allPass"].as_bool().unwrap_or(false);
    let Some(rows) = root["rows"].as_array() else {
        return ResidentLiveMatrixEvidence {
            env,
            source,
            schema,
            schema_version,
            candidate_sha256,
            row_count,
            pass_count,
            all_pass,
            valid: false,
            ready_handlers: BTreeSet::new(),
            error: Some(format!(
                "{REMOTE_LIVE_MATRIX_INVALID}: rows array missing in {source_for_error}"
            )),
        };
    };
    let mut ready_handlers = BTreeSet::new();
    for row in rows {
        let Some(name) = row["row"].as_str() else {
            continue;
        };
        if resident_live_matrix_row_passes(name, row) {
            ready_handlers.insert(name.to_owned());
        }
    }
    let required_handlers = resident_live_adapter_matrix_entries()
        .iter()
        .map(|entry| entry.formal_matrix_handler)
        .collect::<BTreeSet<_>>();
    let all_handlers_ready = required_handlers
        .iter()
        .all(|handler| ready_handlers.contains(*handler));
    let valid = schema.as_deref() == Some("native-current-live-resident-matrix")
        && schema_version == Some(1)
        && all_pass
        && row_count == required_handlers.len()
        && pass_count == required_handlers.len()
        && rows.len() == required_handlers.len()
        && all_handlers_ready;
    let error = if valid {
        None
    } else {
        Some(format!(
            "{REMOTE_LIVE_MATRIX_INVALID}: schema={schema:?} schemaVersion={schema_version:?} rowCount={row_count} passCount={pass_count} allPass={all_pass} readyHandlers={}",
            ready_handlers.len()
        ))
    };
    ResidentLiveMatrixEvidence {
        env,
        source,
        schema,
        schema_version,
        candidate_sha256,
        row_count,
        pass_count,
        all_pass,
        valid,
        ready_handlers,
        error,
    }
}

pub(crate) fn resident_live_matrix_row_passes(name: &str, row: &Value) -> bool {
    row["pass"].as_bool() == Some(true)
        && row["ready"].as_bool() == Some(true)
        && target_large_page_passes(row, "google", 10_000)
        && target_large_page_passes(row, "youtube", 100_000)
        && proxy_evidence_passes(row, "www.google.com")
        && proxy_evidence_passes(row, "www.youtube.com")
        && row["targetFailures"]
            .as_array()
            .is_none_or(|failures| failures.is_empty())
        && resident_live_adapter_matrix_entries()
            .iter()
            .any(|entry| entry.formal_matrix_handler == name)
}

pub(crate) fn target_large_page_passes(row: &Value, target: &str, min_size: u64) -> bool {
    let target = &row["targets"][target];
    target["http_code"].as_u64() == Some(200)
        && target["largePagePass"].as_bool() == Some(true)
        && target["size"].as_u64().is_some_and(|size| size >= min_size)
}

pub(crate) fn proxy_evidence_passes(row: &Value, domain: &str) -> bool {
    row["proxyEvidence"][domain].as_bool() == Some(true)
}
