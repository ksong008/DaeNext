use super::*;
#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        RESIDENT_LIVE_MATRIX_EVIDENCE_ENV, resident_live_adapter_entry_missing,
        resident_live_adapter_entry_remote_live_matrix_ready, resident_live_adapter_matrix_entries,
        resident_live_matrix_evidence_from_value,
    };

    #[test]
    fn remote_live_matrix_evidence_admits_all_rows_only_when_large_pages_are_proxied() {
        let rows = resident_live_adapter_matrix_entries()
            .iter()
            .map(|entry| live_row(entry.formal_matrix_handler))
            .collect::<Vec<_>>();
        let evidence = resident_live_matrix_evidence_from_value(
            RESIDENT_LIVE_MATRIX_EVIDENCE_ENV,
            Some("/tmp/current-live-summary.json".to_owned()),
            &json!({
                "schema": "native-current-live-resident-matrix",
                "schemaVersion": 1,
                "candidateSha256": "abc",
                "rowCount": rows.len(),
                "passCount": rows.len(),
                "allPass": true,
                "rows": rows,
                "directControlNotCounted": {
                    "google": {"http_code": 200, "size": 90000},
                    "youtube": {"http_code": 200, "size": 700000}
                }
            }),
        );

        assert!(evidence.valid);
        for entry in resident_live_adapter_matrix_entries() {
            assert!(resident_live_adapter_entry_remote_live_matrix_ready(
                entry, &evidence
            ));
            assert!(resident_live_adapter_entry_missing(entry, &evidence).is_empty());
        }
    }

    #[test]
    fn remote_live_matrix_evidence_rejects_missing_proxy_evidence() {
        let mut rows = resident_live_adapter_matrix_entries()
            .iter()
            .map(|entry| live_row(entry.formal_matrix_handler))
            .collect::<Vec<_>>();
        rows[0]["proxyEvidence"]["www.youtube.com"] = json!(false);
        let evidence = resident_live_matrix_evidence_from_value(
            RESIDENT_LIVE_MATRIX_EVIDENCE_ENV,
            Some("/tmp/current-live-summary.json".to_owned()),
            &json!({
                "schema": "native-current-live-resident-matrix",
                "schemaVersion": 1,
                "rowCount": rows.len(),
                "passCount": rows.len(),
                "allPass": true,
                "rows": rows
            }),
        );

        assert!(!evidence.valid);
        let first = &resident_live_adapter_matrix_entries()[0];
        assert!(!resident_live_adapter_entry_remote_live_matrix_ready(
            first, &evidence
        ));
        assert!(!resident_live_adapter_entry_missing(first, &evidence).is_empty());
    }

    fn live_row(row: &str) -> Value {
        json!({
            "row": row,
            "pass": true,
            "ready": true,
            "targets": {
                "google": {
                    "http_code": 200,
                    "size": 82_000,
                    "largePagePass": true
                },
                "youtube": {
                    "http_code": 200,
                    "size": 712_000,
                    "largePagePass": true
                }
            },
            "proxyEvidence": {
                "www.google.com": true,
                "www.youtube.com": true
            },
            "targetFailures": []
        })
    }
}
