use serde::{Deserialize, Serialize};

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LatencyProbeConfigSource {
    ActiveRuntime,
    SelectedState,
}

impl LatencyProbeConfigSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::ActiveRuntime => "current-runtime-config",
            Self::SelectedState => "selected-state-snapshot",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "current-runtime-config" => Some(Self::ActiveRuntime),
            "selected-state-snapshot" => Some(Self::SelectedState),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct LatencyProbeHelperConfig {
    pub(super) source: String,
    pub(super) content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct LatencyProbeHelperRequest {
    #[serde(rename = "schemaVersion")]
    pub(super) schema_version: u64,
    pub(super) scope: String,
    #[serde(rename = "reloadGeneration")]
    pub(super) reload_generation: u64,
    #[serde(rename = "requestedLinks")]
    pub(super) requested_links: Vec<String>,
    pub(super) config: LatencyProbeHelperConfig,
    pub(super) concurrency: usize,
}

#[derive(Serialize)]
struct LatencyProbeHelperConfigRef<'a> {
    source: &'static str,
    content: &'a str,
}

#[derive(Serialize)]
struct LatencyProbeHelperRequestRef<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    scope: &'static str,
    #[serde(rename = "reloadGeneration")]
    reload_generation: u64,
    #[serde(rename = "requestedLinks")]
    requested_links: &'a [String],
    config: LatencyProbeHelperConfigRef<'a>,
    concurrency: usize,
}

pub(super) fn encode_latency_probe_helper_request(
    config_content: &str,
    config_source: LatencyProbeConfigSource,
    reload_generation: u64,
    concurrency: usize,
    links: &[String],
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&LatencyProbeHelperRequestRef {
        schema_version: 1,
        scope: "manual-latency-probe",
        reload_generation,
        requested_links: links,
        config: LatencyProbeHelperConfigRef {
            source: config_source.as_str(),
            content: config_content,
        },
        concurrency: concurrency.max(1),
    })
}

pub(crate) fn latency_probe_helper_response_from_request(input: &[u8]) -> Result<Value, String> {
    let request = latency_probe_helper_request_from_input(input)?;
    let config = build_runtime_config_from_content(&request.config.content)?;
    let snapshots = crate::production_runtime_owner::run_resident_manual_latency_probe_helper(
        &config,
        &request.requested_links,
        request.reload_generation,
        request.concurrency.max(1),
    );
    Ok(json!({
        "schemaVersion": 1,
        "scope": "manual-latency-probe",
        "reloadGeneration": request.reload_generation,
        "snapshots": snapshots,
        "errors": [],
    }))
}

pub(crate) fn latency_probe_helper_response_lines_from_request<W: Write>(
    input: &[u8],
    mut writer: W,
) -> Result<(), String> {
    let request = latency_probe_helper_request_from_input(input)?;
    let config = build_runtime_config_from_content(&request.config.content)?;
    crate::production_runtime_owner::run_resident_manual_latency_probe_helper_streaming(
        &config,
        &request.requested_links,
        request.reload_generation,
        request.concurrency.max(1),
        |snapshot| {
            serde_json::to_writer(&mut writer, &snapshot)
                .map_err(|err| format!("write latency probe helper stream snapshot: {err}"))?;
            writer
                .write_all(b"\n")
                .map_err(|err| format!("write latency probe helper stream newline: {err}"))?;
            writer
                .flush()
                .map_err(|err| format!("flush latency probe helper stream: {err}"))?;
            Ok(())
        },
    )
}

fn latency_probe_helper_request_from_input(
    input: &[u8],
) -> Result<LatencyProbeHelperRequest, String> {
    if input.len() > LATENCY_PROBE_HELPER_MAX_IO_BYTES {
        return Err(format!(
            "latency probe helper stdin exceeds {} bytes",
            LATENCY_PROBE_HELPER_MAX_IO_BYTES
        ));
    }
    let request: LatencyProbeHelperRequest = serde_json::from_slice(input)
        .map_err(|err| format!("parse latency probe helper request: {err}"))?;
    if request.schema_version != 1 {
        return Err("unsupported latency probe helper request schemaVersion".to_owned());
    }
    if request.scope != "manual-latency-probe" {
        return Err("unsupported latency probe helper request scope".to_owned());
    }
    if LatencyProbeConfigSource::parse(&request.config.source).is_none() {
        return Err("unsupported latency probe helper config source".to_owned());
    }
    Ok(request)
}
