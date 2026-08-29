use std::io;
use std::path::Path;

use serde_json::{Value, json};

use crate::{
    GeodataKind, GeodataPreparedDownload, ProductGeodataUpdateCoordinator, RuntimeInputVersions,
    advise_file_dontneed, commit_geodata_generation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeodataPreparationMode {
    Inline,
    IsolatedProcess,
}

impl GeodataPreparationMode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::IsolatedProcess => "isolated-process",
        }
    }
}

pub trait GeodataUpdateCallbacks {
    fn prepare_download(
        &self,
        state: &Path,
        dir: &Path,
        kind: GeodataKind,
        output: &Path,
        mode: GeodataPreparationMode,
    ) -> io::Result<GeodataPreparedDownload>;

    fn runtime_input_versions_if_running(
        &self,
        state: &Path,
    ) -> io::Result<Option<RuntimeInputVersions>>;

    fn update_status_cache(&self, kind: GeodataKind, status: Value);
}

pub fn update_geodata_with_lease_using<C: GeodataUpdateCallbacks>(
    callbacks: &C,
    updates: &ProductGeodataUpdateCoordinator,
    state: &Path,
    dir: &Path,
    kind: GeodataKind,
    update_lease: crate::ProductGeodataUpdateLease,
    preparation_mode: GeodataPreparationMode,
) -> io::Result<Value> {
    let _update_lease = update_lease;
    std::fs::create_dir_all(dir)?;
    crate::recover_geodata_transaction(dir, state, kind)?;
    let tmp_path = updates.reserve_staging_path(dir, kind, "download")?;
    let prepared = match callbacks.prepare_download(state, dir, kind, &tmp_path, preparation_mode) {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(error);
        }
    };
    let input_versions_before = match callbacks.runtime_input_versions_if_running(state) {
        Ok(version) => version,
        Err(error) => {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(error);
        }
    };
    let committed = commit_geodata_generation(
        updates,
        state,
        dir,
        kind,
        crate::PreparedGeodataGeneration {
            data_stage: tmp_path,
            version: prepared.version,
            summary: prepared.summary,
            sha256: prepared.sha256,
            input_versions_before,
        },
    )?;
    let path = dir.join(kind.file_name());
    let _ = advise_file_dontneed(&path);
    let status = committed.status;
    callbacks.update_status_cache(kind, status.clone());
    let mut response = serde_json::Map::new();
    response.insert(kind.response_key().to_owned(), status);
    response.insert("updated".to_owned(), json!(kind.response_key()));
    if committed.runtime_reload_required {
        response.insert("runtimeReloadRequired".to_owned(), json!(true));
    }
    Ok(Value::Object(response))
}
