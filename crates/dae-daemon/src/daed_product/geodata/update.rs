use super::http::{fetch_geodata_latest_release, fetch_geodata_url_to_file};
use super::status::update_geodata_resource_status_cache;
use super::update_admission::ProductGeodataUpdateLease;
use super::*;
use super::{GeodataKind, GeodataRelease, GeodataSourceMode};
use dae_product_geodata::geodata_source;
use dae_product_geodata::{GeodataUpdateCallbacks, summarize_geodata_file};

pub(super) fn update_geodata(app: &AppState, kind: GeodataKind) -> io::Result<Value> {
    let context = ProductGeodataUpdateContext::from_app(app);
    let update_lease = context.updates.acquire(kind)?;
    update_geodata_with_lease(&context, kind, update_lease)
}

pub(super) fn update_geodata_with_lease(
    context: &ProductGeodataUpdateContext,
    kind: GeodataKind,
    update_lease: ProductGeodataUpdateLease,
) -> io::Result<Value> {
    update_geodata_with_lease_using(context, kind, update_lease, GeodataPreparationMode::Inline)
}

pub(super) fn update_geodata_with_lease_using(
    context: &ProductGeodataUpdateContext,
    kind: GeodataKind,
    update_lease: ProductGeodataUpdateLease,
    preparation_mode: GeodataPreparationMode,
) -> io::Result<Value> {
    dae_product_geodata::update_geodata_with_lease_using(
        context,
        &context.updates,
        &context.state,
        &context.dir,
        kind,
        update_lease,
        preparation_mode,
    )
}

impl GeodataUpdateCallbacks for ProductGeodataUpdateContext {
    fn prepare_download(
        &self,
        state: &Path,
        dir: &Path,
        kind: GeodataKind,
        output: &Path,
        mode: GeodataPreparationMode,
    ) -> io::Result<dae_product_geodata::GeodataPreparedDownload> {
        match mode {
            GeodataPreparationMode::Inline => {
                prepare_geodata_download_inline(&self.control_runtime, state, kind, output)
            }
            GeodataPreparationMode::IsolatedProcess => {
                prepare_geodata_with_helper(&self.updates, state, dir, kind, output)
            }
        }
    }

    fn runtime_input_versions_if_running(
        &self,
        _state: &Path,
    ) -> io::Result<Option<dae_product_geodata::RuntimeInputVersions>> {
        super::transaction::runtime_input_versions_if_running(self)
    }

    fn update_status_cache(&self, kind: GeodataKind, status: Value) {
        update_geodata_resource_status_cache(self, kind, status);
    }
}

pub(super) fn prepare_geodata_download_inline(
    control_runtime: &ProductControlRuntime,
    state: &Path,
    kind: GeodataKind,
    tmp_path: &Path,
) -> io::Result<GeodataPreparedDownload> {
    let source = geodata_source(state, kind)?;
    let proxy_config = if source.use_proxy {
        Some(product_default_proxy_config(state)?)
    } else {
        None
    };
    let release = match source.mode {
        GeodataSourceMode::ReleaseApi => {
            fetch_geodata_latest_release(control_runtime, kind, &source.url, proxy_config.as_ref())?
        }
        GeodataSourceMode::DirectFile => {
            direct_geodata_release(control_runtime, kind, &source.url, proxy_config.as_ref())
        }
    };
    let download = fetch_geodata_url_to_file(
        control_runtime,
        &release.download_url,
        tmp_path,
        proxy_config.as_ref(),
    )?;
    let summary = summarize_geodata_file(kind, tmp_path)?;
    if summary.category_count == 0 || summary.item_count == 0 || download.bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "downloaded geodata is empty",
        ));
    }
    let version = release
        .version
        .unwrap_or_else(|| geodata_sha256_version(&download.sha256));
    Ok(GeodataPreparedDownload {
        version,
        summary,
        sha256: download.sha256,
        download_bytes: download.bytes,
    })
}

fn geodata_sha256_version(sha256: &str) -> String {
    sha256.chars().take(10).collect()
}

fn direct_geodata_release(
    control_runtime: &ProductControlRuntime,
    kind: GeodataKind,
    source_url: &url::Url,
    proxy_config: Option<&Config>,
) -> GeodataRelease {
    let version = if source_url.as_str() == kind.default_source_url() {
        default_direct_geodata_version(control_runtime, kind, proxy_config)
    } else {
        None
    };
    GeodataRelease {
        version,
        download_url: source_url.clone(),
    }
}

fn default_direct_geodata_version(
    control_runtime: &ProductControlRuntime,
    kind: GeodataKind,
    proxy_config: Option<&Config>,
) -> Option<String> {
    let api_url = url::Url::parse(kind.legacy_release_api_url()).ok()?;
    fetch_geodata_latest_release(control_runtime, kind, &api_url, proxy_config)
        .ok()?
        .version
}
