use super::*;

const PRODUCT_CONTROL_RESULT_GRACE: Duration = Duration::from_millis(100);
const PRODUCT_PROXY_FETCH_TIMEOUT: Duration = Duration::from_secs(60);

pub(super) fn fetch_http_url_via_default_proxy_on_control(
    control_runtime: &ProductControlRuntime,
    config: &Config,
    url: &url::Url,
    tls: bool,
    request: &[u8],
    response_limit: usize,
) -> Result<Vec<u8>, String> {
    let config = config.clone();
    let url = url.clone();
    let request = request.to_vec();
    control_runtime
        .execute(
            ProductControlTaskKind::ProxyHttp,
            PRODUCT_PROXY_FETCH_TIMEOUT.saturating_add(PRODUCT_CONTROL_RESULT_GRACE),
            move |cancellation| async move {
                crate::production_runtime_owner::fetch_http_url_via_default_proxy_async(
                    &config,
                    &url,
                    tls,
                    &request,
                    response_limit,
                    cancellation.cancelled(),
                )
                .await
            },
        )
        .map_err(|error| error.to_string())?
}

pub(super) fn product_default_proxy_config(state: &Path) -> io::Result<Config> {
    let preview = materialize_runtime(state, None, true)?;
    let content = preview
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("runtime materializer did not return content"))?;
    build_runtime_config_from_content(content)
        .map_err(|err| io::Error::other(format!("build default proxy config: {err}")))
}
