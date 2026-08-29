use super::http::fetch_http_url_with_proxy_config;
use super::*;
pub(crate) use dae_product_control::subscription::subscription_file_path;
pub(super) use dae_product_control::subscription::{
    FetchedSubscriptionContent, persist_subscription_path, write_persisted_subscription,
};
use dae_product_control::subscription::{read_subscription_file, subscription_url_with_scheme};

#[cfg(test)]
pub(crate) fn fetch_subscription_content(
    config_dir: &Path,
    tag: Option<&str>,
    link: &str,
) -> io::Result<String> {
    let control_runtime = product_test_control_runtime();
    fetch_subscription_content_with_proxy_config(&control_runtime, config_dir, tag, link, None)
        .map(|fetched| fetched.content)
}

pub(super) fn fetch_subscription_content_with_proxy_config(
    control_runtime: &ProductControlRuntime,
    config_dir: &Path,
    tag: Option<&str>,
    link: &str,
    proxy_config: Option<&Config>,
) -> io::Result<FetchedSubscriptionContent> {
    let url = url::Url::parse(link)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    match url.scheme() {
        "http" => fetch_http_url_with_proxy_config(control_runtime, &url, false, proxy_config)
            .map(FetchedSubscriptionContent::without_persist),
        "https" => fetch_http_url_with_proxy_config(control_runtime, &url, true, proxy_config)
            .map(FetchedSubscriptionContent::without_persist),
        "file" => read_subscription_file(&subscription_file_path(config_dir, &url)?)
            .map(FetchedSubscriptionContent::without_persist),
        "http-file" | "https-file" => {
            let persist_path = persist_subscription_path(config_dir, tag)?;
            let fetch_url =
                subscription_url_with_scheme(&url, url.scheme().trim_end_matches("-file"))?;
            let fetched = match fetch_url.scheme() {
                "http" => fetch_http_url_with_proxy_config(
                    control_runtime,
                    &fetch_url,
                    false,
                    proxy_config,
                ),
                "https" => fetch_http_url_with_proxy_config(
                    control_runtime,
                    &fetch_url,
                    true,
                    proxy_config,
                ),
                scheme => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported subscription scheme: {scheme}"),
                )),
            };
            match fetched {
                Ok(content) => Ok(FetchedSubscriptionContent {
                    content,
                    persist_path: Some(persist_path),
                }),
                Err(fetch_err) => read_subscription_file(&persist_path)
                    .map(FetchedSubscriptionContent::without_persist)
                    .map_err(|read_err| {
                        io::Error::new(
                            read_err.kind(),
                            format!(
                                "fetch failed: {}; persisted subscription fallback failed: {}",
                                fetch_err, read_err
                            ),
                        )
                    }),
            }
        }
        scheme => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported subscription scheme: {scheme}"),
        )),
    }
}
