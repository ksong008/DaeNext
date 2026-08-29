use super::*;

mod content {
    #[cfg(test)]
    pub(crate) use dae_product_control::subscription::subscription_links_from_content;
    pub(in crate::daed_product) use dae_product_control::subscription::{
        SubscriptionContentReport, parse_subscription_content,
    };
}
mod compat_node_sync;
mod helper;
mod http;
mod node_stage;
mod outcome {
    pub(in crate::daed_product) use dae_product_control::subscription::SubscriptionRefreshOutcome;
}
mod source;

use dae_product_control::subscription::fetch_error;
use dae_product_control::subscription::{
    SubscriptionRefreshCallbacks, SubscriptionRefreshFetch, SubscriptionRefreshPersist,
    SubscriptionRefreshPersistContent, SubscriptionSourceIdentity,
};

pub(super) use outcome::SubscriptionRefreshOutcome;

#[cfg(test)]
pub(crate) use self::compat_node_sync::replace_subscription_nodes;
#[cfg(test)]
pub(crate) use self::content::subscription_links_from_content;
#[cfg(test)]
pub(crate) use self::http::{
    decode_chunked_body, decode_chunked_body_with_limit, http_response_body_with_limit,
    read_subscription_http_response_with_limit, subscription_http_request,
    subscription_tls_alpn_protocols,
};
#[cfg(test)]
pub(crate) use self::source::fetch_subscription_content;

const SUBSCRIPTION_MAX_BYTES: usize = dae_product_control::subscription::SUBSCRIPTION_MAX_BYTES;

pub(in crate::daed_product) use helper::run_subscription_prepare_helper_command;

struct DaemonSubscriptionRefreshCallbacks<'a> {
    #[cfg(test)]
    control_runtime: &'a ProductControlRuntime,
    #[cfg(not(test))]
    marker: std::marker::PhantomData<&'a ()>,
}

impl SubscriptionRefreshCallbacks for DaemonSubscriptionRefreshCallbacks<'_> {
    fn fetch_subscription(
        &self,
        state: &Path,
        config_dir: &Path,
        source: &SubscriptionSourceIdentity,
    ) -> io::Result<SubscriptionRefreshFetch> {
        #[cfg(not(test))]
        {
            match helper::prepare_subscription_with_helper(state, config_dir, source)? {
                helper::SubscriptionHelperOutcome::Prepared(mut prepared) => {
                    let persist = if prepared.prepared.persist_content {
                        let staging = prepared.persist_staging.take().ok_or_else(|| {
                            io::Error::other(
                                "subscription helper omitted persisted content staging",
                            )
                        })?;
                        Some(SubscriptionRefreshPersist {
                            path: source::persist_subscription_path(
                                config_dir,
                                source.tag.as_deref(),
                            )?,
                            content: SubscriptionRefreshPersistContent::StagedFile(staging),
                        })
                    } else {
                        None
                    };
                    Ok(SubscriptionRefreshFetch::Prepared {
                        prepared: prepared.prepared.clone(),
                        persist,
                    })
                }
                helper::SubscriptionHelperOutcome::FetchFailed(failure) => {
                    Ok(SubscriptionRefreshFetch::FetchFailed(failure))
                }
            }
        }

        #[cfg(test)]
        {
            let proxy_config =
                if source.use_proxy && subscription_link_uses_http_transport(&source.link) {
                    Some(product_default_proxy_config(state)?)
                } else {
                    None
                };
            let fetched = source::fetch_subscription_content_with_proxy_config(
                self.control_runtime,
                config_dir,
                source.tag.as_deref(),
                &source.link,
                proxy_config.as_ref(),
            )?;
            let content = content::parse_subscription_content(&fetched.content);
            let prepared = node_stage::prepare_subscription_refresh(&content);
            let persist = fetched.persist_path.map(|path| SubscriptionRefreshPersist {
                path,
                content: SubscriptionRefreshPersistContent::Bytes(fetched.content.into_bytes()),
            });
            Ok(SubscriptionRefreshFetch::Prepared { prepared, persist })
        }
    }
}

pub(crate) fn refresh_subscription_from_remote(
    control_runtime: &ProductControlRuntime,
    state: &Path,
    config_dir: &Path,
    id: i64,
) -> io::Result<Value> {
    #[cfg(not(test))]
    let _ = control_runtime;
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Subscription);
    let callbacks = DaemonSubscriptionRefreshCallbacks {
        #[cfg(test)]
        control_runtime,
        #[cfg(not(test))]
        marker: std::marker::PhantomData,
    };
    let result = dae_product_control::subscription::refresh_subscription_from_remote_with_callbacks(
        &callbacks, state, config_dir, id,
    );
    allocator_request_reclaim(AllocatorReclaimReason::SubscriptionRefresh);
    result.map(|mut report| {
        if let Value::Object(object) = &mut report {
            object.insert(
                "preparationMode".to_owned(),
                json!(if cfg!(test) {
                    "inline-test"
                } else {
                    "isolated-process"
                }),
            );
        }
        report
    })
}

#[cfg(test)]
pub(in crate::daed_product) fn apply_subscription_refresh_result(
    state: &Path,
    id: i64,
    fetched_at: &str,
    links: &[String],
) -> io::Result<(bool, Vec<Value>)> {
    let content = content::SubscriptionContentReport::from_links(links);
    let source = dae_product_control::subscription::subscription_source_by_id(state, id)?;
    let prepared = node_stage::prepare_subscription_refresh(&content);
    match dae_product_control::subscription::apply_prepared_subscription_refresh_report(
        state, &source, fetched_at, &prepared, None,
    )? {
        dae_product_control::subscription::SubscriptionCommitResult::Applied(applied) => {
            Ok((applied.runtime_input_changed, applied.node_import_result))
        }
        dae_product_control::subscription::SubscriptionCommitResult::Stale => {
            Ok((false, Vec::new()))
        }
    }
}

fn subscription_http_body_limit() -> usize {
    SUBSCRIPTION_MAX_BYTES
}

fn subscription_link_uses_http_transport(link: &str) -> bool {
    url::Url::parse(link)
        .map(|url| matches!(url.scheme(), "http" | "https" | "http-file" | "https-file"))
        .unwrap_or(false)
}
