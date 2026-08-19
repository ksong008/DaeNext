use super::*;

pub fn new_cleanup_deadline() -> ProxiedDoh3CleanupDeadline {
    ProxiedDoh3CleanupDeadline::from_profile()
}

pub async fn cleanup_proxied_doh3_exchange<T>(target: &mut T) -> ProxiedDoh3CleanupOutcome
where
    T: ProxiedDoh3ExchangeTarget,
{
    cleanup_proxied_doh3_exchange_until(target, new_cleanup_deadline()).await
}

async fn cleanup_proxied_doh3_exchange_until<T>(
    target: &mut T,
    deadline: ProxiedDoh3CleanupDeadline,
) -> ProxiedDoh3CleanupOutcome
where
    T: ProxiedDoh3ExchangeTarget,
{
    let client_discarded = target.discard_client();
    let connection_closed = target.close_connection();

    let mut failures = Vec::new();
    let endpoint = match target.close_endpoint_and_wait_idle(deadline).await {
        Ok(completion) => completion,
        Err(error) => {
            failures.push(format!("close proxied DoH3 endpoint: {error}"));
            None
        }
    };
    let driver = match target.finish_driver(deadline).await {
        Ok(completion) => completion,
        Err(error) => {
            failures.push(format!("finish proxied DoH3 driver: {error}"));
            None
        }
    };
    let bridge = match target.shutdown_bridge(deadline).await {
        Ok(completion) => completion,
        Err(error) => {
            failures.push(format!("shut down proxied DoH3 UDP bridge: {error}"));
            None
        }
    };
    ProxiedDoh3CleanupOutcome {
        deadline,
        client_discarded,
        connection_closed,
        endpoint,
        driver,
        bridge,
        failures,
    }
}

pub fn merge_exchange_and_cleanup_result(
    exchange: Result<Vec<u8>, ProxyDnsRequestError>,
    cleanup: &ProxiedDoh3CleanupOutcome,
) -> Result<Vec<u8>, ProxyDnsRequestError> {
    if cleanup.failures.is_empty() {
        if cleanup.has_forced_completion() {
            return exchange.map_err(|error| {
                ProxyDnsRequestError::new(
                    error.stage(),
                    error.failure(),
                    format!("{error}; cleanup_outcome={cleanup}"),
                )
            });
        }
        return exchange;
    }

    let cleanup_failures = cleanup.failures.join("; ");
    match exchange {
        Ok(_) => Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            ProxyDnsRequestFailure::Network,
            format!(
                "proxied DNS over HTTP/3 cleanup failed: {cleanup_failures}; cleanup_outcome={cleanup}"
            ),
        )),
        Err(error)
            if matches!(
                error.failure(),
                ProxyDnsRequestFailure::Cancelled | ProxyDnsRequestFailure::Deadline
            ) =>
        {
            Err(ProxyDnsRequestError::new(
                error.stage(),
                error.failure(),
                format!(
                    "exchange_error={error}; proxied DNS over HTTP/3 cleanup failed: {cleanup_failures}; cleanup_outcome={cleanup}"
                ),
            ))
        }
        Err(error) => Err(ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Cleanup,
            ProxyDnsRequestFailure::Network,
            format!(
                "exchange_error={error}; proxied DNS over HTTP/3 cleanup failed: {cleanup_failures}; cleanup_outcome={cleanup}"
            ),
        )),
    }
}
