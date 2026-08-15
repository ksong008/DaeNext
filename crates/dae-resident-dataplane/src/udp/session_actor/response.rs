use super::*;

pub(super) async fn wait_and_record_udp_session_response(
    key: &UdpSessionKey,
    context: &UdpSessionActorContext,
    executor: &mut Option<UdpSessionExecutor>,
    proxy: Option<&ResidentProxyBinding>,
) -> Result<(), String> {
    let (Some(executor), Some(proxy)) = (executor.as_mut(), proxy) else {
        return std::future::pending().await;
    };
    let exchange = match executor.wait_response().await {
        Ok(Some(exchange)) => exchange,
        Ok(None) => return Ok(()),
        Err(err) => {
            record_response_error(key, context, proxy, &err).await;
            return Err(format!("upstream-read-failed: {err}"));
        }
    };
    record_response(key, context, proxy, exchange).await;
    drain_udp_session_responses(key, context, executor, proxy).await
}

pub(super) async fn drain_udp_session_responses(
    key: &UdpSessionKey,
    context: &UdpSessionActorContext,
    executor: &mut UdpSessionExecutor,
    proxy: &ResidentProxyBinding,
) -> Result<(), String> {
    for _ in 0..16 {
        let exchange = match executor.poll_response().await {
            Ok(Some(exchange)) => exchange,
            Ok(None) => return Ok(()),
            Err(err) => {
                record_response_error(key, context, proxy, &err).await;
                return Err(format!("upstream-read-failed: {err}"));
            }
        };
        record_response(key, context, proxy, exchange).await;
    }
    Ok(())
}

async fn record_response(
    key: &UdpSessionKey,
    context: &UdpSessionActorContext,
    proxy: &ResidentProxyBinding,
    exchange: (ResidentEventKind, UdpExchangeResult),
) {
    record_udp_session_response_result(
        proxy,
        key.peer(),
        key.original_destination(),
        context.event_file.clone(),
        Arc::clone(&context.event_lock),
        Arc::clone(&context.metrics),
        &context.udp_reply,
        Ok(exchange),
    )
    .await;
}

async fn record_response_error(
    key: &UdpSessionKey,
    context: &UdpSessionActorContext,
    proxy: &ResidentProxyBinding,
    error: &str,
) {
    record_udp_session_response_result(
        proxy,
        key.peer(),
        key.original_destination(),
        context.event_file.clone(),
        Arc::clone(&context.event_lock),
        Arc::clone(&context.metrics),
        &context.udp_reply,
        Err(error.to_owned()),
    )
    .await;
}
