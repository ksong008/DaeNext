use std::sync::Arc;

use tokio::sync::Notify;

use super::*;

pub(super) struct OpenedConnectUdpH2Client {
    pub(super) sender: ::h2::client::SendRequest<Bytes>,
    pub(super) driver_task: tokio::task::JoinHandle<()>,
}

pub(super) async fn open_connect_udp_h2_client(
    proxy: &ResidentProxyPlan,
    state_changed: Arc<Notify>,
) -> Result<OpenedConnectUdpH2Client, String> {
    let tls = open_async_resident_tls_client(proxy).await?;
    let (sender, mut connection) =
        time::timeout(RESIDENT_CONNECT_TIMEOUT, ::h2::client::handshake(tls))
            .await
            .map_err(|_| "CONNECT-UDP H2 client handshake timeout".to_owned())?
            .map_err(|err| format!("CONNECT-UDP H2 client handshake: {err}"))?;
    let mut ping_pong = connection
        .ping_pong()
        .ok_or_else(|| "CONNECT-UDP H2 client could not acquire settings barrier".to_owned())?;
    let driver_task = tokio::spawn(async move {
        let _ = connection.await;
        state_changed.notify_waiters();
    });
    match time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        ping_pong.ping(::h2::Ping::opaque()),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            driver_task.abort();
            return Err(format!(
                "CONNECT-UDP H2 wait for peer settings barrier: {err}"
            ));
        }
        Err(_) => {
            driver_task.abort();
            return Err("CONNECT-UDP H2 peer settings barrier timeout".to_owned());
        }
    }
    let sender = match time::timeout(RESIDENT_CONNECT_TIMEOUT, sender.ready()).await {
        Ok(Ok(sender)) => sender,
        Ok(Err(err)) => {
            driver_task.abort();
            return Err(format!("CONNECT-UDP H2 wait for peer settings: {err}"));
        }
        Err(_) => {
            driver_task.abort();
            return Err("CONNECT-UDP H2 peer settings timeout".to_owned());
        }
    };
    if !sender.is_extended_connect_protocol_enabled() {
        driver_task.abort();
        return Err("CONNECT-UDP H2 peer did not enable the extended CONNECT protocol".to_owned());
    }
    Ok(OpenedConnectUdpH2Client {
        sender,
        driver_task,
    })
}
