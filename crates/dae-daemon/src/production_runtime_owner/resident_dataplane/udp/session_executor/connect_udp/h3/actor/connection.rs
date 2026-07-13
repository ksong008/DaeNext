use std::{borrow::Cow, sync::Arc};

use ::h3::ConnectionState;
use futures_util::future::poll_fn;
use super::runtime::{ConnectUdpH3ActorContext, run_connect_udp_h3_actor};
use super::*;
use crate::production_runtime_owner::resident_dataplane::resolve_socket_addr_candidates;
use crate::production_runtime_owner::resident_dataplane::tcp::{
    connect_quic_endpoint_candidates_async, open_marked_quic_endpoint_for_remote,
};
use crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3::tls::build_connect_udp_h3_client_config;

pub(super) async fn start_connect_udp_h3_actor(
    proxy: &ResidentProxyPlan,
    runtime: ResidentConnectUdpRuntimePlan,
    admission: Arc<ConnectUdpH3ActorAdmission>,
) -> Result<ConnectUdpH3ActorClient, String> {
    let target = authority_from_host_port(&proxy.server_host, proxy.server_port);
    let candidates = resolve_socket_addr_candidates(
        &target,
        RESIDENT_CONNECT_TIMEOUT,
        "resolve CONNECT-UDP H3 endpoint",
    )
    .await?;
    let client_config = build_connect_udp_h3_client_config(proxy, runtime)?;
    let (_, endpoint, connection) = connect_quic_endpoint_candidates_async(
        &candidates,
        &proxy.server_name,
        RESIDENT_CONNECT_TIMEOUT,
        "connect CONNECT-UDP H3 QUIC endpoint",
        |remote| {
            let mut endpoint = open_marked_quic_endpoint_for_remote(proxy.mark, remote)?;
            endpoint.set_default_client_config(client_config.clone());
            Ok(endpoint)
        },
    )
    .await?;
    let max_datagram_size = connection.max_datagram_size().ok_or_else(|| {
        "CONNECT-UDP H3 peer did not negotiate QUIC DATAGRAM transport support".to_owned()
    })?;
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let mut builder = ::h3::client::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let (mut driver, client) = time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        builder.build::<_, _, Bytes>(h3_connection),
    )
    .await
    .map_err(|_| "create CONNECT-UDP H3 client timeout".to_owned())?
    .map_err(|err| format!("create CONNECT-UDP H3 client: {err:?}"))?;
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });
    if let Err(err) = wait_for_connect_udp_h3_settings(&client, &driver_task).await {
        connection.close(0_u32.into(), b"CONNECT-UDP H3 settings rejected");
        driver_task.abort();
        endpoint.wait_idle().await;
        return Err(err);
    }

    let (sender, receiver) = tokio::sync::mpsc::channel(runtime.h3_command_queue_depth.max(1));
    let proxy = Arc::new(proxy.clone());
    let task = tokio::spawn(async move {
        run_connect_udp_h3_actor(ConnectUdpH3ActorContext {
            endpoint,
            connection,
            client,
            driver_task,
            proxy,
            runtime,
            max_datagram_size,
            receiver,
            admission: Arc::clone(&admission),
        })
        .await;
        admission.state_changed.notify_waiters();
    });
    Ok(ConnectUdpH3ActorClient {
        sender,
        task,
        max_datagram_size,
    })
}

async fn wait_for_connect_udp_h3_settings(
    client: &::h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver_task: &tokio::task::JoinHandle<()>,
) -> Result<(), String> {
    let deadline = time::Instant::now() + RESIDENT_CONNECT_TIMEOUT;
    loop {
        let settings = client.settings();
        if let Cow::Borrowed(settings) = settings {
            return if settings.enable_extended_connect() && settings.enable_datagram() {
                Ok(())
            } else {
                Err(
                    "CONNECT-UDP H3 peer did not advertise both extended CONNECT and H3 DATAGRAM"
                        .to_owned(),
                )
            };
        }
        if driver_task.is_finished() {
            return Err(
                "CONNECT-UDP H3 connection closed before required peer settings were admitted"
                    .to_owned(),
            );
        }
        if time::Instant::now() >= deadline {
            return Err(
                "CONNECT-UDP H3 peer did not advertise both extended CONNECT and H3 DATAGRAM"
                    .to_owned(),
            );
        }
        time::sleep(RESIDENT_IDLE_SLEEP).await;
    }
}
