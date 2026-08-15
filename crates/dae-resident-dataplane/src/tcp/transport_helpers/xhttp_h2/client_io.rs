use super::h1::begin_xhttp_h1_packet_up_request;
use super::h2_transport::{begin_xhttp_h2_packet_up_request, replace_xhttp_h2_packet_up_client};
use super::h3_transport::{
    begin_xhttp_h3_packet_up_request, note_xhttp_h3_stream_error, replace_xhttp_h3_packet_up_client,
};
use super::*;
use bytes::{Buf, Bytes};
use std::future::poll_fn;
use std::task::Poll;

pub(crate) async fn send_xhttp_packet_up_request(
    upload: &mut XhttpUploadClient,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<(), String> {
    if reserve_xhttp_packet_up_post(upload) {
        replace_xhttp_packet_up_client(upload).await?;
    }
    begin_xhttp_packet_up_request(upload, session_id, seq, payload)
        .await?
        .await
}

pub(super) async fn replace_xhttp_packet_up_client(
    upload: &mut XhttpUploadClient,
) -> Result<(), String> {
    match upload {
        XhttpUploadClient::H1 { .. } => Ok(()),
        XhttpUploadClient::H2 {
            binding,
            endpoint,
            mptcp,
            sender,
            connection_task,
            xmux_lease,
            xmux_request,
            ..
        } => {
            replace_xhttp_h2_packet_up_client(
                binding,
                endpoint,
                *mptcp,
                sender,
                connection_task,
                xmux_lease,
                xmux_request,
            )
            .await
        }
        XhttpUploadClient::H3 {
            binding,
            endpoint,
            client,
            connection,
            xmux_lease,
            xmux_request,
            ..
        } => {
            replace_xhttp_h3_packet_up_client(
                binding,
                endpoint,
                client,
                connection,
                xmux_lease,
                xmux_request,
            )
            .await
        }
    }
}

pub(super) async fn begin_xhttp_packet_up_request(
    upload: &mut XhttpUploadClient,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<XhttpPacketUpCompletion, String> {
    match upload {
        XhttpUploadClient::H1 {
            binding,
            endpoint,
            mptcp,
        } => {
            begin_xhttp_h1_packet_up_request(binding, endpoint, *mptcp, session_id, seq, payload)
                .await
        }
        XhttpUploadClient::H2 {
            endpoint, sender, ..
        } => begin_xhttp_h2_packet_up_request(sender, endpoint, session_id, seq, payload).await,
        XhttpUploadClient::H3 {
            endpoint,
            client,
            xmux_request,
            ..
        } => {
            begin_xhttp_h3_packet_up_request(
                client,
                endpoint,
                session_id,
                seq,
                payload,
                xmux_request.as_ref(),
            )
            .await
        }
    }
}

pub(super) fn reserve_xhttp_packet_up_post(upload: &XhttpUploadClient) -> bool {
    match upload {
        XhttpUploadClient::H2 {
            xmux_request: Some(request),
            ..
        }
        | XhttpUploadClient::H3 {
            xmux_request: Some(request),
            ..
        } => !request.use_for_packet_up_post(),
        XhttpUploadClient::H1 { .. }
        | XhttpUploadClient::H2 {
            xmux_request: None, ..
        }
        | XhttpUploadClient::H3 {
            xmux_request: None, ..
        } => false,
    }
}

pub(crate) async fn poll_xhttp_download_data(
    download: &mut XhttpDownloadClient,
) -> Result<Option<Bytes>, String> {
    match download {
        XhttpDownloadClient::H1 { body } => {
            let data = poll_fn(|cx| match body.poll_next(cx) {
                Poll::Ready(value) => Poll::Ready(Some(value)),
                Poll::Pending => Poll::Ready(None),
            })
            .await;
            match data {
                Some(value) => value,
                None => Ok(None),
            }
        }
        XhttpDownloadClient::H2 { recv, .. } => {
            let data = {
                let data_future = recv.data();
                tokio::pin!(data_future);
                poll_fn(|cx| match data_future.as_mut().poll(cx) {
                    Poll::Ready(value) => Poll::Ready(Some(value)),
                    Poll::Pending => Poll::Ready(None),
                })
                .await
            };
            match data {
                Some(Some(Ok(bytes))) => {
                    recv.flow_control()
                        .release_capacity(bytes.len())
                        .map_err(|err| format!("release xHTTP HTTP/2 download capacity: {err}"))?;
                    Ok(Some(bytes))
                }
                Some(Some(Err(err))) => Err(format!("read xHTTP HTTP/2 download data: {err}")),
                Some(None) => Err("xHTTP HTTP/2 download stream closed".to_owned()),
                None => Ok(None),
            }
        }
        XhttpDownloadClient::H3 {
            recv, xmux_lease, ..
        } => {
            let data_future = recv.recv_data();
            tokio::pin!(data_future);
            let data = poll_fn(|cx| match data_future.as_mut().poll(cx) {
                Poll::Ready(value) => Poll::Ready(Some(value)),
                Poll::Pending => Poll::Ready(None),
            })
            .await;
            match data {
                Some(Ok(Some(mut chunk))) => {
                    let remaining = chunk.remaining();
                    Ok(Some(chunk.copy_to_bytes(remaining)))
                }
                Some(Ok(None)) => Err("xHTTP H3 download stream closed".to_owned()),
                Some(Err(err)) => {
                    note_xhttp_h3_stream_error(&err, xmux_lease.as_ref());
                    Err(format!("read xHTTP H3 download data: {err:?}"))
                }
                None => Ok(None),
            }
        }
        XhttpDownloadClient::H3StreamOne { recv } => {
            let data_future = recv.recv_data();
            tokio::pin!(data_future);
            let data = poll_fn(|cx| match data_future.as_mut().poll(cx) {
                Poll::Ready(value) => Poll::Ready(Some(value)),
                Poll::Pending => Poll::Ready(None),
            })
            .await;
            match data {
                Some(Ok(Some(mut chunk))) => {
                    let remaining = chunk.remaining();
                    Ok(Some(chunk.copy_to_bytes(remaining)))
                }
                Some(Ok(None)) => Err("xHTTP H3 stream-one download stream closed".to_owned()),
                Some(Err(err)) => Err(format!("read xHTTP H3 stream-one data: {err:?}")),
                None => Ok(None),
            }
        }
    }
}

pub(crate) async fn read_xhttp_download_data(
    download: &mut XhttpDownloadClient,
) -> Result<Option<Bytes>, String> {
    match download {
        XhttpDownloadClient::H1 { body } => body.read_next().await,
        XhttpDownloadClient::H2 { recv, .. } => match recv.data().await {
            Some(Ok(bytes)) => {
                recv.flow_control()
                    .release_capacity(bytes.len())
                    .map_err(|err| format!("release xHTTP HTTP/2 download capacity: {err}"))?;
                Ok(Some(bytes))
            }
            Some(Err(err)) => Err(format!("read xHTTP HTTP/2 download data: {err}")),
            None => Ok(None),
        },
        XhttpDownloadClient::H3 {
            recv, xmux_lease, ..
        } => match recv.recv_data().await {
            Ok(Some(mut chunk)) => {
                let remaining = chunk.remaining();
                Ok(Some(chunk.copy_to_bytes(remaining)))
            }
            Ok(None) => Ok(None),
            Err(err) => {
                note_xhttp_h3_stream_error(&err, xmux_lease.as_ref());
                Err(format!("read xHTTP H3 download data: {err:?}"))
            }
        },
        XhttpDownloadClient::H3StreamOne { recv } => match recv.recv_data().await {
            Ok(Some(mut chunk)) => {
                let remaining = chunk.remaining();
                Ok(Some(chunk.copy_to_bytes(remaining)))
            }
            Ok(None) => Ok(None),
            Err(err) => Err(format!("read xHTTP H3 stream-one data: {err:?}")),
        },
    }
}

pub(crate) async fn close_xhttp_upload_client(mut upload: XhttpUploadClient) {
    match &mut upload {
        XhttpUploadClient::H1 { .. } => {}
        XhttpUploadClient::H2 {
            connection_task,
            xmux_lease,
            ..
        } => {
            if let Some(task) = connection_task.take() {
                abort_and_reap_xhttp_task(task);
            }
            drop(xmux_lease.take());
        }
        XhttpUploadClient::H3 {
            connection,
            xmux_lease,
            ..
        } => {
            if let Some(connection) = connection.take() {
                connection.close(b"resident xhttp upload done").await;
            }
            drop(xmux_lease.take());
        }
    }
}

pub(crate) async fn close_xhttp_download_client(mut download: XhttpDownloadClient) {
    match &mut download {
        XhttpDownloadClient::H1 { body } => {
            body.shutdown().await;
        }
        XhttpDownloadClient::H2 {
            connection_task,
            xmux_lease,
            ..
        } => {
            if let Some(task) = connection_task.take() {
                abort_and_reap_xhttp_task(task);
            }
            drop(xmux_lease.take());
        }
        XhttpDownloadClient::H3 {
            connection,
            xmux_lease,
            ..
        } => {
            if let Some(connection) = connection.take() {
                connection.close(b"resident xhttp download done").await;
            }
            drop(xmux_lease.take());
        }
        XhttpDownloadClient::H3StreamOne { .. } => {}
    }
}

pub(crate) async fn send_xhttp_stream_data(
    upload: &mut XhttpStreamUploadClient,
    payload: Bytes,
    end_stream: bool,
) -> Result<(), String> {
    match upload {
        XhttpStreamUploadClient::H1 { writer } => writer.write_chunk(payload, end_stream).await,
        XhttpStreamUploadClient::H2 { send_stream, .. } => {
            send_h2_data_with_context(
                send_stream,
                payload,
                end_stream,
                "xHTTP HTTP/2 stream upload",
            )
            .await
        }
        XhttpStreamUploadClient::H3 {
            stream, xmux_lease, ..
        } => {
            if !payload.is_empty() {
                time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.send_data(payload))
                    .await
                    .map_err(|_| "send xHTTP H3 stream body timeout".to_owned())?
                    .map_err(|err| {
                        note_xhttp_h3_stream_error(&err, xmux_lease.as_ref());
                        format!("send xHTTP H3 stream body: {err:?}")
                    })?;
            }
            if end_stream {
                time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.finish())
                    .await
                    .map_err(|_| "finish xHTTP H3 stream body timeout".to_owned())?
                    .map_err(|err| {
                        note_xhttp_h3_stream_error(&err, xmux_lease.as_ref());
                        format!("finish xHTTP H3 stream body: {err:?}")
                    })?;
            }
            Ok(())
        }
        XhttpStreamUploadClient::H3StreamOne {
            send, xmux_lease, ..
        } => {
            if !payload.is_empty() {
                time::timeout(RESIDENT_CONNECT_TIMEOUT, send.send_data(payload))
                    .await
                    .map_err(|_| "send xHTTP H3 stream-one body timeout".to_owned())?
                    .map_err(|err| {
                        note_xhttp_h3_stream_error(&err, xmux_lease.as_ref());
                        format!("send xHTTP H3 stream-one body: {err:?}")
                    })?;
            }
            if end_stream {
                time::timeout(RESIDENT_CONNECT_TIMEOUT, send.finish())
                    .await
                    .map_err(|_| "finish xHTTP H3 stream-one body timeout".to_owned())?
                    .map_err(|err| {
                        note_xhttp_h3_stream_error(&err, xmux_lease.as_ref());
                        format!("finish xHTTP H3 stream-one body: {err:?}")
                    })?;
            }
            Ok(())
        }
    }
}

pub(crate) async fn close_xhttp_stream_upload_client(mut upload: XhttpStreamUploadClient) {
    match &mut upload {
        XhttpStreamUploadClient::H1 { writer } => {
            let _ = writer.write_chunk(Bytes::new(), true).await;
            writer.shutdown().await;
        }
        XhttpStreamUploadClient::H2 {
            upload_response_task,
            connection_task,
            xmux_lease,
            ..
        } => {
            if let Some(task) = upload_response_task.take() {
                abort_and_reap_xhttp_task(task);
            }
            if let Some(task) = connection_task.take() {
                abort_and_reap_xhttp_task(task);
            }
            drop(xmux_lease.take());
        }
        XhttpStreamUploadClient::H3 {
            connection,
            xmux_lease,
            ..
        } => {
            if let Some(connection) = connection.take() {
                connection.close(b"resident xhttp stream upload done").await;
            }
            drop(xmux_lease.take());
        }
        XhttpStreamUploadClient::H3StreamOne {
            connection,
            xmux_lease,
            ..
        } => {
            if let Some(connection) = connection.take() {
                connection.close(b"resident xhttp stream-one done").await;
            }
            drop(xmux_lease.take());
        }
    }
}
