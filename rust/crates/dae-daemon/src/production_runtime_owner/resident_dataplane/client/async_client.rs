use super::*;
impl AsyncVlessTlsClient {
    pub(in crate::production_runtime_owner::resident_dataplane) async fn write_plain_all(
        &mut self,
        payload: &[u8],
        label: &str,
    ) -> Result<(), String> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } => {
                tls.write_all(payload)
                    .await
                    .map_err(|err| format!("{label}: {err}"))?;
                tls.flush()
                    .await
                    .map_err(|err| format!("flush {label}: {err}"))
            }
            AsyncVlessTlsEngine::Boring { tls } => {
                tls.write_all(payload)
                    .await
                    .map_err(|err| format!("{label}: {err}"))?;
                tls.flush()
                    .await
                    .map_err(|err| format!("flush {label}: {err}"))
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn read_plain(
        &mut self,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } => tls.read(buf).await,
            AsyncVlessTlsEngine::Boring { tls } => tls.read(buf).await,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn raw_read(
        &mut self,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } => tls.get_mut().0.read(buf).await,
            AsyncVlessTlsEngine::Boring { tls } => tls.get_mut().read(buf).await,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn raw_write_all(
        &mut self,
        payload: &[u8],
        label: &str,
    ) -> Result<(), String> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } => {
                let raw = tls.get_mut().0;
                let raw = raw.raw_mut();
                raw.write_all(payload)
                    .await
                    .map_err(|err| format!("{label}: {err}"))?;
                raw.flush()
                    .await
                    .map_err(|err| format!("flush {label}: {err}"))
            }
            AsyncVlessTlsEngine::Boring { tls } => {
                let raw = tls.get_mut();
                raw.write_all(payload)
                    .await
                    .map_err(|err| format!("{label}: {err}"))?;
                raw.flush()
                    .await
                    .map_err(|err| format!("flush {label}: {err}"))
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn shutdown(&mut self) {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } => {
                let _ = tls.shutdown().await;
            }
            AsyncVlessTlsEngine::Boring { tls } => {
                let _ = tls.shutdown().await;
            }
        }
    }
}

impl AsyncRead for AsyncVlessTlsClient {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } => Pin::new(tls).poll_read(cx, buf),
            AsyncVlessTlsEngine::Boring { tls } => Pin::new(tls).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AsyncVlessTlsClient {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } => Pin::new(tls).poll_write(cx, buf),
            AsyncVlessTlsEngine::Boring { tls } => Pin::new(tls).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } => Pin::new(tls).poll_flush(cx),
            AsyncVlessTlsEngine::Boring { tls } => Pin::new(tls).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } => Pin::new(tls).poll_shutdown(cx),
            AsyncVlessTlsEngine::Boring { tls } => Pin::new(tls).poll_shutdown(cx),
        }
    }
}
