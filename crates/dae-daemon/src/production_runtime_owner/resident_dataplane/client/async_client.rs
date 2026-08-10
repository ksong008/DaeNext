use super::*;

impl AsyncVlessTlsClient {
    pub(in crate::production_runtime_owner::resident_dataplane) fn enable_vision_record_handoff(
        &mut self,
    ) {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } | AsyncVlessTlsEngine::RealityRustls { tls } => {
                tls.get_mut().0.enable_vision_record_handoff();
            }
            AsyncVlessTlsEngine::Boring { tls } | AsyncVlessTlsEngine::RealityBoring { tls } => {
                tls.get_mut().enable_vision_record_handoff();
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn poll_plain_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } | AsyncVlessTlsEngine::RealityRustls { tls } => {
                Pin::new(tls).poll_read(cx, buf)
            }
            AsyncVlessTlsEngine::Boring { tls } | AsyncVlessTlsEngine::RealityBoring { tls } => {
                Pin::new(tls).poll_read(cx, buf)
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn poll_plain_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } | AsyncVlessTlsEngine::RealityRustls { tls } => {
                Pin::new(tls).poll_write(cx, buf)
            }
            AsyncVlessTlsEngine::Boring { tls } | AsyncVlessTlsEngine::RealityBoring { tls } => {
                Pin::new(tls).poll_write(cx, buf)
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn poll_plain_flush(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } | AsyncVlessTlsEngine::RealityRustls { tls } => {
                Pin::new(tls).poll_flush(cx)
            }
            AsyncVlessTlsEngine::Boring { tls } | AsyncVlessTlsEngine::RealityBoring { tls } => {
                Pin::new(tls).poll_flush(cx)
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn poll_plain_shutdown(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } | AsyncVlessTlsEngine::RealityRustls { tls } => {
                Pin::new(tls).poll_shutdown(cx)
            }
            AsyncVlessTlsEngine::Boring { tls } | AsyncVlessTlsEngine::RealityBoring { tls } => {
                Pin::new(tls).poll_shutdown(cx)
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn poll_raw_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let raw =
            match &mut self.engine {
                AsyncVlessTlsEngine::Rustls { tls }
                | AsyncVlessTlsEngine::RealityRustls { tls } => tls.get_mut().0.raw_mut(),
                AsyncVlessTlsEngine::Boring { tls }
                | AsyncVlessTlsEngine::RealityBoring { tls } => tls.get_mut().raw_mut(),
            };
        Pin::new(raw).poll_read(cx, buf)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn take_vision_record_handoff(
        &mut self,
    ) -> bool {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } | AsyncVlessTlsEngine::RealityRustls { tls } => {
                tls.get_mut().0.take_vision_record_handoff()
            }
            AsyncVlessTlsEngine::Boring { tls } | AsyncVlessTlsEngine::RealityBoring { tls } => {
                tls.get_mut().take_vision_record_handoff()
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn poll_raw_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let raw =
            match &mut self.engine {
                AsyncVlessTlsEngine::Rustls { tls }
                | AsyncVlessTlsEngine::RealityRustls { tls } => tls.get_mut().0.raw_mut(),
                AsyncVlessTlsEngine::Boring { tls }
                | AsyncVlessTlsEngine::RealityBoring { tls } => tls.get_mut().raw_mut(),
            };
        Pin::new(raw).poll_write(cx, buf)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn poll_raw_flush(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let raw =
            match &mut self.engine {
                AsyncVlessTlsEngine::Rustls { tls }
                | AsyncVlessTlsEngine::RealityRustls { tls } => tls.get_mut().0.raw_mut(),
                AsyncVlessTlsEngine::Boring { tls }
                | AsyncVlessTlsEngine::RealityBoring { tls } => tls.get_mut().raw_mut(),
            };
        Pin::new(raw).poll_flush(cx)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn poll_raw_shutdown(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let raw =
            match &mut self.engine {
                AsyncVlessTlsEngine::Rustls { tls }
                | AsyncVlessTlsEngine::RealityRustls { tls } => tls.get_mut().0.raw_mut(),
                AsyncVlessTlsEngine::Boring { tls }
                | AsyncVlessTlsEngine::RealityBoring { tls } => tls.get_mut().raw_mut(),
            };
        Pin::new(raw).poll_shutdown(cx)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn negotiated_alpn(
        &self,
    ) -> Option<&[u8]> {
        match &self.engine {
            AsyncVlessTlsEngine::Rustls { tls } | AsyncVlessTlsEngine::RealityRustls { tls } => {
                tls.get_ref().1.alpn_protocol()
            }
            AsyncVlessTlsEngine::Boring { tls } | AsyncVlessTlsEngine::RealityBoring { tls } => {
                tls.ssl().selected_alpn_protocol()
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn write_plain_all(
        &mut self,
        payload: &[u8],
        label: &str,
    ) -> Result<(), String> {
        self.write_plain_all_buffered(payload, label).await?;
        self.flush_plain(label).await
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn write_plain_all_buffered(
        &mut self,
        payload: &[u8],
        label: &str,
    ) -> Result<(), String> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } | AsyncVlessTlsEngine::RealityRustls { tls } => tls
                .write_all(payload)
                .await
                .map_err(|err| format!("{label}: {err}")),
            AsyncVlessTlsEngine::Boring { tls } | AsyncVlessTlsEngine::RealityBoring { tls } => tls
                .write_all(payload)
                .await
                .map_err(|err| format!("{label}: {err}")),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn flush_plain(
        &mut self,
        label: &str,
    ) -> Result<(), String> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } | AsyncVlessTlsEngine::RealityRustls { tls } => tls
                .flush()
                .await
                .map_err(|err| format!("flush {label}: {err}")),
            AsyncVlessTlsEngine::Boring { tls } | AsyncVlessTlsEngine::RealityBoring { tls } => tls
                .flush()
                .await
                .map_err(|err| format!("flush {label}: {err}")),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn read_plain(
        &mut self,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } | AsyncVlessTlsEngine::RealityRustls { tls } => {
                tls.read(buf).await
            }
            AsyncVlessTlsEngine::Boring { tls } | AsyncVlessTlsEngine::RealityBoring { tls } => {
                tls.read(buf).await
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn shutdown(&mut self) {
        match &mut self.engine {
            AsyncVlessTlsEngine::Rustls { tls } | AsyncVlessTlsEngine::RealityRustls { tls } => {
                let _ = tls.shutdown().await;
            }
            AsyncVlessTlsEngine::Boring { tls } | AsyncVlessTlsEngine::RealityBoring { tls } => {
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
        self.poll_plain_read(cx, buf)
    }
}

impl AsyncWrite for AsyncVlessTlsClient {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.poll_plain_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_plain_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_plain_shutdown(cx)
    }
}
