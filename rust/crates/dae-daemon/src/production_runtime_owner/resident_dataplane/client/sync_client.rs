use super::*;
impl VlessTlsClient {
    pub(in crate::production_runtime_owner::resident_dataplane) fn set_nonblocking(
        &mut self,
        nonblocking: bool,
    ) -> Result<(), String> {
        self.raw_tcp_mut()
            .set_nonblocking(nonblocking)
            .map_err(|err| format!("set proxy tcp nonblocking: {err}"))
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn queue_plain(
        &mut self,
        payload: &[u8],
        label: &str,
    ) -> Result<(), String> {
        match &mut self.engine {
            VlessTlsEngine::Rustls { conn, .. } | VlessTlsEngine::RealityRustls { conn, .. } => {
                conn.writer()
                    .write_all(payload)
                    .map_err(|err| format!("{label}: {err}"))
            }
            VlessTlsEngine::Boring {
                pending_plaintext, ..
            } => {
                pending_plaintext.extend_from_slice(payload);
                Ok(())
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn read_plain(
        &mut self,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        match &mut self.engine {
            VlessTlsEngine::Rustls { conn, .. } | VlessTlsEngine::RealityRustls { conn, .. } => {
                conn.reader().read(buf)
            }
            VlessTlsEngine::Boring { tls, .. } => tls.read(buf),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn raw_read(
        &mut self,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        self.raw_tcp_mut().read(buf)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn raw_write_all_nonblocking(
        &mut self,
        mut payload: &[u8],
        stop: &AtomicBool,
        label: &str,
    ) -> Result<(), String> {
        while !payload.is_empty() && !stop.load(Ordering::Relaxed) {
            match self.raw_tcp_mut().write(payload) {
                Ok(0) => return Err(format!("{label}: wrote zero bytes")),
                Ok(written) => payload = &payload[written..],
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(RESIDENT_IDLE_SLEEP);
                }
                Err(err) => return Err(format!("{label}: {err}")),
            }
        }
        Ok(())
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn send_close_notify(&mut self) {
        match &mut self.engine {
            VlessTlsEngine::Rustls { conn, .. } | VlessTlsEngine::RealityRustls { conn, .. } => {
                conn.send_close_notify()
            }
            VlessTlsEngine::Boring { tls, .. } => {
                let _ = tls.shutdown();
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn idle_tls_complete(
        &self,
    ) -> bool {
        match &self.engine {
            VlessTlsEngine::Rustls { conn, .. } | VlessTlsEngine::RealityRustls { conn, .. } => {
                !conn.wants_write() && !conn.wants_read()
            }
            VlessTlsEngine::Boring {
                pending_plaintext, ..
            } => pending_plaintext.is_empty(),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn raw_tcp_mut(
        &mut self,
    ) -> &mut TcpStream {
        match &mut self.engine {
            VlessTlsEngine::Rustls { tcp, .. } | VlessTlsEngine::RealityRustls { tcp, .. } => {
                tcp.raw_mut()
            }
            VlessTlsEngine::Boring { tls, .. } => tls.get_mut(),
        }
    }
}
