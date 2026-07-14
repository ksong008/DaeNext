use super::*;
use std::collections::HashMap;
use std::net::Shutdown;
use std::sync::atomic::{AtomicBool, AtomicU64};

#[derive(Debug, Default)]
pub(super) struct ProductHttpConnectionRegistry {
    closing: AtomicBool,
    next_id: AtomicU64,
    connections: Mutex<HashMap<u64, TcpStream>>,
}

#[derive(Debug)]
pub(super) struct ProductHttpConnectionLease {
    id: u64,
    registry: Arc<ProductHttpConnectionRegistry>,
}

impl ProductHttpConnectionRegistry {
    pub(super) fn register(
        self: &Arc<Self>,
        stream: &TcpStream,
    ) -> io::Result<ProductHttpConnectionLease> {
        let owned = stream.try_clone()?;
        let mut connections = self
            .connections
            .lock()
            .map_err(|_| io::Error::other("HTTP connection registry lock poisoned"))?;
        if self.closing.load(Ordering::Acquire) {
            drop(connections);
            let _ = owned.shutdown(Shutdown::Both);
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "product HTTP server is shutting down",
            ));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        connections.insert(id, owned);
        Ok(ProductHttpConnectionLease {
            id,
            registry: Arc::clone(self),
        })
    }

    pub(super) fn shutdown_all(&self) -> io::Result<usize> {
        self.closing.store(true, Ordering::Release);
        let connections = {
            let mut connections = self
                .connections
                .lock()
                .map_err(|_| io::Error::other("HTTP connection registry lock poisoned"))?;
            connections
                .drain()
                .map(|(_, stream)| stream)
                .collect::<Vec<_>>()
        };
        let count = connections.len();
        let mut first_error = None;
        for stream in connections {
            if let Err(err) = stream.shutdown(Shutdown::Both)
                && first_error.is_none()
            {
                first_error = Some(err);
            }
        }
        match first_error {
            Some(err) => Err(io::Error::new(
                err.kind(),
                format!("close {count} active HTTP connections during shutdown: {err}"),
            )),
            None => Ok(count),
        }
    }

    fn unregister(&self, id: u64) {
        if let Ok(mut connections) = self.connections.lock() {
            connections.remove(&id);
        }
    }

    #[cfg(test)]
    pub(super) fn active_count(&self) -> usize {
        self.connections
            .lock()
            .map(|connections| connections.len())
            .unwrap_or(usize::MAX)
    }
}

impl Drop for ProductHttpConnectionLease {
    fn drop(&mut self) {
        self.registry.unregister(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_interrupts_registered_socket_and_rejects_late_registration() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let registry = Arc::new(ProductHttpConnectionRegistry::default());
        let lease = registry.register(&server).unwrap();
        assert_eq!(registry.active_count(), 1);
        assert_eq!(registry.shutdown_all().unwrap(), 1);
        assert_eq!(registry.active_count(), 0);
        assert_eq!(
            registry.register(&server).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        drop(lease);
        drop(peer);
    }
}
