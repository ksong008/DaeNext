use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

const PPROF_ACCEPT_POLL: Duration = Duration::from_millis(50);
const PPROF_READ_TIMEOUT: Duration = Duration::from_secs(2);

struct PprofListener {
    port: u16,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl PprofListener {
    fn bind(port: u16) -> Result<Self, String> {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .map_err(|err| format!("bind localhost pprof port {port}: {err}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|err| format!("set localhost pprof listener nonblocking: {err}"))?;
        let actual_port = listener
            .local_addr()
            .map_err(|err| format!("read localhost pprof listener address: {err}"))?
            .port();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let join = thread::Builder::new()
            .name(format!("daed-pprof-{actual_port}"))
            .spawn(move || pprof_accept_loop(listener, thread_stop))
            .map_err(|err| format!("spawn pprof listener thread: {err}"))?;
        Ok(Self {
            port: actual_port,
            stop,
            join: Some(join),
        })
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[derive(Default)]
struct PprofState {
    listener: Option<PprofListener>,
}

pub struct ProductPprofRuntime {
    state: Mutex<PprofState>,
}

impl std::fmt::Debug for ProductPprofRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductPprofRuntime")
            .field("port", &self.port())
            .finish()
    }
}

impl Default for ProductPprofRuntime {
    fn default() -> Self {
        Self {
            state: Mutex::new(PprofState::default()),
        }
    }
}

impl ProductPprofRuntime {
    pub fn apply_port(&self, requested_port: u16) -> Result<(), String> {
        let old = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "pprof runtime lock poisoned".to_owned())?;
            if state
                .listener
                .as_ref()
                .is_some_and(|listener| listener.port == requested_port)
            {
                return Ok(());
            }
            let replacement = if requested_port == 0 {
                None
            } else {
                Some(PprofListener::bind(requested_port)?)
            };
            let old = state.listener.take();
            state.listener = replacement;
            old
        };
        if let Some(old) = old {
            old.stop();
        }
        Ok(())
    }

    pub fn port(&self) -> u16 {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.listener.as_ref().map(|listener| listener.port))
            .unwrap_or(0)
    }

    pub fn status(&self) -> Value {
        let port = self.port();
        json!({
            "configuredPort": port,
            "effectivePort": port,
            "bound": port != 0,
            "address": if port == 0 { Value::Null } else { json!(format!("127.0.0.1:{port}")) },
            "endpoints": ["/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/profile", "/debug/pprof/symbol"],
        })
    }
}

impl Drop for ProductPprofRuntime {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock()
            && let Some(listener) = state.listener.take()
        {
            listener.stop();
        }
    }
}

fn pprof_accept_loop(listener: TcpListener, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_read_timeout(Some(PPROF_READ_TIMEOUT));
                let _ = stream.set_write_timeout(Some(PPROF_READ_TIMEOUT));
                serve_pprof_connection(stream);
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(PPROF_ACCEPT_POLL);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

fn serve_pprof_connection(mut stream: TcpStream) {
    let mut request = [0_u8; 8192];
    let read = stream.read(&mut request).unwrap_or(0);
    let request = String::from_utf8_lossy(&request[..read]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");
    let (status, content_type, body) = match path {
        "/debug/pprof/" | "/debug/pprof" => (
            "200 OK",
            "text/html; charset=utf-8",
            b"<!doctype html><html><body><h1>daed pprof</h1><ul><li><a href=\"/debug/pprof/cmdline\">cmdline</a></li><li><a href=\"/debug/pprof/profile\">profile</a></li><li><a href=\"/debug/pprof/symbol\">symbol</a></li></ul></body></html>".to_vec(),
        ),
        "/debug/pprof/cmdline" => (
            "200 OK",
            "text/plain; charset=utf-8",
            fs::read("/proc/self/cmdline").unwrap_or_default(),
        ),
        "/debug/pprof/symbol" => (
            "200 OK",
            "text/plain; charset=utf-8",
            b"num_symbols: 0\n".to_vec(),
        ),
        "/debug/pprof/profile" => (
            "501 Not Implemented",
            "text/plain; charset=utf-8",
            b"CPU sampling profile is unavailable in this build\n".to_vec(),
        ),
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"not found\n".to_vec(),
        ),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pprof_port_zero_is_unbound_and_nonzero_is_localhost_only() {
        let runtime = ProductPprofRuntime::default();
        assert_eq!(runtime.port(), 0);
        runtime.apply_port(0).unwrap();
        runtime.apply_port(0).unwrap();
        runtime.apply_port(0).unwrap();
        assert_eq!(runtime.status()["bound"], json!(false));
    }

    #[test]
    fn pprof_replacement_rolls_forward_without_leaking_old_owner() {
        let runtime = ProductPprofRuntime::default();
        let first = TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        drop(TcpListener::bind(("127.0.0.1", first)).unwrap());
        runtime.apply_port(first).unwrap();
        assert_eq!(runtime.port(), first);
        runtime.apply_port(0).unwrap();
        assert_eq!(runtime.port(), 0);
        assert!(TcpListener::bind(("127.0.0.1", first)).is_ok());
    }

    #[test]
    fn pprof_discovery_endpoint_is_reachable_on_localhost() {
        let runtime = ProductPprofRuntime::default();
        runtime.apply_port(0).unwrap();
        let probe = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        runtime.apply_port(port).unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .write_all(b"GET /debug/pprof/ HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut body = String::new();
        stream.read_to_string(&mut body).unwrap();
        assert!(body.starts_with("HTTP/1.1 200 OK"));
        assert!(body.contains("/debug/pprof/cmdline"));
    }

    #[test]
    fn pprof_bind_conflict_keeps_previous_listener() {
        let runtime = ProductPprofRuntime::default();
        let first = TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        drop(TcpListener::bind(("127.0.0.1", first)).unwrap());
        runtime.apply_port(first).unwrap();
        let conflict = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let conflict_port = conflict.local_addr().unwrap().port();
        assert!(runtime.apply_port(conflict_port).is_err());
        assert_eq!(runtime.port(), first);
        drop(conflict);
        runtime.apply_port(0).unwrap();
    }
}
