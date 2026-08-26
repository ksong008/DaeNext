use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use dae_product_core::{
    DEFAULT_PRODUCT_CONTROL_SOCKET, DaedProductOutput, PRODUCT_CONTROL_SOCKET_ENV,
};
use serde_json::{Value, json};

pub const LOCAL_CONTROL_MAX_RESPONSE_BYTES: u64 = 16 * 1024;
pub const LOCAL_CONTROL_OP_RELOAD: &str = "reload";
pub const LOCAL_CONTROL_OP_STATUS: &str = "status";

const LOCAL_CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(60);
const LOCAL_CONTROL_READY_POLL_INTERVAL: Duration = Duration::from_millis(100);

pub fn run_local_control_reload_command(args: &[String]) -> DaedProductOutput {
    let mut socket = std::env::var_os(PRODUCT_CONTROL_SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PRODUCT_CONTROL_SOCKET));
    let mut timeout = LOCAL_CONTROL_IO_TIMEOUT;
    let mut json_output = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--control" | "--control-socket" => {
                let Some(value) = iter.next() else {
                    return DaedProductOutput::usage("missing reload --control value");
                };
                socket = value.into();
            }
            _ if arg.starts_with("--control=") => {
                socket = arg.trim_start_matches("--control=").into();
            }
            _ if arg.starts_with("--control-socket=") => {
                socket = arg.trim_start_matches("--control-socket=").into();
            }
            "--timeout" => {
                let Some(value) = iter.next() else {
                    return DaedProductOutput::usage("missing reload --timeout value");
                };
                timeout = match parse_local_control_timeout(value) {
                    Ok(value) => value,
                    Err(err) => return DaedProductOutput::usage(err),
                };
            }
            _ if arg.starts_with("--timeout=") => {
                timeout = match parse_local_control_timeout(arg.trim_start_matches("--timeout=")) {
                    Ok(value) => value,
                    Err(err) => return DaedProductOutput::usage(err),
                };
            }
            "--json" => json_output = true,
            _ => return DaedProductOutput::usage(format!("unsupported reload argument: {arg}")),
        }
    }

    match request_local_control_reload(&socket, timeout) {
        Ok(response) if response["ok"].as_bool().unwrap_or(false) => {
            if json_output {
                DaedProductOutput::ok(format!("{response}\n"))
            } else {
                DaedProductOutput::ok("OK\n".to_owned())
            }
        }
        Ok(response) => DaedProductOutput::error(
            response["error"]
                .as_str()
                .unwrap_or("local reload request failed"),
        ),
        Err(err) => DaedProductOutput::error(format!("reload failed: {err}")),
    }
}

pub fn run_local_control_wait_ready_command(args: &[String]) -> DaedProductOutput {
    let mut socket = std::env::var_os(PRODUCT_CONTROL_SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PRODUCT_CONTROL_SOCKET));
    let mut timeout = LOCAL_CONTROL_IO_TIMEOUT;
    let mut json_output = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--control" | "--control-socket" => {
                let Some(value) = iter.next() else {
                    return DaedProductOutput::usage("missing wait-ready --control value");
                };
                socket = value.into();
            }
            _ if arg.starts_with("--control=") => {
                socket = arg.trim_start_matches("--control=").into();
            }
            _ if arg.starts_with("--control-socket=") => {
                socket = arg.trim_start_matches("--control-socket=").into();
            }
            "--timeout" => {
                let Some(value) = iter.next() else {
                    return DaedProductOutput::usage("missing wait-ready --timeout value");
                };
                timeout = match parse_local_control_timeout(value) {
                    Ok(value) => value,
                    Err(err) => return DaedProductOutput::usage(err),
                };
            }
            _ if arg.starts_with("--timeout=") => {
                timeout = match parse_local_control_timeout(arg.trim_start_matches("--timeout=")) {
                    Ok(value) => value,
                    Err(err) => return DaedProductOutput::usage(err),
                };
            }
            "--json" => json_output = true,
            _ => {
                return DaedProductOutput::usage(format!("unsupported wait-ready argument: {arg}"));
            }
        }
    }
    match wait_for_local_control_ready(&socket, timeout) {
        Ok(report) if json_output => DaedProductOutput::ok(format!("{report}\n")),
        Ok(_) => DaedProductOutput::ok("READY\n".to_owned()),
        Err(err) => DaedProductOutput::error(format!("wait-ready failed: {err}")),
    }
}

fn request_local_control_reload(path: &Path, timeout: Duration) -> io::Result<Value> {
    request_local_control(path, timeout, json!({"op": LOCAL_CONTROL_OP_RELOAD}))
}

fn request_local_control_status(path: &Path, timeout: Duration) -> io::Result<Value> {
    request_local_control(path, timeout, json!({"op": LOCAL_CONTROL_OP_STATUS}))
}

fn request_local_control(path: &Path, timeout: Duration, request: Value) -> io::Result<Value> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    serde_json::to_writer(&mut stream, &request).map_err(io::Error::other)?;
    stream.write_all(b"\n")?;
    stream.shutdown(Shutdown::Write)?;
    let mut text = String::new();
    stream
        .take(LOCAL_CONTROL_MAX_RESPONSE_BYTES.saturating_add(1))
        .read_to_string(&mut text)?;
    if text.len() as u64 > LOCAL_CONTROL_MAX_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local control response exceeds the bounded message contract",
        ));
    }
    serde_json::from_str(text.trim()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid local control response: {err}"),
        )
    })
}

fn wait_for_local_control_ready(path: &Path, timeout: Duration) -> io::Result<Value> {
    let started = Instant::now();
    let mut last_error = None;
    loop {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "control socket did not become ready within {}ms{}",
                    timeout.as_millis(),
                    last_error
                        .as_deref()
                        .map(|error| format!("; last error: {error}"))
                        .unwrap_or_default()
                ),
            ));
        }
        match request_local_control_status(path, remaining.min(Duration::from_secs(1))) {
            Ok(report) if report["ready"].as_bool() == Some(true) => return Ok(report),
            Ok(report) => {
                last_error = Some(
                    report["error"]
                        .as_str()
                        .unwrap_or("product is not ready")
                        .to_owned(),
                );
            }
            Err(err) => last_error = Some(err.to_string()),
        }
        thread::sleep(remaining.min(LOCAL_CONTROL_READY_POLL_INTERVAL));
    }
}

fn parse_local_control_timeout(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("invalid reload --timeout value".to_owned());
    }
    if let Some(milliseconds) = value.strip_suffix("ms") {
        return milliseconds
            .parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|_| "invalid reload --timeout value".to_owned());
    }
    value
        .strip_suffix('s')
        .unwrap_or(value)
        .parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|_| "invalid reload --timeout value".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_control_timeout_accepts_seconds_and_milliseconds() {
        assert_eq!(
            parse_local_control_timeout("60").unwrap(),
            Duration::from_secs(60)
        );
        assert_eq!(
            parse_local_control_timeout("30s").unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_local_control_timeout("250ms").unwrap(),
            Duration::from_millis(250)
        );
        assert!(parse_local_control_timeout("bad").is_err());
    }
}
