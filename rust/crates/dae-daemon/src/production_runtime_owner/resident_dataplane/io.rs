use std::io::{ErrorKind, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use super::RESIDENT_IDLE_SLEEP;

pub(super) fn write_all_nonblocking(
    stream: &mut TcpStream,
    mut payload: &[u8],
    stop: &AtomicBool,
    label: &str,
) -> Result<(), String> {
    while !payload.is_empty() && !stop.load(Ordering::Relaxed) {
        match stream.write(payload) {
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
