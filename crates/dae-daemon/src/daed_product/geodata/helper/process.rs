use super::protocol::{
    GEODATA_HELPER_MAX_RESPONSE_BYTES, GeodataHelperRequest, decode_geodata_helper_response,
    encode_geodata_helper_request,
};
use super::*;

const GEODATA_HELPER_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const GEODATA_HELPER_WAIT_INTERVAL: Duration = Duration::from_millis(20);
const GEODATA_HELPER_CONTROL_SO_MARK: u32 = 0x100;

pub(in crate::daed_product::geodata) fn prepare_geodata_with_helper(
    coordinator: &ProductGeodataUpdateCoordinator,
    state: &Path,
    dir: &Path,
    kind: GeodataKind,
    output: &Path,
) -> io::Result<GeodataPreparedDownload> {
    let response = coordinator.reserve_staging_path(dir, kind, "helper-response")?;
    let _response_cleanup = HelperResponseCleanup(response.clone());
    let request = encode_geodata_helper_request(&GeodataHelperRequest {
        state: state.to_path_buf(),
        output: output.to_path_buf(),
        response: response.clone(),
        kind,
    })?;
    let executable = std::env::current_exe()
        .map_err(|error| io::Error::other(format!("resolve geodata helper executable: {error}")))?;
    let mut child = Command::new(executable)
        .args(["geodata-prepare-helper", "--stdin-json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env(
            GEODATA_PREPARE_HELPER_SO_MARK_ENV,
            GEODATA_HELPER_CONTROL_SO_MARK.to_string(),
        )
        .spawn()
        .map(GeodataHelperChild::new)
        .map_err(|error| io::Error::other(format!("spawn geodata helper: {error}")))?;
    let mut stdin = child
        .child_mut()
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("open geodata helper stdin: unavailable"))?;
    stdin
        .write_all(&request)
        .map_err(|error| io::Error::other(format!("write geodata helper request: {error}")))?;
    drop(stdin);
    drop(request);

    let deadline = Instant::now()
        .checked_add(GEODATA_HELPER_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let status = loop {
        if let Some(status) = child
            .child_mut()
            .try_wait()
            .map_err(|error| io::Error::other(format!("wait geodata helper: {error}")))?
        {
            child.mark_reaped();
            break status;
        }
        if Instant::now() >= deadline {
            child.terminate_and_wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{} geodata helper timed out", kind.response_key()),
            ));
        }
        thread::sleep(GEODATA_HELPER_WAIT_INTERVAL);
    };

    let response_bytes = read_bounded_response(&response)?;
    let decoded = decode_geodata_helper_response(&response_bytes, kind);
    if !status.success() {
        return match decoded {
            Err(error) => Err(error),
            Ok(_) => Err(io::Error::other(format!(
                "{} geodata helper exited with status {status}",
                kind.response_key()
            ))),
        };
    }
    decoded
}

fn read_bounded_response(path: &Path) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut response = Vec::new();
    file.take((GEODATA_HELPER_MAX_RESPONSE_BYTES as u64) + 1)
        .read_to_end(&mut response)?;
    if response.len() > GEODATA_HELPER_MAX_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("geodata helper response exceeds {GEODATA_HELPER_MAX_RESPONSE_BYTES} bytes"),
        ));
    }
    Ok(response)
}

struct HelperResponseCleanup(PathBuf);

impl Drop for HelperResponseCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

struct GeodataHelperChild {
    child: std::process::Child,
    reaped: bool,
}

impl GeodataHelperChild {
    fn new(child: std::process::Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn child_mut(&mut self) -> &mut std::process::Child {
        &mut self.child
    }

    fn mark_reaped(&mut self) {
        self.reaped = true;
    }

    fn terminate_and_wait(&mut self) {
        let _ = self.child.kill();
        self.reaped = self.child.wait().is_ok();
    }
}

impl Drop for GeodataHelperChild {
    fn drop(&mut self) {
        if !self.reaped {
            self.terminate_and_wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_child_guard_reaps_an_unfinished_child() {
        let child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        drop(GeodataHelperChild::new(child));
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        assert_eq!(result, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn bounded_response_rejects_oversized_files() {
        let path = std::env::temp_dir().join(format!(
            "daed-geodata-helper-oversized-response-{}",
            fastrand::u64(..)
        ));
        fs::write(&path, vec![b'x'; GEODATA_HELPER_MAX_RESPONSE_BYTES + 1]).unwrap();
        assert_eq!(
            read_bounded_response(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_file(path).unwrap();
    }
}
