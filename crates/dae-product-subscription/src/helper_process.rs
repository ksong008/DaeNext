use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::fetch_error::SubscriptionFetchFailure;
use crate::{
    DecodedSubscriptionHelperOutcome, PreparedSubscriptionRefresh,
    SUBSCRIPTION_HELPER_MAX_RESPONSE_BYTES, SubscriptionHelperRequest, SubscriptionSourceIdentity,
    decode_subscription_helper_response, encode_subscription_helper_request,
};

const SUBSCRIPTION_HELPER_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SUBSCRIPTION_HELPER_WAIT_INTERVAL: Duration = Duration::from_millis(20);
const SUBSCRIPTION_HELPER_CONTROL_SO_MARK: u32 = 0x100;
const SUBSCRIPTION_HELPER_STAGING_DIR: &str = "subscription-helper";
const SUBSCRIPTION_PREPARE_HELPER_SO_MARK_ENV: &str = "DAED_CONTROL_HELPER_SO_MARK";

static SUBSCRIPTION_HELPER_STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub struct PreparedSubscriptionHelper {
    pub prepared: PreparedSubscriptionRefresh,
    pub persist_staging: Option<PathBuf>,
}

impl Drop for PreparedSubscriptionHelper {
    fn drop(&mut self) {
        if let Some(path) = self.persist_staging.take() {
            let _ = fs::remove_file(path);
        }
    }
}

pub enum SubscriptionHelperOutcome {
    Prepared(PreparedSubscriptionHelper),
    FetchFailed(SubscriptionFetchFailure),
}

pub fn prepare_subscription_with_helper(
    state: &Path,
    config_dir: &Path,
    source: &SubscriptionSourceIdentity,
) -> io::Result<SubscriptionHelperOutcome> {
    let response = reserve_private_staging_path(config_dir, source.id, "response")?;
    let persist_staging = reserve_private_staging_path(config_dir, source.id, "persist-content")?;
    let _response_cleanup = SubscriptionHelperFileCleanup::new(response.clone());
    let mut persist_cleanup = SubscriptionHelperFileCleanup::new(persist_staging.clone());
    let request = encode_subscription_helper_request(&SubscriptionHelperRequest {
        state: state.to_path_buf(),
        config_dir: config_dir.to_path_buf(),
        response: response.clone(),
        persist_staging,
        source: source.clone(),
    })?;
    let executable = std::env::current_exe().map_err(|error| {
        io::Error::other(format!("resolve subscription helper executable: {error}"))
    })?;
    let mut child = Command::new(executable)
        .args(["subscription-prepare-helper", "--stdin-json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env(
            SUBSCRIPTION_PREPARE_HELPER_SO_MARK_ENV,
            SUBSCRIPTION_HELPER_CONTROL_SO_MARK.to_string(),
        )
        .spawn()
        .map(SubscriptionHelperChild::new)
        .map_err(|error| io::Error::other(format!("spawn subscription helper: {error}")))?;
    let mut stdin = child
        .child_mut()
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("open subscription helper stdin: unavailable"))?;
    stdin
        .write_all(&request)
        .map_err(|error| io::Error::other(format!("write subscription helper request: {error}")))?;
    drop(stdin);
    drop(request);

    let deadline = Instant::now()
        .checked_add(SUBSCRIPTION_HELPER_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let status = loop {
        if let Some(status) = child
            .child_mut()
            .try_wait()
            .map_err(|error| io::Error::other(format!("wait subscription helper: {error}")))?
        {
            child.mark_reaped();
            break status;
        }
        if Instant::now() >= deadline {
            child.terminate_and_wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "subscription prepare helper timed out",
            ));
        }
        thread::sleep(SUBSCRIPTION_HELPER_WAIT_INTERVAL);
    };

    let response_file = open_bounded_response(&response)?;
    let decoded = decode_subscription_helper_response(io::BufReader::new(response_file), source);
    if !status.success() {
        return match decoded {
            Ok(DecodedSubscriptionHelperOutcome::FetchFailed(failure)) => {
                Ok(SubscriptionHelperOutcome::FetchFailed(failure))
            }
            Ok(DecodedSubscriptionHelperOutcome::Prepared(_)) => Err(io::Error::other(format!(
                "subscription helper exited with status {status} after a success response"
            ))),
            Err(error) => Err(error),
        };
    }
    match decoded? {
        DecodedSubscriptionHelperOutcome::FetchFailed(failure) => {
            Ok(SubscriptionHelperOutcome::FetchFailed(failure))
        }
        DecodedSubscriptionHelperOutcome::Prepared(prepared) => {
            let persist_staging = prepared
                .persist_content
                .then(|| persist_cleanup.take_path());
            Ok(SubscriptionHelperOutcome::Prepared(
                PreparedSubscriptionHelper {
                    prepared,
                    persist_staging,
                },
            ))
        }
    }
}

fn reserve_private_staging_path(
    config_dir: &Path,
    subscription_id: i64,
    purpose: &str,
) -> io::Result<PathBuf> {
    let dir = config_dir
        .join("runtime")
        .join(SUBSCRIPTION_HELPER_STAGING_DIR);
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    for _ in 0..32 {
        let sequence = SUBSCRIPTION_HELPER_STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!(
            ".subscription-{subscription_id}-{purpose}-{}-{sequence}",
            std::process::id()
        ));
        match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
        {
            Ok(file) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
                }
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "cannot reserve a unique subscription helper staging path",
    ))
}

fn open_bounded_response(path: &Path) -> io::Result<fs::File> {
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "subscription helper response is not a regular file",
        ));
    }
    if metadata.len() > SUBSCRIPTION_HELPER_MAX_RESPONSE_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "subscription helper response exceeds {SUBSCRIPTION_HELPER_MAX_RESPONSE_BYTES} bytes"
            ),
        ));
    }
    Ok(file)
}

struct SubscriptionHelperFileCleanup {
    path: Option<PathBuf>,
}

impl SubscriptionHelperFileCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn take_path(&mut self) -> PathBuf {
        self.path
            .take()
            .expect("subscription helper staging path is present")
    }
}

impl Drop for SubscriptionHelperFileCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

struct SubscriptionHelperChild {
    child: std::process::Child,
    reaped: bool,
}

impl SubscriptionHelperChild {
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

impl Drop for SubscriptionHelperChild {
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
    fn private_staging_paths_are_unique_and_mode_0600() {
        let dir = std::env::temp_dir().join(format!(
            "daed-subscription-helper-staging-{}",
            fastrand::u64(..)
        ));
        let first = reserve_private_staging_path(&dir, 7, "response").unwrap();
        let second = reserve_private_staging_path(&dir, 7, "response").unwrap();
        assert_ne!(first, second);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&first).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
