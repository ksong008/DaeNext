use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

const HOST_COMMAND_STREAM_LIMIT: usize = 1024 * 1024;
const HOST_COMMAND_TRUNCATED_SUFFIX: &[u8] = b"\n...[output truncated]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HostOpKind {
    Ip,
    Netns,
    Tc,
    Ebpf,
    Sysctl,
    Filesystem,
    Generic,
}

impl HostOpKind {
    fn infer(program: &str, args: &[String]) -> Self {
        let has_tc = program == "tc" || args.iter().any(|arg| arg == "tc");
        let has_bpf = program == "bpftool"
            || args
                .iter()
                .any(|arg| arg == "bpf" || arg == "bpftool" || arg == "obj");
        if has_tc && has_bpf {
            return Self::Ebpf;
        }
        if has_tc {
            return Self::Tc;
        }
        match program {
            "bpftool" => Self::Ebpf,
            "ip" if args.first().is_some_and(|arg| arg == "netns") => Self::Netns,
            "ip" => Self::Ip,
            "sysctl" => Self::Sysctl,
            "cat" => Self::Filesystem,
            _ => Self::Generic,
        }
    }

    fn timeout(self) -> Duration {
        match self {
            Self::Filesystem => Duration::from_secs(2),
            Self::Sysctl => Duration::from_secs(3),
            Self::Ip | Self::Netns | Self::Tc | Self::Ebpf | Self::Generic => {
                Duration::from_secs(10)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HostOpSpec {
    program: String,
    args: Vec<String>,
    kind: HostOpKind,
}

impl HostOpSpec {
    pub(super) fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let program = program.into();
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        let kind = HostOpKind::infer(&program, &args);
        Self {
            program,
            args,
            kind,
        }
    }

    fn program(&self) -> &str {
        &self.program
    }

    fn args(&self) -> &[String] {
        &self.args
    }

    fn kind(&self) -> HostOpKind {
        self.kind
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostOpStatus {
    Pass,
    Fail,
}

impl HostOpStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HostOpResult {
    name: Option<String>,
    status: HostOpStatus,
    program: String,
    args: Vec<String>,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    started_at_unix_ms: u64,
    finished_at_unix_ms: u64,
    elapsed_ms: u64,
    timeout_ms: u64,
    timed_out: bool,
}

impl HostOpResult {
    fn from_output(
        name: Option<String>,
        spec: HostOpSpec,
        command: HostCommandOutput,
        timing: HostOpTiming,
    ) -> Self {
        let (status, exit_code, stdout, stderr) = match command.output {
            Ok(output) if command.timed_out => (
                HostOpStatus::Fail,
                output.status.code(),
                String::from_utf8_lossy(&output.stdout).trim().to_owned(),
                timeout_stderr(
                    String::from_utf8_lossy(&output.stderr).trim(),
                    timing.timeout_ms,
                ),
            ),
            Ok(output) => (
                if output.status.success() {
                    HostOpStatus::Pass
                } else {
                    HostOpStatus::Fail
                },
                output.status.code(),
                String::from_utf8_lossy(&output.stdout).trim().to_owned(),
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ),
            Err(err) if command.timed_out => {
                (HostOpStatus::Fail, None, String::new(), err.to_string())
            }
            Err(err) => (HostOpStatus::Fail, None, String::new(), err.to_string()),
        };
        Self {
            name,
            status,
            program: spec.program,
            args: spec.args,
            exit_code,
            stdout,
            stderr,
            started_at_unix_ms: timing.started_at_unix_ms,
            finished_at_unix_ms: timing.finished_at_unix_ms,
            elapsed_ms: timing.elapsed_ms,
            timeout_ms: timing.timeout_ms,
            timed_out: command.timed_out,
        }
    }

    pub(super) fn passed(&self) -> bool {
        self.status == HostOpStatus::Pass
    }

    pub(super) fn to_step_json(&self) -> Value {
        json!({
            "name": self.name.clone().map(Value::String).unwrap_or(Value::Null),
            "status": self.status.as_str(),
            "program": self.program.clone(),
            "args": self.args.clone(),
            "exit_code": self.exit_code,
            "stdout": self.stdout.clone(),
            "stderr": self.stderr.clone(),
            "started_at_unix_ms": self.started_at_unix_ms,
            "finished_at_unix_ms": self.finished_at_unix_ms,
            "elapsed_ms": self.elapsed_ms,
            "timeout_ms": self.timeout_ms,
            "timed_out": self.timed_out,
        })
    }
}

struct HostCommandOutput {
    output: io::Result<Output>,
    timed_out: bool,
}

struct HostOpTiming {
    started_at_unix_ms: u64,
    finished_at_unix_ms: u64,
    elapsed_ms: u64,
    timeout_ms: u64,
}

pub(super) struct HostOps;

impl HostOps {
    pub(super) fn run_named(name: &str, spec: HostOpSpec) -> HostOpResult {
        Self::run_command_backend(Some(name.to_owned()), spec)
    }

    pub(super) fn observe_named(name: &str, spec: HostOpSpec) -> HostOpResult {
        Self::run_command_backend(Some(name.to_owned()), spec)
    }

    pub(super) fn observe(spec: HostOpSpec) -> HostOpResult {
        Self::run_command_backend(None, spec)
    }

    fn run_command_backend(name: Option<String>, spec: HostOpSpec) -> HostOpResult {
        let timeout = spec.kind().timeout();
        Self::run_command_backend_with_timeout(name, spec, timeout)
    }

    fn run_command_backend_with_timeout(
        name: Option<String>,
        spec: HostOpSpec,
        timeout: Duration,
    ) -> HostOpResult {
        let started_at_unix_ms = unix_time_millis();
        let started = Instant::now();
        let command_output = match spec.kind() {
            HostOpKind::Ip
            | HostOpKind::Netns
            | HostOpKind::Tc
            | HostOpKind::Ebpf
            | HostOpKind::Sysctl
            | HostOpKind::Filesystem
            | HostOpKind::Generic => run_output_with_timeout(&spec, timeout),
        };
        let elapsed_ms = duration_millis(started.elapsed());
        let finished_at_unix_ms = unix_time_millis();
        HostOpResult::from_output(
            name,
            spec,
            command_output,
            HostOpTiming {
                started_at_unix_ms,
                finished_at_unix_ms,
                elapsed_ms,
                timeout_ms: duration_millis(timeout),
            },
        )
    }
}

fn run_output_with_timeout(spec: &HostOpSpec, timeout: Duration) -> HostCommandOutput {
    let mut command = Command::new(spec.program());
    command
        .args(spec.args())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            return HostCommandOutput {
                output: Err(err),
                timed_out: false,
            };
        }
    };

    // Drain both pipes on dedicated threads while the child runs. Without a
    // concurrent reader, a child that writes more than the pipe capacity
    // (64 KiB on Linux) before exiting would block on write forever, be
    // misreported as a timeout, and lose its output.
    let stdout_reader = match spawn_pipe_reader("stdout", child.stdout.take()) {
        Ok(reader) => reader,
        Err(err) => {
            let _ = terminate_child_process_group(&mut child);
            return HostCommandOutput {
                output: Err(err),
                timed_out: false,
            };
        }
    };
    let stderr_reader = match spawn_pipe_reader("stderr", child.stderr.take()) {
        Ok(reader) => reader,
        Err(err) => {
            let _ = terminate_child_process_group(&mut child);
            let _ = stdout_reader.join();
            return HostCommandOutput {
                output: Err(err),
                timed_out: false,
            };
        }
    };

    let started = Instant::now();
    let mut timed_out = false;
    let wait_result = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() >= timeout => {
                timed_out = true;
                // The child is the leader of its own process group. Killing
                // the group also terminates descendants that inherited the
                // output pipes; otherwise joining the pipe readers below can
                // block until an unrelated grandchild finally exits.
                break terminate_child_process_group(&mut child);
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(err) => {
                // try_wait failed (e.g. ECHILD). Kill and reap to close the
                // pipes so the reader threads can finish before we join them.
                let _ = terminate_child_process_group(&mut child);
                break Err(err);
            }
        }
    };

    // Joining on every path (normal exit, timeout, or error) prevents
    // leaking the reader threads.
    let stdout = join_pipe_reader(stdout_reader, "stdout");
    let stderr = join_pipe_reader(stderr_reader, "stderr");

    let output = match (wait_result, stdout, stderr) {
        (Ok(status), Ok(stdout), Ok(stderr)) => Ok(Output {
            status,
            stdout,
            stderr,
        }),
        (_, Err(err), _) | (_, _, Err(err)) => Err(err),
        (Err(err), _, _) => Err(err),
    };
    HostCommandOutput { output, timed_out }
}

fn terminate_child_process_group(
    child: &mut std::process::Child,
) -> io::Result<std::process::ExitStatus> {
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
    let _ = child.kill();
    child.wait()
}

fn spawn_pipe_reader<R>(
    stream_name: &str,
    pipe: Option<R>,
) -> io::Result<thread::JoinHandle<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name(format!("dae-host-{stream_name}"))
        .spawn(move || read_pipe_bounded(pipe))
}

fn read_pipe_bounded<R: Read>(pipe: Option<R>) -> Vec<u8> {
    let mut bytes = Vec::new();
    let Some(mut pipe) = pipe else {
        return bytes;
    };
    let mut chunk = [0_u8; 8192];
    let mut truncated = false;
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                let remaining = HOST_COMMAND_STREAM_LIMIT.saturating_sub(bytes.len());
                let retained = remaining.min(read);
                bytes.extend_from_slice(&chunk[..retained]);
                truncated |= retained < read;
            }
        }
    }
    if truncated {
        bytes.truncate(HOST_COMMAND_STREAM_LIMIT - HOST_COMMAND_TRUNCATED_SUFFIX.len());
        bytes.extend_from_slice(HOST_COMMAND_TRUNCATED_SUFFIX);
    }
    bytes
}

fn join_pipe_reader(reader: thread::JoinHandle<Vec<u8>>, stream_name: &str) -> io::Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| io::Error::other(format!("{stream_name} reader thread panicked")))
}

fn timeout_stderr(stderr: &str, timeout_ms: u64) -> String {
    let message = format!("command timed out after {timeout_ms} ms");
    if stderr.trim().is_empty() {
        message
    } else {
        format!("{message}; {}", stderr.trim())
    }
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::{HOST_COMMAND_STREAM_LIMIT, HostOpKind, HostOpSpec, HostOps};

    #[test]
    fn classifies_host_operation_kind() {
        assert_eq!(
            HostOpSpec::new("ip", ["netns", "add", "daens"]).kind(),
            HostOpKind::Netns
        );
        assert_eq!(
            HostOpSpec::new("tc", ["filter", "add", "dev", "dae0", "ingress", "bpf"]).kind(),
            HostOpKind::Ebpf
        );
        assert_eq!(
            HostOpSpec::new("sysctl", ["-w", "net.ipv4.ip_forward=1"]).kind(),
            HostOpKind::Sysctl
        );
        assert_eq!(
            HostOpSpec::new("cat", ["/sys/class/net/dae0/ifindex"]).kind(),
            HostOpKind::Filesystem
        );
    }

    #[test]
    fn step_json_preserves_legacy_fields_and_adds_timing() {
        let value = HostOps::observe(HostOpSpec::new(
            "__dae_missing_host_op_command_for_json_shape_test__",
            ["--noop"],
        ))
        .to_step_json();
        let object = value.as_object().expect("legacy step json must be object");
        for key in [
            "args",
            "exit_code",
            "name",
            "program",
            "status",
            "stderr",
            "stdout",
        ] {
            assert!(object.contains_key(key), "missing legacy key {key}");
        }
        for key in [
            "started_at_unix_ms",
            "finished_at_unix_ms",
            "elapsed_ms",
            "timeout_ms",
        ] {
            assert!(object.get(key).and_then(|value| value.as_u64()).is_some());
        }
        assert_eq!(value["timed_out"], false);
        assert!(value["name"].is_null());
        assert_eq!(value["status"], "fail");
        assert_eq!(
            value["program"],
            "__dae_missing_host_op_command_for_json_shape_test__"
        );
    }

    #[test]
    fn command_timeout_marks_step_failed_without_waiting_for_process_exit() {
        let value = HostOps::run_command_backend_with_timeout(
            None,
            HostOpSpec::new("sh", ["-c", "sleep 1"]),
            std::time::Duration::from_millis(20),
        )
        .to_step_json();

        assert_eq!(value["status"], "fail");
        assert_eq!(value["timed_out"], true);
        assert_eq!(value["timeout_ms"], 20);
        assert!(value["stderr"].as_str().unwrap().contains("timed out"));
    }

    #[test]
    fn command_timeout_kills_descendants_holding_output_pipes() {
        let started = std::time::Instant::now();
        let value = HostOps::run_command_backend_with_timeout(
            None,
            HostOpSpec::new("sh", ["-c", "sleep 5 & wait"]),
            std::time::Duration::from_millis(20),
        )
        .to_step_json();

        assert_eq!(value["timed_out"], true);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "timeout waited for a descendant to close inherited pipes"
        );
    }

    #[test]
    fn large_output_is_captured_without_false_timeout() {
        // Each stream exceeds the 64 KiB pipe capacity; without concurrent
        // pipe draining the child would block on write and be misreported
        // as a timeout with its output lost.
        let value = HostOps::run_command_backend_with_timeout(
            None,
            HostOpSpec::new(
                "sh",
                ["-c", "head -c 262144 /dev/zero | tr '\\0' 'A'; head -c 262144 /dev/zero | tr '\\0' 'B' >&2"],
            ),
            std::time::Duration::from_secs(10),
        )
        .to_step_json();

        assert_eq!(value["status"], "pass");
        assert_eq!(value["timed_out"], false);
        assert_eq!(value["stdout"].as_str().unwrap().len(), 262_144);
        assert!(value["stdout"].as_str().unwrap().chars().all(|c| c == 'A'));
        assert_eq!(value["stderr"].as_str().unwrap().len(), 262_144);
        assert!(value["stderr"].as_str().unwrap().chars().all(|c| c == 'B'));
    }

    #[test]
    fn command_output_is_drained_but_retained_within_limit() {
        let value = HostOps::run_command_backend_with_timeout(
            None,
            HostOpSpec::new("sh", ["-c", "head -c 2097152 /dev/zero | tr '\\0' 'A'"]),
            std::time::Duration::from_secs(10),
        )
        .to_step_json();

        assert_eq!(value["status"], "pass");
        assert_eq!(value["timed_out"], false);
        let stdout = value["stdout"].as_str().unwrap();
        assert_eq!(stdout.len(), HOST_COMMAND_STREAM_LIMIT);
        assert!(stdout.ends_with("\n...[output truncated]"));
    }
}
