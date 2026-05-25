use std::io;
use std::process::{Command, Output};

use serde_json::{Value, json};

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
}

impl HostOpResult {
    fn from_output(name: Option<String>, spec: HostOpSpec, output: io::Result<Output>) -> Self {
        let (status, exit_code, stdout, stderr) = match output {
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
        })
    }
}

pub(super) struct HostOps;

impl HostOps {
    pub(super) fn run_named(name: &str, spec: HostOpSpec) -> HostOpResult {
        Self::run_command_fallback(Some(name.to_owned()), spec)
    }

    pub(super) fn observe_named(name: &str, spec: HostOpSpec) -> HostOpResult {
        Self::run_command_fallback(Some(name.to_owned()), spec)
    }

    pub(super) fn observe(spec: HostOpSpec) -> HostOpResult {
        Self::run_command_fallback(None, spec)
    }

    fn run_command_fallback(name: Option<String>, spec: HostOpSpec) -> HostOpResult {
        let output = match spec.kind() {
            HostOpKind::Ip
            | HostOpKind::Netns
            | HostOpKind::Tc
            | HostOpKind::Ebpf
            | HostOpKind::Sysctl
            | HostOpKind::Filesystem
            | HostOpKind::Generic => Command::new(spec.program()).args(spec.args()).output(),
        };
        HostOpResult::from_output(name, spec, output)
    }
}

#[cfg(test)]
mod tests {
    use super::{HostOpKind, HostOpSpec, HostOps};

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
    fn legacy_step_json_shape_is_preserved() {
        let value = HostOps::observe(HostOpSpec::new(
            "__dae_missing_host_op_command_for_json_shape_test__",
            ["--noop"],
        ))
        .to_step_json();
        let object = value.as_object().expect("legacy step json must be object");
        let mut keys = object.keys().cloned().collect::<Vec<_>>();
        keys.sort();

        assert_eq!(
            keys,
            [
                "args",
                "exit_code",
                "name",
                "program",
                "status",
                "stderr",
                "stdout",
            ]
        );
        assert!(value["name"].is_null());
        assert_eq!(value["status"], "fail");
        assert_eq!(
            value["program"],
            "__dae_missing_host_op_command_for_json_shape_test__"
        );
    }
}
