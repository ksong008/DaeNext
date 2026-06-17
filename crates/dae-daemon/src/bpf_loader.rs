use crate::runner::DaemonOutput;

pub(crate) fn run_bpf_loader_command(args: &[String]) -> DaemonOutput {
    let output = dae_ebpf_loader::run_bpf_loader_command(args);
    DaemonOutput {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.exit_code,
    }
}
