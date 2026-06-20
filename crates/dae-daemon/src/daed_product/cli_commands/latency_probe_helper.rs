use super::*;

const LATENCY_PROBE_HELPER_TASK_COMM: &[u8] = b"daed-latency\0";

pub(crate) fn run_latency_probe_helper_command(args: &[String]) -> DaedProductOutput {
    if args != ["--stdin-json"] {
        return DaedProductOutput::usage("latency-probe-helper requires --stdin-json");
    }
    if let Err(err) = set_latency_probe_helper_task_comm() {
        return DaedProductOutput::error(format!("prepare latency probe helper identity: {err}"));
    }
    let mut input = Vec::new();
    let mut stdin = io::stdin().take((LATENCY_PROBE_HELPER_MAX_IO_BYTES as u64) + 1);
    if let Err(err) = stdin.read_to_end(&mut input) {
        return DaedProductOutput::error(format!("read latency probe helper stdin: {err}"));
    }
    match latency_probe_helper_response_from_request(&input) {
        Ok(response) => DaedProductOutput::ok(format!("{response}\n")),
        Err(err) => DaedProductOutput::error(format!("latency probe helper failed: {err}")),
    }
}

fn set_latency_probe_helper_task_comm() -> io::Result<()> {
    let status = unsafe {
        libc::prctl(
            libc::PR_SET_NAME,
            LATENCY_PROBE_HELPER_TASK_COMM.as_ptr() as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
