use super::*;
use dae_product_geodata::{
    GEODATA_HELPER_MAX_REQUEST_BYTES, GeodataHelperRequest, decode_geodata_helper_request,
    encode_geodata_helper_failure, encode_geodata_helper_success,
};

pub(in crate::daed_product) fn run_geodata_prepare_helper_command(
    args: &[String],
) -> DaedProductOutput {
    if args != ["--stdin-json"] {
        return DaedProductOutput::usage("geodata-prepare-helper requires --stdin-json");
    }
    if let Err(error) = set_geodata_prepare_helper_task_comm() {
        return DaedProductOutput::error(format!("prepare geodata helper identity: {error}"));
    }
    let mut input = Vec::new();
    let mut stdin = io::stdin().take((GEODATA_HELPER_MAX_REQUEST_BYTES as u64) + 1);
    if let Err(error) = stdin.read_to_end(&mut input) {
        return DaedProductOutput::error(format!("read geodata helper stdin: {error}"));
    }
    let request = match decode_geodata_helper_request(&input) {
        Ok(request) => request,
        Err(error) => {
            return DaedProductOutput::error(format!("decode geodata helper request: {error}"));
        }
    };
    match run_geodata_prepare_helper(&request) {
        Ok(prepared) => {
            let response = encode_geodata_helper_success(request.kind, &prepared);
            match write_geodata_helper_response(&request.response, &response) {
                Ok(()) => DaedProductOutput::ok(String::new()),
                Err(error) => DaedProductOutput::error(format!(
                    "write {} geodata helper response: {error}",
                    request.kind.response_key()
                )),
            }
        }
        Err(error) => {
            let response = encode_geodata_helper_failure(request.kind, &error.to_string());
            if let Err(write_error) = write_geodata_helper_response(&request.response, &response) {
                return DaedProductOutput::error(format!(
                    "{} geodata helper failed: {error}; write failure response: {write_error}",
                    request.kind.response_key()
                ));
            }
            DaedProductOutput::error(format!(
                "{} geodata helper failed: {error}",
                request.kind.response_key()
            ))
        }
    }
}

fn set_geodata_prepare_helper_task_comm() -> io::Result<()> {
    let task_name = std::ffi::CString::new(GEODATA_PREPARE_HELPER_TASK_NAME)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let status = unsafe {
        libc::prctl(
            libc::PR_SET_NAME,
            task_name.as_ptr() as libc::c_ulong,
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

fn run_geodata_prepare_helper(
    request: &GeodataHelperRequest,
) -> io::Result<GeodataPreparedDownload> {
    // eBPF admits a marked helper socket only when the creating task has the
    // dedicated helper comm. Tokio creates network sockets on runtime and
    // blocking-pool threads, so those threads must carry the same identity as
    // the helper's initial thread.
    let control_runtime = start_product_control_helper_runtime(GEODATA_PREPARE_HELPER_TASK_NAME)?;
    let result = prepare_geodata_download_inline(
        &control_runtime,
        &request.state,
        request.kind,
        &request.output,
    );
    let shutdown = control_runtime.shutdown();
    match (result, shutdown) {
        (Ok(prepared), Ok(_)) => Ok(prepared),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(io::Error::other(format!(
            "shutdown geodata helper control runtime: {error}"
        ))),
    }
}

fn write_geodata_helper_response(path: &Path, response: &Value) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    serde_json::to_writer(&mut file, response)
        .map_err(|error| io::Error::other(format!("encode geodata helper response: {error}")))?;
    file.flush()
}
