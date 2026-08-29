use super::*;
use dae_product_control::subscription::{
    SUBSCRIPTION_HELPER_MAX_REQUEST_BYTES, SubscriptionHelperRequest,
    decode_subscription_helper_request, encode_subscription_helper_failure,
    encode_subscription_helper_success,
};

pub(in crate::daed_product) fn run_subscription_prepare_helper_command(
    args: &[String],
) -> DaedProductOutput {
    if args != ["--stdin-json"] {
        return DaedProductOutput::usage("subscription-prepare-helper requires --stdin-json");
    }
    if let Err(error) = set_subscription_prepare_helper_task_comm() {
        return DaedProductOutput::error(format!("prepare subscription helper identity: {error}"));
    }
    let mut input = Vec::new();
    let mut stdin = io::stdin().take((SUBSCRIPTION_HELPER_MAX_REQUEST_BYTES as u64) + 1);
    if let Err(error) = stdin.read_to_end(&mut input) {
        return DaedProductOutput::error(format!("read subscription helper stdin: {error}"));
    }
    let request = match decode_subscription_helper_request(&input) {
        Ok(request) => request,
        Err(error) => {
            return DaedProductOutput::error(format!(
                "decode subscription helper request: {error}"
            ));
        }
    };
    match run_subscription_prepare_helper(&request) {
        Ok(prepared) => {
            let response = encode_subscription_helper_success(&request.source, &prepared);
            match write_subscription_helper_response(&request.response, &response) {
                Ok(()) => DaedProductOutput::ok(String::new()),
                Err(error) => {
                    DaedProductOutput::error(format!("write subscription helper response: {error}"))
                }
            }
        }
        Err(error) => {
            let failure = fetch_error::SubscriptionFetchFailure::from_io_error(&error);
            let response = encode_subscription_helper_failure(&request.source, &failure);
            if let Err(write_error) =
                write_subscription_helper_response(&request.response, &response)
            {
                return DaedProductOutput::error(format!(
                    "subscription helper failed: {}; write failure response: {write_error}",
                    failure.message()
                ));
            }
            DaedProductOutput::error(format!("subscription helper failed: {}", failure.message()))
        }
    }
}

fn set_subscription_prepare_helper_task_comm() -> io::Result<()> {
    let task_name = std::ffi::CString::new(SUBSCRIPTION_PREPARE_HELPER_TASK_NAME)
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

fn run_subscription_prepare_helper(
    request: &SubscriptionHelperRequest,
) -> io::Result<node_stage::PreparedSubscriptionRefresh> {
    let control_runtime =
        start_product_control_helper_runtime(SUBSCRIPTION_PREPARE_HELPER_TASK_NAME)?;
    let result = (|| {
        let proxy_config = if request.source.use_proxy
            && subscription_link_uses_http_transport(&request.source.link)
        {
            Some(product_default_proxy_config(&request.state)?)
        } else {
            None
        };
        source::fetch_subscription_content_with_proxy_config(
            &control_runtime,
            &request.config_dir,
            request.source.tag.as_deref(),
            &request.source.link,
            proxy_config.as_ref(),
        )
        .and_then(|fetched| {
            let content = content::parse_subscription_content(&fetched.content);
            let mut prepared = node_stage::prepare_subscription_refresh(&content);
            if fetched.persist_path.is_some() {
                source::write_persisted_subscription(
                    &request.persist_staging,
                    fetched.content.as_bytes(),
                )?;
                prepared.persist_content = true;
            }
            Ok(prepared)
        })
    })();
    let shutdown = control_runtime.shutdown();
    match (result, shutdown) {
        (Ok(prepared), Ok(_)) => Ok(prepared),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(io::Error::other(format!(
            "shutdown subscription helper control runtime: {error}"
        ))),
    }
}

fn write_subscription_helper_response(path: &Path, response: &Value) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    serde_json::to_writer(&mut file, response).map_err(|error| {
        io::Error::other(format!("encode subscription helper response: {error}"))
    })?;
    file.flush()
}
