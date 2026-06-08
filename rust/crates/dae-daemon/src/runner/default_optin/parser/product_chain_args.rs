use super::*;
pub(crate) fn parse_product_chain_arg<'a>(
    arg: &str,
    iter: &mut std::slice::Iter<'a, String>,
    state: &mut DefaultOptinParsedArgs,
) -> Result<bool, DaemonOutput> {
    macro_rules! usage {
        ($($arg:tt)*) => {
            return Err(DaemonOutput::usage($($arg)*))
        };
    }
    match arg {
        "--execute-product-chain-recertification" => {
            state.product_chain_recertification = true;
        }
        "--product-chain-admission-evidence" => {
            let Some(value) = iter.next() else {
                usage!("missing run --product-chain-admission-evidence value",);
            };
            state.product_chain_admission_evidence = Some(value.into());
        }
        _ if arg.starts_with("--product-chain-admission-evidence=") => {
            state.product_chain_admission_evidence =
                arg.split_once('=').map(|(_, value)| value.into());
        }
        "--request-default-path-mutation" => {
            state.request_default_path_mutation = true;
        }
        "--plan-production-run-command-replacement" => {
            state.plan_production_run_command_replacement = true;
        }
        "--execute-production-run-command-replacement" => {
            state.execute_production_run_command_replacement = true;
        }
        "--plan-production-run-command-apply" => {
            state.plan_production_run_command_apply = true;
        }
        "--allow-host-default-path-mutation" => {
            state.allow_host_default_path_mutation = true;
        }
        "--plan-local-validation-fresh-install" => {
            state.plan_local_validation_fresh_install = true;
        }
        "--product-chain-fresh-install-binary-source" => {
            let Some(value) = iter.next() else {
                usage!("missing run --product-chain-fresh-install-binary-source value",);
            };
            state.product_chain_fresh_install_binary_source = Some(value.into());
        }
        _ if arg.starts_with("--product-chain-fresh-install-binary-source=") => {
            state.product_chain_fresh_install_binary_source =
                arg.split_once('=').map(|(_, value)| value.into());
        }
        "--product-chain-resident-default-daemon-binary-source" => {
            let Some(value) = iter.next() else {
                usage!("missing run --product-chain-resident-default-daemon-binary-source value",);
            };
            state.product_chain_resident_default_daemon_binary_source = Some(value.into());
        }
        _ if arg.starts_with("--product-chain-resident-default-daemon-binary-source=") => {
            state.product_chain_resident_default_daemon_binary_source =
                arg.split_once('=').map(|(_, value)| value.into());
        }
        "--product-chain-dae-repo" => {
            let Some(value) = iter.next() else {
                usage!("missing run --product-chain-dae-repo value");
            };
            state.product_chain_dae_repo = Some(value.into());
        }
        _ if arg.starts_with("--product-chain-dae-repo=") => {
            state.product_chain_dae_repo = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--product-chain-dae-wing-repo" => {
            let Some(value) = iter.next() else {
                usage!("missing run --product-chain-dae-wing-repo value");
            };
            state.product_chain_dae_wing_repo = Some(value.into());
        }
        _ if arg.starts_with("--product-chain-dae-wing-repo=") => {
            state.product_chain_dae_wing_repo = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--product-chain-daed-repo" => {
            let Some(value) = iter.next() else {
                usage!("missing run --product-chain-daed-repo value");
            };
            state.product_chain_daed_repo = Some(value.into());
        }
        _ if arg.starts_with("--product-chain-daed-repo=") => {
            state.product_chain_daed_repo = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--product-chain-outbound-repo" => {
            let Some(value) = iter.next() else {
                usage!("missing run --product-chain-outbound-repo value");
            };
            state.product_chain_outbound_repo = Some(value.into());
        }
        _ if arg.starts_with("--product-chain-outbound-repo=") => {
            state.product_chain_outbound_repo = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--product-chain-quic-go-repo" => {
            let Some(value) = iter.next() else {
                usage!("missing run --product-chain-quic-go-repo value");
            };
            state.product_chain_quic_go_repo = Some(value.into());
        }
        _ if arg.starts_with("--product-chain-quic-go-repo=") => {
            state.product_chain_quic_go_repo = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--product-chain-service-file" => {
            let Some(value) = iter.next() else {
                usage!("missing run --product-chain-service-file value");
            };
            state.product_chain_service_file = Some(value.into());
        }
        _ if arg.starts_with("--product-chain-service-file=") => {
            state.product_chain_service_file = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--product-chain-go-mod-file" => {
            let Some(value) = iter.next() else {
                usage!("missing run --product-chain-go-mod-file value");
            };
            state.product_chain_go_mod_file = Some(value.into());
        }
        _ if arg.starts_with("--product-chain-go-mod-file=") => {
            state.product_chain_go_mod_file = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--exit-after-ready" | "--once" => state.exit_after_ready = true,
        _ => return Ok(false),
    }
    Ok(true)
}
