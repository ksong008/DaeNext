use super::*;
mod state;
pub(super) use self::state::*;
mod base_run_args;
pub(super) use self::base_run_args::*;
mod runtime_owner_args;
pub(super) use self::runtime_owner_args::*;
mod active_dataplane_args;
pub(super) use self::active_dataplane_args::*;
mod benchmark_args;
pub(super) use self::benchmark_args::*;
mod product_chain_args;
pub(super) use self::product_chain_args::*;

pub(crate) fn parse_default_optin_args(
    args: &[String],
) -> Result<DefaultOptinParsedArgs, DaemonOutput> {
    let mut parsed = DefaultOptinParsedArgs::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if parse_base_run_arg(arg, &mut iter, &mut parsed)? {
            continue;
        }
        if parse_runtime_owner_arg(arg, &mut iter, &mut parsed)? {
            continue;
        }
        if parse_active_dataplane_arg(arg, &mut iter, &mut parsed)? {
            continue;
        }
        if parse_benchmark_arg(arg, &mut iter, &mut parsed)? {
            continue;
        }
        if parse_product_chain_arg(arg, &mut iter, &mut parsed)? {
            continue;
        }
        return Err(DaemonOutput::usage(format!(
            "unsupported run argument: {arg}"
        )));
    }
    Ok(parsed)
}
