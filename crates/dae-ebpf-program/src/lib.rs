#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]
// eBPF helper and program entry boundaries use fixed verifier raw-pointer ABI.
#![cfg_attr(
    feature = "tproxy-program",
    allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)
)]

#[cfg(feature = "tproxy-program")]
pub mod abi;
#[cfg(feature = "tproxy-program")]
pub mod cgroup;
#[cfg(feature = "tproxy-program")]
pub mod helpers;
#[cfg(feature = "tproxy-program")]
pub mod maps;
#[cfg(feature = "tproxy-program")]
pub mod packet;
#[cfg(feature = "tproxy-program")]
pub mod programs;
#[cfg(feature = "tproxy-program")]
pub mod redirect_key;
#[cfg(feature = "tproxy-program")]
pub mod routing;
#[cfg(feature = "tproxy-program")]
pub mod tproxy;
#[cfg(feature = "trace-program")]
pub mod trace;
#[cfg(feature = "tproxy-program")]
pub mod udp_state;

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
