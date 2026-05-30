#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

pub mod abi;
pub mod cgroup;
pub mod helpers;
pub mod maps;
pub mod packet;
pub mod programs;
pub mod routing;
pub mod tproxy;
pub mod udp_state;

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
