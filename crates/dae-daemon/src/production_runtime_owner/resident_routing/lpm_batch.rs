use super::maps::prefix_to_lpm_key;
use dae_ebpf_support::ValidatedRuntimeMapHandle;
use dae_routing::IpPrefix;
use std::{io, mem::size_of};

pub(super) fn update_lpm_batch(
    map: &ValidatedRuntimeMapHandle,
    prefixes: &[IpPrefix],
) -> io::Result<()> {
    #[repr(C)]
    struct BatchAttr {
        in_batch: u64,
        out_batch: u64,
        keys: u64,
        values: u64,
        count: u32,
        map_fd: u32,
        elem_flags: u64,
        flags: u64,
    }
    let keys = prefixes.iter().map(prefix_to_lpm_key).collect::<Vec<_>>();
    let values = vec![1_u32; prefixes.len()];
    let mut attr = BatchAttr {
        in_batch: 0,
        out_batch: 0,
        keys: keys.as_ptr() as u64,
        values: values.as_ptr() as u64,
        count: prefixes.len() as u32,
        map_fd: map.as_raw_fd() as u32,
        elem_flags: 0,
        flags: 0,
    };
    // SAFETY: both contiguous arrays outlive the syscall; the validated map
    // uses exactly 20-byte keys and 4-byte values. The kernel updates count.
    let result = unsafe { libc::syscall(libc::SYS_bpf, 26_u32, &mut attr, size_of::<BatchAttr>()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if attr.count as usize != prefixes.len() {
        return Err(io::Error::other("resident LPM batch update was incomplete"));
    }
    Ok(())
}
