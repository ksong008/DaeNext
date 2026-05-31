use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;

use dae_ebpf_support::{
    BpfDomainRouting, BpfLpmKey, BpfMatchSet, DomainRoutingMapEntry, LpmMapBuildSpec, LpmMapEntry,
    RoutingMapEntry, apply_domain_routing_map_by_id, apply_routing_maps_with_lpm_build_by_id,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiRoutingMapEntry {
    pub index: u32,
    pub value: BpfMatchSet,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiLpmMapEntry {
    pub key: BpfLpmKey,
    pub value: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiLpmMapBuildSpec {
    pub index: u32,
    pub flags: u32,
    pub max_entries: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub entries: *const FfiLpmMapEntry,
    pub entries_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiDomainRoutingUpdate {
    pub key: [u32; 4],
    pub bitmap: [u32; 32],
}

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").expect("empty CString"));
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_last_error_message() -> *const c_char {
    LAST_ERROR.with(|last| last.borrow().as_ptr())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_ffi_abi_version() -> u32 {
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_apply_routing_maps_with_lpm_build_by_id(
    routing_map_id: u32,
    lpm_array_map_id: u32,
    routing_entries: *const FfiRoutingMapEntry,
    routing_entries_len: usize,
    lpm_maps: *const FfiLpmMapBuildSpec,
    lpm_maps_len: usize,
) -> i32 {
    ffi_result(|| {
        let routing_entries = unsafe { slice_from_raw(routing_entries, routing_entries_len)? };
        let lpm_maps = unsafe { slice_from_raw(lpm_maps, lpm_maps_len)? };
        let routing_entries = routing_entries
            .iter()
            .map(|entry| RoutingMapEntry {
                index: entry.index,
                value: entry.value,
            })
            .collect::<Vec<_>>();
        let lpm_maps = lpm_maps
            .iter()
            .map(|spec| {
                let entries = unsafe { slice_from_raw(spec.entries, spec.entries_len)? };
                let entries = entries
                    .iter()
                    .map(|entry| LpmMapEntry {
                        key: entry.key,
                        value: entry.value,
                    })
                    .collect::<Vec<_>>();
                Ok(LpmMapBuildSpec {
                    index: spec.index,
                    flags: spec.flags,
                    max_entries: spec.max_entries,
                    key_size: spec.key_size,
                    value_size: spec.value_size,
                    entries,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        apply_routing_maps_with_lpm_build_by_id(
            routing_map_id,
            lpm_array_map_id,
            &routing_entries,
            &[],
            &lpm_maps,
        )
        .map_err(|err| format!("apply routing maps via Rust in-process: {err}"))?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_apply_domain_routing_map_by_id(
    map_id: u32,
    updates: *const FfiDomainRoutingUpdate,
    updates_len: usize,
    deletes: *const [u32; 4],
    deletes_len: usize,
) -> i32 {
    ffi_result(|| {
        let updates = unsafe { slice_from_raw(updates, updates_len)? };
        let deletes = unsafe { slice_from_raw(deletes, deletes_len)? };
        let updates = updates
            .iter()
            .map(|entry| DomainRoutingMapEntry {
                key: entry.key,
                value: BpfDomainRouting {
                    bitmap: entry.bitmap,
                },
            })
            .collect::<Vec<_>>();
        apply_domain_routing_map_by_id(map_id, &updates, deletes)
            .map_err(|err| format!("apply domain routing map via Rust in-process: {err}"))?;
        Ok(())
    })
}

unsafe fn slice_from_raw<'a, T>(ptr: *const T, len: usize) -> Result<&'a [T], String> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err("nonnull pointer required when length is nonzero".to_owned());
    }
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

fn ffi_result(f: impl FnOnce() -> Result<(), String>) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(f));
    match result {
        Ok(Ok(())) => {
            set_last_error("");
            0
        }
        Ok(Err(err)) => {
            set_last_error(&err);
            -1
        }
        Err(_) => {
            set_last_error("panic in dae-control FFI");
            -2
        }
    }
}

fn set_last_error(message: &str) {
    let sanitized = message.replace('\0', "\\0");
    let cstr =
        CString::new(sanitized).unwrap_or_else(|_| CString::new("invalid ffi error").unwrap());
    LAST_ERROR.with(|last| {
        *last.borrow_mut() = cstr;
    });
}

pub fn last_error_for_tests() -> String {
    LAST_ERROR.with(|last| unsafe {
        CStr::from_ptr(last.borrow().as_ptr())
            .to_string_lossy()
            .into_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_rejects_null_pointer_with_nonzero_len() {
        let rc = unsafe {
            dae_control_apply_domain_routing_map_by_id(0, std::ptr::null(), 1, std::ptr::null(), 0)
        };
        assert_eq!(rc, -1);
        assert!(last_error_for_tests().contains("nonnull pointer required"));
    }

    #[test]
    fn ffi_abi_version_is_stable() {
        assert_eq!(unsafe { dae_control_ffi_abi_version() }, 1);
    }
}
