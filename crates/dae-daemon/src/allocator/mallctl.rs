#[cfg(feature = "allocator-jemalloc")]
use std::ffi::c_void;

#[cfg(feature = "allocator-jemalloc")]
pub(super) fn read_u32(name: &[u8]) -> Result<u32, String> {
    validate_name(name)?;
    let mut value = 0_u32;
    let mut length = std::mem::size_of::<u32>();
    let result = unsafe {
        tikv_jemalloc_sys::mallctl(
            name.as_ptr().cast(),
            (&mut value as *mut u32).cast::<c_void>(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result == 0 && length == std::mem::size_of::<u32>() {
        Ok(value)
    } else if result == 0 {
        Err(format!(
            "mallctl returned an unexpected value size {length}"
        ))
    } else {
        Err(error(result))
    }
}

#[cfg(feature = "allocator-jemalloc")]
pub(super) fn read_bool(name: &[u8]) -> Result<bool, String> {
    validate_name(name)?;
    let mut value = 0_u8;
    let mut length = std::mem::size_of::<u8>();
    let result = unsafe {
        tikv_jemalloc_sys::mallctl(
            name.as_ptr().cast(),
            (&mut value as *mut u8).cast::<c_void>(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result == 0 && length == std::mem::size_of::<u8>() {
        Ok(value != 0)
    } else if result == 0 {
        Err(format!(
            "mallctl returned an unexpected value size {length}"
        ))
    } else {
        Err(error(result))
    }
}

#[cfg(feature = "allocator-jemalloc")]
pub(super) fn read_usize(name: &[u8]) -> Result<usize, String> {
    validate_name(name)?;
    let mut value = 0_usize;
    let mut length = std::mem::size_of::<usize>();
    let result = unsafe {
        tikv_jemalloc_sys::mallctl(
            name.as_ptr().cast(),
            (&mut value as *mut usize).cast::<c_void>(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result == 0 && length == std::mem::size_of::<usize>() {
        Ok(value)
    } else if result == 0 {
        Err(format!(
            "mallctl returned an unexpected value size {length}"
        ))
    } else {
        Err(error(result))
    }
}

#[cfg(feature = "allocator-jemalloc")]
pub(super) fn write_u32(name: &[u8], value: u32) -> Result<(), String> {
    validate_name(name)?;
    let result = unsafe {
        tikv_jemalloc_sys::mallctl(
            name.as_ptr().cast(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            (&value as *const u32).cast::<c_void>().cast_mut(),
            std::mem::size_of::<u32>(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(error(result))
    }
}

#[cfg(feature = "allocator-jemalloc")]
pub(super) fn read_command_u32(name: &[u8]) -> Result<u32, String> {
    read_u32(name)
}

#[cfg(feature = "allocator-jemalloc")]
pub(super) fn command(name: &[u8]) -> Result<(), String> {
    validate_name(name)?;
    let result = unsafe {
        tikv_jemalloc_sys::mallctl(
            name.as_ptr().cast(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(error(result))
    }
}

#[cfg(feature = "allocator-jemalloc")]
fn validate_name(name: &[u8]) -> Result<(), String> {
    if name.ends_with(&[0]) {
        Ok(())
    } else {
        Err("mallctl name must be null-terminated".to_owned())
    }
}

#[cfg(feature = "allocator-jemalloc")]
fn error(result: i32) -> String {
    let error = std::io::Error::from_raw_os_error(result);
    format!("mallctl returned {result}: {error}")
}
