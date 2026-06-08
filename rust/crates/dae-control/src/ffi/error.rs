use super::*;
thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").expect("empty CString"));
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_control_last_error_message() -> *const c_char {
    LAST_ERROR.with(|last| last.borrow().as_ptr())
}

pub(super) fn ffi_result(f: impl FnOnce() -> Result<(), String>) -> i32 {
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

pub(super) fn set_last_error(message: &str) {
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
