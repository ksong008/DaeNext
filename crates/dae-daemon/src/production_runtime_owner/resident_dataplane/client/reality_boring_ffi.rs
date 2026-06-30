use super::*;
use boring::ssl::SslRef;
use foreign_types::ForeignTypeRef;

unsafe extern "C" {
    fn DAE_SSL_set1_reality_config(
        ssl: *mut boring_sys::SSL,
        server_public_key: *const u8,
        server_public_key_len: usize,
        short_id: *const u8,
        short_id_len: usize,
        client_version: *const u8,
    ) -> libc::c_int;

    fn DAE_SSL_get0_reality_auth_key(
        ssl: *const boring_sys::SSL,
        out_key: *mut *const u8,
        out_key_len: *mut usize,
    ) -> libc::c_int;

}

pub(super) fn configure_reality_boring_ssl(
    ssl: &mut SslRef,
    reality: &ResidentRealityUnderlayPlan,
) -> Result<(), String> {
    let short_id = reality.short_id.as_slice();
    let short_id_ptr = if short_id.is_empty() {
        std::ptr::null()
    } else {
        short_id.as_ptr()
    };
    let ok = unsafe {
        DAE_SSL_set1_reality_config(
            ssl.as_ptr(),
            reality.public_key.as_ptr(),
            reality.public_key.len(),
            short_id_ptr,
            short_id.len(),
            REALITY_VERSION.as_ptr(),
        )
    };
    if ok == 1 {
        Ok(())
    } else {
        Err("configure VLESS Reality BoringSSL underlay".to_owned())
    }
}

pub(super) fn reality_boring_auth_key(ssl: &SslRef) -> Option<[u8; 32]> {
    let mut key_ptr = std::ptr::null();
    let mut key_len = 0_usize;
    let ok = unsafe { DAE_SSL_get0_reality_auth_key(ssl.as_ptr(), &mut key_ptr, &mut key_len) };
    if ok != 1 || key_ptr.is_null() || key_len != 32 {
        return None;
    }
    let mut key = [0_u8; 32];
    let source = unsafe { std::slice::from_raw_parts(key_ptr, key_len) };
    key.copy_from_slice(source);
    Some(key)
}
