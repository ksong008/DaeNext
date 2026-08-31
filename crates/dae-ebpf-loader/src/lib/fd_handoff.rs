pub(super) fn send_fd_handoff(socket_fd: i32, payload: &[u8], fds: &[i32]) -> Result<(), String> {
    if payload.is_empty() {
        return Err("fd handoff payload must not be empty".to_owned());
    }
    if fds.is_empty() {
        return Err("fd handoff requires at least one fd".to_owned());
    }

    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let rights_bytes = std::mem::size_of_val(fds);
    let rights_len = rights_bytes
        .try_into()
        .map_err(|_| "fd handoff rights payload exceeds the platform cmsg limit".to_owned())?;
    let control_len = unsafe { libc::CMSG_SPACE(rights_len) } as usize;
    let cmsg_len = unsafe { libc::CMSG_LEN(rights_len) };
    let mut control = vec![0_u8; control_len];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    #[cfg(target_env = "musl")]
    {
        msg.msg_controllen = u32::try_from(control.len()).map_err(|_| {
            "fd handoff control buffer exceeds the platform msghdr limit".to_owned()
        })?;
    }
    #[cfg(not(target_env = "musl"))]
    {
        msg.msg_controllen = control.len();
    }

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err("failed to allocate SCM_RIGHTS control message".to_owned());
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        #[cfg(target_env = "musl")]
        {
            (*cmsg).cmsg_len = cmsg_len;
        }
        #[cfg(not(target_env = "musl"))]
        {
            (*cmsg).cmsg_len = cmsg_len as usize;
        }
        std::ptr::copy_nonoverlapping(
            fds.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(cmsg).cast::<u8>(),
            rights_bytes,
        );
        #[cfg(target_os = "linux")]
        let send_flags = libc::MSG_NOSIGNAL;
        #[cfg(not(target_os = "linux"))]
        let send_flags = 0;
        let sent = libc::sendmsg(socket_fd, &msg, send_flags);
        if sent < 0 {
            return Err(format!(
                "sendmsg failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if sent as usize != payload.len() {
            return Err(format!(
                "sendmsg wrote {sent} bytes, expected {}",
                payload.len()
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "native-ebpf")]
pub(super) fn mac_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
