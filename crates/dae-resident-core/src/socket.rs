pub fn set_socket_mark(fd: i32, mark: u32) -> std::io::Result<()> {
    let mark = mark as libc::c_int;
    let status = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const libc::c_int).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn apply_udp_socket_buffer_tuning(fd: i32, bytes: usize) {
    let _ = set_socket_buffer_bytes(fd, libc::SO_RCVBUF, bytes);
    let _ = set_socket_buffer_bytes(fd, libc::SO_SNDBUF, bytes);
}

fn set_socket_buffer_bytes(fd: i32, option: i32, bytes: usize) -> std::io::Result<()> {
    let value = bytes.min(i32::MAX as usize) as libc::c_int;
    let status = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&value as *const libc::c_int).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
