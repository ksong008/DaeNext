use std::ffi::CString;
use std::io;
use std::mem::size_of;
use std::net::UdpSocket;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const BPF_PROG_LOAD: libc::c_uint = 5;
const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
const BPF_ALU: u8 = 0x04;
const BPF_MOV: u8 = 0xb0;
const BPF_K: u8 = 0x00;
const BPF_JMP: u8 = 0x05;
const BPF_EXIT: u8 = 0x90;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemporaryBpfProgramAttachSmoke {
    pub prog_type: &'static str,
    pub prog_name: &'static str,
    pub instruction_count: u32,
    pub attach_target: &'static str,
    pub socket_bound_addr: String,
    pub program_loaded: bool,
    pub socket_attach_passed: bool,
    pub socket_detach_passed: bool,
}

pub fn run_temporary_socket_filter_attach_smoke() -> io::Result<TemporaryBpfProgramAttachSmoke> {
    let program = load_minimal_socket_filter_program()
        .map_err(|err| io::Error::new(err.kind(), format!("program load failed: {err}")))?;
    let socket = UdpSocket::bind(("127.0.0.1", 0))?;
    attach_socket_filter(socket.as_raw_fd(), program.as_raw_fd())
        .map_err(|err| io::Error::new(err.kind(), format!("socket attach failed: {err}")))?;
    detach_socket_filter(socket.as_raw_fd())
        .map_err(|err| io::Error::new(err.kind(), format!("socket detach failed: {err}")))?;

    Ok(TemporaryBpfProgramAttachSmoke {
        prog_type: "SocketFilter",
        prog_name: "dae_stg162",
        instruction_count: 2,
        attach_target: "temporary-loopback-udp-socket",
        socket_bound_addr: socket.local_addr()?.to_string(),
        program_loaded: true,
        socket_attach_passed: true,
        socket_detach_passed: true,
    })
}

fn load_minimal_socket_filter_program() -> io::Result<OwnedFd> {
    let instructions = [
        BpfInsn {
            code: BPF_ALU | BPF_MOV | BPF_K,
            dst_src: 0,
            off: 0,
            imm: 0xffff,
        },
        BpfInsn {
            code: BPF_JMP | BPF_EXIT,
            dst_src: 0,
            off: 0,
            imm: 0,
        },
    ];
    let license = CString::new("GPL").unwrap();
    let mut log_buf = vec![0_u8; 4096];
    let mut attr = BpfProgLoadAttr {
        prog_type: BPF_PROG_TYPE_SOCKET_FILTER,
        insn_cnt: instructions.len() as u32,
        insns: instructions.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size: log_buf.len() as u32,
        log_buf: log_buf.as_mut_ptr() as u64,
        ..BpfProgLoadAttr::default()
    };
    attr.prog_name[..10].copy_from_slice(b"dae_stg162");

    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_LOAD,
            &attr as *const BpfProgLoadAttr,
            size_of::<BpfProgLoadAttr>(),
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        let log = String::from_utf8_lossy(&log_buf)
            .trim_matches(char::from(0))
            .trim()
            .to_string();
        if log.is_empty() {
            return Err(err);
        }
        return Err(io::Error::new(
            err.kind(),
            format!("{err}; verifier: {log}"),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn attach_socket_filter(socket_fd: i32, program_fd: i32) -> io::Result<()> {
    let fd = program_fd as libc::c_int;
    let status = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_BPF,
            (&fd as *const libc::c_int).cast::<libc::c_void>(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn detach_socket_filter(socket_fd: i32) -> io::Result<()> {
    let value = 0 as libc::c_int;
    let status = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_DETACH_BPF,
            (&value as *const libc::c_int).cast::<libc::c_void>(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BpfInsn {
    code: u8,
    dst_src: u8,
    off: i16,
    imm: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}
