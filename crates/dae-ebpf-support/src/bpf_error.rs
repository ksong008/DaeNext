use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BpfErrorClass {
    Permission,
    Capacity,
    MissingObject,
    Busy,
    Verifier,
    InvalidInput,
    Unsupported,
    Other,
}

impl BpfErrorClass {
    pub const fn as_report_str(self) -> &'static str {
        match self {
            Self::Permission => "permission",
            Self::Capacity => "capacity",
            Self::MissingObject => "missing_object",
            Self::Busy => "busy",
            Self::Verifier => "verifier",
            Self::InvalidInput => "invalid_input",
            Self::Unsupported => "unsupported",
            Self::Other => "other",
        }
    }
}

pub fn classify_bpf_io_error(err: &io::Error) -> BpfErrorClass {
    if error_message_contains_verifier(err) {
        return BpfErrorClass::Verifier;
    }
    match err.raw_os_error() {
        Some(errno) if errno == libc::EPERM || errno == libc::EACCES => BpfErrorClass::Permission,
        Some(errno)
            if errno == libc::ENOSPC
                || errno == libc::E2BIG
                || errno == libc::ENOMEM
                || errno == libc::EMFILE
                || errno == libc::ENFILE =>
        {
            BpfErrorClass::Capacity
        }
        Some(errno) if errno == libc::ENOENT || errno == libc::ENODEV => {
            BpfErrorClass::MissingObject
        }
        Some(errno) if errno == libc::EBUSY || errno == libc::EEXIST => BpfErrorClass::Busy,
        Some(errno) if errno == libc::EINVAL => BpfErrorClass::InvalidInput,
        Some(errno) if errno == libc::ENOSYS || errno == libc::EOPNOTSUPP => {
            BpfErrorClass::Unsupported
        }
        _ => match err.kind() {
            io::ErrorKind::PermissionDenied => BpfErrorClass::Permission,
            io::ErrorKind::NotFound => BpfErrorClass::MissingObject,
            io::ErrorKind::AlreadyExists => BpfErrorClass::Busy,
            io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => BpfErrorClass::InvalidInput,
            io::ErrorKind::Unsupported => BpfErrorClass::Unsupported,
            _ => BpfErrorClass::Other,
        },
    }
}

pub fn format_bpf_io_error(context: &str, err: &io::Error) -> String {
    let class = classify_bpf_io_error(err).as_report_str();
    format!("{context} failed: {err}; class={class}")
}

fn error_message_contains_verifier(err: &io::Error) -> bool {
    err.to_string().to_ascii_lowercase().contains("verifier")
}
