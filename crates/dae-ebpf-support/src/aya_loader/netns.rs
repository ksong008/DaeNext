use super::*;
pub(super) fn with_optional_netns<T>(
    netns: Option<&str>,
    f: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let Some(netns) = netns else {
        return f();
    };
    let mut guard = NetnsGuard::enter(netns)?;
    let result = f();
    let restore_result = guard.restore();
    match (result, restore_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(err), Ok(())) => Err(err),
        (Ok(_), Err(err)) => Err(err),
        (Err(err), Err(restore_err)) => Err(format!(
            "{err}; additionally failed to restore original netns after {netns}: {restore_err}"
        )),
    }
}

pub(super) struct NetnsGuard {
    pub(super) original: fs::File,
    pub(super) restored: bool,
}

impl NetnsGuard {
    pub(super) fn enter(netns: &str) -> Result<Self, String> {
        let original = fs::File::open("/proc/self/ns/net")
            .map_err(|err| format!("open current netns failed: {err}"))?;
        let target_path = netns_path(netns);
        let target = fs::File::open(&target_path)
            .map_err(|err| format!("open target netns {} failed: {err}", target_path.display()))?;
        setns(target.as_raw_fd())
            .map_err(|err| format!("enter target netns {} failed: {err}", target_path.display()))?;
        Ok(Self {
            original,
            restored: false,
        })
    }

    pub(super) fn restore(&mut self) -> Result<(), String> {
        if self.restored {
            return Ok(());
        }
        setns(self.original.as_raw_fd())
            .map_err(|err| format!("restore original netns failed: {err}"))?;
        self.restored = true;
        Ok(())
    }
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub(super) fn netns_path(netns: &str) -> PathBuf {
    let path = Path::new(netns);
    if path.is_absolute() {
        path.to_owned()
    } else {
        Path::new("/var/run/netns").join(netns)
    }
}

pub(super) fn setns(fd: i32) -> io::Result<()> {
    let status = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
    if status < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn add_clsact_or_accept_existing(iface: &str) -> Result<(), String> {
    match tc::qdisc_add_clsact(iface) {
        Ok(()) => Ok(()),
        Err(err)
            if err.kind() == io::ErrorKind::AlreadyExists
                || err.raw_os_error() == Some(libc::EEXIST) =>
        {
            Ok(())
        }
        Err(err) => Err(format!("aya tc clsact qdisc add failed on {iface}: {err}")),
    }
}
