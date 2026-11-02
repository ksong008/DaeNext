use super::*;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use crate::runtime_maps::{delete_map_elem_bytes, lookup_map_elem_bytes};

pub(super) trait MapIo {
    fn cookie(&self, key: u32) -> io::Result<Option<u64>>;
    fn put(&self, key: u32, fd: i32) -> io::Result<()>;
    fn delete(&self, key: u32) -> io::Result<()>;
}

#[derive(Debug)]
pub(super) struct KernelMap(pub OwnedFd);
impl MapIo for KernelMap {
    fn cookie(&self, key: u32) -> io::Result<Option<u64>> {
        let mut value = [0; 8];
        match lookup_map_elem_bytes(self.0.as_raw_fd(), &key.to_ne_bytes(), &mut value) {
            Ok(()) => Ok(Some(u64::from_ne_bytes(value))),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn put(&self, key: u32, fd: i32) -> io::Result<()> {
        update_sockmap_fd(self.0.as_raw_fd(), key, fd)
    }
    fn delete(&self, key: u32) -> io::Result<()> {
        delete_map_elem_bytes(self.0.as_raw_fd(), &key.to_ne_bytes())
    }
}

/// A cold map's four slots remain invisible until the final ready-slot write.
/// An active map accepts only an identical, complete publication. Replacing an
/// active physical owner requires stopping it, not rewriting its socket slots.
#[derive(Debug)]
pub(super) struct Transaction<M: MapIo> {
    map: M,
    cookies: [u64; 4],
    fds: [i32; 4],
    inserted: Vec<u32>,
    published: bool,
}
impl<M: MapIo> Transaction<M> {
    pub(super) fn stage(map: M, fds: [i32; 4], cookies: [u64; 4]) -> io::Result<Self> {
        let mut existing = [None; 5];
        for (key, value) in existing.iter_mut().enumerate() {
            *value = map.cookie(key as u32)?;
        }
        let published =
            existing[..4].iter().copied().eq(cookies.map(Some)) && existing[4] == Some(cookies[0]);
        if !published && existing.iter().any(Option::is_some) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "listener map belongs to another or incomplete publication; active replacement is unsupported",
            ));
        }
        let mut transaction = Self {
            map,
            cookies,
            fds,
            inserted: Vec::new(),
            published,
        };
        if !published {
            for key in LISTEN_SOCKET_KEYS {
                if let Err(error) = transaction.map.put(key, fds[key as usize]) {
                    return match transaction.rollback() {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(io::Error::other(format!(
                            "stage listener key {key}: {error}; rollback: {cleanup}"
                        ))),
                    };
                }
                transaction.inserted.push(key);
            }
        }
        Ok(transaction)
    }
    pub(super) fn publish(&mut self) -> io::Result<ListenerPublicationOutcome> {
        if self.published {
            return Ok(ListenerPublicationOutcome::AlreadyPublished);
        }
        // Recheck ownership before exposing any staged slot.
        for key in LISTEN_SOCKET_KEYS {
            if self.map.cookie(key)? != Some(self.cookies[key as usize]) {
                return Err(io::Error::other("staged listener ownership changed"));
            }
        }
        if self.map.cookie(LISTEN_SOCKET_KEY_READY)?.is_some() {
            return Err(io::Error::other(
                "listener ready slot changed during staging",
            ));
        }
        self.map.put(LISTEN_SOCKET_KEY_READY, self.fds[0])?;
        self.published = true;
        Ok(ListenerPublicationOutcome::Published)
    }
    fn rollback(&mut self) -> io::Result<()> {
        let mut failure = None;
        for key in self.inserted.drain(..).rev() {
            match self.map.cookie(key) {
                Ok(Some(cookie)) if cookie == self.cookies[key as usize] => {
                    if let Err(error) = self.map.delete(key) {
                        failure = Some(error);
                    }
                }
                Err(error) => failure = Some(error),
                _ => {}
            }
        }
        failure.map_or(Ok(()), Err)
    }
}
impl<M: MapIo> Drop for Transaction<M> {
    fn drop(&mut self) {
        if !self.published {
            let _ = self.rollback();
        }
    }
}

#[derive(Debug)]
pub(super) struct ListenerPublication {
    // Keep duplicates alive until all writes and any rollback have completed.
    transaction: Transaction<KernelMap>,
    _sockets: [OwnedFd; 4],
    lock: Option<File>,
}
impl ListenerPublication {
    pub(super) fn stage(map: OwnedFd, fds: [i32; 4]) -> io::Result<Self> {
        let lock = writer_lock()?;
        let mut sockets = Vec::new();
        let mut cookies = [0; 4];
        for (index, fd) in fds.into_iter().enumerate() {
            let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
            if duplicated < 0 {
                return Err(io::Error::last_os_error());
            }
            let socket = unsafe { OwnedFd::from_raw_fd(duplicated) };
            cookies[index] = validate_socket(socket.as_raw_fd(), index < 2)?;
            sockets.push(socket);
        }
        let sockets: [OwnedFd; 4] = sockets.try_into().expect("four validated sockets");
        let transaction = Transaction::stage(
            KernelMap(map),
            sockets.each_ref().map(AsRawFd::as_raw_fd),
            cookies,
        )?;
        Ok(Self {
            transaction,
            _sockets: sockets,
            lock: Some(lock),
        })
    }
    pub(super) fn publish(&mut self) -> io::Result<ListenerPublicationOutcome> {
        let outcome = self.transaction.publish()?;
        // Never unlink the lock inode: another process may already be waiting.
        self.lock.take();
        Ok(outcome)
    }
}
fn writer_lock() -> io::Result<File> {
    std::fs::create_dir_all("/run/lock")?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/run/lock/dae-listener-map.lock")?;
    let metadata = lock.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1
    {
        return Err(io::Error::other("unsafe listener map writer lock"));
    }
    while unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    Ok(lock)
}
fn socket_option<T: Default>(fd: i32, option: i32) -> io::Result<T> {
    let mut value = T::default();
    let mut len = size_of::<T>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut T).cast(),
            &mut len,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if len as usize != size_of::<T>() {
        return Err(io::Error::other("invalid socket option length"));
    }
    Ok(value)
}
fn validate_socket(fd: i32, tcp: bool) -> io::Result<u64> {
    let kind = socket_option::<i32>(fd, libc::SO_TYPE)?;
    let domain = socket_option::<i32>(fd, libc::SO_DOMAIN)?;
    if !matches!(domain, libc::AF_INET | libc::AF_INET6)
        || kind
            != if tcp {
                libc::SOCK_STREAM
            } else {
                libc::SOCK_DGRAM
            }
        || (tcp && socket_option::<i32>(fd, libc::SO_ACCEPTCONN)? != 1)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected IP TCP listener / UDP socket",
        ));
    }
    socket_option(fd, libc::SO_COOKIE)
}

#[cfg(test)]
mod tests;
