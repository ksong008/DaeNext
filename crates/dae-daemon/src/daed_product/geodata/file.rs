use super::types::{GEODATA_HTTP_BODY_LIMIT, GeodataKind};
use super::*;
use std::os::fd::AsRawFd;

pub(super) fn summarize_geodata_file(
    kind: GeodataKind,
    path: &Path,
) -> io::Result<dae_geodata::GeoDataSummary> {
    validate_geodata_file_size(path)?;
    match MappedGeodataFile::open(path) {
        Ok(mapped) => kind.summarize(mapped.as_slice()).map_err(|err| {
            io::Error::new(io::ErrorKind::InvalidData, format!("parse geodata: {err}"))
        }),
        Err(_) => {
            let data = fs::read(path)?;
            kind.summarize(&data).map_err(|err| {
                io::Error::new(io::ErrorKind::InvalidData, format!("parse geodata: {err}"))
            })
        }
    }
}

pub(super) fn sha256_file(path: &Path) -> io::Result<String> {
    validate_geodata_file_size(path)?;
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        sha2::Digest::update(&mut hasher, &buffer[..read]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn validate_geodata_file_size(path: &Path) -> io::Result<()> {
    let len = fs::metadata(path)?.len();
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("geodata asset {} is empty", path.display()),
        ));
    }
    if len > GEODATA_HTTP_BODY_LIMIT as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("geodata asset exceeds {GEODATA_HTTP_BODY_LIMIT} bytes"),
        ));
    }
    Ok(())
}

pub(super) fn advise_file_dontneed(path: &Path) -> io::Result<()> {
    let file = fs::File::open(path)?;
    #[cfg(target_os = "linux")]
    {
        let rc = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
    }
    Ok(())
}

struct MappedGeodataFile {
    ptr: std::ptr::NonNull<u8>,
    len: usize,
}

impl MappedGeodataFile {
    fn open(path: &Path) -> io::Result<Self> {
        let file = fs::File::open(path)?;
        let len_u64 = file.metadata()?.len();
        let len = usize::try_from(len_u64).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("geodata asset {} is too large to map", path.display()),
            )
        })?;
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("geodata asset {} is empty", path.display()),
            ));
        }
        if len_u64 > GEODATA_HTTP_BODY_LIMIT as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("geodata asset exceeds {GEODATA_HTTP_BODY_LIMIT} bytes"),
            ));
        }
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = std::ptr::NonNull::new(mapped.cast::<u8>())
            .ok_or_else(|| io::Error::other("mmap returned a null pointer"))?;
        Ok(Self { ptr, len })
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for MappedGeodataFile {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}
