use std::{fs, io, path::Path};

const PROC_MEMINFO: &str = "/proc/meminfo";
const MEMINFO_READ_LIMIT: u64 = 64 * 1024;
pub(super) const HOST_MEMORY_CAPACITY_SOURCE: &str = "host-MemTotal";

pub(super) fn read_host_memory_bytes() -> io::Result<u64> {
    let content = read_bounded_text(Path::new(PROC_MEMINFO), MEMINFO_READ_LIMIT)?;
    parse_memtotal_bytes(&content)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "MemTotal is unavailable"))
}

pub(super) fn parse_memtotal_bytes(content: &str) -> Option<u64> {
    let line = content.lines().find(|line| line.starts_with("MemTotal:"))?;
    let mut fields = line.split_whitespace();
    if fields.next()? != "MemTotal:" {
        return None;
    }
    let kibibytes = fields.next()?.parse::<u64>().ok()?;
    if !fields.next()?.eq_ignore_ascii_case("kb") || fields.next().is_some() {
        return None;
    }
    kibibytes.checked_mul(1024)
}

pub(super) fn read_bounded_text(path: &Path, limit: u64) -> io::Result<String> {
    use std::io::Read;

    let mut content = String::new();
    fs::File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_string(&mut content)?;
    if content.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "host capacity input exceeds read limit",
        ));
    }
    Ok(content)
}
