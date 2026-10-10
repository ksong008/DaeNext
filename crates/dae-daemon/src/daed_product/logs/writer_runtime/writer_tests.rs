use super::*;

#[cfg(test)]
thread_local! {
    pub(crate) static LOG_APPEND_PARTIAL_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(crate) static LOG_VISIBILITY_PARTIAL_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(crate) static LOG_APPEND_TRUNCATE_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(crate) static LOG_ROTATE_AFTER_RENAME_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(crate) static LOG_ROTATE_AFTER_CREATE_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(super) fn write_product_log_line(file: &mut fs::File, line: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    if LOG_APPEND_PARTIAL_FAILURE.with(|fail| fail.replace(false)) {
        file.write_all(&line[..line.len() / 2])?;
        return Err(io::Error::from_raw_os_error(libc::ENOSPC));
    }
    file.write_all(line)
}

pub(super) fn write_log_visibility_record(file: &mut fs::File, record: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    if LOG_VISIBILITY_PARTIAL_FAILURE.with(|fail| fail.replace(false)) {
        file.write_all(&record[..record.len() / 2])?;
        return Err(io::Error::from_raw_os_error(libc::ENOSPC));
    }
    file.write_all(record)
}
