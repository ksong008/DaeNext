use super::*;

#[repr(C)]
#[derive(Default)]
struct BatchAttr {
    in_batch: u64,
    out_batch: u64,
    keys: u64,
    values: u64,
    count: u32,
    map_fd: u32,
    elem_flags: u64,
    flags: u64,
}

pub(super) fn visit(
    map: &ValidatedRuntimeMapHandle,
    visit: &mut impl FnMut(&[u8], &[u8]) -> io::Result<()>,
) -> io::Result<Option<u64>> {
    // Per-CPU maps require a padded value per CPU, not value_size bytes.
    if !matches!(
        map.info.map_type,
        BPF_MAP_TYPE_HASH | BPF_MAP_TYPE_LRU_HASH | 2
    ) {
        return Ok(None);
    }
    let key_size = map.info.key_size as usize;
    let value_size = map.info.value_size as usize;
    let size = 256_usize.min(map.info.max_entries as usize);
    if size == 0 || key_size == 0 || value_size == 0 {
        return Ok(Some(0));
    }
    let mut keys = vec![0_u8; key_size * size];
    let mut values = vec![0_u8; value_size * size];
    // Hash-map batch cursors contain a u32 bucket even with a shorter map key.
    let mut cursor = vec![0_u8; key_size.max(4)];
    let mut next_cursor = vec![0_u8; key_size.max(4)];
    let mut total = 0;
    loop {
        let mut attr = BatchAttr {
            in_batch: if total == 0 {
                0
            } else {
                cursor.as_ptr() as u64
            },
            out_batch: next_cursor.as_mut_ptr() as u64,
            keys: keys.as_mut_ptr() as u64,
            values: values.as_mut_ptr() as u64,
            count: size as u32,
            map_fd: map.as_raw_fd() as u32,
            ..BatchAttr::default()
        };
        // SAFETY: map metadata fixes buffer element sizes. Cursors and mutable
        // output buffers remain alive and exclusive for the complete syscall.
        let status = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                24,
                &mut attr as *mut BatchAttr,
                size_of::<BatchAttr>(),
            )
        };
        let error = (status < 0).then(io::Error::last_os_error);
        if let Some(error) = &error {
            if total == 0
                && matches!(
                    error.raw_os_error(),
                    Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP | libc::ENOSPC)
                )
            {
                return Ok(None);
            }
            if error.raw_os_error() != Some(libc::ENOENT) {
                return Err(io::Error::from_raw_os_error(
                    error.raw_os_error().unwrap_or(libc::EIO),
                ));
            }
        }
        if attr.count as usize > size {
            return Err(io::Error::other("BPF lookup batch count exceeds buffer"));
        }
        for i in 0..attr.count as usize {
            visit(
                &keys[i * key_size..(i + 1) * key_size],
                &values[i * value_size..(i + 1) * value_size],
            )?;
        }
        total += u64::from(attr.count);
        if error.is_some() || attr.count == 0 || total >= u64::from(map.info.max_entries) {
            return Ok(Some(total));
        }
        std::mem::swap(&mut cursor, &mut next_cursor);
    }
}
