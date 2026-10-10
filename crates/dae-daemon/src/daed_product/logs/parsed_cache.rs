use super::*;

#[derive(Default)]
pub(super) struct ParsedLogCache {
    entries: VecDeque<(ProductLogContentVersion, Arc<[ProductLogEntry]>)>,
}

pub(super) fn sealed_entries(
    store: &ProductLogStore,
    input: &mut Option<std::io::Take<fs::File>>,
    version: Option<ProductLogContentVersion>,
) -> io::Result<Option<Arc<[ProductLogEntry]>>> {
    let Some(version) = version else {
        return Ok(None);
    };
    // Reuse the version already checked by open + fstat.
    if input.as_ref().expect("opened snapshot file").limit() > 256 * 1024 {
        return Ok(None);
    }
    {
        let mut cache = log_lock(&store.parsed_cache)?;
        if let Some(index) = cache.entries.iter().position(|(key, _)| *key == version) {
            let entry = cache.entries.remove(index).expect("cache index");
            let result = Arc::clone(&entry.1);
            cache.entries.push_back(entry);
            return Ok(Some(result));
        }
    }
    let mut reader = super::reverse_reader::ReverseFileLineReader::new(
        input.take().expect("opened file"),
        MAX_LOG_LINE_BYTES * 2,
    );
    let mut line = Vec::new();
    let mut entries = Vec::new();
    let mut retained = 0;
    while reader.read_line(&mut line)? {
        if let Some(entry) = std::str::from_utf8(&line)
            .ok()
            .and_then(parse_log_entry_line)
        {
            retained += std::mem::size_of::<ProductLogEntry>()
                + entry.ts.capacity()
                + entry.level.capacity()
                + entry.message.capacity()
                + entry
                    .fields
                    .iter()
                    .map(|(k, v)| k.capacity() + v.capacity() + 96)
                    .sum::<usize>();
            entries.push(entry);
        }
    }
    if ProductLogContentVersion::from_metadata(&reader.metadata()?) != version {
        return Err(super::store::snapshot_changed());
    }
    let entries: Arc<[ProductLogEntry]> = entries.into();
    if retained > 512 * 1024 || entries.len() > 512 {
        return Ok(Some(entries));
    }
    let mut cache = log_lock(&store.parsed_cache)?;
    if cache.entries.len() == 8 {
        cache.entries.pop_front();
    }
    cache.entries.push_back((version, Arc::clone(&entries)));
    Ok(Some(entries))
}
