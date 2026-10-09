use super::*;

// Startup/standalone commands reuse a small number of synchronous writers.
// Runtime startup holds this lock through registration, so a fallback writer
// cannot race the ownership handover and mistake runtime writes for replacement.
const FALLBACK_WRITER_LIMIT: usize = 4;
static FALLBACK_WRITERS: Mutex<VecDeque<(PathBuf, ProductLogWriter)>> = Mutex::new(VecDeque::new());

pub(super) fn fallback_writers()
-> io::Result<std::sync::MutexGuard<'static, VecDeque<(PathBuf, ProductLogWriter)>>> {
    FALLBACK_WRITERS
        .lock()
        .map_err(|_| io::Error::other("product log fallback writers poisoned"))
}

pub(super) fn append_without_runtime(
    config_dir: &Path,
    state: &Path,
    level: String,
    message: &str,
    fields: BTreeMap<String, String>,
    respect_runtime_log_level: bool,
) -> io::Result<()> {
    let policy = ProductLogPolicy::load(state)?;
    if respect_runtime_log_level && !log_level_enabled(&level, &policy.runtime_level) {
        return Ok(());
    }
    let mut writers = fallback_writers()?;
    if let Some(runtime) = product_log_runtime_for(config_dir) {
        return runtime.append(level, message, fields, respect_runtime_log_level);
    }
    let path = product_log_file(config_dir);
    let index = writers.iter().position(|(key, _)| *key == path);
    let mut writer = match index.and_then(|index| writers.remove(index)) {
        Some((_, writer)) => writer,
        None => ProductLogWriter::open(config_dir.to_path_buf(), policy.clone())?,
    };
    let result = writer
        .replace_policy(policy)
        .and_then(|_| {
            writer.append(ProductLogAppendRequest {
                level,
                message: message.to_owned(),
                fields,
                respect_runtime_log_level,
            })
        })
        .map(|_| ());
    if writers.len() >= FALLBACK_WRITER_LIMIT {
        writers.pop_front();
    }
    writers.push_back((path, writer));
    result
}
