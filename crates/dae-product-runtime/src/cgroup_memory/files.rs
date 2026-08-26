use super::*;

const CGROUP_FILE_READ_LIMIT: usize = 64 * 1024;
const CGROUP_UNLIMITED_VALUE: &str = "max";

pub(super) fn read_bounded_cgroup_file(path: &Path) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let mut limited = file.take(CGROUP_FILE_READ_LIMIT as u64 + 1);
    let mut content = String::new();
    limited.read_to_string(&mut content)?;
    if content.len() > CGROUP_FILE_READ_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cgroup file exceeds read limit",
        ));
    }
    Ok(content)
}

pub(super) fn read_cgroup_required_bytes(path: &Path, file_name: &str) -> io::Result<u64> {
    let value = read_bounded_cgroup_file(&path.join(file_name))?;
    value
        .trim()
        .parse::<u64>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub(super) fn read_cgroup_optional_limit(path: &Path, file_name: &str) -> io::Result<Option<u64>> {
    let value = read_bounded_cgroup_file(&path.join(file_name))?;
    parse_cgroup_optional_limit(value.trim())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid cgroup memory limit"))
}

pub(super) fn parse_cgroup_optional_limit(value: &str) -> Option<Option<u64>> {
    if value == CGROUP_UNLIMITED_VALUE {
        Some(None)
    } else {
        value.parse::<u64>().ok().map(Some)
    }
}

pub(super) fn read_cgroup_key_values(
    path: &Path,
    file_name: &str,
) -> io::Result<BTreeMap<String, u64>> {
    let content = read_bounded_cgroup_file(&path.join(file_name))?;
    Ok(parse_cgroup_key_values(&content))
}

pub(super) fn parse_cgroup_key_values(content: &str) -> BTreeMap<String, u64> {
    content
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let key = fields.next()?;
            let value = fields.next()?.parse::<u64>().ok()?;
            Some((key.to_owned(), value))
        })
        .collect()
}

pub(super) fn cgroup_key_values_json(values: &BTreeMap<String, u64>) -> Value {
    let mut object = Map::new();
    for (key, value) in values {
        object.insert(key.clone(), json!(value));
    }
    Value::Object(object)
}
