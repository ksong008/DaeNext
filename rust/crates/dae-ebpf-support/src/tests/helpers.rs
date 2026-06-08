fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{}-{name}", std::process::id()))
}

fn assert_layout<T>(fixture: &Value, name: &str, expected_size: usize, expected_align: usize) {
    let item = fixture_struct(fixture, name);
    assert_eq!(size_of::<T>(), expected_size);
    assert_eq!(align_of::<T>(), expected_align);
    assert_eq!(item["size"].as_u64().unwrap() as usize, size_of::<T>());
    assert_eq!(item["align"].as_u64().unwrap() as usize, align_of::<T>());
}

fn assert_offset<T>(fixture: &Value, struct_name: &str, field_name: &str, offset: usize) {
    let item = fixture_struct(fixture, struct_name);
    let offsets = item["offsets"].as_array().unwrap();
    let expected = offsets
        .iter()
        .find(|entry| entry["field"].as_str().unwrap() == field_name)
        .unwrap();
    assert_eq!(expected["offset"].as_u64().unwrap() as usize, offset);
}

fn fixture_struct<'a>(fixture: &'a Value, name: &str) -> &'a Value {
    fixture["structs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"].as_str().unwrap() == name)
        .unwrap()
}

fn parse_go_version(input: &str) -> Version {
    let trimmed = input.trim_start_matches('v');
    let parts = trimmed
        .split('.')
        .map(|part| part.parse::<u16>().unwrap())
        .collect::<Vec<_>>();
    Version::new(parts[0], parts[1], parts.get(2).copied().unwrap_or(0))
}
