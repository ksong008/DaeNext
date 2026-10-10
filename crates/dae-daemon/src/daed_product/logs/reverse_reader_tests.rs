use super::super::*;
use super::ReverseFileLineReader;

#[test]
fn reverse_reader_matches_bounded_forward_reader_across_block_boundaries() {
    let path = std::env::temp_dir().join(format!(
        "daed-reverse-log-{}-{}",
        std::process::id(),
        fastrand::u64(..)
    ));
    let mut data = b"first\r\n\n".to_vec();
    data.extend(std::iter::repeat_n(b'x', 16_500));
    data.push(b'\n');
    data.extend(std::iter::repeat_n(b'y', MAX_LOG_LINE_BYTES * 2));
    data.push(b'\n');
    data.extend_from_slice(b"last-without-newline");
    fs::write(&path, &data).unwrap();
    let mut forward = io::BufReader::new(fs::File::open(&path).unwrap());
    let mut expected = Vec::new();
    let mut line = Vec::new();
    while read_product_log_line(&mut forward, &mut line).unwrap() {
        if !line.is_empty() {
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if !line.is_empty() {
                expected.push(line.clone());
            }
        }
    }
    expected.reverse();
    let mut reverse = ReverseFileLineReader::new(
        fs::File::open(&path).unwrap().take(data.len() as u64),
        MAX_LOG_LINE_BYTES * 2,
    );
    let mut observed = Vec::new();
    while reverse.read_line(&mut line).unwrap() {
        if !line.is_empty() {
            observed.push(line.clone());
        }
    }
    assert_eq!(observed, expected);
    fs::remove_file(path).unwrap();
}

#[test]
fn reverse_reader_respects_snapshot_length_when_file_is_appended() {
    let path = std::env::temp_dir().join(format!(
        "daed-reverse-snapshot-{}-{}",
        std::process::id(),
        fastrand::u64(..)
    ));
    fs::write(&path, b"first\nsecond\n").unwrap();
    let file = fs::File::open(&path).unwrap().take(13);
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"third\n")
        .unwrap();
    let mut reverse = ReverseFileLineReader::new(file, MAX_LOG_LINE_BYTES * 2);
    let mut line = Vec::new();
    let mut observed = Vec::new();
    while reverse.read_line(&mut line).unwrap() {
        if !line.is_empty() {
            observed.push(line.clone());
        }
    }
    assert_eq!(observed, vec![b"second".to_vec(), b"first".to_vec()]);
    fs::remove_file(path).unwrap();
}
