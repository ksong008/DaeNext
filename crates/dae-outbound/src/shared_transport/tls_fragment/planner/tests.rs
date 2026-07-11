use super::*;

fn handshake_record(payload_len: usize) -> Vec<u8> {
    let mut record = vec![TLS_HANDSHAKE_CONTENT_TYPE, 0x03, 0x03];
    record.extend_from_slice(&(payload_len as u16).to_be_bytes());
    record.extend((0..payload_len).map(|index| (index % 251) as u8));
    record
}

#[test]
fn seeded_planner_samples_length_and_interval_ranges() {
    let options = TlsFragmentOptions::from_ranges("4-9", "3-7").unwrap();
    let mut planner = TlsFragmentPlanner::with_seed(options, 0x5eed);
    let plan = planner.push(&handshake_record(256)).unwrap();

    let mut previous_end = 0;
    let mut payload_lens = Vec::new();
    let mut delays = Vec::new();
    for segment in plan.segments() {
        payload_lens.push(segment.end - previous_end - TLS_RECORD_HEADER_LEN);
        delays.push(segment.delay_before_ms);
        previous_end = segment.end;
    }

    assert!(
        payload_lens[..payload_lens.len() - 1]
            .iter()
            .all(|len| (4..=9).contains(len))
    );
    assert!(payload_lens.iter().any(|len| *len > 4));
    assert_eq!(delays[0], 0);
    assert!(delays[1..].iter().all(|delay| (3..=7).contains(delay)));
    assert!(delays[1..].iter().any(|delay| *delay > 3));
}

#[test]
fn planner_assembles_split_records_and_preserves_trailing_application_data() {
    let options = TlsFragmentOptions::from_ranges("8-8", "0-0").unwrap();
    let mut planner = TlsFragmentPlanner::with_seed(options, 1);
    let first = handshake_record(20);
    let second = handshake_record(9);
    let application_data = [23, 0x03, 0x03, 0, 3, 1, 2, 3];
    let split_at = TLS_RECORD_HEADER_LEN + 2;

    let plan = planner.push(&first[..split_at]).unwrap();
    assert!(plan.is_empty());
    assert_eq!(planner.buffered_len(), split_at);

    let mut trailing = first[split_at..].to_vec();
    trailing.extend_from_slice(&second);
    trailing.extend_from_slice(&application_data);
    let plan = planner.push(&trailing).unwrap();

    assert_eq!(plan.reports().len(), 3);
    assert_eq!(plan.reports()[0].fragment_payload_lens, vec![8, 8, 4]);
    assert_eq!(plan.reports()[1].fragment_payload_lens, vec![8, 1]);
    assert_eq!(
        &plan.bytes()[plan.bytes().len() - application_data.len()..],
        application_data
    );
    assert_eq!(planner.buffered_len(), 0);

    let later = b"later encrypted TLS bytes";
    let plan = planner.push(later).unwrap();
    assert_eq!(plan.bytes(), later);
    assert_eq!(plan.segments().len(), 1);
}

#[test]
fn planner_flushes_an_incomplete_record_once_and_switches_to_passthrough() {
    let options = TlsFragmentOptions::from_ranges("8-8", "0-0").unwrap();
    let mut planner = TlsFragmentPlanner::with_seed(options, 1);
    let record = handshake_record(20);

    assert!(planner.push(&record[..8]).unwrap().is_empty());
    let flushed = planner.finish_incomplete();
    assert_eq!(flushed.bytes(), &record[..8]);
    assert_eq!(
        flushed.reports()[0].passthrough_reason,
        Some("incomplete-handshake-record")
    );
    assert!(planner.finish_incomplete().is_empty());

    let remainder = planner.push(&record[8..]).unwrap();
    assert_eq!(remainder.bytes(), &record[8..]);
}

#[test]
fn planner_buffers_at_most_one_maximum_length_tls_record() {
    let options = TlsFragmentOptions::from_ranges("65535-65535", "0-0").unwrap();
    let mut planner = TlsFragmentPlanner::with_seed(options, 1);
    let record = handshake_record(u16::MAX as usize);

    assert!(
        planner
            .push(&record[..record.len() - 1])
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        planner.buffered_len(),
        TLS_FRAGMENT_MAX_BUFFERED_RECORD_LEN - 1
    );
    let plan = planner.push(&record[record.len() - 1..]).unwrap();
    assert_eq!(planner.buffered_len(), 0);
    assert_eq!(plan.segments().len(), 1);
    assert_eq!(plan.bytes(), record);
}
