use serde_json::Value;

use crate::*;

#[test]
fn ringbuf_size_parser_matches_golden_fixture() {
    let fixture = load("trace/ringbuf/size.json");
    assert_eq!(
        DEFAULT_RINGBUF_SIZE,
        fixture["default"]["text"].as_str().unwrap()
    );
    assert_eq!(
        default_ringbuf_size_bytes(),
        fixture["default"]["bytes"].as_u64().unwrap()
    );
    assert_eq!(
        MIN_RINGBUF_SIZE_BYTES,
        fixture["min_bytes"].as_u64().unwrap()
    );
    assert_eq!(
        RINGBUF_SIZE_ALIGNMENT,
        fixture["alignment_bytes"].as_u64().unwrap()
    );

    for case in fixture["cases"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let got = parse_ringbuf_size_bytes(input);
        if case["ok"].as_bool().unwrap() {
            assert_eq!(got.unwrap(), case["bytes"].as_u64().unwrap());
        } else {
            let err = got.unwrap_err().to_string();
            assert!(
                err.contains(case["error_contains"].as_str().unwrap()),
                "input={input:?} err={err:?}"
            );
        }
    }
}

#[test]
fn skb_tracker_bounds_match_golden_fixture() {
    let fixture = load("trace/tracker/bounded.json");
    let caps = &fixture["caps"];
    assert_eq!(
        MAX_TRACKED_SKBS,
        caps["max_tracked_skbs"].as_u64().unwrap() as usize
    );
    assert_eq!(
        MAX_EVENTS_PER_SKB,
        caps["max_events_per_skb"].as_u64().unwrap() as usize
    );
    assert_eq!(
        MAX_SYMBOLS_PER_SKB,
        caps["max_symbols_per_skb"].as_u64().unwrap() as usize
    );

    let mut tracker = SkbTraceTracker::new();
    let per_skb = &fixture["per_skb_cap"];
    for i in 0..per_skb["input_events"].as_u64().unwrap() {
        tracker.add(TraceEventRecord::with_payload(1, i as u16), "sym");
    }
    let events = tracker.events(1);
    let symbols = tracker.sym_names(1);
    assert_eq!(
        events.len(),
        per_skb["retained_events"].as_u64().unwrap() as usize
    );
    assert_eq!(
        symbols.len(),
        per_skb["retained_symbols"].as_u64().unwrap() as usize
    );
    assert_eq!(
        events.first().unwrap().payload_len,
        per_skb["oldest_retained_payload"].as_u64().unwrap() as u16
    );
    assert_eq!(
        events.last().unwrap().payload_len,
        per_skb["newest_retained_payload"].as_u64().unwrap() as u16
    );

    let mut eviction = SkbTraceTracker::new();
    let tracked = &fixture["tracked_skb_eviction"];
    for skb in 0..tracked["input_skbs"].as_u64().unwrap() {
        eviction.add(TraceEventRecord::for_skb(skb), "sym");
    }
    assert_eq!(
        eviction.tracked_count(),
        tracked["retained_skbs"].as_u64().unwrap() as usize
    );
    assert_eq!(
        eviction.contains_skb(0),
        tracked["oldest_present"].as_bool().unwrap()
    );
    assert_eq!(
        eviction.contains_skb(MAX_TRACKED_SKBS as u64),
        tracked["newest_present"].as_bool().unwrap()
    );
}

#[test]
fn trace_command_surface_matches_golden_fixture() {
    let fixture = load("trace/cli/surface.json");
    let surface = default_trace_command_surface();

    assert_eq!(
        surface.feature_gated,
        fixture["feature_gated"].as_bool().unwrap()
    );
    assert_eq!(surface.build_tag, fixture["build_tag"].as_str().unwrap());
    assert_eq!(surface.use_name, fixture["use"].as_str().unwrap());
    assert_eq!(surface.short, fixture["short"].as_str().unwrap());
    assert_eq!(
        surface.defaults.ipv4_when_unspecified,
        fixture["defaults"]["ipv4_when_unspecified"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        surface.defaults.l4_proto,
        fixture["defaults"]["l4_proto"].as_str().unwrap()
    );
    assert_eq!(
        surface.defaults.port,
        fixture["defaults"]["port"].as_u64().unwrap() as u16
    );
    assert_eq!(
        surface.defaults.drop_only,
        fixture["defaults"]["drop_only"].as_bool().unwrap()
    );
    assert_eq!(
        surface.defaults.output,
        fixture["defaults"]["output"].as_str().unwrap()
    );
    assert_eq!(
        surface.defaults.ringbuf_size,
        fixture["defaults"]["ringbuf_size"].as_str().unwrap()
    );

    let flags = fixture["flags"].as_array().unwrap();
    assert_eq!(surface.flags.len(), flags.len());
    for (got, want) in surface.flags.iter().zip(flags) {
        assert_eq!(got.name, want["name"].as_str().unwrap());
        assert_eq!(got.shorthand, want["shorthand"].as_str().unwrap());
        assert_default(got, want);
        if let Some(values) = want.get("values").and_then(Value::as_array) {
            assert_eq!(
                got.values,
                values
                    .iter()
                    .map(|value| value.as_str().unwrap())
                    .collect::<Vec<_>>()
            );
        }
    }

    assert_eq!(
        surface.output_fields,
        fixture["output_fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        surface.target_discovery.uses_kernel_btf,
        fixture["target_discovery"]["uses_kernel_btf"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        surface.target_discovery.max_skb_arg_position,
        fixture["target_discovery"]["max_skb_arg_position"]
            .as_u64()
            .unwrap() as u8
    );
    assert_eq!(
        surface.target_discovery.requires_attached_target,
        fixture["target_discovery"]["requires_attached_target"]
            .as_bool()
            .unwrap()
    );
}

fn assert_default(got: &TraceFlag, want: &Value) {
    match (&got.default, &want["default"]) {
        (cli::TraceFlagDefault::Bool(got), Value::Bool(want)) => assert_eq!(got, want),
        (cli::TraceFlagDefault::Number(got), Value::Number(want)) => {
            assert_eq!(*got, want.as_u64().unwrap() as u16)
        }
        (cli::TraceFlagDefault::Text(got), Value::String(want)) => assert_eq!(got, want),
        other => panic!("unexpected default pair: {other:?}"),
    }
}

fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}
