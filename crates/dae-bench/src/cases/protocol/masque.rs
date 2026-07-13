use bytes::Bytes;
use dae_outbound::shared_transport::{
    MasqueCapsule, MasqueCapsuleDecoder, MasqueCapsuleLimits, MasqueQuarterStreamId,
    MasqueUriTemplate, decode_http_datagram, encode_connect_udp_capsule, encode_http_datagram,
};

use super::*;

const MASQUE_BENCH_LINK: &str = "masque://identity:credential@proxy.example:8443?transport=h3&auth=basic&template=%2F.well-known%2Fmasque%2Fudp%2F%7Btarget_host%7D%2F%7Btarget_port%7D%2F&sni=edge.example#benchmark";
const MASQUE_BENCH_TEMPLATE: &str = "/.well-known/masque/udp/{target_host}/{target_port}/";
const MASQUE_BENCH_PAYLOAD_BYTES: usize = 1_200;
const MASQUE_BENCH_FRAME_BYTES: usize = MASQUE_BENCH_PAYLOAD_BYTES + 32;

pub(super) fn bench_masque_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let link = MasqueLink::parse(black_box(MASQUE_BENCH_LINK)).expect("MASQUE bench link");
            black_box(link.server.len() as u64 ^ u64::from(link.port))
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_masque_uri_template_expand(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let template = MasqueUriTemplate::parse(MASQUE_BENCH_TEMPLATE).expect("MASQUE bench template");
    let target = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53);
    Ok(measure(
        || {
            let expanded = template
                .expand(black_box(target))
                .expect("expand MASQUE target");
            black_box(expanded.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_masque_h2_capsule_roundtrip(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let limits = masque_bench_limits();
    let payload = [0xa5_u8; MASQUE_BENCH_PAYLOAD_BYTES];
    Ok(measure(
        || {
            let encoded = encode_connect_udp_capsule(black_box(&payload), limits)
                .expect("encode MASQUE Capsule");
            let mut decoder = MasqueCapsuleDecoder::new(limits);
            let decoded = decoder.push(&encoded).expect("decode MASQUE Capsule");
            let MasqueCapsule::Datagram(payload) = &decoded[0] else {
                panic!("unexpected MASQUE Capsule shape")
            };
            black_box(payload.len() as u64 ^ encoded.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_masque_h3_datagram_roundtrip(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let quarter_stream_id = MasqueQuarterStreamId::from_http3_stream_id(12)
        .expect("MASQUE benchmark request stream ID");
    let payload = [0x5a_u8; MASQUE_BENCH_PAYLOAD_BYTES];
    Ok(measure(
        || {
            let encoded = encode_http_datagram(
                quarter_stream_id,
                black_box(&payload),
                MASQUE_BENCH_PAYLOAD_BYTES,
            )
            .expect("encode MASQUE HTTP Datagram");
            let encoded_len = encoded.len();
            let decoded = decode_http_datagram(Bytes::from(encoded), MASQUE_BENCH_PAYLOAD_BYTES)
                .expect("decode MASQUE HTTP Datagram");
            black_box(decoded.payload.len() as u64 ^ encoded_len as u64)
        },
        iters,
        warmup,
    ))
}

fn masque_bench_limits() -> MasqueCapsuleLimits {
    MasqueCapsuleLimits::new(
        MASQUE_BENCH_FRAME_BYTES,
        MASQUE_BENCH_FRAME_BYTES,
        MASQUE_BENCH_PAYLOAD_BYTES,
    )
    .expect("MASQUE benchmark limits")
}
