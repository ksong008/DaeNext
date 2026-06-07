use std::time::Instant;

use dae_outbound::shared_transport::{
    GrpcLifecycleOptions, MeekRoundTripOptions, MuxFrameOptions, QuicH3HarnessOptions,
    RealityMutationOptions, XHttpLifecycleOptions, grpc_hunk_frame, meek_http_request,
    mux_data_frame, quic_h3_datagram_packet, reality_session_id, xhttp_packet_request,
};

fn main() {
    let iters = std::env::var("DAE_SHARED_TRANSPORT_DEEP_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(200_000);
    let payload = b"shared-transport-deep-ping";
    let reality = RealityMutationOptions::new(
        "reality.example",
        "chrome",
        "0123456789abcdef",
        "-__--u_uq80BI0VniavN7_v__vrv7qvNASNFZ4mrze8",
        "/?p=10-20&c=30&t=40&i=50&r=60-70",
        1_715_846_400,
        "00112233445566778899aabbccddeeff",
    )
    .unwrap();
    let xhttp = XHttpLifecycleOptions::new(
        "xhttp.example",
        "/xhttp?ed=2048",
        "packet-up",
        "tls",
        "h3",
        "session-shared-transport",
        7,
    )
    .unwrap();
    let grpc = GrpcLifecycleOptions::new(
        "grpc.example:443",
        "GunService",
        "grpc-sni.example",
        "dialer-shared-transport",
        true,
        1234,
        true,
    );
    let meek = MeekRoundTripOptions::from_https_url(
        "https://front.example/meek",
        vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ],
    )
    .unwrap();
    let mux = MuxFrameOptions::new([0, 0], "127.0.0.1", 0, "tcp");
    let quic = QuicH3HarnessOptions::new(7, 11, "h3", 1234, false);

    bench("shared_transport_reality_session_id", iters, || {
        reality_session_id(&reality).len()
    });
    bench("shared_transport_xhttp_packet_request", iters, || {
        xhttp_packet_request(&xhttp, payload).len()
    });
    bench("shared_transport_grpc_hunk_frame", iters, || {
        grpc_hunk_frame(payload).unwrap().len() ^ grpc.cache_key().len()
    });
    bench("shared_transport_meek_http_request", iters, || {
        meek_http_request(&meek, payload).len()
    });
    bench("shared_transport_mux_data_frame", iters, || {
        mux_data_frame(mux.id, payload).unwrap().len()
    });
    bench("shared_transport_quic_h3_datagram_packet", iters, || {
        quic_h3_datagram_packet(&quic, payload).unwrap().len()
    });
}

fn bench(name: &str, iters: usize, mut f: impl FnMut() -> usize) {
    let start = Instant::now();
    let mut checksum = 0usize;
    for _ in 0..iters {
        checksum ^= f();
    }
    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() as f64 / iters as f64;
    println!("{name}\t{ns_per_op:.1} ns/op\t{iters} iters\tchecksum {checksum}");
}
