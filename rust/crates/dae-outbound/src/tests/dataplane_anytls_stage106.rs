use super::*;

#[test]
fn stage106_anytls_stream_lifecycle_frames_increment_sid_and_send_fin() {
    let first = anytls::stream_lifecycle_frames(1, "stage106-one.example:443", b"first").unwrap();
    let second = anytls::stream_lifecycle_frames(2, "stage106-two.example:443", b"second").unwrap();

    assert_eq!(anytls::decode_frame(&first.settings_frame).unwrap().sid, 1);
    assert_eq!(
        anytls::decode_frame(&first.syn_frame).unwrap().cmd,
        anytls::contract::CMD_SYN
    );
    assert_eq!(
        anytls::decode_frame(&first.psh_addr_frame).unwrap().cmd,
        anytls::contract::CMD_PSH
    );
    assert_eq!(
        anytls::decode_frame(&first.psh_payload_frame).unwrap().data,
        b"first"
    );
    let first_fin = anytls::decode_frame(&first.fin_frame).unwrap();
    assert_eq!(first_fin.cmd, anytls::contract::CMD_FIN);
    assert_eq!(first_fin.sid, 1);
    assert!(first_fin.data.is_empty());

    assert_eq!(anytls::decode_frame(&second.settings_frame).unwrap().sid, 2);
    assert_eq!(anytls::decode_frame(&second.fin_frame).unwrap().sid, 2);
}

#[test]
fn stage106_anytls_session_reuse_sequence_has_one_auth_and_two_streams() {
    let auth_handshake = anytls::link::handshake_auth_bytes("stage106-auth");
    let first = anytls::stream_lifecycle_frames(1, "stage106-one.example:443", b"first").unwrap();
    let second = anytls::stream_lifecycle_frames(2, "stage106-two.example:443", b"second").unwrap();
    let frames = [
        first.settings_frame.as_slice(),
        first.syn_frame.as_slice(),
        first.psh_addr_frame.as_slice(),
        first.psh_payload_frame.as_slice(),
        first.fin_frame.as_slice(),
        second.settings_frame.as_slice(),
        second.syn_frame.as_slice(),
        second.psh_addr_frame.as_slice(),
        second.psh_payload_frame.as_slice(),
        second.fin_frame.as_slice(),
    ];

    assert_eq!(auth_handshake.len(), 34);
    assert_eq!(&auth_handshake[32..], &[0, 0]);
    assert_eq!(frames.len(), 10);
    assert_eq!(anytls::decode_frame(frames[0]).unwrap().sid, 1);
    assert_eq!(
        anytls::decode_frame(frames[4]).unwrap().cmd,
        anytls::contract::CMD_FIN
    );
    assert_eq!(anytls::decode_frame(frames[5]).unwrap().sid, 2);
    assert_eq!(
        anytls::decode_frame(frames[9]).unwrap().cmd,
        anytls::contract::CMD_FIN
    );
}

#[test]
fn stage106_anytls_reuse_underlay_preserves_tcp_mark_mptcp_boundary() {
    let underlay = anytls::link::underlay_contract("tcp", 1234, true);

    assert_eq!(underlay.underlay_network, "tcp");
    assert_eq!(underlay.underlay_mark, 1234);
    assert!(underlay.underlay_mptcp);
    assert!(anytls::contract::IDLE_SESSION_REUSE_MAP);
    assert!(anytls::contract::SESSION_COUNTER);
}
