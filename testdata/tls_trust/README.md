# TLS trust fixtures

`mtc-leaf.pem` derives from the BoringSSL signatureless MTC test certificate
in `pki/testdata/verify_unittest/mtc-leaf.pem`. It uses the same issuer,
serial 9, validity, names, proof witnesses and subtree range [8, 13).
Its public key was replaced with the key in `mtc-test-key.pem` so that the
fixture can complete TCP and QUIC TLS handshakes. This private key is public
test material.

`mtc.json` contains the subtree hash recomputed from the modified leaf and
the original proof witnesses. The test installs this checkpoint explicitly.
The certificate is valid for `a.example` and `*.blah.a.example`.

The upstream generator and source configuration are retained under the
vendored BoringSSL test data. The production verifier follows upstream
`52b1463b45712c747a810be819a9cd41ab33fc46` and the unused-bit correction
`c3ffc3300a9450cf8e396c7880be7c6cadc16a4a`.
