# TLS trust metadata

`fp=chrome_152` can use a local TLS trust manifest for TCP and XHTTP/H3. Set
`DAE_TLS_TRUST_METADATA_FILE` to its absolute path in the daemon environment.
The daemon uses the file together with its system CA bundle, including any
override set through `SSL_CERT_FILE`. The manifest is optional.

Manage the manifest with the same ownership and write permissions as the
system CA bundle. Its MTC checkpoints and revocation data are trust inputs.
Load them from an authenticated source and replace the manifest atomically
before reloading the daemon. Reload includes the manifest hash in the TLS
and shared carrier configuration identity. Established connections retain
their original authentication. Invalid or unreadable manifests fail trust
loading. An expired MTC checkpoint stops MTC advertisement and verification.

## X.509 trust anchor groups

Add a `groups` array to the manifest. Each group has an `id` and a
`members` array. A member specifies its individual `id` and the hex
`sha256` fingerprint of the CA certificate's DER bytes. Use the IDs and
membership published by the PKI. IDs are canonical dotted relative OIDs.

```json
{
  "groups": [
    {
      "id": "32473.2.1",
      "members": [
        {
          "id": "32473.1",
          "sha256": "<64 hex digits for the first CA certificate>"
        },
        {
          "id": "32473.3",
          "sha256": "<64 hex digits for the second CA certificate>"
        }
      ]
    }
  ]
}
```

If all members are present in the current CA bundle, the initial handshake
advertises the group ID in place of those members. If the group is incomplete,
the client can still advertise the individual IDs of trusted members.
Certificate-chain and peer-name verification apply regardless of the ID sent.
When the eligible peer offers a locally trusted individual ID after selection
fails, the existing recovery handshake sends that ID alone.

## Merkle Tree Certificates

The optional `mtc` object carries local trust data for signatureless proofs in
the `draft-davidben-tls-merkle-tree-certs-08` format. For each trusted log it
specifies the relative OID `log_id`, PKI-assigned `advertised_ids`, trusted
`subtrees` with inclusive `start`, exclusive `end` and hex SHA-256
`sha256` root, and `revoked_serials`. Serial numbers and subtree indexes are
unsigned 64-bit integers. `valid_from_unix` is inclusive and `expires_unix`
is exclusive. They use Unix seconds. The manifest supports up to 32 groups
and 32 logs and at most 256 KiB of JSON.

[The loopback manifest](../testdata/tls_trust/mtc.json) illustrates the format
using test data. MTC uses TLS 1.3, checks the peer name and proof against the
configured checkpoint, and requires a full handshake on TCP and QUIC when
MTC is installed. REALITY, explicit ECH, disabled verification and QUIC pin
policies follow their existing certificate policies. The supported MTC format
is limited to direct leaf proofs against a configured subtree. PLANTS
landmark and cosignature formats and automatic metadata distribution are
outside this implementation.
