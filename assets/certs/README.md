# Vendored Proton local-agent trust anchors

`proton-root-ca.pem` and `proton-intermediate-ca.pem` are the two CA certificates
[`src/agent.rs`](../../src/agent.rs) pins when verifying Proton's "local agent" TLS
endpoint (`10.2.0.1:65432`, reachable only through the WireGuard tunnel — see that module's doc
comment for the full protocol and why the handshake matters).

## What they are

| File | Subject | notBefore | notAfter |
|---|---|---|---|
| `proton-root-ca.pem` | `ProtonVPN Root CA` (self-signed) | 2019-10-17 | 2039-10-12 |
| `proton-intermediate-ca.pem` | `ProtonVPN Intermediate CA 1`, issued by the above | 2022-01-14 | 2032-01-12 |

## Where they came from

Extracted from the embedded `rustls::RootCertStore` compiled into Proton's own official Linux
client, specifically `local_agent.abi3.so` (part of the `proton-vpn` Python/Rust package,
installed system-wide at `/usr/lib/python3/dist-packages/proton/vpn/local_agent.abi3.so` on the
machine this was extracted on). These are the exact same trust anchors Proton's own client pins
for this endpoint — not independently generated or sourced from a third party.

## Verify independently

A reviewer (or anyone regenerating these files from their own copy of Proton's client) can check
the fingerprint matches without trusting this repo's copy on faith:

```
$ openssl x509 -in assets/certs/proton-root-ca.pem -noout -fingerprint -sha256
sha256 Fingerprint=47:47:92:C8:6C:A0:E7:2F:6C:04:EA:87:CB:FD:49:9D:A3:8C:58:F4:46:6E:7B:25:8C:DF:67:DA:34:65:6E:31

$ openssl x509 -in assets/certs/proton-intermediate-ca.pem -noout -fingerprint -sha256
sha256 Fingerprint=A3:70:5C:D0:79:0C:8A:66:5A:E7:E8:E4:26:99:74:C2:EE:31:8A:ED:03:CF:0C:7E:86:0C:22:28:CF:17:E4:AB
```

`src/agent.rs`'s `embedded_ca_pems_have_the_expected_sha256_fingerprint` test asserts these
same fingerprints against the embedded PEM bytes at build/test time, so an accidental or
malicious swap of either file fails `cargo test` loudly instead of silently changing who this
binary trusts.

## Why pin at all, instead of using system roots

The local-agent endpoint's server certificate chains to `ProtonVPN Intermediate CA 1`, which is
**not** in any public/system trust store — it is Proton-internal infrastructure, never meant to
be reachable or verifiable via the public web PKI. System root verification would simply fail
against it; pinning these two certificates is the only way to verify this endpoint at all (and is
what Proton's own client does).

## If Proton rotates these CAs

The local-agent handshake will start failing TLS verification. That is a soft failure by design:
`agent::unlock` returns `Err`, and `manager.rs` falls back to
`Tunnel::wait_until_data_path_ready`'s polling probe — gratis degrades to its previous (slower)
behaviour rather than breaking connections. Fixing it for real means replacing these two files
with the new CA chain (and updating the fingerprints above and in `agent.rs`'s test).
