# Gateinto

Gateinto is a local HTTP/1.1 `CONNECT` proxy for Windows. It listens on
`127.0.0.1:18736`, opens a TLS 1.3 connection to a remote HTTPS forward proxy,
and issues a second `CONNECT` there. Client authentication will use a
non-exportable ECDSA P-256 device key held by Windows CNG (TPM preferred,
software key storage as fallback). Key exchange prefers the hybrid
post-quantum group `X25519MLKEM768` and falls back to `X25519`.

## Status

Early proof of concept. Not production ready. The proxy itself is not
implemented yet; the repository currently contains the project skeleton and a
compatibility spike for rustls, aws-lc-rs and rustls-cng. See
[docs/compatibility.md](docs/compatibility.md).

## Scope

- Target platform: Windows 10/11 x64.
- Local listener: HTTP/1.1 `CONNECT` only.
- Upstream: TLS 1.3 with mutual authentication to an HTTPS forward proxy.

## Security

The loopback listener has no authentication of its own. Any process running on
the same machine can connect to it and use the device identity to reach the
remote proxy.

## Build and test

```sh
cargo build
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features --locked
```

Windows CNG tests only run on Windows. They create and delete temporary keys in
the current user's Microsoft Software Key Storage Provider.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
