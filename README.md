# Gateinto

Gateinto is a local HTTP/1.1 `CONNECT` proxy for Windows. It listens on
`127.0.0.1:18736`, opens a TLS 1.3 connection to a remote HTTPS forward proxy,
and issues a second `CONNECT` there. Client authentication will use a
non-exportable ECDSA P-256 device key held by Windows CNG (TPM preferred,
software key storage as fallback). Key exchange prefers the hybrid
post-quantum group `X25519MLKEM768` and falls back to `X25519`.

## Status

Early proof of concept. Not production ready. The double `CONNECT` data path
works without client authentication. The device key can be created and
inspected with `gateinto key`, but it is not wired into the proxy yet. See
[docs/compatibility.md](docs/compatibility.md).

Windows 7 is experimental and unsupported; see [docs/windows7-feasibility.md](docs/windows7-feasibility.md).

## Scope

- Target platform: Windows 10/11 x64.
- Local listener: HTTP/1.1 `CONNECT` only.
- Upstream: TLS 1.3 with mutual authentication to an HTTPS forward proxy.

## Usage

```sh
gateinto proxy --upstream-host proxy.example.com --upstream-port 443
```

The upstream endpoint has no default and must be given. Clients then use
`http://127.0.0.1:18736` as their HTTP proxy, for example
`curl --proxy http://127.0.0.1:18736 https://example.com/`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--listen` | `127.0.0.1:18736` | Local listen address. Must be loopback. |
| `--unsafe-allow-non-loopback-listen` | off | Allow a non-loopback listen address. This exposes the proxy, and the upstream identity behind it, to the network. |
| `--upstream-host` | required | Upstream HTTPS proxy host name or IP address. |
| `--upstream-port` | required | Upstream HTTPS proxy port. |
| `--upstream-server-name` | upstream host | Name verified against the upstream certificate. |
| `--ca-file` | Mozilla roots | PEM bundle of CAs trusted for the upstream. Replaces the default roots. |
| `--max-tunnels` | 64 | Concurrent connections; further connections get `503`. |
| `--max-header-bytes` | 16384 | Limit for the request and the upstream response header block. |
| `--connect-timeout-secs` | 10 | Limit for reading the request, and a separate limit for connecting, the TLS handshake and the upstream `CONNECT` reply together. |
| `--idle-timeout-secs` | 300 | Close a tunnel after this long without traffic in either direction. |

Logging goes to stderr and is filtered with `RUST_LOG` (default `info`). Tunnel
payload is never logged; target `host:port` is logged only at `debug`.

When more than `--max-tunnels` connections are open, further connections get a
`503`. At most 64 such rejections are handled at a time; beyond that, new
connections are closed without a response.

Local responses:

| Situation | Status |
| --- | --- |
| Upstream `2xx` | `200 Connection Established`, then the tunnel |
| Upstream `403` | `403` |
| Upstream `407` or any other status | `502`; upstream headers and body are not forwarded |
| Upstream connect, TLS or certificate failure, malformed reply | `502` |
| Upstream connect, handshake or reply timeout | `504` |
| Method other than `CONNECT` | `405` |
| Malformed request | `400` |
| Request header block over the limit | `431` |
| Request not complete within the connect timeout | `408` |
| Too many connections | `503` |

The request parser accepts only `CONNECT host:port HTTP/1.1` with exactly one
`Host` header, an LDH host name, IPv4 or bracketed IPv6 literal, and a port from
1 to 65535. It rejects bare LF, CR inside lines, NUL, obs-fold, control
characters in field values, `Transfer-Encoding`, and a non-zero
`Content-Length`. Bytes sent after the request header are forwarded once the
tunnel is up. Upstream replies must use `HTTP/1.1`.

Without `--ca-file` the upstream certificate is verified against the Mozilla
root program as bundled by `webpki-roots`. This is deterministic and identical
on every platform; it ignores roots added to the operating system store, so a
proxy with a private CA needs `--ca-file`.

## Device key

```sh
gateinto key init
gateinto key info --spki-out device.spki.der
```

The device key is a persisted, non-exportable ECDSA P-256 key in Windows CNG,
named `gateinto-device-v1` unless `--name` is given. These commands only work
on Windows; elsewhere they fail with "device keys are only supported on
Windows".

`key init` reuses an existing key with that name. It looks in both the
"Microsoft Platform Crypto Provider" (backend `tpm`) and the "Microsoft
Software Key Storage Provider" (backend `software`) and never creates a second
key. It stops with an error, without creating anything, when:

- keys with that name exist in both providers; the error names both backends
  and fingerprints, and one of the keys has to be deleted by hand;
- the TPM is present but not usable right now, for example because the TPM Base
  Services are stopped or disabled or the device is not ready
  (`TBS_E_SERVICE_NOT_RUNNING`, `TBS_E_SERVICE_DISABLED`,
  `NTE_DEVICE_NOT_READY`, `NTE_PROVIDER_DLL_FAIL`). An existing TPM key cannot
  be ruled out then, so no software key is created; fix the TPM and retry;
- a provider or an existing key cannot be opened for any other reason than
  "not found" or "provider absent".

Only a provider that is genuinely absent (`TBS_E_TPM_NOT_FOUND`,
`NTE_PROV_DLL_NOT_FOUND`, `NTE_BAD_PROVIDER`, `NTE_DEVICE_NOT_FOUND`) counts as
"no key there". Only when no key exists does it create one: in the TPM first,
proving it with a test signature, and otherwise in software with a warning that
says why. A TPM key that fails its test signature is deleted
before falling back. The export policy is set to non-exportable before the key
is finalized in both providers. No private key material is written anywhere.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--name` | `gateinto-device-v1` | CNG key name. Must not be empty or contain NUL. |
| `--backend` | `tpm` | Where to create a new key: `tpm` (falls back to software unless disabled) or `software`. An existing key is reused wherever it is. |
| `--no-software-fallback` | off | Fail instead of creating a software key when the TPM cannot be used. |

`key info` opens the existing key, never creates one, and prints its backend,
algorithm (`ECDSA P-256`), the SHA-256 fingerprint of its DER
SubjectPublicKeyInfo as lowercase hex, and a trust note. A `tpm` key is
hardware-protected. A `software` key has the non-exportable flag set, but an
administrator or malware running as the user can still copy it. `--spki-out
<path>` writes the public SubjectPublicKeyInfo DER to a file. It fails in the
same lookup cases as `key init`, except that keys in both providers only produce
a warning on stderr naming both backends; it then shows the `tpm` key.

There is no rotate or delete command yet. Manual steps for checking a real TPM
are in [docs/tpm-verification.md](docs/tpm-verification.md).

## Security

The loopback listener has no authentication of its own. Any local process,
including those of other users on the same machine, can connect to it and use
the agent, and later its device identity, to reach the remote proxy. Do not run
it on shared hosts you do not trust.

## Build and test

```sh
cargo build
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
```

The minimum supported Rust version is 1.88 (required by `rcgen` and `time`).

Windows CNG tests only run on Windows. They create and delete temporary keys
named `gateinto-test-*` in the current user's Microsoft Software Key Storage
Provider, and in the Microsoft Platform Crypto Provider on machines with a
usable TPM.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
