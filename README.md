# Gateinto

Gateinto is a local HTTP/1.1 `CONNECT` proxy for Windows. It listens on
`127.0.0.1:18736`, opens a TLS 1.3 connection to a remote HTTPS forward proxy,
and issues a second `CONNECT` there. Client authentication (mTLS) uses a
non-exportable ECDSA P-256 device key held by Windows CNG (TPM preferred,
software key storage as fallback) and a client certificate issued for it. Key exchange prefers the hybrid
post-quantum group `X25519MLKEM768` and falls back to `X25519`.

## Status

Early proof of concept. Not production ready. The double `CONNECT` data path
works with and without client authentication. The device key can be created
and inspected with `gateinto key`, and the proxy signs the TLS 1.3 client
authentication with it when a client certificate for it is available. There is
no enrollment: the certificate has to be obtained and installed by hand. See
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
| `--client-certificate` | `optional` | Client authentication to the upstream: `optional`, `required` or `off`. See [Client certificate](#client-certificate-mtls). |
| `--client-cert-file` | search `CurrentUser\My` | PEM file with the client certificate, optionally followed by intermediates. |
| `--key-name` | `gateinto-device-v1` | CNG device key that signs the client authentication. It is only opened, never created. |
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

## Client certificate (mTLS)

The upstream connection is TLS 1.3 only, prefers `X25519MLKEM768`, and
verifies the upstream certificate exactly as without client authentication.
When the upstream asks for a client certificate, Gateinto sends the configured
one and signs `CertificateVerify` with the device key through CNG
(`rustls-cng` `CngSigningKey`, `ECDSA_NISTP256_SHA256`, DER signatures).

At startup the device key named by `--key-name` is opened (TPM provider first,
then software; it is never created here), and the certificate is taken from:

1. `--client-cert-file`: the first PEM certificate is the leaf, any further
   ones are sent as intermediates.
2. Otherwise, on Windows, the `CurrentUser\My` certificate store: a certificate
   whose SubjectPublicKeyInfo is byte-for-byte the device key's, that is valid
   now, and that has the Client Authentication extended key usage or no
   extended key usage at all. Whether Windows holds a private key for it does
   not matter, because the device key signs. If several match, the one with
   the latest NotAfter is used and its SHA-1 thumbprint is logged at `info`.

Before a certificate is used, its public key is compared with the device key's.
A certificate whose private key Gateinto does not hold is never sent.

| Situation | `required` | `optional` (default) | `off` |
| --- | --- | --- | --- |
| Key and matching certificate | client auth | client auth | no client auth |
| Device key missing or unusable | startup error | warning, no client auth | no client auth |
| No certificate for the key | startup error | warning, no client auth | no client auth |
| Certificate for another key, or unreadable `--client-cert-file` | startup error | warning, no client auth | no client auth |
| Not Windows | startup error "device keys are only supported on Windows" | warning, no client auth | no client auth |

Without client auth in `optional` mode the warning is logged once at startup
and ends with "mTLS is not configured and upstream connections do not
authenticate this device". An upstream that requires a client certificate
then rejects the handshake, and local clients get `502`. With client auth
enabled, the subject, thumbprint, NotAfter, source and key backend are logged at
`info`.

### Getting a test client certificate

There is no enrollment yet; the certificate must be issued for the device
key's public key by a CA the upstream trusts. For a test setup with OpenSSL 3
and a throwaway CA (verified with OpenSSL 3.0.13; the device key itself stays
in CNG):

```sh
gateinto key info --spki-out device.spki.der
openssl ecparam -name prime256v1 -genkey -noout -out test-ca.key
openssl req -x509 -new -key test-ca.key -subj "/CN=gateinto test client CA" -days 30 -out test-ca.pem
openssl pkey -pubin -inform DER -in device.spki.der -out device.pub.pem
printf 'basicConstraints = CA:FALSE\nkeyUsage = digitalSignature\nextendedKeyUsage = clientAuth\n' > client.ext
openssl x509 -new -CA test-ca.pem -CAkey test-ca.key -force_pubkey device.pub.pem \
  -subj "/CN=gateinto-device" -days 30 -extfile client.ext -out client.pem
```

Then either pass `--client-cert-file client.pem`, or import it into the user
store so that the proxy finds it by its public key:

```powershell
certutil -user -addstore My client.pem
gateinto key info
```

`key info` should then list the certificate. Remove it again with
`certutil -user -delstore My <thumbprint>`. The import commands have not been
run as part of the test suite, which imports through the Crypt32 API instead.

The upstream only accepts the certificate if it is configured to trust
`test-ca.pem` as a client CA. The same holds for a self-signed client
certificate: it is only trusted by an upstream configured to trust that
certificate. Note that tools such as `New-SelfSignedCertificate` generate a new
key pair, so their certificates do not match the device key and are refused.

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
  be ruled out then, so no software key is created; fix the TPM and retry.
  These codes alone do not tell a missing TPM from one that is not ready, so
  when the Platform Crypto Provider returns one of them, TPM Base Services are
  asked whether a TPM exists (`Tbsi_GetDeviceInfo`). Only when they answer
  `TBS_E_TPM_NOT_FOUND` is the TPM treated as absent;
- a provider or an existing key cannot be opened for any other reason than
  "not found" or "provider absent".

Only a provider that is genuinely absent (`TBS_E_TPM_NOT_FOUND`,
`NTE_PROV_DLL_NOT_FOUND`, `NTE_BAD_PROVIDER`, `NTE_DEVICE_NOT_FOUND`) counts as
"no key there". Only when no key exists does it create one: in the TPM first,
proving it with a test signature, and otherwise in software with a warning that
says why. A TPM key that fails its test signature is deleted
before falling back. The export policy is set to non-exportable before the key
is finalized in both providers. No private key material is written anywhere.

A TPM that is disabled in firmware looks exactly like no TPM to Windows, so
`key init` then falls back to a software key. On machines known to have a TPM,
pass `--no-software-fallback` so that a disabled or missing TPM is an error
instead of a silently weaker software identity. GitHub-hosted `windows-latest`
runners have no TPM; there the Platform Crypto Provider reports
`NTE_DEVICE_NOT_READY` and the software fallback is used.

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

`key info` also shows the client certificate bound to the key, as the proxy
would choose it from `CurrentUser\My`: `client-certificate: none`, or its
subject, SHA-1 thumbprint (`client-certificate-sha1`), NotAfter and source.
With `--client-cert-file <pem>` it checks that file instead and fails if the
certificate's public key is not the device key's.

There is no rotate or delete command yet. Manual steps for checking a real TPM
are in [docs/tpm-verification.md](docs/tpm-verification.md).

## Security

The loopback listener has no authentication of its own. Any local process,
including those of other users on the same machine, can connect to it and use
the agent, including its device identity, to reach the remote proxy. Do not run
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
usable TPM. `tests/mtls_windows.rs` also adds a temporary certificate with
subject `CN=gateinto-test-client` to `CurrentUser\My` and removes it again.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
