# Architecture

This describes the code on `master`. Items marked **Planned** do not exist yet.

## Data path

```text
 client (browser, curl, ...)
   |  TCP to 127.0.0.1:18736
   |  CONNECT target:443 HTTP/1.1
   v
+------------------------------- gateinto ---------------------------------+
|  1. read and parse the request head (limits, timeout)                    |
|  2. TCP connect to the upstream proxy                                    |
|  3. TLS 1.3 handshake, WebPKI verification of the upstream certificate   |
|  4. send CONNECT target:443 HTTP/1.1 inside TLS                          |
|  5. read the upstream status line and header block                       |
|  6. upstream 2xx: send local 200, then relay bytes in both directions    |
|     otherwise:    send a local error status and close                    |
+--------------------------------------------------------------------------+
   |  TLS 1.3 to the upstream HTTPS proxy
   v
 upstream HTTPS forward proxy
   |  TCP
   v
 target:443
```

The client's own TLS session with the target (for example HTTPS to
`example.com`) runs inside the tunnel. Gateinto does not terminate or inspect
it; it relays bytes.

## Modules

| Path | Role |
| --- | --- |
| `src/main.rs` | Command line (`gateinto proxy ...`), logging setup, building `proxy::Config`. |
| `src/http.rs` | Strict parsers for the local `CONNECT` request and the upstream response head. Pure functions over byte buffers, no I/O. |
| `src/proxy/mod.rs` | Listener, connection limit, per-connection state machine, upstream connect, status mapping, error responses. |
| `src/proxy/relay.rs` | Bidirectional copy between client and upstream with an idle timeout that any traffic in either direction resets. |
| `src/tls.rs` | Crypto provider with key exchange groups `X25519MLKEM768`, then `X25519`; default roots from `webpki-roots`; loading `--ca-file` PEM bundles. |
| `src/identity/` | Windows CNG helpers (`windows_cng.rs`, `cfg(windows)` only): create, open, export and delete a persisted ECDSA P-256 key. Used by tests only; not wired into the proxy. |

## Local 200 only after upstream 2xx

The local `200 Connection Established` is written only after the upstream
proxy has answered the inner `CONNECT` with a `2xx` status. Until then no byte
from the upstream is sent to the client. Bytes the client sent after its
request head are buffered and forwarded once the tunnel is up; bytes the
upstream sent after its response head are sent to the client right after the
local `200`.

## Status mapping

| Situation | Local status |
| --- | --- |
| Upstream `2xx` | `200 Connection Established`, then the tunnel |
| Upstream `403` | `403` |
| Upstream `407` or any other status | `502`; upstream headers and body are not forwarded |
| Upstream connect, TLS or certificate failure, malformed reply | `502` |
| Upstream connect, handshake or reply timeout | `504` |
| Method other than `CONNECT` | `405` with `Allow: CONNECT` |
| Malformed request | `400` |
| Request header block over the limit | `431` |
| Request not complete within the connect timeout | `408` |
| Too many connections | `503` |

Error responses have no body and close the connection.
[troubleshooting.md](troubleshooting.md) explains each status from the user's
side.

## Limits

| Limit | Flag | Default |
| --- | --- | --- |
| Concurrent connections, including those still sending their request | `--max-tunnels` | 64 |
| Request and upstream response header block | `--max-header-bytes` | 16384 bytes |
| Reading the local request | `--connect-timeout-secs` | 10 s |
| Upstream TCP connect, TLS handshake and `CONNECT` reply together | `--connect-timeout-secs` | 10 s (separate budget) |
| Tunnel without traffic in either direction | `--idle-timeout-secs` | 300 s |

The listen address must be loopback unless `--unsafe-allow-non-loopback-listen`
is given.

## TLS

- TLS 1.3 only; `rustls` is built without `tls12`.
- Key exchange groups in order: `X25519MLKEM768` (hybrid), `X25519`.
- The upstream certificate is verified with WebPKI against the Mozilla roots
  from `webpki-roots`, or only against `--ca-file` when given. The name checked
  is `--upstream-server-name`, defaulting to `--upstream-host`.
- No client certificate is sent on `master`.

## Planned

These components are designed but not implemented on `master`. Do not rely on
them.

- **Planned: device key lifecycle.** Commands to create, show and delete the
  device key in Windows CNG, preferring the TPM ("Microsoft Platform Crypto
  Provider") and falling back to software key storage, and to export a public
  key or certificate request for enrollment.
- **Planned: mutual TLS.** Presenting a client certificate for the device key
  to the upstream proxy, with signatures made through CNG so the private key
  never leaves the key store.
- **Planned: TLS modes.** Choices for how the upstream TLS connection is
  configured beyond the current fixed TLS 1.3 setup.
- **Planned: configuration file.** A TOML file as an alternative to command
  line flags.

See also [threat-model.md](threat-model.md) and
[compatibility.md](compatibility.md).
