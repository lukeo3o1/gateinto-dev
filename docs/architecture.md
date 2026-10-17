# Architecture

This describes the current code. Items marked **Planned** do not exist yet.

## Data path

```text
 client (browser, curl, ...)
   |  TCP to 127.0.0.1:18736
   |  CONNECT target:443 HTTP/1.1
   v
+------------------------------- gateinto ---------------------------------+
|  1. read and parse the request head (limits, timeout)                    |
|  2. TCP connect to the upstream proxy                                    |
|  3. TLS 1.3 handshake, WebPKI verification of the upstream certificate,  |
|     client certificate signed by the device key if configured;           |
|     check the negotiated version and key exchange against the TLS mode   |
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
| `src/main.rs` | Command line (`proxy`, `check-upstream`, `key init`, `key info`), merging flags over the configuration file, logging setup, building `proxy::Config`. |
| `src/config.rs` | TOML configuration file (`serde`, `toml`, unknown keys rejected), flag-over-file merge, defaults, relative path resolution. |
| `src/check.rs` | `check-upstream`: one connection to the upstream, report of the negotiated TLS parameters, optional `CONNECT`. |
| `src/http.rs` | Strict parsers for the local `CONNECT` request and the upstream response head. Pure functions over byte buffers, no I/O. |
| `src/proxy/mod.rs` | Listener, connection limit, per-connection state machine, upstream connect and post-handshake TLS mode check (`Endpoint`, shared with `check.rs`), status mapping, error responses. |
| `src/proxy/relay.rs` | Bidirectional copy between client and upstream with an idle timeout that any traffic in either direction resets. |
| `src/tls.rs` | TLS modes and their key exchange groups, the post-handshake negotiation check, the TLS 1.3 client configuration, the client certificate resolver; default roots from `webpki-roots`; loading `--ca-file` PEM bundles. |
| `src/identity/` | Device key lifecycle (`device_key.rs`), client certificate selection and binding to the device key (`client_cert.rs`, `x509.rs`), CNG status classification, and the Windows CNG store (`windows_cng.rs`, `cfg(windows)` only). |

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
| Concurrent connections, including those still sending their request | `--max-tunnels` / `max_concurrent_tunnels` | 64 |
| Request and upstream response header block | `--max-header-bytes` / `header_max_bytes` | 16384 bytes |
| Reading the local request | `--connect-timeout-secs` / `connect_timeout_seconds` | 10 s |
| Upstream TCP connect, TLS handshake and `CONNECT` reply together | `--connect-timeout-secs` / `connect_timeout_seconds` | 10 s (separate budget) |
| Tunnel without traffic in either direction | `--idle-timeout-secs` / `idle_timeout_seconds` | 300 s |

The listen address must be loopback unless `--unsafe-allow-non-loopback-listen`
is given on the command line. The configuration file has no key for it.

## Configuration

Settings come from command line flags, then the `--config` TOML file, then
built-in defaults, resolved key by key. The upstream host and port have no
default. See the README for the schema.

## TLS

- TLS 1.3 only; `rustls` is built without `tls12`.
- Key exchange groups by TLS mode: `hybrid_preferred` (default) offers
  `X25519MLKEM768`, then `X25519`; `hybrid_required` offers only
  `X25519MLKEM768`; `classical_only` offers only `X25519`.
- After each handshake the negotiated version and group are logged at `debug`
  and checked: anything but TLS 1.3 with a group the mode offers ends the
  tunnel with `502`. For `hybrid_required` this is a second line of defense
  behind the offered list.
- The upstream certificate is verified with WebPKI against the Mozilla roots
  from `webpki-roots`, or only against `--ca-file` when given. The name checked
  is `--upstream-server-name`, defaulting to `--upstream-host`.
- When the upstream requests a client certificate and one is configured, the
  certificate bound to the device key is sent and `CertificateVerify` is signed
  through CNG.

## Planned

Implemented: the device key lifecycle (`key init`, `key info`, TPM preferred
with software fallback), mutual TLS with the device key, TLS modes with
`check-upstream`, and the TOML configuration file.

These components are designed but not implemented. Do not rely on them.

- **Planned: enrollment.** Obtaining the client certificate for the device key
  (certificate request or enrollment protocol) instead of installing it by
  hand.
- **Planned: key rotation and deletion.** Commands to replace or delete the
  device key.

See also [threat-model.md](threat-model.md) and
[compatibility.md](compatibility.md).
