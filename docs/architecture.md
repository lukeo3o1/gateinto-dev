# Architecture

This describes the current code. [Not implemented](#not-implemented) lists
what does not exist.

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

## Sessions and gateway profiles

```text
             one device key (CNG)
                     |
     +---------------+-------------------+
     |                                   |
 session 1 (device)                  session 2 (browser)
   listener 127.0.0.1:18736            listener 127.0.0.1:<ephemeral>
   local auth: none (default)          local auth: basic_tofu, own realm
   own TLS client config + resolver    own TLS client config + resolver
   own client certificate              own client certificate
   own connection limits, tunnels      own connection limits, tunnels
     |                                   |
 gateway profile "default"           gateway profile "office"
     |                                   |
 upstream HTTPS proxy                upstream HTTPS proxy
```

A gateway profile (`config::GatewayProfile`, from a `[gateways.<name>]`
table) describes one upstream: host, port, server name, CA file, TLS mode and
client certificate settings. `ConfigFile::gateway` looks a profile up by name
in the loaded file and nothing else, so a caller that only has a name can
select a configured upstream but cannot add a host, a CA or any other trust
setting.

A session (`sessions::Session`) is one local entry point bound to one gateway.
`SessionManager::start` builds everything the session uses and shares none of
it with other sessions: its own listener (port `0` gives an ephemeral port),
its own `rustls` client configuration and client certificate resolver, its own
connection and reject limits, and its own set of connection tasks. Its client
certificate comes from the configured source through
`ClientCertificate::for_session`: a self-signed source issues a new
certificate with the device key for every session (and each session renews
only its own), so two sessions never present the same self-signed
certificate; a file or `CurrentUser\My` certificate is the same certificate in
every session, because only one exists for the key. Each session also has a
local authentication policy (`proxy::LocalAuth`): `None` accepts every local
client; `BasicTofu` gives the session its own `proxy::basic_tofu::BasicTofu`
state, created in `Proxy::bind` and owned by that session only (see below).

`SessionManager::close` closes a session: the accept loop stops before it
accepts anything else, the listener is dropped so its port refuses new
connections, and every connection task of the session, including established
tunnels and connections still being answered, is aborted, which closes both
its client and its upstream socket. `close` returns once all of that is done.
The session's TLS configuration, resolver and self-signed certificates are
dropped with it; no other session holds them, so no later `CONNECT` can use
that certificate. Other sessions are not affected.

Kinds: `SessionKind::Device` is the long-running session for background
programs, configured by `[device_session]` (or the command line); its local
authentication is `[device_session] auth`, `none` by default.
`gateinto proxy` starts exactly one device session and runs until it is
stopped (Ctrl+C ends the process). `SessionKind::Browser` is a session for one
browser: `gateinto session browser` starts one on `127.0.0.1:0` with
`BasicTofu`, prints its port and realm and runs until Ctrl+C. Starting browser
sessions from a `gateinto://` URI and launching the browser are not
implemented yet.

### Local proxy authentication (`basic_tofu`)

`BasicTofu` holds, per session: a realm `Gateinto session <16 hex digits>`
from the system random generator, a random HMAC-SHA-256 key, a
`OnceLock` for the bound credential's HMAC tag, and a failure counter with
the time of the first failure in the current window, behind a mutex.
`Shared::handle` calls `BasicTofu::check` after the request head is parsed
and before any upstream connection is opened:

1. If the failure window (60 s from its first failure) has passed, the
   counter is reset. If it holds 10 or more failures, the answer is `429`
   with `Retry-After`, whatever the request carries.
2. No `Proxy-Authorization`: `407` with
   `Proxy-Authenticate: Basic realm="<realm>", charset="UTF-8"`. Not a
   failure.
3. The header is parsed strictly (`http.rs` already refuses a repeated
   header with `400`). Another scheme: `407`. A malformed `Basic` credential:
   `400`.
4. A well-formed credential is MACed. The first one to fill the `OnceLock`
   is bound (logged at `info` without the credential) and accepted; any later
   one is compared with the bound tag in constant time: equal is accepted,
   different is `407` (logged at `warn`).

Every `407` for a wrong credential or other scheme, and every `400` from
step 3, counts as a failure. The check runs under the mutex, so concurrent
first credentials are ordered and exactly one binds. The upstream `CONNECT`
is built from the target alone, so the local credential never reaches the
upstream. `ConnectRequest`'s `Debug` output redacts the header value.

## Modules

| Path | Role |
| --- | --- |
| `src/main.rs` | Command line (`proxy`, `check-upstream`, `session browser`, `key init`, `key info`), merging flags over the configuration file, logging setup, building `proxy::Config` and starting the device session or a browser session. |
| `src/config.rs` | TOML configuration file (`serde`, `toml`, unknown keys rejected), gateway profiles and their lookup by name, the device session's gateway, listen address and local authentication, flag-over-file merge, defaults, relative path resolution. |
| `src/sessions.rs` | `SessionManager`: starting a session (its own client certificate, TLS configuration and listener) and closing it (listener dropped, its tunnels aborted). |
| `src/check.rs` | `check-upstream`: one connection to the upstream, report of the negotiated TLS parameters, optional `CONNECT`. |
| `src/http.rs` | Strict parsers for the local `CONNECT` request and the upstream response head. Pure functions over byte buffers, no I/O. |
| `src/proxy/mod.rs` | Listener and accept loop of one session, until it is closed; connection limit, local authentication hook, per-connection state machine, upstream connect and post-handshake TLS mode check (`Endpoint`, shared with `check.rs`), status mapping, error responses. |
| `src/proxy/basic_tofu.rs` | `basic_tofu` local proxy authentication of one session: realm, strict Basic and base64 parsing, binding the first credential as a keyed hash, constant-time comparison, failure rate limit. |
| `src/proxy/relay.rs` | Bidirectional copy between client and upstream with an idle timeout that any traffic in either direction resets. |
| `src/tls.rs` | TLS modes and their key exchange groups, the post-handshake negotiation check, the TLS 1.3 client configuration, the client certificate resolver; default roots from `webpki-roots`; loading `--ca-file` PEM bundles. |
| `src/identity/` | Device key lifecycle (`device_key.rs`), client certificate selection and binding to the device key (`client_cert.rs`, `x509.rs`), self-signed client certificates issued and renewed with the device key (`certificates.rs`), CNG status classification, and the Windows CNG store (`windows_cng.rs`, `cfg(windows)` only). |

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
| `basic_tofu`: no credential, another scheme, or a credential other than the bound one | `407` with `Proxy-Authenticate: Basic realm="<session realm>", charset="UTF-8"` |
| `basic_tofu`: malformed `Basic` credential or repeated `Proxy-Authorization` | `400` |
| `basic_tofu`: 10 failures within 60 s | `429` with `Retry-After`, until the 60 s are over |
| Request header block over the limit | `431` |
| Request not complete within the connect timeout | `408` |
| Too many connections | `503` |

Error responses have no body and close the connection.
[troubleshooting.md](troubleshooting.md) explains each status from the user's
side.

## Limits

| Limit | Flag | Default |
| --- | --- | --- |
| Concurrent connections per session, including those still sending their request | `--max-tunnels` / `max_concurrent_tunnels` | 64 |
| Request and upstream response header block | `--max-header-bytes` / `header_max_bytes` | 16384 bytes |
| Reading the local request | `--connect-timeout-secs` / `connect_timeout_seconds` | 10 s |
| Upstream TCP connect, TLS handshake and `CONNECT` reply together | `--connect-timeout-secs` / `connect_timeout_seconds` | 10 s (separate budget) |
| Tunnel without traffic in either direction | `--idle-timeout-secs` / `idle_timeout_seconds` | 300 s |
| `basic_tofu` failures before `429` (`Limits::local_auth_failures`) | none | 10 within 60 s |
| `Proxy-Authorization` Basic token | none | 1024 base64 characters |

Limits apply to each session separately. The listen address must be loopback
unless `--unsafe-allow-non-loopback-listen` is given on the command line. The
configuration file has no key for it.

## Configuration

Settings come from command line flags, then the `--config` TOML file, then
built-in defaults, resolved key by key. Gateway flags apply to the gateway in
use (the device session's, or `check-upstream --gateway`). The upstream host
and port have no default. See the README for the schema.

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
  through CNG. With `--self-signed-client-cert` that certificate is issued in
  memory when a session starts, separately for each session, and signed by
  the same CNG key; the session's resolver issues a new one when the current
  one is 30 minutes old
  ([protocol/client-cert.md](protocol/client-cert.md)).

## Not implemented

Do not rely on these; they do not exist.

- **Enrollment.** Obtaining the client certificate for the device key
  (certificate request or enrollment protocol) instead of issuing and
  installing it by hand.
- **Key rotation and deletion.** Commands to replace or delete the device key.
- **Starting browser sessions from a URI.** No `gateinto://` URI handler and
  no browser launch. `gateinto session browser` starts one browser session by
  hand.
- **Several sessions from the command line.** `gateinto proxy` and
  `gateinto session browser` start one session each; more sessions in one
  process exist only through the library (`SessionManager`), as used by the
  tests.

See also [security-model.md](security-model.md),
[threat-model.md](threat-model.md) and [verification.md](verification.md).
