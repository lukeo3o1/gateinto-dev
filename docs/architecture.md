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
|  2. select the session's shared h2 connection, or open upstream TCP       |
|  3. TLS 1.3 handshake, WebPKI verification of the upstream certificate,  |
|     client certificate signed by the device key if configured;           |
|     check the negotiated version and key exchange against the TLS mode   |
|  4. send HTTP/2 CONNECT on a new stream, or HTTP/1.1 CONNECT inside TLS   |
|  5. read the upstream response status and headers                        |
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
it; it relays bytes. ALPN offers `h2`, then `http/1.1`; the selected protocol
determines the upstream CONNECT encoding. HTTP/2 multiplexes streams on one
lazy TLS connection per session. HTTP/1.1, including no ALPN, keeps one TLS
connection per tunnel. See [upstream HTTP CONNECT](protocol/http-connect.md)
for connection ownership, flow control, reconnect, draining and timeouts.

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
its own `rustls` client configuration, per-handshake certificate resolvers and
HTTP/2 pool, its own
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
its client and upstream stream. All current and draining HTTP/2 driver tasks
are also aborted, including when the proxy run future itself is cancelled.
`close` returns once the session tasks are stopped.
The session's TLS configuration, resolver and self-signed certificates are
dropped with it; no other session holds them, so no later `CONNECT` can use
that certificate. Other sessions are not affected.

Kinds: `SessionKind::Device` is the long-running session for background
programs, configured by `[device_session]` (or the command line); its local
authentication is `[device_session] auth`, `none` by default.
`gateinto proxy` starts exactly one device session and runs until Ctrl+C (or
SIGTERM on Unix), then closes it with `SessionManager::close_all` and exits.
`SessionKind::Browser` is a session for one browser: `gateinto session
browser` starts one on `127.0.0.1:0` with `BasicTofu`, prints its port and
realm and runs until Ctrl+C, then closes it the same way. The agent (below)
starts browser sessions for launch URIs and runs the device session too.

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

## Agent, launch URIs and browser sessions

```text
 browser click: gateinto://connect?profile=office[&url=..][&gateway=..&portal=..]
        |
 Windows URL handler (HKCU\Software\Classes\gateinto)
        |  "gateinto.exe" open --config "<file>" -- "%1"
        v
 gateinto open ---- uri::LaunchRequest (strict parse; invalid URI ends here)
        |  "launch office basic_tofu [url=..] [gateway=..] [portal=..]\n"
        |  named pipe \\.\pipe\gateinto-agent-<SID> (Unix socket in tests)
        |  (no agent: spawn detached `gateinto agent --config <file>`, retry)
        v
 gateinto agent ---- agent::Agent
        |  parse again, rate limit, session cap
        |  link::resolve against the config file + gateways/*.toml
        |    known gateway ----------------------------------------------.
        |    new gateway: answer "confirm: <token>", keep the request     |
        |       <- gateinto open asks the user (MessageBoxW / terminal)   |
        |       <- "approve <token>": LinkedStore::add, then -------------|
        |       <- "deny <token>": forget the request                     v
        |-- SessionManager::start(Browser, 127.0.0.1:0, BasicTofu)
        |-- browser::ProfileDir::create(<profiles>/<id>-<random>, marker)
        |-- chrome.exe --user-data-dir=... --proxy-server=http://127.0.0.1:<port> ... <start page>
        '-- watch task: browser exit or close request
               -> SessionManager::close, delete marked profile directory
```

The full protocol, limits and guarantees are in
[protocol/launch-uri.md](protocol/launch-uri.md).

- `uri::LaunchRequest` parses `gateinto://connect?profile=...&auth=...&v=1`
  with the optional `url`, `gateway` and `portal` into a `GatewayName`, a
  `LaunchAuth`, `PortalUrl`s and a `link::GatewayAddress`.
  `LaunchRequest::new` and `LaunchRequest::with_link` hold the value rules
  and are also used by the agent to parse IPC requests, so the agent applies
  the same rules again instead of trusting `open`. Its `Display` prints the
  canonical URI.
- `link` holds the strict `GatewayAddress` (`host[:port]`) and `Origin`
  parsers, `resolve`, a pure function from a request, the known gateways and
  a `Confirm` decision (approve, deny or defer) to a launch, a confirmation
  to ask for, or an error. `link::store::LinkedStore` keeps one file per
  approved gateway in `gateways/`, named only from the canonical address,
  loads them with per-file failure isolation into `Known` (valid gateways,
  invalid entries that still block their name and address, or a store that
  cannot be read), and writes new files atomically without replacing any. `ConfigFile::with_linked` turns linked entries into
  minimal `[gateways.<name>]` tables, so they get exactly the defaults of a
  configured gateway with only `host`, `port` and `portal_url`.
- `prompt` asks the user in `gateinto open`: `MessageBoxW` on an interactive
  Windows desktop, otherwise a `yes` prompt on a terminal, otherwise it
  refuses.
- `ipc` holds the request and response types (`Request`, `Response`), their
  one-line text encoding with size limits, the per-user `Endpoint` (a named
  pipe named after the user's SID on Windows with a DACL for the user and
  SYSTEM only, a socket in a private directory on Unix, both suffixed by
  `GATEINTO_INSTANCE` when it is set), the `Server` that only one agent can
  bind (on Unix under a lock file), and `send` for clients, which checks on
  Windows that the pipe server runs as the same user and gives up after 60
  seconds.
- `agent::Agent` owns a `SessionManager` and one watch task per browser
  session. `Agent::serve` first deletes profile directories left by an
  earlier agent, then accepts at most 8 connections at a time, answers one
  request per connection and stops on `stop` or when its shutdown future
  (Ctrl+C) completes, closing every session before it returns. Launches are
  serialized; each is counted by a sliding-window limiter (5 per 60 s) and
  refused beyond 4 open browser sessions; a launch that needs a confirmation
  is counted too, and the agent keeps at most one pending confirmation
  (token, request, expiry after 120 s). The `agent::Profiles` trait lists the
  known gateways, stores an approved one and turns a gateway name into the
  proxy configuration of a browser session; `main.rs` implements it with the
  loaded configuration file and `LinkedStore` (read again for every launch),
  the tests with in-process fixtures. The agent forces the session to
  `127.0.0.1:0` and `BasicTofu` whatever the profile says.
- A browser's watch task waits for the browser process to exit or for a
  close request (`close <id>`, `stop`, Ctrl+C), kills the browser in the
  second case, closes the session, deletes the profile directory (retrying
  for about 10 seconds) and removes itself. `close` and `stop` answer only
  after that is done.
- `browser` finds Chrome or Edge, builds the argument list, starts the
  process without a shell (`tokio::process`, killed when the agent drops it)
  and manages profile directories. A profile directory is deleted only if it
  lies directly in the profiles directory, has the `<id>-<16 hex>` name, is
  a real directory and holds the marker file with the exact marker content.
- `registration` builds and recognizes the handler command and, on Windows,
  writes and deletes `HKCU\Software\Classes\<scheme>` through `registry`
  (thin `windows-sys` wrappers).
- `gateinto open` (in `main.rs`) parses the URI first, then sends the
  request; if no agent answers it starts one (Windows: `DETACHED_PROCESS`
  and `CREATE_NEW_PROCESS_GROUP`, standard handles made non-inheritable; Unix:
  a new process group) and retries with backoff for up to 30 seconds.

## Modules

| Path | Role |
| --- | --- |
| `src/main.rs` | Command line (`proxy`, `check-upstream`, `session browser`, `session list`, `session close`, `agent`, `open`, `stop`, `gateway list`, `gateway forget`, `uri register`, `uri unregister`, `key init`, `key info`, `setup`, `status`, `reset`), the default config file location, merging flags over the configuration file, logging setup, building `proxy::Config`, starting the device session or a browser session, the agent's `Profiles` from the configuration file, starting a detached agent for `open`, Ctrl+C handling. |
| `src/lifecycle.rs` | `setup`, `status` and `reset` helpers: service account refusal and the elevation note, handler and gateway reporting (with their source), the files a config purge deletes, the purge warning and confirmation, and the purge order (confirm the SPKI, stop the agent, delete the key). |
| `src/uri.rs` | Strict parser for `gateinto://` launch URIs and their canonical form. |
| `src/link.rs` | Gateway addresses and portal origins, the resolution of a link against known gateways, and the confirmation text. |
| `src/link/store.rs` | The per-gateway files in `gateways/`: file names from canonical addresses, safe loading, adding, forgetting and purging. |
| `src/prompt.rs` | The confirmation in `gateinto open`: Windows message box, terminal prompt or refusal. |
| `src/ipc.rs` | Agent requests and responses, their line encoding, the per-user named pipe or Unix socket endpoint, server and client. |
| `src/agent.rs` | The agent: launch validation, rate limit and session cap, browser sessions and their watch tasks, `list`, `close`, `stop`, sweeping stale profiles. |
| `src/browser.rs` | Chrome and Edge discovery, browser arguments, process start, marked per-session profile directories and their safe deletion. |
| `src/registration.rs`, `src/registry.rs` | The URI handler command string and its per-user registration in `HKCU\Software\Classes` (registry calls on Windows only). |
| `src/config.rs` | TOML configuration file (`serde`, `toml`, unknown keys rejected), gateway profiles (with their validated `portal_url`) and their lookup by name, the device session's gateway, listen address and local authentication, the `[browser]` executable, flag-over-file merge, defaults, relative path resolution. |
| `src/sessions.rs` | `SessionManager`: starting a session (its own client certificate, TLS configuration and listener) and closing it (listener dropped, its tunnels aborted). |
| `src/check.rs` | `check-upstream`: one connection to the upstream, report of the negotiated TLS parameters, optional `CONNECT`. |
| `src/http.rs` | Strict parsers for the local `CONNECT` request and the upstream response head. Pure functions over byte buffers, no I/O. |
| `src/proxy/mod.rs` | Listener and accept loop of one session, until it is closed; connection limit, local authentication hook, per-connection state machine, upstream connect and post-handshake TLS mode check (`Endpoint`, shared with `check.rs`), status mapping, error responses. |
| `src/proxy/basic_tofu.rs` | `basic_tofu` local proxy authentication of one session: realm, strict Basic and base64 parsing, binding the first credential as a keyed hash, constant-time comparison, failure rate limit. |
| `src/proxy/h2.rs`, `src/proxy/pool.rs` | Flow-controlled HTTP/2 CONNECT streams and the session's lazy upstream connection pool, certificate rotation and owned connection drivers. |
| `src/proxy/relay.rs` | Bidirectional copy between client and upstream with an idle timeout that any traffic in either direction resets. |
| `src/tls.rs` | TLS modes and their key exchange groups, the post-handshake negotiation check, the TLS 1.3 client configuration, the client certificate resolver; default roots from `webpki-roots`; loading `--ca-file` PEM bundles. |
| `src/identity/` | Device key lifecycle including the confirmed purge (`device_key.rs`), client certificate selection and binding to the device key (`client_cert.rs`, `x509.rs`), self-signed client certificates issued and renewed with the device key (`certificates.rs`), CNG status classification, and the Windows CNG store (`windows_cng.rs`, `cfg(windows)` only). |

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
  one is 12 hours old
  ([protocol/client-cert.md](protocol/client-cert.md)). HTTP/2 stops using the
  old connection for new streams after renewal; accepted old streams drain.
- Every new upstream TLS connection performs a full handshake; resumption and
  early data remain disabled. HTTP/2 reuses an already open TLS connection.
- HTTP/2 transport and pooling live in `src/proxy/h2.rs` and
  `src/proxy/pool.rs`; `relay.rs` applies the same half-close and idle behavior
  to HTTP/1.1 TLS sockets and HTTP/2 streams.

## Installation and the device identity

The per-user MSI ([packaging/wix](../packaging/wix/README.md),
[install.md](install.md)) installs `gateinto.exe` under
`%LOCALAPPDATA%\Programs\Gateinto`, the `HKCU` `gateinto://` handler and an
optional `HKCU` Run entry. Installing binaries is separate from creating the
device key: no custom action touches a key, and the only uninstall custom
action runs `gateinto stop --remove-stale-profiles` as the user. The key is
created by `gateinto setup` (or `key init`) as the user who will use it;
`setup` refuses the LocalSystem, LocalService and NetworkService accounts.
Other commands only open the key. The key and the config file
(`%APPDATA%\Gateinto\gateinto.toml` by default) are not MSI components, so an
uninstall keeps them and a reinstall keeps the SPKI. Only
`gateinto reset --purge-device-identity` deletes the key: it requires the SPKI
prefix, stops the agent, reopens the named key with `NCryptOpenKey`, checks
the SPKI again and deletes that handle with `NCryptDeleteKey`.

## Not implemented

Do not rely on these; they do not exist.

- **Enrollment.** Obtaining the client certificate for the device key
  (certificate request or enrollment protocol) instead of issuing and
  installing it by hand.
- **Key rotation.** A command to replace the device key. Deleting it is
  `gateinto reset --purge-device-identity`.
- **Machine-wide install, machine service and WinGet.** The MSI is per user
  only; there is no `HKLM` registration, no Windows service that runs without
  a logged-on user, no WinGet package and no code signing.
- **Detecting closed browser windows.** The agent watches the browser process
  it started, not its windows; see the limitations in
  [protocol/launch-uri.md](protocol/launch-uri.md#browser-launch).
- **Browsers other than Chrome and Edge.** Firefox and others are not looked
  for; `[browser] executable` can name another Chromium-based browser that
  accepts the same switches.

See also [security-model.md](security-model.md),
[threat-model.md](threat-model.md) and [verification.md](verification.md).
