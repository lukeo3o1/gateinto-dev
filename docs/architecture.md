# Architecture

This describes the current code. [Not implemented](#not-implemented) lists
what does not exist.

## Data path

The default `gateway` route follows this path:

```text
 client (browser, curl, ...)
   |  TCP to the session's 127.0.0.1:<ephemeral port>
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
lazy TLS connection per session; a connection that stops answering is
replaced on a later request. HTTP/1.1, including no ALPN, keeps one TLS
connection per tunnel. See [upstream HTTP CONNECT](protocol/http-connect.md)
for connection ownership, flow control, reconnect, draining and timeouts.

A launch URI can select `route=mixed` only for its new browser session.
`proxy::routing` resolves target and gateway concurrently, selects gateway on
missing/error answers or a canonical IP intersection, and otherwise tries TCP
to the resolved target addresses. Discovery and direct TCP share half the
opening deadline; failure falls through to the ordinary gateway pool within
the original total deadline. A direct success uses the same authenticated
local CONNECT response and byte relay with no upstream TLS. Gateway failures
and established tunnels cannot switch routes. The mode is held by the
session and reported for mixed launches and session listings; gateway files
never store it. See [session routing](protocol/launch-uri.md#session-routing)
for the heuristic's limits and DNS/source-IP exposure.

`dns` owns the process-wide budget of 64 queued or running system lookups for
both mixed discovery and gateway connection setup. It acquires capacity
without waiting before submitting `ToSocketAddrs` to `spawn_blocking`; the
closure retains the slot even if its async waiter is dropped. IP literals
bypass the resolver. Both TCP paths connect resolved address vectors, and a
full DNS budget returns an immediate error. System calls already running can
still delay process shutdown. See [DNS work budget](protocol/http-connect.md#dns-work-budget).

## Sessions and gateway profiles

```text
             one device key (CNG)
                     |
     +---------------+-------------------+
     |                                   |
 session 1 (browser)                 session 2 (browser)
   listener 127.0.0.1:<ephemeral>      listener 127.0.0.1:<ephemeral>
   local auth: session_credentials     local auth: session_credentials
     (and os_user on Windows)            (and os_user on Windows)
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
local authentication policy (`proxy::LocalAuth`). Every session that a
command or the agent starts has `SessionCredentials`, which makes `Proxy::bind` generate the session's own
`proxy::SessionCredentials` and a `Verifier` for them, owned by that session
only (see below).

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

Kind: `SessionKind::Browser` is a session for one browser; it is the only
kind. There is no shared session for background programs. `gateinto session
browser` starts one on `127.0.0.1:0` with `SessionCredentials`, prints its
port and realm, shows the credentials (see below) and runs until Ctrl+C (or
SIGTERM on Unix), then closes it with `SessionManager::close_all` and exits.
The agent (below) starts browser sessions for launch URIs. A session kind
that this build does not know, such as `device` from an older agent, is
listed as `unknown`.

### Local proxy authentication (`session_credentials`)

`SessionCredentials::generate` pairs the fixed user name `gateinto` with a
password of 12 symbols from the 31-symbol alphabet
`abcdefghjkmnpqrstuvwxyz23456789`, drawn by rejection sampling from the system
random generator and grouped by four with hyphens (about 59.4 bits).
`SessionCredentials::parse` accepts no other user name. `Verifier` holds, per session: a realm
`Gateinto session <16 hex digits>`, a random HMAC-SHA-256 key, the tag of the
issued `user:password` under that key, and a failure counter with the time
of the first failure in the current window, behind a mutex. The session keeps
the credentials themselves only so that they can be shown
(`Session::credentials`). `Shared::handle` calls `Verifier::check` right
after the request head is parsed and before any DNS lookup, routing decision,
upstream connection or signature with the device key:

1. If the failure window (60 s from its first failure) has passed, the
   counter is reset. If it holds 10 or more failures, the answer is `429`
   with `Retry-After`, whatever the request carries.
2. No `Proxy-Authorization`: `407` with
   `Proxy-Authenticate: Basic realm="<realm>", charset="UTF-8"`. Not a
   failure.
3. The header is parsed strictly (`http.rs` already refuses a repeated
   header with `400`). Another scheme: `407`. A malformed `Basic` credential:
   `400`.
4. A well-formed credential is MACed and its tag compared with the issued
   one in constant time: equal is accepted, different is `407` (logged at
   `warn` without the credential). Nothing is ever learned from a request.

Every `407` for a wrong credential or other scheme, and every `400` from
step 3, counts as a failure. The upstream `CONNECT`
is built from the target alone, so the local credential never reaches the
upstream. `ConnectRequest`'s `Debug` output redacts the header value, and
`SessionCredentials`' `Debug` output redacts both fields.

The credentials are shown by the command that started the session, never by
the agent: `prompt::show_credentials` uses `MessageBoxW` on an interactive
Windows desktop, otherwise the terminal (stderr), and returns `false` when
there is neither. The text (`prompt::credentials_text`) names the proxy
address and warns against entering the credentials in a website. The agent
returns them only in a successful `launch` answer and for `credentials <id>`;
`gateinto open` and `gateinto session credentials` take them out of the
lines they print (`ipc::without_credentials`) and show them in the prompt.
Closing the session drops the credentials and the verifier with it.

### Local proxy authentication (`os_user`)

`Authenticator` (`src/proxy/local_auth.rs`) combines the session's methods:
the `session_credentials` verifier, an `Owners` lookup for `os_user`, or
both. `Shared::handle` sets one deadline for the connection (the connect
timeout) and, before reading the request, asks `Authenticator::os_user` about
the client's address and the listener's address; the lookup runs in
`spawn_blocking`. Reading the request head shares the same deadline. Then
`Authenticator::check` decides: a passed `os_user` opens the tunnel; otherwise
the `session_credentials` verifier decides as before when it is offered, and
`os_user` alone answers `403`. A lookup past the deadline answers `408`. The
first denial of a session logs a warning, later ones a debug line; denials
never touch the verifier's failure count.

`src/proxy/os_user.rs` holds the denial reasons, the `Owners` trait and the
matching of TCP table rows to a connection (for an IPv4 client, the IPv6
table is also searched for an IPv4-mapped row); tests use a fake `Owners`.
`src/proxy/os_user/windows.rs` is the Windows lookup: `GetExtendedTcpTable`
with `TCP_TABLE_OWNER_PID_CONNECTIONS`, `OpenProcess`, a second table lookup
while the process handle is held, `OpenProcessToken`, `EqualSid` against the
agent's own user SID and, when the session has a job, `IsProcessInJob`.

On Windows the agent creates one job object per browser session (`src/job.rs`:
`CreateJobObjectW` without a name or inheritable handle, with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`), passes it to the session as
`Config::os_user_job`, and starts the browser in it with `CreateProcessW` and
`PROC_THREAD_ATTRIBUTE_JOB_LIST`, or, when that fails, with `CREATE_SUSPENDED`,
`AssignProcessToJobObject` and `ResumeThread`. Stopping the browser process, or
the browser exiting, terminates the job and waits up to 5 seconds until it has
no active process, before the session closes and the profile is removed; a job
still not empty then is logged as a warning. Dropping the browser process
without stopping it terminates the job and leaves that wait to the background.
The waits and the browser start run on the blocking thread pool. Browser
sessions in a job offer `os_user` and `session_credentials`; their `launch`
answers carry no credentials, so `gateinto open` shows no prompt, and
`credentials <id>` still returns them. When no job can be created or the browser
cannot be put in one, the agent logs one warning for that launch, closes that
attempt's session and starts a new one with only `session_credentials` and the
browser outside any job; its `launch` answer carries the credentials.

## Agent, launch URIs and browser sessions

```text
 browser click: gateinto://connect?gateway=proxy.example[&portal=..][&url=..]
        |
 Windows URL handler (HKCU\Software\Classes\gateinto)
        |  "gateinto.exe" open --config "<file>" -- "%1"
        v
 gateinto open ---- uri::LaunchRequest (strict parse; invalid URI ends here)
        |  "launch office session_credentials [url=..] [gateway=..] [portal=..]\n"
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
        |-- SessionManager::start(Browser, 127.0.0.1:0, SessionCredentials)
        |-- browser::ProfileDir::create(<profiles>/<id>-<random>, marker)
        |-- chrome.exe --user-data-dir=... --proxy-server=http://127.0.0.1:<port> ... <start page>
        '-- watch task: browser exit or close request
               -> SessionManager::close, delete marked profile directory
```

The full protocol, limits and guarantees are in
[protocol/launch-uri.md](protocol/launch-uri.md).

- `uri::LaunchRequest` parses a gateway-address or legacy-profile launch
  selector, with optional `portal`, `url`, `route`, `auth` and `v`. At least
  one of `gateway` or `profile` is required; the profile and portal remain
  optional throughout URI, IPC and pending confirmation handling.
  `LaunchRequest::from_fields`, `LaunchRequest::with_route` and
  `LaunchRequest::with_link` hold the value rules
  and are also used by the agent to parse IPC requests, so the agent applies
  the same rules again instead of trusting `open`. Its `Display` prints the
  canonical URI.
- `link` holds the strict `GatewayAddress` (`host[:port]`) and `Origin`
  parsers, deterministic endpoint-derived internal profile names, and
  `resolve`, a pure function from a request, the known gateways and
  a `Confirm` decision (approve, deny or defer) to a launch, a confirmation
  to ask for, or an error. `link::store::LinkedStore` keeps one file per
  approved gateway in `gateways/`, named only from the canonical address,
  loads them with per-file failure isolation into `Known` (valid gateways,
  invalid entries that still block their name and address, or a store that
  cannot be read), and writes new files atomically without replacing any. `ConfigFile::with_linked` turns linked entries into
  minimal `[gateways.<name>]` tables, so they get exactly the defaults of a
  configured gateway with only `host`, `port` and an optional `portal_url`.
  Address-only selection reuses a unique existing profile and its trust
  settings without DNS identity lookup, and refuses ambiguous endpoints.
  Unknown addresses need first-time approval; internal name collisions and
  damaged stored entries fail closed.
- `prompt` asks the user in `gateinto open`: `MessageBoxW` on an interactive
  Windows desktop, otherwise a `yes` prompt on a terminal, otherwise it
  refuses. It also shows the session credentials the same way.
- `ipc` holds the request and response types (`Request`, `Response`), their
  one-line text encoding with size limits, the per-user `Endpoint` (a named
  pipe named after the user's SID on Windows, owned by the user, with a DACL
  for the user and SYSTEM only, a socket in a private directory on Unix, both
  suffixed by `GATEINTO_INSTANCE` when it is set), the `Server` that only one
  agent can bind (on Unix under a lock file), and `send` for clients, which
  checks on Windows that the pipe is owned by the same user and gives up
  after 60 seconds.
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
  `127.0.0.1:0` and `SessionCredentials` whatever the profile says, and
  answers a launch with the session's credentials, which `gateinto open`
  shows.
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
- The GUI (`gateinto-gui.exe`) starts an agent only when the user clicks
  Start agent, which it offers on the sessions page and in the tray flyout
  only while its last poll found no agent. It runs `gateinto.exe agent
  --detach` from the GUI's own directory by absolute path, without a shell or
  `--config`, with null standard handles and, on Windows, `CREATE_NO_WINDOW`.
  At most one start is in flight; the button stays disabled until it ends.
  The GUI waits for that command to exit, off the UI thread, for up to 45
  seconds (then kills it), and polls the agent at once after a clean exit.
  A nonzero exit, a failure to start it or the timeout shows a fixed message,
  never the command's output or error, on the sessions page and in the tray
  flyout until the next start or until a poll finds the agent no longer
  stopped; there are no retries. After a timeout, an agent the command had
  already started may still come up, so the next poll can find it running.
  Quitting the GUI while a start is in flight normally ends the `agent
  --detach` command as the GUI's worker shuts down, so whether an agent comes
  up depends on how far it got. If
  `gateinto.exe` is not a file next to the GUI, it shows a fixed message and
  starts nothing. Demo mode never starts an agent. This is unit-tested but has
  not been tried on a real Windows desktop.
- The agent remembers which config file it loaded (`ipc::ConfigSource`): the
  absolute form of `--config`, the default file when it existed at start, or
  none. The `config` request answers `config: <path>` or `config: none` and
  nothing else (`ipc::config_line`, `ipc::config_source`, which accepts only
  an absolute path). The GUI worker sends it right after each `list` that
  finds the agent running, in the same 2-second poll, and passes the answer
  (`gui/src/agent.rs` `Config`) to the loaders. An absolute path from the
  agent replaces the default path; `none` means no file; a stopped or
  unreachable agent, an error such as `invalid request` from an older agent,
  or any other answer leaves the default path in use. Gateways, agent
  settings, the device key name, the add-gateway name check and Open config
  file use that path. Settings shows the path, with a fixed note when it is
  not the default one or when the agent loaded no file. The GUI only reads
  the file and opens it in the system's editor on request; it never writes
  it. This is unit-tested but has not been tried on a real Windows desktop.
- Settings shows whether the agent starts at sign-in, read-only. On Windows
  `gui/src/win/run.rs` reads the installer's `Gateinto` value in
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with the same
  helper as the app's own `Gateinto App` value, and `settings::agent_start`
  decides the state without Windows calls: On for a program named
  `gateinto.exe` followed exactly by `agent --detach`, Off for no value, and
  Unknown for any other command or a read error. Each state is a fixed
  translated text; the value and its path are never shown. A fixed note says
  the installer sets it (`AUTOSTART=1`). The GUI has no control for it and
  never writes, creates or deletes the value. It reads it when Settings is
  selected and, while Settings stays selected, on worker updates at most once
  per 2-second poll (`settings::reread`); there is no extra timer. Demo mode
  shows a fixed On and never reads the registry. The app's own switch is
  labelled as starting the app, not the agent. This is unit-tested but has
  not been tried on a real Windows desktop.
- The GUI removes a gateway added from a link without the agent: its gateway
  details offer Remove only when the listed gateway's source is the link
  store (a config gateway, including one that shadows a linked entry of the
  same name, has no such control). A confirmation dialog names the gateway
  as the list shows it, with Cancel first in the tab order. Confirming reads
  the config file from the same path as the list and calls
  `LinkedStore::forget_gateway` on `store::default_dir()`, the decision
  `gateinto gateway forget` uses: a name in the config file, a name held by
  several files, a damaged entry or a missing name removes nothing, and an
  unreadable config file or store refuses too. Each refusal maps to a fixed
  message in the dialog (`gui/src/remove.rs`), never the error, which can
  hold paths. Only that gateway's file is deleted. Sessions are not stopped,
  as with the command line. The list changes at the next 2-second poll. Demo
  mode only shows a fixed note. This is unit-tested but has not been tried
  on a real Windows desktop.

## Modules

| Path | Role |
| --- | --- |
| `src/main.rs` | Command line (`check-upstream`, `session browser`, `session list`, `session close`, `session credentials`, `agent`, `open`, `stop`, `gateway list`, `gateway forget`, `uri register`, `uri unregister`, `key init`, `key info`, `setup`, `status`, `reset`), the default config file location, merging flags over the configuration file, logging setup, building `proxy::Config`, starting a browser session, the agent's `Profiles` from the configuration file, starting a detached agent for `open`, Ctrl+C handling. |
| `src/lifecycle.rs` | `setup`, `status` and `reset` helpers: service account refusal and the elevation note, handler and gateway reporting (with their source), the files a config purge deletes, the purge warning and confirmation, and the purge order (confirm the SPKI, stop the agent, delete the key). |
| `src/uri.rs` | Strict parser for `gateinto://` launch URIs and their canonical form. |
| `src/link.rs` | Gateway addresses and portal origins, the resolution of a link against known gateways, and the confirmation text. |
| `src/link/store.rs` | The per-gateway files in `gateways/`: file names from canonical addresses, safe loading, adding, forgetting (with the `gateway forget` decision shared with the GUI) and purging. |
| `src/prompt.rs` | The confirmation in `gateinto open`: Windows message box, terminal prompt or refusal; the session credentials notice (message box, terminal or not shown); failed URI launch notifications on interactive Windows desktops without a persistent terminal or redirected stderr. |
| `src/ipc.rs` | Agent requests and responses, their line encoding, the per-user named pipe or Unix socket endpoint, server and client. |
| `src/agent.rs` | The agent: launch validation, rate limit and session cap, browser sessions and their watch tasks, `list`, `close`, `stop`, sweeping stale profiles. |
| `src/browser.rs` | Chrome and Edge discovery, browser arguments, process start, marked per-session profile directories and their safe deletion. |
| `src/registration.rs`, `src/registry.rs` | The URI handler command string and its per-user registration in `HKCU\Software\Classes` (registry calls on Windows only). |
| `src/config.rs` | TOML configuration file (`serde`, `toml`, unknown keys rejected), gateway profiles (with their validated `portal_url`) and their lookup by name, the refusal of the removed `[device_session]` section, the `[browser]` executable, flag-over-file merge, defaults, relative path resolution. |
| `src/dns.rs` | Process-wide admission for queued/running OS DNS work, blocking-job-owned capacity, IP-literal bypass and resolved socket addresses shared by routing and gateway connections. |
| `src/sessions.rs` | `SessionManager`: starting a session (its own client certificate, TLS configuration and listener) and closing it (listener dropped, its tunnels aborted). |
| `src/check.rs` | `check-upstream`: one connection to the upstream, report of the negotiated TLS parameters, optional `CONNECT`. |
| `src/http.rs` | Strict parsers for the local `CONNECT` request and the upstream response head. Pure functions over byte buffers, no I/O. |
| `src/proxy/mod.rs` | Listener and accept loop of one session, until it is closed; connection limit, local authentication hook, per-connection state machine, upstream connect and post-handshake TLS mode check (`Endpoint`, shared with `check.rs`), status mapping, error responses. |
| `src/proxy/session_credentials.rs` | `session_credentials` local proxy authentication of one session: credential generation, realm, strict Basic and base64 parsing, keyed constant-time comparison with the issued credentials, failure rate limit. |
| `src/proxy/local_auth.rs` | The configured local authentication methods (`LocalAuth`) and the per-connection decision between `os_user` and `session_credentials`. |
| `src/proxy/os_user.rs`, `src/proxy/os_user/windows.rs` | `os_user`: denial reasons, the owner lookup interface, TCP table row matching, and the Windows lookup of the owning process, its user SID and its job. |
| `src/job.rs` | Job objects for browser sessions and starting a process inside one (Windows only); command-line quoting. |
| `src/token.rs` | The current process token and the user SID of a token (Windows only), shared by the named pipe, the elevation check and `os_user`. |
| `src/proxy/h2.rs`, `src/proxy/pool.rs` | Flow-controlled HTTP/2 CONNECT streams and the session's lazy upstream connection pool, on-demand PING liveness checks, certificate rotation and owned connection drivers. |
| `src/proxy/routing.rs` | Per-session gateway/mixed mode, local DNS/IP comparison and bounded direct TCP attempt before gateway fallback. |
| `src/proxy/relay.rs` | Bidirectional copy between client and upstream with an idle timeout that any traffic in either direction resets. |
| `src/tls.rs` | TLS modes and their key exchange groups, the post-handshake negotiation check, the TLS 1.3 client configuration, the client certificate resolver; default roots from `webpki-roots`; loading `--ca-file` PEM bundles. |
| `src/identity/` | Device key lifecycle including the confirmed purge (`device_key.rs`), client certificate selection and binding to the device key (`client_cert.rs`, `x509.rs`), self-signed client certificates issued and renewed with the device key (`certificates.rs`), CNG status classification, and the Windows CNG store (`windows_cng.rs`, `cfg(windows)` only). |
| `gui/src/remove.rs` | The GUI's Remove for gateways added on this device: which gateways offer it, the confirmation text and the fixed refusal messages. |
| `gui/src/settings.rs`, `gui/src/win/run.rs` | The GUI's Settings page: config values, the app's own sign-in value, which it reads and writes, and the installer's agent sign-in value, which it only reads and maps to On, Off or Unknown. |
| `gui/src/start.rs` | The GUI's Start agent: finding `gateinto.exe` next to the GUI, the `agent --detach` command and the bounded wait for it. |

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
| `session_credentials`: no credential, another scheme, or a credential other than the issued one | `407` with `Proxy-Authenticate: Basic realm="<session realm>", charset="UTF-8"` |
| `session_credentials`: malformed `Basic` credential or repeated `Proxy-Authorization` | `400` |
| `session_credentials`: 10 failures within 60 s | `429` with `Retry-After`, until the 60 s are over |
| `os_user` denied, with `session_credentials` offered too | as `session_credentials` without a credential: `407` with the `Basic` challenge |
| `os_user` denied, as the only method | `403` |
| `os_user` lookup not finished within the connect timeout | `408` |
| Request header block over the limit | `431` |
| Request not complete within the connect timeout | `408` |
| Too many connections | `503` |

Error responses have no body and close the connection.
[troubleshooting.md](troubleshooting.md) explains each status from the user's
side.

## Limits

| Limit | Configuration key | Default |
| --- | --- | --- |
| Concurrent connections per session, including those still sending their request | `[limits] max_concurrent_tunnels` | 64 |
| Request and upstream response header block | `[limits] header_max_bytes` | 16384 bytes |
| The `os_user` check and reading the local request together | `[limits] connect_timeout_seconds` | 10 s |
| Upstream TCP connect, TLS handshake and `CONNECT` reply together | `[limits] connect_timeout_seconds` | 10 s (separate budget) |
| Tunnel without traffic in either direction | `[limits] idle_timeout_seconds` | 300 s |
| `session_credentials` failures before `429` (`Limits::local_auth_failures`); `os_user` denials are not counted | none | 10 within 60 s |
| `Proxy-Authorization` Basic token | none | 1024 base64 characters |

Limits apply to each session separately and come only from the configuration
file. `Proxy::bind` refuses every listen address that is not loopback; no flag
or configuration key changes that.

## Configuration

Settings come from command line flags, then the `--config` TOML file, then
built-in defaults, resolved key by key. Gateway flags apply to the gateway in
use: the one named by `--gateway`, or the only configured one; with several
configured, `--gateway` is required. The upstream host
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
