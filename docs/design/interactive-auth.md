# Design: certificate-bound interactive authentication

Status: design decided, not implemented. The decisions are listed in
[Decisions](#decisions). None of the behaviour it expects from gateways,
identity products, browsers or Windows has been tried; what must be checked
first is under [Needs verification](#needs-verification). Names marked
*(proposed)* do not exist in the code yet; every other name refers to code on
`master` at the time of writing.

## Summary

A gateway that does not yet trust a device can refuse a `CONNECT` with
`407 Proxy Authentication Required` and a `Gateinto` challenge naming a
verification page and a short pairing code. The verification URL carries the
SHA-256 fingerprint of the client certificate Gateinto presented in that TLS
handshake. Gateinto checks that the challenge came from the authenticated
gateway, that the fingerprint matches the certificate actually sent on that
connection, and that URL and code are well formed. Only then does it offer the
verification to the user: in the GUI as a dialog with origin, pairing code,
countdown and a locally drawn QR code, and on the console for in-process CLI
sessions. The user completes verification in the system default browser and
retries from the original application.

Nothing changes for the local application: an upstream `407` is still a local
`502`, nothing is replayed, and no request is held open while the user
verifies.

## Problem

A gateway can identify a device by its client certificate (see
[client-cert.md](../protocol/client-cert.md)), but today it cannot ask the
user to bind an unknown certificate to an account. Gateinto discards every
upstream response header ([http-connect.md](../protocol/http-connect.md)), so
the only signal a refusing gateway can send is a status code, which becomes a
local `502` (or `403`) with no hint for the user. A gateway that wants a
device-registration step needs a channel to name the page and the code, and
Gateinto must make sure that channel cannot be abused by tunnelled content or
by a gateway on a different connection.

## Goals

- Send `User-Agent: Gateinto/<version>` and `Gateinto-Auth-Version: 1` on every
  `CONNECT` to the gateway, so the gateway knows the client can show a
  challenge.
- Recognise a `Gateinto` challenge in an upstream `407` on the `CONNECT`
  response, over HTTP/1.1 and HTTP/2.
- Validate the challenge completely before anything is shown, including the
  binding to the client certificate of that handshake.
- Show the verification in the GUI (agent sessions) and on the console
  (in-process sessions), with the verification origin prominent.
- Treat the URL and the pairing code like session credentials: never logged,
  never on disk, never in ordinary list output.

## Non-goals

- Status polling, a transaction id, callbacks, remote cancel, request signing
  beyond the existing client certificate, or OIDC tokens. Completion is
  user-driven.
- Holding, retrying or replaying the refused `CONNECT`. The application
  retries.
- A Retry button.
- A push channel from the agent to the GUI, toast or balloon notifications.
- Challenges for direct tunnels on the mixed route, which never reach the
  gateway.
- Challenges in tunnelled traffic, in `403` bodies, or anywhere other than
  the gateway's own `CONNECT` response.
- Preventing a user from completing an attacker's verification on an
  attacker's page; device registration, transaction binding and redirects
  belong to the identity product (see [Security](#security)).

## What exists today

- `request_tunnel` in `src/proxy/mod.rs` writes exactly
  `CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n`; no other request
  header is sent.
- `h2::request` in `src/proxy/h2.rs` builds the HTTP/2 `CONNECT` with method,
  version and authority only. `Pending::response` returns
  `response.status().as_u16()` and drops the headers.
- `check-upstream` (`src/check.rs`) calls `request_tunnel` with
  `http::parse_status_line` on HTTP/1.1, and `h2::request(...).response()` on
  HTTP/2. It never prints upstream headers.
- `http::parse_response`, used only by the pool's legacy path
  (`Pool::legacy`), checks the status line and that every field is a token
  name with field bytes, then discards the fields. The head is bounded by
  `max_header_bytes` (`DEFAULT_MAX_HEADER_BYTES`, 16384); `h2::connect` sets
  `max_header_list_size` to the same value.
- `UpstreamError::Status(u16)` carries a non-2xx status;
  `local_status` maps `403` to `403` and everything else to `502`. The
  [status mapping](../architecture.md#status-mapping) states that an upstream
  `407` becomes `502` and that upstream headers and body are not forwarded.
  `Shared::handle` logs `upstream refused tunnel` with the target and error.
- The local `407` with `Proxy-Authenticate: Basic realm="..."` is used only by
  `session_credentials` local authentication. Terminal sessions use `os_user`
  only and answer `403` or `408`, never `407`.
- `ClientCertificateResolver` (`src/tls.rs`) records the certificate it hands
  to rustls in `sent` when a signature scheme matches; `sent_certificate()`
  returns it for every certificate source. `connection_certificate()` is for
  self-signed change detection only. `Endpoint::client_certificate.fresh()`
  gives each new TLS connection its own resolver
  (`src/proxy/pool.rs`), so `sent_certificate()` of that resolver is a
  snapshot of one handshake.
- The pool's `Connection` keeps its `resolver`
  (`Arc<ClientCertificateResolver>`, the per-connection one) and
  `certificate` (from `connection_certificate()`), which moves new streams to
  a fresh connection after a self-signed renewal. In `Pool::open` the HTTP/2
  path clones `liveness` and then calls `drop(state)` before awaiting the
  response, so `state.current` can be replaced while a response is pending.
  Legacy HTTP/1.1 tunnels open one TLS connection each; `State::register`
  takes the resolver and hands back the TLS stream, and `Pool::legacy`
  receives only the stream, the target and `max_header_bytes`.
- `ClientCertificate` is `Fixed` (file or `CurrentUser\My`, unchanged for the
  session) or `SelfSigned` (renewed after 12 h; `certificates.current()` is the
  latest).
- `sha256_fingerprint` (`src/identity/encoding.rs`) returns lowercase hex of
  the SHA-256 of a DER blob; `check-upstream` prints it as
  `client-certificate-sha256`.
- `routing::attempt` opens direct tunnels on the mixed route without any
  upstream TLS.
- The IPC protocol (`src/ipc.rs`) has `credentials {id}`; the agent answers
  with `listen:` and the credential lines. `SessionInfo`
  (`ipc-types/src/lib.rs`) uses `serde(default)` and has no
  `deny_unknown_fields`, so an optional field is compatible in both directions.
- The GUI polls `list` every `worker::POLL` (2 s). Show credentials sends
  `Command::Credentials(id, ticket)`; `credentials::Dialog` accepts only the
  reply for its id and ticket, ends when the session's start, listen address
  or auth change, and zeroizes on close. `device::copy_secret` excludes the
  text from clipboard history and cloud clipboard and returns the clipboard
  sequence number; `clear_secret` empties the clipboard only if that number
  is unchanged. Switching pages drops the dialog and the copied secret.
- The approval dialog (`gui/src/approval.rs`) maps Enter, Space and Escape to
  Deny, so Allow is mouse-only.
- The GUI opens the portal with `sys::open_https`, which checks
  `menu::https` and calls `ShellExecuteW(hwnd, "open", url, NULL, NULL,
  SW_SHOWNORMAL)`. `shell32.dll ShellExecuteW` is in
  `.github/scripts/win7-gui-imports.txt`; `shell32.dll ShellExecuteExW` is
  not. The GUI never calls `CoInitializeEx`.
- `GatewaySection` (`src/config.rs`) holds per-gateway settings, including
  `portal_url`, which a link can also carry (`src/link.rs`); `ConfigFile`
  uses `deny_unknown_fields`. `PortalUrl` accepts an `https://` URL of at
  most `MAX_LEN` bytes from `0x21` to `0x7e` except ``"<>\^`{|}``, with a
  host and no userinfo.
- `prompt::show_credentials` (`src/prompt.rs`) writes credentials to standard
  error only when it is a terminal (`is_terminal()`), and otherwise reports
  that they were not shown; the `test-hooks` feature redirects the text to
  `GATEINTO_TEST_CREDENTIALS_FILE`.
- Logging uses `EnvFilter` from `RUST_LOG` to standard error (default `warn`
  for in-process sessions); the agent's logbook records `info` and above.
- The version string is `VERSION` in `src/main.rs`:
  `GATEINTO_BUILD_VERSION` if set at build time, else `CARGO_PKG_VERSION`.
- Fuzz targets live in `fuzz/fuzz_targets` (`connect-head`, `ipc-line`,
  `launch-uri`, `session-credentials`, `x509`); the fuzz crate depends on the
  `gateinto` library only, with its own `fuzz/Cargo.lock`.

## Protocol

### Request headers

Every `CONNECT` Gateinto sends to the gateway carries two headers that
Gateinto generates itself. Local request headers are not forwarded today and
are still not; the two values never come from a local client.

HTTP/1.1, in this order:

```
CONNECT example.com:443 HTTP/1.1
Host: example.com:443
User-Agent: Gateinto/<version>
Gateinto-Auth-Version: 1
```

HTTP/2: `user-agent: Gateinto/<version>` and `gateinto-auth-version: 1` as
regular fields of the `CONNECT` request (lowercase, as RFC 9113 requires).

`<version>` is the same string `gateinto --version` prints. `VERSION` moves
from `src/main.rs` into the library *(proposed: `gateinto::VERSION`)*; a
compile-time check rejects a `GATEINTO_BUILD_VERSION` that is not an RFC 9110
token, so the header can always be written. `Gateinto-Auth-Version` is `1`;
it is a protocol number for this challenge format only, not a product
version.

`check-upstream` sends the same headers, because it calls the same
`request_tunnel` and `h2::request`; it keeps printing only the status (see
[Open questions](#open-questions)).
Direct tunnels send nothing upstream, so they carry no headers.

### Challenge

The gateway answers before the tunnel is established:

```
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Gateinto auth_uri="https://verify.example.test/device?x=1&cert_sha256=<64 hex>",
    user_code="WDJB-MJHT", expires_in="300"
Cache-Control: no-store
```

(The line break is for display; the field is one line.) The challenge has
exactly three required parameters:

| Parameter | Value |
| --- | --- |
| `auth_uri` | absolute `https` URL of the verification page, at most 2048 bytes, see [Client validation](#client-validation) |
| `user_code` | pairing code, `XXXX-XXXX` from `BCDFGHJKLMNPQRSTVWXZ` |
| `expires_in` | seconds, decimal, at least `1`; Gateinto clamps values above `600` to `600` |

Gateinto does not require `Cache-Control: no-store`: it keeps no cache, and the
challenge is never stored beyond its expiry, so the field changes nothing on
the client.

### Parsing

The parser *(proposed: `proxy::challenge`)* follows the RFC 9110
`Proxy-Authenticate` grammar:

- All `Proxy-Authenticate` field lines are combined in order, as a
  comma-separated list. Other fields are only checked as today.
- A field value is a list of challenges; each is `auth-scheme` optionally
  followed by `token68` or a list of `auth-param`. Empty list elements (`, ,`)
  and optional whitespace around commas are allowed, and so is bad whitespace
  (`BWS`) on both sides of `=` in an `auth-param`. Scheme and parameter names
  compare case-insensitively. Values are `token` or `quoted-string`, with
  `quoted-pair` unescaped once.
- Other schemes are skipped. If the combined value does not parse, no
  challenge is recognised.
- A `Gateinto` challenge is invalid if it uses `token68`, repeats a parameter
  (compared case-insensitively, so `user_code` and `USER_CODE` are a
  repetition), or misses or has an invalid value for one of the three
  parameters. Unknown parameters are ignored.
- More than one `Gateinto` challenge in the response makes the whole response
  invalid, even if they are identical.
- The whole head stays within `max_header_bytes`, as today. Value limits
  (the 2048 bytes of `auth_uri`) apply to the value after `quoted-pair`
  unescaping.

Only a `407` is parsed for a challenge. Any other status keeps today's
behaviour; a `Gateinto` challenge on a `401`, `403` or `2xx` is ignored.

On HTTP/1.1 the legacy path replaces `parse_response` with a response parser
*(proposed: `http::parse_tunnel_response`)* that returns the status and, for
`407`, the `Proxy-Authenticate` values. `parse_status_line`, which
`check-upstream` uses, is unchanged. The body of a `407` is not read: the TLS
connection is closed, as for every refused legacy tunnel. On HTTP/2,
`Pending::response` returns the status and, for `407`,
`headers().get_all("proxy-authenticate")`; the stream is dropped and the
connection stays in the pool. `check-upstream` ignores the returned values.

## Client validation

Every check below runs before the challenge is stored. A challenge that fails
any check is treated as a plain `407`: local `502`, nothing shown, nothing
opened, no fallback to another source of URL or code. A fixed reason without
values is logged at `debug` (see [Agent behaviour](#agent-behaviour)).

### Origin of the challenge

- The challenge is read only from the gateway's response to Gateinto's own
  `CONNECT`, after the gateway's TLS certificate was verified by the
  session's `Endpoint` (`verify_negotiated` included). Bytes after a `2xx`
  belong to the tunnel and are never inspected.
- A client certificate must have been presented in that handshake:
  `sent_certificate()` of that connection's resolver is `Some`. If the
  gateway did not request one, if no certificate is configured, or if the
  optional self-signed mode connected anonymously, the flow is unavailable
  and the `407` is plain.

### Certificate binding

- The fingerprint is `sha256_fingerprint` of the leaf DER in the
  `sent_certificate()` snapshot of the TLS connection that carried this
  `CONNECT`. It is not the session's current certificate, not the SPKI, and
  not a certificate issued later by a renewal.
- No new field is needed: the per-connection resolver already is the
  snapshot holder. HTTP/2: `Pool::open` clones `current.resolver` next to
  `liveness`, before `drop(state)`, and reads `sent_certificate()` from that
  clone when a `407` arrives; a connection that replaces `state.current`
  meanwhile does not affect it. Legacy: `Pool::open` keeps a clone of the
  resolver it passes to `State::register` and passes it on to `Pool::legacy`
  *(new parameter)*. The existing `certificate` field, used for renewal
  detection and `None` for `Fixed` sources, is not used.
- The `auth_uri` query must contain exactly one key `cert_sha256`, and its
  value must equal that fingerprint.

### `auth_uri`

The URL is checked as a byte string; it is never normalised, and the string
that passed is the one that is shown, encoded into the QR code and handed to
the browser. The rules keep the URL inside what both RFC 3986 and the WHATWG
URL parser that browsers use read the same way, and keep it safe as a single
command-line argument (see [GUI](#gui)).

- At most 2048 bytes, after `quoted-pair` unescaping.
- Only RFC 3986 URI characters: letters, digits, `-._~`, `:/?[]@`,
  `!$&'()*+,=`, and `%`. This excludes space, control characters, non-ASCII
  and at least everything `PortalUrl` excludes (``"<>\^`{|}``). `#` is
  excluded (no fragment) and so is `;` in the query (see below).
- Scheme `https`, case-insensitive, followed by `//` and an authority that
  ends at the first `/`, `?` or the end of the URL.
- The authority has no userinfo (`@` does not appear in it) and an optional
  port of one to five decimal digits without a leading zero, in `1` to
  `65535`. The effective port is `443` without a port.
- The host is one of:
  - a registered name: labels of 1 to 63 letters, digits and `-`, not
    starting or ending with `-`, separated by single dots; no empty label, so
    no leading, trailing or doubled dot; at most 253 bytes. If the last label
    is all digits, or `0x` followed by hex digits, the host must be a valid
    IPv4 address, because WHATWG parses it as one;
  - an IPv4 address: four decimal octets `0` to `255` without leading zeros;
  - a bracketed IPv6 address in RFC 4291 text form, without a zone
    identifier.
  `%` never appears in the host.
- `[` and `]` appear only around an IPv6 host.
- Every `%` is followed by two hex digits. The path is split on `/`, the
  query on `&` and then on the first `=`; each segment, key and value is
  percent-decoded once, and none may then contain a control character
  (`0x00` to `0x1f`, `0x7f`).
- `;` in the query is rejected, because some servers treat it as a pair
  separator like `&`, and the server and Gateinto would then disagree on how
  many `cert_sha256` keys there are.
- Keys are compared after decoding. A key equal to `cert_sha256` must appear
  exactly once, and its raw value must be 64 lowercase hex characters, so the
  raw and decoded values agree. A key that equals `cert_sha256` or `user_code`
  only ASCII-case-insensitively, or any key that decodes to `user_code`, is
  rejected.
- The origin is `https://<host>[:<port>]` with the host lowercased, an IPv6
  address in its canonical RFC 5952 form, and the port omitted when it is
  `443`. A Punycode name stays visible as Punycode.
  The origin is checked against the gateway's `verification_origins`
  *(proposed)* if that is set (Decision 1).

### `user_code` and `expires_in`

- `user_code`: exactly nine bytes, four uppercase letters from
  `BCDFGHJKLMNPQRSTVWXZ`, `-`, four more. Lowercase is rejected.
- `expires_in`: one to ten decimal digits without a leading zero, so `0` is
  rejected. A value above 600 is clamped to 600 (Decision 16). The deadline
  is the receipt time on a monotonic clock (`tokio::time::Instant`) plus the
  clamped value; network delay is not compensated.

## Agent behaviour

The same logic runs in every process that hosts sessions: the agent, and the
CLI for in-process `session browser` and `session terminal`.

### Refused tunnel

A valid challenge becomes `UpstreamError::Challenge` *(proposed)*. The
challenge is entered in the session's store before `Shared::handle` writes the
local response, so a client that retries right after its `502` finds the
session already marked. It then maps to a local `502`, exactly as
`Status(407)` does; the local client never sees a `407`, a
`Proxy-Authenticate` field or any challenge value. The
`upstream refused tunnel` log line keeps its target and shows the error as a
fixed text (`gateway asks for interactive verification`), without URL, code or
fingerprint. The refused `CONNECT`, its `permit`, and any early data from the
client are dropped as for every refused tunnel; nothing is replayed.

Only gateway-routed `CONNECT`s can be challenged. Direct tunnels on the mixed
route, routing refusals, local authentication (including the `Basic` `407` and
the `os_user` `403` and `408`), and established tunnels behave exactly as
today.

### Pending challenges

Each session owns a bounded store *(proposed: `Verifications`)*, shared with
its proxy like `OpenTunnels`. An entry holds the fingerprint, `auth_uri`,
`user_code`, deadline, the affected targets, counters for further targets and
suppressed challenges, and a serial number assigned by the session that
increases with every new entry.

The session's *current certificate* is the leaf of `certificates.current()`
for a `SelfSigned` source and the fixed leaf for a `Fixed` source. A handshake
renews a self-signed certificate before it is sent, so the newest handshake's
certificate is the current one.

A validated challenge with fingerprint F is applied in this order; the first
rule that matches decides:

1. An entry whose deadline has passed, or whose fingerprint is no longer the
   current certificate's, is removed.
2. If F is not the current certificate's fingerprint (a stream on a
   connection from before a renewal), the challenge is dropped.
3. If the pending entry has the same fingerprint, `auth_uri` and
   `user_code`, the target is added if it is new, up to 8 distinct targets;
   further ones are counted. Deadline, code and serial stay.
4. If an entry is pending, the challenge is counted as suppressed and
   dropped: the first is kept until it expires or is dismissed. At most one
   challenge is pending per session.
5. If the agent already holds 16 pending challenges across all sessions, the
   challenge is counted as suppressed in its session and dropped.
6. Otherwise it becomes the pending entry with a new serial.

Rule 1 is how a renewal replaces an entry: the old entry goes because its
fingerprint is no longer current, and a challenge for the new certificate
becomes pending under rule 6. A replacement therefore only happens when the
new fingerprint equals the session's current certificate.

Expiry is both swept and checked: the store arms one
`tokio::time::sleep_until` for the pending entry's deadline and removes the
entry when it fires, and every read also applies rule 1, so an entry is never
returned after its deadline even if the timer is late. An entry is also
removed when the user dismisses it, when the session closes, and when the
agent or CLI process stops. Removal zeroizes URL and code. Nothing is written
to logs, the logbook, telemetry, configuration or any file.

Dismissal is local: it removes the entry in this process and tells the
gateway and the identity product nothing; the transaction on their side runs
until it expires there.

A repeated `407` after the user retried is handled the same way: if it is
identical it only adds the target, and if it is new after the old one expired
it becomes pending. Nothing ever opens a browser by itself.

### In-process CLI

`gateinto session browser` and `gateinto session terminal` without `--agent`
print each newly pending challenge once to standard error, but only when
standard error is a terminal (`is_terminal()`), the same rule
`prompt::show_credentials` applies to credentials:

```
verification required for gateway <name>
  target: example.com:443
  verify at: https://verify.example.test
  link: https://verify.example.test/device?x=1&cert_sha256=...
  pairing code: WDJB-MJHT
  expires in: 300 s
Complete verification, then retry the connection.
```

When standard error is redirected, the CLI prints only the fixed line
`verification required for gateway <name>; not shown because standard error
is not a terminal`, with the gateway name, which is a validated
`GatewayName`, and no URL, code, origin or target. Under the `test-hooks`
feature, `GATEINTO_TEST_VERIFICATION_FILE` *(proposed)* receives the full
text instead, like `GATEINTO_TEST_CREDENTIALS_FILE`.

Every printed value has passed validation, so it is printable ASCII; targets
come from `parse_connect_request`. The printer still replaces any byte outside
`0x20` to `0x7e` with `?` so no terminal control sequence can reach the
console. No browser is opened and no QR code is printed.

## IPC, GUI and CLI surface

### IPC

- `SessionInfo` gains `verification: bool` *(proposed)*, `serde(default)` and
  skipped when false. The `list` reply carries only this flag, never URL,
  code, origin, serial or fingerprint.
- `verification {id}` *(proposed)* returns, for a pending challenge:
  `challenge: <serial>`, `gateway: <name>`, `origin: <origin>`,
  `auth_uri: <url>`, `user_code: <code>`, `expires_in: <remaining seconds>`,
  one `target: <authority>` line per target, `more_targets: <n>` and
  `suppressed: <n>`. Errors are `no session {id}` and
  `session {id} has no pending verification`. The reply fits well within
  `MAX_RESPONSE_BYTES`.
- `dismiss {id} {serial}` *(proposed)* removes the pending challenge only if
  its serial matches, so a dismissal cannot remove a challenge the user has
  not seen.
- Rejected requests are logged as today; the agent's log line for a
  `verification` request names the session id only.

### GUI

- A session row with `verification` set shows a fixed "Verification
  required" marker and a "Show verification" action; the tray tooltip says
  that a session needs verification. Nothing opens by itself.
- "Show verification" works like Show credentials: the window increments its
  ticket, opens a dialog *(proposed: `verification::Dialog`)* and sends
  `Command::Verification(id, ticket)` *(proposed)*. The dialog accepts only
  the reply for its id and ticket and remembers the reply's serial.
- While the dialog is open, the worker sends the same ticketed
  `verification {id}` once per 2-s poll, together with `list` and never more
  often. The reply is only compared: the dialog ends when the serial differs
  from the remembered one (the challenge was replaced, for example after a
  renewal) or when the agent answers that nothing is pending. Its values are
  zeroized right after the comparison.
- The dialog also ends when the session's start time, listen address or auth
  changes, when the session disappears or its `verification` flag clears, on
  expiry, on page switch, and when the agent stops or restarts.
- The dialog shows, first and largest, the origin with its host lowercased in
  a monospace face, so lookalike characters and Punycode are easy to tell
  apart. When the gateway has a `portal_url` (from the configuration or from
  its link), a fixed line says whether the verification origin is the same as
  the portal's origin or different. Below follow the gateway's display name,
  the targets, the full URL, the pairing code, a countdown from the received
  remaining seconds on the GUI's monotonic clock, the QR code, and the line
  "Complete verification, then retry the connection." All values are drawn
  as plain text through DirectWrite; nothing is interpreted as markup.
- Buttons: "Open verification", "Copy link", "Dismiss" and "Close". "Open
  verification" is mouse-only: Enter, Space and Escape close the dialog, as in
  the approval dialog. "Dismiss" sends `dismiss`; "Close" only closes the
  dialog, and the challenge stays pending in the agent until expiry.
- "Open verification" calls `ShellExecuteExW` *(proposed in `sys`)* with a
  `SHELLEXECUTEINFOW` of: `fMask = SEE_MASK_FLAG_NO_UI`, `hwnd` the main
  window, `lpVerb = "open"`, `lpFile` the validated URL, `lpParameters` and
  `lpDirectory` null, `nShow = SW_SHOWNORMAL`. Windows looks up the `https`
  handler and substitutes the URL into that handler's registered command line
  (typically at `"%1"`). No shell parses it, but the substitution is plain text
  insertion: it is safe only because the validated URL contains no `"`, no
  space and no control character, so it cannot end the quoted argument or
  add one. `SEE_MASK_CLASSNAME` with `lpClass = "https"` was considered; it is
  not used because it reads the `https` class directly and whether that honours
  the user's default-browser choice is unverified (see
  [Needs verification](#needs-verification)); validation already guarantees
  the scheme.
- `ShellExecuteExW` is used rather than the existing `ShellExecuteW` because
  `SEE_MASK_FLAG_NO_UI` suppresses Windows' own error dialogs (such as the
  "how do you want to open this" prompt when no handler is set) in favour of
  Gateinto's fixed text, and because failure is reported as `FALSE` plus
  `GetLastError` rather than through the `HINSTANCE` convention. Any `FALSE`
  return, whatever the error code, shows the fixed text "The browser could
  not be opened."; the code is logged at `debug` without the URL.
- Gateinto does not open the URL through its own proxy, does not pass its
  client certificate, and does not use a session browser or its isolated
  profile.
- "Copy link" uses `device::copy_secret`; the clipboard is cleared with
  `clear_secret` when the dialog ends, only if the sequence number is
  unchanged. There is no copy action for the pairing code (Decision 2).
- The QR code is encoded with error-correction level M; if the URL does not
  fit at M it falls back to L. Levels Q and H are never used, since a
  2048-byte URL does not fit at either. If encoding fails, no QR code is shown
  and a fixed text says "No QR code for this link."; the rest of the dialog is
  unchanged. Encoding uses `qrcodegen-no-heap` with caller-owned buffers held
  by the dialog, so they can be zeroized (Decision 4).
- Errors are fixed texts: verification unavailable, browser could not be
  opened, clipboard failed, no QR code. They never include the URL or code.
- On close and on every ending, URL, code, the QR buffers and the drawn
  module list are zeroized.
- The GUI keeps the 2-s poll; it never polls faster and never starts the agent
  to show a verification.

### CLI for the agent

- `gateinto session list` keeps its table; after it, a line on standard error
  names each session with a pending verification and the command to show it.
  `--json` carries the `verification` field.
- `gateinto session verification <id>` *(proposed)* sends `verification {id}`
  and prints the block shown under [In-process CLI](#in-process-cli) to
  standard error, only when standard error is a terminal; otherwise it prints
  nothing of the challenge and fails with the fixed error `the verification
  for session <id> was not shown: standard error is not a terminal`. It never
  writes to standard output and never opens a browser.

### Configuration

A configuration-file gateway may set:

```toml
[gateways.corp]
verification_origins = ["https://verify.example.test", "https://login.example.test:8443"]
```

Each entry is `https://` plus a host under the same host grammar as
`auth_uri` and an optional port, nothing else: no path, no trailing `/`, no
userinfo, no trailing dot. Entries are stored with the host lowercased, an
IPv6 address in its canonical form, and `:443` dropped. Matching is exact on
the stored host and effective port; there are no prefixes, suffixes,
wildcards or paths. When the key is set, a challenge whose origin is not
listed is invalid. When it is absent, every origin that passes validation is
accepted. An empty list is refused when the configuration loads, because it
would reject every challenge. Links cannot set it, and the GUI never writes
it.

## Security

### Boundary

Gateinto proves to the user that a challenge came from the gateway the
session authenticated, on a connection that presented a specific certificate,
and that the page the user is sent to names that certificate. It cannot
prevent a user from typing an attacker's code into an attacker's page, nor
know what the identity product does with the fingerprint. Device
registration, binding the transaction to the certificate, and redirects after
verification belong to the identity product.

### Trust follows the gateway

By default any valid `auth_uri` from the authenticated gateway is accepted,
and its origin is shown first. This deliberately deviates from issue #88,
which says not to learn trust from the challenge: Gateinto already trusts
that gateway with every tunnelled byte, and a configured origin list would be
a second place to keep in step with the identity product. Where that is not
acceptable, `verification_origins` pins the origins.

Residual risk: a gateway added from a link after one mouse-only confirmation
can present any HTTPS page as its verification page, for example a phishing
page that imitates the organisation's login. Mitigations are the prominent
origin with its lowercased host in a monospace face, the note whether it
matches the gateway's `portal_url` origin, the plain-text rendering, and
`verification_origins` for configuration-file gateways. Linked gateways cannot have an origin list.

### Same-user exposure

Any process of the same user can send `verification {id}` and `dismiss` over
IPC, as it can send `credentials {id}` and `approve` today. This is the
exposure already accepted in the [threat model](../threat-model.md); the URL
and code are no more sensitive than the session credentials such a process
can already read.

### Threat-model additions *(to be made with the implementation)*

| Threat | Mitigation |
| --- | --- |
| Tunnelled content imitates a challenge | Only the gateway's `CONNECT` response is parsed; tunnel bytes and non-`407` responses are never inspected |
| Another server's challenge is replayed through the gateway | The fingerprint must match the certificate sent on this connection; anonymous handshakes disable the flow |
| Challenge bound to a renewed or different certificate | Per-connection snapshot, not the session's current certificate; certificate change clears pending challenges |
| URL with userinfo, fragment, control characters or ambiguous encoding | Byte-level validation; RFC 3986 characters only; a decoded key `cert_sha256` must appear once with a literal lowercase hex value; `;` rejected in the query |
| URL that displays one origin and navigates to another (`\` read as `/` by browsers, odd host forms) | `\` and every `PortalUrl` exclusion rejected; LDH host labels, strict IPv4, bracketed IPv6 only; numeric last labels must be IPv4 |
| Argument injection into the `https` handler's command line | No `"`, space or control character can pass validation, so the substituted URL stays one argument |
| Lookalike verification origin | Host lowercased in a monospace face; exact `verification_origins` match; same-or-different note against the gateway's `portal_url` |
| Pairing code smuggled in the URL | A `user_code` query key is rejected; the QR code holds the URL only |
| Display spoofing or terminal escape sequences | Values are printable ASCII after validation; plain-text rendering; console output sanitized |
| URL and code captured from redirected console output | Printed only when standard error is a terminal; otherwise a fixed line without values |
| Stale dialog shows a replaced challenge | The open dialog re-checks the serial once per poll and ends on a change |
| Phishing verification page from a linked gateway | Origin shown first; `verification_origins` for configuration-file gateways; residual risk documented |
| Flood of challenges | One pending per session, 16 per agent, 8 targets per challenge; extras counted only |
| URL and code leak to logs or disk | Never logged or stored, also at `RUST_LOG=trace` (tested, including `h2` and `rustls`); fixed error texts; zeroized on every ending, QR buffers included |
| Clipboard leak | Same `copy_secret` and `clear_secret` rules as credentials; no code copy |
| Automatic browser opening or loops | Opening is mouse-only and per click; repeated `407`s never open anything |
| Local application learns of the challenge | Upstream `407` stays a local `502`; no header or body is forwarded |
| Version disclosure | `User-Agent` goes to the configured gateway only, inside TLS |
| Same-user process reads or dismisses a challenge | Accepted, same exposure as `credentials` |

## Compatibility

Nothing here has been verified against real gateways or older releases;
"Expected" rows follow from the code and need a check.

| Case | Behaviour | Status |
| --- | --- | --- |
| Gateway that does not know `Gateinto-Auth-Version` or this `User-Agent` | Ignores the unknown request fields, as HTTP intermediaries are expected to; nothing changes | Expected, needs verification |
| Gateway that answers `407` without a `Gateinto` challenge | Local `502`, as today | Expected, by design |
| Newer GUI with an older agent | The `list` reply has no `verification` field, so it reads as `false` and the GUI never sends `verification` or `dismiss` | Expected, by `serde(default)` |
| Older GUI with a newer agent | Ignores the unknown `verification` field; the challenge can still be shown with `gateinto session verification <id>` | Expected, no `deny_unknown_fields` on `SessionInfo` |
| Newer CLI with an older agent | The agent answers `invalid request` to `verification` and `dismiss`; the CLI reports `the agent is too old for verification; restart it`, as it does for `terminal` | Expected, needs a test |
| Configuration file with `verification_origins` read by an older Gateinto | Refused as an unknown key | Expected, by `deny_unknown_fields` |
| `check-upstream` against a gateway that challenges | Prints the `407` status only, as today | Expected, by design |

## Decisions

Numbered in the order the questions were raised during design. Where the
source proposal and these decisions differ, the decision applies.

1. **Trust follows the gateway.** Any valid `auth_uri` from the authenticated
   gateway is accepted and its origin (host and effective port) is shown
   prominently. A configuration-file gateway may set `verification_origins`;
   matching is exact on host and effective port, without prefix, suffix or
   wildcard. Links never set or change it and never carry credentials, CAs,
   TLS settings, certificates or commands; the GUI never writes TOML. This
   deliberately deviates from issue #88's "do not learn trust from the
   challenge"; the residual risk is under [Security](#trust-follows-the-gateway).
2. **URL and pairing code are treated like session credentials.** They are
   available only through an explicit request (`verification {id}`, ticketed
   in the GUI), never logged, never on disk, never in ordinary `session list`
   output; the `list` reply carries a flag only. They are zeroized on dialog
   close, session end, agent stop or restart, page switch, expiry and
   certificate change. GUI errors are fixed texts. Copy link clears the
   clipboard only if the sequence number is unchanged. **The pairing code has
   no copy action:** it is nine characters meant to be read and typed on the
   verification page, the QR code covers the phone case, and leaving it off
   the clipboard keeps it away from clipboard monitors, which
   `copy_secret`'s exclusion formats do not bind.
3. **The browser opens only on an explicit mouse click.** The GUI shows URL,
   origin, code, countdown and QR; "Open verification" is mouse-only and calls
   `ShellExecuteExW` with the URL as `lpFile` and `SEE_MASK_FLAG_NO_UI`; the
   URL is substituted into the handler's command line, which is safe because
   validation leaves no `"`, space or control character in it. Never through
   Gateinto's proxy, never with its client certificate, never in a session
   browser. In-process CLI sessions print sanitized URL and code, only to a
   terminal, and never open a browser. The GUI never starts the agent and never polls faster than
   2 s.
4. **QR code from a pure-Rust encoder.** The GUI uses the `qrcodegen` project's
   encoder without image dependencies, in its `qrcodegen-no-heap` form: the
   heap-based `qrcodegen::QrCode` cannot be zeroized, while the no-heap form
   writes into caller-owned buffers that the dialog zeroizes. The GUI draws
   the modules itself with Direct2D rectangles and a four-module quiet zone.
   Error correction is M, falling back to L; Q and H cannot hold a 2048-byte
   URL. On encoding failure no QR code is shown, with a fixed text. The
   crate needs the usual dependency review (licence, maintenance,
   `unsafe`). It is a GUI dependency only, so it enters `Cargo.lock`; the fuzz
   crate does not depend on the GUI, so `fuzz/Cargo.lock` does not change.
   Any change to packages both lock files share is made in both, since CI
   builds each with `--locked`. No new Windows import is expected from it.
5. **Coalescing keeps the first challenge.** One entry per (session,
   handshake fingerprint, `auth_uri`, `user_code`). Identical repeats add
   targets, at most 8, without touching deadline or code. A different
   challenge while one is pending is counted and dropped: showing several
   codes for one session would make the user guess which one counts, and
   completing one registers the certificate the others name too (an
   assumption under [Needs verification](#needs-verification)). At most one
   pending challenge per session and 16 per agent. A pending challenge is
   replaced only when its fingerprint is no longer the session's current
   certificate and the new challenge's fingerprint is; the precedence is
   listed under [Pending challenges](#pending-challenges).
6. **No Retry button.** The only instruction is "Complete verification, then
   retry the connection."; the application owns the retry.
7. **No push channel.** The 2-s `list` poll carries the `verification` flag;
   details come from `verification {id}`. Any same-user process can send it,
   the same accepted exposure as `credentials`.
8. **Upstream `407` stays a local `502`**, valid challenge or not. The
   challenge is never forwarded and never becomes a local `407`; nothing is
   retained or replayed.
9. **Only gateway-routed `CONNECT`s are challenged.** Direct tunnels, routing
   refusals, local authentication (including terminal sessions' `403` and
   `408`) and established tunnels are unchanged.
10. **An invalid challenge is a plain `407`.** Nothing is shown or opened and
    there is no fallback; a fixed reason without values is logged at `debug`.
11. **The binding uses the per-connection sent certificate**:
    `sent_certificate()` of that connection's resolver, not
    `connection_certificate()`, not the shared `Endpoint` resolver, not the
    session's current certificate.
12. **`User-Agent` and `Gateinto-Auth-Version` go to the configured gateway
    only**, on every `CONNECT`, also from `check-upstream`. The version is
    `gateinto --version`'s string; the auth version is `1` and is not a
    product version.
13. **`Cache-Control: no-store` is not required.** Gateinto keeps no cache,
    so requiring it would only reject otherwise valid gateways.
14. **Lowercase pairing codes are rejected**, so the displayed code is exactly
    what the gateway sent.
15. **CLI output goes to standard error, and only to a terminal.** Standard
    output carries the session lines that scripts may read; a redirected
    standard error gets a fixed line without values, and
    `session verification` fails with a fixed error, as
    `prompt::show_credentials` does for credentials.
16. **`expires_in` above 600 is clamped to 600, not rejected.** RFC 8628
    device flows use lifetimes such as 900 and 1800 seconds; rejecting them
    would turn a usable challenge into an unexplained `502`, while clamping
    only shortens what Gateinto keeps and shows. `0` is still rejected.
17. **The open dialog re-checks its challenge.** While it is open, the worker
    repeats the ticketed `verification {id}` once per 2-s poll; the dialog
    ends when the serial changes or nothing is pending. The `list` flag alone
    cannot show a replacement.
18. **`;` is rejected in the `auth_uri` query**, so Gateinto and a server
    that splits on `;` cannot disagree on the `cert_sha256` key.

## Alternatives rejected

- **Forward the `407` to the local application.** The application would see
  a proxy challenge it cannot answer and might prompt for a password, and the
  terminal sessions' rule of never answering `407` would break.
- **Open the browser automatically.** Any gateway, or anything able to make
  the gateway answer `407`, could open pages on the desktop.
- **Status URI and polling.** More protocol for the gateway, a second request
  channel to secure, and a held local connection; the application retry is
  enough.
- **Bind to the SPKI or the session's current certificate.** A renewed
  certificate has a new key and fingerprint; only the handshake snapshot says
  what the gateway saw.
- **An origin list learned from the first challenge.** It would trust the
  first challenge most, which is the one an attacker would aim for, while
  adding state to keep.
- **QR codes from a web service or an image crate.** A service would see the
  URL; an image crate adds decoders the GUI does not need.
- **Rendering the challenge as HTML or rich text.** Markup is the obvious
  spoofing channel.
- **Several pending challenges per session.** See Decision 5.
- **Copying the pairing code.** See Decision 2.

## Tests planned

### Unit

- Exact HTTP/1.1 request bytes with both headers; HTTP/2 request fields in
  lowercase; no header from the local request appears.
- `gateinto::VERSION` is a token; the compile-time check rejects a bad build
  version.
- Parser: quoted and token values, `quoted-pair`, multiple schemes, multiple
  field lines, empty list elements, whitespace around `=`, case-insensitive
  names, unknown parameters ignored; duplicate parameters (also differing
  only in case), `token68`, missing or invalid values, two `Gateinto`
  challenges and unparsable fields rejected; an `auth_uri` of 2048 bytes
  after unescaping accepted even when its quoted form is longer, and of 2049
  bytes rejected.
- `auth_uri`: every rule under [Client validation](#auth_uri), including
  `cert%5Fsha256`, `CERT_SHA256`, `user_code` and `user%5Fcode` keys,
  uppercase hex, a percent-encoded hash, ports `0`, `0443`, `443`, `65535`,
  `65536`, IPv6 literals with and without a zone identifier, userinfo, `#`,
  malformed `%`, `;` in the query, and a percent-encoded control character
  in a path segment and in a query value.
- Character set: a `"` anywhere (including one that would close a `"%1"`
  argument, such as `https://a.test/"%20--flag`), a space, and each of
  ``<>\^`{|}`` rejected one by one; `\` in the host
  (`https://evil.test\.corp.example/x`) and in the path rejected.
- Host grammar: empty label, leading, trailing and doubled dots, labels
  starting or ending with `-`, a 64-byte label, a 254-byte name, `_` and
  non-ASCII rejected; `1.2.3`, `0x7f.1`, `256.1.1.1` and `01.1.1.1`
  rejected; `127.0.0.1` and `[::1]` accepted.
- `user_code` boundaries; `expires_in` of `0`, `01`, `1`, `600`, `601`
  (clamped to 600), `1800` (clamped) and eleven digits (rejected).
- Origin matching against `verification_origins = ["https://verify.example.test"]`:
  accepted for `verify.example.test`, `verify.example.test:443` and
  `VERIFY.Example.test`; rejected for the suffix `example.test`, the prefix
  form `xverify.example.test`, the appended `verify.example.test.evil`, the
  port `verify.example.test:8443`, and the trailing dot
  `verify.example.test.` (refused by the host grammar). An entry written with
  `:443` matches a URL without a port and the other way round; entries with
  a path, a trailing `/` or dot, a wildcard, userinfo or `http://` are
  refused when the configuration loads; links cannot carry the key.
- The fingerprint is compared with the resolver's `sent_certificate()`; a
  renewed certificate, a `connection_certificate()` value and an anonymous
  handshake do not match.
- Store, rule by rule in the precedence order: identical repeats keep
  deadline, code and serial; target bound; different challenge suppressed;
  a challenge whose fingerprint is not the current certificate's dropped;
  after a renewal the old entry removed and the new challenge pending with a
  new serial; per-agent bound; expiry by the timer and by a read with paused
  Tokio time; dismissal with a stale serial does nothing.
- `local_status` of the new error is `BadGateway`; its display contains no
  URL, code or fingerprint.
- IPC: `verification` and `dismiss` round-trip through `Request::to_string`;
  `SessionInfo` with and without `verification` parses in both directions;
  the CLI maps `invalid request` to the "too old" message.
- Console sanitizer replaces every byte outside `0x20` to `0x7e`.

### Pool

- HTTP/2 reuse: two streams on one connection, each `407` checked against
  that connection's snapshot.
- Two connections: the first stream's response is held until after
  `state.current` has been replaced by a connection with a renewed
  certificate (between `drop(state)` and the response); its challenge
  naming the first connection's certificate passes the binding check, and a
  challenge naming the new certificate does not.
- Legacy: the resolver passed to `Pool::legacy` is the one used for that
  tunnel's handshake.

### Agent

In `tests/agent.rs`, against a test gateway (as in `tests/common` and
`examples/test_upstream.rs`) extended to answer `407` with a challenge over
HTTP/1.1 and HTTP/2:

- The local client gets `502` with no `Proxy-Authenticate`, and the session is
  listed with `verification` by the time the `502` arrives.
- `verification {id}` returns the expected lines; `list` never contains URL or
  code.
- Two concurrent sessions with different certificates on the same gateway: a
  challenge naming session A's certificate, returned on session B's
  connection, is rejected, and neither session is marked.
- A challenge with a wrong fingerprint, a challenge when no client certificate
  was sent, and a direct tunnel on the mixed route leave no pending entry.
- Renewal: with a short certificate lifetime in the test, a pending entry is
  removed after the self-signed certificate renews, a challenge for the new
  certificate becomes pending, and `verification {id}` returns a new serial.
- Log capture: with `RUST_LOG=trace` on the agent and an in-process session,
  standard error and the logbook (`log`) contain neither the URL, the code,
  the fingerprint in the URL, nor the `Proxy-Authenticate` value, over both
  HTTP/1.1 and HTTP/2; this covers `h2`, `rustls` and Gateinto's own targets.
  If a dependency prints them, Gateinto's filter caps that dependency's
  target below the level that does, whatever `RUST_LOG` says.
- Session close and `stop` clear pending entries.

### CLI

In `tests/cli.rs`:

- `session browser` with standard error redirected to a file prints the
  fixed line only: no URL, code, origin or target in the file.
- `session verification <id>` with standard error redirected fails with the
  fixed error and prints none of the challenge; with the `test-hooks`
  `GATEINTO_TEST_VERIFICATION_FILE`, the full text arrives there.
- Standard output never contains the URL or code.

### GUI

- Pure functions in the style of `credentials.rs`: reply matching by id and
  ticket; the re-check ending the dialog when the serial changes and when
  nothing is pending, and keeping it when the serial is unchanged; the
  re-check sent at most once per poll; other ending conditions; key mapping
  (Enter, Space and Escape never open); clipboard clearing by sequence
  number; countdown on a monotonic clock; the same-or-different note against
  `portal_url`.
- QR: the encoder's module matrix for a known URL at M; a URL that needs L;
  the fixed text when encoding fails; the drawing code maps modules to
  rectangles with the quiet zone; buffers zeroized when the dialog ends.
- `win7-gui-imports.txt` gains `shell32.dll ShellExecuteExW` and nothing
  else; `assert-win7-imports.ps1` passes.

### Fuzzing

A new target *(proposed: `fuzz/fuzz_targets/proxy-authenticate.rs`)* drives
the challenge parser and the URL, code and expiry validation through
`src/proxy/fuzzing.rs`. It asserts that an accepted challenge re-validates,
that every accepted value is printable ASCII, and that no accepted
`auth_uri` contains `"`, `\`, space or any ``<>^`{|}`` byte. Its seed corpus
includes the `"` and `\` cases above and one input per excluded character.

### Manual checklist

Results go to `docs/verification.md`: every item under
[Needs verification](#needs-verification).

## Implementation plan

Each step is one pull request into `feat/interactive-auth`, test first.

1. **Request headers.** Move `VERSION` into the library with the token check;
   add both headers to `request_tunnel` and `h2::request`.
2. **Challenge parser and validation.** `proxy::challenge` with the
   `Proxy-Authenticate` parser, `auth_uri`, `user_code` and `expires_in`
   validation and the origin check; `verification_origins` in
   `GatewaySection`; the fuzz target with its `[[bin]]` entry in
   `fuzz/Cargo.toml` and a seed corpus in `fuzz/corpus/proxy-authenticate`.
3. **Handshake snapshot, pending state and IPC.**
   `http::parse_tunnel_response`, header capture on HTTP/2 (with
   `check-upstream` ignoring it), the resolver clone before `drop(state)` and
   the resolver parameter of `Pool::legacy`, `UpstreamError::Challenge`, the
   per-session store and agent bound, `SessionInfo::verification`, and the
   `verification` and `dismiss` requests.
4. **CLI.** Terminal-only printing for in-process sessions, the
   `session list` note and `session verification`, and the "too old"
   message.
5. **GUI.** The marker, the dialog with its per-poll re-check,
   `ShellExecuteExW`, copy link, the `qrcodegen-no-heap` dependency and
   drawing, and the import list.
6. **Docs.** `http-connect.md`, `architecture.md` status mapping,
   `threat-model.md` and `security-model.md` additions, the README command
   table (`session verification`) and status mapping, `docs/compatibility.md`
   evidence, configuration reference, troubleshooting entry, and this
   design's status.

## Open questions

These could not be settled from the code.

- **`check-upstream`.** It sends the new headers; whether it should also say
  that a valid challenge was offered (without printing URL or code) is open.
  The design keeps today's output.
- **`ShellExecuteExW` and the portal.** The portal opener uses `ShellExecuteW`
  through `sys::open_https`. Whether the portal should move to
  `ShellExecuteExW` too, so both use one helper, is left to step 5.
- **Retry on the same HTTP/2 connection.** After verification the
  application's retry may reuse the pooled connection; whether gateways
  re-evaluate the certificate per stream or only per connection is unknown
  (see below). If they need a new connection, the pool would need a way to
  retire a connection after a challenge.

### Needs verification

These are not open design questions; each has a decided answer or fallback
above and must be checked against real gateways, identity products and
systems before it ships. Results go to `docs/verification.md`.

- That a target gateway or identity product sends the challenge in this
  format, binds the transaction to `cert_sha256`, and whether it issues a new
  `user_code` per refused `CONNECT` or reuses one; whether completing one
  code registers the certificate for all of them (Decision 5 assumes so).
- Whether the gateway re-checks device trust on a new stream of an existing
  HTTP/2 connection or only on a new TLS connection.
- That gateways ignore the two new request fields.
- Whether real gateways double-encode `auth_uri` query names or values
  (for example `cert%255Fsha256`); the parser decodes once.
- That rustls records `sent` only for a certificate that is actually sent in
  TLS 1.3 client authentication, also when the server's request is optional,
  and how a server that ignores the certificate looks from the client.
- That the `h2` crate returns every `proxy-authenticate` field of a response
  through `get_all`, and that HTTP/2 gateways send the challenge in the
  response headers rather than trailers.
- `ShellExecuteExW` with an `https` URL on Windows 7, 10 and 11: that the
  default browser opens it, that no Gateinto session browser or isolated
  profile is the `https` handler, how common handlers' registered command
  lines quote `%1`, and what happens when no handler is set.
- Whether `ShellExecuteExW` needs COM initialised on the calling thread
  (`CoInitializeEx`, which the GUI never calls) for the `https` handlers in
  use; the fallback is to initialise an apartment on the GUI thread once.
- Whether `SEE_MASK_CLASSNAME` with `lpClass = "https"` honours the user's
  default-browser choice; if it does, it may be added as defence in depth.
- That a default browser configured by the user to use a Gateinto session's
  local proxy does not loop into another challenge without the user noticing.
- That a QR code for a 2048-byte URL scans reliably on common phones at the
  dialog's size and DPI scales.
- That the monotonic clocks used for the deadline (agent, Tokio) and the
  countdown (GUI) behave sensibly across sleep and hibernation: whether they
  pause, so an entry can outlive its real expiry, or keep running.
- DirectWrite rendering of long URLs, Punycode hosts and the monospace origin
  in the dialog, and the console sanitizer in Windows Terminal, conhost and
  mintty.
- Clipboard behaviour of the copied link with clipboard history and cloud
  clipboard on, as for credentials.
- That the `qrcodegen-no-heap` build adds no imports outside the Windows 7
  allow-list.
