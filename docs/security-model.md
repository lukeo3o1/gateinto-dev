# Security model

What Gateinto protects, how, and what it does not protect. Assets, trust
boundaries and the threat table are in [threat-model.md](threat-model.md);
this page summarizes the mechanisms and points to it rather than repeating
it. Which of these mechanisms are covered by tests is in
[verification.md](verification.md), and
[security-boundaries.md](security-boundaries.md) maps each security acceptance
item to its code, its tests and where they run.

## What it protects

### Routing scope

All traffic received by a session uses the gateway by default. A launch URI
may opt its new browser session into `route=mixed` without changing any other
session or saved gateway. Mixed routing is an IP heuristic, not a policy or
scope guarantee: locally resolved target addresses matching any gateway IP,
empty answers and DNS errors use the gateway; other targets try direct TCP.
Direct opening and DNS share half the total opening timeout before gateway
fallback. A gateway refusal or TLS error never permits a direct retry, and
routes never change after the local success response.

All system DNS work uses one process-wide budget of 64 queued or running
lookups, shared by mixed discovery and gateway connections. Slots belong to
the blocking resolver jobs, not their async waiters, so timeout, cancellation
and session closure do not free capacity while OS work continues. An exhausted
budget rejects new DNS work immediately; mixed mode falls back to the gateway,
and a fresh named gateway without capacity fails closed. IP literals bypass
DNS. Existing OS lookups can still delay process shutdown; their number is
bounded, and the routing deadline does not promise to interrupt them. See
[DNS work budget](protocol/http-connect.md#dns-work-budget).

Mixed mode exposes local DNS queries and the user's source IP, and direct
connections bypass gateway authorization and inspection. Different service
and gateway IPs or shared hosting can misclassify traffic. Any website can
select mixed mode in a link for a known gateway; there is no additional
routing confirmation or locally enforced gateway-only policy. The existing
first-time gateway confirmation discloses mixed routing when requested.
Operators needing all traffic through the gateway must use gateway-mode
links and must not treat this client as an enforcement boundary. Full rules
are in [session routing](protocol/launch-uri.md#session-routing).

The following upstream TLS protections apply to the gateway route. A direct
tunnel carries the browser's own TLS unchanged and uses no gateway client
certificate or Gateinto outer TLS/key-exchange policy.

### The connection to the upstream proxy

- **TLS 1.3 only.** `rustls` is built without its `tls12` feature, so no
  earlier version can be negotiated. After every handshake the negotiated
  version is checked again, and anything but TLS 1.3 refuses the tunnel
  (`502`).
- **Certificate verification is always on.** The upstream certificate and
  name are verified with WebPKI against the Mozilla roots from `webpki-roots`,
  or only against the CAs in `--ca-file` / the gateway's `ca_file`. There is no
  flag or configuration key that disables verification. The name checked is
  `--upstream-server-name`, defaulting to the upstream host.
- **Key exchange modes.** `--tls-mode` / the gateway's `tls_mode` decides which groups are
  offered:
  - `hybrid_preferred` (default): `X25519MLKEM768`, then `X25519`;
  - `hybrid_required`: only `X25519MLKEM768`; an upstream without it fails the
    handshake (`502`), never a downgrade;
  - `classical_only`: only `X25519`.

  The negotiated group is checked after every handshake against the mode's
  list. The hybrid group protects the confidentiality of the outer TLS session
  against later decryption with a quantum computer. Signatures (certificates,
  the device key) are classical ECDSA or RSA, so authentication is not
  post-quantum.
- **Client authentication (mTLS)**, when a certificate for the device key is
  configured. A certificate is only sent if its public key equals the device
  key's; Gateinto never sends a certificate whose private key it does not
  hold. `--client-certificate required` makes a missing or mismatched
  certificate a startup error instead of a warning.
- **No session resumption or early data.** Every upstream connection performs
  a full TLS 1.3 handshake. HTTP/2 tunnels within one Gateinto session share
  that open connection and its authenticated client identity. New TLS
  connections do not resume an earlier TLS session. Self-signed certificate
  renewal rotates new streams to a fresh connection while accepted old
  streams can drain; expiry and renewal failure preserve required/optional
  authentication behavior. See [upstream CONNECT](protocol/http-connect.md).
- **Self-signed client certificates** (`--self-signed-client-cert`). Gateinto
  issues a short-lived certificate (24 hours, renewed after 12 hours) whose
  public key is the device key and which the device key itself signs through
  CNG, as it signs `CertificateVerify`. No other private key is created, and
  the device key is never exported. The signature is verified against the
  device public key before the certificate is used. The certificate proves
  nothing beyond possession of the device key: it is not issued by any CA, and
  an upstream accepts it only if its own policy trusts that public key (for
  example by its SPKI fingerprint). Gateinto does not and cannot make an
  upstream trust it. Fields and trust requirements are in
  [protocol/client-cert.md](protocol/client-cert.md).

### Sessions and gateways

- **Session isolation.** Each session has its own listener, its own TLS client
  configuration and client certificate resolver, its own upstream connections
  and its own limits. With self-signed client certificates each session issues
  its own certificate for the device key, so sessions never present each
  other's certificate; a file or store certificate is necessarily the same in
  every session, since there is one per device key. The device key itself is
  shared: it is the one identity of the machine.
- **Closing a session.** Closing stops accepting at once, drops the listener so
  its port refuses connections, and aborts every tunnel the session has
  established, including every current or draining HTTP/2 connection driver.
  The session's certificate is dropped with it and is not
  reachable from another session, so no new `CONNECT` can use it.
  `gateinto proxy` and `gateinto session browser` run one session each and
  close it on Ctrl+C; the agent closes a browser session when its browser
  exits or on request, and all sessions when it stops.
- **Gateway profiles are local or approved.** An upstream (host, port, server
  name, CA file, TLS mode, client certificate settings) comes from the local
  configuration file or the command line, or, host, port and portal only,
  from a `gateinto://` link that the user explicitly approved (see
  [Launch URIs and the agent](#launch-uris-and-the-agent)). Selecting a
  gateway by name is a lookup in the loaded file and the approved entries; a
  name cannot add a CA or a trust setting, and nothing can change a gateway
  that is already known.

### Launch URIs and the agent

Any website, e-mail or document can open a `gateinto://` link, and with the
handler registered Windows passes it to `gateinto open` without further
checks. Gateinto therefore treats the URI as attacker-controlled. The exact
format is in [protocol/launch-uri.md](protocol/launch-uri.md).

What a launch URI can do, at most:

- make the user's agent start a new browser session for a known gateway,
  selecting default gateway routing or mixed routing, which opens Chrome or Edge with a new, empty profile on that gateway's
  portal or on another page of the same origin;
- for a gateway the device does not know, after the user approves it in a
  dialog that names it: store its host, port and optional portal, then do the above.

How that is bounded:

- **Strict parsing, twice.** `gateinto open` accepts only
  `gateinto://connect?` with the fields `profile`, `auth`, `v`, `url`,
  `gateway`, `portal` and `route`, each at most once, raw characters only from
  `A-Z a-z 0-9 - . _ ~` and percent-escapes, at most 8192 bytes, no fragment,
  user information, port or path. `profile`, `auth`, `route` and `v` decode only to
  `A-Z a-z 0-9 _ -`; `url` and `portal` must be `https://` URLs with a DNS or
  IP host and the same origin; `gateway` must be a plain `host[:port]`. The
  agent parses the forwarded request again with the same rules.
- **No trust setting or secret in the URI.** There is no field for a CA,
  certificate, TLS mode, server name, listen address, credential or command.
  A gateway added from a link always uses the defaults: public (Mozilla)
  roots and the host as server name, so its certificate must be publicly
  trusted for that host name.
- **Start page bound to the portal.** `url` is accepted only on exactly the
  origin (scheme, host, port; 443 when omitted) of the gateway's portal, and
  is refused for a gateway without a portal. It applies to that launch only.
- **Known gateways cannot be changed.** A link that names a known gateway
  with a different host, port or portal is refused; the configuration file
  wins over approved entries and is never written; an address that is
  already known under another name is refused with that name.
- **Address selection preserves trust.** A URI needs a gateway address or
  a legacy profile, not both. Address-only selection compares canonical host
  and port without DNS; a unique match reuses all stored settings. Multiple
  matching profiles require an explicit profile. For unknown addresses a
  deterministic internal name is generated; collisions and damaged entries
  are refused. An omitted portal inherits the stored portal, or leaves a new
  gateway without one. A supplied portal is an exact assertion for an
  existing entry, never an update; `url` cannot invent one.
- **New gateways need the user.** See
  [Gateways added from links](#gateways-added-from-links).
- **No command injection.** The handler command quotes the executable and
  passes the URI after `--`, so the URI is always one positional argument;
  a URI that would split into more arguments is refused by the command line
  parser. Neither `open` nor the agent uses a shell: the browser is started
  with an argument list, and its arguments come from the agent, not the URI.
- **Frequency and volume.** The agent accepts at most 5 launch requests per
  60 seconds (counted whether they succeed, ask for a confirmation or fail)
  and at most 4 open browser sessions, and keeps at most one confirmation
  open at a time. Links beyond those limits cannot open more browser windows
  or gateway confirmation dialogs. Failed Windows desktop URI launches can
  each show a persistent error notification from `open`; those notifications
  are outside the agent's rate and confirmation limits.
- **Per-user endpoint.** The agent listens on a named pipe named after the
  user's SID, created as the first instance, rejecting remote clients, with a
  security descriptor that makes the user its owner and grants access only to
  the user and SYSTEM. Clients refuse a pipe that another user owns. On Unix
  the socket is `0600` in a `0700` directory that must belong to the user.
  The agent answers one short request per connection with size limits and a
  timeout, and clients give up after 60 seconds.
- **Isolation of each launch.** Every launch is a new session with its own
  port, realm, local proxy credentials and client certificate, and a new browser
  profile directory, so a launched browser does not share cookies, cache or
  saved credentials with the user's normal profile or with another launch.
- **Cleanup.** When the browser exits, or on `gateinto session close`,
  `gateinto stop` or Ctrl+C, the session's listener, tunnels, upstream TLS
  connections, local proxy credentials and certificate are dropped and the profile
  directory is deleted. Deletion is limited to directories inside the
  profiles directory that carry Gateinto's marker file and name, does not
  follow links, and never touches other profiles.
- **Registration.** `gateinto uri register` writes only the current user's
  `HKCU\Software\Classes\gateinto`, with quoted absolute paths that cannot
  contain quotes or `%`, and neither registration nor removal changes a
  handler that does not run Gateinto.

### Gateways added from links

The original plan required that a URI never introduce a proxy host. This is
deliberately relaxed, with the user's agreement, so that a gateway's website
can bring its own gateway and optional portal to a user who has no local profile. It
is not silent: nothing is stored or connected before the user approves.

How it is bounded:

- **Explicit first-time confirmation.** Only `gateinto open`, running on the
  user's desktop, asks. On Windows it shows a top-most warning dialog with OK
  and Cancel, Cancel as the default button and no access keys, so no single
  keystroke approves (moving the focus to OK and pressing Enter or Space, or
  clicking OK, does); it names the profile, the gateway `host:port` and
  the portal origin; elsewhere it needs `yes` typed on a terminal; without a
  desktop or terminal it refuses. The agent never prompts, applies the rate
  limit before a confirmation is handed out, keeps one open at a time, and
  accepts an answer only with the one-time 128-bit token of that
  confirmation within 120 seconds. The token ties an answer to the exact
  request the agent validated; it does not prove that a person answered. A
  program running as the user can send `launch` and then `approve` itself,
  but such a program can just as well write a file in `gateways/`, so this
  gives it nothing new. The confirmation protects against websites, not
  against software of the same user.
- **Stored once, never overwritten.** An approved gateway is stored in its
  own file in a separate owner-only directory (`gateways/`, at most 32
  files), named only from its canonical address, written atomically and
  never over an existing file, with only its name, host, port, optional portal and
  approval time. File names are checked to be single plain components; hosts
  that are Windows device names are refused; links and reparse points are
  never followed. A damaged file disables only its own entry and still
  blocks links that name its profile or address. Later links
  with the same values start sessions without asking; links with other
  values for that name are refused. `gateinto gateway forget` removes an
  entry; `gateinto gateway list` and `gateinto status` show the source of
  every gateway.
- **Defaults only.** Public roots, the host as server name, the default TLS
  mode and client certificate mode. A link has no way to supply roots; the
  integration tests inject their test CA only through a build feature that
  release builds do not enable.

What remains:

- **Phishing.** A site can claim to be any organisation and ask the user to
  approve its gateway. The dialog shows the real gateway host and portal
  origin, but a user who approves a hostile gateway sends that isolated
  browser's traffic through it. The browser's TLS still runs end to end to
  each site, so the gateway cannot read HTTPS content, but it learns hosts
  routed to it, can block, delay or misroute those connections, and
  chooses the start page, where it can ask for credentials like any phishing
  site. The browser profile is new and empty, so the user's normal cookies
  and saved passwords are not exposed.
- **Device identity.** With the default `client_certificate = "optional"`, a
  device certificate in `CurrentUser\My` whose key is the device key is
  presented to any gateway that requests one, so an approved gateway learns
  the stable SPKI of the device key and can recognise the device across
  sessions and correlate it with other gateways that see it. Self-signed
  session certificates are off for linked gateways, so the key does not sign
  anything else for them.
- **Programs of the same user.** Any program running as the user can add a
  gateway without a dialog, through the agent's IPC endpoint or by editing
  the files in `gateways/`, as it can edit the configuration file.
- **Approval is permanent until forgotten.** An approved gateway stays
  usable by later links of any site that knows its gateway address or profile.

Mitigations: the confirmation is opt-in per gateway and defaults to Cancel; the
link cannot weaken TLS or change a known gateway; every session is isolated
in a fresh profile; `gateinto gateway list`/`status` make linked gateways
visible and `gateinto gateway forget` removes them. There is no setting yet
to turn gateways from links off; without the `gateinto://` handler no link
reaches Gateinto at all. Manual verification of the
dialog on Windows is not done yet; it is covered by unit tests of its text,
style and answer handling and by integration tests of the agent's side.

### Local proxy authentication (`session_credentials`)

Browser sessions, and the device session unless the configuration sets
`[device_session] auth = "none"` or leaves `session_credentials` out of its
`auth` list, accept the user name and password generated for them when they
start. On Windows browser sessions in a job object also offer `os_user`
([below](#local-proxy-authentication-os_user)), and passing either method is
enough. This is local proxy access
control, not authorization by the upstream, and it does not identify a user.
The trust-on-first-use mode `basic_tofu` it replaces is refused in the
configuration file, in links and in IPC requests with an error naming
`session_credentials`, so an old configuration fails closed instead of
running without local authentication.

Guarantees:

- **Unguessable, per session.** The user name is the fixed `gateinto`;
  browsers show it in clear in their proxy dialog and password manager, so
  all the entropy is in the password. It has 12 symbols, drawn by rejection
  sampling from the system CSPRNG over the 31-symbol alphabet
  `abcdefghjkmnpqrstuvwxyz23456789` and grouped by four (`xxxx-xxxx-xxxx`):
  12 log2 31, about 59.4 bits. Guessing is online only, against the loopback
  port, and capped at 10 failures a minute; there is no stored or transmitted
  hash to attack offline. The alphabet leaves out `i`, `l`, `o`, `0` and `1`
  so that it can be read and typed without confusion. Every session gets a
  new password.
- **An unknown credential never binds.** Nothing is learned from requests:
  the expected value is fixed when the session starts, and a different
  credential, however early it arrives, only gets `407` and counts as a
  failure. Authentication runs right after the request head is parsed and
  before any DNS lookup, routing decision, upstream connection or use of the
  device key, so an unauthenticated client reaches none of them.
- **Constant-time keyed check.** The verifier keeps an HMAC-SHA-256 tag of
  the issued `user:password` under a random per-session key and compares the
  tag of each received credential with it in constant time.
- **Memory only, shown on request.** The credentials live in the memory of
  the process that runs the session (the agent, `gateinto session browser`
  or `gateinto proxy`) and of the command that shows them. They are never
  written to disk, never logged at any level (a test captures `trace` logs
  and checks that neither the password nor the base64 form appear), never
  part of an IPC error message, never shown by `gateinto status` or
  `gateinto session list`, never accepted from a URI and never forwarded to
  the upstream. The agent hands them out only in the successful answer to a
  `launch` or `credentials <id>` request on its per-user endpoint;
  `gateinto open` and `gateinto session credentials` remove them from what
  they print and show them in the prompt instead.
- **A prompt that names the proxy.** On an interactive Windows desktop the
  prompt is a message box; otherwise it goes to the command's terminal. It
  names the proxy address the browser's own sign-in dialog shows and says to
  enter the credentials only there, never in a website's sign-in page or
  dialog. When there is neither, `gateinto open` names the command that
  shows them, and the foreground commands close their session and fail
  rather than serve credentials nobody can see. The presentation lives in
  `src/prompt.rs` and can be replaced without touching the check.
- **Strict parsing.** Exactly one `Proxy-Authorization` header, scheme
  `Basic` (case-insensitive), canonical padded base64 of at most 1024
  characters, decoding to `user:password` with a non-empty password and no
  control characters. Malformed credentials get `400`.
- **Bounded failures.** Wrong and malformed Basic credentials and every
  other scheme (`Bearer`, `Negotiate`, `NTLM` and so on, which get `407`)
  count as failed attempts; a request without credentials does not, and
  neither does a connection that `os_user` denied. After 10
  failed attempts within 60 seconds every request to the session gets `429`
  until the window ends, so guessing is limited to 10 attempts a minute per
  session. The limiter keeps a counter and a timestamp per session, nothing
  per client.
- **Revocation by closing.** Realm, port, credentials and failure count
  belong to one session. Closing it (browser exit, `gateinto session close`,
  `gateinto stop`, Ctrl+C) closes the port, aborts its established tunnels
  and drops the credentials and the verifier; the agent then answers
  `credentials <id>` with `no session <id>`. A browser that cached the old
  credentials can only reach a closed port, and a new session, even if the
  system gives it the same port, has a new realm and new credentials, so the
  cached ones get `407`. Closing is therefore the revocation; there is no
  separate revoke command, and no expiry or rotation while a session runs.

Non-guarantees:

- **Lookalike dialogs.** A website can draw a dialog that looks like the
  browser's proxy sign-in and ask for the credentials. The prompt warns
  against this and names the proxy address, but nothing technical stops a
  user from typing them into a page. Credentials entered there are useful to
  the site's operator only from this machine and only while the session runs,
  because the port listens on loopback (unless
  `--unsafe-allow-non-loopback-listen` was given) and closes with the session.
- **The clipboard.** The prompt does not copy anything, but a user who copies
  the password puts it where every program of the user, and clipboard history
  or sync if enabled, can read it.
- **Not a defense against malware running as the user.** Such a program can
  ask the agent for the credentials over the per-user endpoint
  (`gateinto session credentials`), read them from the agent's or the
  browser's memory or from the prompt, or simply use the device identity
  directly. The endpoint keeps out other users, not other programs of the
  same user.
- **Browser caching and dialogs are not verified.** How Chrome and Edge on
  Windows show the proxy sign-in dialog for this realm, whether and how long
  they cache the credentials, and what they do after the session closes has
  not been verified; see [browser-verification.md](browser-verification.md).
- **The rate limit can lock out the legitimate client.** A local program that
  sends 10 wrong credentials makes the session answer `429` to everyone,
  including the browser with the right credentials, for up to 60 seconds, and
  can renew the lockout for as long as it runs. Closing the session and
  starting a new one gives a new realm and new credentials, and a new
  failure count.
- **Basic credentials are sent in clear on loopback.** Anything that can
  capture loopback traffic on the machine can read them. They only protect
  this one session's port.
- **Memory.** The credentials, the decoded request credential and the request
  head are ordinary heap buffers, not locked and not zeroized when dropped.

### Local proxy authentication (`os_user`)

`os_user` is available on Windows only; elsewhere a configuration that names
it fails to load and the proxy refuses to start with it. It is offered by
browser sessions on Windows, next to `session_credentials`, and by the device
session when `[device_session] auth` names it. The client sends nothing for
it: Gateinto identifies the process at the other end of the connection.

Guarantees:

- **Only the same Windows account.** For each accepted connection Gateinto
  reads the Windows TCP connection table (`GetExtendedTcpTable`, IPv4 or
  IPv6 by the client's address; for an IPv4 client with no IPv4 row, also
  the IPv6 table for an IPv4-mapped row) and takes the process ID of the
  row whose local end is the client's address and port and whose remote end
  is the listener's. Rows without an owning process (ID 0) are skipped. It
  opens that process with `PROCESS_QUERY_LIMITED_INFORMATION` and its token
  with `TOKEN_QUERY`, and accepts the connection only if the token's user
  SID equals the user SID of Gateinto's own process token, compared with
  `EqualSid`, never as strings.
- **No trust in a reused process ID.** After opening the process, Gateinto
  reads the table again while it holds the process handle and requires the
  same row to still name the same process ID. A process that exited in
  between, and a process ID that was reused, are denied.
- **Browser sessions: only the browser's job.** Agent-launched browsers on
  Windows start through `CreateProcessW` with
  `PROC_THREAD_ATTRIBUTE_JOB_LIST`, so the browser is in a job object created
  for that session before its first instruction runs. Where that attribute
  is not available (it needs Windows 10), the browser is created suspended,
  assigned to the job with `AssignProcessToJobObject` and only then resumed,
  so it still runs no instruction outside the job; if the assignment fails,
  the suspended process is terminated, and a failure to terminate it is
  logged as a warning. The job is unnamed and its handle is
  not inheritable, and the session additionally requires `IsProcessInJob` to
  place the connecting process in that job. Other programs of the same user,
  which run outside the job, are denied.
- **No job, no `os_user`.** If no job can be created or the browser cannot
  be put in one (for example on a Windows version that does not allow the
  process into another job), the agent logs one warning for that launch and
  starts the browser without a job, in a session that accepts only
  `session_credentials`; the launch answer then carries the credentials as
  on other platforms. A browser outside a job never gets a session that
  offers `os_user`.
- **No browser process outlives its session.** The job has
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. When the browser exits or the
  session is closed, the agent terminates the job and waits, for at most 5
  seconds, until `JobObjectBasicAccountingInformation` reports no active
  process, before closing the session and deleting the profile directory
  (which it still retries). A process that has not ended after 5 seconds is
  logged as a warning. These waits run on the blocking thread pool, not on
  the async runtime; if the browser process is dropped without being
  stopped, the job is terminated and the wait continues in the background.
- **Fail closed.** No matching row after a few short retries, a process or
  token that cannot be opened, a different user SID, a process outside the
  job and any error from Windows all deny the connection.
- **Before anything else.** The check runs right after the connection is
  accepted, before the request is read, and therefore before any DNS lookup,
  routing decision, upstream connection or use of the device key. It runs on
  the blocking thread pool, not on the async runtime, and shares the connect
  timeout with reading the request; a check that does not finish in time
  gets `408` and is logged with its reason.
- **Clear fallback.** When `session_credentials` is offered too, a denied
  connection is handled exactly like a request without credentials (`407`
  with the `Basic` challenge), and the session credentials keep working.
  When `os_user` is the only method, a denied connection gets `403` and is
  closed. Denials do not count toward the `session_credentials` failure
  limit, because they involve no guess; that limit is unchanged.
- **Nothing secret in logs.** No credentials are involved. The first denial
  of a session logs a warning with its reason (no owner found, another user,
  outside the browser's job, a lookup past the deadline, or the Windows
  error) and the fallback: the command that shows the session credentials,
  or the advice to add `session_credentials`. Later denials of the same
  session are logged at debug level.

Non-guarantees:

- **Not a boundary against code of the same user.** On the device session
  every program of the user is accepted. In a browser session a program of
  the same user can still get in, for example by injecting code into the
  browser or by duplicating the job handle out of Gateinto's process, both
  of which the user's own account allows, or by creating a process with
  `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` set to the browser, which then
  inherits the browser's job. Processes the browser starts inherit the job
  and are accepted as well. `os_user` keeps out other users
  of the machine and, in browser sessions, ordinary programs of the same
  user; it does not keep out malware running as the user.
- **A point-in-time check.** The owner is checked once per connection. Every
  answer other than an established tunnel closes the connection, so every new
  connection is checked again, but an open tunnel is not re-checked.
- **Elevation is not verified.** With a real UAC split token, a Gateinto that
  is not elevated may be unable to open the process or token of an elevated
  client. The check then fails closed, so such a client may get `403`, or the
  `Basic` challenge when `session_credentials` is offered. See
  [verification.md](verification.md#local-proxy-authentication-os_user).
- **Not verified:** domain-joined machines, Chrome inside the job,
  browsers launched by Gateinto itself rather than by a test probe, a run on
  Windows CI, and the suspended-and-assign fallback and the launch without a
  job on real Windows 7 and 8.1.

### The tunnel content

- **No MITM of the inner TLS.** Gateinto does not terminate, inspect or modify
  the client's own TLS session with the target. It relays bytes after the
  upstream accepted the `CONNECT`, or after direct TCP connects in mixed mode.
- **Local `200` only after route establishment.** Gateway routes require
  upstream `2xx`; direct routes require a connected TCP socket. A client never
  believes a gateway tunnel exists when the upstream refused it. Upstream
  error headers and bodies are not forwarded.
- **Strict request parsing and limits** against request smuggling and resource
  exhaustion: only `CONNECT host:port HTTP/1.1` with exactly one `Host`
  header; header size limit, timeouts, idle timeout and a connection limit.
  HTTP/2 adds decoded header limits, bounded flow-control windows and
  per-stream cancellation; peer SETTINGS limits do not replace the local
  connection limit. Details are in the [README](../README.md#proxy) and
  [upstream protocol](protocol/http-connect.md).

### The device identity

- **Non-exportable key.** The device key is a persisted ECDSA P-256 key in
  Windows CNG, created with the export policy set to non-exportable before it
  is finalized. No private key material is ever written to a file, printed or
  logged.
- **Trust levels.** `key info` prints the backend and a trust note:
  - `tpm` (Microsoft Platform Crypto Provider): the private key never leaves
    the TPM. Software running as the user can still ask the TPM to sign while
    it runs.
  - `software` (Microsoft Software Key Storage Provider): protected by the
    operating system only. An administrator, or malware running as the user,
    can copy it.
  `key init` prefers the TPM and falls back to software with a warning that
  says why. `--no-software-fallback` (or
  `software_fallback_on_first_create = false`) makes a missing TPM an error
  instead.
- **Identity continuity.** The identity is never silently replaced:
  - `key init` reuses an existing key with the configured name, in either
    provider, and creates one only when none exists anywhere. Creating a key
    that already exists fails instead of overwriting it.
  - Keys with the same name in both providers stop `key init` with an error
    naming both fingerprints; `key info` and the proxy warn and use the `tpm`
    key.
  - A TPM that is present but not usable right now stops `key init` without
    creating anything, because an existing TPM key cannot be ruled out. Only a
    TPM that is reported absent leads to a software key.
  - `proxy`, `check-upstream`, `key info`, `status`, `agent` and `open` only
    open the key, never create it. Only `key init` and `gateinto setup` create
    one.
- **Installer separate from the key.** The MSI is per user, so it runs as the
  installing user and never as `SYSTEM`; none of its custom actions creates or
  opens a key. `gateinto setup` refuses to run as LocalSystem, LocalService or
  NetworkService, and notes when it runs elevated that the key still belongs
  to the current user. An uninstall keeps the key and the config file, so a
  reinstall keeps the device identity.
- **Explicit purge.** Only `gateinto reset --purge-device-identity` deletes the
  key, never an uninstall. It shows the provider, key name and SPKI with the
  consequences, requires at least the first 16 hex digits of the SPKI (typed
  at a prompt, or `--confirm-spki`; without a terminal and without that flag
  it refuses), stops the agent, and deletes only the key with the configured
  name in the current user's scope, after checking its SPKI again, through
  `NCryptDeleteKey`. It never clears a provider or the TPM. Deleting the key
  does not revoke the device at any gateway; see [install.md](install.md).

### Exposure and logs

- **Loopback-only by default.** The device session's listener defaults to
  `127.0.0.1:18736`; a browser session always listens on an ephemeral port of
  `127.0.0.1`. A
  non-loopback address is refused unless `--unsafe-allow-non-loopback-listen`
  is given on the command line; the configuration file has no key for it.
  With the default `[device_session] auth = "session_credentials"` that flag
  sends the Basic credentials in cleartext over the network, where anything on
  the path can read them; with `auth = "none"` anyone who can reach the
  address can use the tunnel and the device identity behind it.
- **No secrets or payload in logs.** Tunnel payload, private keys and local
  proxy credentials are never logged. At `info`, logs contain each session's id, kind, gateway name and
  listen address, the client's local address and port for each tunnel, tunnel
  established and idle-timeout events, and the client certificate's subject,
  SHA-1 thumbprint, NotAfter, source and key backend (for self-signed
  certificates the device key's SPKI SHA-256 and, per session, the SHA-256 of
  the session's certificate). Target `host:port`, the negotiated TLS version and
  group, and byte counts are logged only at `debug`. `check-upstream` prints
  TLS parameters, the server certificate subject and the upstream status line,
  never upstream headers or bodies. The configuration file holds no secrets.
- **Strict configuration.** Unknown keys are errors and there is no default
  upstream, so a typo cannot silently send traffic somewhere unintended.

## What it does not protect

- **Local users and processes.** `session_credentials`, the default for every
  session, keeps out programs that do not know the issued credentials, not
  programs of the same user, which can ask the agent for them or read them
  from the prompt. A device session with an explicit
  `[device_session] auth = "none"` has no authentication: any local process,
  including other users' processes, can use the tunnel and the device
  identity behind it. `os_user` keeps out other users and, in browser
  sessions, programs outside the browser's job, but not code of the same user
  that injects into the browser or takes the job handle. See
  [above](#local-proxy-authentication-session_credentials) and
  [`os_user`](#local-proxy-authentication-os_user).
- **Administrators and malware running as the user.** They can use or steal
  the identity (a software key can be copied), read traffic before it enters
  the tunnel, change the configuration, add CAs or replace the binary.
- **Traffic from the upstream proxy.** The upstream sees the source address,
  each gateway-routed target `host:port`, the client certificate, and any traffic that is not
  end-to-end encrypted inside the tunnel. It can block, log or redirect
  tunnels. Gateinto provides no anonymity.
- **A wrong trust anchor.** `--ca-file` replaces the default roots entirely;
  a wrong or compromised bundle makes Gateinto trust the wrong upstream.
- **Downgrade to classical key exchange in `hybrid_preferred`.** An upstream
  without `X25519MLKEM768` gets `X25519`. Use `hybrid_required` where that is
  not acceptable.
- **Post-quantum authentication.** Not provided.
- **Plain HTTP and non-`CONNECT` traffic.** Not proxied (`405`).
- **Unwanted launches within the limits.** A website can still open up to 5
  browser windows a minute, and up to 4 at a time, on configured gateways'
  portals, each prompting for a local proxy credential. That is a nuisance
  and a phishing surface (a user may type a real password into the prompt),
  not a way to change trust or reach a new upstream. The prompt is the
  browser's own; the credential only protects the local session.
- **The browser's own behavior.** Chrome or Edge may relaunch itself, keep
  running in the background after its windows close, or fail to start with
  the given profile; the agent watches only the process it started. Closing
  the session explicitly (`gateinto session close`) is then needed. Pages
  in the launched browser can still reach loopback addresses directly,
  because the browser does not send loopback requests to a proxy.
- **Other programs talking to the agent.** Any program running as the user
  can send launch, list, close and stop requests to the agent, as it could
  run `gateinto` itself.
- **Certificate lifecycle.** There is no enrollment, revocation checking of
  the client certificate, or key rotation. Only self-signed certificates are
  renewed, and only by issuing a new one for the same key; a compromised
  device key stays valid wherever its public key is trusted until the upstream
  stops trusting it. Gateinto does not validate the client certificate's
  chain; the upstream does.

The full list of residual risks and non-goals is in
[threat-model.md](threat-model.md#residual-risks). Report vulnerabilities as
described in [SECURITY.md](../SECURITY.md).
