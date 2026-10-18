# Launch URI (`gateinto://`)

A launch URI asks Gateinto to start a browser session for a gateway. It can
name a gateway that is already set up on this machine, choose a start page on
that gateway's portal, and, for a user who has no such gateway yet, bring the
gateway and its portal so that the user can add it after an explicit
confirmation. Version 1 of the format is described here; `src/uri.rs` parses
it and `src/link.rs` decides what it may do.

Any web page can open a custom-scheme URI, so Gateinto treats every launch URI
as untrusted input from an arbitrary website.

## Examples

Open the portal of a gateway the device already knows:

```text
gateinto://connect?profile=office
```

Open a page on that gateway's portal:

```text
gateinto://connect?profile=corp&url=https%3A%2F%2Fportal.corp.example%2Fapp
```

Bring the gateway and its portal, for users who do not have it yet (one line):

```text
gateinto://connect?profile=corp&gateway=proxy.corp.example%3A443&portal=https%3A%2F%2Fportal.corp.example%2F&url=https%3A%2F%2Fportal.corp.example%2Fapp
```

## For gateway operators: writing links

- Percent-encode every value except letters, digits, `-`, `.`, `_` and `~`.
  In particular `:` is `%3A`, `/` is `%2F`, `?` is `%3F`, `=` is `%3D`, `&`
  is `%26`, `%` is `%25` and `[` `]` are `%5B` `%5D`. A raw `:` or `/` makes
  the link invalid.
- `profile` is the name the gateway gets on the device. Choose a stable name:
  later links must use the same name together with the same `gateway` and
  `portal`, or they are refused.
- `portal` must be exactly the portal URL the device stored (or the
  `portal_url` of the configured gateway); compare it as a string. `url` only
  needs the same origin.
- `gateway` and `portal` are needed only for users who may not have the
  gateway yet. A link without them works only where the gateway is
  configured or was added before.
- The TLS settings of a gateway added from a link are the defaults: the
  upstream certificate must chain to a public root (the Mozilla roots built
  into Gateinto) and match the gateway host name; key exchange
  `hybrid_preferred`; client certificate `optional` (see
  [What a gateway added from a link gets](#what-a-gateway-added-from-a-link-gets)).
  A gateway that needs a private CA, another TLS mode or a certificate file
  must be set up in the configuration file by an administrator.
- Keep links short. Each URL may be up to 2048 characters and the whole link
  up to 8192 bytes, but some programs that pass links to Windows may cut
  long ones.

## Grammar

```abnf
launch-uri  = scheme "://connect" ["/"] "?" field *("&" field)
scheme      = "gateinto"                   ; ASCII case-insensitive
field       = name "=" value
name        = 1*char                       ; after decoding: profile, auth, v, url, gateway or portal
value       = 1*char
char        = ALPHA / DIGIT / "-" / "." / "_" / "~" / pct-encoded
pct-encoded = "%" HEXDIG HEXDIG
```

After decoding, field names and the values of `profile`, `auth` and `v` may
contain only `A-Z`, `a-z`, `0-9`, `_` and `-`. The values of `url`,
`gateway` and `portal` must decode to printable ASCII without spaces, then
pass their own checks below.

Fields:

| Name | Required | Value |
| --- | --- | --- |
| `profile` | yes | Gateway name: 1 to 64 characters from `A-Z`, `a-z`, `0-9`, `_` and `-`, not starting with `-`. Case-sensitive. |
| `auth` | no | `basic_tofu`, the only local proxy authentication a browser session uses. Default `basic_tofu`. |
| `v` | no | `1`, the format version. Default `1`. |
| `url` | no | Start page for this launch: an `https://` URL that passes the `portal_url` checks of the configuration file (at most 2048 characters, a host, no user information, no spaces, quotes, `<`, `>`, `\`, `^`, `` ` ``, `{`, `|`, `}`) and whose host is a DNS name or an IP address (below). It must have the same origin (scheme, host, port; port 443 when omitted) as the gateway's portal. |
| `gateway` | with `portal` | `host[:port]` of the gateway's HTTPS proxy, port 443 by default. The host is a DNS name (labels of 1 to 63 letters, digits and `-`, not starting or ending with `-`, at most 253 characters, the last label starting with a letter, no trailing dot; stored in lowercase), an IPv4 address in dotted decimal, or an IPv6 address in brackets without a zone. The port is 1 to 65535 in decimal. No user information, path, query, fragment, wildcard or whitespace. |
| `portal` | with `gateway` | The gateway's portal: an `https://` URL with the same rules as `url`. |

Limits and rules:

- At most 8192 bytes in total, checked before anything else is parsed.
- The host is exactly `connect` (lowercase). It may be followed by one `/`,
  because some programs add it. No user information, port, other path,
  fragment (`#`) or empty query.
- Only the six fields above, each at most once, in any order. Unknown and
  repeated fields, a field without `=`, an empty name or value, and empty
  pairs (`&&`, a leading or trailing `&`) are errors. There is no field for a
  CA file, TLS mode, client certificate, server name, listen address or any
  other setting.
- `gateway` and `portal` come together or not at all. When the link has both
  `portal` and `url`, they must have the same origin.
- Percent-encoding is decoded once. In `profile`, `auth`, `v` and the field
  names it may only yield the allowed characters, so `%00`, `%20`, `%22`,
  `%26`, `%2F`, `%2E` and `%25` are errors there. In `url`, `gateway` and
  `portal`, an encoded control character, space, non-ASCII byte or invalid
  hex is an error. `+`, spaces, quotes, `;`, `\`, `:`, `/` and every other
  unencoded character are errors.
- Leading or trailing whitespace, quotes or line breaks are errors.
- The forms `gateinto:connect?...` and `gateinto:///connect?...` are not
  accepted. Browsers are expected to pass the URI to Windows as written in
  the link, so a link written as in the examples should arrive in the
  accepted form; this is not verified with Chrome or Edge yet (step 21 of
  [browser-verification.md](../browser-verification.md#launch-uri-and-agent)
  records it).
- The registered command line is at most a few hundred characters plus the
  URI, far below the 32767 characters `CreateProcess` accepts (a unit test
  checks the bound with 1024-character paths).

Error messages say which rule was broken and never repeat the URI.

## What it does

1. The registered handler runs `"<gateinto.exe>" open [--config "<file>"] -- "%1"`.
   `--` ends option parsing, so the URI can only ever be the single positional
   argument; a URI that would split into more arguments is refused by the
   command line parser.
2. `gateinto open` parses the URI. An invalid URI ends here, before any
   process or file is touched.
3. It sends `launch <profile> <auth> [url=...] [gateway=...] [portal=...]` to
   the agent of the current user over a local IPC endpoint, starting the
   agent first if none is running (see [Agent and IPC](#agent-and-ipc)).
4. The agent validates the request again, counts it against the launch rate
   limit and the session cap, and resolves it against its configuration file
   and the gateways added from links, which it reads again for every launch
   (see [Resolution](#resolution)).
5. For a known gateway it starts a browser session on a new ephemeral
   loopback port with `basic_tofu`, creates a new browser profile directory
   and starts Chrome or Edge with that profile, that session's proxy and the
   start page.
6. For a new gateway it starts nothing. It keeps the validated request and
   answers `open` with a one-time confirmation token and the gateway name,
   address and portal origin it validated. `open` checks that these equal
   its own parse of the link (it denies and stops otherwise), then, running
   on the user's desktop, asks the user (see [Confirmation](#confirmation)) and
   sends `approve <token>` or `deny <token>`. On `approve` the agent stores
   the gateway and continues with step 5. If the session cap was reached in
   the meantime, the gateway stays stored and the answer says so; the next
   link to it starts a session without asking.

## Resolution

The agent knows the gateways of its configuration file and those in the
gateway files. On a name collision the configuration file wins and the
linked entry is ignored.

1. **The profile is known.** If the link has `gateway` and `portal`, they
   must equal the known gateway's host (case-insensitive, IP addresses by
   value, an IPv4-mapped IPv6 address equal to its IPv4 address), port and
   portal URL (exact string); otherwise the link is refused
   and nothing changes. A `url` must have the origin of the gateway's portal;
   a gateway without a portal refuses every `url`.
2. **The profile differs from a known one only in letter case.** Refused,
   with the known name, so that no look-alike gateway is created.
3. **The profile is unknown and the link has no `gateway`.** Refused: the
   portal must put the gateway in its link, or an administrator must add it
   to the configuration file.
4. **The profile is unknown and the link has `gateway` and `portal`.** If the
   same host and port are already known under another name, the link is
   refused with that name. Otherwise the user is asked; on approval the
   gateway is stored and the session starts, on refusal nothing is stored.
   Later links with the same name, gateway and portal start sessions without
   asking.
5. **Start page.** The link's `url` for this launch only, otherwise the
   gateway's portal, otherwise `about:blank`.

## Confirmation

- Only `gateinto open` asks; the agent never shows anything. The agent
  applies the launch rate limit before it hands out a confirmation, and keeps
  at most one confirmation open: while one waits (up to 120 seconds), a
  further link that needs one is refused with `another gateway confirmation
  is already waiting`. The token is 128 random bits, valid once, and expires
  with the confirmation. It binds an answer to the request the agent
  validated; it does not prove that a person answered, since any program of
  the same user can send `launch` and `approve` (it could equally write the
  gateway files).
- Windows, on an interactive desktop (the window station of `open` is
  visible): a `MessageBoxW` titled `Gateinto` with OK and Cancel, Cancel as
  the default button (`MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2 |
  MB_SETFOREGROUND | MB_TOPMOST`). OK and Cancel have no access keys and
  Enter and Space choose the focused button, Cancel at first, so no single
  keystroke approves. Moving the focus to OK (Tab or an arrow key) and then
  pressing Enter or Space, or clicking OK, does approve, so a page that
  coaches the user ("press Tab, then Enter") remains a social-engineering
  risk. The text names the profile, the gateway
  `host:port` and the portal origin, warns that the gateway will see this
  device's identity and the traffic of the isolated browser, so the user
  should allow it only if they trust the organisation that runs it, and ends
  with `Choose OK to allow this gateway, or Cancel to refuse.`
- Otherwise, with a terminal on standard input and standard error, the same
  text and a prompt that accepts only `yes`.
- Without either, `open` refuses: `no desktop or terminal to ask on; nothing
  was stored`.
- In the dialog and the prompt alike, when the gateway is `localhost`, a
  `*.localhost` name, or a loopback, private, link-local, unique-local,
  shared (`100.64.0.0/10`), `0.0.0.0/8` or broadcast IP address
  (IPv4-mapped and NAT64 `64:ff9b::/96` forms of these included), the text adds
  `This address is on your computer or local network.` under the gateway
  line.
- Any answer other than OK (or `yes`), and every error, sends `deny`.
- The dialog and the prompt are covered by unit tests of their text, style
  and answer handling; the Windows dialog itself has not been checked by hand
  yet.

## Linked gateways

- Each approved gateway is one file in the `gateways` directory next to the
  default configuration file (`%APPDATA%\Gateinto\gateways\`;
  `$XDG_CONFIG_HOME/gateinto/gateways` or `~/.config/gateinto/gateways`
  elsewhere), also when `--config` names another file. The configuration
  file itself is never written.
- The file name comes only from the validated, canonical gateway address,
  never from the profile name or other link text: `<host>.toml` for port
  443, otherwise `<host>_<port>.toml` (`_` never occurs in a host). DNS names
  are lowercase; IPv4 addresses are dotted decimal; IPv6 addresses use the
  compressed form with `-` for `:` and no brackets (`2001-db8--1_3128.toml`),
  and IPv4-mapped IPv6 addresses become IPv4 first. Examples:
  `proxy.corp.example.toml`, `proxy.corp.example_8443.toml`,
  `10.0.0.1_3128.toml`.
- The name must contain only `a-z`, `0-9`, `.`, `_` and `-`, no `..`, be a
  single path component and at most 255 bytes; otherwise the gateway is
  refused before the user is asked: with `.toml`, a host can have at most 250
  characters on port 443, and fewer with another port because the name adds
  `_<port>` (at most 244 characters with a five-digit port). Gateway hosts
  whose first label is a Windows device name (`CON`, `PRN`, `AUX`, `NUL`,
  `COM0` to `COM9`, `LPT0` to `LPT9`, any case) are refused in the link on
  every platform, and so are DNS names that would read as an IPv6 address
  with `-` for `:` (such as `fe80--1`), since their file name would be
  ambiguous.
- A file holds `name` (the profile), `host`, `port`, `portal_url` and
  `approved_at` (Unix seconds), and nothing else.
- The directory is created owner-only (`0700` on Unix). If it is a link, a
  reparse point or not a directory, it is refused: launches of gateways that
  are not in the configuration file fail, and `gateinto status` reports
  `linked-gateways: error: ...`.
- A new file is written to a temporary file `.<pid>.<32 hex digits>.tmp` in
  the directory (created new, synced) and then published without ever
  replacing a file: on Windows with `MoveFileExW` and `MOVEFILE_WRITE_THROUGH`
  but without `MOVEFILE_REPLACE_EXISTING`, using `\\?\` (`\\?\UNC\` for a
  redirected `%APPDATA%` on a share) so long names fit; on Unix with a hard
  link, or, on a filesystem without hard links, by creating the final file
  new in place, removed again only if that write fails after this call
  created it. The directory is then synced and the temporary file removed on
  every path. Approving never overwrites a file.
- Loading reads only regular `*.toml` files directly in the directory, never
  links or reparse points (on Windows the file is opened with
  `FILE_FLAG_OPEN_REPARSE_POINT` and its handle checked) and never
  subdirectories; at most 32 files and
  16 KiB each. A file is valid only if it parses, has no other keys, a valid
  host, port and portal, and its file name is exactly the one its own host
  and port give; a profile name used by two files makes both invalid, also
  when one of them is damaged.
- An invalid file disables only its own entry; the other gateways keep
  working. `gateinto status`, `gateinto gateway list` and every launch
  answer list it as `linked-gateway: error: <file>: <reason>`. A link whose
  profile or gateway address is held by an invalid file is refused without
  asking, and the file is left as it is. While a damaged file has no
  readable name, every link for a profile that is neither configured nor a
  valid linked gateway is refused the same way, since it could be that
  file's.
- `gateinto gateway list` shows every gateway with its source;
  `gateinto gateway forget <name>` deletes the file whose valid content
  carries that name, after checking again that it is a regular file in the
  directory (sessions that are open stay open until closed). If several
  files carry the name, for example a valid and a damaged one, it deletes
  nothing and lists them all. A damaged file is removed by deleting it.
  `gateinto reset --purge-device-identity --purge-config` deletes the
  regular `*.toml` files of the directory and
  Gateinto's own leftover temporary files, and the directory if it is then
  empty, together with the configuration file. Its messages count the
  gateway files and the temporary files separately.

## What a gateway added from a link gets

The same settings as a `[gateways.<name>]` table with only `host`, `port` and
`portal_url`:

- server name: the host;
- trust anchors: the Mozilla roots built into Gateinto (`webpki-roots`), never
  a CA file;
- `tls_mode = "hybrid_preferred"`;
- `client_certificate = "optional"`: on Windows, a certificate in
  `CurrentUser\My` whose public key is the device key is presented when the
  gateway asks for one, so an approved gateway learns the device key's stable
  SPKI; `self_signed_client_cert` is off and no certificate file is used;
- the limits of the configuration file.

A link can never set a CA file, TLS mode, client certificate, server name or
listen address. Tests run with a test-only build feature (`test-hooks`) that
lets the integration tests add the test CA through the environment variable
`GATEINTO_TEST_LINKED_CA_FILE`; release builds do not have the feature, and a
test without it checks that a linked gateway signed by the test CA is refused.

## What it can never do

- Carry or set a credential, key, certificate, password, token or any other
  secret. The local proxy credential is chosen in the browser's own prompt.
- Change a gateway that is configured or was added before, or add one without
  the user's confirmation in `gateinto open`.
- Set a CA, TLS mode, client certificate, server name or any other trust
  setting.
- Open a page outside the origin of the gateway's portal.
- Choose the browser, its arguments, the profile directory or the listen
  address.
- Run a command, a script or anything other than `gateinto open`.
- Reach another user's agent: the IPC endpoint is per user.

## Agent and IPC

`gateinto agent [--config FILE]` runs the agent: the device session if
`[device_session] gateway` is set, and the IPC endpoint. Only one agent per
user (and per `GATEINTO_INSTANCE`, see below) can listen; a second one exits
with `an agent is already running`.

Endpoint:

- Windows: the named pipe `\\.\pipe\gateinto-agent-<user SID>`, created with
  `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS` and the
  protected DACL `D:P(A;;GA;;;<user SID>)(A;;GA;;;SY)`: only the user and
  SYSTEM can open it, so other users cannot read, write or hold its
  connection slots. Before sending a request, a client checks that the
  process serving the pipe (`GetNamedPipeServerProcessId`) runs as the same
  user (token user SIDs compared with `EqualSid`) and refuses the pipe
  otherwise, so a pipe that another user created first under that name is
  not used. Whether Windows enforces these as intended is only exercised by
  the CI runs on `windows-latest` (same user); the other-user cases are not
  tested.
- Unix (development and tests): the socket `agent.sock` in
  `$XDG_RUNTIME_DIR/gateinto`, or `$HOME/.local/state/gateinto` without
  `XDG_RUNTIME_DIR`. The directory must be accessible only by its owner
  (created with mode `0700`) and owned by the user (checked against a file the
  agent creates there), and the socket gets mode `0600`. Probing for a
  running agent, replacing a socket left by a crashed agent and binding happen
  while holding the exclusive lock file `agent.sock.lock` (created with
  `O_EXCL`); a lock file older than 10 seconds is treated as left by a crash
  and taken over.
- `GATEINTO_INSTANCE=<name>` (1 to 32 characters from `A-Z`, `a-z`, `0-9`,
  `_`, `-`) appends `-<name>` to the pipe or socket name and makes the agent
  use `profiles-<name>` instead of `profiles` for browser profiles, so one
  instance never sweeps another's profiles. It exists so that
  tests and development builds can run separate agents; it is read from the
  environment, never from a URI.

Protocol: one request per connection. The client sends one line of at most
8192 bytes ending in `\n`; the agent answers and closes the connection. The
agent parses every request itself and does not trust the client. A launch
line must be in the canonical form below (fields in this order, `gateway` as
lowercase `host:port`), and its values pass the same checks as in a URI, so
they never contain spaces or line breaks.

| Request | Answer lines after `ok` |
| --- | --- |
| `launch <profile> basic_tofu [url=<url>] [gateway=<host:port>] [portal=<url>]` | `session: <id>`, `gateway: <name>`, `listen: 127.0.0.1:<port>`, `realm: <realm>`, `profile: <directory>`, `browser: <executable>`; or, for a new gateway, `confirm: <32 hex digits>`, `gateway: <name>`, `address: <host:port>`, `portal: <origin>` |
| `approve <token>` | as for a started `launch` |
| `deny <token>` | none |
| `list` | `session: <id> <device or browser> <gateway> <listen address>` per session |
| `close <id>` | none |
| `stop` | none; the agent closes every session, then exits |

An error is the single line `error: <message>`. Line breaks inside a message
are replaced by spaces. Answers are at most 64 KiB. The agent serves at most
8 connections at a time and drops a connection that sends no complete request
within 10 seconds. A client gives up on an agent that does not answer within
60 seconds; a connection that the agent closes without an answer is reported
as such. The command line exposes the requests as `gateinto open`,
`gateinto session list`, `gateinto session close <id>` and `gateinto stop`.

`gateinto open` without a running agent starts `gateinto agent` with the same
`--config` as a detached process (on Windows without a console and without
inheriting the standard handles of `open`, on Unix in its own process group,
in both cases with its output discarded) and retries the request with a backoff from
25 ms to 1 s for up to 30 seconds. A missing agent, a busy pipe and a
connection closed without an answer (an agent that is stopping) are retried
within that time; if a started agent exits while no agent answers, `open`
starts another, at most three in all. If they all exit, for example because
the configuration file is invalid, `open` says so; run `gateinto agent` in a
console to see the reason. If two `open` commands race, one agent wins and
the other exits; both requests reach the winner (a test runs two `open`
commands at once without an agent). On `stop` the agent stops accepting
connections before it closes its sessions.

## Launch policy

- Rate limit: at most 5 `launch` requests in any 60 seconds, counted when the
  request arrives, whether it then succeeds, asks for a confirmation or
  fails. Further requests get `error: too many launch requests`. `approve`
  and `deny` are not counted; they need the token of a counted `launch`.
- At most 4 browser sessions at a time; a further launch gets
  `error: 4 browser sessions are already open`.
- Every accepted launch creates a new, separate session: new port, new realm,
  new `basic_tofu` state, new profile directory and new browser process.
  Launches never reuse or replace an existing session, so the result of a
  launch does not depend on what ran before.
- A launch is answered only after the browser process has started. If the
  profile directory or the browser cannot be created, the session is closed
  again and nothing is left behind.

## Browser launch

The agent starts the browser without a shell, with these arguments:

```text
--user-data-dir=<profile directory>
--proxy-server=http://127.0.0.1:<session port>
--no-first-run
--no-default-browser-check
--new-window
<start page: the link's url, else the portal, else about:blank>
```

- Executable: `[browser] executable` from the configuration file, or else the
  first that exists of Chrome (`App Paths` registry entry in HKCU, then HKLM,
  then `%ProgramFiles%`, `%ProgramFiles(x86)%` and `%LOCALAPPDATA%` under
  `Google\Chrome\Application\chrome.exe`) and Edge (`App Paths`, then
  `%ProgramFiles(x86)%` and `%ProgramFiles%` under
  `Microsoft\Edge\Application\msedge.exe`). On Unix, development only, the
  first of `google-chrome`, `google-chrome-stable`, `chromium`,
  `chromium-browser` and `microsoft-edge` on `PATH`.
- Profile directory: `%LOCALAPPDATA%\Gateinto\profiles\<session id>-<16 random hex digits>`
  (Unix: `$XDG_STATE_HOME/gateinto/profiles` or
  `$HOME/.local/state/gateinto/profiles`; `profiles-<instance>` with
  `GATEINTO_INSTANCE`), created new for each launch
  (directories mode `0700` on Unix) with a marker file `gateinto-profile`. A
  separate user data directory makes Chrome and Edge start a new browser
  process instead of handing the arguments to a browser that is already
  running, which would ignore `--proxy-server`.
- No `--proxy-bypass-list`. Chrome and Edge then keep their built-in rule
  that `localhost` and loopback addresses do not use the proxy, so pages on
  the gateway side cannot reach the gateway's own loopback through the
  session, and the browser reaches local addresses as it would without
  Gateinto. Every other request goes through the session, and the session
  only relays `CONNECT`, so plain `http://` pages other than loopback fail
  with `405`.
- When the browser process exits, the agent closes the session (listener
  dropped, tunnels and upstream TLS connections aborted, `basic_tofu` state
  and certificate discarded) and deletes the profile directory.
- `gateinto session close <id>`, `gateinto stop`, and Ctrl+C, Ctrl+Break or
  closing the console of `gateinto agent` (SIGINT or SIGTERM on Unix) kill the browser process, then do the same.

Deletion only touches a directory directly inside the profiles directory
whose name has the form above, that is a real directory (not a link) and that
contains the marker file with Gateinto's exact content. The contents are
removed without following links, the marker last, so a removal that fails
part way (for example because a browser child process still holds a file)
leaves a directory that is still recognized. It is retried for about 10
seconds; whatever remains, and any profile left by an agent that crashed, is
removed when the next agent starts. Nothing else in the profiles directory or
elsewhere is ever deleted.

Limitations:

- The agent watches the process it started. If the browser hands off to
  another process and exits (for example when it restarts itself for an
  update), the session closes while a window may still be open; that window
  then gets connection errors. Use a new launch.
- If the browser process is still running but its windows are closed (for
  example when background apps are allowed to keep running), the session
  stays open. `gateinto session list` shows it and `gateinto session close <id>`
  closes it.
- After a crash of the agent, the browser keeps running without a working
  proxy until it is closed, and its profile is removed at the next agent
  start.

## URI handler registration (Windows, development use)

`gateinto uri register [--config FILE]` writes, for the current user only:

```text
HKCU\Software\Classes\gateinto
    (default)      = "URL:Gateinto launch link"
    URL Protocol   = ""
HKCU\Software\Classes\gateinto\shell\open\command
    (default)      = "<absolute path of gateinto.exe>" open [--config "<absolute config path>"] -- "%1"
```

- The executable and configuration paths must be absolute, must not contain
  `"` or `%` or control characters, and must not end with a separator, so the
  quoting cannot be broken and nothing in them is expanded.
- An existing `gateinto` key is replaced only if its command already runs a
  Gateinto executable in this exact form; any other handler, or a key without
  a command, is left unchanged and reported. Registering again with the same
  command is harmless.
- If writing fails part way, a key that did not exist before is deleted
  again, so no half-written handler remains.

`gateinto uri unregister` deletes `HKCU\Software\Classes\gateinto` and its
subkeys only if its command runs a Gateinto executable in the form above; it
reports when nothing is registered and refuses to touch a foreign handler.

`gateinto.exe` is a console program, so Windows may show a console window
for as long as `gateinto open` runs; the agent it starts has no console.

Both commands report an error on other platforms. Machine-wide registration,
an installer and code signing are out of scope. Chrome and Edge normally ask for
confirmation before they hand a `gateinto://` link to Windows; whether and
how they do is not verified.
