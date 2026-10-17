# Launch URI (`gateinto://`)

A launch URI asks Gateinto to start a browser session for a gateway profile
that is already configured on this machine. It is a request, not
configuration: it can only name a local gateway. Version 1 of the format is
described here; `src/uri.rs` implements it.

Any web page can open a custom-scheme URI, so Gateinto treats every launch URI
as untrusted input from an arbitrary website.

## Example

```text
gateinto://connect?profile=office&auth=basic_tofu
```

## Grammar

```abnf
launch-uri = scheme "://connect" ["/"] "?" field *("&" field)
scheme     = "gateinto"                    ; ASCII case-insensitive
field      = name "=" value
name       = 1*char                        ; after decoding: profile, auth or v
value      = 1*char
char       = ALPHA / DIGIT / "_" / "-" / pct-allowed
pct-allowed = "%" HEXDIG HEXDIG            ; only if it decodes to ALPHA, DIGIT, "_" or "-"
```

Fields:

| Name | Required | Value |
| --- | --- | --- |
| `profile` | yes | Name of a `[gateways.<name>]` table in the agent's configuration file: 1 to 64 characters from `A-Z`, `a-z`, `0-9`, `_` and `-`, not starting with `-`. Case-sensitive. |
| `auth` | no | `basic_tofu`, the only local proxy authentication a browser session uses. Default `basic_tofu`. |
| `v` | no | `1`, the format version. Default `1`. |

Limits and rules:

- At most 512 bytes in total, checked before anything else is parsed.
- The host is exactly `connect` (lowercase). It may be followed by one `/`,
  because some programs add it. No user information, port, other path,
  fragment (`#`) or empty query.
- Only the three fields above, each at most once, in any order. Unknown and
  repeated fields, a field without `=`, an empty name or value, and empty
  pairs (`&&`, a leading or trailing `&`) are errors.
- Percent-encoding is decoded only where it yields one of the allowed
  characters; `%00`, `%20`, `%22`, `%26`, `%2F`, `%2E`, `%25`, invalid hex
  and every non-ASCII byte are errors. `+`, `.`, spaces, quotes, `;`, `\`
  and every other character are errors.
- Leading or trailing whitespace, quotes or line breaks are errors.
- The forms `gateinto:connect?...` and `gateinto:///connect?...` are not
  accepted. Browsers pass the URI to Windows as the user clicked it, so a link
  written as in the example arrives in that form.

Error messages say which rule was broken and never repeat the URI.

## What it does

1. The registered handler runs `"<gateinto.exe>" open [--config "<file>"] -- "%1"`.
   `--` ends option parsing, so the URI can only ever be the single positional
   argument; a URI that would split into more arguments is refused by the
   command line parser.
2. `gateinto open` parses the URI. An invalid URI ends here, before any
   process or file is touched.
3. It sends `launch <profile> <auth>` to the agent of the current user over a
   local IPC endpoint, starting the agent first if none is running (see
   [Agent and IPC](#agent-and-ipc)).
4. The agent validates the request again, counts it against the launch rate
   limit, looks the profile up in its own configuration file, starts a browser
   session on a new ephemeral loopback port with `basic_tofu`, creates a new
   browser profile directory and starts Chrome or Edge with that profile, that
   session's proxy and the gateway's configured `portal_url`.

## What it can never do

- Carry or set a credential, key, certificate, password, token or any other
  secret. The local proxy credential is chosen in the browser's own prompt.
- Add or change a gateway, upstream host or port, server name, CA, TLS mode,
  client certificate or any other trust setting. `profile` is a name looked up
  in the agent's configuration file, never a URL or a path.
- Choose the page the browser opens. The start page is the gateway's
  `portal_url` from the configuration file (`https://` only), or
  `about:blank` without one.
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
  `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`, with the
  default security descriptor (full control for the owner, SYSTEM and
  administrators, read-only for everyone else, so no other user can write a
  request).
- Unix (development and tests): the socket `agent.sock` in
  `$XDG_RUNTIME_DIR/gateinto`, or `$HOME/.local/state/gateinto` without
  `XDG_RUNTIME_DIR`. The directory must be accessible only by its owner
  (created with mode `0700`), the socket gets mode `0600`, and a socket left
  by a crashed agent is replaced.
- `GATEINTO_INSTANCE=<name>` (1 to 32 characters from `A-Z`, `a-z`, `0-9`,
  `_`, `-`) appends `-<name>` to the pipe or socket name. It exists so that
  tests and development builds can run separate agents; it is read from the
  environment, never from a URI.

Protocol: one request per connection. The client sends one line of at most
1024 bytes ending in `\n`; the agent answers and closes the connection. The
agent parses every request itself and does not trust the client.

| Request | Answer lines after `ok` |
| --- | --- |
| `launch <profile> basic_tofu` | `session: <id>`, `gateway: <name>`, `listen: 127.0.0.1:<port>`, `realm: <realm>`, `profile: <directory>`, `browser: <executable>` |
| `list` | `session: <id> <device or browser> <gateway> <listen address>` per session |
| `close <id>` | none |
| `stop` | none; the agent closes every session, then exits |

An error is the single line `error: <message>`. Line breaks inside a message
are replaced by spaces. Answers are at most 64 KiB. The agent serves at most
8 connections at a time and drops a connection that sends no complete request
within 10 seconds. The command line exposes the requests as `gateinto open`,
`gateinto session list`, `gateinto session close <id>` and `gateinto stop`.

`gateinto open` without a running agent starts `gateinto agent` with the same
`--config` as a detached process (on Windows without a console and without
inheriting the standard handles of `open`, on Unix in its own process group,
in both cases with its output discarded) and retries the request with a backoff from
25 ms to 1 s for up to 30 seconds. If the started agent exits first, for
example because the configuration file is invalid, `open` says so; run
`gateinto agent` in a console to see the reason. If two `open` commands race,
one agent wins and the other exits; both requests reach the winner.

## Launch policy

- Rate limit: at most 5 `launch` requests in any 60 seconds, counted when the
  request arrives, whether it then succeeds or not. Further requests get
  `error: too many launch requests`.
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
<portal_url or about:blank>
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
  `$HOME/.local/state/gateinto/profiles`), created new for each launch
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
- `gateinto session close <id>`, `gateinto stop` and Ctrl+C in a console
  running `gateinto agent` kill the browser process, then do the same.

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
