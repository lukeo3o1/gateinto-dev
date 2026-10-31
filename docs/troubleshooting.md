# Troubleshooting

Gateinto logs to stderr. Set `RUST_LOG=debug` for more detail, for example
`RUST_LOG=gateinto=debug`. Tunnel payload is never logged.

## Status codes

Gateinto answers the local `CONNECT` with one of these statuses. Error
responses have no body and close the connection. With curl, use `-v` to see the
proxy's status line.

| Status | Meaning | What to check |
| --- | --- | --- |
| `200` | The upstream proxy accepted the tunnel with a `2xx` status. | If the request still fails, the problem is between the client and the target, inside the tunnel. |
| `400` | The request was malformed, or the client closed the connection before finishing it. Only `CONNECT host:port HTTP/1.1` with exactly one `Host` header and at most one `Proxy-Authorization` header is accepted; with `session_credentials`, a malformed Basic credential (bad base64, no `:`, empty password, control characters, over 1024 characters) is also `400`. | Configure the client to use Gateinto as an HTTP proxy for HTTPS, not as a SOCKS proxy or an HTTPS proxy. |
| `407` | Every session: the request had no credential, another scheme than Basic, or a credential other than the user name and password issued to this session. Browsers show their proxy sign-in dialog. | Enter the issued credentials exactly, including the hyphens. To see them again run `gateinto session credentials <id>` (`gateinto session list` shows the id); for `gateinto session browser` they are in the prompt shown at start. Credentials of a closed or another session never work: a browser that keeps sending old cached ones needs the new ones, or a new session. Gateinto never logs credentials; a `warn` line says when different credentials were refused. |
| `429` | `session_credentials` only: 10 wrong or malformed Basic credentials, or requests with another scheme such as `Bearer`, `Negotiate` or `NTLM`, within 60 seconds. Every request gets `429` until `Retry-After` seconds have passed, even one with the issued credentials. | Which local program is sending wrong credentials (`warn` lines name the client's local port). A browser that cached a mistyped password and replays it on parallel tunnels reaches the limit within seconds: wait for `Retry-After`, then enter the issued credentials. If the session stays locked, close it and start a new one. |
| `403` | The upstream proxy answered `403`. | The upstream proxy's access policy for this target or this device. |
| `405` | The method was not `CONNECT`. Plain HTTP requests such as `GET http://...` are not supported. | Use `https://` URLs, or send the client's plain HTTP traffic elsewhere. |
| `408` | The request head was not complete within `[limits] connect_timeout_seconds`. | A client that opens the connection but does not send a request, or a very slow client. |
| `431` | The request header block was larger than `[limits] header_max_bytes`. | Clients that send many or large headers with `CONNECT`. |
| `502` | The upstream connection failed: TCP connect refused or unreachable, TLS handshake or certificate failure, a key exchange the TLS mode does not allow, a malformed or oversized reply, or any upstream status other than `2xx` and `403` (including `407`). | The `warn` log line `upstream refused tunnel` shows the target `host:port` and the cause. See [Private CA certificates](#private-ca-certificates) and [hybrid_required fails](#hybrid_required-fails). |
| `503` | `[limits] max_concurrent_tunnels` connections are already open in this session. | Raise `max_concurrent_tunnels` in the configuration file, or find the client holding connections open. |
| `504` | The upstream TCP connect, TLS handshake and `CONNECT` reply did not finish within `[limits] connect_timeout_seconds`. | Network reachability of the upstream proxy, firewalls that drop instead of reject, or a slow upstream. |

The upstream's own headers and body are never forwarded, so a `407` from the
upstream appears as a `502` locally. An upstream that requires a client
certificate rejects Gateinto when no client certificate is configured (see the
"mTLS is not configured" warning at startup), and Gateinto returns `502`.

`gateinto check-upstream` (same options as `session browser`, or `--config`) connects
once and prints the negotiated TLS version, key exchange group, cipher suite,
server certificate subject and whether a client certificate was sent. With
`--target host:port` it also prints the upstream's `CONNECT` status line. It
exits nonzero with the reason on stderr when anything fails.

## Private CA certificates

By default the upstream certificate is verified against the Mozilla roots
bundled in `webpki-roots`. Roots added to the Windows certificate store, such
as an enterprise CA, are not used. If the upstream proxy's certificate is
issued by a private CA, every tunnel fails with `502` and the log contains
`TLS handshake failed: invalid peer certificate`.

Pass the CA in PEM format:

```sh
gateinto check-upstream --upstream-host proxy.example.com --upstream-port 443 --ca-file corp-ca.pem
```

- `--ca-file` replaces the default roots. Include every CA the upstream may
  use.
- The file must contain at least one `-----BEGIN CERTIFICATE-----` block.
  Gateinto refuses to start with `contains no certificates`,
  `cannot read CA bundle` or `invalid certificate in CA bundle` otherwise.
- If the certificate is valid but for a different name, for example when
  connecting by IP address, pass `--upstream-server-name` with a name the
  certificate contains.
- Certificate verification cannot be turned off.

## hybrid_required fails

With `--tls-mode hybrid_required` (or `tls_mode = "hybrid_required"` in the gateway table) only
`X25519MLKEM768` is offered. An upstream that does not support it cannot
complete the handshake: every tunnel gets `502`, and the log shows

```text
WARN ... upstream refused tunnel target=example.com:443 error=TLS handshake failed: received fatal alert: HandshakeFailure
```

or a similar handshake error. Gateinto never falls back to `X25519` in this
mode. Check what the upstream negotiates with the default mode:

```sh
gateinto check-upstream --upstream-host proxy.example.com --upstream-port 443 --tls-mode hybrid_preferred
```

If it prints `key-exchange-group: X25519`, the upstream (or a TLS-terminating
middlebox in front of it) lacks the hybrid group. Either enable
`X25519MLKEM768` there or use `hybrid_preferred`. A tunnel that somehow
negotiated another group is also refused, with `TLS negotiation refused: TLS
mode hybrid_required allows key exchange X25519MLKEM768 but ... was negotiated`.

## Configuration file errors

Errors from `--config` name the file and, for syntax and value errors, the line
and key. Inside a `[gateways.<name>]` table they name the gateway and point at
its table header:

```text
error: config file gateinto.toml: TOML parse error at line 1, column 2
  |
1 | [gateways.default]
  |  ^^^^^^^^
gateway "default": unknown field `hostname`, expected one of `host`, `port`, `server_name`, `ca_file`, `tls_mode`, `client_certificate`, `client_cert_file`, `self_signed_client_cert` in `default`
```

- Unknown sections or keys are errors; check the spelling against
  [config.example.toml](../config.example.toml).
- `gateway "<name>": no upstream configured; set host and port in
  [gateways.<name>] or pass --upstream-host and --upstream-port` (or, without
  any gateway table, `no upstream configured; pass --upstream-host and
  --upstream-port, ...`): there is no default upstream. Both host and port are
  needed.
- `--gateway names the unknown gateway "<name>"`: the name must match a
  `[gateways.<name>]` table; the message lists the configured ones.
- `<n> gateways are configured (<names>); pass --gateway to choose one`:
  with several gateways, `check-upstream` and `session browser` cannot pick
  one. Pass `--gateway <name>`.
- `[device_session] was removed: Gateinto no longer runs a shared local
  proxy; ...`: the configuration file still has the `[device_session]`
  section of an earlier build. Delete the whole section; start browser
  sessions with `gateinto open` or a `gateinto://` link, or with
  `gateinto session browser`.
- The `[listen]`, `[upstream]` and `[tls]` sections of earlier development builds are
  unknown sections: move their keys to a `[gateways.<name>]` table
  (`[tls] mode` becomes `tls_mode`) and drop `[listen]`.
- Zero limits, ports or timeouts, an empty `[device_key] name`, and unknown
  values for `tls_mode`, `client_certificate` or `preferred` are rejected, as
  are gateway names other than 1 to 64 characters from `A-Z`, `a-z`, `0-9`,
  `_` and `-`.
- Relative `ca_file` and `client_cert_file` paths are relative to the
  configuration file, not to the current directory.
- Command line flags override the file. If a value seems ignored, check that
  the same flag is not also given.

## The `proxy` command is gone

```text
error: unrecognized subcommand 'proxy'
```

Gateinto no longer runs a shared local proxy on a fixed port. Use
`gateinto open` or a `gateinto://` link to start a browser session, or
`gateinto session browser` for one session with its own loopback port and
credentials. Sessions always listen on loopback; there is no option to listen
on another address. See [threat-model.md](threat-model.md).

## Launch links and the agent

On Windows, when a link starts `gateinto open` with its own temporary console
or no console on an interactive desktop, a failed launch shows the complete
error in a Gateinto dialog until you choose OK; Ctrl+C copies a standard
Windows message box's text. The same error is still written
to stderr and the process exits nonzero. This also covers invalid command-line
arguments to `open`; successful launches and help/version requests do not show
an error dialog. Existing URI handler registrations work without re-registering.

When run from an existing terminal, with stderr redirected to a file or pipe,
or without an interactive desktop, `open` only reports through stderr. Run
`gateinto open --config <file> -- "<link>"` in a terminal to inspect a launch
there. An agent startup error names the selected configuration when one was
supplied; run `gateinto agent` with that same `--config` to see the underlying
startup failure. The detached agent's stderr is not retained in a log file.

Messages from `gateinto open`, `gateinto agent`, `gateinto session list`,
`gateinto session close`, `gateinto session credentials` and `gateinto stop`
([protocol/launch-uri.md](protocol/launch-uri.md)):

- `invalid launch URI: ...`: the link breaks a rule of the format; the
  message names the rule. Nothing was started. `auth=basic_tofu was removed`
  means the link comes from an older portal: leave `auth` out or use
  `auth=session_credentials`.
- `warning: the credentials for Gateinto session <id> on 127.0.0.1:<port>
  were not shown: ...`: `gateinto open` had neither an interactive desktop
  nor a terminal. The session runs; run `gateinto session credentials <id>`
  in a terminal to see its user name and password. `gateinto session browser`
  instead closes its session and fails with this error; start it from a
  terminal or a desktop.
- `no session <id>` from `gateinto session credentials`: the session was
  closed (its browser exited, or `session close` or `stop` ran), and its
  credentials no longer exist. Sessions of `gateinto session browser` are not
  run by the agent; their credentials are only in the prompt shown at start.
- `unknown gateway "<name>": it is not set up on this device and the link
  does not bring one; ...`: neither the agent's configuration file nor the
  gateways added from links has `<name>`, and the link has no `gateway` and
  `portal`. Ask the portal for a link that brings the gateway, or have an
  administrator add `[gateways.<name>]`. The agent reads its configuration
  file once when it starts; after editing the file run `gateinto stop` so the
  next launch starts a new agent. Gateways added from links are read again
  for every launch.
- `the link's gateway or portal differs from the gateway "<name>" set up on
  this device`: the link names a known gateway with another host, port or
  portal. Nothing was changed. If the gateway really moved, remove the old
  entry (`gateinto gateway forget <name>` for one added from a link, or edit
  the configuration file) and open the link again.
- `the link's start page is not on the origin ...` or `... has no
  portal_url`: `url` must have exactly the scheme, host and port of the
  gateway's portal; a gateway without a portal accepts no `url`.
- `... its address is already set up as "<other>"; use profile=<other> in
  the link`: the gateway in the link is known under another name.
- `cannot ask whether to add the gateway: no desktop or terminal to ask on`:
  `gateinto open` was started without a visible desktop or terminal, so it
  could not ask. Click the link in a desktop session, or run `gateinto open
  -- "<link>"` in a terminal and type `yes`.
- `adding the gateway "<name>" was not allowed; nothing was stored`: the
  dialog was answered Cancel or closed, or something other than `yes` was typed.
- `another gateway confirmation is already waiting for an answer`: answer
  the open dialog first; an unanswered confirmation expires after 120
  seconds.
- `no gateway confirmation is waiting for this answer`: the dialog was
  answered after its 120 seconds, or the agent restarted in between. Open
  the link again.
- `linked-gateway: error: <file>: ...`: one file in `gateways/` is damaged,
  was edited by hand (only `name`, `host`, `port`, `portal_url` and
  `approved_at` are allowed), was renamed (its name must match its own host
  and port), is not a regular file, or uses a profile name that another
  file uses too. Only that gateway is disabled, and links to its name or
  address are refused until the file is fixed or deleted; delete it to
  remove that gateway.
- `linked gateways <folder>: ...` after the dialog was answered OK (for
  example `Access is denied` or `Read-only file system`): the `gateways`
  folder next to the config file could not be created or written. Nothing
  was stored and no session was started. Fix the folder's permissions and
  open the link again, or have an administrator add the gateway to the
  config file. A `.<pid>.<hex>.tmp` file left there by a crash is never read
  and is removed by `reset --purge-config`.
- `linked-gateways: error: ... not a directory`: `gateways/` is a file, a
  link or a reparse point. Only gateways of the configuration file work
  until it is replaced by a plain directory or removed.
- `no agent is running`: from `session list`, `session close`,
  `session credentials` or `stop`.
  `gateinto open` starts one by itself.
- `an agent is already running for this user at ...`: only one agent per user
  (and per `GATEINTO_INSTANCE`) can run. Use `gateinto stop` to replace it.
- `the agent exited (...) before accepting requests`: the agent started by
  `open` could not start, usually because of the configuration file. Run `gateinto agent --config <file>` in
  a console to see the error.
- `neither Chrome nor Edge was found`, or `browser executable ... not found`:
  set `[browser] executable` to the browser's full path.
- `too many launch requests` or `4 browser sessions are already open`: wait a
  minute, or close sessions with `gateinto session list` and
  `gateinto session close <id>`.
- The window closed but `gateinto session list` still shows the session: the
  browser process is still running (for example in the background). Close it
  with `gateinto session close <id>`.
- A directory is left in `%LOCALAPPDATA%\Gateinto\profiles`: a browser
  process still held a file when the session closed, or the agent crashed.
  The next agent start deletes it. Directories without Gateinto's marker file
  are never deleted; remove those by hand.

## VCRUNTIME140.dll was not found

"The code execution cannot proceed because VCRUNTIME140.dll was not found"
comes from an older build that linked the Microsoft C runtime dynamically and
needed the Visual C++ Redistributable for x64. Current builds link the C
runtime statically (`.cargo/config.toml` sets `+crt-static` for MSVC targets),
so they need no redistributable: build from source or use a build made after
this change. If you set `RUSTFLAGS` or
`CARGO_ENCODED_RUSTFLAGS` when building, it replaces the flags from
`.cargo/config.toml`; add `-C target-feature=+crt-static` to it.

## Setup, status, reset and the installer

See [install.md](install.md).

- `refusing to run as LocalSystem (S-1-5-18) ...`: `gateinto setup` or
  `gateinto key init` runs as a
  service account, for example from a scheduled task or a deployment tool.
  Run it as the Windows user who uses Gateinto.
- `note: running elevated ...`: only a note; the key is still created for the
  current user.
- `no device key named "..."; run `gateinto setup` to create it`: after a fresh
  install or a purge. Run `gateinto setup`.
- `config: none (no file at ...)` in `status` or `setup`: no
  `%APPDATA%\Gateinto\gateinto.toml` exists and no `--config` was given. The
  installed handler and the autostart entry use that file.
- `uri-handler: another program: ...`: another application owns `gateinto://`
  for this user; Gateinto leaves it alone. `not registered`: install the MSI
  or run `gateinto uri register`.
- `refusing to delete the device key without confirmation: no terminal ...`:
  `reset` was run from a script. Pass `--confirm-spki` with the first 16 or
  more hex digits of `spki-sha256` from `gateinto status`.
- `the device key has spki-sha256 ..., which does not start with the
  confirmed ...`: the prefix does not match; nothing was deleted.
- `stopping the running agent failed: ...; nothing was deleted`: stop the
  agent (`gateinto stop`) and retry.
- `the agent (process <pid>) did not exit within 15 seconds`: from `stop`,
  `reset` or the uninstaller. End that process (Task Manager) and retry;
  `reset` deleted nothing.
- `'gateinto' is not recognized` right after installing: open a new terminal;
  the installer appended the install folder to the user `PATH`.
- `refusing to delete the config file without confirmation`: no device key
  exists and `reset` has no terminal to ask on; pass `--yes` with
  `--purge-config`.
- `--purge-config found no config file ...`: there is no default config file;
  name the file with `--config`.
- After uninstalling, `gateinto.exe` remains in `%LOCALAPPDATA%\Programs\Gateinto`:
  a process still had it open. Stop it and delete the file; the device key is
  not affected.

## Windows 7

Windows 7 is experimental and unsupported. See
[windows7-feasibility.md](windows7-feasibility.md).

- `The procedure entry point Tbsi_GetDeviceInfo could not be located in the
  dynamic link library tbs.dll.` when starting `gateinto.exe`: you are running a
  regular release (`x86_64-pc-windows-msvc` or `i686-pc-windows-msvc`) on
  Windows 7, and those releases require Windows 10 or later. Newer builds
  no longer import this function, but the regular releases still do not run
  before Windows 10. Use Windows 10 or 11. The only Windows 7 candidates are the
  experimental 32-bit `i686-win7-windows-msvc` executable attached to the
  `alpha` and `beta` releases (see [install.md](install.md#releases)) and built
  by the Windows 7 workflow, which has not been verified on Windows 7. There is
  no x64 Windows 7 build.
- On Windows 7 there is no TPM key storage provider, so keys are software keys.
  `Tbsi_GetDeviceInfo unavailable (expected on Windows 7)` in a warning or
  error means Gateinto detected this. With the default
  `software_fallback_on_first_create = true`, `setup` and `key init` create a
  software key. With fallback disabled they stop. Use `--backend software`.
