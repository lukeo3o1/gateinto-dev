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
| `400` | The request was malformed, or the client closed the connection before finishing it. Only `CONNECT host:port HTTP/1.1` with exactly one `Host` header and at most one `Proxy-Authorization` header is accepted; with `basic_tofu`, a malformed Basic credential (bad base64, no `:`, empty password, control characters, over 1024 characters) is also `400`. | Configure the client to use Gateinto as an HTTP proxy for HTTPS, not as a SOCKS proxy or an HTTPS proxy. |
| `407` | Browser sessions and `[device_session] auth = "basic_tofu"` only: the request had no credential, another scheme than Basic, or a credential other than the one bound to the session. Browsers show their credential prompt. | If the prompt keeps coming back with the credential you chose, another local program bound its credential first: stop the session and start a new one. Gateinto never logs credentials; a `warn` line says when a different credential was refused. |
| `429` | `basic_tofu` only: 10 wrong or malformed credentials within 60 seconds. Every request gets `429` until `Retry-After` seconds have passed. | Which local program is sending wrong credentials (`warn` lines name the client's local port). |
| `403` | The upstream proxy answered `403`. | The upstream proxy's access policy for this target or this device. |
| `405` | The method was not `CONNECT`. Plain HTTP requests such as `GET http://...` are not supported. | Use `https://` URLs, or send the client's plain HTTP traffic elsewhere. |
| `408` | The request head was not complete within `--connect-timeout-secs`. | A client that opens the connection but does not send a request, or a very slow client. |
| `431` | The request header block was larger than `--max-header-bytes`. | Clients that send many or large headers with `CONNECT`. |
| `502` | The upstream connection failed: TCP connect refused or unreachable, TLS handshake or certificate failure, a key exchange the TLS mode does not allow, a malformed or oversized reply, or any upstream status other than `2xx` and `403` (including `407`). | The `warn` log line `upstream refused tunnel` shows the cause. See [Private CA certificates](#private-ca-certificates) and [hybrid_required fails](#hybrid_required-fails). |
| `503` | `--max-tunnels` connections are already open. | Raise `--max-tunnels`, or find the client holding connections open. |
| `504` | The upstream TCP connect, TLS handshake and `CONNECT` reply did not finish within `--connect-timeout-secs`. | Network reachability of the upstream proxy, firewalls that drop instead of reject, or a slow upstream. |

The upstream's own headers and body are never forwarded, so a `407` from the
upstream appears as a `502` locally. An upstream that requires a client
certificate rejects Gateinto when no client certificate is configured (see the
"mTLS is not configured" warning at startup), and Gateinto returns `502`.

`gateinto check-upstream` (same options as `proxy`, or `--config`) connects
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
gateinto proxy --upstream-host proxy.example.com --upstream-port 443 --ca-file corp-ca.pem
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
WARN ... upstream refused tunnel error=TLS handshake failed: received fatal alert: HandshakeFailure
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
- `[device_session] gateway names the unknown gateway "<name>"` (or
  `--gateway names ...`): the name must match a `[gateways.<name>]` table; the
  message lists the configured ones. With several gateways and no
  `[device_session] gateway`, the device session cannot pick one and you must
  set it.
- The `[listen]`, `[upstream]` and `[tls]` sections of earlier development builds are
  unknown sections: move their keys to `[device_session] listen` and a
  `[gateways.<name>]` table (`[tls] mode` becomes `tls_mode`).
- Zero limits, ports or timeouts, an empty `[device_key] name`, and unknown
  values for `tls_mode`, `client_certificate` or `preferred` are rejected, as
  are gateway names other than 1 to 64 characters from `A-Z`, `a-z`, `0-9`,
  `_` and `-`.
- Relative `ca_file` and `client_cert_file` paths are relative to the
  configuration file, not to the current directory.
- Command line flags override the file. If a value seems ignored, check that
  the same flag is not also given.
- A non-loopback `[device_session] listen` address is refused unless
  `--unsafe-allow-non-loopback-listen` is passed on the command line; see below.

## Non-loopback listen address refused

```text
error: refusing to listen on non-loopback address 0.0.0.0:18736; pass --unsafe-allow-non-loopback-listen to override
```

The same error appears for a non-loopback `[device_session] listen` in a
configuration file; the opt-in exists only as a command line flag.

The listener has no authentication, so on a non-loopback address anyone on the
network could use it and the identity behind it. Keep the default
`127.0.0.1:18736`, or another loopback address. Pass
`--unsafe-allow-non-loopback-listen` only if you control who can reach the
address. See [threat-model.md](threat-model.md).

## Launch links and the agent

Messages from `gateinto open`, `gateinto agent`, `gateinto session list`,
`gateinto session close` and `gateinto stop`
([protocol/launch-uri.md](protocol/launch-uri.md)):

- `invalid launch URI: ...`: the link breaks a rule of the format; the
  message names the rule. Nothing was started.
- `unknown gateway "<name>"; configured gateways: ...`: the agent's
  configuration file has no `[gateways.<name>]` table. The agent reads its
  file once when it starts; after editing the file run `gateinto stop` so the
  next launch starts a new agent.
- `no agent is running`: from `session list`, `session close` or `stop`.
  `gateinto open` starts one by itself.
- `an agent is already running for this user at ...`: only one agent per user
  (and per `GATEINTO_INSTANCE`) can run. Use `gateinto stop` to replace it.
- `the agent exited (...) before accepting requests`: the agent started by
  `open` could not start, usually because of the configuration file or a
  device session that cannot listen. Run `gateinto agent --config <file>` in
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

## Windows 7

Windows 7 is experimental and unsupported. See
[windows7-feasibility.md](windows7-feasibility.md).
