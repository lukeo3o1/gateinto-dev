# Gateinto

Gateinto is a local HTTP/1.1 `CONNECT` proxy for Windows 10/11 x64. Each
browser session it starts listens on its own ephemeral loopback port with its
own credentials; Gateinto by default opens a TLS 1.3 connection to a remote HTTPS forward proxy that you run and
issues the `CONNECT` there. ALPN selects HTTP/2, sharing one connection per
session, or HTTP/1.1 with a separate connection per tunnel. It can authenticate
the device to that proxy with
mutual TLS, using a non-exportable ECDSA P-256 key held by Windows CNG (TPM
preferred, software key storage as fallback). Key exchange prefers the hybrid
post-quantum group `X25519MLKEM768`.

## Status

Pre-release proof of concept, not production ready, and not externally
security reviewed. Implemented: the double `CONNECT` relay, the device key
(`gateinto key`), mutual TLS with the device key, selectable key exchange
modes, `gateinto check-upstream`, a TOML configuration file with named gateway
profiles, per-session isolation, short-lived
self-signed client certificates issued with the device key, and browser
sessions with random per-session local proxy credentials (`session_credentials`),
started from the command line or from a `gateinto://` launch URI by a per-user
agent that opens Chrome or Edge with an isolated profile, a per-user MSI
installer, `gateinto setup`, `gateinto status`, and deleting the device
identity with a confirmed `gateinto reset --purge-device-identity`. Not
implemented: certificate enrollment (CA-issued client certificates are issued
and installed by hand), key rotation, a WinGet package, an SBOM and code
signing. Browser
behavior (the Chrome and Edge credential prompt, credential caching, a new
session, a real browser launched by the agent, a `gateinto://` link clicked in
a browser) is not verified yet; see
[docs/browser-verification.md](docs/browser-verification.md).

Tests run in CI on GitHub-hosted Linux and Windows runners (`ubuntu-latest`
and `windows-latest`) against in-process test proxies. TPM-backed keys, real
third-party upstream proxies and physical machines are not verified; see
[verification status](docs/verification.md).

## Quickstart

Start with [docs/quickstart.md](docs/quickstart.md): it goes from a fresh
Windows 10/11 x64 machine (no TPM needed) to a working tunnel, including the
upstream proxy you need to bring. Release builds are a bare `gateinto.exe` for
Windows 10/11 x64 (`x86_64-pc-windows-msvc`) and one for 32-bit Windows 10
(`i686-pc-windows-msvc`), each with a `.sha256` checksum file. Builds link the
C runtime statically; CI checks that `gateinto.exe` imports no Visual C++
runtime DLL (see [static C runtime](docs/compatibility.md#static-c-runtime)).

## Install

[docs/install.md](docs/install.md) covers the per-user MSI built from
[packaging/wix](packaging/wix/README.md): install, first run with
`gateinto setup`, `gateinto status`, uninstall (which keeps the device key and
the config file), reinstall with the same device identity, and the explicit
purge. The MSI can also be built with `packaging/wix/build.ps1`. There is no
WinGet package; `winget install` does not install Gateinto. `packaging/winget`
holds manifest templates that have not been submitted.

The MSI installs `gateinto.exe` and the GUI, `gateinto-gui.exe`, side by
side in `%LOCALAPPDATA%\Programs\Gateinto`, and adds a per-user Start Menu
shortcut named **Gateinto** that opens the GUI. Installing starts neither the
GUI nor the agent, and does not turn on the GUI's own **Start the app at
sign-in** value. Uninstalling or upgrading closes a running GUI of the
current user and stops the agent. A full uninstall also removes the GUI's
`Gateinto App` sign-in value when it opens the installed GUI; an upgrade
keeps it. See [docs/install.md](docs/install.md).

## Releases

The repository is private, so its GitHub Releases are for the owner's own
downloads. There are three rolling releases, each with a tag of the same name
that moves to the commit it was built from
([details](docs/install.md#releases)):

- `alpha`: replaced automatically after CI passes on a push to `master` and
  the release build and tests pass; a prerelease.
- `beta`: replaced by hand through `workflow_dispatch` with a commit or ref;
  a prerelease.
- `latest`: replaced by hand the same way; marked as the latest release.

Every release has the x64 and x86 MSIs and the x64 and i686 executables;
`alpha` and `beta` also have the experimental Windows 7 executable for
`i686-win7-windows-msvc`. Each file is attached
with the short commit in its name and as a copy without it, each with a
`.sha256`, so a URL such as
`https://github.com/lukeo3o1/gateinto-dev/releases/download/latest/gateinto-x86_64-pc-windows-msvc.exe`
stays the same from one publish to the next. Verify the `.sha256` before
using a file; nothing is code-signed. Release builds report the version
`0.0.0-<commit>`; an MSI built locally from an older `Cargo.toml` version must
be uninstalled before a release MSI is installed.

## Commands

| Command | Purpose |
| --- | --- |
| `gateinto check-upstream` | Connect to the upstream once and print the negotiated TLS parameters. |
| `gateinto session browser` | Run one browser session with `session_credentials` local proxy authentication on an ephemeral loopback port and show its credentials. |
| `gateinto agent` | Run the per-user agent: the endpoint that starts browser sessions. `--detach` starts it in the background without a console and returns (the installer's logon autostart uses it). |
| `gateinto open -- <uri>` | Start a browser session for a `gateinto://` launch URI through the agent, starting the agent if needed. |
| `gateinto session list`, `gateinto session close <id>` | List the agent's sessions, or close one (its browser is stopped, its profile deleted and its credentials revoked). |
| `gateinto session credentials <id>` | Show the local proxy credentials of one of the agent's sessions again, in the same prompt as at launch. |
| `gateinto stop` | Close all of the agent's sessions and stop it. It waits until the agent process has exited (at most 15 seconds). With `--remove-stale-profiles` (used by the uninstaller) it also succeeds when no agent runs and deletes Gateinto browser profiles left behind. |
| `gateinto gateway list`, `gateinto gateway forget <name>` | List the gateways with their default route and their source (the config file, or a `gateinto://` link the user approved), or remove one added from a link. |
| `gateinto uri register`, `gateinto uri unregister` | Register or remove the per-user `gateinto://` handler (Windows, development use). |
| `gateinto key init` | Open the device key, creating it only if none exists. |
| `gateinto key info` | Show the existing device key and its client certificate without creating anything. |
| `gateinto setup` | First run as the key's user: refuse service accounts, check the config, create or reuse the device key, report the `gateinto://` handler. See [docs/install.md](docs/install.md#first-run-gateinto-setup). |
| `gateinto status` | Show the key provider and SPKI, gateways, the agent's sessions and the handler, without changing anything. |
| `gateinto reset --purge-device-identity` | Delete the device key after the SPKI is confirmed (and with `--purge-config` the config file and the gateways added from links). Does not revoke the device at any gateway. See [docs/install.md](docs/install.md#purge-gateinto-reset---purge-device-identity). |

All commands that read the configuration accept `--config <file>`; flags
override the file key by key. Without `--config` they read
`%APPDATA%\Gateinto\gateinto.toml` if that file exists.
`gateinto <command> --help` lists every flag with its default.

### Upstream options

`gateinto check-upstream` and `gateinto session browser` take the same
upstream, TLS and client certificate options. The upstream endpoint has no
default and must be given, on the command line or in a
[configuration file](#configuration-file).

| Flag | Default | Meaning |
| --- | --- | --- |
| `--config` | none | TOML configuration file. Flags given on the command line override its values. |
| `--gateway` | the only configured gateway | Gateway from the configuration file. Required when several are configured. |
| `--upstream-host` | required (flag or config) | Upstream HTTPS proxy host name or IP address. This and the following upstream, TLS and client certificate flags override the selected [gateway](#configuration-file). |
| `--upstream-port` | required (flag or config) | Upstream HTTPS proxy port. |
| `--upstream-server-name` | upstream host | Name verified against the upstream certificate. |
| `--ca-file` | Mozilla roots | PEM bundle of CAs trusted for the upstream. Replaces the default roots. |
| `--tls-mode` | `hybrid_preferred` | Key exchange policy: `hybrid_preferred`, `hybrid_required` or `classical_only`. See [TLS modes](#tls-modes). |
| `--client-certificate` | `optional` | Client authentication to the upstream: `optional`, `required` or `off`. See [Client certificate](#client-certificate-mtls). |
| `--client-cert-file` | search `CurrentUser\My` | PEM file with the client certificate, optionally followed by intermediates. |
| `--self-signed-client-cert` | off | Issue short-lived self-signed client certificates with the device key, one per session, instead of using a file or `CurrentUser\My`. Cannot be combined with `--client-cert-file`. See [Self-signed client certificate](#self-signed-client-certificate). |
| `--key-name` | `gateinto-device-v1` | CNG device key that signs the client authentication. It is only opened, never created. |

The limits come only from the `[limits]` section of the configuration file:

| Key | Default | Meaning |
| --- | --- | --- |
| `max_concurrent_tunnels` | 64 | Concurrent connections, at most 32767; further connections get `503`. |
| `header_max_bytes` | 16384 | Limit for the request and the upstream response header block. |
| `connect_timeout_seconds` | 10 | Limit for reading the request, and a separate limit for connecting, the TLS handshake and the upstream `CONNECT` reply together. |
| `idle_timeout_seconds` | 300 | Close a tunnel after this long without traffic in either direction. |

### Local proxy behaviour

Every session listens on a loopback address only; there is no option to
listen on any other address.

Logging goes to stderr and is filtered with `RUST_LOG` (default `info`). Tunnel
payload is never logged. The target `host:port` of an established tunnel is
logged only at `debug`; when the gateway or the target refuses a tunnel, the
`warn` line names the target. Credentials and the `Proxy-Authorization` header
are never logged.

When more than `max_concurrent_tunnels` connections are open, further connections get a
`503`. At most 64 such rejections are handled at a time; beyond that, new
connections are closed without a response.

Local responses:

| Situation | Status |
| --- | --- |
| Direct TCP connected (mixed mode only) | `200 Connection Established`, then the tunnel |
| Upstream `2xx` | `200 Connection Established`, then the tunnel |
| Upstream `403` | `403` |
| Upstream `407` or any other status | `502`; upstream headers and body are not forwarded |
| Upstream connect, TLS or certificate failure, malformed reply | `502` |
| `hybrid_required` and the upstream cannot negotiate `X25519MLKEM768` | `502` |
| Upstream connect, handshake or reply timeout | `504` |
| Method other than `CONNECT` | `405` |
| Malformed request | `400` |
| Request header block over the limit | `431` |
| Request not complete within the connect timeout | `408` |
| Too many connections | `503` |

The request parser accepts only `CONNECT host:port HTTP/1.1` with exactly one
`Host` header, an LDH host name, IPv4 or bracketed IPv6 literal, and a port from
1 to 65535. It rejects bare LF, CR inside lines, NUL, obs-fold, control
characters in field values, `Transfer-Encoding`, and a non-zero
`Content-Length`. Bytes sent after the request header are forwarded once the
tunnel is up. The upstream uses HTTP/2 when ALPN selects `h2`, otherwise
HTTP/1.1. HTTP/2 tunnels share one TLS connection per session, with independent
stream limits and timeouts; GOAWAY and certificate renewal let existing streams
drain while new tunnels use a new connection. Details are in
[the upstream protocol](docs/protocol/http-connect.md).

Without `--ca-file` the upstream certificate is verified against the Mozilla
root program as bundled by `webpki-roots`. This is deterministic and identical
on every platform; it ignores roots added to the operating system store, so a
proxy with a private CA needs `--ca-file`.

### Checking the upstream

```sh
gateinto check-upstream --upstream-host proxy.example.com --upstream-port 443
gateinto check-upstream --config gateinto.toml --target example.com:443
gateinto check-upstream --config gateinto.toml --gateway office
```

`check-upstream` takes the [upstream options](#upstream-options), connects
once, completes the TLS handshake and prints:

```text
upstream: proxy.example.com:443
server-name: proxy.example.com
tls-mode: hybrid_preferred
tls-version: TLSv1_3
alpn: h2
key-exchange-group: X25519MLKEM768
cipher-suite: TLS13_AES_256_GCM_SHA384
server-certificate-subject: CN=proxy.example.com
client-certificate: not requested
```

`--gateway <name>` checks that gateway from the configuration file. Without
it the only configured gateway is checked; with several gateways configured,
`--gateway` is required. The upstream, TLS and client certificate flags then
override that gateway.

`client-certificate` is `not requested`, `requested by the upstream, none sent`
or `sent`. With `--self-signed-client-cert` three more lines follow it:
`client-certificate-source: self-signed`, `client-certificate-sha256` (SHA-256
of the certificate sent in the handshake) and `device-key-spki-sha256` (SHA-256
of the device key's SubjectPublicKeyInfo, the same value as `spki-sha256` in
`key info`). With `--target host:port` it also sends `CONNECT` for that target
and prints `connect-target` and the upstream status as `connect-status`
(`HTTP/2 <code>` for h2, the original status line for HTTP/1.1). The `alpn`
line is `h2`, `http/1.1`, or `none`. No upstream headers or body are printed, and the tunnel is
closed right away. No keys or other secrets are printed.

The command exits nonzero, with the reason on stderr, when the connection,
handshake, certificate verification or the mode check fails, when it does not
finish within the connect timeout (`[limits] connect_timeout_seconds`, default
10 s), or when the upstream answers the `CONNECT` with a non-`2xx` status. An
upstream that rejects the client certificate may only report that after the
handshake; use `--target` to see it.

### Device key

```sh
gateinto key init
gateinto key info --spki-out device.spki.der
```

The device key is a persisted, non-exportable ECDSA P-256 key in Windows CNG,
named `gateinto-device-v1` unless `--name` is given. These commands only work
on Windows; elsewhere they fail with "device keys are only supported on
Windows".

`key init` reuses an existing key with that name. It looks in both the
"Microsoft Platform Crypto Provider" (backend `tpm`) and the "Microsoft
Software Key Storage Provider" (backend `software`) and never creates a second
key. It stops with an error, without creating anything, when:

- keys with that name exist in both providers; the error names both backends
  and fingerprints, and one of the keys has to be deleted by hand;
- the TPM is present but not usable right now, for example because the TPM Base
  Services are stopped or disabled or the device is not ready
  (`TBS_E_SERVICE_NOT_RUNNING`, `TBS_E_SERVICE_DISABLED`,
  `NTE_DEVICE_NOT_READY`, `NTE_PROVIDER_DLL_FAIL`). An existing TPM key cannot
  be ruled out then, so no software key is created; fix the TPM and retry.
  These codes alone do not tell a missing TPM from one that is not ready, so
  when the Platform Crypto Provider returns one of them, TPM Base Services are
  asked whether a TPM exists (`Tbsi_GetDeviceInfo`). Only when they answer
  `TBS_E_TPM_NOT_FOUND` is the TPM treated as absent;
- a provider or an existing key cannot be opened for any other reason than
  "not found" or "provider absent".

Only a provider that is genuinely absent (`TBS_E_TPM_NOT_FOUND`,
`NTE_PROV_DLL_NOT_FOUND`, `NTE_BAD_PROVIDER`, `NTE_DEVICE_NOT_FOUND`) counts as
"no key there". Only when no key exists does it create one: in the TPM first,
proving it with a test signature, and otherwise in software with a warning that
says why. A TPM key that fails its test signature is deleted
before falling back. The export policy is set to non-exportable before the key
is finalized in both providers. No private key material is written anywhere.

A TPM that is disabled in firmware looks exactly like no TPM to Windows, so
`key init` then falls back to a software key. On machines known to have a TPM,
pass `--no-software-fallback` so that a disabled or missing TPM is an error
instead of a silently weaker software identity. GitHub-hosted `windows-latest`
runners have no TPM; there the Platform Crypto Provider reports
`NTE_DEVICE_NOT_READY` and the software fallback is used.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--config` | none | Read `[device_key]` from this TOML file; the flags below override it. |
| `--name` | `gateinto-device-v1` | CNG key name. Must not be empty or contain NUL. |
| `--backend` | `tpm` | Where to create a new key: `tpm` (falls back to software unless disabled) or `software`. An existing key is reused wherever it is. |
| `--software-fallback` | not set | Create a software key when the TPM cannot be used. Overrides `software_fallback_on_first_create = false`. |
| `--no-software-fallback` | not set | Fail instead of creating a software key when the TPM cannot be used. Overrides `software_fallback_on_first_create = true`. |

`--software-fallback` and `--no-software-fallback` cannot be combined. With
neither flag, the software fallback is allowed unless the configuration file
sets `software_fallback_on_first_create = false`.

`key info` opens the existing key, never creates one, and prints its backend,
algorithm (`ECDSA P-256`), the SHA-256 fingerprint of its DER
SubjectPublicKeyInfo as lowercase hex, and a trust note. A `tpm` key is
hardware-protected. A `software` key has the non-exportable flag set, but an
administrator or malware running as the user can still copy it. `--spki-out
<path>` writes the public SubjectPublicKeyInfo DER to a file. It fails in the
same lookup cases as `key init`, except that keys in both providers only produce
a warning on stderr naming both backends; it then shows the `tpm` key.

`key info` also shows the client certificate bound to the key, as the proxy
would choose it from `CurrentUser\My`: `client-certificate: none`, or its
subject, SHA-1 thumbprint (`client-certificate-sha1`), NotAfter and source.
With `--client-cert-file <pem>` it checks that file instead and fails if the
certificate's public key is not the device key's.

`gateinto setup` does the same as `key init` and also checks the account, the
config and the handler. `gateinto reset --purge-device-identity` deletes the key
after its SPKI is confirmed; see [docs/install.md](docs/install.md). There is
no rotate command. Manual steps for checking a real TPM are in
[docs/tpm-verification.md](docs/tpm-verification.md).

## Sessions

A session is one local entry point into the tunnel: a loopback listener bound
to one [gateway profile](#configuration-file), with its own TLS client
configuration, its own client certificate, its own upstream connections and
its own limits (`[limits]` applies to each session separately). Sessions
share only the device key.

- `gateinto session browser` runs one browser session: its own listener on
  an ephemeral port of `127.0.0.1`, its own client certificate and upstream
  connections, and `session_credentials` local proxy authentication. It relays
  through `--gateway` (or the only configured gateway) and accepts the same
  [upstream options](#upstream-options) as `check-upstream`. It prints
  its id, kind, gateway, `listen` address and `realm` on stdout, never a
  credential, shows the credentials in a prompt (see
  [Local proxy authentication](#local-proxy-authentication)) and runs until
  Ctrl+C. If the credentials cannot be shown it closes the session and exits
  with an error. Each start is a new session with a new realm and
  credentials, on a new ephemeral port.
- With self-signed client certificates, each session issues its own
  certificate for the device key when it starts and renews only its own; two
  sessions never present the same certificate. A certificate file or
  `CurrentUser\My` certificate is the same in every session.
- Closing a session stops it from accepting immediately: its port refuses new
  connections, its established tunnels are aborted, and its certificate is
  discarded, so no new `CONNECT` can use it. Its credentials are dropped with
  it: a browser that cached them gets connection errors on the closed port, and
  a later session on any port has other credentials. Other sessions keep
  running.
  `gateinto session browser` closes its session on Ctrl+C (or SIGTERM on
  Unix) and then exits.

### Launching a browser session from a link

`gateinto://connect?gateway=proxy.example.com` starts a browser session for
that gateway endpoint, reusing an existing profile or asking before adding a
new gateway. Port 443 is the default. `profile` is an optional legacy selector
and disambiguates several configured profiles at one endpoint. `portal` is
optional: inherit it for a known gateway, otherwise start on `about:blank`.
`url` may choose a start page only on the origin of a trusted portal; neither
`url` nor the gateway address creates a portal automatically.
The format, its limits and everything it can never do are specified in
[docs/protocol/launch-uri.md](docs/protocol/launch-uri.md). In short:

- Any website can open such a link, so the URI is strictly limited: at most
  8192 bytes, only `profile` (a gateway name), `auth` (`session_credentials`), `v`
  (`1`), `url`, `gateway`, `portal` and `route` (`gateway` or `mixed`), each once, percent-encoded. It never
  carries a credential, CA, TLS setting, certificate or command. A link with
  `auth=basic_tofu`, the removed trust-on-first-use mode, is refused with an
  error naming `session_credentials`.
- `url` must have exactly the origin (https, host, port) of the gateway's
  portal and applies to that launch only; a gateway without a portal refuses
  it.
- **Browser sessions default to `mixed` routing, which may reach sites
  directly instead of through the gateway: that exposes your local DNS
  lookups and your source IP address to those sites and bypasses the
  gateway's policy.** The strict option is `gateway` ("All" in the GUI):
  every CONNECT goes through the gateway.
  Each gateway has a saved default route, `mixed` unless its `route` in the
  configuration file or its gateway file says `gateway`; gateways already on
  disk without `route` are `mixed` too. A link without `route`
  uses that saved default; `route=gateway` or `route=mixed` applies to only
  that new browser session and changes nothing saved. In mixed mode, target and gateway DNS answers are compared by IP;
  any shared IP, missing answers or DNS failure selects gateway CONNECT.
  Other targets try direct TCP, falling back to the gateway on TCP error or
  timeout before local `200`. Gateway errors and established tunnels never
  switch routes. DNS and direct opening get at most half the existing total
  opening deadline. This heuristic can misclassify services with different or
  shared IPs; mixed mode exposes local DNS and the user's source IP and can
  bypass gateway policy. A gateway added from a link is saved with the route
  the link names, or with `mixed` when it names none; the confirmation names
  that route and, for `mixed`, warns about the exposure. A gateway added in
  the GUI's Add dialog is saved with `gateway` ("All") until the GUI offers a
  route choice, and `gateinto session browser` always uses the `gateway`
  route. See
  [session routing](docs/protocol/launch-uri.md#session-routing).
- System DNS work is limited to 64 queued or running lookups per process,
  shared by discovery and gateway connections. Timeouts do not release a
  blocking job's slot before it finishes; excess DNS work fails immediately.
  IP literals and existing gateway connections need no slot. OS lookups can
  still delay process shutdown. See
  [DNS work budget](docs/protocol/http-connect.md#dns-work-budget).
- At least one of `gateway` or `profile` is required; no individual field
  is mandatory in every URI. A supplied gateway or portal must match the
  selected known entry; omitted portal inherits it. Gateway-only selection
  matches canonical host and port without DNS and refuses ambiguous profiles.
  Known trust settings and portals are never changed. A new gateway needs
  approval first: a Windows dialog naming the internal or explicit profile,
  gateway, portal origin (or `none`) and the route it is saved with, with
  Cancel as the default button (a `yes` prompt on a terminal elsewhere; no
  desktop or terminal means refusal). For the `mixed` route the dialog warns
  that sites may be reached directly instead of through the gateway, exposing
  local DNS lookups and the IP address and bypassing the gateway's policy; for
  the `gateway` route it says that all traffic goes through the gateway. On
  approval the gateway is stored in its own
  file under `%APPDATA%\Gateinto\gateways\`, named after its address, with
  its name, host, port, optional portal and route, and later links to it do not ask
  again. A damaged file there disables only its own gateway. It uses the default TLS
  settings: public roots, `hybrid_preferred`, `client_certificate =
  "optional"`. The configuration file is never written, and its gateways win
  over linked ones of the same name.
- The registered handler runs `gateinto open -- "<uri>"`, which validates the
  URI and passes the request to the user's agent (`gateinto agent`) over a
  local named pipe that only the user can open (a Unix socket on Linux, for
  development), starting the
  agent with the same `--config` if none runs. The agent validates the request
  again; it never shows a dialog itself.
- On Windows, a failed `open` shows its error in a dialog when it has its own
  console or no console on an interactive desktop, so a link's error stays
  visible until dismissed. Existing terminal sessions and redirected stderr
  keep errors in stderr without a dialog. Argument errors are included;
  successful launches, help and version requests show no error notification.
- The agent accepts at most 5 launches a minute (asking included), one open
  confirmation and 4 browser sessions at a time. Each launch is a new session
  with its own port, realm and credentials, and a new browser process
  with its own profile directory under `%LOCALAPPDATA%\Gateinto\profiles`,
  started with `--user-data-dir`, `--proxy-server=http://127.0.0.1:<port>` and
  the start page: the link's `url`, else the gateway's `portal_url`, else
  `about:blank`. Outside Windows `gateinto open` then shows the session's
  credentials (see [Local proxy authentication](#local-proxy-authentication));
  the agent never shows them itself. On Windows the browser is started inside
  a job object of its own and the session also offers `os_user`, so the
  browser connects without a dialog and `gateinto open` shows no credentials;
  `gateinto session credentials <id>` still shows them for a client that
  `os_user` does not accept. If no job can be used for the browser (for
  example where Windows does not allow it, which may be the case on Windows
  7 and 8.1), the agent logs one warning for that launch and starts the
  browser without a job; that session then accepts only session credentials
  and `gateinto open` shows them.
- When the browser exits, the agent ends every process left in its job,
  waits up to 5 seconds for the job to be empty, then closes the session
  and deletes its profile directory. `gateinto session close <id>` and
  `gateinto stop` do the same explicitly; profiles left by a crashed agent
  are deleted when the next one starts.

For development on Windows, `gateinto uri register --config <file>` writes
`HKCU\Software\Classes\gateinto` for the current user, with the command
`"<gateinto.exe>" open --config "<file>" -- "%1"`, and `gateinto uri
unregister` removes it again; neither touches a handler that is not
Gateinto's. To try it without a browser link:

```powershell
gateinto open --config gateinto.toml -- "gateinto://connect?gateway=proxy.example.com"
gateinto session list
gateinto stop
```

See [docs/architecture.md](docs/architecture.md#sessions-and-gateway-profiles).

### Local proxy authentication

Local proxy authentication controls which local programs may use a session.
It is not authorization by the remote upstream. A session offers one or more
of these methods and accepts a client that passes any one of them. No session
accepts every local client, and no setting turns local proxy authentication
off:

- `session_credentials`: when the session starts, Gateinto generates a random
  password for it; the user name is always `gateinto`. A `CONNECT` without a
  `Proxy-Authorization` header gets `407 Proxy Authentication Required` with
  `Proxy-Authenticate: Basic realm="Gateinto session <16 hex digits>", charset="UTF-8"`,
  so a browser shows its own proxy sign-in dialog. Only the issued user name
  and password are accepted; any other credential gets `407` again and never
  becomes valid. Every session offers it.
- `os_user` (Windows only): the client sends no credentials. Gateinto looks
  up the process that owns the client's end of the connection and accepts the
  connection only when that process runs as the Windows account that runs
  Gateinto (the user SIDs of both process tokens are compared with
  `EqualSid`). In a browser session the process must also be inside the job
  object Gateinto started that session's browser in. Browser sessions on
  Windows offer it together with `session_credentials`. It keeps out other
  users of the machine and programs of the same user that run outside the
  browser's job, but it is not a boundary against code of the same user that
  is determined to get in (see
  [docs/threat-model.md](docs/threat-model.md)).

The removed trust-on-first-use mode `basic_tofu` is refused in a link
(`auth=basic_tofu`) and in the IPC request with an error naming
`session_credentials`.

Details of `session_credentials`:

- The user name is the fixed `gateinto`: browsers show it in clear in their
  proxy dialog and password manager, so it carries no secret. The password is
  12 symbols from the 31-letter alphabet `abcdefghjkmnpqrstuvwxyz23456789`
  (lowercase, without `i`, `l`, `o`, `0` and `1`), grouped by four with
  hyphens, such as `t9ce-hu4w-38nr`. It comes from the operating system's
  CSPRNG by rejection sampling, about 59.4 bits. That is ample against the
  only attack open to it, online guessing capped at 10 failures a minute;
  there is nothing to attack offline.
- They exist only in the memory of the process that runs the session and of
  the command that shows them. They are never written to disk, never logged at
  any log level, never part of an IPC error message, never shown by
  `gateinto status` or `gateinto session list`, never taken from a URI and
  never forwarded to the upstream. The check compares an HMAC-SHA-256 of the
  received `user:password` under a random per-session key with the tag of the
  issued one, in constant time.
- They are shown by the command that started the session, not by the agent:
  `gateinto open` and `gateinto session browser`. On
  Windows, browser sessions started by the agent offer `os_user` and
  `gateinto open` shows nothing, unless the browser could not be put in a job
  object; that session then accepts only session credentials and `open`
  shows them. On Windows with an interactive desktop they appear in a
  message box; elsewhere on the command's terminal (stderr). The prompt
  names the proxy address (`127.0.0.1:<port>`) the browser's sign-in dialog
  shows, and says to enter the credentials only there and never in a
  website's sign-in page or dialog.
  `gateinto session credentials <id>` asks the agent for them over its
  per-user IPC endpoint and shows the same prompt again. Without a desktop or
  terminal `gateinto open` prints a warning naming that command instead, and
  `gateinto session browser` closes its session and exits with an error,
  because nobody could use it.
- Authentication runs right after the request head is parsed, before any DNS
  lookup, routing decision, upstream connection or certificate signing. An
  unknown credential reaches nothing and is never remembered.
- The header must be exactly one `Proxy-Authorization` with the scheme
  `Basic` (any case), then spaces, then canonical padded base64 of at most
  1024 characters that decodes to `user:password` with a non-empty password
  and no control characters. A malformed `Basic` credential or a repeated
  header gets `400`; another scheme (for example `Bearer`) gets `407`.
- Rate limit: wrong, malformed or other-scheme credentials count as failures.
  After 10 failures within 60 seconds of the first one, the session answers
  every request, even one with the issued credentials, with
  `429 Too Many Requests` and `Retry-After` until those 60 seconds are over.
  A request without credentials is not a failure.
- The realm, the listen port, the credentials and the failure count belong to
  one session and are never shared with another session. Closing the session
  revokes its credentials: the port is closed, its tunnels end, and a new
  session has new credentials. There is no expiry or rotation while a session
  runs.
- The credentials keep out local programs that do not know them. They do not
  protect against malware running as the same user, which can read the
  agent's memory or the prompt, a copied password on the clipboard, or a
  website dialog that imitates the proxy sign-in; see
  [docs/security-model.md](docs/security-model.md#local-proxy-authentication-session_credentials).
  How Chrome and Edge on Windows cache and prompt for these credentials has
  not been verified.

Details of `os_user`:

- The check runs once per connection, as soon as it is accepted and before
  the request is read, and shares the connect timeout with reading the
  request: a check that does not finish in time gets `408` and logs the
  reason. Every answer other than an established tunnel closes the
  connection, so every new connection is checked again.
- Gateinto finds the row of the Windows TCP connection table whose local
  end is the client's address and whose remote end is the listener, retrying
  briefly when the row is not there yet. For an IPv4 client it also looks
  for an IPv4-mapped row in the IPv6 table, and rows without an owning
  process are skipped. It opens the owning process with
  `PROCESS_QUERY_LIMITED_INFORMATION`, looks the row up again while it holds
  the process handle (so a process ID reused in between is not trusted),
  reads the user SID of the process token and compares it with its own. In
  a browser session it then asks `IsProcessInJob` about the session's job.
- Any failure denies the connection: no matching row, a process or token
  that cannot be opened, another Windows account, a process outside the
  job, or an error from Windows. A denied connection is treated like one
  without credentials: `407` with the `Basic` challenge, and the session
  credentials work as usual.
- Denials do not count toward the failure limit of `session_credentials`;
  wrong session credentials count as before. The first denial of a session
  logs a warning with its reason and the fallback (`gateinto session
  credentials <session>`); later
  denials of that session are logged at debug level. No credentials are
  involved, and nothing secret is logged.
- Not verified: a client running elevated while Gateinto is not, under a
  real UAC split token. Gateinto may then be unable to open the client's
  process or token; the check fails closed, so such a client gets the
  `Basic` challenge. See
  [docs/compatibility.md](docs/compatibility.md#local-proxy-authentication-os_user)
  and [docs/security-model.md](docs/security-model.md#local-proxy-authentication-os_user).

## Configuration file

`gateinto check-upstream`, `gateinto session browser`,
`gateinto agent`, `gateinto open`, `gateinto uri register`,
`gateinto key init`, `gateinto key info`, `gateinto setup`, `gateinto status`
and `gateinto reset` accept `--config <path>` with a TOML file. Without it they
read `%APPDATA%\Gateinto\gateinto.toml` (`$XDG_CONFIG_HOME/gateinto/gateinto.toml`
on Linux) if it exists, which is where an installed Gateinto finds its gateways.
See [config.example.toml](config.example.toml).

```toml
[gateways.default]               # one table per upstream; any name of 1-64 [A-Za-z0-9_-]
host = "proxy.example.invalid"   # required, here or with --upstream-host
port = 443                       # required, here or with --upstream-port
server_name = "proxy.example.invalid"
ca_file = "upstream-ca.pem"
tls_mode = "hybrid_preferred"    # hybrid_preferred | hybrid_required | classical_only
client_certificate = "optional"  # optional | required | off
client_cert_file = "client.pem"
self_signed_client_cert = false  # true: issue self-signed certificates instead of client_cert_file
portal_url = "https://portal.example.invalid/"  # start page of browser sessions; https only
route = "gateway"                # mixed (default) | gateway: default route of its browser sessions

[browser]
executable = 'C:\Program Files\Google\Chrome\Application\chrome.exe'  # default: Chrome, then Edge

[device_key]
name = "gateinto-device-v1"
preferred = "tpm"                # tpm | software
software_fallback_on_first_create = true

[limits]                         # applies to each session separately
max_concurrent_tunnels = 64
connect_timeout_seconds = 10
idle_timeout_seconds = 300
header_max_bytes = 16384
```

A gateway profile (`[gateways.<name>]`) holds everything about one upstream
HTTPS proxy: its address, the name and CAs its certificate is verified
against, the TLS mode and the client certificate settings.
`check-upstream` and `session browser` use the only configured gateway, or
the one named by `--gateway`; with several gateways `--gateway` is required.

Every key is optional except the gateway's `host` and `port`, which must come
from the file or the command line; there is no default upstream. Missing keys
take the defaults of the matching flags. Without any `[gateways.<name>]`
table, the flags alone describe the upstream, as an unnamed gateway
(`command-line` in logs).

| Key | Flag that overrides it |
| --- | --- |
| `[gateways.<name>] host`, `port`, `server_name`, `ca_file` | `--upstream-host`, `--upstream-port`, `--upstream-server-name`, `--ca-file` |
| `[gateways.<name>] tls_mode`, `client_certificate`, `client_cert_file` | `--tls-mode`, `--client-certificate`, `--client-cert-file` |
| `[gateways.<name>] self_signed_client_cert` | `--self-signed-client-cert` (can only turn it on) |
| `[device_key] name` | `--key-name` (`check-upstream`, `session browser`), `--name` (`key init`, `key info`) |
| `[device_key] preferred` | `--backend` (`key init`) |
| `[device_key] software_fallback_on_first_create` | `--software-fallback` or `--no-software-fallback` (`key init`) |
| `[gateways.<name>] portal_url`, `route`, `[browser] executable` | none |
| `[limits] max_concurrent_tunnels`, `connect_timeout_seconds`, `idle_timeout_seconds`, `header_max_bytes` | none |

Rules:

- Command line flags override the file, key by key. Gateway flags apply only
  to the gateway in use, the one selected with `--gateway` or the only
  configured one. Other gateways are not changed.
- Unknown sections and keys are errors, as are values of the wrong type, zero
  limits, ports or timeouts, an empty key name and an invalid gateway name.
  The earlier `[listen]`, `[upstream]` and `[tls]` sections are unknown
  sections. Errors name the file and, where it applies, the gateway, line and
  key; a `--gateway` that names no configured gateway is an error that lists
  the configured ones.
- The removed `[device_session]` section is refused with an error naming it
  and saying to delete it and start browser sessions with `gateinto open` or
  a `gateinto://` link.
- `self_signed_client_cert = true` and a `client_cert_file` cannot be
  combined, wherever each comes from.
- `portal_url` must be an `https://` URL with a host and no user information,
  of at most 2048 printable ASCII characters without spaces, quotes or
  backslashes. A launch URI cannot change it; a gateway added from a link
  brings its own portal, checked by the same rules.
- `route` is `mixed` (the default, also when the key is missing) or
  `gateway` (the strict option, "All" in the GUI); any other value is an
  error naming the gateway. It is the route of the gateway's browser sessions
  when a launch does not choose one (see
  [session routing](docs/protocol/launch-uri.md#session-routing)).
  **`mixed` may reach sites directly instead of through the gateway: that
  exposes your local DNS lookups and source IP address to those sites, and
  those connections bypass the gateway's policy.** Set `route = "gateway"`
  when all traffic must go through the gateway.
- Relative `ca_file`, `client_cert_file` and `[browser] executable` paths are
  resolved against the directory of the configuration file. Relative paths on the command line are
  resolved against the current directory.
- Sessions always listen on a loopback address. There is no key or flag
  that changes this.
- `[device_key] preferred` and `software_fallback_on_first_create` only affect
  `key init`; sessions only open the key named by `[device_key] name`.

## TLS modes

The upstream connection is always TLS 1.3 only, and the upstream certificate
and name are always verified with WebPKI as described above. `--tls-mode` (or
`[gateways.<name>] tls_mode`) only decides which key exchange groups are offered:

| Mode | Offered groups, in order | Upstream without `X25519MLKEM768` |
| --- | --- | --- |
| `hybrid_preferred` (default) | `X25519MLKEM768`, `X25519` | Falls back to `X25519`. |
| `hybrid_required` | `X25519MLKEM768` | Handshake fails; local clients get `502`. Never downgrades. |
| `classical_only` | `X25519` | Uses `X25519` (also against hybrid-capable upstreams). |

After every upstream handshake Gateinto reads the negotiated protocol version
and key exchange group and logs them at `debug` per TLS connection
(`upstream TLS established version=Some(TLSv1_3)
key_exchange_group=Some(X25519MLKEM768)`). It also checks that the version is
TLS 1.3 and that the group is one the mode offers, and refuses the tunnel with
`502` otherwise. For `hybrid_required` this is a second check behind the offered
list: a tunnel is never relayed over anything but `X25519MLKEM768`.

The hybrid group protects the confidentiality of the outer TLS session against
later decryption by a quantum computer. Certificates and the device key still
use classical signatures, so authentication is not post-quantum.

## Client certificate (mTLS)

The upstream connection is TLS 1.3 only, uses the key exchange of the
selected [TLS mode](#tls-modes), and
verifies the upstream certificate exactly as without client authentication.
When the upstream asks for a client certificate, Gateinto sends the configured
one and signs `CertificateVerify` with the device key through CNG
(`rustls-cng` `CngSigningKey`, `ECDSA_NISTP256_SHA256`, DER signatures).

At startup the device key named by `--key-name` is opened (TPM provider first,
then software; it is never created here), and the certificate is taken from:

1. `--self-signed-client-cert`: a fresh self-signed certificate for the device
   key, issued and signed by the device key itself; no file or store is read.
   See [Self-signed client certificate](#self-signed-client-certificate).
2. `--client-cert-file`: the first PEM certificate is the leaf, any further
   ones are sent as intermediates.
3. Otherwise, on Windows, the `CurrentUser\My` certificate store: a certificate
   whose SubjectPublicKeyInfo is byte-for-byte the device key's, that is valid
   now, and that has the Client Authentication extended key usage or no
   extended key usage at all. Whether Windows holds a private key for it does
   not matter, because the device key signs. If several match, the one with
   the latest NotAfter is used and its SHA-1 thumbprint is logged at `info`.

Before a certificate is used, its public key is compared with the device key's.
A certificate whose private key Gateinto does not hold is never sent.

| Situation | `required` | `optional` (default) | `off` |
| --- | --- | --- | --- |
| Key and matching certificate | client auth | client auth | no client auth |
| Device key missing or unusable | startup error | warning, no client auth | no client auth |
| No certificate for the key (file or store) | startup error | warning, no client auth | no client auth |
| Self-signed certificate cannot be issued | startup error | warning, no client auth | no client auth |
| Certificate for another key, or unreadable `--client-cert-file` | startup error | warning, no client auth | no client auth |
| Not Windows | startup error "device keys are only supported on Windows" | warning, no client auth | no client auth |

Without client auth in `optional` mode the warning is logged once at startup
and ends with "mTLS is not configured and upstream connections do not
authenticate this device". An upstream that requires a client certificate
then rejects the handshake, and local clients get `502`. With client auth
enabled, the subject, thumbprint, NotAfter, source and key backend are logged at
`info` (for a self-signed certificate the device key's SPKI SHA-256 instead of
thumbprint and NotAfter, and each session logs its own certificate's
SHA-256).

### Self-signed client certificate

With `--self-signed-client-cert` (or `[gateways.<name>] self_signed_client_cert = true`),
`check-upstream` issues a new certificate at startup, and every session
issues a new one for itself when it starts:
`CN=Gateinto device` as subject and issuer, a random 16-byte serial number,
valid from 5 minutes before issuance until 24 hours after it, critical basic
constraints without CA, critical key usage `digitalSignature`, extended key
usage `clientAuth`, and the device key's public key. The device key signs the
certificate and the TLS `CertificateVerify` through CNG; there is no other
private key, and the certificate is never written to disk or to a store. Once
a session's current certificate is 12 hours or older, the session issues a
new one for itself before the next upstream connection with `required`, or when the upstream next
asks for one with `optional`. With HTTP/2, new streams rotate to a fresh TLS
connection after renewal and existing streams may drain on the old connection.
A failed renewal is retried at most once a
minute. An expired certificate is never sent: if renewing fails after the
current one has expired, `required` fails each upstream connection locally and
`optional` connects without a client certificate.

Every certificate has a different serial number, DER and fingerprint, but the
same SubjectPublicKeyInfo. The upstream therefore has to identify the device by
its public key (`spki-sha256` from `gateinto key info`, or the DER from
`--spki-out`), not by the certificate fingerprint, and has to be configured to
accept a self-signed client certificate at all. Whether it does is entirely
the upstream's policy; no real upstream proxy has been verified with it.
[docs/protocol/client-cert.md](docs/protocol/client-cert.md) lists every field
and what the upstream has to check.

### Getting a test client certificate

There is no enrollment; the certificate must be issued for the device
key's public key by a CA the upstream trusts. For a test setup with OpenSSL 3
and a throwaway CA (verified with OpenSSL 3.0.13; the device key itself stays
in CNG):

```sh
gateinto key info --spki-out device.spki.der
openssl ecparam -name prime256v1 -genkey -noout -out test-ca.key
openssl req -x509 -new -key test-ca.key -subj "/CN=gateinto test client CA" -days 30 -out test-ca.pem
openssl pkey -pubin -inform DER -in device.spki.der -out device.pub.pem
printf 'basicConstraints = CA:FALSE\nkeyUsage = digitalSignature\nextendedKeyUsage = clientAuth\n' > client.ext
openssl x509 -new -CA test-ca.pem -CAkey test-ca.key -force_pubkey device.pub.pem \
  -subj "/CN=gateinto-device" -days 30 -extfile client.ext -out client.pem
```

Then either pass `--client-cert-file client.pem`, or import it into the user
store so that the proxy finds it by its public key:

```powershell
certutil -user -addstore My client.pem
gateinto key info
```

`key info` should then list the certificate. Remove it again with
`certutil -user -delstore My <thumbprint>`. The import commands have not been
run as part of the test suite, which imports through the Crypt32 API instead.

The upstream only accepts the certificate if it is configured to trust
`test-ca.pem` as a client CA. Note that tools such as
`New-SelfSignedCertificate` generate a new key pair, so their certificates do
not match the device key and are refused; use `--self-signed-client-cert` for a
self-signed certificate of the device key.

## Security model

[docs/security-model.md](docs/security-model.md) describes what Gateinto
protects and how (TLS 1.3 only, certificate verification that cannot be
disabled, no inspection of the inner TLS, non-exportable device key,
loopback-only listener, no secrets or payload in logs) and what it does not.
[docs/threat-model.md](docs/threat-model.md) lists assets, trust boundaries
and residual risks. [docs/security-boundaries.md](docs/security-boundaries.md)
maps each security acceptance item to the code that enforces it and the tests
that prove it.

Every session listens on loopback only and accepts only the random
credentials issued to it and shown to the user, which keeps out other
programs that do not know them but not malware running as the same user.
On Windows a browser session also accepts, without credentials, a program of
the Windows user running Gateinto that is inside the browser's job object.
There is no shared local proxy and no session without authentication. Do not
run Gateinto on shared hosts you do not trust.

Any website can open a `gateinto://` link. With the handler registered, such a
link can at most make the agent start a browser session for a known gateway
on a page of that gateway's portal origin, at most 5 times a minute and 4
sessions at a time, or ask the user, in a dialog that defaults to Cancel, to add
the gateway it names. It cannot change a known gateway, set a trust setting or
a credential, or run anything else. A gateway the user approves sees the
isolated browser's connections and, if it asks for one, the device
certificate; this deliberately relaxes the original rule that a link never
introduces a proxy host. See
[docs/security-model.md](docs/security-model.md#gateways-added-from-links).

## Starting the agent from the GUI

When the GUI (`gateinto-gui.exe`) finds no running agent, its sessions page
and tray flyout offer **Start agent**. Only a click starts it, and only one
start runs at a time. The GUI runs `gateinto.exe agent --detach` from its own
directory by absolute path, without a shell, without `--config` and without
a console window, and waits up to 45 seconds for it to exit. On success it
refreshes at once; otherwise it shows a fixed message, never the command's
output, until the next start or until the agent is no longer stopped. It does
not retry. After a timeout, an agent the command had already started may
still come up and show as running at the next refresh. Quitting the GUI
during a start normally ends the `agent --detach` command, so whether an agent
comes up depends on how far it got. If `gateinto.exe` is missing it shows a fixed
message and starts nothing. The demo never starts an agent. This is
unit-tested but has not been tried on a real Windows desktop.

## Which config file the GUI reads

While an agent runs, the GUI asks it on every refresh (every 2 seconds)
which config file it loaded, and reads gateways, agent settings and the
device key name from that file. When no agent runs, or the agent is too old
to answer, the GUI reads the default config file. If the running agent uses
another file, Settings shows its path marked as used by the running agent; if
it runs without one, Settings says so. The GUI never writes the config file.
This is unit-tested but has not been tried on a real Windows desktop.

## Agent at sign-in in the GUI

Settings shows, read-only, whether the agent starts at sign-in, from the
installer's `Gateinto` string value in
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and the `Gateinto`
value Windows keeps in
`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`
when the entry is turned on or off in Task Manager or Settings. It shows:

- **On** when the Run value runs `gateinto.exe agent --detach` and the
  StartupApproved value is absent or its first byte is `02`;
- **Off** when the Run value is missing, or when it runs that command and the
  StartupApproved value's first byte is `03`;
- **Unknown** otherwise: the Run value holds any other command, has another
  type than a plain string, or cannot be read, or the StartupApproved value
  is empty, starts with another byte, has another type than binary, or cannot
  be read.

Only that fixed text is shown, never the values themselves. A note says the
installer sets it, for example when installed with `AUTOSTART=1` (see
[docs/install.md](docs/install.md)). The GUI never writes, creates or deletes
either value and never starts the agent on its own. It reads the value when Settings opens and at most once per 2-second
refresh while Settings is shown. The separate **Start the app at sign-in**
switch only controls the GUI's own `Gateinto App` value, which opens the app,
not the agent; a full uninstall removes that value (see
[docs/install.md](docs/install.md)). The demo shows **On** without reading the registry. This is
unit-tested but has not been tried on a real Windows desktop.

## Removing a gateway in the GUI

The gateway details in the GUI offer **Remove** only for a gateway added on
this device from a `gateinto://` link. Gateways from the config file stay
read-only there. Remove first asks for confirmation in a dialog that names
the gateway and has Cancel first; it then does what `gateinto gateway forget
<name>` does, with the same refusals: a name defined in the config file, a
name held by several files, a damaged file or no such gateway removes
nothing and shows a fixed message. Only that gateway's file in `gateways/` is
deleted; the config file, the device key and its identity are not touched.
Browser sessions already open through the gateway stay open until they are
closed. The list shows the change at the next refresh, within 2 seconds. The
demo never removes anything. This is unit-tested but has not been tried on a
real Windows desktop.

## Verification status

[docs/verification.md](docs/verification.md) lists each capability (relay,
software and TPM keys, mTLS, hybrid key exchange, `hybrid_required`, Windows 7)
with how it is verified, its current status and what is still needed.
[docs/compatibility.md](docs/compatibility.md) has the detailed evidence.

## 32-bit Windows

The `i686-pc-windows-msvc` build ships as an executable and an x86 MSI. CI
builds it, runs the full test suite as 32-bit processes under WOW64 on 64-bit
Windows, checks that it links the C runtime statically, and installs,
uninstalls and purges an x86 MSI with it under WOW64. Neither has ever run on
a real 32-bit Windows 10 installation, and the x86 MSI is untested on
Windows 7, where the i686 executable does not start. See
[docs/compatibility.md](docs/compatibility.md#32-bit-windows-i686).

## Windows 7

Windows 7 is not supported and the `latest` release has no Windows 7 build.
The `alpha` and `beta` releases attach an experimental 32-bit
`i686-win7-windows-msvc` executable that passes a static import audit in CI.
On Windows 7 it can use only the Software Key Storage Provider, since Windows 7
has no TPM key storage provider. It has never been run on Windows 7; there is
no x64 Windows 7 build. See
[docs/windows7-feasibility.md](docs/windows7-feasibility.md).

## Build and test

```sh
cargo build
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
```

The minimum supported Rust version is 1.88 (required by `rcgen` and `time`).

`.cargo/config.toml` links the C runtime statically on Windows MSVC targets
(`-C target-feature=+crt-static`). Setting `RUSTFLAGS` or
`CARGO_ENCODED_RUSTFLAGS` replaces those flags, so include
`-C target-feature=+crt-static` in it when building for Windows.

Windows CNG tests only run on Windows. They create and delete temporary keys
named `gateinto-test-*` in the current user's Microsoft Software Key Storage
Provider, and in the Microsoft Platform Crypto Provider on machines with a
usable TPM. `tests/mtls_windows.rs` also adds a temporary certificate with
subject `CN=gateinto-test-client` to `CurrentUser\My` and removes it again;
its self-signed certificate test only keeps certificates in memory.
`tests/uri_registration.rs` (Windows only) writes and deletes
`HKCU\Software\Classes\gateinto-test-*` keys; it never touches
`HKCU\Software\Classes\gateinto`. The CLI and launch tests point
`XDG_CONFIG_HOME` and `APPDATA` at empty temporary directories so that a real
default config file does not change them. The agent and launch tests start a fake
browser (`tests/fake_browser.rs`, built as a test target) instead of Chrome or
Edge, with their own `GATEINTO_INSTANCE`, runtime and profile directories.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development rules and quality
gates, and [SECURITY.md](SECURITY.md) for reporting vulnerabilities privately.
Design notes: [architecture](docs/architecture.md),
[troubleshooting](docs/troubleshooting.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
