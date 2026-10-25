# Threat model

Gateinto is a pre-release proof of concept. This document states what it is
meant to protect, against whom, and what it does not protect.
[security-model.md](security-model.md) summarizes the mechanisms;
[verification.md](verification.md) says which of them are tested.

## Assets

- **Device private key.** A non-exportable ECDSA P-256 key in Windows CNG (TPM
  preferred, software key storage as fallback) that authenticates the device
  to the upstream proxy with mutual TLS when a certificate for it is
  installed.
- **Tunnel traffic.** The bytes clients send through the tunnel, and the target
  `host:port` of each tunnel.
- **Upstream credentials.** Whatever the upstream proxy trusts to grant
  access: the device key and its certificate, and the CA bundle that decides
  which upstream Gateinto trusts.
- **Configuration.** The configuration file and command line decide which
  upstream is trusted and which TLS mode is used. They contain no secrets.

## Trust boundaries

- **Local processes and the loopback listener.** The device session's
  listener has no authentication by default. Any process on the machine that
  can open a TCP connection to `127.0.0.1`, including processes of other
  users, can use it and the device identity behind it. A session with
  `session_credentials` (every browser session) accepts only the random user
  name and password generated for it, so it excludes local processes that do
  not know them. The credentials are shown to the user, who types them into
  the browser's proxy sign-in dialog; a program running as the user can get
  them from the agent or from memory.
- **Websites and the launch URI.** Any web page, e-mail or document can open
  a `gateinto://` link. When the handler is registered, the URI reaches
  `gateinto open` and then the agent as untrusted input. It can name a known
  gateway and a start page on that gateway's portal origin, or bring a new
  gateway (host, port and optional portal only) that is used only after the user
  approves it; see [protocol/launch-uri.md](protocol/launch-uri.md).
- **Programs of the same user and the agent's IPC endpoint.** Any program
  running as the user can send requests to the agent, including `approve`
  for a confirmation it requested itself, so it can add a gateway without
  the dialog. That is no new privilege: it could also write
  a file in `gateways/` or the configuration file directly. The
  confirmation token only ties an answer to the request the agent
  validated; it does not prove that a person answered. Other users and
  remote machines cannot write to the endpoint.
- **Gateinto and the upstream proxy.** The upstream proxy sees the target
  `host:port` of every tunnel, the source IP address and the device
  certificate. It does not see the content of an inner TLS session between the
  client and the target. Traffic that is not encrypted end to end inside the
  tunnel is visible to the upstream proxy.
- **Network between Gateinto and the upstream proxy.** Untrusted. Protected by
  TLS 1.3 with certificate verification.
- **TPM versus software key protection.** A TPM-backed key cannot be
  exported from the TPM, though a process running as the user can still ask the
  TPM to sign with it. A key in the "Microsoft Software Key Storage Provider"
  is protected by the operating system (DPAPI) only; anyone with the user's or
  an administrator's rights can extract or misuse it.
- **Administrators and malware running as the user.** Outside the boundary.
  They can read process memory, replace the binary, change its arguments, add
  CAs, and use the device key for signing. Gateinto does not defend against
  them.

## Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| Other machines on the network use the proxy and the identity behind it. | The listen address must be loopback. A non-loopback address is refused unless `--unsafe-allow-non-loopback-listen` is given on the command line; the configuration file has no key that allows it. |
| A configuration file with a typo silently runs with defaults. | Unknown sections and keys are errors (`deny_unknown_fields`), and there is no default upstream. |
| Gateinto reads or alters tunnel content. | No MITM: Gateinto never terminates the client's inner TLS and does not inspect tunnel bytes. |
| Malformed or hostile requests cause request smuggling, desynchronisation or resource exhaustion. | Strict parser: only `CONNECT host:port HTTP/1.1` with exactly one `Host` header; rejects bare LF, CR inside lines, NUL, obs-fold, control characters, `Transfer-Encoding` and a non-zero `Content-Length`. Header block size limit, request and upstream timeouts, idle timeout, and a limit on concurrent connections. |
| A client believes a tunnel exists when the upstream refused it. | A gateway route sends local `200` only after the upstream answers `2xx`; a mixed direct route requires a connected TCP socket. Upstream error headers and bodies are not forwarded. |
| An attacker on the network impersonates the upstream proxy or downgrades TLS. | TLS 1.3 only (`rustls` without `tls12`). The upstream certificate and name are verified with WebPKI against the Mozilla roots or `--ca-file`. There is no option to disable verification. |
| Recorded traffic is decrypted later by a quantum computer. | The hybrid key exchange `X25519MLKEM768` is preferred, with `X25519` as fallback (`hybrid_preferred`). This protects the confidentiality of the outer TLS session only if the upstream also supports it. It is not a post-quantum signature: certificates and the device key use classical ECDSA or RSA, so authentication is not quantum resistant. |
| An attacker on the network, or a misconfigured upstream, downgrades the key exchange to classical `X25519`. | `hybrid_required` offers only `X25519MLKEM768`, so the handshake fails (`502`) instead of downgrading, and every tunnel is also checked after the handshake and refused unless the negotiated group is one the mode offers. TLS 1.3 signs the handshake transcript, so an attacker without the server key cannot alter the negotiated group in the other modes either; `hybrid_preferred` still accepts `X25519` from an upstream that only offers it. `check-upstream` shows which group an upstream negotiates. |
| Another local program uses a browser session's port. | `session_credentials`: the session accepts only the user name and password generated for it from the system CSPRNG (about 99 bits); any other credential gets `407` and is never learned, however early it arrives. The check is an HMAC-SHA-256 under a per-session key compared in constant time, and it runs before any DNS lookup, routing decision, upstream connection or device key signature. Failures beyond 10 a minute get `429`. Closing the session revokes the credentials: the port closes, its tunnels end, and a new session has new credentials. |
| A website phishes the session credentials with a page or dialog that imitates the browser's proxy sign-in. | The prompt that shows the credentials names the proxy address the real dialog shows and says to enter them only there, never in a website. Credentials typed into a page are useful only from this machine, because the port listens on loopback, and only until the session closes. Not prevented technically (see residual risks). |
| A website uses a `gateinto://` link to add a trust anchor or TLS setting, inject a credential, change a known gateway, open an arbitrary page or run a command. | The URI has no field for a CA, TLS mode, client certificate, server name, listen address, credential or command; `auth` is only `session_credentials`, and the removed `basic_tofu` is refused. A link that disagrees with the host, port or portal of a known gateway is refused, and the configuration file is never written. `url` must have the origin of the gateway's portal. Strict parser (allowed characters, no duplicates or unknown fields, 8192 bytes), applied by `open` and again by the agent. The handler passes the URI after `--` as one argument and nothing starts a shell. |
| A website uses a `gateinto://` link to route the user through its own proxy (deliberate, user-approved deviation from the plan's rule that a URI never introduces a proxy host). | Only after an explicit first-time confirmation in `gateinto open` that names the profile, gateway `host:port` and portal origin or `none`, with OK and Cancel, Cancel as the default and no access keys, so no single keystroke approves it; no desktop or terminal means refusal. The agent never prompts, rate-limits before asking, keeps one confirmation open and needs the one-time token of that request (which binds the answer to the request but does not prove a person gave it). The gateway gets only default settings (public roots, host as server name); it is stored separately, listed with its source and removable with `gateinto gateway forget`. Remaining: phishing and the device certificate's SPKI (see residual risks). |
| A website floods the user with launches or confirmation dialogs. | At most 5 launch requests per minute (confirmations included) and 4 browser sessions at a time per agent; at most one confirmation is open at a time. |
| A launch leaks state between browser sessions or into the user's profile. | Each launch gets a new session (port, realm, credentials, failure count, certificate) and a new browser profile directory, deleted when the browser exits or the session is closed. |
| Profile cleanup deletes the wrong directory. | Only directories directly in the profiles directory, with Gateinto's name pattern and marker file, are deleted; links are not followed. |
| Another user or a remote machine controls the agent. | Per-user named pipe (named after the SID, first instance, remote clients rejected, owned by the user, DACL granting access only to the user and SYSTEM); clients refuse a pipe owned by another user; `0600` socket in a `0700` directory owned by the user on Unix. |
| URI registration clobbers another application's handler or leaves a broken one. | Only `HKCU\Software\Classes\gateinto` is written; an existing non-Gateinto handler is refused; a failed first registration is rolled back; unregistration removes only a Gateinto handler. |
| Logs leak secrets or traffic. | Tunnel payload and local proxy credentials are never logged, at any level. Session credentials exist only in memory and are never written to disk, part of an IPC error message or shown by `gateinto status`; the session verifies against an HMAC tag of them. Private keys are never logged; the client certificate's subject, thumbprint and NotAfter are logged at `info`. Target `host:port`, the negotiated key exchange group and byte counts are logged at `debug`. `check-upstream` prints only TLS parameters, the server certificate subject and the upstream status line, never upstream headers or bodies. |
| An installer running as `SYSTEM` or another account creates a device key the user cannot use, or a second identity. | The MSI is per user and has no custom action that touches a key. `gateinto setup` refuses LocalSystem, LocalService and NetworkService and reuses an existing key. The agent and `open` never create a key. |
| An uninstall, a silent uninstall or a script destroys the device identity. | Uninstall keeps the key and the config; they are not MSI components. `reset --purge-device-identity` requires the SPKI prefix, refuses without a terminal unless `--confirm-spki` matches, and deletes only the named Gateinto key after rechecking its SPKI. |
| Uninstall cleanup deletes the user's own browser data. | The uninstaller only runs `gateinto stop --remove-stale-profiles`, which deletes Gateinto-marked profile directories under `%LOCALAPPDATA%\Gateinto\profiles`, never the user's Chrome or Edge profiles. |
| The device identity is silently replaced, for example by an attacker or a bug that recreates the key. | `key init` reuses an existing key in either provider and creates one only when none exists; creating a key that already exists fails instead of overwriting it; the proxy and `key info` only open the key, never create it. |

## Residual risks

- Any local process, including other users' processes, can use the loopback
  proxy of a session without local authentication. Do not run Gateinto on
  shared hosts you do not trust.
- With `session_credentials`, a local process that does not know the
  credentials can still make the session answer `429` to everyone, the
  browser included, for up to a minute at a time by sending wrong ones.
  Closing the session and starting a new one gives a new port.
- A website can draw a dialog or page that looks like the browser's proxy
  sign-in and ask for the session credentials. The prompt warns against it
  and names the proxy address, but nothing stops a user from typing them in.
- A user who copies the password puts it on the clipboard, where every
  program of the user, and clipboard history or sync if enabled, can read it.
- Session credentials give no isolation from programs running as the same
  user: they can ask the agent for them over its IPC endpoint
  (`gateinto session credentials`), read the prompt or process memory, or
  use the device identity directly. The credentials are not zeroized.
- How Chrome and Edge on Windows show the proxy sign-in dialog for a
  session, whether and how long they cache the credentials, and what they do
  after the session closes has not been verified; see
  [browser-verification.md](browser-verification.md).
- Administrators and malware running as the user can use or steal the
  identity, read traffic before it enters the tunnel, or redirect Gateinto to
  another upstream.
- A software-stored device key can be exported by anyone with the user's
  rights. TPM storage reduces this to misuse while the attacker has access.
- `--ca-file` replaces the default roots entirely; a wrong or compromised
  bundle makes Gateinto trust the wrong upstream.
- `--unsafe-allow-non-loopback-listen` exposes the proxy to the network
  without authentication.
- The upstream proxy learns every target `host:port` and can block, log or
  redirect tunnels.
- Traffic is linkable to the device by the upstream proxy when mutual TLS is
  used.
- With `hybrid_preferred` (the default), an upstream without
  `X25519MLKEM768` gets classical `X25519` only. Use `hybrid_required` where
  that is not acceptable.
- Anyone who can edit the configuration file can point Gateinto at another
  upstream or CA bundle, like anyone who can change its command line.
- A website can select `route=mixed` in a launch link for a known gateway
  without an additional prompt. This exposes local DNS and the source IP of
  direct connections, which bypass gateway policy. DNS/IP matching is a
  heuristic: a service on another IP may go direct, and a shared gateway IP
  may send unrelated traffic through it. Only that new session is affected;
  the stored gateway, device session and other browser sessions are unchanged.
- A website can open up to 5 browser windows a minute (4 at a time) on
  configured gateways' portals, each with a proxy credential prompt that a
  user might mistake for a real login.
- A user can be talked into approving a hostile gateway from a link
  (phishing). That gateway then sees hosts routed through it (every CONNECT
  by default), can block or misroute those connections and chooses the start page,
  where it can phish credentials. It cannot read end-to-end HTTPS content and
  gets a new, empty browser profile.
- The confirmation stops accidental approval, not a user who is persuaded:
  a page can tell the user to click OK, or to press Tab (or an arrow key)
  and then Enter or Space, for example by posing as a required setup step.
  A deliberate focus change followed by Enter or Space, or a click on OK,
  approves the gateway.
- An approved gateway that requests a client certificate gets the device
  certificate from `CurrentUser\My` (default `client_certificate =
  "optional"`) and so the stable SPKI of the device key, which lets it
  recognise the device and correlate it with other gateways.
- An approved gateway stays usable by any later link with the same name,
  gateway address or profile until `gateinto gateway forget` removes it, and there is
  no setting yet to disable gateways from links other than not registering
  the handler. The confirmation dialog has not been verified by hand on
  Windows.
- A browser that relaunches itself or keeps running after its windows close
  can end a session early or keep it open; the user then closes it with
  `gateinto session close`.
- Another user can still create a pipe with the agent's name before the
  agent starts. The agent then cannot start and reports that another user
  holds the pipe name (or, if the pipe stays busy for a second, that it could
  not open it), and `gateinto open` refuses to talk to that pipe because
  another user owns it, so launches fail until the other pipe is gone
  (denial of service, no data reaches that user). The pipe DACL and this
  check are exercised on `windows-latest` only as the same user; the
  other-user cases are not tested.
- SYSTEM and administrators can always act as or impersonate the user and
  are outside the boundary, as for the rest of Gateinto.
- Purging the key locally does not revoke the device at a gateway. Until the
  gateway operator revokes it, a copy of a software key (see above) still
  authenticates.
- Anyone running as the user can run `reset --purge-device-identity` with the
  SPKI shown by `status`. The confirmation protects against mistakes, not
  against malware running as the user.
- The MSI uninstall deletes the whole `HKCU\Software\Classes\gateinto` key it
  installed, even if another program changed it afterwards.
- The code has not had an external security review and has not been tested
  against a real upstream proxy or on physical Windows machines.

## Non-goals

- Anonymity or hiding target hosts from the upstream proxy.
- Inspecting, filtering or caching tunnel content.
- Protecting against administrators, malware running as the user, or physical
  attacks on an unlocked machine.
- Authenticating local clients beyond trust on first use: proving which
  local process or user is connecting.
- Acting as a general-purpose HTTP proxy (only `CONNECT` is supported).
- Post-quantum authentication.
- Forcing system-wide traffic through the proxy; only clients configured to
  use it are proxied.
- Authorizing access to services on the remote Edge's behalf; that decision
  stays with the upstream.
