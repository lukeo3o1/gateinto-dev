# Security model

What Gateinto protects, how, and what it does not protect. Assets, trust
boundaries and the threat table are in [threat-model.md](threat-model.md);
this page summarizes the mechanisms and points to it rather than repeating
it. Which of these mechanisms are covered by tests is in
[verification.md](verification.md).

## What it protects

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
  a full TLS 1.3 handshake, so a connection never reuses a session, or the
  client certificate identity, established by an earlier one.
- **Self-signed client certificates** (`--self-signed-client-cert`). Gateinto
  issues a short-lived certificate (1 hour, renewed after 30 minutes) whose
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
  established. The session's certificate is dropped with it and is not
  reachable from another session, so no new `CONNECT` can use it. The
  command line runs one session per process (`gateinto proxy` or
  `gateinto session browser`); it is closed when the process ends.
- **Gateway profiles are local.** An upstream (host, port, server name, CA
  file, TLS mode, client certificate settings) only comes from the local
  configuration file or the command line. Selecting a gateway by name is a
  lookup in the loaded file; a name cannot add a host, a CA or a trust setting.
  Browser sessions name a configured gateway with `--gateway`; the planned
  `gateinto://` URI will only be able to do the same.

### Local proxy authentication (`basic_tofu`)

Browser sessions, and the device session with
`[device_session] auth = "basic_tofu"`, accept only one local credential:
the first well-formed Basic credential they receive (trust on first use).
This is local proxy access control, not authorization by the upstream, and it
does not identify a user.

Guarantees:

- **One credential per session.** The first well-formed credential is bound
  atomically. Concurrent first attempts with different credentials bind
  exactly one; the others are rejected with `407` like any other wrong
  credential. Afterwards only the identical user name and password are
  accepted, compared in constant time.
- **No stored or logged secret.** The session keeps an HMAC-SHA-256 of the
  decoded credential under a random per-session key, never the credential.
  The credential is never logged at any level (a test captures `trace` logs
  and checks that neither the password nor the base64 form appear), never
  printed, and never forwarded to the upstream. There is no way to provision
  a credential in advance or to pass one in a URI.
- **Strict parsing.** Exactly one `Proxy-Authorization` header, scheme
  `Basic` (case-insensitive), canonical padded base64 of at most 1024
  characters, decoding to `user:password` with a non-empty password and no
  control characters. Malformed credentials get `400` and bind nothing.
- **Bounded failures.** After 10 failed attempts within 60 seconds every
  request to the session gets `429` until the window ends, so guessing the
  bound credential is limited to 10 attempts a minute per session. The
  limiter keeps a counter and a timestamp per session, nothing per client.
- **Per-session state.** Realm (random per session), port, bound credential
  and failure count belong to one session. Closing a session discards them;
  a new session starts with a new port, a new realm and nothing bound.

Non-guarantees:

- **TOFU does not prove which local process connected first.** Any local
  program, including another user's, that sends a credential to a new
  session's port before the browser does gets bound instead. The browser then
  only sees repeated prompts; the remedy is to close the session and start a
  new one, which is again open to whoever is first. Nothing ties the binding
  to the browser process.
- **Not a defense against malware running as the user.** Such a program can
  read the credential from the browser, or wait for it and race a new
  session, or simply use the device identity directly.
- **The rate limit can lock out the legitimate client.** A local program that
  sends 10 wrong credentials makes the session answer `429` to everyone,
  including the browser with the right credential, for up to 60 seconds.
  This is accepted because a local attacker can already take the binding
  first.
- **Basic credentials are sent in clear on loopback.** Anything that can
  capture loopback traffic on the machine can read them. The credential only
  protects this one session's port.
- **Memory.** The decoded credential and the request head are ordinary heap
  buffers, dropped after the request is checked but not zeroized.

### The tunnel content

- **No MITM of the inner TLS.** Gateinto does not terminate, inspect or modify
  the client's own TLS session with the target. It relays bytes after the
  upstream accepted the `CONNECT`.
- **Local `200` only after upstream `2xx`.** A client never believes a tunnel
  exists when the upstream refused it. Upstream error headers and bodies are
  not forwarded.
- **Strict request parsing and limits** against request smuggling and resource
  exhaustion: only `CONNECT host:port HTTP/1.1` with exactly one `Host`
  header; header size limit, timeouts, idle timeout and a connection limit.
  Details are in the [README](../README.md#proxy).

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
  - `proxy`, `check-upstream` and `key info` only open the key, never create
    it.

### Exposure and logs

- **Loopback-only by default.** The device session's listener defaults to
  `127.0.0.1:18736`; a browser session always listens on an ephemeral port of
  `127.0.0.1`. A
  non-loopback address is refused unless `--unsafe-allow-non-loopback-listen`
  is given on the command line; the configuration file has no key for it.
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

- **Local users and processes.** The device session's loopback listener has
  no authentication by default (`auth = "none"`). Any local process, including
  other users' processes, can use the tunnel and the device identity behind
  it. `basic_tofu` keeps out only programs that arrive after the first
  credential was bound; see
  [above](#local-proxy-authentication-basic_tofu).
- **Administrators and malware running as the user.** They can use or steal
  the identity (a software key can be copied), read traffic before it enters
  the tunnel, change the configuration, add CAs or replace the binary.
- **Traffic from the upstream proxy.** The upstream sees the source address,
  every target `host:port`, the client certificate, and any traffic that is not
  end-to-end encrypted inside the tunnel. It can block, log or redirect
  tunnels. Gateinto provides no anonymity.
- **A wrong trust anchor.** `--ca-file` replaces the default roots entirely;
  a wrong or compromised bundle makes Gateinto trust the wrong upstream.
- **Downgrade to classical key exchange in `hybrid_preferred`.** An upstream
  without `X25519MLKEM768` gets `X25519`. Use `hybrid_required` where that is
  not acceptable.
- **Post-quantum authentication.** Not provided.
- **Plain HTTP and non-`CONNECT` traffic.** Not proxied (`405`).
- **Certificate lifecycle.** There is no enrollment, revocation checking of
  the client certificate, or key rotation. Only self-signed certificates are
  renewed, and only by issuing a new one for the same key; a compromised
  device key stays valid wherever its public key is trusted until the upstream
  stops trusting it. Gateinto does not validate the client certificate's
  chain; the upstream does.

The full list of residual risks and non-goals is in
[threat-model.md](threat-model.md#residual-risks). Report vulnerabilities as
described in [SECURITY.md](../SECURITY.md).
