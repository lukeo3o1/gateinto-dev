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
  or only against the CAs in `--ca-file` / `[upstream] ca_file`. There is no
  flag or configuration key that disables verification. The name checked is
  `--upstream-server-name`, defaulting to the upstream host.
- **Key exchange modes.** `--tls-mode` / `[tls] mode` decides which groups are
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

- **Loopback-only by default.** The listener defaults to `127.0.0.1:18736`. A
  non-loopback address is refused unless `--unsafe-allow-non-loopback-listen`
  is given on the command line; the configuration file has no key for it.
- **No secrets or payload in logs.** Tunnel payload and private keys are never
  logged. At `info`, logs contain the listen address, the client's local
  address and port for each tunnel, tunnel established and idle-timeout
  events, and the client certificate's subject, SHA-1 thumbprint, NotAfter,
  source and key backend. Target `host:port`, the negotiated TLS version and
  group, and byte counts are logged only at `debug`. `check-upstream` prints
  TLS parameters, the server certificate subject and the upstream status line,
  never upstream headers or bodies. The configuration file holds no secrets.
- **Strict configuration.** Unknown keys are errors and there is no default
  upstream, so a typo cannot silently send traffic somewhere unintended.

## What it does not protect

- **Local users and processes.** The loopback listener has no
  authentication. Any local process, including other users' processes, can
  use the tunnel and the device identity behind it.
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
- **Certificate lifecycle.** There is no enrollment, renewal, revocation
  checking of the client certificate, or key rotation. Gateinto does not
  validate the client certificate's chain; the upstream does.

The full list of residual risks and non-goals is in
[threat-model.md](threat-model.md#residual-risks). Report vulnerabilities as
described in [SECURITY.md](../SECURITY.md).
