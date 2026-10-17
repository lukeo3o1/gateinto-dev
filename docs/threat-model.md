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
  `basic_tofu` (every browser session) accepts only the first Basic
  credential it receives, so it excludes other local processes only if the
  intended client is first.
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
| A client believes a tunnel exists when the upstream refused it. | The local `200` is sent only after the upstream answers `2xx`. Upstream error headers and bodies are not forwarded. |
| An attacker on the network impersonates the upstream proxy or downgrades TLS. | TLS 1.3 only (`rustls` without `tls12`). The upstream certificate and name are verified with WebPKI against the Mozilla roots or `--ca-file`. There is no option to disable verification. |
| Recorded traffic is decrypted later by a quantum computer. | The hybrid key exchange `X25519MLKEM768` is preferred, with `X25519` as fallback (`hybrid_preferred`). This protects the confidentiality of the outer TLS session only if the upstream also supports it. It is not a post-quantum signature: certificates and the device key use classical ECDSA or RSA, so authentication is not quantum resistant. |
| An attacker on the network, or a misconfigured upstream, downgrades the key exchange to classical `X25519`. | `hybrid_required` offers only `X25519MLKEM768`, so the handshake fails (`502`) instead of downgrading, and every tunnel is also checked after the handshake and refused unless the negotiated group is one the mode offers. TLS 1.3 signs the handshake transcript, so an attacker without the server key cannot alter the negotiated group in the other modes either; `hybrid_preferred` still accepts `X25519` from an upstream that only offers it. `check-upstream` shows which group an upstream negotiates. |
| Another local program uses a browser session's port. | `basic_tofu`: the session binds the first well-formed Basic credential and then answers `407` to any other credential, compared in constant time, with exactly one winner among concurrent first attempts. Failures beyond 10 a minute get `429`. A program that is first still wins; the user then starts a new session (new port, realm and state). |
| Logs leak secrets or traffic. | Tunnel payload and local proxy credentials are never logged, at any level; the session keeps only a keyed hash of its bound credential. Private keys are never logged; the client certificate's subject, thumbprint and NotAfter are logged at `info`. Target `host:port`, the negotiated key exchange group and byte counts are logged at `debug`. `check-upstream` prints only TLS parameters, the server certificate subject and the upstream status line, never upstream headers or bodies. |
| The device identity is silently replaced, for example by an attacker or a bug that recreates the key. | `key init` reuses an existing key in either provider and creates one only when none exists; creating a key that already exists fails instead of overwriting it; the proxy and `key info` only open the key, never create it. |

## Residual risks

- Any local process, including other users' processes, can use the loopback
  proxy of a session without local authentication. With `basic_tofu`, a local
  process that reaches a new session before the browser binds its own
  credential; trust on first use does not prove which process was first. It
  can also make the session answer `429` to everyone for up to a minute by
  sending wrong credentials. Do not run Gateinto on shared hosts you do not
  trust.
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
