# Threat model

Gateinto is a pre-release proof of concept. This document states what it is
meant to protect, against whom, and what it does not protect. Items marked
**Planned** are not implemented on `master`; see
[architecture.md](architecture.md#planned).

## Assets

- **Device private key.** **Planned:** an ECDSA P-256 key in Windows CNG that
  will authenticate the device to the upstream proxy with mutual TLS. On
  `master` the CNG helpers exist, but the proxy sends no client certificate.
- **Tunnel traffic.** The bytes clients send through the tunnel, and the target
  `host:port` of each tunnel.
- **Upstream credentials.** Whatever the upstream proxy trusts to grant
  access: the device key and its certificate once mutual TLS exists, and the
  CA bundle that decides which upstream Gateinto trusts.

## Trust boundaries

- **Local processes and the loopback listener.** The listener has no
  authentication. Any process on the machine that can open a TCP connection to
  `127.0.0.1`, including processes of other users, can use the proxy and,
  once mutual TLS exists, the device identity behind it.
- **Gateinto and the upstream proxy.** The upstream proxy sees the target
  `host:port` of every tunnel, the source IP address and, later, the device
  certificate. It does not see the content of an inner TLS session between the
  client and the target. Traffic that is not encrypted end to end inside the
  tunnel is visible to the upstream proxy.
- **Network between Gateinto and the upstream proxy.** Untrusted. Protected by
  TLS 1.3 with certificate verification.
- **TPM versus software key protection. Planned.** A TPM-backed key cannot be
  exported from the TPM, though a process running as the user can still ask the
  TPM to sign with it. A key in the "Microsoft Software Key Storage Provider"
  is protected by the operating system (DPAPI) only; anyone with the user's or
  an administrator's rights can extract or misuse it.
- **Administrators and malware running as the user.** Outside the boundary.
  They can read process memory, replace the binary, change its arguments, add
  CAs, and use the device key for signing. Gateinto does not defend against
  them.

## Threats and mitigations

| Threat | Mitigation on `master` |
| --- | --- |
| Other machines on the network use the proxy and the identity behind it. | The listen address must be loopback. A non-loopback address is refused unless `--unsafe-allow-non-loopback-listen` is given. |
| Gateinto reads or alters tunnel content. | No MITM: Gateinto never terminates the client's inner TLS and does not inspect tunnel bytes. |
| Malformed or hostile requests cause request smuggling, desynchronisation or resource exhaustion. | Strict parser: only `CONNECT host:port HTTP/1.1` with exactly one `Host` header; rejects bare LF, CR inside lines, NUL, obs-fold, control characters, `Transfer-Encoding` and a non-zero `Content-Length`. Header block size limit, request and upstream timeouts, idle timeout, and a limit on concurrent connections. |
| A client believes a tunnel exists when the upstream refused it. | The local `200` is sent only after the upstream answers `2xx`. Upstream error headers and bodies are not forwarded. |
| An attacker on the network impersonates the upstream proxy or downgrades TLS. | TLS 1.3 only (`rustls` without `tls12`). The upstream certificate and name are verified with WebPKI against the Mozilla roots or `--ca-file`. There is no option to disable verification. |
| Recorded traffic is decrypted later by a quantum computer. | The hybrid key exchange `X25519MLKEM768` is preferred, with `X25519` as fallback. This protects the confidentiality of the outer TLS session only if the upstream also supports it. It is not a post-quantum signature: certificates and, later, the device key use classical ECDSA or RSA, so authentication is not quantum resistant. |
| Logs leak secrets or traffic. | Tunnel payload is never logged. Keys and certificates are not logged. Target `host:port` is logged at `info`, and byte counts at `debug`. |
| The device identity is silently replaced, for example by an attacker or a bug that recreates the key. | **Planned:** creating a key that already exists fails instead of overwriting it (the CNG helper on `master` already behaves this way, see [compatibility.md](compatibility.md#on-github-actions)); the device identity is never replaced without an explicit command. |

## Residual risks

- Any local process, including other users' processes, can use the loopback
  proxy. Do not run Gateinto on shared hosts you do not trust.
- Administrators and malware running as the user can use or steal the
  identity, read traffic before it enters the tunnel, or redirect Gateinto to
  another upstream.
- A software-stored device key can be exported by anyone with the user's
  rights. **Planned:** TPM storage reduces this to misuse while the attacker
  has access.
- `--ca-file` replaces the default roots entirely; a wrong or compromised
  bundle makes Gateinto trust the wrong upstream.
- `--unsafe-allow-non-loopback-listen` exposes the proxy to the network
  without authentication.
- The upstream proxy learns every target `host:port` and can block, log or
  redirect tunnels.
- Traffic is linkable to the device by the upstream proxy once mutual TLS
  exists.
- The code has not had an external security review and has not been tested
  against a real upstream proxy or on physical Windows machines.

## Non-goals

- Anonymity or hiding target hosts from the upstream proxy.
- Inspecting, filtering or caching tunnel content.
- Protecting against administrators, malware running as the user, or physical
  attacks on an unlocked machine.
- Authenticating local clients of the loopback listener.
- Acting as a general-purpose HTTP proxy (only `CONNECT` is supported).
- Post-quantum authentication.
