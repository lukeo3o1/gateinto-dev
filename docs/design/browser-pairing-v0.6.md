# Browser pairing design v0.6 (experimental)

This is a **target design / in-progress PoC**, not a shipped feature. The existing
browser proxy still uses HTTP/1.1 CONNECT with `basic_tofu`. Nothing in this
document claims Chrome or Edge has been verified with HTTPS/h2.

## Scope

Gateinto must provide two first-class ingress modes: the existing browser
launch flow and future native application IPC. This phase focuses on the
browser path only, with no Passkey, browser extension, WFP driver, or WASM
dependency.

The browser goal is:

```text
Gateinto Agent → managed browser profile → localhost HTTPS control Web App
                          │ separately authenticated user approval
                          ▼
                  single-use pairing proof
                          │ special local proxy CONNECT (PoC)
                          ▼
Browser → localhost TLS1.3/h2 proxy → 1 active authorized TLS connection
           ├── CONNECT stream 1 → ephemeral key A → gateway mTLS connection A
           └── CONNECT stream 3 → ephemeral key B → gateway mTLS connection B
```

Every Gateway client certificate applies to an entire *Gateway TLS
connection*, not to a CONNECT stream. Separate gateway ephemeral identities
therefore require separate gateway TLS connections. Local h2 multiplexing
does not imply gateway h2 pooling across credentials.

## Authorization and state

- `BrowserSession` has one pairing policy and at most one active *local TLS
  connection*. Connection IDs are assigned by the local TLS ingress, never
  by the browser.
- A normal CONNECT is denied until that *connection* is paired. This check
  happens before routing, DNS, hardware-key signing, or gateway connection.
- After an **independently authenticated** user approval, the control plane
  generates a CSPRNG 256-bit nonce valid for at most 60 seconds. Approval
  never silently promotes the first incoming TCP/TLS client.
- A reserved pairing CONNECT consumes the nonce on the *same local h2
  connection* that will be authorized for ordinary CONNECT. The pairing
  request must not reach an external host or DNS resolver.
- Pairing uses constant-time verification and single use. An already active
  connection cannot be replaced by a competing connection.
- On disconnect, GOAWAY or explicit revocation, the connection's authorization
  is removed. A new connection requires a new approval and nonce.
- Pending handshakes, pair attempts and CONNECT streams need independent
  resource budgets and timeouts (not yet implemented).

## Implementation stage

`src/browser_pairing.rs` implements **only** the fail-closed policy
primitive. It is exported so ingress code can use it in later changes;
nothing currently calls it from the HTTP/1.1 proxy, TLS listener or Web App.
Its unit tests cover default deny, one active connection, failed/replayed
nonce, TTL, disconnect and revocation. Passing these tests is **not**
proof of browser binding or identity assurance.

Next steps, in order:

1. Implement a separate loopback HTTPS Control Web App and **secure user
   approval**. Merely requiring Origin/Cookie is not sufficient protection
   against same-user malware.
2. Implement TLS1.3 + ALPN h2 inbound proxy and give accepted connections
   non-client-selectable IDs, then call pairing authorization before CONNECT.
3. Prototype reserved pairing CONNECT from real Chrome and Edge. Verify the
   pairing stream and normal streams use the same TLS/h2 connection under
   PAC, DNS, caching, connection racing, GOAWAY and reconnect conditions.
4. Build per-CONNECT gateway ephemeral key issuance and gateway verification;
   disallow reuse of a gateway mTLS identity across separate TunnelSessions.
5. Test hostile same-user clients; record that this model does **not**
   cryptographically prove Chrome's executable/PID or the browser profile.

## Open design risks

- JavaScript/WASM/WebCrypto cannot choose the browser's proxy TLS/h2
  connection. The proposed special-host `fetch` is only a PoC candidate;
  proxy bypass, direct DNS, network fallback, HTTP/2 connection reuse and
  accidental token leakage must be tested before adoption.
- The Control Web App must not turn an unauthenticated localhost HTTP call
  into a valid approval. Local TLS server trust does not authenticate the
  client.
- Strict single-connection mode can break when the browser races a new
  connection or replaces an old one. No unverified fallback to direct
  access is acceptable.
- This design isolates approved connections; it does *not* assert that
  an attacker cannot control the approved browser process.

Full SSoT/MSS v0.6 is tracked separately from this incremental implementation.
