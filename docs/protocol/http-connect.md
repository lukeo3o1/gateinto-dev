# Upstream HTTP CONNECT

Gateinto accepts HTTP/1.1 `CONNECT` from local clients. Its TLS 1.3 connection
to the gateway offers ALPN `h2`, then `http/1.1`. The selected protocol applies
to that connection: `h2` uses HTTP/2 CONNECT; `http/1.1` or no ALPN uses the
existing HTTP/1.1 CONNECT request and response parser. Every handshake checks
ALPN again, including after a gateway changes its supported protocols.

## HTTP/2 request and data

The request follows RFC 9113 section 8.5: `:method` is `CONNECT`, `:authority`
is the validated target `host:port` (including brackets for IPv6), and
`:scheme` and `:path` are absent. Extended CONNECT is not used. Local proxy
credentials and headers are not forwarded to the gateway.

The request stream stays open while the tunnel carries bytes in DATA frames.
For gateway-routed tunnels, Gateinto sends the local `200 Connection Established`
only after a gateway
`2xx` response. Bytes following the local request head and DATA received with
the gateway response remain tunnel payload. END_STREAM maps to TCP half-close;
one side can finish sending while the other continues receiving.

A non-2xx response or a stream reset before establishment closes only that
local tunnel: gateway `403` maps to local `403`, other statuses and stream
errors to `502`. Response headers and bodies are not forwarded. Once a tunnel
is established, a reset closes its byte relay; it cannot send a second HTTP
response to the local client.

## Mixed routing

All CONNECTs use the gateway by default. A launch URI with `route=mixed`
selects an opt-in DNS/IP heuristic for that browser session; see
[session routing](launch-uri.md#session-routing) for the rules and exposure.
Local request parsing, authentication and the tunnel permit precede route
selection. Distinct, nonempty target and gateway DNS answers permit a direct
TCP attempt to the resolved target addresses. An IP intersection, DNS error
or empty answers select gateway CONNECT with the original authority.

Local `200` for a direct route is sent only after TCP connects. Direct errors
or timeout may fall back to gateway CONNECT before that response. DNS and
direct TCP share at most half of the existing opening timeout, leaving the
remaining total deadline for the gateway. Gateway statuses, TLS failures and
other gateway errors never cause a direct retry. Neither route can replay
bytes after local `200`; target TLS and HTTP errors belong to the browser.
Early client bytes, half-close, idle limits, concurrency limits and shutdown
use the same relay for both routes. Direct tunnels create no upstream TLS
connection and do not use or refresh the gateway client certificate.

## DNS work budget

Mixed-route discovery and new gateway connections share a process-wide limit
of 64 queued or running system DNS lookups. An IP literal needs no lookup
slot. Capacity is acquired before submitting blocking work, without a waiting
queue; the blocking job holds its slot until the system resolver returns,
including when its async caller times out, is cancelled or closes its session.
Errors and panics release the slot when that job finishes. TCP connects use
the resulting address vector, so they cannot start an implicit extra lookup.

At capacity, mixed discovery selects the gateway. An existing gateway
connection or an IP-literal gateway may still work; a new named gateway that
cannot obtain a slot fails immediately with the existing local `502` mapping.
The budget is shared across sessions and `check-upstream` within one process.
Opening deadlines bound the caller's wait, not the system resolver's lifetime.
Already-running OS lookups remain non-cancellable and may delay process
shutdown, but cancellation cannot admit unlimited replacement DNS work.

## Connection ownership and limits

Each Proxy, and therefore each session, owns its own lazy connection pool.
The first concurrent requests coordinate one TLS/HTTP/2 connection, then use
one stream per CONNECT. Sessions never share an HTTP/2 connection, even when
they use the same gateway or device key. HTTP/1.1 fallback keeps a separate TLS
connection per tunnel; after fallback is known, those handshakes run in
parallel. If several such handshakes discover HTTP/2 together, one connection
is retained for streams and redundant handshakes are discarded.

Before publishing a shared connection, Gateinto sends one initialization PING
and waits for its PONG within the opening deadline. The `h2` client handshake
only sends the client preface. For a protocol-compliant peer, PONG follows its
mandatory initial SETTINGS, including a valid zero stream limit. Timeout or
cancellation during this initialization aborts the driver and closes its TLS
socket, so the next local CONNECT can establish a fresh connection. A timeout
on an already initialized connection resets only that request's stream.

The `h2` library applies the peer's SETTINGS_MAX_CONCURRENT_STREAMS and flow
control, including a zero stream limit. Gateinto starts with zero provisional
send streams until peer SETTINGS arrive. Waiting for stream capacity consumes
the local tunnel's opening deadline and its existing
`max_concurrent_tunnels` permit; excess local connections still get `503`.

The receive window is 64 KiB per stream. Receive credit is released only as
bytes are consumed by the relay, so a stream whose local client stops reading
holds at most 64 KiB of the connection window. The connection window is the
stream window multiplied by `max_concurrent_tunnels` (4 MiB for the default
64). Configuration and the proxy reject `max_concurrent_tunnels` above 32767,
the largest value whose product stays within the HTTP/2 maximum window of
2^31-1 bytes. Every gateway stream holds a tunnel permit, so even when every
other tunnel has stopped reading, the connection window still has credit for
the remaining stream. A slow stream therefore applies backpressure to its own
data only. Buffered receive data remains bounded by `max_concurrent_tunnels`
times 64 KiB per session. Writes reserve available send capacity and copy at
most 16 KiB at a time; they never enqueue an unbounded body. Decoded response
headers are limited by `header_max_bytes`; server push is disabled.

## Reconnect, drain and shutdown

After GOAWAY or a connection error, a new local request may open one fresh TLS
connection when the cached connection cannot accept a stream. A fresh
connection that fails also fails that local request; Gateinto does not loop
through handshakes until the deadline. A synchronous error before submission
can discard the cached connection and use that fresh attempt. Once
`send_request` returns a stream, Gateinto never replays that CONNECT, even if
GOAWAY, RST_STREAM, a transport error or a response timeout follows. The local
client decides whether to make another request.

A connection can also stop answering without closing, for example after a NAT
drops its mapping, the host sleeps or the network changes without a reset.
Gateinto therefore checks liveness with an HTTP/2 PING on demand and retires a
connection whose PONG does not arrive within a quarter of the opening timeout
(2.5 s by default):

- Before reusing a connection that has not answered a CONNECT or PING for at
  least one opening timeout, the request waits for a PING. If it fails, that
  request opens a fresh connection within its remaining deadline. The PING,
  and after a failed PING that fresh connection, run while the request holds
  the session's pool lock, so other gateway requests of the session wait
  behind both. The PING takes up to a quarter of the opening timeout, or about
  twice that when a watchdog probe (next item) already has a PING outstanding,
  because a connection has one PING in flight at a time.
- When a submitted CONNECT has no reply after a quarter of the opening timeout,
  a PING runs beside it. If that fails, later requests open a fresh connection.
  The unanswered CONNECT is not replayed and still ends with `504` at its own
  deadline.

A retired connection is only removed from reuse, like after GOAWAY: its
existing streams keep running until they end or reach their idle deadline. A
`4xx`/`5xx` status, RST_STREAM or a slow CONNECT reply on a connection that
still answers PING does not retire it. A connection whose PONG is delayed
beyond the deadline, for example behind a saturated uplink, is also retired;
the cost is one new TLS connection.

GOAWAY prevents new streams on the old connection while existing accepted
streams drain. A transport error can terminate every stream on that
connection. Dropping or cancelling an opening or established tunnel resets
only its stream. Closing a session, normal proxy shutdown and aborting the
proxy run future abort both tunnel tasks and all current or draining HTTP/2
drivers, closing their TLS sockets.

## Certificates and timeouts

A TLS connection keeps the client identity authenticated by its handshake.
When a self-signed certificate becomes eligible for renewal after 12 hours,
new CONNECTs refresh the session's certificate and use a fresh TLS connection
when its certificate changes. Existing streams may drain on the old
connection. Required authentication is checked even if the gateway did not
request a certificate; optional authentication renews when that connection's
gateway requested one. Eligibility is checked again after waiting for stream
capacity, before submitting CONNECT.

A failed renewal keeps a still-valid certificate and the existing connection,
with the existing 60-second retry throttle. After expiry, required mode
refuses new streams locally if renewal fails; optional mode opens a connection
without a client certificate. A successful later retry rotates to an
authenticated connection. An upstream that does not accept anonymous clients
can refuse the optional handshake. Certificate snapshots belong to individual
TLS handshakes, so an old connection cannot masquerade as a renewed one.

Each gateway-routed request retains its opening timeout, including pool coordination,
TCP/TLS, stream-capacity waits and the CONNECT reply. Timeout maps to `504`.
Established streams retain independent bidirectional idle deadlines: traffic
on another stream does not keep an idle tunnel alive. HTTP/2 PING keepalive is
not enabled, and no TCP keepalive is configured. Besides the initialization
PING, PINGs are sent only for the on-demand liveness checks above, so an idle
connection generates no background traffic. A silent connection is detected
the next time a CONNECT needs it; established tunnels on it end through their
idle deadlines.

TLS session resumption and TLS early data remain disabled. Reusing an open
HTTP/2 connection shares its existing authenticated TLS transport; creating a
new connection always performs a full TLS 1.3 handshake.

## Checking and verification

`check-upstream` reports `alpn: h2`, `alpn: http/1.1`, or `alpn: none`. With a
`--target`, it sends CONNECT using that negotiated protocol. HTTP/2 statuses
are printed as `connect-status: HTTP/2 <code>`; HTTP/1.1 preserves the gateway's
status line. Non-2xx statuses keep the existing nonzero exit behavior. Without
a target, the command checks TLS only.

`tests/h2_connect.rs` and `tests/h2_fixture/mod.rs` exercise real TLS and HTTP/2
on loopback, including reuse, fallback, protocol changes, session isolation,
shutdown, GOAWAY, connection errors without replay, statuses and resets,
stream limits, independent timeouts, half-close, early bytes, IPv6 authorities,
large transfers, slow-reader backpressure, many unread streams beside a live
one, a gateway that stops answering without closing, and certificate rotation
and retry with injected clocks and verified certificates. No real gateway has
been verified with HTTP/2, and liveness recovery has been tested only against
the loopback fixture.
