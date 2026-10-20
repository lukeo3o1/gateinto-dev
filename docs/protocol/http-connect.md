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
Gateinto sends the local `200 Connection Established` only after a gateway
`2xx` response. Bytes following the local request head and DATA received with
the gateway response remain tunnel payload. END_STREAM maps to TCP half-close;
one side can finish sending while the other continues receiving.

A non-2xx response or a stream reset before establishment closes only that
local tunnel: gateway `403` maps to local `403`, other statuses and stream
errors to `502`. Response headers and bodies are not forwarded. Once a tunnel
is established, a reset closes its byte relay; it cannot send a second HTTP
response to the local client.

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

Receive windows are 64 KiB per stream and 1 MiB per connection. Receive credit
is released only as bytes are consumed by the relay. Writes reserve available
send capacity and copy at most 16 KiB at a time; they never enqueue an
unbounded body. A slow stream therefore applies backpressure without requiring
other streams to stop. Decoded response headers are limited by
`header_max_bytes`; server push is disabled.

## Reconnect, drain and shutdown

After GOAWAY or a connection error, a new local request may open one fresh TLS
connection when the cached connection cannot accept a stream. A fresh
connection that fails also fails that local request; Gateinto does not loop
through handshakes until the deadline. A synchronous error before submission
can discard the cached connection and use that fresh attempt. Once
`send_request` returns a stream, Gateinto never replays that CONNECT, even if
GOAWAY, RST_STREAM, a transport error or a response timeout follows. The local
client decides whether to make another request.

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

Each local request retains its opening timeout, including pool coordination,
TCP/TLS, stream-capacity waits and the CONNECT reply. Timeout maps to `504`.
Established streams retain independent bidirectional idle deadlines: traffic
on another stream does not keep an idle tunnel alive. HTTP/2 PING keepalive is
not enabled. The single initialization PING checks protocol setup, rather than
keeping an established connection alive. Opening and idle deadlines plus
reconnect on a later request provide failure handling without background
keepalive traffic.

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
large transfers, slow-reader backpressure, and certificate rotation and retry
with injected clocks and verified certificates. No real gateway has been
verified with HTTP/2.
