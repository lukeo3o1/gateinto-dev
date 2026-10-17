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
| `400` | The request was malformed, or the client closed the connection before finishing it. Only `CONNECT host:port HTTP/1.1` with exactly one `Host` header is accepted. | Configure the client to use Gateinto as an HTTP proxy for HTTPS, not as a SOCKS proxy or an HTTPS proxy. |
| `403` | The upstream proxy answered `403`. | The upstream proxy's access policy for this target or this device. |
| `405` | The method was not `CONNECT`. Plain HTTP requests such as `GET http://...` are not supported. | Use `https://` URLs, or send the client's plain HTTP traffic elsewhere. |
| `408` | The request head was not complete within `--connect-timeout-secs`. | A client that opens the connection but does not send a request, or a very slow client. |
| `431` | The request header block was larger than `--max-header-bytes`. | Clients that send many or large headers with `CONNECT`. |
| `502` | The upstream connection failed: TCP connect refused or unreachable, TLS handshake or certificate failure, a malformed or oversized reply, or any upstream status other than `2xx` and `403` (including `407`). | The `warn` log line `upstream refused tunnel` shows the cause. See [Private CA certificates](#private-ca-certificates). |
| `503` | `--max-tunnels` connections are already open. | Raise `--max-tunnels`, or find the client holding connections open. |
| `504` | The upstream TCP connect, TLS handshake and `CONNECT` reply did not finish within `--connect-timeout-secs`. | Network reachability of the upstream proxy, firewalls that drop instead of reject, or a slow upstream. |

The upstream's own headers and body are never forwarded, so a `407` from the
upstream appears as a `502` locally. Mutual TLS client authentication is
planned but not implemented on `master`; an upstream that requires a client
certificate will fail the handshake and Gateinto returns `502`.

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

## Non-loopback listen address refused

```text
error: refusing to listen on non-loopback address 0.0.0.0:18736; pass --unsafe-allow-non-loopback-listen to override
```

The listener has no authentication, so on a non-loopback address anyone on the
network could use it and the identity behind it. Keep the default
`127.0.0.1:18736`, or another loopback address. Pass
`--unsafe-allow-non-loopback-listen` only if you control who can reach the
address. See [threat-model.md](threat-model.md).

## Windows 7

Windows 7 is experimental and unsupported. See
[windows7-feasibility.md](windows7-feasibility.md).
