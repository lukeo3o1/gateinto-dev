# Quickstart

This guide goes from nothing to a working tunnel on a Windows 10 or 11 x64
machine, for example a VM without a TPM. It takes the shortest path; the
[README](../README.md) has the full reference.

```text
browser / curl.exe --CONNECT--> gateinto (127.0.0.1:18736) --TLS 1.3--> your HTTPS proxy --> target
```

You need:

- A Windows 10 or 11 x64 machine for Gateinto.
- An upstream HTTPS forward proxy that you control (step 2). Gateinto is not a
  VPN and brings no server of its own.

## 1. Get the binary

### From a GitHub release

The repository is private; its releases are the owner's own downloads.
[install.md](install.md#releases) describes the three channels (`alpha`,
`beta` and `latest`), their files and their stable URLs. On 64-bit Windows 10
or 11 download `gateinto-x86_64-pc-windows-msvc.exe` and
`gateinto-x86_64-pc-windows-msvc.exe.sha256` from the `latest` release (or
`alpha` or `beta` for a newer, less tested commit) into one folder, then
verify the executable in PowerShell and rename it:

```powershell
$exe = "gateinto-x86_64-pc-windows-msvc.exe"
$expected = (Get-Content "$exe.sha256").Split(" ")[0]
$actual = (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLowerInvariant()
if ($actual -eq $expected) { Rename-Item $exe gateinto.exe } else { throw "SHA-256 mismatch: do not use this file" }
```

32-bit Windows 10 uses `gateinto-i686-pc-windows-msvc.exe` the same way. The
per-user MSIs are `gateinto-x86_64-pc-windows-msvc.msi` and
`gateinto-i686-pc-windows-msvc.msi` (see [install](install.md)); this guide
uses the executable. `gateinto --version` prints `gateinto 0.0.0-<commit>` for
a release build.

Notes:

- The checksum only proves the download matches the file the workflow
  published next to it. `gateinto.exe` is not code signed, so SmartScreen may
  warn about it.
- Builds link the C runtime statically; CI checks that `gateinto.exe`
  imports no Visual C++ runtime DLL (see
  [static C runtime](compatibility.md#static-c-runtime)). Older builds needed
  the Visual C++ Redistributable; see
  [troubleshooting](troubleshooting.md#vcruntime140dll-was-not-found).
- The release workflow has not published a release yet at the time of
  writing. Until it has, build from source.

### From source

Install Rust with [rustup](https://rustup.rs/) (MSVC toolchain, Rust 1.88 or
newer) and the Visual Studio Build Tools with the "Desktop development with
C++" workload (MSVC and a Windows SDK). Then:

```powershell
git clone <repository URL> gateinto
cd gateinto
cargo build --release --locked
.\target\release\gateinto.exe --version
```

The examples below call `gateinto`; use the path to `gateinto.exe` or add its
folder to `PATH`.

## 2. Bring an upstream HTTPS proxy you control

Gateinto relays through an HTTPS forward proxy: a server that accepts TLS from
Gateinto and then an HTTP `CONNECT host:port` request inside that TLS
connection. It must:

- speak TLS 1.3 (Gateinto never offers TLS 1.2);
- accept `CONNECT` to the ports you need (usually 443) and answer with an
  `HTTP/1.1` status line such as `HTTP/1.1 200 Connection established`. A
  reply in `HTTP/1.0` or without a reason phrase is treated as malformed and
  the tunnel fails with `502`;
- present a certificate that normal WebPKI verification accepts for the name
  you connect to (see below).

Use a server that you run, on a machine you own or rent. Never use an unknown
or free public proxy: it sees the source address, every target `host:port`
and any traffic that is not end-to-end encrypted, and it can block or log your
traffic.

### Certificate and name

Gateinto verifies the upstream certificate and cannot be told not to. One of
these must hold:

- **Public CA.** Point a DNS name, for example `proxy.example.com`, at your
  server and get a certificate for that name from a public CA (for example
  Let's Encrypt). The name must be in the certificate's Subject Alternative
  Name. Gateinto trusts the Mozilla root program as bundled in `webpki-roots`;
  roots added to the Windows certificate store are not used.
- **Private CA.** Issue the server certificate from your own CA, with the
  server's name in the Subject Alternative Name, and give Gateinto the CA
  certificate in PEM format with `--ca-file` or `ca_file` in the gateway table. Use a
  separate CA and server certificate, not one self-signed certificate for both.

If you connect by IP address, the certificate must contain that address as an
IP Subject Alternative Name, or set
`--upstream-server-name` / `server_name` to a DNS name the
certificate contains.

### Example: stunnel in front of Squid

This is one minimal self-hosted setup, given as an illustration. It has not
been tested by this project; the [stunnel](https://www.stunnel.org/) and
[Squid](https://www.squid-cache.org/) documentation is authoritative for their
configuration. Any HTTPS forward proxy that meets the requirements above works.

On a Linux server you control, with a certificate for `proxy.example.com`:

- Squid as a plain HTTP forward proxy reachable only from the server itself:
  `http_port 127.0.0.1:3128`, with access rules that allow `localhost`, allow
  `CONNECT` only to port 443 and deny everything else. Squid's stock
  `squid.conf` typically has rules of this shape; check yours.
- stunnel terminating TLS 1.3 and forwarding to Squid:

  ```ini
  [https-proxy]
  accept = 0.0.0.0:443
  connect = 127.0.0.1:3128
  cert = /etc/stunnel/proxy.example.com.fullchain.pem
  key = /etc/stunnel/proxy.example.com.key
  sslVersionMin = TLSv1.3
  ```

Without client certificates, anyone who can reach port 443 can use this proxy.
Restrict it with a firewall to your own source addresses, or require client
certificates (step 7). Whether `X25519MLKEM768` is negotiated depends on the
TLS library the server uses (for stunnel, its OpenSSL version); step 4 shows
what was negotiated.

## 3. Create the device key

```powershell
gateinto key init
```

On a machine without a TPM, `key init` creates a key in the Microsoft Software
Key Storage Provider and says why on stderr. The output looks like this (the
status codes depend on the machine):

```text
warning: the TPM provider is unavailable: NTE_DEVICE_NOT_READY (0x80090030); TPM Base Services report TBS_E_TPM_NOT_FOUND (0x8028400f)
created software device key "gateinto-device-v1" because the TPM could not be used
backend: software
algorithm: ECDSA P-256
spki-sha256: <64 hex digits>
trust: non-exportable flag set, but not protected against copying by an administrator or malware running as the user
```

With a usable TPM it prints `created device key "gateinto-device-v1"` and
`backend: tpm`. Running it again prints `using existing device key
"gateinto-device-v1"` and the same `spki-sha256`; an existing key is never
replaced. On a machine that should have a TPM, use
`gateinto key init --no-software-fallback` so a missing or disabled TPM is an
error instead of a software key.

If `key init` stops with "the TPM is present but not usable right now", it
created nothing; see [Device key](../README.md#device-key).

Show the key at any time:

```powershell
gateinto key info
```

```text
backend: software
algorithm: ECDSA P-256
spki-sha256: <64 hex digits>
trust: non-exportable flag set, but not protected against copying by an administrator or malware running as the user
client-certificate: none
```

`client-certificate: none` is expected until you do step 7. The device key is
only used for client certificates (mTLS); a tunnel works without it if your
upstream does not require client certificates.

## 4. Write a configuration file and check the upstream

Copy [config.example.toml](../config.example.toml) to, for example,
`C:\gateinto\gateinto.toml` and set at least the upstream in the
`[gateways.default]` table (a gateway profile):

```toml
[gateways.default]
host = "proxy.example.com"
port = 443
# ca_file = "upstream-ca.pem"   # only for a private CA; relative to this file
```

Keep the other sections as in the example or delete them; missing keys take
the defaults. Unknown keys are errors, so a typo is reported instead of
ignored.

Then connect once, without opening a tunnel:

```powershell
gateinto check-upstream --config C:\gateinto\gateinto.toml --target example.com:443
```

```text
upstream: proxy.example.com:443
server-name: proxy.example.com
tls-mode: hybrid_preferred
tls-version: TLSv1_3
key-exchange-group: X25519MLKEM768
cipher-suite: TLS13_AES_256_GCM_SHA384
server-certificate-subject: CN=proxy.example.com
client-certificate: not requested
connect-target: example.com:443
connect-status: HTTP/1.1 200 Connection established
```

How to read it:

- `tls-version` is always `TLSv1_3`; anything else fails the check.
- `key-exchange-group` is `X25519MLKEM768` (hybrid post-quantum) or `X25519`
  (classical) if the upstream lacks the hybrid group. See
  [TLS modes](../README.md#tls-modes).
- `server-certificate-subject` is the verified upstream certificate.
- `client-certificate` is `not requested`, `requested by the upstream, none
  sent` or `sent`.
- `connect-status` is the upstream's status line, exactly as the upstream sent
  it. Without `--target` the last two lines are missing.

The command exits nonzero with the reason on stderr if the connection,
handshake, certificate verification or `CONNECT` fails. The most common
failure is a certificate the default roots do not trust (`invalid peer
certificate`); see [Private CA certificates](troubleshooting.md#private-ca-certificates).

## 5. Run the proxy

```powershell
gateinto proxy --config C:\gateinto\gateinto.toml
```

Logs go to stderr:

```text
2026-10-17T02:36:36.630936Z  WARN gateinto::identity::client_cert: no client certificate for device key "gateinto-device-v1" (spki-sha256: ...): none was given with --client-cert-file and CurrentUser\My has no currently valid certificate for this key that allows client authentication; mTLS is not configured and upstream connections do not authenticate this device
2026-10-17T02:36:36.631175Z  INFO session{id=1 kind=device gateway=default}: gateinto::proxy: listening local_addr=127.0.0.1:18736
```

The warning is expected without a client certificate: the default
`client_certificate = "optional"` mode continues without mTLS. Set
`client_certificate = "off"` in the gateway table to silence it, or `"required"` once you have a
certificate (step 7). Stop the proxy with Ctrl+C.

## 6. Use the tunnel

In a second PowerShell window:

```powershell
curl.exe -x http://127.0.0.1:18736 https://example.com
```

This prints the HTML of `example.com`, and the proxy logs
`INFO session{id=1 kind=device gateway=default}:connection{peer=127.0.0.1:<port>}: gateinto::proxy: tunnel established`.
Use `curl.exe` (not the PowerShell `curl` alias). Add `-v` to see the proxy's
`CONNECT` status; [troubleshooting.md](troubleshooting.md#status-codes)
explains each status.

To send a browser through it, configure `127.0.0.1` port `18736` as the HTTP
proxy for HTTPS traffic, either in the browser's own proxy settings or in
Windows under Settings, Network & Internet, Proxy, Manual proxy setup. Only
`CONNECT` is supported: plain `http://` URLs sent to the proxy get `405`, so
use HTTPS sites or exclude plain HTTP where the client allows it.

Security caveat: the listener has no authentication. Any local process,
including processes of other users on the same machine, can use the tunnel
and the device identity behind it. Keep the default loopback address and do
not run Gateinto on shared machines you do not trust. See the
[security model](security-model.md).

## 7. Optional: mutual TLS with the device key

If your upstream should accept only this device, configure it to require
client certificates from a CA you control, then issue a certificate for the
device key's public key:

1. Export the public key: `gateinto key info --spki-out device.spki.der`.
2. Issue a client certificate for exactly that public key from your CA, as in
   [Getting a test client certificate](../README.md#getting-a-test-client-certificate).
   Tools that generate their own key pair (such as `New-SelfSignedCertificate`)
   produce certificates that do not match and are refused.
3. Point Gateinto at it with `client_cert_file = "client.pem"` in the
   gateway table, or import it into `CurrentUser\My`, and set
   `client_certificate = "required"` there.
4. `gateinto key info --client-cert-file client.pem` checks the certificate
   against the key, and `check-upstream` should then print
   `client-certificate: sent`.

If your upstream can instead be configured to trust the device key's public
key directly (its `spki-sha256`), `--self-signed-client-cert` makes Gateinto
issue and send a short-lived self-signed certificate for the device key, with
no CA involved. Whether your upstream supports that is up to its own
configuration; see [protocol/client-cert.md](protocol/client-cert.md).

For a TPM-backed key, follow [tpm-verification.md](tpm-verification.md); that
path has not been verified yet.

## Next

- [README](../README.md): every command, flag and configuration key.
- [security-model.md](security-model.md): what Gateinto protects and what it
  does not.
- [verification.md](verification.md): which capabilities are verified and how.
- [troubleshooting.md](troubleshooting.md): status codes and common errors.
