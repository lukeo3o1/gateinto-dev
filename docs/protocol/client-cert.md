# Self-signed client certificates

This page describes exactly which client certificate Gateinto sends when
`--self-signed-client-cert` or the gateway's `self_signed_client_cert = true` is set,
how it is signed, and what an upstream has to do to accept it. Other sources
(a `--client-cert-file` or `CurrentUser\My`) are described in the
[README](../../README.md#client-certificate-mtls).

A self-signed certificate is not trusted by anything by default. Whether an
upstream accepts it depends entirely on how that upstream is configured.
Gateinto cannot make an upstream trust it.

## When a certificate is issued

- `gateinto check-upstream` issues a certificate once at startup, before the
  check connects. `gateinto proxy` issues one at startup to check the device
  key, and then each session issues its own when it starts, before it listens
  (see [Sessions](../../README.md#sessions)); the device session uses its own,
  and two sessions never share one. Nothing is read from a file or from
  `CurrentUser\My`, and the certificate is never written to disk or to a
  certificate store; it exists only in memory.
- `--client-certificate` (the gateway's `client_certificate`) applies as for the other
  sources: with `required`, failing to open the device key or to issue the
  certificate is a startup error (for a session, an error that stops it from
  starting); with `optional` (the default) it is logged as a warning and the
  upstream connection is made without client authentication; with `off` no
  certificate is issued.
- `--self-signed-client-cert` cannot be combined with `--client-cert-file`, and
  `self_signed_client_cert = true` cannot be combined with a
  `client_cert_file`, whether each comes from the configuration file or the
  command line; Gateinto exits with an error naming both.
- Every start, and every session, issues a new certificate. A running session
  also issues a new one for itself once its current certificate was issued 12
  hours or more earlier (half its
  validity): with `required`, before opening the next upstream connection,
  whether or not the upstream will ask for a certificate; with `optional`, when
  the upstream next asks for one (or before a new HTTP/2 stream when its
  existing connection requested one). The renewal is logged at `info` with the
  SHA-256 of the new certificate. If a renewal fails while the previous
  certificate is still valid, a warning is logged and the previous certificate
  is sent. A failed renewal is not retried until a minute has passed; until
  then the previous certificate is used without a new attempt or warning. An
  expired certificate is never sent: once the previous certificate's NotAfter
  has been reached and a renewal fails, no certificate is available until a
  later renewal succeeds. With `required`, every new upstream connection then
  fails locally before connecting, retrying the renewal first when a minute has
  passed since the last attempt; the proxy answers `502` and logs the error,
  and `check-upstream` exits with it. With `optional`, a warning is logged and
  the handshake continues without a client certificate, as when none could be
  loaded at startup.

With HTTP/2, a session shares one TLS connection for its tunnels. New CONNECTs
check certificate renewal eligibility before submitting a stream, including
after a wait for peer stream capacity. A renewed certificate moves new streams
to a fresh TLS connection; accepted old streams can drain. If renewal fails,
new streams keep the existing connection only while its certificate is valid.
After expiry, required mode refuses new streams locally and optional mode
opens a connection without a certificate, retaining the same one-minute retry
throttle. A successful retry rotates optional mode back to an authenticated
connection. A gateway that never requests optional client authentication does
not trigger its certificate renewal. See [upstream HTTP CONNECT](http-connect.md).

## The key and the signatures

- The certificate is for the device key named by `--key-name`
  (`[device_key] name`, default `gateinto-device-v1`): a persisted,
  non-exportable ECDSA P-256 key in Windows CNG. The key is opened (the TPM
  provider first, then the software provider) and never created here; run
  `gateinto key init` first. It is the same key `gateinto key info` describes.
- There is no other private key. The certificate signature and the TLS 1.3
  `CertificateVerify` are both made by the device key through the same
  `rustls-cng` `CngSigningKey` with scheme `ECDSA_NISTP256_SHA256`: the message
  is hashed with SHA-256 (`BCryptHash`), the hash is signed by CNG
  (`NCryptSignHash`), and the signature is converted to DER. For a TPM key the
  signing happens inside the TPM; for a software key, inside the Microsoft
  Software Key Storage Provider.
- After signing, Gateinto verifies the certificate signature against the device
  public key. A certificate whose signature does not verify is never used.
- Device keys exist only on Windows. On other platforms issuing fails with
  "device keys are only supported on Windows".

## Certificate contents

| Field | Value |
| --- | --- |
| Version | v3 |
| Serial number | 16 random bytes from AWS-LC's system random generator, with the top two bits set to `01`, so it is always positive and 16 bytes long. New for every certificate. |
| Signature algorithm | `ecdsa-with-SHA256` (1.2.840.10045.4.3.2), no parameters, in both the TBSCertificate and the outer certificate |
| Issuer | `CN=Gateinto device` (UTF8String) |
| Subject | `CN=Gateinto device` (UTF8String), identical to the issuer |
| Not before | Issuance time minus 5 minutes, to tolerate clock skew |
| Not after | Issuance time plus 24 hours |
| Time encoding | UTCTime for years before 2050, GeneralizedTime from 2050 |
| Subject public key info | `id-ecPublicKey` with `prime256v1` and the uncompressed device public key; byte-for-byte the DER that `gateinto key info --spki-out` writes, so its SHA-256 is the `spki-sha256` that `key info` prints |
| Basic constraints | Critical; `cA` false (an empty sequence) |
| Key usage | Critical; `digitalSignature` only |
| Extended key usage | Not critical; `clientAuth` (1.3.6.1.5.5.7.3.2) only |

There is no subject alternative name, subject or authority key identifier,
CRL distribution point or authority information access extension. The chain
sent in the TLS `Certificate` message is this one certificate.

The 5-minute backdating and 24-hour validity are constants in
`src/identity/certificates.rs` (`BACKDATE`, `VALIDITY`) and cannot be
configured.

## What changes between certificates

| Same for every certificate of one device key | Different for every certificate |
| --- | --- |
| Subject public key info and its SHA-256 (`spki-sha256`) | Serial number |
| Subject and issuer | Validity period |
| Extensions | Signature (ECDSA signatures are randomized) |
| Signing key | DER encoding, and therefore the SHA-256 and SHA-1 fingerprints |

## What the upstream has to do

The upstream decides whether to accept the certificate. Gateinto only
guarantees that the certificate's public key is the device key and that the
device key signed both the certificate and the handshake.

- Identify the device by its public key, not by the certificate. Take the
  SPKI SHA-256 from `gateinto key info` (`spki-sha256`) or the SPKI DER from
  `gateinto key info --spki-out device.spki.der`, and accept a client
  certificate whose SubjectPublicKeyInfo matches it. The TLS 1.3
  `CertificateVerify` check every TLS server performs then proves possession
  of the device key.
- Do not pin the certificate's own fingerprint: it changes with every start,
  every session and every renewal.
- A server that only accepts client certificates issued by a configured client
  CA rejects these certificates unless its policy is configured to trust them.
  How, and whether, a given proxy can be configured to trust a client by its
  public key is specific to that proxy and has not been verified with any real
  proxy.

The test fixture in `tests/fixture/mod.rs` (`SpkiClientVerifier`) shows one
such policy: it accepts a client certificate only if its SPKI equals the
expected one, and then has `rustls-webpki` verify the certificate with itself
as the only trust anchor, which checks the self-signature, the validity period
and the `clientAuth` extended key usage. It is test code, not a recommendation
for a production policy.

## Seeing what was sent

`gateinto check-upstream --self-signed-client-cert` prints, after
`client-certificate`:

```text
client-certificate: sent
client-certificate-source: self-signed
client-certificate-sha256: <SHA-256 of the certificate DER, lowercase hex>
device-key-spki-sha256: <SHA-256 of the device key's SPKI DER, lowercase hex>
```

The source and fingerprint lines are printed whenever a self-signed
certificate is configured, also when the upstream did not request a client
certificate (`client-certificate: not requested`).
`client-certificate-sha256` is the certificate sent in the handshake, or the
current certificate when none was sent.

At startup the proxy logs at `info` the subject, the device key's SPKI SHA-256
(`spki_sha256`), `source=self-signed` and the key backend. Each session then
logs the SHA-256 of its own certificate (`issued the session's self-signed
client certificate sha256=...`), and every renewal logs the SHA-256 of the new
one.

## Verification status

- Linux, locally: unit tests in `src/identity/certificates.rs` check every
  field above, that two certificates share the SPKI and differ in DER,
  fingerprint and serial, that the signature verifies with `rustls-webpki`
  (validity boundaries included), that a key not matching the public key or
  unable to sign ECDSA P-256 SHA-256 is refused, the renewal after 12
  hours, and that after failed renewals the previous certificate is used
  only until it expires. `tests/mtls.rs` runs the proxy twice against an
  upstream fixture that trusts the SPKI, with a software test key, and checks
  two different certificates with the same SPKI; an upstream trusting another
  SPKI rejects the handshake. With an expired certificate whose renewal fails,
  `required` fails without connecting and `optional` connects without a
  client certificate. `tests/sessions.rs` runs two sessions in one process
  from the same self-signed source and checks that each presents its own
  certificate (same SPKI, different fingerprints) on every tunnel and never
  the other's. `tests/check_upstream.rs` checks the report lines.
- An issued certificate was also inspected once with OpenSSL 3.0.13
  (`openssl x509 -text`, and `openssl verify -purpose sslclient` with the
  certificate as its own CA, which reported `OK`). This is not part of the
  test suite.
- Windows: `tests/mtls_windows.rs`
  (`self_signed_certificates_are_signed_by_the_cng_device_key`) does the same
  with a real Software Key Storage Provider key, so CNG signs both the
  certificate and `CertificateVerify`. It has not run yet; it runs in the
  `windows-latest` CI job.
- TPM-backed keys: not verified.
- Real upstream proxies: not verified.
