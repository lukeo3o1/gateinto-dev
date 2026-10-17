# Compatibility

Findings from the project skeleton spike, recorded on 2026-10-16 with Rust 1.97.0
on Linux x86_64. Windows behavior is only type-checked locally; runtime results
on Windows come from CI.

## Crates

| Crate | Version | Role | Notes |
| --- | --- | --- | --- |
| `rustls` | 0.23.46 | TLS 1.3 client | Latest stable. `0.24.0-dev.*` exists but is a pre-release and is not used. Features: `aws_lc_rs`, `std`. `tls12` is off, so only TLS 1.3 is available. |
| `aws-lc-rs` | 1.18.2 | Crypto provider | Pulled in by `rustls/aws_lc_rs`. Also a direct dependency for SHA-256 fingerprints and the device key self-test signature check; this resolves to the same package, so `Cargo.lock` gains no new crate. |
| `aws-lc-sys` | 0.46.0 | AWS-LC build | Transitive. |
| `rustls-cng` | 0.7.1 | CNG `SigningKey` | Requires `rustls ^0.23` and `windows-sys ^0.61`. Used with `default-features = false` so it does not enable `rustls/tls12`. |
| `windows-sys` | 0.61.2 | NCrypt FFI | Same major as `rustls-cng`, so key handles are the same type. |
| `tokio` | 1.53.3 | Async runtime | Features: `rt-multi-thread`, `net`, `io-util`, `macros`, `time`, `sync`. |
| `tokio-rustls` | 0.26.6 | Async TLS | Requires `rustls ^0.23.27`, compatible with 0.23.46. Its default features enable `rustls/tls12`, so it is used with `default-features = false, features = ["aws_lc_rs"]`. |
| `webpki-roots` | 1.0.9 | Default upstream roots | Mozilla root program as static data. License CDLA-Permissive-2.0. Replaced entirely by `--ca-file`. |
| `tracing` | 0.1.44 | Logging | |
| `tracing-subscriber` | 0.3.23 | Log output | `default-features = false, features = ["fmt", "std", "env-filter"]`. |
| `rcgen` | 0.14.10 | Test certificates | Dev-dependency, `default-features = false, features = ["aws_lc_rs", "pem"]`. Requires Rust 1.88, which sets the crate's `rust-version`. |
| `clap` | 4.6.7 | CLI | `derive` feature. |

All of `rustls`, `rustls-cng` and `tokio-rustls` resolve to a single `rustls`
0.23.46 in the dependency graph, and `rustls/tls12` is not enabled on any
target.

`webpki-roots` was chosen over `rustls-native-certs` for the default roots: it
is pure data, behaves the same on every platform and in CI, and adds no
platform certificate store code. The cost is that roots added to the Windows
store (for example an enterprise CA) are not trusted; such deployments pass
`--ca-file`.

## Verified

Locally on Linux:

| Claim | How |
| --- | --- |
| Crate versions above are the latest stable releases on crates.io. | `cargo search <crate>`, `cargo info <crate>`, crates.io API `/api/v1/crates/<crate>/versions`. |
| `rustls-cng` 0.7.1 depends on `rustls ^0.23`; `tokio-rustls` 0.26.6 depends on `rustls ^0.23.27`. | crates.io API `/api/v1/crates/<crate>/<version>/dependencies`. |
| `rustls`, `rustls-cng` and `tokio-rustls` resolve to one `rustls`. | Scratch crate with all three plus `rcgen` and `aws-lc-rs`, then `cargo tree -i rustls --target all -e normal`. |
| `rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768` exists. | Used by `src/tls.rs`; compiles. |
| `ClientConnection::negotiated_key_exchange_group()` returns the negotiated group. | `tests/key_exchange.rs`. |
| A client limited to `[X25519MLKEM768, X25519]` negotiates `X25519MLKEM768` over TLS 1.3, falls back to `X25519`, and fails with `NoKxGroupsInCommon` against a `secp256r1`-only server. | `cargo test --test key_exchange`. |
| Without `prefer-post-quantum`, the rustls `aws_lc_rs` default provider puts `X25519` before `X25519MLKEM768`, so the explicit group list is required. | Temporarily replacing the list with `default_provider().kx_groups` made two `key_exchange` tests fail. |
| `rustls/tls12` is off with `tokio-rustls` added, and one `rustls` is used. | `cargo tree -e features -i rustls --target all` lists no `tls12`; `cargo tree -i rustls --target all -e normal`. |
| The crate builds and all tests pass with Rust 1.88.0, the declared `rust-version`. `rcgen` and `time` declare 1.88. | `cargo +1.88 test --all-targets --all-features --locked`; `cargo metadata` `rust_version` fields. |
| The double `CONNECT` data path, status mapping, limits, half-close and early data behave as documented in the README. | `tests/proxy.rs` against an in-process TLS 1.3 upstream proxy fixture, loopback only. |
| Windows code type-checks and passes clippy for `x86_64-pc-windows-msvc`, including `src/identity/windows_cng.rs` and `tests/device_key_windows.rs`. | See below. |
| The device key lifecycle rules hold: an existing `tpm` or `software` key is reused; both providers are always probed, and keys in both are an error for `key init` and a warning for `key info`; a TPM that is present but not ready during lookup is an error that creates nothing in either provider, even when a software key exists; any other open failure than "not found" or "provider unavailable" is an error and creates nothing; an unavailable TPM, a failed TPM creation or a failed TPM self-test falls back to software (deleting a half-created TPM key first); a TPM reported as not ready while TPM Base Services report `TBS_E_TPM_NOT_FOUND` counts as unavailable, so a software key is created on first init (or an error with fallback disabled, creating nothing) and reused afterwards, while not ready with a TPM present stops with an error and creates nothing; disabled fallback is an error; `--backend software` skips the TPM; `key info` never creates. | Unit tests in `src/identity/device_key.rs` against a fake key store. |
| The DER SubjectPublicKeyInfo built from an uncompressed P-256 point equals the one AWS-LC produces; the fingerprint is lowercase hex SHA-256; the ECC public blob parser rejects a wrong magic, a wrong `cbKey` and wrong lengths with a specific error. | Unit tests in `src/identity/encoding.rs`. |
| CNG status codes are classified as "not found" (`NTE_BAD_KEYSET`, `NTE_NOT_FOUND`, `NTE_NO_KEY`), "provider unavailable", meaning absent (`NTE_PROV_DLL_NOT_FOUND`, `NTE_BAD_PROVIDER`, `NTE_DEVICE_NOT_FOUND`, `TBS_E_TPM_NOT_FOUND`), "provider not ready", meaning present but not usable now (`NTE_DEVICE_NOT_READY`, `NTE_PROVIDER_DLL_FAIL`, `TBS_E_SERVICE_NOT_RUNNING`, `TBS_E_SERVICE_DISABLED`), or other failures. When opening a provider fails, "not found" codes also count as absent; "not ready" and other failures are passed through and stop the lookup. A "not ready" result from the Platform Crypto Provider becomes "provider unavailable" only when the TPM Base Services probe returns `TBS_E_TPM_NOT_FOUND`; a successful probe or any other probe failure keeps it "not ready", with the probe result appended to the reason; the probe runs only for "not ready". | Unit tests in `src/identity/cng_status.rs`. Whether Windows actually returns these codes is not verified; see Unverified. |
| `gateinto key init` and `key info` fail with "device keys are only supported on Windows" on other platforms. | `tests/cli.rs`. |

### Windows type check from Linux

`cargo xwin` could not download the MSVC CRT through the network proxy (403),
and its `windows-msvc-sysroot` backend failed to compile AWS-LC's `hrss.c`
because of conflicting SSE intrinsic headers. Type checking does not link, so
AWS-LC's C build can be replaced by a stub "system" install that only provides
headers and the pre-generated bindings shipped in `aws-lc-sys`:

```sh
rustup target add x86_64-pc-windows-msvc
SYS=$(dirname $(cargo metadata --format-version 1 | jq -r '.packages[] | select(.name=="aws-lc-sys") | .manifest_path'))
STUB=$(mktemp -d)
mkdir -p "$STUB/lib" && cp -r "$SYS/aws-lc/include" "$STUB/" && touch "$STUB/lib/crypto.lib"
python3 -c 'import re,sys; s=open(sys.argv[1]).read(); open(sys.argv[2],"w").write(re.sub(r"#!\[allow\([^\]]*\)\]","",s,count=1))' \
  "$SYS/src/x86_64_pc_windows_msvc_crypto.rs" "$STUB/bindings.rs"
AWS_LC_SYS_SYSTEM_DIR="$STUB" AWS_LC_SYS_SYSTEM_BINDINGS="$STUB/bindings.rs" \
  cargo clippy --target x86_64-pc-windows-msvc --all-targets --all-features --locked -- -D warnings
```

This checks Rust types and FFI signatures only. Nothing is linked or run.

### On GitHub Actions

CI run [38955641860](https://github.com/lukeo3o1/gateinto-dev/actions/runs/38955641860)
(commit `ab46f33`) passed `cargo fmt --all -- --check`, `cargo clippy --all-targets
--all-features --locked -- -D warnings` and `cargo test --all-targets
--all-features --locked` on both `ubuntu-latest` and `windows-latest`. Run
[38954849945](https://github.com/lukeo3o1/gateinto-dev/actions/runs/38954849945) (commit `5983184`) also passed on both.

On `windows-latest`:

| Claim | How |
| --- | --- |
| `aws-lc-sys` builds with only the runner's preinstalled tools. This is expected because `rustls/aws_lc_rs` enables `aws-lc-rs/prebuilt-nasm` and `aws-lc-sys` ships pre-generated `x86_64-pc-windows-msvc` bindings. | The workflow has no NASM or CMake setup step. |
| Creating, opening, exporting and deleting an ECDSA P-256 persisted key in "Microsoft Software Key Storage Provider" works; creating an existing key fails. | `tests/windows_cng.rs`: `creating_an_existing_key_fails`, `exported_public_key_is_an_uncompressed_p256_point`, `persisted_key_can_be_reopened_and_deleted`. |
| `NCryptSignHash` returns a 64-byte raw `r \|\| s` signature for P-256. | `tests/windows_cng.rs`: `ncrypt_signature_is_raw_r_and_s`. |
| `rustls_cng::signer::CngSigningKey` produces a DER `ECDSA-Sig-Value` for `ECDSA_NISTP256_SHA256`, verified with `aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1`, and returns no signer when offered only `ECDSA_NISTP384_SHA384` and `RSA_PSS_SHA256`. | `tests/windows_cng.rs`: `rustls_signer_produces_der_ecdsa_p256_sha256_signature`, `rustls_signer_rejects_unsupported_schemes`. |
| An in-process TLS 1.3 handshake succeeds in which a rustls server requires a client certificate issued by a test CA for the CNG public key and the client signs `CertificateVerify` through CNG, negotiating `X25519MLKEM768`. | `tests/windows_cng.rs`: `tls13_client_authenticates_with_cng_key`. |
| The three `tests/key_exchange.rs` tests pass. | `tests/key_exchange.rs`: 3 passed. |

### Device key tests on Windows

`tests/device_key_windows.rs` is written for `windows-latest`, where the
Platform Crypto Provider is expected to be unusable, so the software fallback
runs for real: init creates once and a second init reuses the same
fingerprint, `key info` matches `key init`, `NCRYPT_EXPORT_POLICY_PROPERTY`
reads 0, and exporting `ECCPRIVATEBLOB` or `PKCS8_PRIVATEKEY` fails. Tests that
depend on a TPM require the outcome for the environment that TPM Base Services
report (see below). Test keys get unique names and are deleted from both
providers by a drop guard. **The first CI run failed (see below); the fixed
tests have only been type-checked so far.**

### Hosted runner without a TPM

CI run [38963331196](https://github.com/lukeo3o1/gateinto-dev/actions/runs/38963331196)
(commit `40469ff`) failed 10 of 13 tests in `tests/device_key_windows.rs` on
`windows-latest`: opening a key in the Microsoft Platform Crypto Provider
returned `NTE_DEVICE_NOT_READY` (`0x80090030`), which was classified as "TPM
present but not usable", so the lookup stopped before the software path ran.

`NTE_DEVICE_NOT_READY` alone cannot tell "no TPM" from "TPM present but not
ready". `CngStore` now asks TPM Base Services (`Tbsi_GetDeviceInfo` from
`tbs.dll`) whenever the Platform Crypto Provider reports a "not ready" code
during open or create. `TBS_E_TPM_NOT_FOUND` (`0x8028400F`) makes the provider
count as absent, so the software key is created once and reused afterwards;
anything else keeps the "not ready" error. On the hosted runner TBS is expected
to return `TBS_E_TPM_NOT_FOUND`; this is not confirmed until the next CI run.

`tests/device_key_windows.rs` calls `Tbsi_GetDeviceInfo` itself to decide which
outcome to require. Without a TPM: opening a missing TPM key is "provider
unavailable", default init falls back with `TpmProblem::Unavailable`, and init
with fallback disabled fails with "the TPM provider is unavailable" and creates
nothing in either provider. With a TPM: opening a missing TPM key is "not
found", and init with fallback disabled either creates a `tpm` key or fails
without creating a software key.

A TPM disabled in firmware is indistinguishable from no TPM, so it leads to a
software identity. Use `--no-software-fallback` on machines known to have a TPM.

## Unverified

Not exercised at all yet:

- `tests/device_key_windows.rs` and the updated `tests/windows_cng.rs` on
  Windows with the TPM Base Services probe (pending the next CI run). That
  `Tbsi_GetDeviceInfo` returns `TBS_E_TPM_NOT_FOUND` on `windows-latest` is
  expected, not observed.
- The Platform Crypto Provider path on a machine with a TPM. Manual steps are
  in [tpm-verification.md](tpm-verification.md); they have not been executed.
- Which status codes Windows returns for a missing key, a missing TPM or a TPM
  that is present but not ready in the Platform Crypto Provider, beyond the
  `NTE_DEVICE_NOT_READY` observed on `windows-latest`. If it returns a code
  outside the lists above when opening the provider or a key, `key init` stops
  with an error instead of falling back.
- `keys_in_both_providers_stop_init_and_make_info_warn` returns early unless a
  TPM key can be created, so it only checks anything on a machine with a TPM.

Not exercised on physical hardware:

- Windows 10/11 machines. Runtime results so far come only from the
  GitHub-hosted `windows-latest` runner image.

Design-only, not exercised at all:

- UI/PIN behavior for TPM keys.
- The proxy against a real upstream HTTPS proxy, and with real clients such as
  browsers or curl. Tests use only the in-process fixture.

## Open issues

- `rustls` 0.23.46 was released on 2026-10-14. The 0.24 line is in pre-release;
  its `SigningKey` API may change and `rustls-cng` will need a matching release.
- `rustls-cng` hashes with `BCryptHash` and converts P1363 to DER with
  `CryptEncodeObjectEx`. If TPM keys need different flags (for example
  non-silent operations) the adapter may have to be replaced by a thin custom
  `SigningKey`.
- `rustls-cng::key::NCryptKey::sign` uses `NCRYPT_SILENT_FLAG` by default; a TPM
  key with a PIN or consent UI would fail instead of prompting.
- Test keys are user-scoped and deleted by a drop guard. A test process that is
  killed before the guard runs leaves a key named `gateinto-test-<pid>-<nanos>-<n>`
  or `gateinto-test-device-<pid>-<nanos>-<n>` in the user's key store.
- A software device key is only marked non-exportable. An administrator, or
  malware running as the user, can still copy the key files.
