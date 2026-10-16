# Compatibility

Findings from the project skeleton spike, recorded on 2026-10-16 with Rust 1.97.0
on Linux x86_64. Windows behavior is only type-checked locally; runtime results
on Windows come from CI.

## Crates

| Crate | Version | Role | Notes |
| --- | --- | --- | --- |
| `rustls` | 0.23.46 | TLS 1.3 client | Latest stable. `0.24.0-dev.*` exists but is a pre-release and is not used. Features: `aws_lc_rs`, `std`. `tls12` is off, so only TLS 1.3 is available. |
| `aws-lc-rs` | 1.18.2 | Crypto provider | Pulled in by `rustls/aws_lc_rs`; also a Windows dev-dependency for signature verification in tests. |
| `aws-lc-sys` | 0.46.0 | AWS-LC build | Transitive. |
| `rustls-cng` | 0.7.1 | CNG `SigningKey` | Requires `rustls ^0.23` and `windows-sys ^0.61`. Used with `default-features = false` so it does not enable `rustls/tls12`. |
| `windows-sys` | 0.61.2 | NCrypt FFI | Same major as `rustls-cng`, so key handles are the same type. |
| `tokio-rustls` | 0.26.6 | Async TLS | Not a dependency yet. Requires `rustls ^0.23.27`, compatible with 0.23.46. Its default features enable `rustls/tls12`; use `default-features = false, features = ["aws_lc_rs"]` when it is added. |
| `rcgen` | 0.14.10 | Test certificates | Dev-dependency, `default-features = false, features = ["aws_lc_rs"]`. |
| `clap` | 4.6.7 | CLI | `derive` feature. |

All of `rustls`, `rustls-cng` and (when added) `tokio-rustls` resolve to a single
`rustls` 0.23.46 in the dependency graph.

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
| Windows code type-checks and passes clippy for `x86_64-pc-windows-msvc`. | See below. |

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

## Unverified

These are expected to hold but have not been executed. CI on `windows-latest`
is the first place they run.

- Creating, opening, exporting and deleting an ECDSA P-256 persisted key in
  "Microsoft Software Key Storage Provider" (`src/identity/windows_cng.rs`,
  `tests/windows_cng.rs`).
- `NCryptSignHash` returning a 64-byte raw `r || s` signature for P-256.
- `rustls_cng::signer::CngSigningKey` converting that to a DER
  `ECDSA-Sig-Value` for `ECDSA_NISTP256_SHA256`, verified with
  `aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1`.
- An in-process TLS 1.3 handshake in which a rustls server requires a client
  certificate issued by a test CA for the CNG public key, and the client signs
  `CertificateVerify` through CNG.
- Building `aws-lc-sys` on `windows-latest`. With `rustls/aws_lc_rs` the
  `aws-lc-rs/prebuilt-nasm` feature is enabled, so AWS-LC's `cc` builder uses
  pre-assembled objects when NASM is absent, and pre-generated bindings exist
  for `x86_64-pc-windows-msvc`, so neither NASM, CMake nor bindgen/libclang
  should be needed. The MSVC toolchain on the runner is required.

Design-only, not exercised at all:

- "Microsoft Platform Crypto Provider" (TPM). The key functions take a provider
  name, but no TPM test exists and GitHub-hosted runners have no TPM.
- Non-exportable key policy and UI/PIN behavior for TPM keys.
- `tokio-rustls` integration.

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
  in the user's key store.
