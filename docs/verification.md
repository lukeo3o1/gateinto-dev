# Verification status

Which capabilities have been verified, how, and what is still needed. Detailed
evidence and the history behind it are in [compatibility.md](compatibility.md).
Recorded on 2026-10-17.

CI ([.github/workflows/ci.yml](../.github/workflows/ci.yml)) runs
`cargo fmt --check`, `cargo clippy -D warnings` and
`cargo test --all-targets --all-features --locked` on GitHub-hosted
`ubuntu-latest` and `windows-latest`. `windows-latest` has no TPM. All tests
use in-process rustls fixtures on loopback; no test talks to a real upstream
proxy.

A separate `quickstart` job on `windows-latest` follows the
[quickstart](quickstart.md) with the release build: `gateinto key init` (on the
TPM-less runner it must report a software key created after the TPM fallback),
`gateinto key info`, a configuration file derived from `config.example.toml`,
`gateinto check-upstream` (asserting `TLSv1_3` and `X25519MLKEM768`), then
`gateinto proxy` with `curl.exe -x http://127.0.0.1:18736 https://example.com/`
(asserting `200`, with curl verifying the certificate of `example.com`) and a
plain-HTTP request (asserting `405`). The upstream is the development-only
`examples/test_upstream.rs`: a throwaway test CA, TLS 1.3 offering
`X25519MLKEM768` and `X25519`, loopback only. No third-party proxy is
involved; the only public host contacted is `example.com`, the quickstart's
own target. The job was added after the results recorded here; its outcome is
not recorded yet.

Every suite listed below as "CI, both platforms" runs in both the
`ubuntu-latest` and `windows-latest` CI jobs. An
earlier `windows-latest` failure of the TLS modes, `check-upstream` and
configuration file change was a test bug:
`config::tests::relative_paths_are_resolved_against_the_file` assumed that
`/abs/client.pem` is an absolute path on Windows. The test was fixed; no
production code changed. After the fix these suites passed in both jobs.

Status values: **verified in CI**, **partial**, **manual steps documented but
not executed**, **not verified**.

| Capability | How it is verified | Status | Needed to verify further |
| --- | --- | --- | --- |
| Relay (local `CONNECT` to upstream HTTPS proxy, status mapping, limits) | `tests/proxy.rs` against an in-process TLS 1.3 upstream fixture; parser unit tests in `src/http.rs`. CI, `ubuntu-latest` and `windows-latest`. `curl.exe` through the release binary in the `quickstart` job. | Verified in CI (fixture and local test upstream only) | A real third-party upstream proxy, browsers, and physical Windows 10/11 machines. |
| Quickstart flow on Windows without a TPM, Software KSP key, local proxy to remote HTTPS `CONNECT` | The `quickstart` job on `windows-latest` runs the [quickstart](quickstart.md) commands against `examples/test_upstream.rs` on loopback, as described above. | In CI (local test upstream only); first outcome not recorded yet | A person following the docs by hand on a physical machine or VM, and a real third-party upstream. |
| Software device key (create once, reuse, non-exportable, `key info`) | `tests/device_key_windows.rs` and `tests/windows_cng.rs` on `windows-latest`, where the TPM is absent and the software fallback runs for real; lifecycle rules in unit tests of `src/identity/device_key.rs` against a fake store. | Verified in CI (`windows-latest`) | Physical Windows 10/11 machines. Which status code the TPM probe returns on the runner is expected, not observed. |
| TPM device key | Manual steps 1 to 8 in [tpm-verification.md](tpm-verification.md). The decision logic is unit-tested with a fake store. | Manual steps documented but not executed | A Windows 10/11 machine with a usable TPM 2.0, running those steps. |
| mTLS with a software key | `tests/mtls.rs` (test-only software identity, all platforms) and `tests/mtls_windows.rs` (real CNG software key signing `CertificateVerify`, certificate from a file and from `CurrentUser\My`). CI, both platforms. | Verified in CI (fixture only) | A real upstream proxy that requires client certificates. |
| mTLS with a TPM key | Manual steps 9 to 15 in [tpm-verification.md](tpm-verification.md). | Manual steps documented but not executed | A TPM machine and an upstream requiring client certificates from a test CA. Whether the TPM signs without a PIN or consent prompt is unknown. |
| Hybrid post-quantum key exchange (`X25519MLKEM768`, fallback to `X25519`) | `tests/key_exchange.rs` (both platforms); `tests/tls_modes.rs` and `tests/check_upstream.rs` through the proxy and `check-upstream` against hybrid and classical fixtures; unit tests in `src/tls.rs`. CI, both platforms. | Verified in CI (fixture only) | `check-upstream` against a real upstream (which group it negotiates depends on the server's TLS library). |
| `hybrid_required` refusal (no downgrade, local `502`) | `tests/tls_modes.rs`: against a classical fixture the handshake fails and the client gets `502`, never `200`; `tests/check_upstream.rs`: the command exits nonzero; unit tests for the post-handshake group check. CI, both platforms. | Verified in CI (fixture only) | A real classical-only upstream. |
| Windows 7 SP1 x64 | [.github/workflows/windows7.yml](../.github/workflows/windows7.yml) builds `x86_64-win7-windows-msvc` on `windows-latest` and audits the import table. See [windows7-feasibility.md](windows7-feasibility.md). | Partial: build and static import audit only; runtime not verified | A Windows 7 SP1 VM with the UCRT update, running the steps in [windows7-feasibility.md](windows7-feasibility.md#alternatives-if-blocked). Windows 7 is not a supported release target. |
| Configuration file and CLI overrides | Unit tests in `src/config.rs` and `src/main.rs`; `tests/config_cli.rs` and `tests/cli.rs` through the binary. CI, both platforms. | Verified in CI | Physical Windows 10/11 machines. |
| Release packaging (zip and `.sha256`) | [.github/workflows/release.yml](../.github/workflows/release.yml) ran once via `workflow_dispatch` on a branch and produced the `x86_64-pc-windows-msvc` zip artifact. No release was created and no tag was pushed. | Partial: one manual run, no release | A `v*` tag run that creates the draft release, then downloading the zip and checksum and verifying them on Windows as in the [quickstart](quickstart.md#from-a-github-release). |

Not verified at all:

- Any real third-party upstream HTTPS proxy, including the stunnel and Squid
  example in the [quickstart](quickstart.md#2-bring-an-upstream-https-proxy-you-control).
- Physical Windows 10/11 machines; runtime results come only from the
  GitHub-hosted `windows-latest` image.
- A person following the [quickstart](quickstart.md) by hand on a physical
  machine or VM. The `quickstart` CI job automates the same commands, but not
  the reading of the docs.
- Browsers and system proxy settings.
- The `certutil -user -addstore My` import shown in the README.
