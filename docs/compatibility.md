# Compatibility

Detailed evidence. For a one-table summary of what is verified, see
[verification.md](verification.md).

Findings from the project skeleton spike, recorded on 2026-10-16 with Rust 1.97.0
on Linux x86_64. Windows behavior is only type-checked locally; runtime results
on Windows come from CI.

## Crates

| Crate | Version | Role | Notes |
| --- | --- | --- | --- |
| `rustls` | 0.23.46 | TLS 1.3 client | Latest stable. `0.24.0-dev.*` exists but is a pre-release and is not used. Features: `aws_lc_rs`, `std`. `tls12` is off, so only TLS 1.3 is available. |
| `aws-lc-rs` | 1.18.2 | Crypto provider | Pulled in by `rustls/aws_lc_rs`. Also a direct dependency for SHA-256 fingerprints and the device key self-test signature check; this resolves to the same package, so `Cargo.lock` gains no new crate. |
| `aws-lc-sys` | 0.46.0 | AWS-LC build | Transitive. |
| `rustls-cng` | 0.7.1 | CNG `SigningKey`, certificate store | Requires `rustls ^0.23` and `windows-sys ^0.61`. Used with `default-features = false` so it does not enable `rustls/tls12`. `CngSigningKey` signs the TLS 1.3 client authentication; `CertStore::open(CurrentUser, "My")` and `find_all` enumerate `CurrentUser\My`. `CngSigningKey` does not implement `SigningKey::public_key`, so rustls' `CertifiedKey::keys_match` cannot be used; Gateinto compares the certificate's SPKI with the device key's itself. |
| `windows-sys` | 0.61.2 | NCrypt, TBS, registry, token and process FFI | Same major as `rustls-cng`, so key handles are the same type. Features `Win32_System_Registry` (URI handler registration and Chrome and Edge `App Paths`), `Win32_Security_Authorization`, `Win32_System_Threading` and `Win32_System_Pipes` (the user's SID for the agent's pipe name and its DACL, the pipe server's user check, detached agent process flags) were added for the launch URI; features do not change `Cargo.lock`. |
| `tokio` | 1.53.3 | Async runtime | Features: `rt-multi-thread`, `net`, `io-util`, `macros`, `time`, `sync`, `process` (starting and watching the browser), `signal` (Ctrl+C and SIGTERM). Named pipes come from `net` on Windows. `signal` adds `signal-hook-registry` 1.4.8 and `errno` 0.3.14 to `Cargo.lock`, built on Unix only. |
| `tokio-rustls` | 0.26.6 | Async TLS | Requires `rustls ^0.23.27`, compatible with 0.23.46. Its default features enable `rustls/tls12`, so it is used with `default-features = false, features = ["aws_lc_rs"]`. |
| `webpki-roots` | 1.0.9 | Default upstream roots | Mozilla root program as static data. License CDLA-Permissive-2.0. Replaced entirely by `--ca-file`. |
| `tracing` | 0.1.44 | Logging | |
| `tracing-subscriber` | 0.3.23 | Log output | `default-features = false, features = ["fmt", "std", "env-filter"]`. |
| `rcgen` | 0.14.10 | Test certificates | Dev-dependency, `default-features = false, features = ["aws_lc_rs", "pem"]`. Requires Rust 1.88, which sets the crate's `rust-version`. |
| `clap` | 4.6.7 | CLI | `derive` feature. |
| `serde` | 1.0.229 | Configuration file | `derive` feature. Latest stable; `rust-version` 1.56. Also pulls `serde_core` and `serde_derive` 1.0.229. |
| `toml` | 1.1.8+spec-1.1.0 | Configuration file | `default-features = false, features = ["std", "serde", "parse"]` (no writer). Latest stable; `rust-version` 1.85. Pulls `toml_parser` 1.1.5, `toml_datetime` 1.1.2, `serde_spanned` 1.1.2 and `winnow` 1.0.4. `Cargo.lock` also lists `toml_writer`, `indexmap`, `hashbrown` and `equivalent` as entries of disabled optional features; they are not built (`cargo tree -p toml -e normal`). |

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
| Windows code type-checks and passes clippy for `x86_64-pc-windows-msvc`, including `src/identity/windows_cng.rs`, `tests/device_key_windows.rs`, `tests/mtls_windows.rs`, and (since the TLS modes and configuration file work) `src/config.rs`, `src/check.rs`, `tests/tls_modes.rs`, `tests/check_upstream.rs` and `tests/config_cli.rs`. | See below. |
| The device key lifecycle rules hold: an existing `tpm` or `software` key is reused; both providers are always probed, and keys in both are an error for `key init` and a warning for `key info`; a TPM that is present but not ready during lookup is an error that creates nothing in either provider, even when a software key exists; any other open failure than "not found" or "provider unavailable" is an error and creates nothing; an unavailable TPM, a failed TPM creation or a failed TPM self-test falls back to software (deleting a half-created TPM key first); a TPM reported as not ready while TPM Base Services report `TBS_E_TPM_NOT_FOUND` counts as unavailable, so a software key is created on first init (or an error with fallback disabled, creating nothing) and reused afterwards, while not ready with a TPM present stops with an error and creates nothing; disabled fallback is an error; `--backend software` skips the TPM; `key info` never creates. | Unit tests in `src/identity/device_key.rs` against a fake key store. |
| The DER SubjectPublicKeyInfo built from an uncompressed P-256 point equals the one AWS-LC produces; the fingerprint is lowercase hex SHA-256; the ECC public blob parser rejects a wrong magic, a wrong `cbKey` and wrong lengths with a specific error. | Unit tests in `src/identity/encoding.rs`. |
| CNG status codes are classified as "not found" (`NTE_BAD_KEYSET`, `NTE_NOT_FOUND`, `NTE_NO_KEY`), "provider unavailable", meaning absent (`NTE_PROV_DLL_NOT_FOUND`, `NTE_BAD_PROVIDER`, `NTE_DEVICE_NOT_FOUND`, `TBS_E_TPM_NOT_FOUND`), "provider not ready", meaning present but not usable now (`NTE_DEVICE_NOT_READY`, `NTE_PROVIDER_DLL_FAIL`, `TBS_E_SERVICE_NOT_RUNNING`, `TBS_E_SERVICE_DISABLED`), or other failures. When opening a provider fails, "not found" codes also count as absent; "not ready" and other failures are passed through and stop the lookup. A "not ready" result from the Platform Crypto Provider becomes "provider unavailable" only when the TPM Base Services probe returns `TBS_E_TPM_NOT_FOUND`; a successful probe or any other probe failure keeps it "not ready", with the probe result appended to the reason; the probe runs only for "not ready". | Unit tests in `src/identity/cng_status.rs`. Whether Windows actually returns these codes is not verified; see Unverified. |
| `gateinto key init` and `key info` fail with "device keys are only supported on Windows" on other platforms. | `tests/cli.rs`. |
| TLS modes offer `[X25519MLKEM768, X25519]` (`hybrid_preferred`), `[X25519MLKEM768]` (`hybrid_required`) and `[X25519]` (`classical_only`); the post-handshake check accepts only TLS 1.3 with a group the mode offers. | Unit tests in `src/tls.rs`. |
| Through the proxy, against in-process upstream fixtures offering `[X25519MLKEM768, X25519]` (hybrid) or `[X25519]` (classical): `hybrid_preferred` negotiates `X25519MLKEM768` with the hybrid and `X25519` with the classical upstream and both tunnels relay data; `hybrid_required` negotiates `X25519MLKEM768` with the hybrid upstream, and with the classical one the upstream handshake fails with `NoKxGroupsInCommon` and the local client gets `502`, never `200`; `classical_only` negotiates `X25519` with the hybrid upstream; every mode still rejects an untrusted CA and a name mismatch with `502`. The negotiated group is recorded on the fixture's server side. | `tests/tls_modes.rs`. |
| Upstream connections never resume a session or send early data: `enable_early_data` is off, and a second handshake with the same client configuration against a fixture that issues session tickets is full on both sides. Temporarily removing `Resumption::disabled()` made the test fail with `HandshakeKind::Resumed`. | `tests/session_resumption.rs`. |
| The negotiated version and group are logged once per tunnel at `debug` and not at `info`, for the default and each `--tls-mode`. | `tests/proxy.rs` (spawning the binary). |
| `check-upstream` reports TLS 1.3, the negotiated group (`X25519MLKEM768` or `X25519` per fixture and mode), a `TLS13_*` cipher suite, the server certificate subject and whether a client certificate was not requested, requested but not sent, or sent; with `--target` the upstream status line only (no headers or body). The binary prints the group for each fixture and mode and exits nonzero for `hybrid_required` against the classical fixture, an unreachable upstream, an untrusted CA, a non-`2xx` `CONNECT` reply and a malformed `--target`. | `tests/check_upstream.rs` (library calls and the binary). |
| Configuration file: every section and key, defaults, unknown keys and sections (including the earlier `[listen]`, `[upstream]` and `[tls]`) rejected, invalid values rejected, gateway names limited to 1 to 64 characters from `[A-Za-z0-9_-]` (as table keys, in `[device_session] gateway` and for `--gateway`), a missing or incomplete upstream is an error naming the gateway and `--upstream-host`/`--upstream-port`, the device session uses `[device_session] gateway` or the only gateway, several gateways without `[device_session] gateway` and a reference to an unknown gateway are errors listing the configured gateways, gateway lookup by name reads only the loaded file, flags override the selected gateway key by key and leave the others unchanged, relative paths in every gateway resolve against the file, errors name the file, `config.example.toml` parses. Through the binary: `proxy`, `check-upstream`, `key init` and `key info` read `--config`; flags override it; `proxy` relays through the device session's gateway; `check-upstream --gateway` checks the named gateway, applies flags to it and names the file and the configured gateways for an unknown one; `[limits] max_concurrent_tunnels` and its `--max-tunnels` override take effect; a non-loopback `[device_session] listen` is refused without `--unsafe-allow-non-loopback-listen` and binds with it; there is no file key that allows it. | Unit tests in `src/config.rs`; `tests/config_cli.rs`; `tests/cli.rs`. |
| Sessions: several sessions in one process each bind their own loopback listener (ephemeral ports differ), build their own TLS client configuration and resolver, and with a self-signed source issue their own certificate, so the upstream fixture sees one fingerprint per session over several alternating tunnels, the same SPKI for all, and never the source's or the other session's certificate, on one gateway and on two gateways (each session reaching only its own upstream). Closing a session refuses new connections on its port without reaching the upstream, aborts its established tunnels, and leaves the other session's tunnels and new tunnels working with their own certificate; closing every session refuses every port. A required self-signed certificate that cannot be issued for a session fails its start; an optional one starts the session without a client certificate. A non-loopback listen address still needs the opt-in. | `tests/sessions.rs`; unit tests `a_reissue_has_its_own_certificate_for_the_same_key` in `src/identity/certificates.rs` and `a_session_gets_its_own_self_signed_certificate_but_shares_a_fixed_one` in `src/identity/client_cert.rs`. |
| `basic_tofu`: a `CONNECT` without credentials gets `407` with `Proxy-Authenticate: Basic realm="Gateinto session <hex>", charset="UTF-8"` and reaches no upstream; the first well-formed Basic credential binds and works for many sequential and concurrent tunnels; it is not forwarded upstream; other credentials get `407` and malformed ones `400` without binding; of 32 simultaneous first `CONNECT`s with distinct credentials exactly one ever succeeds; the failure limit answers `429` with `Retry-After` even for the bound credential; a session started after closing a taken one has a new port and realm and binds afresh; a device session and two browser sessions in one process use distinct self-signed certificates and separate bindings; `trace` logs contain no password and no base64 credential. Through the binary: `session browser` listens on an ephemeral loopback port, prints `listen` and `realm`, and requires `basic_tofu`; two processes have separate ports, realms and bindings; `proxy` applies `[device_session] auth = "basic_tofu"`. | Unit tests in `src/proxy/basic_tofu.rs` and `src/http.rs`; `tests/basic_tofu.rs`; `tests/basic_tofu_logs.rs`; `tests/config_cli.rs`. |
| Launch URIs and the agent, on Linux with a Unix socket and a fake browser: the strict URI grammar and its rejections; `open` refusing invalid URIs before any agent exists, starting a detached agent, and later calls reaching it; the agent re-validating requests, refusing unknown profiles, malformed and oversized requests, launches beyond 5 a minute (a lower limit in the test) and beyond the session cap; each launch starting a new session and a browser with its own marked profile directory, the session's proxy and the configured `portal_url` or `about:blank`; a `basic_tofu` tunnel through the launched session; the browser's exit, `session close`, `stop`, SIGINT and SIGTERM closing the session and deleting the profile; stale profiles swept at agent start without touching other directories; a second agent refused; the device session run by the agent. The registration command string and its recognition. | `tests/agent.rs`, `tests/launch.rs`; unit tests in `src/uri.rs`, `src/ipc.rs`, `src/agent.rs`, `src/browser.rs`, `src/registration.rs`. Linux only so far; the Windows paths (named pipe, registry, SID) are type-checked. |
| `key init` flags override `[device_key] software_fallback_on_first_create` in both directions (`--no-software-fallback` over `true`, `--software-fallback` over `false`), the default allows fallback, and the two flags cannot be combined. | Unit tests in `src/main.rs`. |
| The `[default: ...]` values in `--help` match `DEFAULT_LISTEN`, the limit defaults, `DEFAULT_KEY_NAME`, the default backend, TLS mode and client certificate mode. Temporarily changing `DEFAULT_KEY_NAME` made the test fail. | `tests/cli.rs`: `help_defaults_match_the_real_defaults`. |
| The crate, including `serde` and `toml`, builds and all tests pass with Rust 1.88.0. | `cargo +1.88 test --all-targets --all-features --locked`. |

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

The same check passes for `i686-pc-windows-msvc` (`rustup target add
i686-pc-windows-msvc`) with stub `cc` and `ar` scripts set as
`CC_i686_pc_windows_msvc` and `AR_i686_pc_windows_msvc` and a `nasm` on `PATH`,
since the `aws-lc-sys` build script assembles the x86 sources even for a type
check.

### 32-bit Windows (i686)

`i686-pc-windows-msvc` is built and released as a zip next to the x64 one.
What is verified:

- CI (`windows-i686` job in [.github/workflows/ci.yml](../.github/workflows/ci.yml))
  builds it on `windows-latest` and runs
  `cargo test --target i686-pc-windows-msvc --all-targets --all-features --locked`.
  The tests run as 32-bit processes under WOW64 on 64-bit Windows Server,
  including the CNG Software KSP tests, the named-pipe agent tests and the
  registry tests. The job then runs the static C runtime check on the 32-bit
  `gateinto.exe`. `dumpbin` from the `Hostx64d` toolset reads the import
  table of 32-bit PE files as well, and the `KERNEL32.dll` check is
  case-insensitive.
- The release workflow runs the same tests, builds the release binary and runs
  the static C runtime check before packaging.
- These jobs have not run yet.

Not verified: running on a real 32-bit Windows 10 installation, a TPM key from a
32-bit process, and Chrome or Edge launched by a 32-bit agent. There is no
32-bit MSI; the MSI is x64 only.

`aws-lc-sys` 0.46.0 compiles the `generated-src/win-x86/*.asm` sources with
NASM (`-f win32`). Its prebuilt NASM objects exist only for `x86_64`
(`use_prebuilt_nasm` requires `target_arch() == "x86_64"`), and without NASM
the build stops with "NASM command not found! Build cannot continue."
`aws-lc-rs` recommends installing NASM from nasm.us. The i686 jobs install
NASM 2.16.03 with `ilammy/setup-nasm@v1`, which downloads that release from
nasm.us; the x64 jobs do not install it, so they keep using the prebuilt
objects. `aws-lc-sys` ships pre-generated `i686-pc-windows-msvc` bindings, so
no `libclang` is needed.

A 32-bit process on 64-bit Windows sees a different registry and environment:

- Reads from `HKLM\SOFTWARE` are redirected to `WOW6432Node`, where 64-bit
  Chrome and Edge do not register their App Paths. Gateinto reads the
  registry with `KEY_WOW64_64KEY` (`RRF_SUBKEY_WOW6464KEY` for
  `RegGetValueW`), so 32-bit and 64-bit builds see the same keys.
  `src/registry.rs` tests this by creating a key under `HKLM\SOFTWARE` in the
  64-bit view and reading it back; it fails without the flag only in the
  32-bit build, and it skips outside GitHub Actions when the process is not
  elevated.
- `ProgramFiles` is `C:\Program Files (x86)` in a 32-bit process. Browser
  discovery also looks under `ProgramW6432` (the 64-bit `Program Files`), so it
  finds 64-bit Chrome and Edge installed there; duplicates are dropped when
  both variables name the same folder. Unit tests in `src/browser.rs` cover
  both environments.
- `HKCU\Software\Classes\gateinto` (the URI handler) and
  `HKCU\...\CurrentVersion\Run` are not redirected, so registration is the
  same for both builds. The handler registered by a 32-bit build points to the
  32-bit exe.
- No code casts pointers or handles to fixed-width integers; the only `usize`
  conversions widen `u32` values.

### On GitHub Actions

The CI workflow ([.github/workflows/ci.yml](../.github/workflows/ci.yml))
runs `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features
--locked -- -D warnings` and `cargo test --all-targets --all-features --locked`
in two jobs, `ubuntu-latest` and `windows-latest`. Pull requests that change
only Markdown files or files under `docs/` skip the workflow, except changes to
`README.md` and `docs/quickstart.md`; no test or job reads any other
documentation file. `master` has no required status checks. If required checks are ever added,
this paths filter has to change, because a skipped workflow never reports
its checks and the pull request would wait for them forever. Pushes to `master` always run it. A new push to a pull
request cancels the run still in progress for it.
Other runs, such as pushes to `master`, each get their own concurrency group,
so none of them is cancelled or replaced by a later one.

A `build-windows-release` job runs the quickstart's
`cargo build --release --locked` on `windows-latest`, builds the
`test_upstream` example, checks the release `gateinto.exe` with the static C
runtime check below and uploads both executables; the `quickstart` and `msi`
jobs download them instead of compiling. This split has not run in CI yet;
the results below were recorded when each job built its own binary. The
`quickstart` job runs the
[quickstart](quickstart.md) commands on `windows-latest` with that release
build: `key init` and `key info` (asserting
the software key created after the TPM fallback, or printing the backend if a
TPM is ever present), `check-upstream` with a configuration file derived from
`config.example.toml` (asserting `TLSv1_3` and `X25519MLKEM768`), and `proxy`
with `curl.exe` to `https://example.com/` (`200`) and a plain-HTTP request
(`405`). The upstream is `examples/test_upstream.rs`, a development-only cargo
example built on `tests/fixture/`: it generates a throwaway test CA, writes
only the CA certificate, listens on loopback only, accepts TLS 1.3 with
`X25519MLKEM768` and `X25519`, and relays one `CONNECT`. Its in-process tests
run in both CI jobs. The job has run and passed: `key init` created a software
key after the TPM fallback and `key info` matched it; `check-upstream` reported
`TLSv1_3`, `X25519MLKEM768`, `TLS13_AES_256_GCM_SHA384` and
`HTTP/1.1 200 Connection established` for `example.com:443`; `curl.exe` got
`200` and `405`; and `certutil -delkey` removed the key afterwards.

Every job that compiles Rust uses `Swatinem/rust-cache@v2` with its own
`shared-key`. The CI jobs save their cache only on `master`, so pull requests
restore the `master` cache without evicting it with their own. The Windows 7
workflow saves its cache only when it is started by hand (`workflow_dispatch`),
so a run started from `master` fills the cache that its pull request runs
restore. The release
workflow only restores caches (`save-if: false`): the x64 build restores the
`windows-latest` CI job's cache (`shared-key: check-windows-latest`) and runs
the same `cargo test --all-targets --all-features --locked` without `--target`
(the runner's host is `x86_64-pc-windows-msvc`), so it reuses that job's debug
build; the i686 build restores the `windows-i686` CI job's cache and reuses its
debug build of the same `cargo test --target i686-pc-windows-msvc`. Neither cache contains a
`target\<target>\release` directory, so each shipped `gateinto.exe` is
compiled from scratch, and a release never writes a cache.

The release workflow
([.github/workflows/release.yml](../.github/workflows/release.yml)) ran once
via `workflow_dispatch` on a branch and produced the `x86_64-pc-windows-msvc`
zip artifact. No release was created and no tag was pushed. The workflow now
also builds the MSI from the release `gateinto.exe` with
`packaging/wix/build.ps1` and WiX 5.0.2 and attaches it with its `.sha256`;
this step has not run yet.

### Static C runtime

Builds before the static C runtime change imported `VCRUNTIME140.dll` and the
UCRT (`api-ms-win-crt-*`). On Windows 10 only `VCRUNTIME140.dll` was missing
without the Visual C++ Redistributable, because the UCRT ships with Windows
10; the UCRT only matters on Windows 7 and 8.1. `.cargo/config.toml` now sets
`-C target-feature=+crt-static` for `cfg(all(windows, target_env = "msvc"))`,
which covers `x86_64-pc-windows-msvc`, `i686-pc-windows-msvc` and
`x86_64-win7-windows-msvc`. No
workflow sets `RUSTFLAGS` or `CARGO_ENCODED_RUSTFLAGS`, which would replace
these flags.

AWS-LC's C code follows the same setting. `aws-lc-sys` 0.46.0 uses its `cc`
builder here; it does not call `cc::Build::static_crt`, so `cc` 1.8.0 reads
`CARGO_CFG_TARGET_FEATURE` and passes `-MT` instead of `-MD` when it contains
`crt-static`. The CMake builder checks the same variable (`is_crt_static` in
`builder/main.rs`) and sets `CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded`. In a
Linux cross build for `x86_64-pc-windows-msvc` with a logging stub compiler,
all 257 AWS-LC compiler invocations got `-MT`; with `RUSTFLAGS` set in the
environment they got `-MD`.

`.github/scripts/assert-static-crt.ps1` runs `dumpbin /dependents` (found with
`vswhere`) and fails if `gateinto.exe` depends on `VCRUNTIME*.dll`,
`MSVCP*.dll`, `MSVCR*.dll`, `CONCRT*.dll`, `VCOMP*.dll`, `VCCORLIB*.dll`,
`ucrtbase*.dll` or `api-ms-win-crt-*.dll`, or if the list lacks
`KERNEL32.dll`. The `windows-latest` CI job runs it on the debug binary that
`cargo test` builds, the `build-windows-release` CI job on the release binary
used by the `quickstart` and `msi` jobs, the release workflow on the release
binary of each target before packaging, the `windows-i686` CI job on the
`i686-pc-windows-msvc` debug binary, and the Windows 7 workflow on the
`x86_64-win7-windows-msvc` build,
whose import table names `kernel32.dll` in lower case; the `KERNEL32.dll` check
is case-insensitive. Whether the binary starts on a Windows 10 machine without
the redistributable has not been checked; only this import check verifies it.

On `windows-latest`:

| Claim | How |
| --- | --- |
| For `x86_64-pc-windows-msvc`, `aws-lc-sys` builds with only the runner's preinstalled tools. This is expected because `rustls/aws_lc_rs` enables `aws-lc-rs/prebuilt-nasm` and `aws-lc-sys` ships pre-generated `x86_64-pc-windows-msvc` bindings. `i686-pc-windows-msvc` needs NASM; see [32-bit Windows](#32-bit-windows-i686). | The x64 jobs have no NASM or CMake setup step. |
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
providers by a drop guard. The first version of these tests failed in CI
(see below); the fixed tests run in the `windows-latest` job. Only job results
were checked; the per-test logs were not retrieved, so which TPM branch the
tests took is not recorded.

### Hosted runner without a TPM

An earlier version of the suite failed 10 of 13 tests in `tests/device_key_windows.rs` on
`windows-latest`: opening a key in the Microsoft Platform Crypto Provider
returned `NTE_DEVICE_NOT_READY` (`0x80090030`), which was classified as "TPM
present but not usable", so the lookup stopped before the software path ran.

`NTE_DEVICE_NOT_READY` alone cannot tell "no TPM" from "TPM present but not
ready". `CngStore` now asks TPM Base Services (`Tbsi_GetDeviceInfo` from
`tbs.dll`) whenever the Platform Crypto Provider reports a "not ready" code
during open or create. `TBS_E_TPM_NOT_FOUND` (`0x8028400F`) makes the provider
count as absent, so the software key is created once and reused afterwards;
anything else keeps the "not ready" error. On the hosted runner TBS is expected
to return `TBS_E_TPM_NOT_FOUND`. The suite passes there, but the returned
code itself has not been observed.

`tests/device_key_windows.rs` calls `Tbsi_GetDeviceInfo` itself to decide which
outcome to require. Without a TPM: opening a missing TPM key is "provider
unavailable", default init falls back with `TpmProblem::Unavailable`, and init
with fallback disabled fails with "the TPM provider is unavailable" and creates
nothing in either provider. With a TPM: opening a missing TPM key is "not
found", and init with fallback disabled either creates a `tpm` key or fails
without creating a software key.

A TPM disabled in firmware is indistinguishable from no TPM, so it leads to a
software identity. Use `--no-software-fallback` on machines known to have a TPM.

### Negotiated key exchange

Evidence for which group is negotiated comes from the tests above and from
`gateinto check-upstream`, which prints the group the client actually
negotiated (`negotiated_key_exchange_group()`); run it against a real upstream
to see what that upstream supports. `hybrid_required` is enforced twice: the
client offers only `X25519MLKEM768`, so an upstream without it cannot complete
the handshake, and after the handshake the negotiated group is checked again
and the tunnel is refused with `502` if it is anything else. The second check
cannot be reached through a real handshake with the restricted offer; unit
tests cover the group check and its mapping to a local `502`, and temporarily offering both groups in every mode
showed the `tests/tls_modes.rs` `hybrid_required` test still getting `502`
from the post-handshake check alone (but failing on the server-side assertion
that the handshake itself failed).

### Configuration file

The schema has gateway profiles (`[gateways.<name>]` with `host`, `port`,
`server_name`, `ca_file`, `tls_mode`, `client_certificate`,
`client_cert_file`, `self_signed_client_cert`), the device session
(`[device_session] gateway`, `listen`), `[device_key] name`, `preferred`,
`software_fallback_on_first_create` and `[limits] max_concurrent_tunnels`,
`connect_timeout_seconds`, `idle_timeout_seconds`, `header_max_bytes`. The
earlier `[listen]`, `[upstream]` and `[tls]` sections were replaced, not kept
as aliases, since no release used them. Adaptations:

- Relative `ca_file` and `client_cert_file` are resolved against the
  directory of the configuration file.
- `[device_key] preferred` and `software_fallback_on_first_create` are used by
  `key init` only; the proxy only opens `[device_key] name`.
- `check-upstream` uses `[limits] connect_timeout_seconds` as the limit for the
  whole check and `header_max_bytes` for the `CONNECT` reply; other limits and
  `[device_session] listen` are ignored there.
- There is deliberately no key for `--unsafe-allow-non-loopback-listen`.

The suites for TLS modes, `check-upstream` and the configuration file
(`tests/tls_modes.rs`, `tests/check_upstream.rs`, `tests/config_cli.rs` and
the unit tests in `src/config.rs`) run in both CI jobs. Their first
`windows-latest` run failed because
`config::tests::relative_paths_are_resolved_against_the_file` treated
`/abs/client.pem` as absolute, which it is not on Windows. That was a bug in
the test, fixed in the test; production code did not change. After the fix
these suites passed in both jobs.

## Client certificate (mTLS)

Design choices:

- The certificate store is read with `rustls-cng` `CertStore` (already a
  dependency, no extra `unsafe` in Gateinto) rather than with Crypt32 through
  `windows-sys`. All selection logic runs on the DER bytes, so it is the same
  code on every platform.
- X.509 fields (SubjectPublicKeyInfo, validity, extended key usage, subject)
  are read by a small DER reader in `src/identity/x509.rs` instead of a new
  crate; `Cargo.lock` is unchanged. The thumbprint is SHA-1 over the
  certificate DER, as Windows computes it. Certificates the reader cannot
  parse are skipped during the store search and are an error in a
  `--client-cert-file`.
- The client certificate is only checked against the device key. Gateinto does
  not validate its chain or issuer; the upstream does.
- Self-signed certificates are DER-encoded by hand in
  `src/identity/certificates.rs` instead of with `rcgen`, which stays a
  dev-dependency. `rcgen` 0.14.10 can sign with an external `SigningKey`, but
  without its `crypto` feature its defaults differ (no default serial number,
  and an empty subject key identifier for an explicit non-CA certificate), and
  the dev-dependency enables that feature in test builds,
  so tests would not cover the release behavior. The encoding is a fixed
  template; `Cargo.lock` is unchanged. The certificate is signed through the
  rustls `SigningKey` of the device key (`CngSigningKey` on Windows), the same
  object that signs `CertificateVerify`.

Where each check runs:

| Check | Where | Platforms |
| --- | --- | --- |
| SPKI, validity (UTCTime and GeneralizedTime, inclusive bounds), EKU, subject and thumbprint extraction; malformed DER is rejected. | Unit tests in `src/identity/x509.rs` with `rcgen` certificates. | All (Linux locally and in CI, Windows in CI) |
| Store candidate selection: SPKI equality, Client Authentication EKU or no EKU, validity at a given time, latest NotAfter among several, unparsable entries skipped. | Unit tests in `src/identity/client_cert.rs`. | All |
| PEM loading: leaf and intermediates in order; missing file, file without certificates and malformed leaf name the file. | Unit tests in `src/identity/client_cert.rs`. | All |
| `optional`/`required`/`off` decision table, including unsupported platform, missing key, missing certificate, mismatched certificate and unreadable file; the key is opened, never created; a mismatched certificate is refused before the signing key is opened. | Unit tests in `src/identity/client_cert.rs` against a fake `ClientIdentityStore`. | All |
| An upstream that requires client certificates (`WebPkiClientVerifier` with a test client CA) rejects an agent without one (`502`, never `200`); accepts the certificate bound to a software test key (tunnel works and the fixture recorded exactly that certificate); rejects a certificate from another CA (`502`). A certificate for a different key is refused locally before any connection. | `tests/mtls.rs` with a test-only software `ClientIdentityStore`. | All. Ran locally on Linux. |
| `--client-certificate` values, `--key-name` validation; `required` fails with "device keys are only supported on Windows" off Windows, also with `--client-cert-file`; `optional` (default) logs the "mTLS is not configured" warning exactly once and relays; `off` does not warn. `key info --client-cert-file` fails off Windows. | `tests/cli.rs`, `tests/proxy.rs` (spawning the binary). The warning tests pass a key name that does not exist, so they also hold on Windows. | All; the Windows branches only in CI. |
| A software CNG device key with a unique name gets an `rcgen` test-CA certificate for its SPKI. (a) Via `--client-cert-file` semantics the tunnel through the mTLS fixture works, signed by `CngSigningKey`, and `key info --client-cert-file` reports its thumbprint. (b) After importing it into `CurrentUser\My` (Crypt32 `CertAddEncodedCertificateToStore`), the proxy finds it by SPKI with no file, the tunnel works, and `key info` reports it with source `CurrentUser\My`. Drop guards remove the certificate and delete the key. | `tests/mtls_windows.rs`. | `windows-latest` only (Software KSP; the TPM-absent probe makes init use software there). Runs in the `windows-latest` CI job. |
| Self-signed certificate fields (version, serial, `ecdsa-with-SHA256`, `CN=Gateinto device`, 5-minute backdating, 1-hour validity, critical non-CA basic constraints, critical `digitalSignature`, `clientAuth`), distinct serials and fingerprints with the same SPKI, signature accepted by `rustls-webpki` with the certificate as its own anchor (validity bounds included), refusal of a key that does not match the public key or cannot sign ECDSA P-256 SHA-256, renewal at 30 minutes. One certificate was also inspected with OpenSSL 3.0.13 (`openssl x509 -text`; `openssl verify -purpose sslclient` with itself as CA: `OK`), outside the test suite. | Unit tests in `src/identity/certificates.rs` and `src/identity/x509.rs`. | All. Ran locally on Linux. |
| With a self-signed certificate from a software test key, two proxy starts tunnel through an upstream fixture whose test-only verifier accepts only the device SPKI and has `rustls-webpki` check the certificate with itself as anchor; the fixture recorded two different certificates with the same SPKI. A fixture trusting another SPKI rejects the handshake. `check-upstream` reports the source, the certificate SHA-256 and the device key SPKI SHA-256. `--self-signed-client-cert` and a certificate file are refused together. | `tests/mtls.rs`, `tests/check_upstream.rs`, `tests/cli.rs`, `tests/config_cli.rs`. | All. Ran locally on Linux. |
| The same two self-signed certificates from a real Software KSP device key, so CNG signs the certificate and `CertificateVerify`. | `tests/mtls_windows.rs`: `self_signed_certificates_are_signed_by_the_cng_device_key`. | `windows-latest` only. Not run yet. |
| TPM-backed device key signing the client authentication. | Manual steps in [tpm-verification.md](tpm-verification.md). | Not executed. |

### MSI installer

Only a reduced variant of `packaging/wix/gateinto.wxs` was compiled locally:
WiX 5.0.2 on Linux, with the `Directory` elements removed because WiX on Linux
rejects every `Directory/@Name`, stops at binding (no `msi.dll`). The committed
source was first built, ICE-validated and installed in the `msi` CI job on
`windows-latest`, which passed with the Microsoft Software Key Storage
Provider: silent per-user install, uninstall with a running agent, reinstall
with the same SPKI, purge and a new SPKI (see
[verification.md](verification.md)). A TPM key, interactive install and
uninstall, the Windows 10/11 matrix, an upgrade between two versions, the
logon autostart starting an agent at a real logon, and a `gateinto://` link
clicked in a real browser after installing are manual and not verified. There
is no WinGet package.

## Unverified

Not exercised:

- TLS modes and `check-upstream` against a real upstream proxy or a
  TLS-terminating middlebox; only the in-process rustls fixtures were used.
- mTLS with a TPM-backed key, including whether `CngSigningKey` signs with it
  silently. Manual steps are in [tpm-verification.md](tpm-verification.md).
- The `certutil -user -addstore My` import shown in the README. The OpenSSL
  commands there were run with OpenSSL 3.0.13 on Linux against a stand-in key,
  and the result was parsed by `load_certificate_file`.
- A real upstream proxy requiring client certificates.

- That `Tbsi_GetDeviceInfo` returns `TBS_E_TPM_NOT_FOUND` on `windows-latest`
  is expected, not observed; `tests/device_key_windows.rs` passes there
  either way.
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
  GitHub-hosted `windows-latest` runner image, which has Visual Studio and
  its C runtime DLLs installed, so it cannot show a missing C runtime.
- A person following the [quickstart](quickstart.md) on a physical machine or
  VM. The `quickstart` CI job runs the same commands against a local test
  upstream.

Design-only, not exercised at all:

- UI/PIN behavior for TPM keys.
- Browsers with `basic_tofu`: whether Chrome and Edge show their native
  prompt for the `407`, cache the credential across tunnels and restarts, and
  prompt again for a new session with a new port and realm. Manual steps are
  in [browser-verification.md](browser-verification.md); they have not been
  executed.
- Chrome and Edge started by the agent, and a `gateinto://` link clicked in
  them. Only a fake browser has been started; manual steps are in
  [browser-verification.md](browser-verification.md#launch-uri-and-agent).
- The URI handler registration and the named pipe on Windows: both are only
  type-checked from Linux so far (`tests/uri_registration.rs`, the
  named-pipe path of `tests/agent.rs`).
- The proxy against a real third-party upstream HTTPS proxy, and with
  browsers. `curl.exe` through the proxy runs only in the `quickstart` CI job,
  against the local test upstream `examples/test_upstream.rs`.

## Open issues

- `rustls` 0.23.46 was released on 2026-10-14. The 0.24 line is in pre-release;
  its `SigningKey` API may change and `rustls-cng` will need a matching release.
- `rustls-cng` hashes with `BCryptHash` and converts P1363 to DER with
  `CryptEncodeObjectEx`. If TPM keys need different flags (for example
  non-silent operations) the adapter may have to be replaced by a thin custom
  `SigningKey`.
- `rustls-cng::key::NCryptKey::sign` uses `NCRYPT_SILENT_FLAG` by default; a TPM
  key with a PIN or consent UI would fail instead of prompting.
- Ctrl+C is handled by `gateinto proxy`, `gateinto session browser` and
  `gateinto agent`, which close their sessions before exiting; on Windows
  also Ctrl+Break, closing the console, logoff and shutdown, and on Unix
  SIGTERM. The handlers are registered before any session starts. Tests
  send SIGINT and SIGTERM on Unix only; the Windows console events are not
  exercised by a test, and Windows ends a process a few seconds after a
  console close, which may cut the cleanup short. An agent started by
  `gateinto open` has no console and is stopped with `gateinto stop`.
- The Unix bind lock is a plain `O_EXCL` lock file, because `File::lock`
  needs Rust 1.89 and `flock` would need `libc`. Two agents that find the
  same lock file older than 10 seconds at the same moment can both take it
  over; this needs a crashed agent and two simultaneous starts, and Unix is
  a development platform.
- `tests/agent.rs` and `tests/launch.rs` find the fake browser next to their
  own executable in `target/<profile>/deps` (`fake_browser-<hash>`), because
  `cargo test` builds examples as test harnesses and only exposes binaries,
  not test targets, through `CARGO_BIN_EXE_*`. Running one of those test
  files alone with `--test` needs `--test fake_browser` too.
- Self-signed certificates are now issued per session. `gateinto proxy` with
  `--self-signed-client-cert` therefore signs twice at startup with the device
  key: once to check the key while configuring client authentication, and
  once for the device session. On a TPM this is a second signing operation.
- Test keys are user-scoped and deleted by a drop guard. A test process that is
  killed before the guard runs leaves a key named `gateinto-test-<pid>-<nanos>-<n>`
  or `gateinto-test-device-<pid>-<nanos>-<n>` in the user's key store.
- A software device key is only marked non-exportable. An administrator, or
  malware running as the user, can still copy the key files.
