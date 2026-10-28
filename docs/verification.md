# Verification status

Which capabilities have been verified, how, and what is still needed. Detailed
evidence and the history behind it are in [compatibility.md](compatibility.md).
Recorded on 2026-10-17.

CI ([.github/workflows/ci.yml](../.github/workflows/ci.yml)) runs
`cargo fmt --check`, `cargo clippy -D warnings` and
`cargo test --all-targets --all-features --locked` on GitHub-hosted
`ubuntu-latest` and `windows-latest`. `windows-latest` has no TPM. All tests
use in-process rustls fixtures on loopback; no test talks to a real upstream
proxy. Pull requests that change only Markdown files or files under `docs/`
skip CI, except changes to `README.md` and `docs/quickstart.md`; pushes to
`master` always run it. `master` has no required status checks. If required checks are ever added,
this paths filter has to change, because a skipped workflow never reports
its checks and the pull request would wait for them forever.

A `build-windows-release` job on `windows-latest` runs the quickstart's
`cargo build --release --locked` and builds `examples/test_upstream.rs`, checks
that the release `gateinto.exe` links the C runtime statically, and uploads both
executables. The `quickstart` and `msi` jobs download them instead of compiling
again. This split has not run in CI yet; the results below were recorded when
each job built its own binary. The `quickstart` job on `windows-latest` then follows the
[quickstart](quickstart.md) with that release build, starting with
`gateinto.exe --version`: `gateinto key init` (on the
TPM-less runner it must report a software key created after the TPM fallback),
`gateinto key info`, a configuration file derived from `config.example.toml`,
and `gateinto check-upstream --target example.com:443` (asserting `TLSv1_3`,
`X25519MLKEM768` and the upstream's `200`). It does not tunnel `curl.exe`
through a session: a session's credentials are only shown in a prompt, which
the runner has no desktop or terminal for. The relay, `200` and `405` through
a session are covered by `tests/proxy.rs` and `tests/config_cli.rs` against
the same kind of in-process upstream. The upstream is the development-only
`examples/test_upstream.rs`: a throwaway test CA, TLS 1.3 offering
`X25519MLKEM768` and `X25519`, loopback only. No third-party proxy is
involved; the only public host contacted is `example.com`, the quickstart's
own target. The job has run and passed: the software key was created after the
TPM fallback and matched by `key info`; `check-upstream` reported `TLSv1_3`,
`X25519MLKEM768`, `TLS13_AES_256_GCM_SHA384` and
`HTTP/1.1 200 Connection established` for `example.com:443`; and
`certutil -delkey` removed the key afterwards. That run also tunnelled `curl.exe`
through the since removed `gateinto proxy`; the job in its current form has
not run yet.

Every suite listed below as "CI, both platforms" runs in both the
`ubuntu-latest` and `windows-latest` CI jobs. An
earlier `windows-latest` failure of the TLS modes, `check-upstream` and
configuration file change was a test bug:
`config::tests::relative_paths_are_resolved_against_the_file` assumed that
`/abs/client.pem` is an absolute path on Windows. The test was fixed; no
production code changed. After the fix these suites passed in both jobs.

The compatibility workflow
([.github/workflows/compat.yml](../.github/workflows/compat.yml)) runs the
x64 tests, the i686 tests under WOW64 and the MSI lifecycle on `windows-2022`
and `windows-2025` weekly and by `workflow_dispatch`, not on pushes; it has not
run yet. Which Windows versions are covered by
what is in the [compatibility matrix](compatibility.md#compatibility-matrix).
Windows Server runners do not verify Windows 10 or 11 client editions.

Status values: **verified in CI**, **partial**, **manual steps documented but
not executed**, **not verified**.

| Capability | How it is verified | Status | Needed to verify further |
| --- | --- | --- | --- |
| Relay (local `CONNECT` to upstream HTTPS proxy, status mapping, limits) | `tests/proxy.rs` against an in-process TLS 1.3 upstream fixture; parser unit tests in `src/http.rs`. CI, `ubuntu-latest` and `windows-latest`. `curl.exe` through the release binary in the `quickstart` job. | Verified in CI (fixture and local test upstream only) | A real third-party upstream proxy, browsers, and physical Windows 10/11 machines. |
| Quickstart flow on Windows without a TPM, Software KSP key, local proxy to remote HTTPS `CONNECT` | The `quickstart` job on `windows-latest` runs the [quickstart](quickstart.md) commands against `examples/test_upstream.rs` on loopback, as described above. | Verified in CI (local test upstream only) | A person following the docs by hand on a physical machine or VM, and a real third-party upstream. |
| Software device key (create once, reuse, non-exportable, `key info`) | `tests/device_key_windows.rs` and `tests/windows_cng.rs` on `windows-latest`, where the TPM is absent and the software fallback runs for real; lifecycle rules in unit tests of `src/identity/device_key.rs` against a fake store. | Verified in CI (`windows-latest`) | Physical Windows 10/11 machines. Which status code the TPM probe returns on the runner is expected, not observed. |
| TPM device key | Manual steps 1 to 8 in [tpm-verification.md](tpm-verification.md). The decision logic is unit-tested with a fake store. | Manual steps documented but not executed | A Windows 10/11 machine with a usable TPM 2.0, running those steps. |
| mTLS with a software key | `tests/mtls.rs` (test-only software identity, all platforms) and `tests/mtls_windows.rs` (real CNG software key signing `CertificateVerify`, certificate from a file and from `CurrentUser\My`). CI, both platforms. | Verified in CI (fixture only) | A real upstream proxy that requires client certificates. |
| Self-signed client certificate from the device key (`--self-signed-client-cert`) | Unit tests in `src/identity/certificates.rs` (fields, distinct serials and fingerprints with the same SPKI, signature checked by `rustls-webpki`, refusal of a mismatched or non-P-256 key, renewal) and `src/identity/client_cert.rs`; `tests/mtls.rs` (two proxy starts with a software test key against a fixture that trusts the SPKI; another SPKI is rejected); `tests/check_upstream.rs` (report lines); `tests/config_cli.rs` and `tests/cli.rs` (exclusive with a certificate file). `tests/mtls_windows.rs` does the same with a real CNG Software KSP key signing the certificate and `CertificateVerify`. See [protocol/client-cert.md](protocol/client-cert.md). | Partial: passed locally on Linux; not yet run in CI, and the Windows CNG test has not run | A `windows-latest` CI run, a TPM key, and a real upstream proxy configured to trust the device key's SPKI. |
| mTLS with a TPM key | Manual steps 9 to 15 in [tpm-verification.md](tpm-verification.md). | Manual steps documented but not executed | A TPM machine and an upstream requiring client certificates from a test CA. Whether the TPM signs without a PIN or consent prompt is unknown. |
| Hybrid post-quantum key exchange (`X25519MLKEM768`, fallback to `X25519`) | `tests/key_exchange.rs` (both platforms); `tests/tls_modes.rs` and `tests/check_upstream.rs` through the proxy and `check-upstream` against hybrid and classical fixtures; unit tests in `src/tls.rs`. CI, both platforms. | Verified in CI (fixture only) | `check-upstream` against a real upstream (which group it negotiates depends on the server's TLS library). |
| `hybrid_required` refusal (no downgrade, local `502`) | `tests/tls_modes.rs`: against a classical fixture the handshake fails and the client gets `502`, never `200`; `tests/check_upstream.rs`: the command exits nonzero; unit tests for the post-handshake group check. CI, both platforms. | Verified in CI (fixture only) | A real classical-only upstream. |
| No upstream session resumption or early data | `tests/session_resumption.rs`: early data is off in the client configuration, and a second handshake with the same configuration against a fixture that issues session tickets is full on both sides, never resumed. Temporarily removing the setting made the test fail with a resumed handshake. CI, both platforms. | Verified in CI (fixture only) | A real upstream that issues session tickets or accepts early data. |
| No Visual C++ Redistributable needed (static C runtime) | `.cargo/config.toml` sets `+crt-static` for MSVC targets; `.github/scripts/assert-static-crt.ps1` fails if `gateinto.exe` depends on `VCRUNTIME*`, `MSVCP*`, `ucrtbase` or `api-ms-win-crt-*` DLLs. It runs in the `windows-latest` CI job (debug binary), the `build-windows-release` CI job (release binary) and the release workflow (release binary). See [compatibility.md](compatibility.md#static-c-runtime). | Partial: import check added; not yet run in CI | A CI run, and starting the release binary on a Windows 10/11 machine without the redistributable. |
| 32-bit Windows (`i686-pc-windows-msvc`) | The `windows-i686` CI job on `windows-latest` builds the target with NASM 2.16.03, runs `cargo test --target i686-pc-windows-msvc --all-targets --all-features --locked` as 32-bit processes under WOW64 on 64-bit Windows, and runs the static C runtime check on the 32-bit `gateinto.exe`; the release workflow does the same and attaches the executable. Unit tests cover browser discovery through `ProgramW6432` and reading `HKLM` in the 64-bit registry view. See [compatibility.md](compatibility.md#32-bit-windows-i686). | Partial: passed clippy locally on Linux for `i686-pc-windows-msvc`; the CI and release jobs have not run yet | A CI run, and running the executable on a real 32-bit Windows 10 installation (not verified), including a TPM key and Chrome or Edge launched by a 32-bit agent. The x86 MSI has only run under WOW64 in CI and is untested on Windows 7. |
| Windows 7 SP1 | The regular releases require Windows 10 or later. A user report showed a regular build failing to load on Windows 7: `Tbsi_GetDeviceInfo` could not be found in `tbs.dll`. That import is now resolved at runtime, and `BCryptHash` (Windows 10) is no longer imported. [.github/workflows/windows7.yml](../.github/workflows/windows7.yml) builds the experimental `i686-win7-windows-msvc` target on `windows-latest` (the x64 Windows 7 target is no longer built), fails on any static import outside a Windows 7 allow-list or on `ProcessPrng`, and uploads the exe. See [windows7-feasibility.md](windows7-feasibility.md). | Partial: earlier x64 builds imported both functions and would not have loaded. In run 39074036884 (x64 Windows 7 build, since dropped) the fixed x64 build passed the audit, and the i686 build built and failed only on three Windows 7-safe imports, now allowed. Runtime not verified. | A passing workflow run, then the steps in [windows7-feasibility.md](windows7-feasibility.md#alternatives-if-blocked) on a Windows 7 SP1 machine, 32-bit first. Windows 7 is not a supported release target. |
| Configuration file and CLI overrides | Unit tests in `src/config.rs` and `src/main.rs`; `tests/config_cli.rs` and `tests/cli.rs` through the binary. CI, both platforms. | Verified in CI | Physical Windows 10/11 machines. |
| Gateway profiles (`[gateways.<name>]`, `--gateway`, command-line-only upstream, the refused `[device_session]`) | Unit tests in `src/config.rs` (selection, name validation, unknown and ambiguous references, lookup by name only, overrides only on the selected gateway, the command-line-only gateway kept apart from one named `command-line`); the removed `[device_session]` section refused with an error naming it; through the binary, `tests/config_cli.rs` with config files (gateway selection by `--gateway`, several gateways without a selection refused by `check-upstream` and `session browser`, a missing upstream, the limits read from the file), `tests/cli.rs` for `check-upstream --gateway` without a config file, a missing upstream and the removed `proxy` command, and `tests/proxy.rs` for command-line-only use. | Partial: passed locally on Linux and in the Windows type check; not yet run in CI | A CI run on both platforms, and the `quickstart` job with the new `config.example.toml`. |
| Session isolation and closing (`src/sessions.rs`) | `tests/sessions.rs`, several sessions in one process against in-process fixtures with a software test key: two sessions on one gateway, and on two gateways, each present their own self-signed certificate (same SPKI, different fingerprints) on every tunnel and never the other's; a closed session's port refuses connections while the other session keeps relaying; closing aborts the session's established tunnels and leaves the other session's open; a required self-signed certificate that cannot be issued stops the session start, an optional one starts without a certificate. Unit tests for per-session issuance in `src/identity/`. Temporarily sharing the certificate between sessions, or spawning tunnels outside the session's task set, made these tests fail. | Partial: passed locally on Linux; not yet run in CI | A CI run on both platforms; real CNG keys issuing per-session certificates (`tests/mtls_windows.rs` still starts one proxy at a time). |
| `session_credentials` local proxy authentication and browser sessions (`src/proxy/session_credentials.rs`, `src/prompt.rs`, `gateinto session browser`, `gateinto session credentials`) | Unit tests in `src/proxy/session_credentials.rs` (the alphabet, uniform mapping of random bytes by rejection sampling, the fixed user name with a grouped and fresh password, any other user name refused, `Debug` redacted, strict Basic and base64 parsing against RFC 4648 vectors, only the issued credentials accepted, an unknown first credential binding nothing, another session's credentials refused, rate limit and window reset with injected times, the issued credentials refused during a flood), `src/http.rs` (header returned, repeated header refused, `Debug` redacted), `src/prompt.rs` (the text names the proxy and warns against other dialogs, the note for unshown credentials does not contain them, a message box that fails falls back to the terminal; on Windows the message box style and a failed box counted as not shown), `src/ipc.rs` (credential lines read and stripped from printed output), and `src/config.rs`, `src/uri.rs`, `src/ipc.rs` (`basic_tofu` refused naming `session_credentials`); `tests/session_credentials.rs` through sessions against in-process fixtures: the `407` challenge and its exact header, many sequential and concurrent tunnels with the issued credentials and none reaching the gateway, the credentials not forwarded upstream, unknown credentials `407` and never binding, a rejected request causing no DNS lookup, routing decision or gateway connection, malformed headers `400`, `429` with `Retry-After` after the failure limit even for the issued credentials, distinct sessions with credentials that work only on their own port, and closing a session ending its tunnels, closing its port and leaving the old credentials refused by a new session; `tests/session_credentials_logs.rs` captures `trace` logs and checks that neither the password nor base64 credentials appear; `tests/config_cli.rs` runs `session browser` (ephemeral loopback port, realm, credentials only in the prompt, `407`, a second process with its own credentials, refusal to run when the credentials cannot be shown, an interrupt ending it while its prompt is still open); `tests/proxy.rs` checks that `session browser` without a configuration file answers `407` without credentials and relays with the ones shown. The prompt is captured in these tests through the `test-hooks` feature (`GATEINTO_TEST_CREDENTIALS_FILE`); the message box itself has not been shown. | Partial: passed locally on Linux and in the Windows type check; not yet run in CI | A CI run on both platforms. |
| Fuzzing of the parsing surface (`CONNECT` heads and upstream responses, `session_credentials` answers, launch URIs, agent IPC lines, X.509) | The cargo-fuzz crate in `fuzz/` (a separate workspace with its own `Cargo.lock`) has five targets that check invariants: a streamed head never parses differently from the whole, the `Debug` output does not depend on the credential, only the issued credentials tunnel and every rejection is fixed by its status and realm, accepted profiles use only `[A-Za-z0-9_-]`, accepted links round-trip through their canonical URI and the IPC line, start pages share their portal's origin after resolution and gateway hosts carry no delimiters, encoded responses decode to themselves, X.509 fields stay in range. [.github/workflows/fuzz.yml](../.github/workflows/fuzz.yml) runs each target for 60 seconds weekly, by `workflow_dispatch` and on pull requests that change the parsers. | Partial: each target ran locally for 60 seconds on 2026-10-17 without findings in the code, `launch-uri` (90 s) and `ipc-line` (60 s) again with the link fields, and `session-credentials` for 60 seconds on 2026-10-25; the workflow has not run yet | Longer runs, and the workflow running in CI. |
| Launch URI parsing (`src/uri.rs`) | Unit tests: accepted forms, scheme case, optional `/`, decoded allowed percent-encoding, rejection of other schemes, hosts, user information, ports, paths, fragments, unknown, duplicate, empty and malformed fields, and injection attempts (quotes, spaces, `&`, `%00`, CR/LF, `..`, slashes, shell characters, non-ASCII and bidi characters, leading `-`, `--config`, the 8192-byte limit); the `url`, `gateway` and `portal` fields (raw `:` and `/` refused, encoded spaces, controls, quotes, backslashes and non-ASCII refused, `https` and strict hosts only, at least one of `gateway` or legacy `profile`, optional `portal`, `url` on a trusted portal's origin, no CA, TLS mode, listen or certificate fields), the canonical form round-tripping, the longest portal and start page fitting, and the Windows command-line bound. | Partial: passed locally on Linux and in the Windows type check; not yet run in CI | A CI run on both platforms. |
| Links that choose a start page or bring a gateway (`src/link.rs`, `src/prompt.rs`, `gateinto gateway list`, `gateinto gateway forget`) | Unit tests of `resolve` for every rule (known profile with matching, different or incomplete gateway and portal; start pages on and off the portal origin and without a portal; unknown profile with and without a gateway; a known address under another name; approve, deny and defer), gateway address and origin parsing, the per-gateway files in `gateways/` (`src/link/store.rs`: canonical file names for DNS, IPv4, IPv6 and IPv4-mapped addresses and their reverse mapping, the 255-byte limit, only single plain `[a-z0-9._-]` components, a private directory, no temporary leftovers, no overwriting of a name or an address, the 32-file and 16 KiB bounds, forgetting by validated name, other keys, renamed or planted files and duplicate names each disabling only their own entry, non-regular entries, links never followed and a linked or non-directory `gateways/` refused, purging only regular `*.toml` files and an empty directory), Windows device names and IPv6 look-alike hosts refused, resolution failing closed for names and addresses held by invalid files and for an unreadable directory, linked gateways getting exactly the settings of a minimal config gateway, the confirmation text, the terminal prompt (`yes` only) and, on Windows, the dialog style. `tests/agent.rs` in process: start pages, refused mismatches, a new gateway stored only after `approve` and relaying through the test upstream, `deny`, one confirmation at a time with expiry, wrong tokens, the rate limit before asking. `tests/launch.rs` through the binary: start pages and refusals with `open`; without a terminal `open` refuses a new gateway and stores nothing; with the `test-hooks` feature an approved gateway is stored and a session relays through the test upstream, and later links do not ask; without the test CA a linked gateway's upstream is refused (`502`). `tests/cli.rs`: `gateway list`, `gateway forget`, the sources in `status`, a damaged file reported by `status`, `setup` and `gateway list` while the other gateways stay listed, and an unusable `gateways/`. `tests/launch.rs` also checks that a damaged file blocks only its own name and address and is left unchanged. The fuzz target `launch-uri` checks that resolved start pages share the portal origin and gateway hosts have no delimiters. | Partial: passed locally on Linux and in the Windows type checks; not yet run in CI. The Windows dialog and real browsers are not verified by hand | A CI run on both platforms; the dialog on Windows 7 and 10/11 and links clicked in Chrome and Edge (step 21 of [browser-verification.md](browser-verification.md#launch-uri-and-agent)). |
| Agent, IPC and browser launch (`src/agent.rs`, `src/ipc.rs`, `src/browser.rs`, `gateinto agent`, `open`, `session list`, `session close`, `stop`) | `tests/agent.rs` in process over a Unix socket (Linux) or a named pipe (Windows) and `tests/launch.rs` through the binary, both with a fake browser (`tests/fake_browser.rs`) that records its arguments and writes into its profile: the browser gets its own profile directory, the session's proxy and the configured `portal_url` (or `about:blank`); a tunnel with the issued session credentials works through the launched session; `open` shows the credentials in the prompt and does not print them, `session credentials <id>` shows them again until the session closes and then answers `no session <id>` without them, and without a desktop or terminal `open` names that command instead; `session close` ends the session's tunnels and closes its port; the browser exiting closes the session (it leaves `session list`) and deletes the profile; `session close` and `stop` kill the browser and clean up; repeated launches create separate sessions, profiles and browsers; the rate limit and the session cap; unknown profiles and malformed IPC requests are refused by the agent; a browser that cannot start leaves nothing behind; only one agent per endpoint; a stale Unix socket and a stale bind lock are replaced, and a shared runtime directory or one owned by another user (checked only when the tests run as root) refused; a request to an agent that never answers times out and a connection closed without an answer is reported; two concurrent `open` commands without an agent both succeed with one agent; an agent of another `GATEINTO_INSTANCE` leaves the first instance's profiles alone; stale profiles are swept at agent start, foreign directories kept; `open` starts a detached agent and later calls reach it; SIGINT and SIGTERM stop `agent` with exit status 0 after its browser profile is deleted and its endpoint is gone; SIGINT stops `session browser` with exit status 0 (Unix only; the closed listener is not probed, and Windows console events, including closing the console, are not tested). Unit tests for the limiter, the IPC encoding, endpoint names, profile directories (marker, privacy, no link following) and browser discovery order. | Partial: passed locally on Linux and in the Windows type check; not yet run in CI | A CI run on both platforms, which also runs the named-pipe path, its owner and DACL and the client's pipe owner check, and the SID-based pipe name. Another Windows user squatting or opening the pipe. A real Chrome and Edge launched by the agent: manual steps in [browser-verification.md](browser-verification.md#launch-uri-and-agent). |
| Per-user URI handler registration (`gateinto uri register`, `unregister`) | Unit tests of the command string (quoting, `--`, refused paths) and its recognition, on all platforms; `tests/uri_registration.rs` on Windows registers a test-only scheme under `HKCU\Software\Classes`, reads it back, unregisters it, and checks that a foreign handler and a key without a command are left alone and an invalid command is never written. | Partial: unit tests passed locally on Linux; the Windows test has only been type-checked | A `windows-latest` CI run, and a `gateinto://` link clicked in Chrome and Edge on Windows 10/11 (manual steps in [browser-verification.md](browser-verification.md#launch-uri-and-agent)). |
| `os_user` local proxy authentication (`src/proxy/os_user.rs`, `src/proxy/os_user/windows.rs`, `src/proxy/local_auth.rs`, `src/job.rs`) | Cross-platform unit tests with a fake owner lookup, `tests/os_user_windows.rs` with the real lookup and job, and a manual check in Windows Sandbox with a probe of the same lookup; see [below](#local-proxy-authentication-os_user). | Partial: unit tests passed locally on Linux; the Windows code passes the cross-compiled clippy and the Windows test is type-checked only, not yet run in CI; the manual check passed with a local account | A CI run on `windows-latest`; a real UAC split token, domain accounts, Chrome in the job, and browsers started by Gateinto itself for a launch link, and the suspended-and-assign fallback and the launch without a job on real Windows 7 and 8.1. |
| Chrome and Edge with `session_credentials` (the credentials message box, native `407` sign-in dialog, credential caching across tunnels and restarts, wrong credentials and the rate limit, open tabs when the session closes, a new session after a close) | Manual steps in [browser-verification.md](browser-verification.md). | Manual steps documented but not executed | Running those steps on Windows 10/11 with current Chrome and Edge. Until then the browser behavior described in the README is expected, not verified. |
| Per-user MSI installer (`packaging/wix`): install, uninstall, reinstall, purge | The `msi` job on `windows-latest` builds an x64 MSI with WiX 5.0.2 from the `gateinto.exe` of the `build-windows-release` job, and an x86 MSI from the i686 debug `gateinto.exe` of the `windows-i686` job, and for each runs [.github/scripts/msi-lifecycle.ps1](../.github/scripts/msi-lifecycle.ps1), which installs silently per user (`msiexec /i /qn`), checks the exe, the exact `HKCU\Software\Classes\gateinto` command and the uninstall entry, runs `gateinto setup --backend software` (Microsoft Software Key Storage Provider, not a TPM), checks that no key exists before `setup` and that the first `setup` creates one, uninstalls silently while an agent runs and checks that the `StopAgent` action ran, the agent stopped, the exe, the handler and the `PATH` entry are gone and `key info` from a copy outside the install folder shows the same SPKI, reinstalls with `AUTOSTART=1` and checks the exact Run value and that `setup` reuses the same SPKI, then checks that `reset --purge-device-identity` refuses a wrong prefix and a missing confirmation, deletes the key with the right prefix, keeps the handler, and that the next `setup` creates a different SPKI, then uninstalls and checks the Run value is gone. Every `msiexec` call uses `/norestart` and fails on any nonzero exit code, including 3010. The `compat.yml` `msi` jobs run the same script with their own release build on `windows-2022` and `windows-2025` in weekly and manual runs; they have not run yet. See [install.md](install.md). | Verified in CI (`windows-latest`, Software KSP): the committed WiX source was first built, ICE-validated and installed by this job, which passed on 553b5ae. Only a reduced variant (without `Directory` elements) was compiled locally, on Linux, where WiX cannot bind. The PATH, autostart, StopAgent and no-key checks were added afterwards and have not run yet. | TPM keys, interactive install and uninstall, Windows 10/11 versions other than the runner's, upgrades between two versions, the autostart agent at a real logon, and a `gateinto://` link clicked in a real browser are manual and not verified. |
| `gateinto setup`, `status`, `reset --purge-device-identity`, default config location, `stop --remove-stale-profiles` | Unit tests in `src/lifecycle.rs` (service account refusal by SID, elevation note, handler state, gateway listing without secrets, purge warning text, interactive confirmation) and `src/identity/device_key.rs` (SPKI confirmation parsing, purge deletes only the confirmed key, refuses a mismatch, a missing key and keys in both providers, a new key after purge); `tests/lifecycle.rs` with an in-memory key store (reinstall keeps the SPKI, wrong prefix deletes nothing and leaves the agent running, the agent is stopped before deletion, a failed stop deletes nothing, other keys are kept, setup after purge creates a new SPKI); `tests/cli.rs` (refusals before any key is opened, config checked before the key, read-only `status`, the default config file); `tests/launch.rs` (`status` with a running agent and its sessions and no secrets, `stop --remove-stale-profiles`, `open` without `--config` using the default config); `tests/device_key_windows.rs` (purge of a real Software KSP key, another key kept). | Partial: passed locally on Linux and in the Windows type check; not yet run in CI | A CI run on both platforms, and the `msi` job. |
| Release packaging (executables, MSI and their `.sha256`) | An earlier [.github/workflows/release.yml](../.github/workflows/release.yml) ran once via `workflow_dispatch` on a branch and produced the `x86_64-pc-windows-msvc` zip artifact. It now publishes the rolling `alpha`, `beta` and `latest` releases described in [install.md](install.md#releases); `.github/scripts/release-test.sh` checks the per-channel file set, the copies without the commit and the release notes in CI. Release builds print `0.0.0-<commit>` from `gateinto --version`, which `tests/cli.rs` and a release step check; their MSIs have version `0.0.0`. The release MSI itself is not installed by any job (the CI `msi` job installs one built the same way from the CI release build), and no job installs one build over another of the same version. | Partial: the publishing workflow has not run | An `alpha` publish after a push to `master` and a manual `beta` and `latest` publish, then downloading an executable and the MSI with their checksums from the stable URLs and verifying them on Windows as in [install.md](install.md#releases). |

Not verified at all:

- Any real third-party upstream HTTPS proxy, including the stunnel and Squid
  example in the [quickstart](quickstart.md#2-bring-an-upstream-https-proxy-you-control).
- Physical Windows 10/11 machines; runtime results come only from the
  GitHub-hosted `windows-latest` image.
- A person following the [quickstart](quickstart.md) by hand on a physical
  machine or VM. The `quickstart` CI job automates the same commands, but not
  the reading of the docs.
- A real Chrome or Edge started by the agent, Chrome's and Edge's handling
  of `--user-data-dir`, `--proxy-server` and the start page, whether their
  process exit reliably signals that the user closed the browser, and a
  `gateinto://` link clicked in a browser with the handler registered
  (including the browser's confirmation prompt). Manual steps are in
  [browser-verification.md](browser-verification.md#launch-uri-and-agent).
- Browsers and system proxy settings, including Chrome's and Edge's
  sign-in dialog for a `session_credentials` `407`, their credential
  caching, and their behavior after a session is closed or replaced by a new
  one. The credentials message box on a real Windows desktop. Manual steps are
  in [browser-verification.md](browser-verification.md).
- The `certutil -user -addstore My` import shown in the README.
- The MSI with a TPM key, an interactive install or uninstall, the Windows
  10/11 matrix, and a `gateinto://` link clicked in a browser after
  installing. CI covers only silent installs on `windows-latest` with the
  Software KSP.
- `winget`: there is no WinGet package.
- Any real upstream proxy accepting a self-signed client certificate by the
  device key's public key.

## Local proxy authentication (`os_user`)

Automated:

- Cross-platform unit tests in `src/config.rs` (string or list, duplicates,
  empty lists and `none` combined refused, `os_user` refused outside Windows),
  `src/proxy/os_user.rs` (connection table rows in network byte order, finding
  the row whose local end is the peer and whose remote end is the listener, IPv6
  and IPv4-mapped addresses, denial reasons, no lookup outside Windows),
  `src/proxy/local_auth.rs` and `src/proxy/mod.rs` against a fake owner lookup
  (the lookup sees the client's address and the listener's, the same user
  tunnels, `os_user` alone answers `403` with `Connection: close`, a denial with
  `session_credentials` offered answers the Basic `407`, a slow lookup is cut
  off by the handshake deadline with `408`, denials are not counted toward
  `429`), and `src/agent.rs` (browser sessions offer `os_user` with
  `session_credentials` on Windows only when the browser is in a job; a browser
  without a job gets only `session_credentials` and its launch answer carries
  them; when putting the browser in its job fails, the agent closes that
  attempt's session, logs one warning and starts the browser again in a session
  that accepts only `session_credentials`, and the launch answer carries the
  credentials). Also: an IPv4 client is looked up as an IPv4-mapped row in the
  IPv6 table when the IPv4 table has none, rows without an owning process are
  skipped, a row count beyond the table buffer is a lookup error, only the first
  denial of a session is a warning, a lookup past the deadline is logged, and
  binding a proxy with `os_user` fails outside Windows. Passed locally on Linux.
- `tests/os_user_windows.rs`: with the real lookup, a connection from the test
  process tunnels; with a job, the test process outside it gets `403` and a
  helper started in the job with `PROC_THREAD_ATTRIBUTE_JOB_LIST` tunnels, and
  the upstream sees its `CONNECT`. `tests/job_windows.rs`: killing a process
  started in a job ends its children and leaves the job with no active process;
  dropping it empties the job in the background on a runtime and before
  returning outside one. A Windows unit test in `src/job.rs`: the
  suspended-and-assign fallback runs the process inside the job. They run in the
  `windows-latest` CI job; status partial: only type-checked from Linux, not yet
  run in CI.

Manual, in Windows Sandbox with a local account (versions not recorded),
using a probe that runs the same lookup. Windows Sandbox gives a limited
(LUA) token, not a real UAC linked token, so the elevation results are
approximate:

- The probe at medium integrity with an elevated `curl.exe` client, and the
  probe elevated with a medium-integrity client, both found the same SID
  and allowed the connection.
- Edge started in a job: every connection came from `msedge.exe`, inside
  the job, with the same SID, and was allowed. Each lookup took 0.2 to
  3.7 ms and found the row on the first attempt.
- Edge also sent plain-HTTP `GET` requests, which got `405`.

Not verified: a real UAC split token (a non-elevated Gateinto may be unable
to open an elevated client's token, which would answer `403`), domain
accounts, Chrome in the job, browsers started by Gateinto itself for a
launch link, the suspended-and-assign fallback and the launch without a job
on real Windows 7 and 8.1, and a CI run on Windows. See
[compatibility.md](compatibility.md#local-proxy-authentication-os_user).
