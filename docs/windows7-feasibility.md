# Windows 7 feasibility

Feasibility study, not a release gate. Windows 7 is experimental and
unsupported. Recorded on 2026-10-16.

## Goal

Find out whether `gateinto` can be built for Windows 7 SP1 x64 without changing
product code or weakening its security settings (TLS 1.3 only, certificate
verification, `X25519MLKEM768` preferred), and which dependencies would stop it.

## Environment

Executed, on Linux x86_64:

- Reading the sources of every crate in the Windows dependency graph from
  `~/.cargo/registry` and of Rust std from the `rust-src` component of
  `nightly-2026-09-15` (`rustc 1.100.0-nightly (574ff7d98 2026-09-14)`).
- `cargo tree --target x86_64-pc-windows-msvc` and `--target all` to find which
  crates reach the binary.
- A type check (no C build, no link) of the `gateinto` binary for
  `x86_64-win7-windows-msvc` with `-Z build-std`, using the AWS-LC stub from
  [compatibility.md](compatibility.md#windows-type-check-from-linux). It passed.
  The stub uses the `x86_64-pc-windows-msvc` bindings, while a real build uses
  `aws-lc-sys`'s universal bindings.
- Parsing the workflow with Python `yaml` and `actionlint` 1.7.12 (shellcheck
  and pyflakes were not installed, so `run:` scripts were not linted).

Executed in CI, on `windows-latest` (see [CI result](#ci-result)):

- A real build and link for `x86_64-win7-windows-msvc` and a static import
  audit of the resulting `gateinto.exe`.

Not executed:

- Anything on Windows 7. No Windows 7 VM is available here, so runtime on
  Windows 7 SP1 is NOT tested.

## Build attempt

`x86_64-win7-windows-msvc` is a Tier 3 target with no prebuilt std, so std is
built from source on a pinned nightly. On a Windows x64 machine with Visual
Studio 2022 Build Tools (MSVC x64 tools and a Windows SDK):

```powershell
rustup toolchain install nightly-2026-09-15 --profile minimal --component rust-src
cargo +nightly-2026-09-15 build -Z build-std=std,panic_abort --target x86_64-win7-windows-msvc --locked --release --bin gateinto
dumpbin /nologo /imports target\x86_64-win7-windows-msvc\release\gateinto.exe
```

NASM and CMake are not needed: `rustls`'s `aws_lc_rs` feature enables
`aws-lc-rs/prebuilt-nasm`, and `aws-lc-sys` uses its `cc` builder when the
universal bindings apply. The build log should contain the `aws-lc-sys` warning
`Setting _WIN32_WINNT to _WIN32_WINNT_WIN7 for x86_64-win7-windows-msvc target`;
without it the binary uses `ProcessPrng` (see below).

CI: [.github/workflows/windows7.yml](../.github/workflows/windows7.yml) runs the
same build on `windows-latest` on `workflow_dispatch` and on pull requests that
change the workflow or this document. It then runs `dumpbin /imports`, prints
the imported DLLs, lists Windows 8+ API names found as strings in the binary
(candidates for `GetProcAddress`), fails if a Windows 8+ API is in the static
import table, and uploads `gateinto.exe` and `imports.txt` when the build
succeeded. If the string scan finds `ProcessPrng`, the job emits a
`ProcessPrng found` warning annotation but does not fail: AWS-LC loads
`ProcessPrng` at runtime and would abort on Windows 7, so a green job is not
evidence of Windows 7 compatibility. Check the annotations, not only the job
status.

The workflow names its variables `NIGHTLY_TOOLCHAIN` and `WIN7_TARGET` because
Windows environment variable names are case-insensitive: a workflow-level
`TOOLCHAIN` overrides the `toolchain` variable that `dtolnay/rust-toolchain`
sets from its input, and the action then fails with `'toolchain' is a required
input`.

## CI result

Run [38962289234](https://github.com/lukeo3o1/gateinto-dev/actions/runs/38962289234),
job `x86_64-win7-windows-msvc`, commit `f9c4134`, `windows-latest`,
`nightly-2026-09-15`, `-Z build-std=std,panic_abort --release --locked`. An
earlier run failed in the `dtolnay/rust-toolchain` step because of the variable
name collision above, before any build.

- Build: succeeded. The artifact `gateinto-x86_64-win7-windows-msvc`
  (`gateinto.exe`, `imports.txt`) was uploaded.
- Imported DLLs: `ADVAPI32.dll`, `api-ms-win-crt-{convert,environment,heap,locale,math,runtime,stdio,string,utility}-l1-1-0.dll`,
  `bcrypt.dll`, `kernel32.dll`, `ntdll.dll`, `VCRUNTIME140.dll`, `WS2_32.dll`.
- Windows 8+ APIs in the static import table: none.
- `ProcessPrng` as a string in the binary: not found, so no `ProcessPrng found`
  warning. With `bcrypt.dll` imported, this is consistent with the `cc` builder
  compiling AWS-LC with `_WIN32_WINNT=0x0601` and using `BCryptGenRandom`. That
  is an inference from build output, not a runtime observation.
- Windows 8+ API names found as strings (runtime lookups):
  `api-ms-win-core-synch-l1-2-0`, `GetSystemTimePreciseAsFileTime`,
  `SetThreadDescription`, `WaitOnAddress`, `WakeByAddressSingle`. These match
  the optional lookups of the std win7 target, which fall back to Windows 7
  APIs when they are missing (see the std sources in the table below). That is
  the documented std behaviour, not verified on Windows 7.

The static audit passing does not show that the binary runs on Windows 7.

## Dependency findings

Versions are those in `Cargo.lock`. Only crates that reach the Windows binary
are listed, plus `getrandom`.

| Crate | Version | Windows API concern | Win7 status | Evidence |
| --- | --- | --- | --- | --- |
| Rust std (`x86_64-win7-windows-msvc`) | `nightly-2026-09-15` | Tier 3: no upstream tests, needs nightly `-Z build-std`. The target replaces `ProcessPrng` with `RtlGenRandom`, `GetSystemTimePreciseAsFileTime` with `GetSystemTimeAsFileTime`, loads `WaitOnAddress` optionally with an NT keyed-event fallback, and uses SRW locks for `Mutex`, `RwLock` and `Condvar`. `SetThreadDescription` is also looked up at runtime. The CI string scan found exactly these optional names (`WaitOnAddress`, `WakeByAddressSingle` via `api-ms-win-core-synch-l1-2-0`, `GetSystemTimePreciseAsFileTime`, `SetThreadDescription`) and none in the import table. | risk (Tier 3, builds; fallbacks not run on Windows 7) | `library/std/src/sys/random/windows.rs`, `sys/pal/windows/c.rs`, `sys/pal/windows/compat.rs`, `sys/sync/{mutex,condvar,rwlock,thread_parking}/mod.rs` |
| MSVC CRT | runner toolset | Rust links `vcruntime140.dll` and the UCRT (`api-ms-win-crt-*`) dynamically. Windows 7 SP1 needs the UCRT update (KB2999226) or a Visual C++ redistributable that still installs on Windows 7, or a static CRT build. | risk (needs KB2999226 or redistributable) | CI `imports.txt`: `VCRUNTIME140.dll` and nine `api-ms-win-crt-*-l1-1-0.dll` |
| `tokio` / `mio` | 1.53.3 / 1.2.4 | IOCP plus AFD polling: `NtCreateFile` on `\Device\Afd\Mio`, `NtDeviceIoControlFile` (`IOCTL_AFD_POLL`), `NtCancelIoFileEx`, `GetQueuedCompletionStatusEx`, `SetFileCompletionNotificationModes`, all Vista or later. `WSASocketW` is called with `WSA_FLAG_NO_HANDLE_INHERIT` and no fallback, a flag supported from Windows 7 SP1. | ok on SP1 | `mio-1.2.4/src/sys/windows/afd.rs`, `iocp.rs`, `net.rs:36` |
| `socket2` | 0.6.5 | `WSA_FLAG_NO_HANDLE_INHERIT`, as above. | ok on SP1 | `socket2-0.6.5/src/sys/windows.rs` |
| `aws-lc-sys` (AWS-LC) | 0.46.0 | Entropy: by default `LoadLibraryW("bcryptprimitives")` plus `GetProcAddress("ProcessPrng")`, which calls `abort()` on Windows 7 and does not show in the import table. With `_WIN32_WINNT <= 0x0601` it uses `BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)` from `bcrypt.dll` instead. The `cc` builder defines `_WIN32_WINNT=0x0601` for `-win7-windows-` targets; the CMake builder does so only for `-win7-windows-gnu`. Threads use `InitOnceExecuteOnce` and SRW locks (Windows 7 or later). CI build: `bcrypt.dll` imported and no `ProcessPrng` string in the binary, consistent with the `BCryptGenRandom` path. | ok by build evidence (not run on Windows 7) | `aws-lc/crypto/rand_extra/windows.c`, `builder/cc_builder.rs:445`, `builder/cmake_builder.rs:450`, `builder/main.rs` (`get_builder`, `is_bindgen_required`), `aws-lc/crypto/thread_win.c` |
| `aws-lc-rs` | 1.18.2 | No Windows API of its own. The win7 target is not among the pre-generated binding targets, so the universal bindings are used; not a documented platform. | risk | `aws-lc-sys-0.46.0/builder/main.rs` (`supported_platform`), no `win7` in `aws-lc-rs-1.18.2` |
| `rustls`, `rustls-webpki`, `tokio-rustls`, `webpki-roots` | 0.23.46, 0.103.15, 0.26.6, 1.0.9 | No OS API; TLS does not use SChannel, so no Windows TLS updates are needed. | ok | Source has no Windows FFI |
| `rustls-cng` | 0.7.1 | `NCryptSignHash`, `NCryptGetProperty`, `NCryptSetProperty`, `NCryptFreeObject`, `Cert*`, `CryptAcquireCertificatePrivateKey`, `BCryptHash`: all Vista or later. | ok | `rustls-cng-0.7.1/src` |
| `windows-sys`, `windows-link` | 0.61.2, 0.2.1 | `raw-dylib` imports by DLL name. Every function used by the crates above maps to `kernel32`, `ntdll`, `ws2_32`, `ncrypt`, `crypt32` or `bcrypt`, not to API-set DLLs. | ok | `windows-link-0.2.1/src/lib.rs`, `link!` lines in `windows-sys-0.61.2/src` |
| `gateinto` CNG key code | 0.1.0 | Software KSP (`Microsoft Software Key Storage Provider`) and `NCryptCreatePersistedKey` and related functions exist on Windows 7. The TPM key backend needs the `Microsoft Platform Crypto Provider`, which first shipped with Windows 8. | risk (TPM not available) | `src/identity/windows_cng.rs` |
| `anstyle-query`, `anstyle-wincon` (clap) | 1.1.5, 3.0.11 | `ENABLE_VIRTUAL_TERMINAL_PROCESSING` is rejected on Windows 7; the failure is handled and only disables colors. | ok | `anstyle-query-1.1.5/src/windows.rs` |
| `getrandom` | 0.4.3, 0.2.17 | 0.4.3 is only a build-script dependency on the host (`jobserver` from `cc` from `aws-lc-sys`); 0.2.17 is in `Cargo.lock` but in no build graph. Neither reaches the binary. 0.4.3 would pick `windows_legacy` (`RtlGenRandom`) on win7. | ok | `cargo tree --target all -e all -i getrandom@…`, `getrandom-0.4.3/src/backends.rs:161` |

No examined code uses `SetDefaultDllDirectories` or `LOAD_LIBRARY_SEARCH_*`, so
KB2533623 (superseded by KB3063858) is not required by this evidence.

## Conclusion

`partial`

`gateinto.exe` builds and links for `x86_64-win7-windows-msvc` in CI and passes
the static import audit: no Windows 8+ API in the import table, no `ProcessPrng`
string, and the only Windows 8+ names found by the string scan are std's
optional runtime lookups. Nothing has been run on Windows 7 SP1, the target is
Tier 3, the binary needs the UCRT and VC++ runtime there, and the TPM key
storage provider does not exist on Windows 7.

## Alternatives if blocked

- If a later build finds `ProcessPrng`: force the `cc` builder
  (`AWS_LC_SYS_CMAKE_BUILDER=0`) or pass `_WIN32_WINNT=0x0601` through
  `CFLAGS_x86_64_win7_windows_msvc`, then confirm with the binary string scan.
- If AWS-LC does not build: the `ring` provider in `rustls` keeps TLS 1.3,
  certificate verification and `X25519`, and `ring` 0.17 gets entropy from
  `getrandom` 0.2 (`BCryptGenRandom` with an `RtlGenRandom` fallback). It has no
  `X25519MLKEM768`, so it drops the post-quantum hybrid group. Taking that
  trade-off is a policy decision, not part of this study.
- If the UCRT is the problem: link the CRT statically with
  `-C target-feature=+crt-static`.

To reach `working`:

1. Windows 7 SP1 x64 VM with all updates, including KB2999226 (UCRT) and
   KB3063858.
2. Copy `gateinto.exe` from the `gateinto-x86_64-win7-windows-msvc` artifact
   of run 38962289234 (or a newer one), or rebuild with
   [windows7.yml](../.github/workflows/windows7.yml) if the artifact has
   expired, and check that it starts: `gateinto --help`.
3. Run `gateinto proxy --upstream-host <host> --upstream-port <port>` against a
   controlled upstream proxy and send
   `curl --proxy http://127.0.0.1:18736 https://example.com/` through it. The
   TLS 1.3 handshake to the upstream proxy exercises AWS-LC's `BCryptGenRandom`
   entropy path at runtime. Confirm in the upstream proxy's TLS log that
   `X25519MLKEM768` was negotiated.
4. Run `gateinto key init --backend software` and `gateinto key info`, and
   confirm that a software KSP key is created and reused.
5. Record the results here and replace the label above.
