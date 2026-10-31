# Windows 7 feasibility

Feasibility study, not a release gate. Windows 7 is experimental and
unsupported. Recorded on 2026-10-16, updated on 2026-10-17 and 2026-10-30.

The regular releases, `x86_64-pc-windows-msvc` and `i686-pc-windows-msvc`,
require Windows 10 or later: Rust std for those targets needs Windows 10. They
do not start on Windows 7. The only Windows 7 candidate is the experimental
`i686-win7-windows-msvc` build of
[windows7.yml](../.github/workflows/windows7.yml), which the `alpha` and `beta`
releases also attach as `gateinto-<commit>-i686-win7-windows-msvc-experimental.exe`
(see [install.md](install.md#releases)); it has not been run on Windows 7. The
`x86_64-win7-windows-msvc` build below is no longer made by CI or attached to
releases; its results are kept as evidence.

## Observed failure on Windows 7

A user ran a regular release build of `gateinto.exe` on Windows 7 (most likely
32-bit, so the `i686-pc-windows-msvc` zip) and the loader refused to start it:

```text
The procedure entry point Tbsi_GetDeviceInfo could not be located in the dynamic link library tbs.dll.
```

`Tbsi_GetDeviceInfo` first shipped with Windows 8, and the TPM probe in
`src/identity/windows_cng.rs` imported it statically. The regular builds would
not have run on Windows 7 even without it, because of Rust std. The win7
artifact had the same import: the workflow's deny-list of Windows 8+ names did
not include `Tbsi_GetDeviceInfo`, so the job passed. It also missed
`bcrypt.dll!BCryptHash`, a Windows 10 function imported by
`rustls_cng::signer::CngSigningKey`.

Fixes:

- `Tbsi_GetDeviceInfo` is now loaded at runtime with
  `LoadLibraryExW("tbs.dll", LOAD_LIBRARY_SEARCH_SYSTEM32)` and `GetProcAddress`.
  When it is missing, the TPM probe reports `Tbsi_GetDeviceInfo unavailable
  (expected on Windows 7)`. A not-ready TPM provider is then treated
  as unavailable, so `key init` falls back to the Software KSP, or fails with
  that reason when fallback is disabled. On Windows 8 and later the probe
  behaves as before. A unit test in `src/identity/windows_cng.rs`, run by the
  Windows CI jobs, checks this: it asserts that the function resolves and that
  the probe never reports it missing.
- TLS client authentication and certificate signing no longer use
  `CngSigningKey`. Gateinto hashes with aws-lc-rs, signs the SHA-256 digest with
  `NCryptSignHash`, and encodes the signature as DER
  (`src/identity/p256_signer.rs`), so `BCryptHash` is no longer referenced.
- The workflow now fails on any static import that is not in an allow-list of
  functions that exist on Windows 7 SP1 (see [CI](#build-attempt)).

In run 39074036884 (commit `47926ff`), both win7 builds succeeded and passed
the static C runtime check:

- x64: 200 static imports, all on the allow-list. There is no `tbs.dll` and no
  `BCryptHash`.
- i686: built with NASM and the `cc` builder. The audit failed only on the three
  kernel32 functions above, which are now on the list.

For both targets, `bcrypt.dll` contributes only `BCryptGenRandom`, the only
bcrypt entry on the list, and the string scan found no `ProcessPrng`.

None of this has been run on Windows 7 yet.

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

For `x86_64-win7-windows-msvc`, NASM and CMake are not needed: `rustls`'s
`aws_lc_rs` feature enables `aws-lc-rs/prebuilt-nasm`, and `aws-lc-sys` uses its
`cc` builder when the universal bindings apply. `i686-win7-windows-msvc` builds
the same way, with `--target i686-win7-windows-msvc`, but needs NASM on `PATH`:
prebuilt NASM objects exist only for `x86_64`, and the 32-bit sources are
assembled with `nasm -f win32`. The build log should contain the `aws-lc-sys` warning
`Setting _WIN32_WINNT to _WIN32_WINNT_WIN7 for x86_64-win7-windows-msvc target`;
without it the binary uses `ProcessPrng` (see below).

CI: [.github/workflows/windows7.yml](../.github/workflows/windows7.yml) runs this
build for `i686-win7-windows-msvc` only on `windows-latest`, once for
`gateinto.exe` and once for `gateinto-gui.exe` (see
[GUI static import audit](#gui-static-import-audit)). It runs on `workflow_dispatch` and on pull requests that
change the workflow, its actions, its scripts, `.cargo/config.toml`,
`Cargo.toml`, `Cargo.lock`, anything under `src/`, `ipc-types/` or `gui/`, or
this document. The steps
live in two composite actions,
[win7-build](../.github/actions/win7-build/action.yml) and
[win7-audit](../.github/actions/win7-audit/action.yml), which the
[release workflow](../.github/workflows/release.yml) also uses for the alpha
and beta releases. The i686 job installs NASM 2.16.03 with
`ilammy/setup-nasm@v1`, as `ci.yml` does. Both jobs set
`AWS_LC_SYS_CMAKE_BUILDER=0`: only the `cc` builder defines
`_WIN32_WINNT=0x0601` for `-win7-windows-msvc` targets. Each job checks the
static C runtime and runs
`dumpbin /imports`. Then
[assert-win7-imports.ps1](../.github/scripts/assert-win7-imports.ps1) fails the
job in two cases:

- a static import is not in
  [win7-imports.txt](../.github/scripts/win7-imports.txt), an allow-list of
  `dll function` pairs that exist on Windows 7 SP1;
- `ProcessPrng` appears as a string in the binary (AWS-LC's runtime lookup,
  which aborts on Windows 7).

The audit also lists the other Windows 8+ names found as strings (candidates for
`GetProcAddress`), including the DPI functions the GUI resolves at runtime. The
`gateinto` job uploads `gateinto.exe` and `imports.txt` as the artifact
`gateinto-<target>`, and the GUI job uploads `gateinto-gui.exe` and
`gui-imports.txt` as `gateinto-gui-<target>`, when the build succeeded. The
release workflow builds and audits only `gateinto.exe`; no GUI is attached to
the experimental Windows 7 release.

An allow-list replaced the old deny-list because the deny-list only caught the
names someone thought of. `Tbsi_GetDeviceInfo` and `BCryptHash` got through it.
The allow-list started as the import table of the last x64 win7 build, minus
those two. The first i686 import table, from run
[39074036884](https://github.com/lukeo3o1/gateinto-dev/actions/runs/39074036884),
added three kernel32 functions that the 32-bit static CRT imports:
`DecodePointer` (XP SP2), and `InitOnceBeginInitialize` and `InitOnceComplete`
(Vista). When a dependency update adds an import, the job fails until someone
checks the function's minimum supported client and either adds it to the list
or removes the import.

`os_user` added `iphlpapi.dll GetExtendedTcpTable` (Vista) and these
kernel32 functions to the list: `CreateJobObjectW`, `SetInformationJobObject`,
`TerminateJobObject`, `QueryInformationJobObject`, `AssignProcessToJobObject`,
`IsProcessInJob` and `ResumeThread` (XP or earlier), and
`InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute` and
`DeleteProcThreadAttributeList` (Vista). All are static imports that exist on
Windows 7 SP1. The `PROC_THREAD_ATTRIBUTE_JOB_LIST` attribute itself needs
Windows 10, so on Windows 7 and 8.1 the agent is expected to fall back to
creating the browser suspended, assigning it to the job with
`AssignProcessToJobObject` and resuming it. Windows 7 does not allow nested
jobs, so the assignment fails when the agent itself already runs in a job
(as under some launchers and terminals); the agent then terminates the
suspended browser, logs one warning for that launch and starts it again
without a job, in a session that accepts only `session_credentials`. None of
this has been run on Windows 7 or 8.1.

`Tbsi_GetDeviceInfo` now appears in the string scan for both targets. That is
expected: it is the name passed to `GetProcAddress`, not a static import.

The actions name their variables `NIGHTLY_TOOLCHAIN` and `WIN7_TARGET` because
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

Run [39056727677](https://github.com/lukeo3o1/gateinto-dev/actions/runs/39056727677),
job `x86_64-win7-windows-msvc`, commit `983f38a`: the build succeeded and the
old audit passed. The import table lists `advapi32.dll`, `bcrypt.dll`,
`crypt32.dll`, `kernel32.dll`, `ncrypt.dll`, `ntdll.dll`, `tbs.dll` and
`ws2_32.dll`, and no `VCRUNTIME140.dll` or `api-ms-win-crt-*`, so the static C
runtime applies to this target. It also lists `tbs.dll!Tbsi_GetDeviceInfo`
(Windows 8) and `bcrypt.dll!BCryptHash` (Windows 10), so that binary would not
have loaded on Windows 7. Run against this run's import table, the new audit
reports exactly those two imports. With both removed, it passes.

## GUI static import audit

Recorded on 2026-10-30. This is a static import audit of `gateinto-gui.exe`
(crate `gui/`). The GUI has not been run on Windows 7, and nothing below shows
that it starts, draws or works there.

Executed, on Linux x86_64 with `cargo xwin` (clang, lld-link and the xwin
Windows SDK):

- `cargo xwin build --release --locked -p gateinto-gui` for
  `x86_64-pc-windows-msvc` and `i686-pc-windows-msvc`, and
  `cargo +nightly-2026-09-15 xwin build -Z build-std=std,panic_abort --target i686-win7-windows-msvc --release --locked -p gateinto-gui`
  with `AWS_LC_SYS_CMAKE_BUILDER=0` and NASM, on commit `7090bd3`. The win7
  link needed `LIB` pointed at the xwin `i686-unknown-windows-msvc` libraries,
  because `cargo xwin` does not set the library path for the Tier 3 triple.
- `llvm-readobj --coff-imports` on the three executables, compared with
  [win7-imports.txt](../.github/scripts/win7-imports.txt), and a scan of the
  binaries for the API names of the audit's string check.
- Reading every `GetProcAddress` lookup in `gui/src/win/sys.rs` and the COM
  interfaces used in `gui/src/win/d2d.rs` and `gui/src/win/text.rs`.

Executed in CI: the `dumpbin` audit of the GUI job in
[windows7.yml](../.github/workflows/windows7.yml) passed on PR #68 (merged as
`0e30bf7`) and on `f4661ea` (PR #69).

Not executed: anything on Windows 7.

The `i686-win7-windows-msvc` `gateinto-gui.exe` has 247 static imports from 13
DLLs: `advapi32`, `bcrypt`, `comctl32`, `d2d1`, `dwrite`, `gdi32`, `kernel32`,
`ncrypt`, `ntdll`, `oleaut32`, `secur32`, `shell32` and `user32`. There are no
delay-load imports, no ordinal imports, no API-set DLLs (`api-ms-win-*`), and
no static import from `shcore.dll`, `dwmapi.dll` or `uxtheme.dll`. 157 of the
imports are already in `win7-imports.txt`; the other 90 are in
[win7-gui-imports.txt](../.github/scripts/win7-gui-imports.txt), which the GUI
job checks in addition to `win7-imports.txt`. Each of those 90 has a minimum
supported client of Windows 7 or earlier according to its Microsoft
documentation; none was found missing from Windows 7. The string scan found no
`ProcessPrng`, and the same std names as in `gateinto.exe`
(`api-ms-win-core-synch-l1-2-0`, `GetSystemTimePreciseAsFileTime`,
`SetThreadDescription`, `WaitOnAddress`, `WakeByAddressSingle`) plus
`Tbsi_GetDeviceInfo` from the `gateinto` library.

The regular `x86_64-pc-windows-msvc` and `i686-pc-windows-msvc` GUI builds also
import `bcryptprimitives.dll!ProcessPrng`,
`api-ms-win-core-synch-l1-2-0.dll!WaitOnAddress`, `WakeByAddressSingle`,
`WakeByAddressAll` and `kernel32.dll!GetSystemTimePreciseAsFileTime` (Windows 8
or later) through Rust std, so, like the regular `gateinto.exe`, they cannot
load on Windows 7. Only the win7 target replaces those. Compared with the two
allow-lists, the i686 import table differs in exactly those five imports, which
shows that the allow-lists would reject them.

Static imports added by the GUI, by DLL. "Windows 7 SP1" is the documented
minimum supported client, not a runtime observation:

| DLL | Functions | Minimum client | Windows 7 SP1 |
| --- | --- | --- | --- |
| `d2d1.dll` | `D2D1CreateFactory` | Windows 7, or Vista SP2 with the Platform Update | present |
| `dwrite.dll` | `DWriteCreateFactory` | Windows 7, or Vista SP2 with the Platform Update | present |
| `user32.dll` | 63 window, message, menu, clipboard, cursor, monitor and timer functions, such as `CreateWindowExW`, `GetMonitorInfoW`, `TrackMouseEvent`, `SetProcessDPIAware` (Vista) and `ChangeWindowMessageFilterEx` (Windows 7) | Windows 7 or earlier | present |
| `gdi32.dll` | `CreateBitmap`, `CreateDIBSection`, `DeleteObject`, `GetDeviceCaps` | Windows 2000 | present |
| `shell32.dll` | `ShellExecuteW`, `Shell_NotifyIconW` | Windows XP or earlier | present |
| `comctl32.dll` | `InitCommonControlsEx` | Windows XP or earlier | present |
| `oleaut32.dll` | `GetErrorInfo` (from the `windows` crate's error handling) | Windows 2000 | present |
| `secur32.dll` | `GetUserNameExW` | Windows 2000 | present |
| `advapi32.dll` | `RegDeleteKeyValueW`, `RegSetKeyValueW` | Windows Vista | present |
| `kernel32.dll` | `GetTickCount64`, `GetUserPreferredUILanguages`, `QueryFullProcessImageNameW` (Vista); `CreateMutexW`, `GetComputerNameExW`, `GetLocalTime`, `GetNativeSystemInfo`, `GetSystemTime`, `GetUserDefaultUILanguage`, `GlobalAlloc`, `GlobalFree`, `GlobalLock`, `GlobalSize`, `GlobalUnlock` (XP or earlier) | Windows Vista or earlier | present |

Functions newer than Windows 7 that the GUI uses, all looked up at runtime by
`gui/src/win/sys.rs` with `GetModuleHandleW` or
`LoadLibraryExW(LOAD_LIBRARY_SEARCH_SYSTEM32)` and `GetProcAddress`, none in the
import table:

| DLL | Function | Minimum client | Fallback when missing |
| --- | --- | --- | --- |
| `user32.dll` | `SetProcessDpiAwarenessContext` | Windows 10 1703 | `SetProcessDPIAware` (static, Vista) |
| `user32.dll` | `GetDpiForWindow` | Windows 10 1607 | `GetDeviceCaps(LOGPIXELSY)` of the window's DC |
| `user32.dll` | `GetSystemMetricsForDpi` | Windows 10 1607 | `GetSystemMetrics` |
| `user32.dll` | `AdjustWindowRectExForDpi` | Windows 10 1607 | `AdjustWindowRectEx` |
| `shcore.dll` | `GetDpiForMonitor` | Windows 8.1 | the window DPI path above for the whole screen |
| `uxtheme.dll` | ordinals 135 and 136 (`SetPreferredAppMode`, `FlushMenuThemes`) | Windows 10 1903 (undocumented) | not called: `theme::menu_mode` requires build 18362 |
| `dwmapi.dll` | `DwmSetWindowAttribute` with `DWMWA_USE_IMMERSIVE_DARK_MODE` (19 or 20) | function Vista; attribute Windows 10 1809 | not called: `theme::immersive_attribute` returns `None` below build 17763 |
| `dwmapi.dll` | `DwmSetWindowAttribute` with `DWMWA_WINDOW_CORNER_PREFERENCE` (33) | attribute Windows 11 | called for the tray flyout on every version; the result is ignored |
| `uxtheme.dll` | `SetWindowTheme` with `DarkMode_Explorer` | function XP; theme Windows 10 1809 | not called: `theme::dark_controls` requires build 17763 |

Other runtime lookups exist on Windows 7: `dwmapi.dll!DwmIsCompositionEnabled`
(Vista) and `ntdll.dll!RtlGetVersion` (2000). `sys::os_build` reports build 0
below Windows 10, and `Frame::choose` keeps the system window frame below
Windows 10; unit tests in `gui/src/theme.rs` (build 7601 gets no dark title bar
attribute) and `gui/src/frame.rs` (major version 6 gets the system frame) cover
those decisions, not the Windows calls. On Windows 7 without KB2533623
(superseded by KB3063858), `LOAD_LIBRARY_SEARCH_SYSTEM32` makes `LoadLibraryExW`
fail, so `dwmapi.dll` and `uxtheme.dll` lookups would fail unless the DLL is
already loaded, and `DwmIsCompositionEnabled` would then report no composition;
`shcore.dll` does not exist on Windows 7 either way.

Direct2D and DirectWrite are used only through their 1.0 interfaces, which ship
with Windows 7 SP1 without the Platform Update (KB2670838): `ID2D1Factory`,
`ID2D1DCRenderTarget`, `ID2D1PathGeometry`, `ID2D1SolidColorBrush`,
`ID2D1StrokeStyle`, `IDWriteFactory`, `IDWriteFontCollection` (the system
font collection), `IDWriteTextFormat`, `IDWriteInlineObject` (the ellipsis
trimming sign), `IDWriteTextLayout` and `IDWriteRenderingParams`.
`IDWriteFactory2`, `IDWriteFontFallbackBuilder`, `IDWriteFontFallback` and
`IDWriteTextFormat1` (Windows 8.1) serve only to add a CJK font fallback: the
builder and the fallback are reached only through `IDWriteFactory2`, which is
obtained with `QueryInterface`, and the fallback is applied through
`IDWriteTextFormat1`, also obtained with `QueryInterface`. When either cast
fails, the fallback is skipped and the text formats are created without it. These COM paths are not visible in an import
table, and none of them has been run on Windows 7.

Not checked: the manifest's `dpiAwareness` and `dpiAware` (`true/pm`) settings
on Windows 7, the tray icon and its menu, font rendering of the fallback path,
and whether the hard-coded Windows 10 UI looks acceptable on Windows 7.

## Dependency findings

Versions are those in `Cargo.lock`. Only crates that reach the Windows binary
are listed, plus `getrandom`.

| Crate | Version | Windows API concern | Win7 status | Evidence |
| --- | --- | --- | --- | --- |
| Rust std (`x86_64-win7-windows-msvc`) | `nightly-2026-09-15` | Tier 3: no upstream tests, needs nightly `-Z build-std`. The target replaces `ProcessPrng` with `RtlGenRandom`, `GetSystemTimePreciseAsFileTime` with `GetSystemTimeAsFileTime`, loads `WaitOnAddress` optionally with an NT keyed-event fallback, and uses SRW locks for `Mutex`, `RwLock` and `Condvar`. `SetThreadDescription` is also looked up at runtime. The CI string scan found exactly these optional names (`WaitOnAddress`, `WakeByAddressSingle` via `api-ms-win-core-synch-l1-2-0`, `GetSystemTimePreciseAsFileTime`, `SetThreadDescription`) and none in the import table. | risk (Tier 3, builds; fallbacks not run on Windows 7) | `library/std/src/sys/random/windows.rs`, `sys/pal/windows/c.rs`, `sys/pal/windows/compat.rs`, `sys/sync/{mutex,condvar,rwlock,thread_parking}/mod.rs` |
| MSVC CRT | runner toolset | The first recorded run linked `vcruntime140.dll` and the UCRT (`api-ms-win-crt-*`) dynamically. `.cargo/config.toml` now sets `+crt-static` for every MSVC target, and run 39056727677 imports neither for `x86_64-win7-windows-msvc`, so the UCRT update is no longer needed. The i686 win7 build has not run yet. | ok for x64 by build evidence | CI `imports.txt` of run 38962289234 and the import table of run 39056727677; [compatibility.md](compatibility.md#static-c-runtime) |
| `tokio` / `mio` | 1.54.1 / 1.2.4 | IOCP plus AFD polling: `NtCreateFile` on `\Device\Afd\Mio`, `NtDeviceIoControlFile` (`IOCTL_AFD_POLL`), `NtCancelIoFileEx`, `GetQueuedCompletionStatusEx`, `SetFileCompletionNotificationModes`, all Vista or later. `WSASocketW` is called with `WSA_FLAG_NO_HANDLE_INHERIT` and no fallback, a flag supported from Windows 7 SP1. | ok on SP1 | `mio-1.2.4/src/sys/windows/afd.rs`, `iocp.rs`, `net.rs:36` |
| `socket2` | 0.6.5 | `WSA_FLAG_NO_HANDLE_INHERIT`, as above. | ok on SP1 | `socket2-0.6.5/src/sys/windows.rs` |
| `aws-lc-sys` (AWS-LC) | 0.46.0 | Entropy: by default `LoadLibraryW("bcryptprimitives")` plus `GetProcAddress("ProcessPrng")`, which calls `abort()` on Windows 7 and does not show in the import table. With `_WIN32_WINNT <= 0x0601` it uses `BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)` from `bcrypt.dll` instead. The `cc` builder defines `_WIN32_WINNT=0x0601` for `-win7-windows-` targets; the CMake builder does so only for `-win7-windows-gnu`. Threads use `InitOnceExecuteOnce` and SRW locks (Windows 7 or later). CI build: `bcrypt.dll` imported and no `ProcessPrng` string in the binary, consistent with the `BCryptGenRandom` path. | ok by build evidence (not run on Windows 7) | `aws-lc/crypto/rand_extra/windows.c`, `builder/cc_builder.rs:445`, `builder/cmake_builder.rs:450`, `builder/main.rs` (`get_builder`, `is_bindgen_required`), `aws-lc/crypto/thread_win.c` |
| `aws-lc-rs` | 1.18.2 | No Windows API of its own. The win7 target is not among the pre-generated binding targets, so the universal bindings are used; not a documented platform. | risk | `aws-lc-sys-0.46.0/builder/main.rs` (`supported_platform`), no `win7` in `aws-lc-rs-1.18.2` |
| `rustls`, `rustls-webpki`, `tokio-rustls`, `webpki-roots` | 0.23.46, 0.103.16, 0.26.6, 1.0.10 | No OS API; TLS does not use SChannel, so no Windows TLS updates are needed. | ok | Source has no Windows FFI |
| `rustls-cng` | 0.7.1 | `NCryptSignHash`, `NCryptGetProperty`, `NCryptSetProperty`, `NCryptFreeObject`, `Cert*`: Vista or later. `CngSigningKey` hashes with `BCryptHash` and the `BCRYPT_SHA*_ALG_HANDLE` pseudo-handles, which need Windows 10, and was imported statically until Gateinto stopped using it. Unreferenced functions such as `CryptAcquireCertificatePrivateKey` do not reach the import table. | ok now that `CngSigningKey` is unused | `rustls-cng-0.7.1/src/signer.rs`; import table of run 39056727677 |
| `windows-sys`, `windows-link` | 0.61.2, 0.2.1 | `raw-dylib` imports by DLL name. Every function used by the crates above maps to `kernel32`, `ntdll`, `ws2_32`, `ncrypt`, `crypt32` or `bcrypt`, not to API-set DLLs. | ok | `windows-link-0.2.1/src/lib.rs`, `link!` lines in `windows-sys-0.61.2/src` |
| `gateinto` CNG key code | 0.1.0 | Software KSP (`Microsoft Software Key Storage Provider`) and `NCryptCreatePersistedKey` and related functions exist on Windows 7. The TPM key backend needs the `Microsoft Platform Crypto Provider`, which first shipped with Windows 8. Opening it on Windows 7 is expected to fail with a "provider unavailable" status (`NTE_BAD_PROVIDER`, `NTE_PROV_DLL_NOT_FOUND`, `NTE_NOT_FOUND` and similar), which makes `key init` fall back to the Software KSP. An unrecognised status would stop `key init` with an error instead. `Tbsi_GetDeviceInfo` (Windows 8) is resolved at runtime. | risk (TPM not available; provider status on Windows 7 not observed) | `src/identity/windows_cng.rs`, `src/identity/cng_status.rs` |
| `anstyle-query`, `anstyle-wincon` (clap) | 1.1.5, 3.0.11 | `ENABLE_VIRTUAL_TERMINAL_PROCESSING` is rejected on Windows 7; the failure is handled and only disables colors. | ok | `anstyle-query-1.1.5/src/windows.rs` |
| `getrandom` | 0.4.3, 0.2.17 | 0.4.3 is only a build-script dependency on the host (`jobserver` from `cc` from `aws-lc-sys`); 0.2.17 is in `Cargo.lock` but in no build graph. Neither reaches the binary. 0.4.3 would pick `windows_legacy` (`RtlGenRandom`) on win7. | ok | `cargo tree --target all -e all -i getrandom@…`, `getrandom-0.4.3/src/backends.rs:161` |

Gateinto passes `LOAD_LIBRARY_SEARCH_SYSTEM32` to `LoadLibraryExW` when it
loads `tbs.dll`. On Windows 7 without KB2533623 (superseded by KB3063858), that
flag makes the call fail with `ERROR_INVALID_PARAMETER`. The probe then reports
the device info as unavailable, which is the right answer on Windows 7 anyway,
so the update is not required.

## Conclusion

`partial`

`gateinto.exe` built and linked for `x86_64-win7-windows-msvc` in CI before that
build was dropped; CI now builds only `i686-win7-windows-msvc`. The builds
recorded so far imported `Tbsi_GetDeviceInfo` and `BCryptHash`, so they would not
have loaded on Windows 7. Both imports are removed now, and the allow-list audit
fails if another import that Windows 7 lacks appears. In run 39074036884 the
fixed x64 build passed that audit. The `i686-win7-windows-msvc` build succeeded
and failed only on three Windows 7-safe imports, which are now on the list.
Nothing has been run on Windows 7 SP1, the targets are Tier 3, and the TPM key storage provider
does not exist on Windows 7, so only software keys can work there.

`gateinto-gui.exe` for `i686-win7-windows-msvc` built locally with `cargo xwin`
and its import table contains only functions documented as present on Windows
7 SP1 (see [GUI static import audit](#gui-static-import-audit)). That is a
static import audit only: the GUI has not been run on Windows 7, and it is not
part of any Windows 7 release.

## Alternatives if blocked

- If a later build finds `ProcessPrng`: force the `cc` builder
  (`AWS_LC_SYS_CMAKE_BUILDER=0`) or pass `_WIN32_WINNT=0x0601` through
  `CFLAGS_x86_64_win7_windows_msvc`, then confirm with the binary string scan.
- If AWS-LC does not build: the `ring` provider in `rustls` keeps TLS 1.3,
  certificate verification and `X25519`, and `ring` 0.17 gets entropy from
  `getrandom` 0.2 (`BCryptGenRandom` with an `RtlGenRandom` fallback). It has no
  `X25519MLKEM768`, so it drops the post-quantum hybrid group. Taking that
  trade-off is a policy decision, not part of this study.
- If the UCRT is the problem: `.cargo/config.toml` already links the CRT
  statically with `-C target-feature=+crt-static`; confirm that the import
  table no longer lists `VCRUNTIME140.dll` or `api-ms-win-crt-*`.

To reach `working`:

1. A Windows 7 SP1 machine or VM with all updates, 32-bit preferred; an x64
   machine would run the 32-bit build under WOW64, which is also unverified.
2. Copy `gateinto.exe` from the `gateinto-i686-win7-windows-msvc` artifact of a passing
   [windows7.yml](../.github/workflows/windows7.yml) run made after the fixes
   above. Older artifacts import `Tbsi_GetDeviceInfo` and do not load. Check
   that it starts: `gateinto --help`.
3. Run `gateinto session browser --upstream-host <host> --upstream-port <port>`
   against a controlled upstream proxy. It prints its `listen` address and
   shows its session credentials at start; send
   `curl --proxy http://127.0.0.1:<listen-port> --proxy-user gateinto:<password> https://example.com/`
   through it with that password. The
   TLS 1.3 handshake to the upstream proxy exercises AWS-LC's `BCryptGenRandom`
   entropy path at runtime. Confirm in the upstream proxy's TLS log that
   `X25519MLKEM768` was negotiated.
4. Run `gateinto setup` (or `gateinto key init`) without `--backend`, and
   confirm that it creates a software KSP key with a "the TPM provider is
   unavailable" warning instead of an error. Then run `gateinto key info` and
   confirm the key is reused.
5. Record the results here and replace the label above.
