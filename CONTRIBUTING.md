# Contributing

Thank you for helping. Gateinto is an early proof of concept, so please open an
issue to discuss larger changes before writing code. Report vulnerabilities as
described in [SECURITY.md](SECURITY.md), not in public issues.

## Rules

- Write code, comments, documentation, commit messages and reviews in English.
- Add a comment only when the reasoning cannot be derived from the code.
- Use test-driven development: write a failing test first, make it pass with
  minimal code, then refactor.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
  in English, for example `fix: map upstream 407 to 502`. Do not reference plan
  sections, milestones or task numbers.
- The author and the reviewer of a change are different people (or agents).
  Every pull request needs a review by someone who did not write it.

## Quality gates

CI runs these on `ubuntu-latest` and `windows-latest`. Run them before opening a
pull request:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
```

If a change needs a new `Cargo.lock`, run the commands once without `--locked`,
then confirm with `--locked` and commit the lock file.

Windows-only code (`cfg(windows)`) is not compiled on Linux or macOS. To
type-check it from Linux, follow the recipe in
[docs/compatibility.md](docs/compatibility.md#windows-type-check-from-linux).
It does not link or run anything, so say so in the pull request if that is all
you could do.

## Tests

- Tests must not use public proxies or any other service on the internet. Use
  the in-process TLS upstream fixture in `tests/fixture/` on loopback.
- For manual checks, `cargo run --example test_upstream -- --port 18443
  --ca-out upstream-ca.pem` runs that fixture as a standalone HTTPS `CONNECT`
  upstream on loopback with a throwaway test CA (server name `localhost`,
  change it with `--name`). Point a `[gateways.<name>]` table at `127.0.0.1:18443` with
  `server_name = "localhost"` and `ca_file = "upstream-ca.pem"`. It is for
  development only and is not shipped; the `quickstart` CI job uses it.
- Tests must not disable TLS certificate verification. Issue test certificates
  from a test CA with `rcgen` and trust that CA instead.
- Tests that create Windows CNG keys must delete them, for example with a drop
  guard.
- Fuzz targets live in `fuzz/`, a separate workspace with its own
  `Cargo.lock`. With a nightly toolchain and `cargo install cargo-fuzz
  --version 0.13.2 --locked`, run `cargo +nightly fuzz list` and
  `cargo +nightly fuzz run <target> -- -max_total_time=60`. libFuzzer adds
  new inputs to `fuzz/corpus/<target>/`; commit only small seeds, and turn a
  crash into a unit test before fixing it. The entry points in
  `gateinto::proxy::fuzzing` exist only with `--cfg fuzzing`, which cargo-fuzz
  sets; to lint the fuzz workspace directly, run
  `RUSTFLAGS="--cfg fuzzing" cargo clippy --all-targets --locked` in `fuzz/`.

## Releases

`.github/workflows/release.yml` maintains three rolling GitHub releases,
`alpha`, `beta` and `latest`, described in
[docs/install.md](docs/install.md#releases). `alpha` is replaced after the
`CI` workflow succeeds on a push to `master`. To replace `beta` or `latest`,
run the workflow by hand (Actions, Release, Run workflow) with the channel and
a branch, tag or full commit SHA; the commit must contain this workflow's
`.github/actions` and `.github/scripts`. Runs for the same channel queue
instead of overlapping; a newer queued run replaces an older queued one.

Each run tests and builds `gateinto.exe` for `x86_64-pc-windows-msvc` and
`i686-pc-windows-msvc`, builds the x64 MSI, and for `alpha` and `beta` also
the experimental Windows 7 executables with the steps of the Windows 7
workflow. The publish job then checks the file set with
`.github/scripts/release-assets.sh`, writes the notes with
`.github/scripts/release-notes.sh`, deletes the release and its tag, and
creates them again at the built commit. Only that job has `contents: write`.
`.github/scripts/release-test.sh` tests both scripts in CI.

Not done yet: an SBOM, code signing of `gateinto.exe`, and build provenance
attestations.

## License

Gateinto is licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT license](LICENSE-MIT) at your option (`MIT OR Apache-2.0`).

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
