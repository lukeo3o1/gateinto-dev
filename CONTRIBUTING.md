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

## Releases

`.github/workflows/release.yml` runs on `v*` tags and on manual dispatch. On
`windows-latest` it runs the test suite, builds `gateinto.exe` for
`x86_64-pc-windows-msvc` and uploads a zip with the binary, the licenses,
`README.md` and `SECURITY.md`, plus a SHA-256 checksum file, as a workflow
artifact. For tag pushes it also creates a draft GitHub release with these
files. A maintainer reviews and publishes the draft.

The files are `gateinto-<version>-x86_64-pc-windows-msvc.zip` and
`gateinto-<version>-x86_64-pc-windows-msvc.zip.sha256`, where `<version>` is
the tag, or the first 12 characters of the commit for a manual run. The only
release target is Windows 10/11 x64; Windows 7 is not a release target (see
[docs/windows7-feasibility.md](docs/windows7-feasibility.md)). The workflow has
run once via manual dispatch on a branch and produced the zip artifact; no
release has been created and no tag has been pushed.

Not done yet: an SBOM, code signing of `gateinto.exe`, and build provenance
attestations.

## License

Gateinto is licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT license](LICENSE-MIT) at your option (`MIT OR Apache-2.0`).

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
