# Security policy

## Supported versions

Gateinto is a pre-release proof of concept. There are no releases with
security support yet. Only the latest commit on `master` is considered, and
fixes are made there.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub. On this repository, open the
**Security** tab and choose **Report a vulnerability**. This creates a private
security advisory that only the maintainers can see. See GitHub's
[documentation on privately reporting a security vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).

Do not open a public issue, pull request or discussion for a vulnerability. If
private reporting is not available on the repository, open a public issue that
only asks for a private contact and contains no details.

Please include:

- the affected commit,
- the platform (Windows version, TPM or software key storage if relevant),
- steps to reproduce, ideally against a local test upstream proxy,
- the impact you expect.

There is no bug bounty and no guaranteed response time.

## Scope

In scope is the code in this repository:

- the local `CONNECT` listener, request parser and limits,
- the TLS client to the upstream proxy, certificate verification and key
  exchange configuration,
- device key handling through Windows CNG,
- logging, if it leaks secrets or tunnel payload,
- the CI and release workflows in `.github/workflows/`.

The intended security properties are described in
[docs/threat-model.md](docs/threat-model.md).

## Out of scope

- Public or open proxies, and anyone using Gateinto with one.
- Third-party gateways and upstream HTTPS proxies, including their
  configuration and their access control. Report those to their vendors.
- Vulnerabilities in dependencies that do not affect Gateinto as configured.
  Report those upstream; a note to us is welcome if Gateinto needs to update.
- Attacks that require administrator rights or code already running as the
  user on the machine, which the threat model lists as residual risks.
- Use of the loopback listener by other local processes, which is documented
  behavior.
- Running with `--unsafe-allow-non-loopback-listen`.
