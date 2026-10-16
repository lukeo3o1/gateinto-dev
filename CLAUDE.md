# Gateinto Agent Guidelines

Gateinto is an independent open source Rust local HTTP CONNECT proxy agent. It relays local client traffic through a TLS 1.3 connection to a remote HTTPS forward proxy, using Windows CNG device keys (TPM preferred, software fallback) for mTLS and preferring the hybrid `X25519MLKEM768` key exchange.

These rules apply to every agent and contributor working in this repository.

## 1. Language

- Everything committed to the repository is written in English: source code, identifiers, tests, documentation, configuration, commit messages, branch names, and pull request text.

## 2. Code Comments

- Do not write code comments by default. Express intent through names, types, and small functions.
- Write a comment only when the reasoning cannot be derived from the code itself, such as an external constraint, a protocol or platform quirk, a security invariant, or a non-obvious workaround. Such a comment explains why, never what.
- Do not leave commented-out code, TODO notes without context, or comments that restate the code.
- Public API documentation (`///`) is allowed where it documents a contract callers cannot infer from the signature.

## 3. Test-Driven Development

All behavior changes follow red, green, refactor:

1. Red: write a failing test that captures the required behavior. Run it and confirm it fails for the expected reason.
2. Green: write the minimum production code that makes the test pass.
3. Refactor: clean up code and tests while keeping the suite green.

Additional rules:

- No production code without a test that required it. Bug fixes start with a test that reproduces the bug.
- Tests must be deterministic and must not depend on public network services or unknown third-party proxies. Use local fixtures.
- Never weaken, skip, or delete a test to make the suite pass.
- Tests that require real hardware (TPM) or a specific OS are clearly gated and documented with manual verification steps.

## 4. Separate Development and Review Agents

Development and review are performed by two different agents. An agent never approves its own work.

- `developer` (`.claude/agents/developer.md`) implements changes using TDD.
- `reviewer` (`.claude/agents/reviewer.md`) reviews the resulting diff independently and does not modify code.

Workflow:

1. The developer agent implements the change and runs all local checks.
2. A separate reviewer agent, started with fresh context, reviews the diff against these guidelines.
3. The developer agent addresses every blocking finding, and the change goes back to review.
4. A change is committed only after the reviewer reports no blocking findings.

## 5. Commit Messages

- Follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/): `<type>(<optional scope>): <description>`.
- Allowed types: `feat`, `fix`, `test`, `refactor`, `perf`, `docs`, `build`, `ci`, `chore`, `style`, `revert`.
- Write in English, imperative mood, lowercase description, no trailing period, subject line at most 72 characters.
- Use the body to explain why when it is not obvious. Mark breaking changes with `!` or a `BREAKING CHANGE:` footer.
- Do not reference plan sections, milestones, task numbers, issue numbers, or work item identifiers in commit messages.

Examples:

```text
feat(proxy): reject non-connect methods with 405
test(upstream): cover 407 response from upstream proxy
fix(tls): fail closed when hybrid group is required but not negotiated
```

## 6. Quality Gates

Before requesting review, the following must pass:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

## 7. Security Ground Rules

- Never disable or weaken TLS certificate or hostname verification, including in tests.
- Never write private keys to disk in plaintext or log secrets.
- Never silently replace an existing device key with a new one.
- Bind to loopback only by default.
- Never claim a feature works (TPM, mTLS, hybrid PQC, Windows 7) without reproducible verification evidence.

## 8. Scope Discipline

- Implement only the client agent. Do not build gateway, edge, IAM, connector, browser extension, PAC, SOCKS, HTTP/2 CONNECT, or QUIC functionality.
- Keep the module structure minimal. Do not introduce speculative abstractions, plugin systems, or extra crates without a concrete need.
