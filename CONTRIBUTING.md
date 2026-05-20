# Contributing to The Relic

Thanks for your interest in contributing. The Relic is the open-source
mediation layer for AI agents — the part that runs on your machine and
governs every tool call. It is Apache-2.0–licensed and built to be hackable.

This document covers how to file issues, propose changes, and get a patch
merged in this repository. The control plane (`therelic-platform`) and
dashboard (`therelic-app`) live in separate repositories under the
**Apache License 2.0**; they accept contributions under the same
contribution terms there are different (BSL releases convert to Apache 2.0
after four years; contributing to a BSL repo means your contribution is
BSL until the Change Date for the file it lands in). See those repos'
CONTRIBUTING files for specifics.

---

## Ground rules

- **Be specific.** Bugs need a reproduction, proposals need a concrete use case.
- **Discuss large changes first.** Open an issue before writing >200 lines.
- **One concern per PR.** Easier to review, easier to revert.
- **Tests required for behavior changes.** Bug fixes need a regression test.
- **No new dependencies without justification.** This is a security tool; every
  import is a supply-chain commitment.

---

## Reporting bugs

Open a [GitHub issue](https://github.com/therelicai/therelic/issues) with:

1. Version (`relic --version`) and platform (OS, arch).
2. Minimal reproduction — the smallest policy + invocation that triggers it.
3. Expected vs actual behavior. Trace excerpts (with secrets redacted) help.
4. Any relevant lines from the trace file (`.tr/traces/*.trtrace`).

If the bug has security implications, **do not file a public issue** — see
[SECURITY.md](SECURITY.md).

---

## Proposing changes

Open an issue first if the change touches:

- The policy schema (new fields, new constraint types)
- The trace event format
- The mediation engine's evaluation order
- The CLI's surface area (new commands, new flags)
- Any of the cryptographic primitives (signing, integrity chain, identity)

Smaller fixes — bugs, doc improvements, additional test cases, glob edge cases,
new example policies — can go straight to a PR.

---

## Development setup

```bash
git clone https://github.com/therelicai/therelic
cd therelic
go build ./cmd/relic
go test ./...
```

Required: Go 1.23+. No other dependencies for the core build.

For the OpenClaw integration tests:

```bash
go test ./test/integration/...
```

---

## Code conventions

- **Format with `gofmt -s`.** CI rejects unformatted code.
- **Lint with `golangci-lint run`.** Configuration in `.golangci.yml`.
- **Vulnerability scan with `govulncheck ./...`.** Run before opening a PR.
- **Names match the architecture doc.** If you rename a concept in code,
  update [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) in the same PR.
- **Errors wrap with `%w` and include the operation name.** Example:
  `fmt.Errorf("policy parse: %w", err)`.
- **No comments that restate the code.** Comment the *why*, not the *what*.

---

## Test requirements

| Change type | Required tests |
|---|---|
| Bug fix | Regression test that fails without the fix |
| New policy field | Parser test, validator test, evaluator test |
| New CLI command | End-to-end test in `internal/cli/*_test.go` |
| New trace event | Writer test, reader test |
| Crypto primitive | Round-trip test, tampered-input test, fuzz target |
| Glob pattern change | Add cases to `policy/engine_test.go` table |

Fuzz targets live in `*_fuzz_test.go` and run on CI. New parsers should add
a fuzz target.

---

## Pull request checklist

- [ ] `go test ./...` passes
- [ ] `golangci-lint run` clean
- [ ] `govulncheck ./...` clean
- [ ] New behavior covered by tests
- [ ] Architecture doc updated if the surface changed
- [ ] Changelog entry in PR description (we curate `CHANGELOG.md` at release time)
- [ ] No secrets, internal hostnames, or customer data in fixtures or traces

---

## Scope: what belongs here vs the platform

The split is by concern *and* by license:

| Belongs in this repo (Apache 2.0) | Belongs in `therelic-platform` (Apache 2.0) | Belongs in `therelic-app` (Apache 2.0) |
|---|---|---|
| Mediation engine, policy engine, trace writer | Trace storage, S3, Postgres | Web dashboard, trace viewer UI |
| MCP proxy, HTTP logger | Org/user management, API keys | Proposals UI, policy editor |
| Local identity manifest, policy signing | Governance worker, LLM classifier | Audit log views, marketplace UI |
| Filesystem sandbox, network policy | Policy proposal data model | Onboarding flow |
| Trust-network protocol and transport binding | Capability registry, trust scoring | Settings, billing UI |
| OpenClaw skill (distribution + UX) | Notification dispatch, billing | Real-time trace tail (planned) |

The substrate (this repo) is what the agent process actually runs against
— it must be true OSS to clear procurement gates and distro packaging.
The platform stores and analyzes traces; the app visualizes them — both
get BSL because the hosted-service moat needs protection. If you're not
sure where a contribution belongs, open an issue and we'll route it.

---

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE) that covers this repository (inbound=outbound,
per Apache 2.0 §5). We do not require a separate CLA.
