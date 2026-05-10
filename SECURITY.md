# Security Policy

The Relic is a security tool. We take vulnerabilities in the mediation layer,
policy engine, sandbox, and cryptographic primitives seriously, and we
appreciate disclosures from the security community.

---

## Reporting a vulnerability

**Do not open a public GitHub issue for security bugs.**

Email **security@therelic.dev** with:

1. A description of the issue and its impact.
2. A reproduction — minimal policy, invocation, and observed behavior.
3. The version of `relic` (output of `relic --version`).
4. Whether the issue is already public anywhere (CVE, blog, social).

You will receive an acknowledgement within **2 business days**. If you have
not heard back in that window, retry through GitHub Security Advisories
(private mode) on the [therelicai/therelic](https://github.com/therelicai/therelic/security/advisories)
repository.

For PGP-encrypted reports, request our key via the same address.

---

## Scope

In scope (please report):

- Bypasses of the policy engine — actions that should have been denied but
  reached the upstream tool.
- Bypasses of the filesystem sandbox — agent processes reading or writing
  outside of declared mounts.
- Bypasses of the network policy — outbound traffic to denied hostnames.
- Trace integrity issues — tampering, insertion, or deletion that does not
  break the HMAC chain.
- Policy signature verification flaws — accepting an invalid signature, or
  rejecting a valid one.
- Identity manifest forgery — running under a manifest the runtime should
  have rejected.
- Environment-hardening bypasses — agent processes inheriting variables we
  claim to strip (proxy overrides, `LD_PRELOAD`, `RELIC_*` spoofing, etc.).
- Redaction failures — sensitive values reaching disk despite a redaction
  rule that should have caught them.
- Memory-unsafety, panics from untrusted input, or DoS in the proxy.

Out of scope:

- Vulnerabilities in dependencies that we re-export through the trace file
  format — report those upstream and we'll bump the dependency.
- Issues in agents, MCP servers, or LLMs that The Relic mediates. Those are
  what The Relic exists to *contain*; please file feature requests for new
  policy primitives instead.
- Issues in the hosted control plane (`api.therelic.dev`) or dashboard
  (`app.therelic.dev`). Those repositories have their own SECURITY.md.
- Social engineering, physical access, denial of service via local resource
  exhaustion (CPU/disk/file handles).

---

## Disclosure timeline

1. **Day 0:** report received.
2. **Day 0–2:** acknowledgement.
3. **Day 0–14:** triage and reproduction; severity assigned.
4. **Day 0–90:** fix developed, reviewed, and released.
5. **Release + 7 days:** public advisory and CVE published. We coordinate
   credit with the reporter.

We can extend the 90-day window if a fix is structurally complex; we will
not extend it silently. If you need to disclose earlier (regulatory
obligation, ongoing exploitation), email and we will coordinate.

---

## Hardening assumptions

The Relic assumes the following are *outside* its threat model. Reports
that hinge on these are still welcome but will likely be classified as
"won't fix in the runtime; mitigate at the host layer":

- The host operating system is trusted. A privileged process on the host
  can read trace files, the identity key, and policy signing keys.
- The Go runtime and the standard library are trusted.
- The signer of a policy file is trusted to sign accurate policy.
- A user who can edit `.tr/policy.yaml` and re-sign it has the same
  authority as the policy author.

The Relic *does* defend against:

- Untrusted agent code: the mediated process is assumed hostile.
- Untrusted MCP servers: tool calls and parameters are policy-checked
  before forwarding; server binaries can be SHA-256 pinned.
- Untrusted upstream HTTP services: outbound network policy applies.
- Trace tampering after a run completes (HMAC chain).
- Policy tampering between sign and load (Ed25519 verification).

---

## Acknowledgements

Researchers who report valid issues receive credit in the release notes
and the public advisory unless they request anonymity.
