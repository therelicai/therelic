# Licensing

All code in this repository is licensed under the [Apache License,
Version 2.0](./LICENSE).

This includes:

- `cmd/relic/` — CLI binary
- `internal/` — core runtime (policy engine, proxy, trace writer, redaction,
  identity, signing, sandbox, delegation, mediation, fingerprinting)
- `dist/` — skill definitions and homebrew formula
- `docs/` — architecture and user documentation
- `examples/` — sample policy files
- `test/` — integration and unit tests

You are free to use, modify, and distribute the runtime in any project —
commercial or otherwise — subject to the Apache 2.0 terms (notably:
preserve copyright, the LICENSE, the NOTICE, and any third-party
attribution; carry forward modification notices in derivative works).

## The Relic stack uses two licenses

| Repo | License | Notes |
|---|---|---|
| `therelic` (this repo) — mediation layer, CLI, policy engine | **Apache 2.0** | Maximum adoption: OSI-approved, distro-packageable, no CLA. |
| `therelic-website` — marketing site | **Apache 2.0** | Same posture as the runtime. |
| `therelic-platform` — control plane API and governance worker | **BSL 1.1** | Source-available. Self-host for any purpose; no offering of a competing hosted Governance Service. Each release converts to Apache 2.0 four years after publication. |
| `therelic-app` — web dashboard | **BSL 1.1** | Same Additional Use Grant and Change Date as the platform. |

The hosted service operated at `therelic.dev` is a separate commercial
offering by The Relic AI, Inc. Self-hosting the platform and app under
the BSL Additional Use Grant is explicitly encouraged.

## Trademarks

Neither Apache 2.0 nor BSL 1.1 grants rights in the marks "The Relic",
the Relic shield logo, or related product names. See
[TRADEMARKS.md](./TRADEMARKS.md) for the trademark policy — what's
permitted descriptive use, what requires permission, and how to name a
fork.

## Contributions

By submitting a contribution to this repository you agree it is licensed
under Apache 2.0 under the inbound=outbound convention (Apache License
2.0 §5). We do not require a CLA for this repository.

The platform and app repositories are BSL-licensed; contributing there
means your contribution is BSL until the per-file Change Date converts
it to Apache 2.0. See those repos' CONTRIBUTING files for specifics.
