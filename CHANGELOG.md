# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-10-20

Distribution, benchmarks and docs. This is the first release whose published
numbers are checked in CI.

### Added
- Multi stage container image running as uid 10001, a system user with no home directory and no shell, published to ghcr.io on a tag through OIDC with no stored registry credential. Build provenance is attested.
- `ibr serve`, a read only query service answering blast radius and path questions over a loaded account, with health, summary, blast radius and paths endpoints.
- `ibr gate`, exiting non zero above a one hop escalation count or a mislabelled percentage.
- Benchmark harness across 200, 2,000 and 20,000 principal accounts.
- `tools/collect_metrics.py` and `tools/check_numbers.py`, verifying every published figure across the README and docs against measured values on every CI run.
- `tools/check_dependencies.py`, which fails CI on any declared dependency nothing imports.
- MkDocs Material documentation site, including a reference for every escalation edge and a guide to preparing a real account export.
- Community health files, issue and PR templates, Dependabot for pip, Actions and Docker, pre-commit hooks and a provenance audit of the repository's own signals.
- Structural tests asserting the Dockerfile's security properties, since this development environment cannot reach a container registry and the image itself is built and started in CI.

### Changed
- The report and the badge lead with the share of principals labelled least privilege that reach admin anyway, which barely moves across two orders of magnitude of account size and so describes hygiene rather than size.

### Fixed
- `duckdb` and `pyyaml` were declared and never imported. The CloudTrail activity scan duckdb was added for is recorded as out of scope with its trigger condition.

### Performance
- Graph construction went from 118 seconds to 1.5 on a 2,177 principal account, and reachability from 34.9 seconds to 0.016. Effective statements are memoised, candidate targets are indexed from the resource patterns an escalation action is permitted on rather than enumerated, administrative principals are skipped as edge sources, and distance to admin comes from one reverse breadth first search rather than a path enumeration per principal. ADR-002 has the measurements.

## [0.2.0] - 2026-10-20

Reachability and reporting.

### Added
- Blast radius and admin reachability queries, reporting paths rather than counts: every finding carries the principals it passes through and the technique at each step.
- HTML report with light and dark themes, status carried by glyph and word as well as colour, and machine readable JSON.
- `ibr analyse` and `ibr generate` with a reproducible synthetic account generator.
- Structured JSON logging with a per-run id.

### Fixed
- Conditional edges were indistinguishable from unconditional ones in the output, so a reader could not tell which paths rested on an unevaluated condition.

## [0.1.0] - 2026-10-20

The model and the graph.

### Added
- Account model covering statements, explicit Deny, action and resource wildcards, group inheritance, managed policy versions and role trust policies.
- Ten privilege escalation edge definitions, each with the actions it requires, the technique and why holding those actions grants the target's privileges.
- Reachability graph construction with per edge preconditions.

### Fixed
- `iam:PassRole` plus a service action created an edge to every role in the account, including roles that trust no service and so cannot back a function. The check modelled the caller's permission and not the role's willingness to be assumed.
- `iam:SetDefaultPolicyVersion` created an edge to every principal whose attached policy had any older version. Rolling a policy back grants the principal more of its own privileges, so there is no second principal and an edge is the wrong shape; and the version comparison asked whether a non default version mentioned any different action rather than whether it granted an administrative one.
- PowerUserAccess, which is Allow on `*` with an explicit Deny on `iam:*`, was reported as administrative. The admin equivalent set contained the literal strings `*` and `iam:*`, and asking whether a principal is allowed the action `*` matches the Allow while the Deny does not match it.

[Unreleased]: https://github.com/__GITHUB_USERNAME__/iam-blast-radius/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/__GITHUB_USERNAME__/iam-blast-radius/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/__GITHUB_USERNAME__/iam-blast-radius/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/__GITHUB_USERNAME__/iam-blast-radius/releases/tag/v0.1.0
