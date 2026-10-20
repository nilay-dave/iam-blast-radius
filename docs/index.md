# iam-blast-radius

IAM findings get triaged by severity label. The question that decides whether a
compromise is contained is a different one: if this principal is taken, what is
reachable, and in how many steps.

This computes that. It reads an account snapshot, builds a privilege
reachability graph from the escalation primitives that actually grant one
principal another's permissions, and reports which principals reach
administrative access, by which route, and at what hop distance.

The headline it produces is the gap between intention and fact: the share of
principals somebody labelled least privilege that reach admin anyway.

## Start here

- [The escalation edges](edges.md) is the list the tool's correctness rests on, with the rationale for each.
- [Preparing a real account](real-accounts.md) covers the export and what to strip from it.
- The [example report](report.html) is regenerated on every docs deploy from a synthetic account.

## Install

As a container, which is the distribution channel for this project:

```bash
docker pull ghcr.io/__GITHUB_USERNAME__/iam-blast-radius:latest
```

Or from source:

```bash
pip install git+https://github.com/__GITHUB_USERNAME__/iam-blast-radius.git
```

## The shortest useful run

```bash
ibr generate --principals 2000 --out account.json --seed 7
ibr analyse --account account.json --out report.html
```

The first command exists so the tool can be evaluated without exporting
anything real. Replace it with a snapshot of your own account and the numbers
stop being a simulation.

## What it never does

No AWS calls, no credentials, no writes. The account is a file, and the analysis
path has no network code in it at all. That is a design decision with a reason,
recorded in [ADR-001](adr/adr-001-graph-over-policy-simulator.md): a service
that could refresh itself from AWS would need a role with `iam:List*` across the
account, and that role is a more attractive target than the report it produces.

## Decisions

- [ADR-001](adr/adr-001-graph-over-policy-simulator.md): an offline graph rather than the IAM policy simulator.
- [ADR-002](adr/adr-002-one-traversal-not-a-search-per-principal.md): one traversal rather than a search per principal, and the 118 seconds that forced it.
- [ADR-003](adr/adr-003-over-report-rather-than-under-report.md): why every approximation errs toward reporting more reachability, and the one place it does not.
