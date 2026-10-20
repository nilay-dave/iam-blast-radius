# Optional verification against the IAM policy simulator
labels: enhancement

ADR-001 rejected calling `iam:SimulatePrincipalPolicy` for every pair on
arithmetic: a 20,000 principal account has 400 million ordered pairs. Verifying
only the edges the graph found is a much smaller set.

## What to do

- `ibr verify --account a.json --profile prod` confirming each reported edge with the simulator.
- Report edges the simulator disagrees with, in both directions, because a false negative in the edge list is the more serious finding.
- Rate limit and cache; the simulator is not fast.

## The constraint

This reintroduces the credential requirement that ADR-001 removed, for the
subset of pairs that matter, and those are exactly the pairs an attacker would
probe. It must stay opt in, must never be required for the default analysis
path, and the credential must be documented as read only.

## Why it is worth doing anyway

It is the only way to measure this tool's false positive rate against the
authority, rather than against its own test fixtures.
