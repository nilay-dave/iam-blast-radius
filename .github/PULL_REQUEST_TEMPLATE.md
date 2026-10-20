## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- The problem this solves. For a fix, one line of symptom and one of root cause. -->

## Checklist

- [ ] `make verify` passes locally, run and read before committing
- [ ] New behaviour has a test; a fix has a regression test that failed before it
- [ ] If a published number moved, `make report` was run and the README updated in this PR
- [ ] Figures from the bundled synthetic corpus are labelled as simulations
- [ ] No alert content appears in any report, log line or error message
- [ ] Approximations err toward over reporting reachability, per ADR-003
- [ ] No em dashes or en dashes anywhere
- [ ] Conventional Commit messages

## Numbers this changes

<!-- Which values in docs/metrics.json move, and why. "None" is a fine answer. -->
