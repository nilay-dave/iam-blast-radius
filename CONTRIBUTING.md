# Contributing

## Getting set up

```bash
git clone https://github.com/__GITHUB_USERNAME__/iam-blast-radius.git
cd iam-blast-radius
python -m venv .venv && source .venv/bin/activate
make install
make verify
```

`make verify` runs every check CI runs, in the same order: lint, tests with
coverage, the dependency check, the report contrast check and the provenance
audit. A verify that is a subset of CI is a verify that lies.

It needs no AWS account, no credentials and no network. Everything runs through
`$(PYTHON)`, which defaults to `python3`; override it with
`make verify PYTHON=python3.12` if the console scripts on your PATH belong to a
different interpreter.

## The rules that matter here

**Every escalation edge carries a rationale.** `src/ibr/graph/edges.py` is the
file this tool's correctness rests on. A new edge needs the actions it requires,
the technique in one sentence, and why holding those actions grants the target's
privileges rather than merely touching it. An edge nobody can defend in a review
is an edge that produces findings nobody acts on.

**Approximations err toward over reporting.** When the evaluator cannot be
certain an edge exists, include it and flag it. A false positive costs an
engineer ten minutes of checking; a false negative costs a breach. ADR-003 has
the argument, and the one exception is explicit Deny, which is evaluated
properly and always wins.

**Deny evaluation is not optional.** A principal holding `iam:*` with an
explicit Deny on `iam:AttachUserPolicy` is not an administrator. Any change to
`src/ibr/account/model.py` needs a test covering Deny for the path it touches.

**Verify before you commit, as two separate steps.** Run the tests, read the
output, then commit. Do not chain `pytest && git commit`.

**Every published number is measured.** Numbers in the README and `docs/` are
tagged with `<!--number:path-->` markers and checked against `docs/metrics.json`
by `tools/check_numbers.py`. Run `make report` and update the document in the
same commit. Do not edit `docs/metrics.json` by hand.

**Numbers from the bundled account are labelled as simulations.**

**No policy document contents in any output.** The report carries principal
identifiers, edge kinds and hop counts. A change that put a policy document into
a report, a log line or an error message changes what a user has to protect; see
SECURITY.md.

**No em dashes or en dashes anywhere.**

## Commit messages

Conventional Commits: `type(scope): imperative summary` under 72 characters, no
trailing period. Fix commits carry a body with one line of symptom and one line
of root cause.

## Adding an escalation edge

1. Add an `EdgeDefinition` to `DEFINITIONS` with its required actions, technique and rationale.
2. If it needs a service to assume a role, set `requires_service_trust`. Passing a role to Lambda is useless if the role does not trust `lambda.amazonaws.com`, and forgetting that was a real bug here.
3. Constrain the target principal type in `_edge_applies` if the action only works against one.
4. Add a test asserting both that the edge appears when it should and that it does not when a precondition is missing. The second half is what catches an edge that reaches everybody.

## A note on self escalation

Not every privilege escalation primitive is a graph edge. An edge means "A
obtains B's privileges". Rolling a managed policy back to an older version grants
the principal more of its own privileges, so there is no B, and it is evaluated
in `is_admin_equivalent` instead. Getting this wrong produced an edge from one
principal to every principal with an old policy version.

## Pull requests

One concern per pull request. CI must be green. New behaviour needs a test; a
bug fix needs a regression test that fails before the fix.
