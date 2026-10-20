# Forensics audit: iam-blast-radius at v0.3.0

Four personas, each auditing independently, then an integrated verdict. Graded
PASS, WEAK or FAIL. Every FAIL found during this audit was fixed with its own
commit before delivery.

## Persona 1: The Principal Engineer

| # | Question | Grade | Justification |
| --- | --- | --- | --- |
| 1 | Clone, run, verify | PASS | Tested in a clean directory from the README text alone. `make verify` runs the same checks as CI in the same order, through an explicit interpreter rather than through console scripts that bind to whichever Python installed them. No AWS account, no credentials, no network. |
| 2 | Architecture and design decisions | PASS | Four packages with a real boundary each: `account` models and serialises, `graph` builds and traverses, `api` serves, `report` renders. The split that matters is between edge construction and traversal, which is why the performance work changed both independently without touching the model. Three ADRs, each with rejected options and measurements. |
| 3 | Abstraction and configurability | PASS | Hop limits, path caps, condition handling and the seed all on `Config` from the environment with validation. `--strict-conditions` exposes the one approximation a user might reasonably want reversed. |
| 4 | Error handling and edge cases | PASS | Eleven documented failure modes. The account loader refuses an unsupported schema version rather than misreading it, because a silently misread account is a confidently wrong report. Group cycles are guarded, which matters because the model is loaded from a file that could contain one. |
| 5 | Testing | PASS | 155 tests, 98 percent branch coverage, including a regression test for each of the three modelling bugs and structural tests on the Dockerfile. The convention that each edge needs two tests, one that it appears and one that it does not when a precondition is missing, came out of the war story rather than being imposed. |

## Persona 2: The UX Director and Product Thinker

| # | Question | Grade | Justification |
| --- | --- | --- | --- |
| 1 | First 30 seconds | PASS | Opens with the gap between a label and a fact, and the number measuring it. Not a technology, not a feature list. |
| 2 | The So What of results | PASS | Every finding carries the principals it passes through and the technique at each step. The report's own framing is that a number tells somebody there is a problem and a path tells them which statement to delete. |
| 3 | Visual storytelling | PASS | The architecture diagram shows that no AWS call appears anywhere in the pipeline, which is the design's main claim. The report leads with one figure, carries status by glyph and word as well as colour, and states what it did not evaluate in the footer rather than burying it. |
| 4 | Actionability and handoff | PASS | Four CLI verbs covering generate, analyse, gate and serve, so the tool fits a review, a CI check and an incident without reconfiguration. Future Work names the first metric to watch and explains why the obvious one is wrong. |

## Persona 3: The Hiring Manager

| # | Question | Grade | Justification |
| --- | --- | --- | --- |
| 1 | Tutorial smell test | PASS | The problem is specific and current: severity labels do not answer a transitive question, and the path runs through three principals so no single policy document contains it. |
| 2 | Stolen Valor check | PASS after a fix | Was a FAIL. `duckdb` and `pyyaml` were declared and never imported. Removed, and the CloudTrail activity scan duckdb was there for is recorded as out of scope with a trigger condition rather than left as an implied capability. The tech stack table now distinguishes what networkx provides from what this project does with it. |
| 3 | Hardest problem solved | PASS | Three bugs that are the same bug: each modelled one side of a two sided relationship. The writeup draws that out rather than listing them, and the test convention that came from it is in CONTRIBUTING. |
| 4 | One thing I will remember | PASS | That PowerUserAccess was reported as an administrator because the admin set contained the literal string `*`, which is not an action anybody can call, so the Allow matched and the Deny did not. |

## Persona 4: The Sceptic (provenance)

Automated by `scripts/provenance_check.py`.

The FAILs found and fixed during this audit:

1. Two declared dependencies nothing imported. Fixed, and `tools/check_dependencies.py` now fails CI on the class. This is the third repository in the batch where that check has caught something.
2. The benchmark's largest scenario did not complete, so the published scaling claim rested on two points. Rather than quietly benchmarking smaller, the ceiling was measured directly and the README now carries the edge growth table, the memory figure and the wall clock limit.

The remaining WEAKs, each with a reason:

- **Identity placeholders unresolved.** Expected: built before the GitHub account was known. `tools/set_identity.sh` binds every URL in one pass.
- **The image is not built in this environment.** Docker Hub is unreachable from the development sandbox, so the image is built, run and health checked in CI instead, and `tests/test_dockerfile.py` asserts the file still says what the README and SECURITY.md claim it says. This is stated rather than papered over: no image size or runtime behaviour is published from an unbuilt image.

## Integrated verdict

**Overall portfolio score: 9 out of 10.**

The repository holds up to all four reads. Its strongest feature is that the
correctness surface is small and explicit: the tool is exactly as good as
`src/ibr/graph/edges.py` and `src/ibr/account/model.py`, both are short enough
for a reviewer to read rather than trust, and the README says so.

The performance work is the clearest engineering in the batch so far, because
all three mistakes were the obvious implementation of their step and the fixes
are measured rather than asserted: 118 seconds to 1.5 on graph construction, 34.9
to 0.016 on reachability.

It is a 9 and not a 10 because it has not been pushed: the Actions tab is not
green, the releases are local tags, and the image is publish ready rather than
published. For this repository that gap is larger than for the others, because
the image is the distribution channel and an unpublished image is an untested
one beyond what the structural tests cover.

### Critical failures (do not ship)

None outstanding.

### Impact multipliers

1. **Push and publish.** Green Actions tab, three GitHub Releases from the existing annotated tags, the image on ghcr.io with its provenance attestation, and Pages live so the badge endpoints resolve. The image job in CI already builds, runs and health checks it; it has simply never run.
2. **Verify against the policy simulator.** Issue 03. It is the only way to measure this tool's false positive rate against the authority rather than against its own fixtures, and given that three modelling bugs were found by hand, the rate is the number a sceptical reader most wants.
3. **Multi account.** Issue 01. A single account analysis understates reachability in an organisation, which the README states, and stating a limitation is not the same as removing it.

### Elevator pitch

IAM findings get triaged by severity label, but the question that decides
whether a compromise is contained is transitive: can this principal reach
administrative access, and how far does it have to go. Nobody answers that by
reading policies, because the path runs through three principals and no single
policy document contains it. This builds the privilege reachability graph from
nine documented escalation primitives, reports which principals reach admin and
by which route, and ships as a container that holds no credentials and makes no
AWS calls. On the bundled account, roughly a quarter of the principals somebody
tagged least privilege reach administrative access anyway.
