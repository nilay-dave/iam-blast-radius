# ADR-002: One traversal, not a search per principal

Status: accepted
Date: 2026-10-20

## Context

The first working version of this tool was correct and unusable. On a 2,177
principal account it took 118 seconds to build the graph and a further 35
seconds to answer the reachability question, which is not a tool anybody runs
weekly.

Three separate mistakes, each the obvious implementation of its step.

**Edge construction tested every pair.** Every principal against every
principal, for every escalation definition, with a full policy evaluation inside
the innermost loop. Quadratic in principals with an expensive constant.

**Effective statements were recomputed every time.** Resolving what a principal
is allowed walks its inline statements, its attached managed policies and every
group it belongs to. The build asked for the same principal's statements
thousands of times and recomputed from scratch each time.

**Reachability enumerated simple paths per principal.** `all_simple_paths` from
every principal to every administrative node. With 338 administrative nodes in
that account, that is 2,177 searches against 338 targets each, to extract two
numbers: the hop distance and one shortest path.

## Decision

Memoise effective statements on the Account. Index candidate targets from the
resource patterns a principal is actually allowed the escalation action on.
Replace per principal path enumeration with a single breadth first search over
the reversed graph, seeded with every administrative node.

## What was measured

On a 2,177 principal account, median of three runs:

| Stage | Before | After |
| --- | --- | --- |
| Graph build | 118 s | 1.5 s |
| Reachability | 34.9 s | 0.016 s |

The reachability change is the larger one and the more interesting. A reverse
breadth first search labels every principal with its distance to the nearest
administrative node in one pass, linear in the graph. Recording the first step
of each shortest path during that pass means the path is reconstructed by
following pointers rather than searched for again.

## Consequences

**Candidate indexing changes the shape of the work, not just its speed.** A
principal allowed `iam:CreateAccessKey` only on its own ARN has exactly one
candidate. A principal holding no escalation action at all has none, and the
majority of principals in any account hold none. Only a principal with a
wildcard resource scope expands to the whole account, and that principal is
itself the finding.

**Administrative principals are skipped as edge sources.** An administrator
reaches every principal by definition, and enumerating those edges added
hundreds of thousands of entries that nobody acts on: "the administrator can
attach a policy to this user" is not a finding. Blast radius for an
administrator is reported as the whole account by the query layer rather than
stored as edges.

**The count of enumerated paths was replaced.** It was exponential to compute
and told a reader nothing they acted on. What replaced it is the number of
distinct next steps that lead toward admin, which is the out degree restricted
to neighbours closer to admin: how many separate statements have to be removed
to contain this principal. Cheaper and more useful.

**Blast radius per principal is off by default.** It is a breadth first search
per principal, which is quadratic over the account, while every other number
here comes from one traversal. The CLI computes it only for the principals it
displays, and the API computes it per request, which is the right shape for a
question asked about one principal at a time.

The remaining ceiling is edge count rather than principal count. An account
where many principals hold wildcard scoped IAM write actions produces millions
of edges, and that is a true property of the account rather than an artefact:
the graph is large because the blast radius is large.
