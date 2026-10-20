# ADR-001: An offline reachability graph rather than the IAM policy simulator

Status: accepted
Date: 2026-10-20

## Context

AWS ships an authoritative answer to "can this principal perform this action":
`iam:SimulatePrincipalPolicy`. It evaluates the real policy language including
condition keys, permission boundaries and service control policies, which is
more than this project implements and always will be.

The question this tool asks is not that one. It asks: given every principal in
an account, which of them can obtain administrative privileges, by what route,
and in how many steps. That is a transitive question over tens of thousands of
pairs, and the simulator answers one pair at a time.

## Options considered

1. **Call the simulator for every pair.** Rejected on arithmetic before
   anything else. A 20,000 principal account has 400 million ordered pairs, and
   even restricted to plausible ones the call count is in the millions at a
   request rate measured in tens per second. It would also require credentials
   with `iam:SimulatePrincipalPolicy` across the account, and it would put the
   audit's load on the production IAM control plane.
2. **Call the simulator to confirm each edge the graph finds.** Attractive, and
   still rejected for v1: it reintroduces the credential requirement and the
   rate limit for the subset of pairs that matter, and the pairs that matter are
   exactly the ones an attacker would be probing. Recorded in the roadmap as an
   opt in verification pass rather than the default.
3. **Parse policies offline and build a reachability graph.** Chosen.

## Decision

Model the subset of IAM that determines whether one principal can obtain
another's privileges, build a directed graph from it, and answer reachability
questions by traversal. No AWS calls in the analysis path at all.

## Consequences

The tool runs with no credentials, no account access and no network, which is
what lets the entire test suite execute on a clean checkout and lets the service
run anywhere. That is not a convenience: a service that could refresh itself
from AWS would need a role with `iam:List*` and `iam:Get*` across the account,
which is a more attractive thing to compromise than the report it produces.

The cost is real and is stated rather than hidden. Condition keys are recorded
and not evaluated. Permission boundaries and service control policies are
recorded and not applied. Resource policies other than role trust are out of
scope. Each of those can only make the real answer more restrictive than the
reported one, which is the direction ADR-003 argues for deliberately.

The subset is small enough to be read in one sitting, which matters more than it
sounds. The correctness of this tool rests on `src/ibr/graph/edges.py` being
complete and `src/ibr/account/model.py` being right about Deny, and both are
short enough for a reviewer to check rather than trust.
