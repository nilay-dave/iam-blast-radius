# ADR-003: Over report reachability rather than under report it

Status: accepted
Date: 2026-10-20

## Context

Several places in this tool face the same choice: an edge might exist, and the
evaluator cannot be certain.

A statement allows `iam:PassRole` but carries a condition key the model records
and does not evaluate. A permission boundary is attached and not applied. A
service control policy exists above the account and is not read.

In each case the tool can include the edge and flag it, or exclude it.

## Options considered

1. **Exclude anything uncertain.** Produces a clean report with no false
   positives and an unknown number of false negatives. Every excluded edge is a
   path the report says does not exist.
2. **Include everything uncertain, unflagged.** Produces a report nobody trusts
   after the first time an engineer chases a path that a condition blocks.
3. **Include and flag, with an option to exclude.** Chosen.

## Decision

Include the edge, mark it conditional, and surface that in every output. The
report shows which principals reach admin only through a conditional edge.
`--strict-conditions` and `IBR_ASSUME_CONDITIONS=false` flip the behaviour for
anybody who wants the conservative set.

## The argument, stated plainly

The two errors are not symmetric and treating them as a tuning problem misses
the point.

A false positive costs an engineer the time to check one path. They open the
policy, see the condition, confirm it holds, and move on. Ten minutes, and the
tool is slightly less pleasant to use.

A false negative costs a breach. The report said the principal was contained.
Nobody looked again.

Every approximation in this tool is therefore pushed in the same direction:
toward reporting more reachability than certainly exists. Conditions are assumed
satisfiable. Permission boundaries are not applied, which can only make the real
answer more restrictive. Trust policy conditions are flagged rather than
evaluated.

## Consequences

The report has to say this, and it does: the footer of the HTML output states
what was not evaluated, and the conditional count is one of the four headline
tiles rather than a footnote. A tool that over reports without saying so is
simply a tool that is wrong.

The flag matters for the people who need the other direction. A team doing
quarterly attestation rather than incident response may want the set they can
defend as certain, and `--strict-conditions` gives it to them with the trade
stated.

The one place this reasoning does not apply is explicit Deny, which is evaluated
properly and always wins. A Deny is not an uncertainty: it is a fact in the
policy that makes the edge not exist, and including it anyway would be reporting
a path that provably cannot be taken. The asymmetry argument is about things the
evaluator does not know, not about things it does.
