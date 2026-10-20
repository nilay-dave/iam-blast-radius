# Order remediation by how many paths a single statement removal closes
labels: enhancement,good first issue

The report lists principals that reach admin. It does not say which single
change closes the most paths, and in a large account that is the first question
a remediation owner asks.

## What to do

- For each edge, count how many principals lose their shortest path if it is removed.
- Report the top N edges by paths closed, with the statement to delete.
- The graph already supports this: it is one recomputation of `admin_distances` per candidate edge, and the candidate set is only the edges on at least one shortest path.

## Why this is a good first issue

The algorithm is a loop over existing functions, there is no new IAM modelling,
and `tests/test_reach.py` shows exactly how a reachability assertion is written.

## The refinement worth having

Removing an edge may simply route the path through another. Report paths closed
rather than principals contained, and say which principals are fully contained
separately, because those are the ones worth celebrating.
