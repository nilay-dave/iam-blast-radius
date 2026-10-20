# Follow escalation across account boundaries
labels: enhancement

A single account analysis understates reachability in an organisation. Cross
account escalation runs through role trust policies naming external principals,
which the model records and cannot resolve without the other account's snapshot.

## What to do

- Accept several account snapshots in one run.
- Resolve trust policies naming principals in a sibling account into real edges.
- Report the hop at which a path crosses an account boundary, because that is where remediation ownership changes.

## The hard part

Not the graph, which is the same algorithm over a bigger node set. It is that an
organisation's accounts are usually exported by different people at different
times, and a graph assembled from snapshots taken weeks apart will report paths
that no longer exist and miss ones that now do. The output needs to carry the
export timestamp per account and refuse to join snapshots more than a
configurable age apart.

## Until then

The README and docs/real-accounts.md both say to read a role trusting an
external principal as an open edge rather than a closed one.
