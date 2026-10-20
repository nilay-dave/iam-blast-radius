# Apply permission boundaries
labels: enhancement

Permission boundaries are recorded in the model and not applied. A principal
with an administrative identity policy and a restrictive boundary is reported
as administrative and is not.

## Why this is not simply a bug

ADR-003: every approximation in this tool errs toward reporting more
reachability. Ignoring a boundary can only make the reported answer broader than
the real one, which is the safe direction. So this is a precision improvement
rather than a correctness fix, and it is worth saying that plainly rather than
filing it as a defect.

## What to do

- Evaluate the boundary as an intersection: an action is allowed only if both the identity policy and the boundary allow it.
- Apply it in `Account.allows`, which is the single place policy evaluation happens.
- Report which findings changed when the boundary was applied, because a team that has invested in boundaries will want to see them working.

## What this will not fix

Service control policies, which are a separate issue and a harder one because
they live outside the account snapshot entirely.
