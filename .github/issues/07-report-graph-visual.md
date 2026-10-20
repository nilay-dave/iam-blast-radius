# Draw the escalation subgraph
labels: enhancement

The report lists paths as text. A picture of the escalation subgraph, the nodes
that reach admin and the edges between them, would make the shape obvious:
whether an account has one overprivileged role everything funnels through, or
fifty independent one hop paths. Those need completely different responses and
the table does not distinguish them.

## What to do

- Render the subgraph induced by principals that reach admin, excluding everything contained.
- Collapse principals with identical edge sets into one node with a count, or a 2,000 principal account draws as noise.
- Keep it to the static report; an interactive graph is a different project.

## Accessibility constraint

The existing report carries no information in colour alone and has measured
contrast on every pair, verified in CI. A graph image needs alt text that
carries the shape, not the appearance: how many funnel points, how many
independent paths, the largest in degree.
