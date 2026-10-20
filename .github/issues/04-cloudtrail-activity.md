# Weight paths by whether the actions have ever been used
labels: enhancement

Every reported path is equally plausible today. A path through an action the
principal has used a thousand times in ninety days is different from a path
through an action it has never used, and a remediation queue should know which.

## What to do

- Accept an optional CloudTrail summary: principal, action, last used, call count over a window.
- Annotate each edge with whether its actions have been exercised.
- Add a report view ordering by "reachable and routinely exercised" first.

## Note on interpretation

Never-used is not safe. An unused escalation action is a path nobody has walked
yet, and the obvious misreading of this feature is to deprioritise exactly the
paths an attacker would prefer because they generate no anomalous activity. The
report has to frame this as "which paths are also already part of normal
operations", not as a risk score.

## Why the dependency was removed

An earlier commit declared duckdb for this and never used it.
`tools/check_dependencies.py` caught it, and the feature is recorded here rather
than left as an unused import.
