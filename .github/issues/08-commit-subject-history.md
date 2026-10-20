# Commit subjects over 72 characters
labels: chore,wontfix

The provenance audit reports any subject over the 72 character limit.

## Decision: not fixing retroactively

Rewriting history to tidy prose invalidates every existing clone and every
commit reference for no functional gain. `tools/check_commit_subject.py` runs as
a commit-msg hook so the count cannot grow.

Recorded as an issue rather than left silent because the audit reports it on
every run, and a reader deserves to find the reason rather than assume nobody
noticed.
