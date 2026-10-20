# Generate accounts containing paths longer than two hops
labels: chore,good first issue

The bundled generator produces principals at one and two hops from admin and
none at three, so the default `max_hops` of 3 never finds anything the default
of 2 would not.

## What to do

Add a shape that chains through two intermediaries, and assert in
`tests/test_generate.py` that a generated account contains a principal at three
hops, alongside the existing assertions for one and two.

## Why this matters less than it looks

Real accounts rarely contain paths longer than two hops, and that is itself a
finding worth stating in the README rather than engineering around: escalation
in practice is short, because the actions that grant privilege grant a lot of it
at once. The reason to add it is to exercise the traversal, not to make the
synthetic account more realistic.
