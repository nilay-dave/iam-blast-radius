# Issue backlog, ready to open

These are written as issue bodies rather than opened, because the repository has
not been pushed yet. Each one comes from a WEAK finding in the forensics audit,
the roadmap, or the Intentionally out of scope section of the README.

Open them with the GitHub CLI once the remote exists:

```bash
for f in .github/issues/*.md; do
  [ "$(basename "$f")" = "README.md" ] && continue
  title=$(head -1 "$f" | sed 's/^# //')
  labels=$(grep -m1 '^labels:' "$f" | cut -d: -f2- | tr -d ' ')
  gh issue create --title "$title" --label "$labels" --body-file <(tail -n +3 "$f")
done
```

The three marked `good first issue` are the ones a stranger could pick up, which
is the point of having them.
