# Security Policy

## Supported versions

The latest minor release receives security fixes. This project is pre 1.0, so
older minors are not patched.

| Version | Supported |
| --- | --- |
| 0.3.x | yes |
| < 0.3 | no |

## Reporting a vulnerability

Open a private security advisory through the repository's Security tab rather
than a public issue. Expect an acknowledgement within three working days.

## Threat model for this tool

**An account's IAM configuration is a map of where to attack the organisation.**
That is the whole threat model in one sentence, and everything else follows from
it. An attacker who obtains this tool's input has a precomputed list of which
principals reach administrative access and by which route, which is more useful
to them than it is to you.

**The tool holds no credentials and makes no AWS calls.** Not in the CLI, not in
the service, not in the test suite. The account is a file, produced out of band
by an operator who already has the access, and the analysis path has no network
code in it at all. This is ADR-001's main consequence and it is deliberate: a
service that could refresh itself from AWS would need a role with `iam:List*`
and `iam:Get*` across the account, and that role would be a more attractive
target than anything the service produces.

**The service is read only by construction.** It loads one file at startup and
answers questions about it. There is no write path, no mutation endpoint and no
way to make it call AWS.

**Treat the account file and the report as you treat the account itself.** Both
name principals and the escalation paths between them. The report is a shorter,
better organised version of the attack plan. Store it accordingly, and prefer
the JSON output behind the same access controls as your IAM configuration rather
than pasting the HTML into a ticket.

**Policy document contents never leave the input.** The report carries principal
identifiers, tags, edge kinds and hop counts. It does not reproduce policy
documents, ARNs of resources, or condition key values.

## Running the container

The published image runs as uid 10001, a system user with no home directory and
no shell. Mount the account read only:

```bash
docker run --rm --read-only \
  -v "$PWD/account.json:/data/account.json:ro" \
  ghcr.io/__GITHUB_USERNAME__/iam-blast-radius:v0.3.0 \
  analyse --account /data/account.json
```

The image needs no network to analyse. If you run the service, bind it to
localhost or put it behind your own authentication: it has none of its own, by
design, because an authentication layer inside a tool like this is an
authentication layer nobody reviews.

## What this tool deliberately does not evaluate

Each of these can only make the real answer more restrictive than the reported
one, which is the direction ADR-003 argues for:

- Condition keys are recorded and not evaluated. Edges that depend on one are included and flagged.
- Permission boundaries are recorded and not applied.
- Service control policies are out of scope entirely.
- Resource policies other than role trust are out of scope.

If a reported path turns out to be blocked by one of these, that is the tool
behaving as designed rather than a bug. A path it failed to report is a bug, and
is the one worth filing.

## Dependency hygiene

Dependabot is configured for pip, GitHub Actions and Docker. CI runs on every
pull request and on pushes to `main`, and the image is built and started in CI
on every run.
