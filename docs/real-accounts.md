# Preparing a real account

The tool reads a JSON snapshot. The bundled generator exists so it can be
evaluated without one; this page is how to produce the real thing.

## The export

Everything needed comes from one call:

```bash
aws iam get-account-authorization-details \
  --filter User Role Group LocalManagedPolicy AWSManagedPolicy \
  > raw.json
```

That requires `iam:GetAccountAuthorizationDetails`, which is read only. The
tool itself never makes this call and never holds the credential that can: see
[ADR-001](adr/adr-001-graph-over-policy-simulator.md) for why that boundary is
where it is.

## The transform

The snapshot format is documented by `src/ibr/account/serialise.py` and is
deliberately small. For each principal you need:

- `principal_id` and `principal_type`
- `inline_statements`: effect, actions, resources, and the names of any condition keys
- `attached_policy_arns`
- `group_ids` for users
- `trust_policy` for roles: trusted principals, trusted services, condition key names
- `tags`

For each managed policy you need every version, with `is_default` marked on one.
The versions matter: rolling back to an older one is an escalation primitive and
a snapshot carrying only the default version cannot detect it.

## What to strip

**Condition key values.** The model records that a statement is conditional and
the names of the keys. It never evaluates them and never needs their values, and
values frequently carry account ids, VPC ids and IP ranges.

**Resource ARNs that are not principals.** The tool matches resource patterns
against principal identifiers. An S3 bucket ARN in a statement is noise to it
and may be sensitive to you.

**Policy descriptions and tags you do not want in a report.** Tags are carried
into the output, which is how the least privilege label is read. Strip any tag
you would not want in a ticket.

## Handling the output

Treat the snapshot and the report the way you treat the account. Both name
principals and the escalation paths between them, and the report is a shorter,
better organised version of the attack plan. SECURITY.md has the full argument.

## Multi account

Out of scope for v1, and worth being precise about why. Cross account
escalation runs through role trust policies naming external principals, which
the model records but cannot resolve without the other account's snapshot. Until
it can, a role trusting an external principal is a boundary the tool reports and
does not follow.

The honest consequence: in an organisation, a single account analysis understates
reachability. If you run this per account, read the trust policies naming
external principals as open edges rather than closed ones.
