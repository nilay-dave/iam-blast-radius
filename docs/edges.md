# The escalation edges

A node is a principal. An edge from A to B means a compromise of A yields B's
privileges. This page is the list, because the tool is only as correct as it is:
a missing edge is a principal reported contained when it is not, which is worse
than not running the tool at all because it manufactures confidence.

The techniques are the documented AWS privilege escalation families. The
implementation and the preconditions are this project's own.

## The edges

| Edge | Required actions | What an attacker does |
| --- | --- | --- |
| `assume_role` | `sts:AssumeRole` | Assume the target role directly |
| `attach_policy` | `iam:AttachUserPolicy` | Attach AdministratorAccess to yourself |
| `put_inline_policy` | `iam:PutUserPolicy` | Write yourself an inline policy granting any action |
| `create_access_key` | `iam:CreateAccessKey` | Create long lived credentials for another user |
| `update_login_profile` | `iam:UpdateLoginProfile` | Set a console password for another user |
| `pass_role_to_lambda` | `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction` | Run code as the target role |
| `pass_role_to_ec2` | `iam:PassRole`, `ec2:RunInstances` | Launch an instance with the target role attached |
| `update_assume_role_policy` | `iam:UpdateAssumeRolePolicy`, `sts:AssumeRole` | Rewrite the trust policy to name yourself, then assume |
| `add_user_to_group` | `iam:AddUserToGroup` | Add yourself to a more privileged group |

## The preconditions that matter

An edge is not created just because the source holds the actions. Three checks
remove paths that would fail at the first API call, and each of them was a bug
before it was a check.

**`sts:AssumeRole` means nothing without the trust policy.** Holding the action
in an identity policy is half the requirement; the target role's trust policy has
to name the principal. Skipping this turns every principal with `sts:AssumeRole`
into a path to every role in the account, which is the single most common way a
reachability tool produces a report nobody believes.

**Passing a role to a service requires the service to trust it.** A role that
does not trust `lambda.amazonaws.com` cannot back a function, so `iam:PassRole`
plus `lambda:CreateFunction` against it is not a path. The first version of this
tool created those edges and they were all false.

**Resource scope is evaluated.** A principal allowed `iam:CreateAccessKey` only
on its own ARN reaches nobody. These look alarming in a policy grep and are not
findings, which is why the bundled account contains them deliberately: the
resource scoping needs something to get right.

## What is not an edge

**Rolling a policy back to an older version.** `iam:SetDefaultPolicyVersion` is
a real escalation primitive and it is not an edge, because an edge means "A
obtains B's privileges" and here there is no B: the principal gains more of its
own permissions. It is evaluated as admin equivalence instead, and only when a
non default version actually grants an administrative action. Modelling it as an
edge produced a path from the principal to everyone whose policy had any old
version, including rollbacks that granted nothing but `s3:List*`.

**Anything an administrator can do.** An administrator reaches every principal
by definition. Those edges are not stored: "the administrator can attach a policy
to this user" is not a finding, and enumerating them added hundreds of thousands
of entries nobody acts on. Blast radius for an administrator is the account.

## Admin equivalence

A principal is treated as already administrative when it can perform any of a
set of concrete API actions that grant arbitrary privilege:
`iam:AttachUserPolicy`, `iam:PutUserPolicy`, `iam:AttachRolePolicy`,
`iam:PutRolePolicy`, `iam:AttachGroupPolicy`, `iam:PutGroupPolicy`,
`iam:CreatePolicyVersion`.

Every entry is a concrete action and never a wildcard, which is less obvious
than it sounds. An earlier version included the literal strings `*` and `iam:*`.
Asking whether a principal is allowed the action `*` matches an Allow on `*`
while an explicit Deny on `iam:*` does not match it, because `*` is not an
action anybody can call. PowerUserAccess, which is exactly Allow `*` plus Deny
`iam:*`, was therefore reported as administrative.

## Adding one

See CONTRIBUTING. The short version: state the actions, the technique, and why
holding them grants the target's privileges rather than merely touching it, and
write a test for both halves, that the edge appears when it should and that it
does not when a precondition is missing. The second half is what catches an edge
that reaches everybody.
