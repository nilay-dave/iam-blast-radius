"""Generate a reproducible synthetic AWS account.

A portfolio repository cannot ship a real account's IAM configuration: it is a
map of exactly where to attack an organisation. So the account is synthetic, the
generator is in the repository, and every figure derived from it is labelled as
a simulation.

The generator's job is not to look plausible, it is to contain the failure modes
the tool claims to find, in proportions that are defensible. Five shapes, each
a pattern that occurs in real accounts and each named so a reader can argue with
the proportion:

  contained         a principal with narrowly scoped permissions and no path
  self_scoped       holds an escalation action but only against its own ARN,
                    which looks alarming in a policy grep and is not a path
  one_hop           a direct escalation, usually PassRole or AttachUserPolicy
  multi_hop         reaches admin through another principal
  already_admin     holds administrative power outright

The interesting one is `self_scoped`. A tool that string matched policy
documents would report every one of those as a finding, and an engineer who
chased a few would stop trusting the tool. They are in the account specifically
so the resource scoping has something to get right.

Least privilege tags are applied independently of actual reachability, which is
what makes the headline number meaningful: the tag records what somebody
intended, and the graph records what is true.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path

from ibr.account.model import (
    Account,
    Effect,
    Policy,
    PolicyVersion,
    Principal,
    PrincipalType,
    Statement,
    TrustPolicy,
)
from ibr.logging import get_logger

log = get_logger(__name__)

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
READONLY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
POWERUSER_ARN = "arn:aws:iam::aws:policy/PowerUserAccess"

# Shares of the principal population. These are the numbers to argue with, and
# they are set from what a mature but imperfect account tends to look like:
# most principals are fine, a meaningful minority hold one dangerous action,
# and administrators are a small group.
SHAPE_SHARES = {
    "contained": 0.62,
    "self_scoped": 0.12,
    "one_hop": 0.14,
    "multi_hop": 0.08,
    "already_admin": 0.04,
}

# Fraction of principals somebody tagged least privilege, applied independently
# of whether it is true.
LEAST_PRIVILEGE_TAG_SHARE = 0.45

BENIGN_ACTIONS = (
    ("s3:GetObject", "s3:ListBucket"),
    ("dynamodb:GetItem", "dynamodb:Query"),
    ("logs:PutLogEvents", "logs:CreateLogStream"),
    ("sqs:ReceiveMessage", "sqs:DeleteMessage"),
    ("cloudwatch:PutMetricData",),
    ("secretsmanager:GetSecretValue",),
)

ONE_HOP_GRANTS = (
    ("iam:AttachUserPolicy",),
    ("iam:PutUserPolicy",),
    ("iam:CreateAccessKey",),
    ("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"),
    ("iam:PassRole", "ec2:RunInstances"),
    ("iam:AddUserToGroup",),
)

SELF_SCOPED_GRANTS = (
    ("iam:AttachUserPolicy",),
    ("iam:PutUserPolicy",),
    ("iam:CreateAccessKey",),
)


@dataclass(frozen=True)
class GenerationResult:
    path: Path
    account: Account
    principals: int
    seed: int
    shapes: dict[str, int]


def _policies() -> dict[str, Policy]:
    return {
        ADMIN_ARN: Policy(ADMIN_ARN, "AdministratorAccess",
                          (PolicyVersion("v1", (Statement(Effect.ALLOW, ("*",)),), True),)),
        POWERUSER_ARN: Policy(POWERUSER_ARN, "PowerUserAccess",
                              (PolicyVersion("v1", (
                                  Statement(Effect.ALLOW, ("*",)),
                                  Statement(Effect.DENY, ("iam:*", "organizations:*")),
                              ), True),)),
        READONLY_ARN: Policy(READONLY_ARN, "ReadOnlyAccess",
                             (PolicyVersion("v1", (Statement(Effect.ALLOW, ("s3:Get*", "ec2:Describe*")),), True),)),
    }


def generate(out_path: Path | str, principals: int, seed: int = 7) -> GenerationResult:
    """Build a synthetic account of `principals` principals and write it to JSON."""
    if principals < 10:
        raise ValueError(f"principals must be at least 10 to form a meaningful graph, got {principals}")

    rng = random.Random(seed)
    account = Account(account_id="111122223333", policies=_policies())
    shapes: dict[str, int] = dict.fromkeys(SHAPE_SHARES, 0)

    shape_names = list(SHAPE_SHARES)
    shape_weights = [SHAPE_SHARES[name] for name in shape_names]
    assigned = rng.choices(shape_names, weights=shape_weights, k=principals)
    # Guarantee at least one of every shape, so a small account still exercises
    # every path the tool claims to find.
    for index, name in enumerate(shape_names):
        assigned[index] = name

    # Admin roles first: every escalation path needs somewhere to land.
    admin_role_ids: list[str] = []
    admin_count = max(2, sum(1 for s in assigned if s == "already_admin"))
    for index in range(admin_count):
        role_id = f"role/admin-{index:03d}"
        admin_role_ids.append(role_id)
        account.principals[role_id] = Principal(
            principal_id=role_id,
            principal_type=PrincipalType.ROLE,
            attached_policy_arns=(ADMIN_ARN,),
            trust_policy=TrustPolicy(
                trusted_principals=(),
                trusted_services=("lambda.amazonaws.com", "ec2.amazonaws.com"),
            ),
            tags=("purpose:break-glass",),
        )
        shapes["already_admin"] += 1

    user_ids: list[str] = []
    for index, shape in enumerate(assigned):
        user_id = f"user/app-{index:04d}"
        tags: list[str] = []
        if rng.random() < LEAST_PRIVILEGE_TAG_SHARE:
            tags.append("least-privilege")
        tags.append(f"team:{rng.choice(('web', 'data', 'platform', 'ml'))}")

        statements = [Statement(Effect.ALLOW, rng.choice(BENIGN_ACTIONS))]

        if shape == "self_scoped":
            statements.append(
                Statement(Effect.ALLOW, rng.choice(SELF_SCOPED_GRANTS), resources=(user_id,))
            )
        elif shape == "one_hop":
            grant = rng.choice(ONE_HOP_GRANTS)
            if "iam:PassRole" in grant:
                statements.append(Statement(Effect.ALLOW, grant, resources=(rng.choice(admin_role_ids),)))
            else:
                statements.append(Statement(Effect.ALLOW, grant))
        elif shape == "multi_hop":
            # Reaches an intermediary rather than admin directly. The
            # intermediary is wired up after every principal exists.
            statements.append(Statement(Effect.ALLOW, ("iam:CreateAccessKey",), resources=("PENDING",)))
        elif shape == "already_admin":
            statements.append(Statement(Effect.ALLOW, ("*",)))

        account.principals[user_id] = Principal(
            principal_id=user_id,
            principal_type=PrincipalType.USER,
            inline_statements=tuple(statements),
            tags=tuple(tags),
        )
        if shape != "already_admin":
            shapes[shape] += 1
        else:
            shapes["already_admin"] += 1
        user_ids.append(user_id)

    # Wire the multi hop principals to an intermediary that itself reaches admin.
    one_hop_users = [
        user_id for user_id, shape in zip(user_ids, assigned, strict=True) if shape == "one_hop"
    ]
    if one_hop_users:
        for user_id, shape in zip(user_ids, assigned, strict=True):
            if shape != "multi_hop":
                continue
            intermediary = rng.choice(one_hop_users)
            principal = account.principals[user_id]
            rewritten = tuple(
                Statement(s.effect, s.actions, (intermediary,), s.conditions)
                if s.resources == ("PENDING",) else s
                for s in principal.inline_statements
            )
            account.principals[user_id] = Principal(
                principal_id=principal.principal_id,
                principal_type=principal.principal_type,
                inline_statements=rewritten,
                attached_policy_arns=principal.attached_policy_arns,
                group_ids=principal.group_ids,
                trust_policy=principal.trust_policy,
                tags=principal.tags,
            )

    # A handful of roles trusting real principals, so assume_role edges exist.
    for index in range(max(1, principals // 20)):
        role_id = f"role/service-{index:03d}"
        trusted = rng.sample(user_ids, k=min(3, len(user_ids)))
        account.principals[role_id] = Principal(
            principal_id=role_id,
            principal_type=PrincipalType.ROLE,
            attached_policy_arns=(POWERUSER_ARN,),
            trust_policy=TrustPolicy(trusted_principals=tuple(trusted)),
            tags=("purpose:service",),
        )
        for user_id in trusted:
            principal = account.principals[user_id]
            account.principals[user_id] = Principal(
                principal_id=principal.principal_id,
                principal_type=principal.principal_type,
                inline_statements=principal.inline_statements
                + (Statement(Effect.ALLOW, ("sts:AssumeRole",), resources=(role_id,)),),
                attached_policy_arns=principal.attached_policy_arns,
                group_ids=principal.group_ids,
                trust_policy=principal.trust_policy,
                tags=principal.tags,
            )

    out_path = Path(out_path)
    from ibr.account.serialise import write_account

    write_account(account, out_path)
    log.info(
        "account generated",
        extra={"principals": len(account.principals), "path": str(out_path), "seed": seed, "shapes": shapes},
    )
    return GenerationResult(
        path=out_path, account=account, principals=len(account.principals), seed=seed, shapes=shapes
    )
