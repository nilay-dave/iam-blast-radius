"""What counts as a privilege edge, and why each one is in the list.

This is the file that decides whether the tool is right. A reachability graph is
only as good as its edge definitions: miss an escalation technique and the tool
reports a principal as contained when it is not, which is worse than not running
the tool at all because it manufactures confidence.

Each edge below is a documented AWS privilege escalation primitive. The list is
deliberately conservative in what it claims and deliberately broad in what it
includes, for the reason set out in ADR-003: over reporting reachability costs
an engineer ten minutes of checking, under reporting it costs a breach.

Sources for the techniques themselves are the AWS IAM documentation on each
action, and the escalation technique families that have been public since the
2018 Rhino Security Labs enumeration. The implementation is this project's own.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class EdgeKind(StrEnum):
    """How one principal reaches another's privileges."""

    ASSUME_ROLE = "assume_role"
    ATTACH_POLICY = "attach_policy"
    PUT_INLINE_POLICY = "put_inline_policy"
    CREATE_ACCESS_KEY = "create_access_key"
    UPDATE_LOGIN_PROFILE = "update_login_profile"
    PASS_ROLE_TO_LAMBDA = "pass_role_to_lambda"
    PASS_ROLE_TO_EC2 = "pass_role_to_ec2"
    UPDATE_ASSUME_ROLE_POLICY = "update_assume_role_policy"
    SET_DEFAULT_POLICY_VERSION = "set_default_policy_version"
    ADD_USER_TO_GROUP = "add_user_to_group"


@dataclass(frozen=True)
class EdgeDefinition:
    kind: EdgeKind
    # Actions that, held together, create this edge. All of them are required.
    required_actions: tuple[str, ...]
    # Short description of what an attacker does with it.
    technique: str
    # Why this edge grants the target's privileges rather than merely touching it.
    rationale: str
    # True when the edge needs iam:PassRole plus a service action, which is the
    # family people most often forget to model.
    needs_pass_role: bool = False
    # The service principal that must appear in the target role's trust policy
    # for this edge to work. Passing a role to Lambda is useless if the role
    # does not trust lambda.amazonaws.com: the service cannot assume it and the
    # escalation fails at the first step.
    requires_service_trust: str | None = None


DEFINITIONS: tuple[EdgeDefinition, ...] = (
    EdgeDefinition(
        kind=EdgeKind.ASSUME_ROLE,
        required_actions=("sts:AssumeRole",),
        technique="Assume the target role directly.",
        rationale=(
            "The explicit case. Requires the target's trust policy to name this principal, which is "
            "checked separately: holding sts:AssumeRole in an identity policy is not sufficient."
        ),
    ),
    EdgeDefinition(
        kind=EdgeKind.ATTACH_POLICY,
        required_actions=("iam:AttachUserPolicy",),
        technique="Attach a managed policy, including AdministratorAccess, to yourself.",
        rationale=(
            "A principal that can attach any managed policy to itself is already an administrator. "
            "This is the single most common finding and the one most often labelled low severity "
            "because the principal's own policy looks modest."
        ),
    ),
    EdgeDefinition(
        kind=EdgeKind.PUT_INLINE_POLICY,
        required_actions=("iam:PutUserPolicy",),
        technique="Write an inline policy granting yourself any action.",
        rationale="Equivalent to AttachUserPolicy without needing a managed policy to exist.",
    ),
    EdgeDefinition(
        kind=EdgeKind.CREATE_ACCESS_KEY,
        required_actions=("iam:CreateAccessKey",),
        technique="Create long lived credentials for another user.",
        rationale=(
            "Grants the target's privileges and persists past the compromise of the original "
            "credential, which is why it is an escalation rather than lateral movement."
        ),
    ),
    EdgeDefinition(
        kind=EdgeKind.UPDATE_LOGIN_PROFILE,
        required_actions=("iam:UpdateLoginProfile",),
        technique="Set a console password for another user.",
        rationale="Same effect as CreateAccessKey through the console path.",
    ),
    EdgeDefinition(
        kind=EdgeKind.PASS_ROLE_TO_LAMBDA,
        required_actions=("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"),
        technique="Create a function running as the target role and invoke it.",
        rationale=(
            "The classic PassRole family. Each action alone is unremarkable, which is exactly why "
            "this is missed: a reviewer looking at any one statement sees nothing wrong. The role "
            "must trust lambda.amazonaws.com or the service cannot assume it."
        ),
        needs_pass_role=True,
        requires_service_trust="lambda.amazonaws.com",
    ),
    EdgeDefinition(
        kind=EdgeKind.PASS_ROLE_TO_EC2,
        required_actions=("iam:PassRole", "ec2:RunInstances"),
        technique="Launch an instance with the target role as its instance profile.",
        rationale=(
            "Same family, and harder to spot because ec2:RunInstances is routinely granted to "
            "developers who have no business assuming the roles they can pass. The role must trust "
            "ec2.amazonaws.com to be usable as an instance profile."
        ),
        needs_pass_role=True,
        requires_service_trust="ec2.amazonaws.com",
    ),
    EdgeDefinition(
        kind=EdgeKind.UPDATE_ASSUME_ROLE_POLICY,
        required_actions=("iam:UpdateAssumeRolePolicy", "sts:AssumeRole"),
        technique="Rewrite the target's trust policy to name yourself, then assume it.",
        rationale=(
            "Defeats trust policy analysis done at a point in time, because the trust relationship "
            "the analysis read is one the attacker can change."
        ),
    ),
    EdgeDefinition(
        kind=EdgeKind.SET_DEFAULT_POLICY_VERSION,
        required_actions=("iam:SetDefaultPolicyVersion",),
        technique="Roll a managed policy back to an older, more permissive version.",
        rationale=(
            "Requires an older version to exist and to be more permissive, which the account model "
            "records per policy rather than assuming."
        ),
    ),
    EdgeDefinition(
        kind=EdgeKind.ADD_USER_TO_GROUP,
        required_actions=("iam:AddUserToGroup",),
        technique="Add yourself to a more privileged group.",
        rationale="Grants the group's attached policies without touching any policy document.",
    ),
)

BY_KIND: dict[EdgeKind, EdgeDefinition] = {d.kind: d for d in DEFINITIONS}

# Actions that are administrative on their own. A principal holding any of these
# is treated as already at the top of the graph rather than one hop from it.
ADMIN_EQUIVALENT_ACTIONS: frozenset[str] = frozenset(
    {
        "*",
        "iam:*",
        "iam:CreateUser",
        "iam:PutUserPolicy",
        "iam:AttachUserPolicy",
        "iam:PutRolePolicy",
        "iam:AttachRolePolicy",
        "organizations:*",
    }
)
