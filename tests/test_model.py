"""Policy evaluation. A wrong answer here is a confidently wrong finding."""

import pytest
from tests.conftest import ADMIN_ARN, allow, deny, group, new_account, role, user

from ibr.account.model import Effect, Policy, PolicyVersion, Statement


def test_inline_allow_is_granted():
    account = new_account()
    user(account, "u:a", allow("s3:GetObject"))
    assert account.allows("u:a", "s3:GetObject")


def test_action_not_granted_is_denied_by_default():
    account = new_account()
    user(account, "u:a", allow("s3:GetObject"))
    assert not account.allows("u:a", "s3:PutObject")


def test_explicit_deny_beats_a_broad_allow():
    """The one IAM rule a reachability tool cannot skip. A principal holding
    iam:* with a Deny on AttachUserPolicy is not an administrator, and reporting
    it as one sends somebody to fix the wrong thing."""
    account = new_account()
    user(account, "u:a", allow("iam:*"), deny("iam:AttachUserPolicy"))
    assert account.allows("u:a", "iam:PutUserPolicy")
    assert not account.allows("u:a", "iam:AttachUserPolicy")


def test_deny_applies_regardless_of_statement_order():
    account = new_account()
    user(account, "u:a", deny("iam:AttachUserPolicy"), allow("iam:*"))
    assert not account.allows("u:a", "iam:AttachUserPolicy")


@pytest.mark.parametrize(
    "pattern, action, expected",
    [
        ("*", "iam:PutUserPolicy", True),
        ("iam:*", "iam:PutUserPolicy", True),
        ("iam:Put*", "iam:PutUserPolicy", True),
        ("iam:Put*", "iam:AttachUserPolicy", False),
        ("s3:Get*", "s3:GetObject", True),
        ("s3:Get*", "s3:ListBucket", False),
    ],
)
def test_action_wildcards(pattern, action, expected):
    account = new_account()
    user(account, "u:a", allow(pattern))
    assert account.allows("u:a", action) is expected


def test_action_matching_is_case_insensitive():
    account = new_account()
    user(account, "u:a", allow("IAM:putuserpolicy"))
    assert account.allows("u:a", "iam:PutUserPolicy")


def test_resource_scoping_limits_the_grant():
    """A principal allowed an escalation action only on its own ARN is not a
    path to anybody. This is the finding a policy grep gets wrong."""
    account = new_account()
    user(account, "u:a", allow("iam:CreateAccessKey", resources=("u:a",)))
    assert account.allows("u:a", "iam:CreateAccessKey", "u:a")
    assert not account.allows("u:a", "iam:CreateAccessKey", "u:b")


def test_group_statements_are_inherited():
    account = new_account()
    group(account, "g:devs", allow("ec2:RunInstances"))
    user(account, "u:a", allow("s3:GetObject"), groups=("g:devs",))
    assert account.allows("u:a", "ec2:RunInstances")


def test_group_cycle_does_not_recurse_forever():
    """IAM has no nested groups, but the model is loaded from a file that could
    contain a cycle, and an audit tool must not hang on bad input."""
    account = new_account()
    group(account, "g:a", allow("s3:GetObject"))
    group(account, "g:b", allow("ec2:RunInstances"))
    account.principals["g:a"] = account.principals["g:a"].__class__(
        principal_id="g:a", principal_type=account.principals["g:a"].principal_type,
        inline_statements=account.principals["g:a"].inline_statements, group_ids=("g:b",))
    account.principals["g:b"] = account.principals["g:b"].__class__(
        principal_id="g:b", principal_type=account.principals["g:b"].principal_type,
        inline_statements=account.principals["g:b"].inline_statements, group_ids=("g:a",))
    account._statement_cache.clear()
    user(account, "u:a", groups=("g:a",))
    assert account.allows("u:a", "s3:GetObject")
    assert account.allows("u:a", "ec2:RunInstances")


def test_attached_managed_policy_is_applied():
    account = new_account()
    user(account, "u:a", policies=(ADMIN_ARN,))
    assert account.allows("u:a", "organizations:LeaveOrganization")


def test_unknown_policy_arn_is_ignored_not_fatal():
    account = new_account()
    user(account, "u:a", allow("s3:GetObject"), policies=("arn:aws:iam::aws:policy/DoesNotExist",))
    assert account.allows("u:a", "s3:GetObject")


def test_unknown_principal_has_no_statements():
    assert new_account().effective_statements("u:nobody") == []
    assert not new_account().allows("u:nobody", "s3:GetObject")


def test_conditional_allow_is_flagged():
    account = new_account()
    user(account, "u:a", allow("iam:PassRole", conditions=("iam:PassedToService",)))
    assert account.allows("u:a", "iam:PassRole")
    assert account.allowed_conditionally("u:a", "iam:PassRole")


def test_unconditional_allow_is_not_flagged_even_alongside_a_conditional_one():
    account = new_account()
    user(account, "u:a",
         allow("iam:PassRole", conditions=("iam:PassedToService",)),
         allow("iam:PassRole"))
    assert not account.allowed_conditionally("u:a", "iam:PassRole")


def test_allow_patterns_collects_resources():
    account = new_account()
    user(account, "u:a",
         allow("iam:CreateAccessKey", resources=("u:b",)),
         allow("iam:CreateAccessKey", resources=("u:c",)))
    patterns, conditional = account.allow_patterns("u:a", "iam:CreateAccessKey")
    assert patterns == {"u:b", "u:c"}
    assert conditional is False


def test_allow_patterns_is_empty_when_action_is_absent():
    account = new_account()
    user(account, "u:a", allow("s3:GetObject"))
    patterns, conditional = account.allow_patterns("u:a", "iam:CreateAccessKey")
    assert patterns == frozenset()
    assert conditional is False


def test_statement_cache_returns_the_same_answer():
    account = new_account()
    group(account, "g:devs", allow("ec2:RunInstances"))
    user(account, "u:a", allow("s3:GetObject"), groups=("g:devs",))
    first = account.effective_statements("u:a")
    second = account.effective_statements("u:a")
    assert first == second
    assert len(first) == 2


ADMIN_ACTIONS = frozenset({"iam:AttachUserPolicy", "iam:PutUserPolicy"})


def test_non_default_version_granting_an_admin_action_is_detected():
    """Rolling back only escalates when the older version grants something
    administrative."""
    policy = Policy("arn:p", "p", (
        PolicyVersion("v1", (Statement(Effect.ALLOW, ("s3:Get*",)),), True),
        PolicyVersion("v2", (Statement(Effect.ALLOW, ("iam:*",)),), False),
    ))
    assert policy.grants_in_a_non_default_version(ADMIN_ACTIONS)


def test_a_merely_different_version_is_not_an_escalation():
    """Regression: any difference between versions read as an escalation, so a
    rollback from s3:Get to s3:List was reported as a path to admin."""
    policy = Policy("arn:p", "p", (
        PolicyVersion("v1", (Statement(Effect.ALLOW, ("s3:Get*",)),), True),
        PolicyVersion("v2", (Statement(Effect.ALLOW, ("s3:List*",)),), False),
    ))
    assert not policy.grants_in_a_non_default_version(ADMIN_ACTIONS)


def test_a_narrower_older_version_is_not_an_escalation():
    policy = Policy("arn:p", "p", (
        PolicyVersion("v1", (Statement(Effect.ALLOW, ("iam:*", "s3:Get*")),), True),
        PolicyVersion("v2", (Statement(Effect.ALLOW, ("s3:Get*",)),), False),
    ))
    assert not policy.grants_in_a_non_default_version(ADMIN_ACTIONS)


def test_deny_inside_a_version_blocks_the_escalation():
    policy = Policy("arn:p", "p", (
        PolicyVersion("v1", (Statement(Effect.ALLOW, ("s3:Get*",)),), True),
        PolicyVersion("v2", (
            Statement(Effect.ALLOW, ("*",)),
            Statement(Effect.DENY, ("iam:*",)),
        ), False),
    ))
    assert not policy.grants_in_a_non_default_version(ADMIN_ACTIONS)


def test_single_version_policy_cannot_be_rolled_back():
    policy = Policy("arn:p", "p", (PolicyVersion("v1", (Statement(Effect.ALLOW, ("*",)),), True),))
    assert not policy.grants_in_a_non_default_version(ADMIN_ACTIONS)


def test_default_version_falls_back_to_the_first():
    policy = Policy("arn:p", "p", (PolicyVersion("v1", (Statement(Effect.ALLOW, ("s3:*",)),), False),))
    assert policy.default_version.version_id == "v1"


def test_trust_policy_matches_by_pattern():
    account = new_account()
    role(account, "r:a", trusts=("u:ops", "u:deploy-*"))
    trust = account.principals["r:a"].trust_policy
    assert trust.trusts("u:ops")
    assert trust.trusts("u:deploy-ci")
    assert not trust.trusts("u:dev")


def test_empty_trust_policy_trusts_nobody():
    account = new_account()
    role(account, "r:a")
    assert not account.principals["r:a"].trust_policy.trusts("u:anyone")
