"""Edge construction. A missing edge is a principal wrongly reported contained."""


from tests.conftest import ADMIN_ARN, allow, deny, group, new_account, role, user

from ibr.graph.build import build_graph, is_admin_equivalent
from ibr.graph.edges import DEFINITIONS, EdgeKind


def _graph(account, config):
    return build_graph(account, config)


def test_every_edge_kind_has_a_definition():
    assert {d.kind for d in DEFINITIONS} == set(EdgeKind)


def test_every_definition_states_its_rationale():
    """An edge without a reason is one nobody can defend in a review."""
    for definition in DEFINITIONS:
        assert definition.technique.strip()
        assert len(definition.rationale) > 40, definition.kind


def test_assume_role_requires_the_trust_policy_to_name_the_principal(config):
    """The check most commonly skipped. Without it, every principal holding
    sts:AssumeRole becomes a path to every role in the account."""
    account = new_account()
    role(account, "r:admin", policies=(ADMIN_ARN,), trusts=("u:ops",))
    user(account, "u:ops", allow("sts:AssumeRole"))
    user(account, "u:dev", allow("sts:AssumeRole"))
    graph = _graph(account, config)
    assert graph.has_edge("u:ops", "r:admin")
    assert not graph.has_edge("u:dev", "r:admin")


def test_pass_role_requires_the_role_to_trust_the_service(config):
    """Regression: iam:PassRole plus lambda:CreateFunction created an edge to
    every role, including roles that trust no service and so cannot back a
    function at all."""
    account = new_account()
    role(account, "r:fn", policies=(ADMIN_ARN,), services=("lambda.amazonaws.com",))
    role(account, "r:locked", policies=(ADMIN_ARN,))
    user(account, "u:a", allow("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"))
    graph = _graph(account, config)
    assert graph.has_edge("u:a", "r:fn")
    assert not graph.has_edge("u:a", "r:locked")


def test_pass_role_to_ec2_requires_ec2_trust(config):
    account = new_account()
    role(account, "r:instance", policies=(ADMIN_ARN,), services=("ec2.amazonaws.com",))
    role(account, "r:fn", policies=(ADMIN_ARN,), services=("lambda.amazonaws.com",))
    user(account, "u:a", allow("iam:PassRole", "ec2:RunInstances"))
    graph = _graph(account, config)
    assert graph.has_edge("u:a", "r:instance")
    assert not graph.has_edge("u:a", "r:fn")


def test_pass_role_needs_every_required_action(config):
    """Each action alone is unremarkable, which is why this family is missed."""
    account = new_account()
    role(account, "r:fn", policies=(ADMIN_ARN,), services=("lambda.amazonaws.com",))
    user(account, "u:partial", allow("lambda:CreateFunction", "lambda:InvokeFunction"))
    user(account, "u:full", allow("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"))
    graph = _graph(account, config)
    assert not graph.has_edge("u:partial", "r:fn")
    assert graph.has_edge("u:full", "r:fn")


def test_self_scoped_escalation_is_not_a_path(config):
    """A principal allowed iam:CreateAccessKey only on its own ARN looks
    alarming in a policy grep and reaches nobody."""
    account = new_account()
    user(account, "u:a", allow("iam:CreateAccessKey", resources=("u:a",)))
    user(account, "u:b", allow("s3:GetObject"))
    graph = _graph(account, config)
    assert list(graph.out_edges("u:a")) == []


def test_unscoped_escalation_reaches_every_user(config):
    account = new_account()
    user(account, "u:a", allow("iam:CreateAccessKey"))
    user(account, "u:b", allow("s3:GetObject"))
    user(account, "u:c", allow("s3:GetObject"))
    graph = _graph(account, config)
    assert {t for _, t in graph.out_edges("u:a")} == {"u:b", "u:c"}


def test_edges_respect_the_target_principal_type(config):
    """CreateAccessKey against a role is not a thing."""
    account = new_account()
    role(account, "r:a", policies=(ADMIN_ARN,), services=("lambda.amazonaws.com",))
    user(account, "u:target", allow("s3:GetObject"))
    user(account, "u:a", allow("iam:CreateAccessKey"))
    graph = _graph(account, config)
    assert graph.has_edge("u:a", "u:target")
    assert not graph.has_edge("u:a", "r:a")


def test_add_user_to_group_only_targets_groups(config):
    account = new_account()
    group(account, "g:admins", allow("*"))
    user(account, "u:other", allow("s3:GetObject"))
    user(account, "u:a", allow("iam:AddUserToGroup"))
    graph = _graph(account, config)
    assert graph.has_edge("u:a", "g:admins")
    assert not graph.has_edge("u:a", "u:other")


def test_no_self_edges(config):
    account = new_account()
    user(account, "u:a", allow("iam:CreateAccessKey"))
    user(account, "u:b", allow("s3:GetObject"))
    graph = _graph(account, config)
    assert not graph.has_edge("u:a", "u:a")


def test_explicit_deny_removes_an_edge(config):
    account = new_account()
    user(account, "u:a", allow("iam:*"), deny("iam:CreateAccessKey"))
    user(account, "u:b", allow("s3:GetObject"))
    graph = _graph(account, config)
    data = graph.get_edge_data("u:a", "u:b")
    assert data is None or data["kind"] != EdgeKind.CREATE_ACCESS_KEY.value


def test_conditional_edge_is_flagged(config):
    account = new_account()
    role(account, "r:fn", policies=(ADMIN_ARN,), services=("lambda.amazonaws.com",))
    user(account, "u:a", allow("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction",
                               conditions=("iam:PassedToService",)))
    graph = _graph(account, config)
    assert graph.edges["u:a", "r:fn"]["conditional"] is True


def test_conditional_edges_are_dropped_when_configured(config):
    from dataclasses import replace

    account = new_account()
    role(account, "r:fn", policies=(ADMIN_ARN,), services=("lambda.amazonaws.com",))
    user(account, "u:a", allow("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction",
                               conditions=("iam:PassedToService",)))
    graph = _graph(account, replace(config, assume_conditions_satisfiable=False))
    assert not graph.has_edge("u:a", "r:fn")


def test_policy_rollback_is_self_escalation_not_an_edge(config):
    """Rolling a policy back grants the principal more of its own privileges.
    An edge means "A obtains B's privileges" and there is no B here, so this is
    evaluated as admin equivalence rather than as a graph edge."""
    from ibr.account.model import Effect, Policy, PolicyVersion, Statement

    account = new_account()
    account.policies["arn:wide"] = Policy("arn:wide", "wide", (
        PolicyVersion("v1", (Statement(Effect.ALLOW, ("s3:Get*",)),), True),
        PolicyVersion("v2", (Statement(Effect.ALLOW, ("iam:*",)),), False),
    ))
    user(account, "u:rollback", allow("iam:SetDefaultPolicyVersion"), policies=("arn:wide",))
    user(account, "u:other", allow("s3:GetObject"))
    graph = _graph(account, config)
    assert graph.nodes["u:rollback"]["admin"] is True
    assert not graph.has_edge("u:rollback", "u:other")


def test_rollback_to_a_harmless_version_is_not_escalation(config):
    """Regression: any difference between versions read as an escalation, so
    rolling back from s3:Get to s3:List was reported as a path to admin."""
    from ibr.account.model import Effect, Policy, PolicyVersion, Statement

    account = new_account()
    account.policies["arn:narrow"] = Policy("arn:narrow", "narrow", (
        PolicyVersion("v1", (Statement(Effect.ALLOW, ("s3:Get*",)),), True),
        PolicyVersion("v2", (Statement(Effect.ALLOW, ("s3:List*",)),), False),
    ))
    user(account, "u:rollback", allow("iam:SetDefaultPolicyVersion"), policies=("arn:narrow",))
    graph = _graph(account, config)
    assert graph.nodes["u:rollback"]["admin"] is False


def test_rollback_without_the_action_is_not_escalation(config):
    from ibr.account.model import Effect, Policy, PolicyVersion, Statement

    account = new_account()
    account.policies["arn:wide"] = Policy("arn:wide", "wide", (
        PolicyVersion("v1", (Statement(Effect.ALLOW, ("s3:Get*",)),), True),
        PolicyVersion("v2", (Statement(Effect.ALLOW, ("iam:*",)),), False),
    ))
    user(account, "u:plain", allow("s3:GetObject"), policies=("arn:wide",))
    graph = _graph(account, config)
    assert graph.nodes["u:plain"]["admin"] is False


def test_admin_equivalence_respects_deny(config):
    account = new_account()
    user(account, "u:power", allow("*"), deny("iam:*"), deny("organizations:*"))
    user(account, "u:admin", allow("*"))
    assert is_admin_equivalent(account, "u:admin")
    assert not is_admin_equivalent(account, "u:power")


def test_admin_principals_are_not_enumerated_as_sources(config):
    """An administrator reaches everything by definition. Enumerating those
    edges adds entries nobody acts on and dominates the graph."""
    account = new_account()
    user(account, "u:admin", allow("*"))
    for index in range(5):
        user(account, f"u:{index}", allow("s3:GetObject"))
    graph = _graph(account, config)
    assert graph.nodes["u:admin"]["admin"] is True
    assert list(graph.out_edges("u:admin")) == []


def test_unconditional_edge_is_preferred_over_a_conditional_one(config):
    """A reader fixing a path wants the edge that definitely works."""
    account = new_account()
    user(account, "u:target", allow("s3:GetObject"))
    user(account, "u:a",
         allow("iam:CreateAccessKey", conditions=("aws:SourceIp",)),
         allow("iam:UpdateLoginProfile"))
    graph = _graph(account, config)
    assert graph.edges["u:a", "u:target"]["conditional"] is False


def test_node_carries_tags_and_type(config):
    account = new_account()
    user(account, "u:a", allow("s3:GetObject"), tags=("least-privilege", "team:web"))
    graph = _graph(account, config)
    assert graph.nodes["u:a"]["tags"] == ["least-privilege", "team:web"]
    assert graph.nodes["u:a"]["principal_type"] == "user"


def test_empty_account_builds_an_empty_graph(config):
    graph = _graph(new_account(), config)
    assert graph.number_of_nodes() == 0
    assert graph.number_of_edges() == 0


def test_candidate_targets_is_empty_without_the_action(config):
    from ibr.graph.build import _candidate_targets
    from ibr.graph.edges import BY_KIND, EdgeKind

    account = new_account()
    user(account, "u:a", allow("s3:GetObject"))
    candidates = _candidate_targets(
        account, BY_KIND[EdgeKind.CREATE_ACCESS_KEY], "u:a", tuple(account.principals)
    )
    assert candidates == []


def test_candidate_targets_intersects_across_required_actions(config):
    """What makes the PassRole family cheap: plenty of principals hold
    lambda:CreateFunction and very few also hold iam:PassRole."""
    from ibr.graph.build import _candidate_targets
    from ibr.graph.edges import BY_KIND, EdgeKind

    account = new_account()
    role(account, "r:a", policies=(ADMIN_ARN,), services=("lambda.amazonaws.com",))
    role(account, "r:b", policies=(ADMIN_ARN,), services=("lambda.amazonaws.com",))
    user(account, "u:a",
         allow("iam:PassRole", resources=("r:a",)),
         allow("lambda:CreateFunction", "lambda:InvokeFunction"))
    candidates = _candidate_targets(
        account, BY_KIND[EdgeKind.PASS_ROLE_TO_LAMBDA], "u:a", tuple(account.principals)
    )
    assert candidates == ["r:a"]


def test_candidate_targets_resolves_a_glob_pattern(config):
    from ibr.graph.build import _candidate_targets
    from ibr.graph.edges import BY_KIND, EdgeKind

    account = new_account()
    user(account, "u:dev-1", allow("s3:GetObject"))
    user(account, "u:dev-2", allow("s3:GetObject"))
    user(account, "u:prod-1", allow("s3:GetObject"))
    user(account, "u:a", allow("iam:CreateAccessKey", resources=("u:dev-*",)))
    candidates = _candidate_targets(
        account, BY_KIND[EdgeKind.CREATE_ACCESS_KEY], "u:a", tuple(account.principals)
    )
    assert candidates == ["u:dev-1", "u:dev-2"]


def test_candidate_targets_for_an_unresolvable_pattern_is_empty(config):
    from ibr.graph.build import _candidate_targets
    from ibr.graph.edges import BY_KIND, EdgeKind

    account = new_account()
    user(account, "u:a", allow("iam:CreateAccessKey", resources=("u:nobody",)))
    candidates = _candidate_targets(
        account, BY_KIND[EdgeKind.CREATE_ACCESS_KEY], "u:a", tuple(account.principals)
    )
    assert candidates == []


def test_assume_role_with_a_conditional_trust_policy_is_flagged(config):
    account = new_account()
    role(account, "r:admin", policies=(ADMIN_ARN,), trusts=("u:a",), conditions=("sts:ExternalId",))
    user(account, "u:a", allow("sts:AssumeRole"))
    graph = build_graph(account, config)
    assert graph.edges["u:a", "r:admin"]["conditional"] is True


def test_update_assume_role_policy_defeats_a_point_in_time_trust_read(config):
    """A trust relationship the attacker can rewrite is not a boundary."""
    account = new_account()
    role(account, "r:admin", policies=(ADMIN_ARN,), trusts=())
    user(account, "u:a", allow("iam:UpdateAssumeRolePolicy", "sts:AssumeRole"))
    graph = build_graph(account, config)
    assert graph.has_edge("u:a", "r:admin")
    assert graph.edges["u:a", "r:admin"]["kind"] == "update_assume_role_policy"
