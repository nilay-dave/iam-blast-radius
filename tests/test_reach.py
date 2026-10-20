"""Reachability. A wrong distance is a principal wrongly reported contained."""

import pytest
from tests.conftest import ADMIN_ARN, allow, new_account, role, user

from ibr.graph.build import build_graph
from ibr.graph.reach import (
    admin_distances,
    analyse,
    distinct_first_steps,
    path_from,
    paths_to_admin,
    reachable_within,
)


def _chain(account):
    """dev -> ops -> admin role. Two hops, with dev labelled least privilege."""
    role(account, "r:admin", policies=(ADMIN_ARN,), trusts=("u:ops",))
    user(account, "u:ops", allow("sts:AssumeRole", resources=("r:admin",)))
    user(account, "u:dev", allow("iam:CreateAccessKey", resources=("u:ops",)), tags=("least-privilege",))
    user(account, "u:contained", allow("s3:GetObject"), tags=("least-privilege",))
    return account


def test_distance_labels_every_principal(config):
    graph = build_graph(_chain(new_account()), config)
    distances = admin_distances(graph, config.max_hops)
    assert distances.distance["r:admin"] == 0
    assert distances.distance["u:ops"] == 1
    assert distances.distance["u:dev"] == 2
    assert "u:contained" not in distances.distance


def test_distance_respects_the_hop_cap(config):
    from dataclasses import replace

    graph = build_graph(_chain(new_account()), config)
    distances = admin_distances(graph, 1)
    assert "u:ops" in distances.distance
    assert "u:dev" not in distances.distance
    del replace


def test_path_is_reconstructed_from_next_hop(config):
    graph = build_graph(_chain(new_account()), config)
    distances = admin_distances(graph, config.max_hops)
    path = path_from(graph, "u:dev", distances)
    assert path.principals == ("u:dev", "u:ops", "r:admin")
    assert path.hops == 2
    assert [s.kind for s in path.steps] == ["create_access_key", "assume_role"]


def test_path_for_an_admin_is_none(config):
    graph = build_graph(_chain(new_account()), config)
    distances = admin_distances(graph, config.max_hops)
    assert path_from(graph, "r:admin", distances) is None


def test_path_for_a_contained_principal_is_none(config):
    graph = build_graph(_chain(new_account()), config)
    distances = admin_distances(graph, config.max_hops)
    assert path_from(graph, "u:contained", distances) is None


def test_distinct_first_steps_counts_statements_to_remove(config):
    """The number a reader acts on: how many separate statements have to go."""
    account = new_account()
    role(account, "r:a", policies=(ADMIN_ARN,), trusts=("u:a",))
    role(account, "r:b", policies=(ADMIN_ARN,), trusts=("u:a",))
    user(account, "u:a", allow("sts:AssumeRole"))
    graph = build_graph(account, config)
    distances = admin_distances(graph, config.max_hops)
    assert distinct_first_steps(graph, "u:a", distances) == 2


def test_distinct_first_steps_is_zero_for_a_contained_principal(config):
    graph = build_graph(_chain(new_account()), config)
    distances = admin_distances(graph, config.max_hops)
    assert distinct_first_steps(graph, "u:contained", distances) == 0


def test_reachable_within_counts_the_blast_radius(config):
    graph = build_graph(_chain(new_account()), config)
    reachable = reachable_within(graph, "u:dev", 3)
    assert set(reachable) == {"u:ops", "r:admin"}
    assert reachable["u:ops"] == 1
    assert reachable["r:admin"] == 2


def test_reachable_within_rejects_an_unknown_principal(config):
    graph = build_graph(_chain(new_account()), config)
    with pytest.raises(KeyError):
        reachable_within(graph, "u:nobody", 3)


def test_report_separates_admins_from_escalators(config):
    account = _chain(new_account())
    report = analyse(build_graph(account, config), account.account_id, config)
    assert [f.principal_id for f in report.admin_principals] == ["r:admin"]
    assert {f.principal_id for f in report.escalating} == {"u:ops", "u:dev"}


def test_mislabelled_is_the_headline(config):
    """A label records intent. Reachability records fact. The gap is the point."""
    account = _chain(new_account())
    report = analyse(build_graph(account, config), account.account_id, config)
    assert {f.principal_id for f in report.labelled_least_privilege} == {"u:dev", "u:contained"}
    assert [f.principal_id for f in report.mislabelled] == ["u:dev"]
    assert report.mislabelled_pct == pytest.approx(50.0)


def test_mislabelled_pct_is_zero_when_nothing_is_labelled(config):
    account = new_account()
    role(account, "r:admin", policies=(ADMIN_ARN,))
    user(account, "u:a", allow("s3:GetObject"))
    report = analyse(build_graph(account, config), account.account_id, config)
    assert report.mislabelled_pct == 0.0


def test_escalating_pct_excludes_principals_that_are_already_admin(config):
    """Counting administrators as escalating would inflate the number with
    principals that have nothing to escalate to."""
    account = _chain(new_account())
    report = analyse(build_graph(account, config), account.account_id, config)
    non_admin = report.principal_count - len(report.admin_principals)
    assert report.escalating_pct == pytest.approx(100.0 * 2 / non_admin)


def test_findings_are_sorted_nearest_first(config):
    account = _chain(new_account())
    report = analyse(build_graph(account, config), account.account_id, config)
    hops = [f.hops_to_admin for f in report.findings if f.hops_to_admin is not None]
    assert hops == sorted(hops)


def test_at_hop_buckets_correctly(config):
    account = _chain(new_account())
    report = analyse(build_graph(account, config), account.account_id, config)
    assert [f.principal_id for f in report.at_hop(1)] == ["u:ops"]
    assert [f.principal_id for f in report.at_hop(2)] == ["u:dev"]
    assert report.at_hop(3) == []


def test_blast_radius_is_not_computed_by_default(config):
    """It is a breadth first search per principal, which is quadratic over the
    account while every other number comes from one traversal."""
    account = _chain(new_account())
    report = analyse(build_graph(account, config), account.account_id, config)
    assert all(f.reachable_within_max_hops == -1 for f in report.findings)


def test_blast_radius_is_computed_on_request(config):
    account = _chain(new_account())
    report = analyse(build_graph(account, config), account.account_id, config, with_blast_radius=True)
    finding = next(f for f in report.findings if f.principal_id == "u:dev")
    assert finding.reachable_within_max_hops == 2


def test_conditional_only_is_flagged(config):
    account = new_account()
    role(account, "r:fn", policies=(ADMIN_ARN,), services=("lambda.amazonaws.com",))
    user(account, "u:a", allow("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction",
                               conditions=("iam:PassedToService",)))
    report = analyse(build_graph(account, config), account.account_id, config)
    finding = next(f for f in report.findings if f.principal_id == "u:a")
    assert finding.reaches_admin
    assert finding.conditional_only


def test_paths_to_admin_enumerates_distinct_routes(config):
    account = new_account()
    role(account, "r:a", policies=(ADMIN_ARN,), trusts=("u:a",))
    role(account, "r:b", policies=(ADMIN_ARN,), trusts=("u:a",))
    user(account, "u:a", allow("sts:AssumeRole"))
    graph = build_graph(account, config)
    found = [p for p in paths_to_admin(graph, "u:a", config) if p.steps]
    assert len(found) == 2


def test_paths_to_admin_is_capped(config):
    from dataclasses import replace

    account = new_account()
    for index in range(10):
        role(account, f"r:{index}", policies=(ADMIN_ARN,), trusts=("u:a",))
    user(account, "u:a", allow("sts:AssumeRole"))
    graph = build_graph(account, config)
    found = paths_to_admin(graph, "u:a", replace(config, max_paths_per_principal=3))
    assert len(found) == 3


def test_paths_to_admin_for_an_admin_returns_the_empty_path(config):
    account = _chain(new_account())
    graph = build_graph(account, config)
    found = paths_to_admin(graph, "r:admin", config)
    assert len(found) == 1 and found[0].steps == ()
    assert found[0].describe() == "already administrative"


def test_path_describe_renders_the_chain(config):
    graph = build_graph(_chain(new_account()), config)
    distances = admin_distances(graph, config.max_hops)
    assert path_from(graph, "u:dev", distances).describe() == "u:dev -> u:ops -> r:admin"


def test_empty_graph_analyses_without_error(config):
    report = analyse(build_graph(new_account(), config), "111122223333", config)
    assert report.principal_count == 0
    assert report.escalating_pct == 0.0
    assert report.mislabelled_pct == 0.0
