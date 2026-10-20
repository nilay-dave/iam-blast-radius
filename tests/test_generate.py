import pytest

from ibr.account.generate import SHAPE_SHARES, generate
from ibr.account.serialise import read_account
from ibr.graph.build import build_graph
from ibr.graph.reach import analyse


def test_too_small_an_account_is_refused(tmp_path):
    with pytest.raises(ValueError, match="at least 10"):
        generate(tmp_path / "a.json", 5)


def test_shares_sum_to_one():
    assert abs(sum(SHAPE_SHARES.values()) - 1.0) < 1e-9


def test_generation_is_deterministic(tmp_path):
    first = read_account(generate(tmp_path / "a.json", 200, seed=11).path)
    second = read_account(generate(tmp_path / "b.json", 200, seed=11).path)
    assert first.principals == second.principals


def test_different_seeds_differ(tmp_path):
    first = read_account(generate(tmp_path / "a.json", 200, seed=11).path)
    second = read_account(generate(tmp_path / "b.json", 200, seed=12).path)
    assert first.principals != second.principals


def test_every_shape_is_present_even_in_a_small_account(tmp_path):
    """A small account must still exercise every path the tool claims to find."""
    result = generate(tmp_path / "a.json", 12, seed=3)
    assert all(count > 0 for count in result.shapes.values()), result.shapes


def test_account_contains_self_scoped_principals_that_are_not_paths(tmp_path, config):
    """The shape a policy grep gets wrong. If the generator stopped producing
    them, the resource scoping would have nothing to get right."""
    result = generate(tmp_path / "a.json", 400, seed=5)
    assert result.shapes["self_scoped"] > 0
    graph = build_graph(result.account, config)

    self_scoped = [
        principal_id for principal_id, principal in result.account.principals.items()
        if any(
            s.resources == (principal_id,)
            for s in principal.inline_statements
        )
    ]
    assert self_scoped
    assert any(graph.out_degree(principal_id) == 0 for principal_id in self_scoped)


def test_generated_account_has_principals_at_more_than_one_hop(tmp_path, config):
    """A generator that only produced one hop paths would never exercise the
    multi hop traversal."""
    result = generate(tmp_path / "a.json", 500, seed=7)
    report = analyse(build_graph(result.account, config), result.account.account_id, config)
    assert len(report.at_hop(1)) > 0
    assert len(report.at_hop(2)) > 0


def test_least_privilege_labels_are_independent_of_reachability(tmp_path, config):
    """The headline only means something if the label is applied without
    reference to the truth. Both labelled escalators and labelled contained
    principals must exist."""
    result = generate(tmp_path / "a.json", 500, seed=7)
    report = analyse(build_graph(result.account, config), result.account.account_id, config)
    labelled = report.labelled_least_privilege
    assert labelled
    assert any(f.reaches_admin or f.already_admin for f in labelled)
    assert any(not f.reaches_admin and not f.already_admin for f in labelled)


def test_admin_roles_trust_the_services_that_make_pass_role_work(tmp_path):
    result = generate(tmp_path / "a.json", 200, seed=4)
    admin_roles = [p for p in result.account.principals.values() if p.principal_id.startswith("role/admin")]
    assert admin_roles
    for principal in admin_roles:
        assert "lambda.amazonaws.com" in principal.trust_policy.trusted_services


def test_written_account_reads_back(tmp_path):
    result = generate(tmp_path / "a.json", 100, seed=2)
    assert read_account(result.path).account_id == result.account.account_id
