import json

import pytest
from tests.conftest import ADMIN_ARN, allow, new_account, role, user

from ibr.graph.build import build_graph
from ibr.graph.reach import analyse
from ibr.report.render import TABLE_LIMIT, render_html, render_json, to_dict


def _report(config):
    account = new_account()
    role(account, "r:admin", policies=(ADMIN_ARN,), trusts=("u:ops",))
    user(account, "u:ops", allow("sts:AssumeRole", resources=("r:admin",)))
    user(account, "u:dev", allow("iam:CreateAccessKey", resources=("u:ops",)), tags=("least-privilege",))
    user(account, "u:contained", allow("s3:GetObject"), tags=("least-privilege",))
    return analyse(build_graph(account, config), account.account_id, config)


def test_dict_carries_the_headline(config):
    payload = to_dict(_report(config))
    assert payload["account"]["mislabelled"] == 1
    assert payload["account"]["mislabelled_pct"] == pytest.approx(50.0)
    assert payload["account"]["by_hop"]["1"] == 1


def test_every_finding_carries_its_path_or_none(config):
    payload = to_dict(_report(config))
    for finding in payload["findings"]:
        if finding["reaches_admin"]:
            assert finding["shortest_path"]["steps"]
        else:
            assert finding["shortest_path"] is None


def test_json_render_is_valid(tmp_path, config):
    path = render_json(_report(config), tmp_path / "out" / "r.json")
    assert json.loads(path.read_text(encoding="utf-8"))["account"]["principals"] == 4


def test_html_leads_with_the_mislabelled_percentage(tmp_path, config):
    html = render_html(_report(config), tmp_path / "r.html").read_text(encoding="utf-8")
    assert "<!doctype html>" in html
    assert "50.0" in html
    assert "prefers-color-scheme: dark" in html


def test_html_escapes_principal_ids(tmp_path, config):
    account = new_account()
    role(account, "r:admin", policies=(ADMIN_ARN,))
    user(account, "<script>alert(1)</script>", allow("s3:GetObject"))
    report = analyse(build_graph(account, config), account.account_id, config)
    html = render_html(report, tmp_path / "r.html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_status_is_not_carried_by_colour_alone(tmp_path, config):
    html = render_html(_report(config), tmp_path / "r.html").read_text(encoding="utf-8")
    assert 'content: "A"' in html and 'content: "!"' in html and 'content: "ok"' in html
    assert ">admin<" in html and ">reaches<" in html and ">contained<" in html


def test_html_has_a_skip_link_and_captions(tmp_path, config):
    html = render_html(_report(config), tmp_path / "r.html").read_text(encoding="utf-8")
    assert 'class="skip" href="#findings"' in html
    assert html.count("<caption>") >= 2


def test_html_states_the_scope_limits(tmp_path, config):
    """A reader has to know what the tool did not evaluate."""
    html = render_html(_report(config), tmp_path / "r.html").read_text(encoding="utf-8")
    assert "Permission boundaries" in html
    assert "not evaluated" in html


def test_table_is_truncated_but_json_is_not(tmp_path, config):
    account = new_account()
    role(account, "r:admin", policies=(ADMIN_ARN,))
    for index in range(TABLE_LIMIT + 20):
        user(account, f"u:{index:04d}", allow("s3:GetObject"))
    report = analyse(build_graph(account, config), account.account_id, config)
    html = render_html(report, tmp_path / "r.html").read_text(encoding="utf-8")
    assert "Showing" in html
    assert len(to_dict(report)["findings"]) == TABLE_LIMIT + 21


def test_every_colour_pair_meets_its_contrast_threshold():
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(root / "tools" / "check_contrast.py")],
        cwd=root, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_every_declared_dependency_is_used():
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(root / "tools" / "check_dependencies.py")],
        cwd=root, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
