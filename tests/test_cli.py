import json

from tests.conftest import ADMIN_ARN, allow, new_account, role, user
from typer.testing import CliRunner

from ibr import __version__
from ibr.account.serialise import write_account
from ibr.cli import app

runner = CliRunner()


def _account(tmp_path):
    account = new_account()
    role(account, "r:admin", policies=(ADMIN_ARN,), trusts=("u:ops",))
    user(account, "u:ops", allow("sts:AssumeRole", resources=("r:admin",)))
    user(account, "u:dev", allow("iam:CreateAccessKey", resources=("u:ops",)), tags=("least-privilege",))
    user(account, "u:contained", allow("s3:GetObject"), tags=("least-privilege",))
    return write_account(account, tmp_path / "account.json")


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == __version__


def test_version_matches_package_metadata():
    from importlib.metadata import version

    assert __version__ == version("iam-blast-radius")


def test_generate_writes_an_account(tmp_path):
    out = tmp_path / "a.json"
    result = runner.invoke(app, ["generate", "--principals", "100", "--out", str(out), "--seed", "3"])
    assert result.exit_code == 0
    assert out.exists()
    assert "principals to" in result.output


def test_generate_refuses_a_tiny_account(tmp_path):
    result = runner.invoke(app, ["generate", "--principals", "5", "--out", str(tmp_path / "a.json")])
    assert result.exit_code != 0


def test_analyse_reports_the_headline(tmp_path):
    result = runner.invoke(app, ["analyse", "--account", str(_account(tmp_path))])
    assert result.exit_code == 0
    assert "labelled least privilege" in result.output
    assert "of those, reach admin    1 (50.0%)" in result.output


def test_analyse_writes_html_and_json(tmp_path):
    html, js = tmp_path / "r.html", tmp_path / "r.json"
    result = runner.invoke(app, [
        "analyse", "--account", str(_account(tmp_path)), "--out", str(html), "--json", str(js),
    ])
    assert result.exit_code == 0
    assert "<!doctype html>" in html.read_text(encoding="utf-8")
    payload = json.loads(js.read_text(encoding="utf-8"))
    assert payload["account"]["mislabelled"] == 1


def test_analyse_respects_a_hop_override(tmp_path):
    result = runner.invoke(app, ["analyse", "--account", str(_account(tmp_path)), "--max-hops", "1"])
    assert result.exit_code == 0
    assert "at 1 hop(s)         1" in result.output
    assert "at 2 hop(s)" not in result.output


def test_strict_conditions_drops_conditional_edges(tmp_path):
    account = new_account()
    role(account, "r:fn", policies=(ADMIN_ARN,), services=("lambda.amazonaws.com",))
    user(account, "u:a", allow("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction",
                               conditions=("iam:PassedToService",)))
    path = write_account(account, tmp_path / "a.json")

    lenient = runner.invoke(app, ["analyse", "--account", str(path)])
    strict = runner.invoke(app, ["analyse", "--account", str(path), "--strict-conditions"])
    assert "reach admin           1" in lenient.output
    assert "reach admin           0" in strict.output


def test_analyse_rejects_a_missing_account(tmp_path):
    result = runner.invoke(app, ["analyse", "--account", str(tmp_path / "nope.json")])
    assert result.exit_code != 0


def test_gate_fails_above_the_one_hop_limit(tmp_path):
    result = runner.invoke(app, [
        "gate", "--account", str(_account(tmp_path)), "--max-one-hop", "0", "--max-mislabelled-pct", "100",
    ])
    assert result.exit_code == 2
    assert "reach admin in one hop" in result.output


def test_gate_fails_above_the_mislabelled_limit(tmp_path):
    result = runner.invoke(app, [
        "gate", "--account", str(_account(tmp_path)), "--max-one-hop", "100", "--max-mislabelled-pct", "10",
    ])
    assert result.exit_code == 2
    assert "least-privilege labelled principals reach admin" in result.output


def test_gate_passes_within_limits(tmp_path):
    result = runner.invoke(app, [
        "gate", "--account", str(_account(tmp_path)), "--max-one-hop", "10", "--max-mislabelled-pct", "100",
    ])
    assert result.exit_code == 0
    assert "PASS" in result.output
