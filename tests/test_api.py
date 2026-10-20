"""The query service. No network, no credentials, no AWS."""

import pytest
from fastapi.testclient import TestClient
from tests.conftest import ADMIN_ARN, allow, new_account, role, user

from ibr.account.serialise import write_account
from ibr.api.service import create_app


@pytest.fixture
def client(tmp_path, config):
    account = new_account()
    role(account, "r:admin", policies=(ADMIN_ARN,), trusts=("u:ops",))
    user(account, "u:ops", allow("sts:AssumeRole", resources=("r:admin",)))
    user(account, "u:dev", allow("iam:CreateAccessKey", resources=("u:ops",)), tags=("least-privilege",))
    user(account, "u:contained", allow("s3:GetObject"), tags=("least-privilege",))
    path = write_account(account, tmp_path / "account.json")
    return TestClient(create_app(path, config))


def test_health_reports_a_loaded_account(client):
    payload = client.get("/health").json()
    assert payload["status"] == "ok"
    assert payload["account_loaded"] is True
    assert payload["principals"] == 4


def test_summary_carries_the_headline(client):
    payload = client.get("/summary").json()
    assert payload["principals"] == 4
    assert payload["already_admin"] == 1
    assert payload["escalating"] == 2
    assert payload["mislabelled"] == 1
    assert payload["mislabelled_pct"] == pytest.approx(50.0)
    assert payload["by_hop"]["1"] == 1
    assert payload["by_hop"]["2"] == 1


def test_blast_radius_returns_hop_distances(client):
    payload = client.get("/principals/u:dev/blast-radius").json()
    assert payload["reaches_admin"] is True
    assert payload["hops_to_admin"] == 2
    assert payload["reachable"] == {"u:ops": 1, "r:admin": 2}
    assert payload["shortest_path"]["principals"] == ["u:dev", "u:ops", "r:admin"]


def test_blast_radius_step_carries_the_technique(client):
    """A number tells somebody there is a problem. The technique tells them
    which statement to delete."""
    steps = client.get("/principals/u:dev/blast-radius").json()["shortest_path"]["steps"]
    assert [s["kind"] for s in steps] == ["create_access_key", "assume_role"]
    assert all(s["technique"].strip() for s in steps)


def test_blast_radius_respects_a_hop_override(client):
    payload = client.get("/principals/u:dev/blast-radius", params={"max_hops": 1}).json()
    assert payload["max_hops"] == 1
    assert payload["reachable"] == {"u:ops": 1}


def test_blast_radius_of_a_contained_principal_is_empty(client):
    payload = client.get("/principals/u:contained/blast-radius").json()
    assert payload["reaches_admin"] is False
    assert payload["reachable"] == {}
    assert payload["shortest_path"] is None


def test_blast_radius_of_an_admin_says_so(client):
    payload = client.get("/principals/r:admin/blast-radius").json()
    assert payload["already_admin"] is True
    assert payload["hops_to_admin"] is None


def test_unknown_principal_is_a_404(client):
    assert client.get("/principals/u:nobody/blast-radius").status_code == 404
    assert client.get("/principals/u:nobody/paths-to-admin").status_code == 404


def test_paths_endpoint_enumerates_routes(client):
    payload = client.get("/principals/u:dev/paths-to-admin").json()
    assert len(payload) == 1
    assert payload[0]["hops"] == 2


def test_paths_endpoint_is_empty_for_a_contained_principal(client):
    assert client.get("/principals/u:contained/paths-to-admin").json() == []


def test_principal_ids_containing_slashes_resolve(tmp_path, config):
    """Real principal ids look like role/admin-001, so the route has to accept
    a path segment rather than a bare identifier."""
    account = new_account()
    role(account, "role/admin-001", policies=(ADMIN_ARN,), trusts=("user/app-0001",))
    user(account, "user/app-0001", allow("sts:AssumeRole", resources=("role/admin-001",)))
    path = write_account(account, tmp_path / "account.json")
    client = TestClient(create_app(path, config))
    payload = client.get("/principals/user/app-0001/blast-radius").json()
    assert payload["hops_to_admin"] == 1


def test_service_without_an_account_returns_503(config):
    from ibr.api import service

    service.state.account = None
    service.state.graph = None
    client = TestClient(create_app(None, config))
    assert client.get("/health").json()["account_loaded"] is False
    assert client.get("/summary").status_code == 503
