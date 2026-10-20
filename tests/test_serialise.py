import json

import pytest
from tests.conftest import ADMIN_ARN, allow, deny, group, new_account, role, user

from ibr.account.serialise import AccountFormatError, from_dict, read_account, to_dict, write_account


def _populated():
    account = new_account()
    group(account, "g:devs", allow("ec2:RunInstances"))
    user(account, "u:a", allow("iam:*"), deny("iam:AttachUserPolicy"),
         groups=("g:devs",), policies=(ADMIN_ARN,), tags=("least-privilege",))
    role(account, "r:a", trusts=("u:a",), services=("lambda.amazonaws.com",), conditions=("aws:SourceVpc",))
    return account


def test_round_trip_preserves_everything(tmp_path):
    original = _populated()
    path = write_account(original, tmp_path / "a.json")
    restored = read_account(path)

    assert restored.account_id == original.account_id
    assert set(restored.principals) == set(original.principals)
    assert set(restored.policies) == set(original.policies)
    for principal_id, principal in original.principals.items():
        assert restored.principals[principal_id] == principal


def test_round_trip_preserves_evaluation(tmp_path):
    original = _populated()
    restored = read_account(write_account(original, tmp_path / "a.json"))
    for action in ("iam:PutUserPolicy", "iam:AttachUserPolicy", "ec2:RunInstances", "s3:PutObject"):
        assert restored.allows("u:a", action) == original.allows("u:a", action), action


def test_trust_policy_survives_the_round_trip(tmp_path):
    restored = read_account(write_account(_populated(), tmp_path / "a.json"))
    trust = restored.principals["r:a"].trust_policy
    assert trust.trusted_principals == ("u:a",)
    assert trust.trusted_services == ("lambda.amazonaws.com",)
    assert trust.conditions == ("aws:SourceVpc",)


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_account(tmp_path / "nope.json")


def test_invalid_json_raises_a_readable_error(tmp_path):
    path = tmp_path / "a.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(AccountFormatError, match="not valid JSON"):
        read_account(path)


def test_wrong_schema_version_is_refused():
    """A silently misread account file is a confidently wrong report."""
    with pytest.raises(AccountFormatError, match="unsupported schema_version"):
        from_dict({"schema_version": 99, "principals": []})


def test_missing_principals_is_refused():
    with pytest.raises(AccountFormatError, match="no 'principals'"):
        from_dict({"schema_version": 1})


def test_non_object_is_refused():
    with pytest.raises(AccountFormatError, match="not a JSON object"):
        from_dict([])


def test_invalid_principal_type_is_refused():
    with pytest.raises(AccountFormatError, match="invalid principal_type"):
        from_dict({"schema_version": 1, "principals": [{"principal_id": "u:a", "principal_type": "robot"}]})


def test_invalid_statement_is_refused():
    with pytest.raises(AccountFormatError, match="invalid statement"):
        from_dict({
            "schema_version": 1,
            "principals": [{
                "principal_id": "u:a", "principal_type": "user",
                "inline_statements": [{"effect": "Maybe", "actions": ["s3:Get*"]}],
            }],
        })


def test_policy_without_versions_is_refused():
    with pytest.raises(AccountFormatError, match="declares no versions"):
        from_dict({
            "schema_version": 1,
            "policies": [{"arn": "arn:p", "name": "p", "versions": []}],
            "principals": [],
        })


def test_serialised_shape_is_stable(tmp_path):
    """The on disk shape is the input contract a real export has to target."""
    payload = to_dict(_populated())
    assert payload["schema_version"] == 1
    assert {"account_id", "policies", "principals"} <= set(payload)
    principal = next(p for p in payload["principals"] if p["principal_id"] == "u:a")
    assert set(principal) == {
        "principal_id", "principal_type", "inline_statements",
        "attached_policy_arns", "group_ids", "tags", "trust_policy",
    }
    assert json.dumps(payload)


def test_principal_without_a_trust_policy_serialises_as_null():
    payload = to_dict(_populated())
    principal = next(p for p in payload["principals"] if p["principal_id"] == "u:a")
    assert principal["trust_policy"] is None
