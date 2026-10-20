"""Read and write the account model as JSON.

The on disk shape is the tool's input contract: a real deployment produces this
from `aws iam get-account-authorization-details` plus a small transform, rather
than from the generator. Keeping it explicit and versioned means that transform
has something stable to target.
"""

from __future__ import annotations

import json
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

SCHEMA_VERSION = 1


class AccountFormatError(ValueError):
    """Raised when an account file cannot be read."""


def _statement_to_dict(statement: Statement) -> dict:
    return {
        "effect": statement.effect.value,
        "actions": list(statement.actions),
        "resources": list(statement.resources),
        "conditions": list(statement.conditions),
    }


def _statement_from_dict(raw: dict) -> Statement:
    try:
        return Statement(
            effect=Effect(raw["effect"]),
            actions=tuple(raw["actions"]),
            resources=tuple(raw.get("resources", ("*",))),
            conditions=tuple(raw.get("conditions", ())),
        )
    except (KeyError, ValueError) as exc:
        raise AccountFormatError(f"invalid statement: {raw!r}") from exc


def to_dict(account: Account) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "account_id": account.account_id,
        "policies": [
            {
                "arn": policy.arn,
                "name": policy.name,
                "versions": [
                    {
                        "version_id": version.version_id,
                        "is_default": version.is_default,
                        "statements": [_statement_to_dict(s) for s in version.statements],
                    }
                    for version in policy.versions
                ],
            }
            for policy in account.policies.values()
        ],
        "principals": [
            {
                "principal_id": principal.principal_id,
                "principal_type": principal.principal_type.value,
                "inline_statements": [_statement_to_dict(s) for s in principal.inline_statements],
                "attached_policy_arns": list(principal.attached_policy_arns),
                "group_ids": list(principal.group_ids),
                "tags": list(principal.tags),
                "trust_policy": (
                    {
                        "trusted_principals": list(principal.trust_policy.trusted_principals),
                        "trusted_services": list(principal.trust_policy.trusted_services),
                        "conditions": list(principal.trust_policy.conditions),
                    }
                    if principal.trust_policy is not None
                    else None
                ),
            }
            for principal in account.principals.values()
        ],
    }


def from_dict(raw: dict) -> Account:
    if not isinstance(raw, dict):
        raise AccountFormatError("account file is not a JSON object")
    version = raw.get("schema_version")
    if version != SCHEMA_VERSION:
        raise AccountFormatError(
            f"unsupported schema_version {version!r}, this build reads version {SCHEMA_VERSION}"
        )
    if "principals" not in raw:
        raise AccountFormatError("account file has no 'principals' list")

    account = Account(account_id=str(raw.get("account_id", "unknown")))
    for entry in raw.get("policies", []):
        versions = tuple(
            PolicyVersion(
                version_id=str(v["version_id"]),
                statements=tuple(_statement_from_dict(s) for s in v.get("statements", [])),
                is_default=bool(v.get("is_default", False)),
            )
            for v in entry.get("versions", [])
        )
        if not versions:
            raise AccountFormatError(f"policy {entry.get('arn')!r} declares no versions")
        account.policies[str(entry["arn"])] = Policy(
            arn=str(entry["arn"]), name=str(entry.get("name", entry["arn"])), versions=versions
        )

    for entry in raw["principals"]:
        try:
            principal_type = PrincipalType(entry["principal_type"])
        except (KeyError, ValueError) as exc:
            raise AccountFormatError(f"invalid principal_type on {entry.get('principal_id')!r}") from exc
        trust_raw = entry.get("trust_policy")
        account.principals[str(entry["principal_id"])] = Principal(
            principal_id=str(entry["principal_id"]),
            principal_type=principal_type,
            inline_statements=tuple(_statement_from_dict(s) for s in entry.get("inline_statements", [])),
            attached_policy_arns=tuple(entry.get("attached_policy_arns", ())),
            group_ids=tuple(entry.get("group_ids", ())),
            trust_policy=(
                TrustPolicy(
                    trusted_principals=tuple(trust_raw.get("trusted_principals", ())),
                    trusted_services=tuple(trust_raw.get("trusted_services", ())),
                    conditions=tuple(trust_raw.get("conditions", ())),
                )
                if trust_raw
                else None
            ),
            tags=tuple(entry.get("tags", ())),
        )
    return account


def write_account(account: Account, path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_dict(account), indent=2) + "\n", encoding="utf-8")
    return path


def read_account(path: Path | str) -> Account:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"account file not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AccountFormatError(f"{path} is not valid JSON: {exc}") from exc
    return from_dict(raw)
