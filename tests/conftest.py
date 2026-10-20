"""Shared fixtures. No AWS account, no credentials, no network."""

from __future__ import annotations

import pytest

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
from ibr.config import Config

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


@pytest.fixture
def config() -> Config:
    return Config(max_hops=3, max_paths_per_principal=25, seed=7, assume_conditions_satisfiable=True)


def allow(*actions: str, resources: tuple[str, ...] = ("*",), conditions: tuple[str, ...] = ()) -> Statement:
    return Statement(Effect.ALLOW, actions, resources, conditions)


def deny(*actions: str, resources: tuple[str, ...] = ("*",)) -> Statement:
    return Statement(Effect.DENY, actions, resources)


def admin_policy() -> Policy:
    return Policy(ADMIN_ARN, "AdministratorAccess", (PolicyVersion("v1", (allow("*"),), True),))


def new_account(account_id: str = "111122223333") -> Account:
    account = Account(account_id=account_id)
    account.policies[ADMIN_ARN] = admin_policy()
    return account


def user(account: Account, principal_id: str, *statements: Statement, tags: tuple[str, ...] = (),
         policies: tuple[str, ...] = (), groups: tuple[str, ...] = ()) -> Principal:
    principal = Principal(
        principal_id=principal_id,
        principal_type=PrincipalType.USER,
        inline_statements=statements,
        attached_policy_arns=policies,
        group_ids=groups,
        tags=tags,
    )
    account.principals[principal_id] = principal
    account._statement_cache.clear()
    return principal


def role(account: Account, principal_id: str, *statements: Statement,
         trusts: tuple[str, ...] = (), services: tuple[str, ...] = (),
         policies: tuple[str, ...] = (), tags: tuple[str, ...] = (),
         conditions: tuple[str, ...] = ()) -> Principal:
    principal = Principal(
        principal_id=principal_id,
        principal_type=PrincipalType.ROLE,
        inline_statements=statements,
        attached_policy_arns=policies,
        trust_policy=TrustPolicy(trusted_principals=trusts, trusted_services=services, conditions=conditions),
        tags=tags,
    )
    account.principals[principal_id] = principal
    account._statement_cache.clear()
    return principal


def group(account: Account, principal_id: str, *statements: Statement) -> Principal:
    principal = Principal(
        principal_id=principal_id, principal_type=PrincipalType.GROUP, inline_statements=statements
    )
    account.principals[principal_id] = principal
    account._statement_cache.clear()
    return principal


@pytest.fixture
def account_factory():
    return new_account
