"""Build the privilege reachability graph from an account.

A node is a principal. A directed edge from A to B means: a compromise of A
yields B's privileges, through one of the escalation primitives in edges.py.

The graph is built once and queried many times, which is why it is a graph
rather than a per question evaluation.

Edge construction is the expensive part and the naive version is genuinely
quadratic: every principal tested against every principal, for every escalation
definition, with a full policy evaluation inside the innermost loop. That
measured 118 seconds on a 2,177 principal account.

Two things make it tractable, both documented in ADR-002. Effective statements
are memoised on the Account, because resolving them walks attached policies and
group membership and the build asks for the same principal thousands of times.
And candidate targets are indexed from the resource patterns a principal is
actually allowed the escalation action on, rather than enumerated: a principal
allowed iam:CreateAccessKey only on its own ARN has one candidate, and the
majority of principals, which hold no escalation action at all, have none.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass

import networkx as nx

from ibr.account.model import Account, PrincipalType
from ibr.config import Config
from ibr.graph.edges import (
    ADMIN_EQUIVALENT_ACTIONS,
    DEFINITIONS,
    SELF_ESCALATION_ACTIONS,
    EdgeDefinition,
    EdgeKind,
)
from ibr.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    kind: EdgeKind
    # True when at least one required action is allowed only through a
    # conditional statement the evaluator does not interpret.
    conditional: bool
    technique: str


def _resource_for(kind: EdgeKind, target_id: str) -> str:
    """The resource an escalation action is exercised against.

    Modelling this matters: a principal allowed iam:AttachUserPolicy only on
    its own ARN cannot attach a policy to anybody else, and a tool that ignored
    the resource would report every such principal as reaching everyone.
    """
    if kind in {
        EdgeKind.ATTACH_POLICY,
        EdgeKind.PUT_INLINE_POLICY,
        EdgeKind.CREATE_ACCESS_KEY,
        EdgeKind.UPDATE_LOGIN_PROFILE,
        EdgeKind.ADD_USER_TO_GROUP,
    }:
        return target_id
    if kind in {EdgeKind.ASSUME_ROLE, EdgeKind.UPDATE_ASSUME_ROLE_POLICY}:
        return target_id
    if kind in {EdgeKind.PASS_ROLE_TO_LAMBDA, EdgeKind.PASS_ROLE_TO_EC2}:
        return target_id
    return "*"


def _edge_applies(
    account: Account,
    definition: EdgeDefinition,
    source_id: str,
    target_id: str,
    config: Config,
) -> tuple[bool, bool]:
    """Whether this edge exists, and whether it rests on a condition.

    Returns (applies, conditional).
    """
    target = account.principals[target_id]

    # Self edges are not escalation.
    if source_id == target_id:
        return False, False

    # Edges that act on a user cannot target a role, and the reverse.
    if definition.kind in {
        EdgeKind.CREATE_ACCESS_KEY,
        EdgeKind.UPDATE_LOGIN_PROFILE,
        EdgeKind.ATTACH_POLICY,
        EdgeKind.PUT_INLINE_POLICY,
    } and target.principal_type is not PrincipalType.USER:
        return False, False
    if definition.kind is EdgeKind.ADD_USER_TO_GROUP and target.principal_type is not PrincipalType.GROUP:
        return False, False
    if definition.kind in {
        EdgeKind.ASSUME_ROLE,
        EdgeKind.UPDATE_ASSUME_ROLE_POLICY,
        EdgeKind.PASS_ROLE_TO_LAMBDA,
        EdgeKind.PASS_ROLE_TO_EC2,
    } and not target.is_role:
        return False, False

    resource = _resource_for(definition.kind, target_id)
    conditional = False
    for action in definition.required_actions:
        if not account.allows(source_id, action, resource):
            return False, False
        if account.allowed_conditionally(source_id, action, resource):
            conditional = True

    # Passing a role to a service only escalates if the service can assume it.
    # A role that does not trust lambda.amazonaws.com cannot be used by a
    # function, so iam:PassRole plus lambda:CreateFunction against it is not a
    # path. Omitting this check inflates the graph with edges that would fail
    # on the first API call, which is the kind of false path that gets a tool
    # dismissed after one review.
    if definition.requires_service_trust is not None:
        trust = target.trust_policy
        if trust is None or definition.requires_service_trust not in trust.trusted_services:
            return False, False
        if trust.conditions:
            conditional = True

    # sts:AssumeRole in an identity policy means nothing without the role's
    # trust policy naming this principal. This is the check most commonly
    # skipped, and skipping it turns every principal with sts:AssumeRole into a
    # path to every role in the account.
    if definition.kind is EdgeKind.ASSUME_ROLE:
        trust = target.trust_policy
        if trust is None or not trust.trusts(source_id):
            return False, False
        if trust.conditions:
            conditional = True

    if conditional and not config.assume_conditions_satisfiable:
        return False, False
    return True, conditional


def is_admin_equivalent(account: Account, principal_id: str) -> bool:
    """True when the principal already holds administrative power.

    Checked by evaluating each administrative action through the full policy
    evaluation rather than by string matching on policy documents, so an
    explicit Deny correctly removes a principal from this set.

    Self escalation counts. A principal that can roll one of its own attached
    policies back to a version granting an administrative action is an
    administrator in one step that touches nobody else, which is why this is
    not modelled as a graph edge: an edge means "A obtains B's privileges" and
    there is no B here.
    """
    if any(account.allows(principal_id, action) for action in sorted(ADMIN_EQUIVALENT_ACTIONS)):
        return True

    principal = account.principals.get(principal_id)
    if principal is None:
        return False
    for action in sorted(SELF_ESCALATION_ACTIONS):
        if not account.allows(principal_id, action):
            continue
        for arn in principal.attached_policy_arns:
            policy = account.policies.get(arn)
            if policy is not None and policy.grants_in_a_non_default_version(ADMIN_EQUIVALENT_ACTIONS):
                return True
    return False


def _candidate_targets(
    account: Account,
    definition: EdgeDefinition,
    source_id: str,
    all_ids: tuple[str, ...],
) -> list[str]:
    """Principals this source could possibly reach through this definition.

    Narrowed from the resource patterns the source is allowed the escalation
    actions on. A literal pattern resolves to one principal; a bare wildcard
    means every principal and is itself a finding; anything else is matched by
    glob, which is rare enough not to matter.

    The source must hold every required action, so the candidate set is the
    intersection across them. That is what makes the PassRole family cheap:
    plenty of principals hold lambda:CreateFunction and very few also hold
    iam:PassRole.
    """
    candidates: set[str] | None = None
    for action in definition.required_actions:
        patterns, _ = account.allow_patterns(source_id, action)
        if not patterns:
            return []

        if "*" in patterns:
            resolved: set[str] = set(all_ids)
        else:
            resolved = set()
            for pattern in patterns:
                if pattern in account.principals:
                    resolved.add(pattern)
                elif any(char in pattern for char in "*?["):
                    resolved.update(fnmatch.filter(all_ids, pattern))
        if not resolved:
            return []
        candidates = resolved if candidates is None else (candidates & resolved)
        if not candidates:
            return []
    return sorted(candidates or ())


def build_graph(account: Account, config: Config) -> nx.DiGraph:
    """Construct the privilege reachability graph."""
    graph = nx.DiGraph()
    all_ids = tuple(account.principals)

    admin_ids: set[str] = set()
    for principal_id, principal in account.principals.items():
        admin = is_admin_equivalent(account, principal_id)
        if admin:
            admin_ids.add(principal_id)
        graph.add_node(
            principal_id,
            principal_type=principal.principal_type.value,
            tags=list(principal.tags),
            admin=admin,
        )

    considered = 0
    conditional_count = 0
    for source_id in all_ids:
        # An administrator reaches every principal by definition, so enumerating
        # those edges adds hundreds of thousands of entries that carry no
        # information: nobody fixes "the administrator can attach a policy to
        # this user". Blast radius for an admin is reported as the whole account
        # by the query layer rather than stored. See ADR-002.
        if source_id in admin_ids:
            continue
        for definition in DEFINITIONS:
            for target_id in _candidate_targets(account, definition, source_id, all_ids):
                considered += 1
                applies, conditional = _edge_applies(account, definition, source_id, target_id, config)
                if not applies:
                    continue
                # Keep the first edge found between a pair, and prefer an
                # unconditional one: a reader fixing a path wants the edge that
                # definitely works, not one that may be blocked by a condition.
                existing = graph.get_edge_data(source_id, target_id)
                if existing is not None and not existing["conditional"]:
                    continue
                graph.add_edge(
                    source_id,
                    target_id,
                    kind=definition.kind.value,
                    conditional=conditional,
                    technique=definition.technique,
                )
                conditional_count += int(conditional)

    log.info(
        "graph built",
        extra={
            "principals": graph.number_of_nodes(),
            "edges": graph.number_of_edges(),
            "pairs_considered": considered,
            "conditional_edges": conditional_count,
            "admin_principals": len(admin_ids),
        },
    )
    return graph
