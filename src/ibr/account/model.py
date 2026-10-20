"""The account model: principals, policies and trust, as the analysis needs them.

This is deliberately not a full IAM implementation. It is the subset of IAM that
determines whether one principal can obtain another's privileges, which is a
much smaller thing than the policy language. What it keeps:

  - statements, with effect, actions and resources, including wildcards
  - explicit Deny, which beats any Allow, and which a reachability tool that
    ignored it would be dangerously wrong about
  - role trust policies, because sts:AssumeRole in an identity policy means
    nothing without a trust policy on the other side
  - managed policy versions, because SetDefaultPolicyVersion escalation needs an
    older, more permissive version to roll back to
  - group membership, because a user's effective permissions include the
    group's

What it does not keep, and says so rather than failing quietly: condition keys
are recorded but not evaluated, permission boundaries and SCPs are recorded but
not applied, and resource policies other than role trust are out of scope. Each
of those is a documented limitation with a trigger condition in the README.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import StrEnum


class Effect(StrEnum):
    ALLOW = "Allow"
    DENY = "Deny"


class PrincipalType(StrEnum):
    USER = "user"
    ROLE = "role"
    GROUP = "group"


@dataclass(frozen=True)
class Statement:
    """One policy statement, reduced to what reachability depends on."""

    effect: Effect
    actions: tuple[str, ...]
    resources: tuple[str, ...] = ("*",)
    # Condition keys present on the statement. Recorded, not evaluated.
    conditions: tuple[str, ...] = ()

    def matches_action(self, action: str) -> bool:
        """True when this statement covers `action`.

        IAM action matching is case insensitive and supports a trailing
        wildcard, so iam:Put* covers iam:PutUserPolicy and * covers everything.
        """
        target = action.lower()
        return any(fnmatch.fnmatch(target, pattern.lower()) for pattern in self.actions)

    def matches_resource(self, resource: str) -> bool:
        return any(fnmatch.fnmatch(resource.lower(), pattern.lower()) for pattern in self.resources)

    @property
    def is_conditional(self) -> bool:
        return bool(self.conditions)


@dataclass(frozen=True)
class PolicyVersion:
    version_id: str
    statements: tuple[Statement, ...]
    is_default: bool = False


@dataclass(frozen=True)
class Policy:
    """A managed policy, which may carry several versions."""

    arn: str
    name: str
    versions: tuple[PolicyVersion, ...]

    @property
    def default_version(self) -> PolicyVersion:
        for version in self.versions:
            if version.is_default:
                return version
        return self.versions[0]

    @property
    def statements(self) -> tuple[Statement, ...]:
        return self.default_version.statements

    def version_allows(self, version: PolicyVersion, action: str) -> bool:
        """Whether a specific version allows an action, Deny included."""
        allowed = False
        for statement in version.statements:
            if not statement.matches_action(action):
                continue
            if statement.effect is Effect.DENY:
                return False
            allowed = True
        return allowed

    def grants_in_a_non_default_version(self, actions: frozenset[str]) -> bool:
        """True when a non default version allows an action the default does not.

        The question is specifically about the actions passed in, not about any
        difference between versions. An earlier version of this method returned
        true whenever a non default version mentioned any action the default did
        not, which made a rollback from s3:Get to s3:List read as an escalation.
        Rolling back to a version that grants a different harmless permission is
        not a privilege escalation, and reporting it as one is noise in exactly
        the place a reader has least patience for it.
        """
        for version in self.versions:
            if version.is_default:
                continue
            for action in actions:
                if self.version_allows(version, action) and not self.version_allows(
                    self.default_version, action
                ):
                    return True
        return False


@dataclass(frozen=True)
class TrustPolicy:
    """Who may assume a role. Empty means nobody, which is the safe default."""

    trusted_principals: tuple[str, ...] = ()
    trusted_services: tuple[str, ...] = ()
    conditions: tuple[str, ...] = ()

    def trusts(self, principal_id: str) -> bool:
        return any(
            fnmatch.fnmatch(principal_id.lower(), pattern.lower())
            for pattern in self.trusted_principals
        )


@dataclass(frozen=True)
class Principal:
    """A user, role or group."""

    principal_id: str
    principal_type: PrincipalType
    inline_statements: tuple[Statement, ...] = ()
    attached_policy_arns: tuple[str, ...] = ()
    group_ids: tuple[str, ...] = ()
    trust_policy: TrustPolicy | None = None
    # Free form labels from the account, for example a least-privilege tag that
    # somebody applied. The tool reports against these rather than trusting them.
    tags: tuple[str, ...] = ()

    @property
    def is_role(self) -> bool:
        return self.principal_type is PrincipalType.ROLE


@dataclass
class Account:
    account_id: str
    principals: dict[str, Principal] = field(default_factory=dict)
    policies: dict[str, Policy] = field(default_factory=dict)
    # Memoised effective statements. Resolving them walks attached policies and
    # group membership, and the graph build asks for the same principal's
    # statements thousands of times, so recomputing was the single largest cost
    # in the build. Invalidated by rebuilding the Account, which is what every
    # caller does anyway: the model is loaded from a file and not mutated.
    _statement_cache: dict[str, list[Statement]] = field(default_factory=dict, repr=False)

    def effective_statements(self, principal_id: str, _seen: frozenset[str] | None = None) -> list[Statement]:
        """Every statement that applies to a principal.

        Inline statements, attached managed policies at their default version,
        and the same for every group the principal belongs to. Group nesting is
        not a thing in IAM, but the traversal guards against cycles anyway
        because the account model is loaded from a file that could contain one.
        """
        seen = _seen or frozenset()
        if principal_id in seen:
            return []
        if _seen is None:
            cached = self._statement_cache.get(principal_id)
            if cached is not None:
                return cached
        principal = self.principals.get(principal_id)
        if principal is None:
            return []

        collected = list(principal.inline_statements)
        for arn in principal.attached_policy_arns:
            policy = self.policies.get(arn)
            if policy is not None:
                collected.extend(policy.statements)
        for group_id in principal.group_ids:
            collected.extend(self.effective_statements(group_id, seen | {principal_id}))
        if _seen is None:
            self._statement_cache[principal_id] = collected
        return collected

    def allow_patterns(self, principal_id: str, action: str) -> tuple[frozenset[str], bool]:
        """Resource patterns on which this principal is allowed `action`.

        Returns the patterns and whether every matching Allow carried a
        condition. Used to index candidate targets rather than testing every
        principal against every principal: a user allowed
        iam:CreateAccessKey only on its own ARN has exactly one candidate, and
        a user allowed nothing has none.

        Deny is handled by the caller through `allows`, because a Deny may be
        scoped more narrowly than the Allow and only the specific target
        resolves it.
        """
        patterns: set[str] = set()
        conditional = True
        for statement in self.effective_statements(principal_id):
            if statement.effect is not Effect.ALLOW or not statement.matches_action(action):
                continue
            patterns.update(statement.resources)
            if not statement.is_conditional:
                conditional = False
        return frozenset(patterns), (conditional and bool(patterns))

    def allows(self, principal_id: str, action: str, resource: str = "*") -> bool:
        """True when the principal may perform the action on the resource.

        Explicit Deny wins, which is the one IAM evaluation rule a reachability
        tool cannot skip: a principal holding iam:* and an explicit Deny on
        iam:AttachUserPolicy is not an administrator, and a tool that reported
        it as one would send somebody to fix the wrong thing.
        """
        statements = self.effective_statements(principal_id)
        allowed = False
        for statement in statements:
            if not (statement.matches_action(action) and statement.matches_resource(resource)):
                continue
            if statement.effect is Effect.DENY:
                return False
            allowed = True
        return allowed

    def allowed_conditionally(self, principal_id: str, action: str, resource: str = "*") -> bool:
        """True when the only Allow covering this action carries a condition.

        Reported so a reader can see which edges rest on an unevaluated
        condition rather than having them silently indistinguishable from
        unconditional ones.
        """
        statements = self.effective_statements(principal_id)
        matching = [
            s for s in statements
            if s.effect is Effect.ALLOW and s.matches_action(action) and s.matches_resource(resource)
        ]
        return bool(matching) and all(s.is_conditional for s in matching)
