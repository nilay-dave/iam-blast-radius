"""Answer the question the graph exists for: what can a compromise of X reach.

Two queries matter and they are different shapes.

**Blast radius.** Given a principal, what is reachable within k hops. This is
the question asked during an incident, when somebody has a credential and needs
to know what it touches.

**Admin reachability.** Across every principal, which ones reach an
administrative action, at what hop count, and by which path. This is the
question asked during a review, and it is the one that produces the headline
number: the share of principals that reach admin despite carrying a
least-privilege label.

Paths are reported, not just counts. A number tells somebody there is a problem;
a path tells them which policy statement to delete, and only the second one gets
fixed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from ibr.config import Config
from ibr.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class PathStep:
    source: str
    target: str
    kind: str
    conditional: bool
    technique: str


@dataclass(frozen=True)
class EscalationPath:
    steps: tuple[PathStep, ...]

    @property
    def hops(self) -> int:
        return len(self.steps)

    @property
    def principals(self) -> tuple[str, ...]:
        if not self.steps:
            return ()
        return (self.steps[0].source,) + tuple(step.target for step in self.steps)

    @property
    def conditional(self) -> bool:
        """True when any step rests on a condition the evaluator did not check."""
        return any(step.conditional for step in self.steps)

    def describe(self) -> str:
        if not self.steps:
            return "already administrative"
        return " -> ".join(self.principals)


@dataclass
class PrincipalFinding:
    principal_id: str
    principal_type: str
    tags: tuple[str, ...]
    already_admin: bool
    reaches_admin: bool
    hops_to_admin: int | None
    shortest_path: EscalationPath | None
    paths_found: int
    reachable_within_max_hops: int
    conditional_only: bool = False

    @property
    def claims_least_privilege(self) -> bool:
        """True when somebody labelled this principal as least privilege.

        The tool reports against the label rather than trusting it, which is the
        entire point: a label is an intention and reachability is a fact.
        """
        return any("least" in tag.lower() and "priv" in tag.lower() for tag in self.tags)


@dataclass
class ReachabilityReport:
    account_id: str
    max_hops: int
    findings: list[PrincipalFinding] = field(default_factory=list)
    assume_conditions_satisfiable: bool = True

    @property
    def principal_count(self) -> int:
        return len(self.findings)

    @property
    def admin_principals(self) -> list[PrincipalFinding]:
        return [f for f in self.findings if f.already_admin]

    @property
    def escalating(self) -> list[PrincipalFinding]:
        """Principals that are not admin but reach it."""
        return [f for f in self.findings if f.reaches_admin and not f.already_admin]

    @property
    def escalating_pct(self) -> float:
        non_admin = [f for f in self.findings if not f.already_admin]
        if not non_admin:
            return 0.0
        return 100.0 * len(self.escalating) / len(non_admin)

    @property
    def labelled_least_privilege(self) -> list[PrincipalFinding]:
        return [f for f in self.findings if f.claims_least_privilege]

    @property
    def mislabelled(self) -> list[PrincipalFinding]:
        """Principals labelled least privilege that reach admin anyway.

        The headline. A label is an intention; reachability is a fact.
        """
        return [f for f in self.labelled_least_privilege if f.reaches_admin or f.already_admin]

    @property
    def mislabelled_pct(self) -> float:
        labelled = self.labelled_least_privilege
        if not labelled:
            return 0.0
        return 100.0 * len(self.mislabelled) / len(labelled)

    def at_hop(self, hops: int) -> list[PrincipalFinding]:
        return [f for f in self.escalating if f.hops_to_admin == hops]


def _edge_step(graph: nx.DiGraph, source: str, target: str) -> PathStep:
    data = graph.edges[source, target]
    return PathStep(
        source=source,
        target=target,
        kind=data["kind"],
        conditional=data["conditional"],
        technique=data["technique"],
    )


def _to_path(graph: nx.DiGraph, nodes: list[str]) -> EscalationPath:
    steps = tuple(_edge_step(graph, nodes[i], nodes[i + 1]) for i in range(len(nodes) - 1))
    return EscalationPath(steps=steps)


def reachable_within(graph: nx.DiGraph, principal_id: str, max_hops: int) -> dict[str, int]:
    """Every principal reachable from `principal_id`, with its hop distance.

    Breadth first with a depth cap, which is the right traversal here because
    the question is "within k hops" and a shortest path per target is what gets
    reported.
    """
    if principal_id not in graph:
        raise KeyError(f"principal not in graph: {principal_id}")
    distances = nx.single_source_shortest_path_length(graph, principal_id, cutoff=max_hops)
    return {node: hops for node, hops in distances.items() if node != principal_id}


def paths_to_admin(
    graph: nx.DiGraph,
    principal_id: str,
    config: Config,
) -> list[EscalationPath]:
    """Simple paths from a principal to any administrative node.

    Capped at `max_paths_per_principal`. A principal with more paths than that
    needs remediation rather than a longer report, and enumerating all simple
    paths in a dense graph is exponential, so the cap is a correctness
    requirement as much as a readability one.
    """
    admin_nodes = {n for n, d in graph.nodes(data=True) if d.get("admin")}
    if principal_id in admin_nodes:
        return [EscalationPath(steps=())]

    found: list[EscalationPath] = []
    for target in admin_nodes:
        if target == principal_id:
            continue
        try:
            generator = nx.all_simple_paths(graph, principal_id, target, cutoff=config.max_hops)
        except nx.NodeNotFound:
            continue
        for nodes in generator:
            found.append(_to_path(graph, nodes))
            if len(found) >= config.max_paths_per_principal:
                return found
    return found


def analyse(graph: nx.DiGraph, account_id: str, config: Config) -> ReachabilityReport:
    """Compute the reachability report for every principal in the graph."""
    report = ReachabilityReport(
        account_id=account_id,
        max_hops=config.max_hops,
        assume_conditions_satisfiable=config.assume_conditions_satisfiable,
    )

    for principal_id, data in graph.nodes(data=True):
        already_admin = bool(data.get("admin"))
        reachable = reachable_within(graph, principal_id, config.max_hops)
        paths = paths_to_admin(graph, principal_id, config)
        real_paths = [p for p in paths if p.steps]

        shortest = min(real_paths, key=lambda p: p.hops) if real_paths else None
        report.findings.append(
            PrincipalFinding(
                principal_id=principal_id,
                principal_type=str(data.get("principal_type", "unknown")),
                tags=tuple(data.get("tags", ())),
                already_admin=already_admin,
                reaches_admin=bool(real_paths),
                hops_to_admin=shortest.hops if shortest else None,
                shortest_path=shortest,
                paths_found=len(real_paths),
                reachable_within_max_hops=len(reachable),
                conditional_only=bool(real_paths) and all(p.conditional for p in real_paths),
            )
        )

    report.findings.sort(key=lambda f: (f.hops_to_admin is None, f.hops_to_admin or 0, f.principal_id))
    log.info(
        "reachability analysed",
        extra={
            "principals": report.principal_count,
            "already_admin": len(report.admin_principals),
            "escalating": len(report.escalating),
            "escalating_pct": round(report.escalating_pct, 2),
            "mislabelled": len(report.mislabelled),
            "max_hops": config.max_hops,
        },
    )
    return report
