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

Both answers come from one traversal, not from a search per principal. Running
all_simple_paths from every principal to every administrative node measured 35
seconds on a 2,177 principal account and is the wrong shape for the question:
a single breadth first search backwards from every administrative node, over the
reversed graph, labels every principal with its hop distance and its next step
in one pass. See ADR-002.
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
    # Distinct next steps that lead toward admin: how many separate statements
    # have to be removed to contain this principal.
    paths_found: int
    # Principals reachable within max_hops. -1 when not computed; see analyse.
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


@dataclass(frozen=True)
class AdminDistances:
    """Hop distance to the nearest administrative principal, for every node.

    `next_hop` is the first step of a shortest path, so a full path is
    reconstructed by following it without searching again.
    """

    distance: dict[str, int]
    next_hop: dict[str, str]
    admin_nodes: frozenset[str]


def admin_distances(graph: nx.DiGraph, max_hops: int) -> AdminDistances:
    """Label every principal with its distance to the nearest admin node.

    One breadth first search over the reversed graph, seeded with every
    administrative node at distance zero. Linear in the graph rather than
    quadratic in principals, which is the difference between 35 seconds and
    well under one on an account of a few thousand.
    """
    admin_nodes = frozenset(n for n, d in graph.nodes(data=True) if d.get("admin"))
    distance: dict[str, int] = dict.fromkeys(admin_nodes, 0)
    next_hop: dict[str, str] = {}

    frontier = list(admin_nodes)
    hops = 0
    while frontier and hops < max_hops:
        hops += 1
        nxt: list[str] = []
        for node in frontier:
            # Reversed traversal: who can reach `node` in one step.
            for predecessor in graph.predecessors(node):
                if predecessor in distance:
                    continue
                distance[predecessor] = hops
                next_hop[predecessor] = node
                nxt.append(predecessor)
        frontier = nxt

    return AdminDistances(distance=distance, next_hop=next_hop, admin_nodes=admin_nodes)


def path_from(graph: nx.DiGraph, principal_id: str, distances: AdminDistances) -> EscalationPath | None:
    """Reconstruct a shortest escalation path by following next_hop."""
    if principal_id in distances.admin_nodes:
        return None
    if principal_id not in distances.next_hop:
        return None
    nodes = [principal_id]
    current = principal_id
    while current in distances.next_hop:
        current = distances.next_hop[current]
        nodes.append(current)
    return _to_path(graph, nodes)


def distinct_first_steps(graph: nx.DiGraph, principal_id: str, distances: AdminDistances) -> int:
    """How many independent next steps lead toward admin.

    Replaces a count of enumerated simple paths, which was exponential to
    compute and told a reader nothing they acted on. The number of distinct
    first steps is what matters for remediation: it is how many separate
    statements have to be removed to contain this principal, and it is the
    out degree restricted to neighbours that are themselves closer to admin.
    """
    own = distances.distance.get(principal_id)
    if own is None:
        return 0
    return sum(
        1
        for neighbour in graph.successors(principal_id)
        if distances.distance.get(neighbour, 10**9) < own
    )


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


def analyse(
    graph: nx.DiGraph,
    account_id: str,
    config: Config,
    with_blast_radius: bool = False,
) -> ReachabilityReport:
    """Compute the reachability report for every principal in the graph.

    `with_blast_radius` adds a per principal count of everything reachable
    within max_hops. It is off by default because it is a breadth first search
    per principal, which is quadratic over the account, while every other
    number here comes from a single traversal. The CLI turns it on for the
    principals it actually displays.
    """
    report = ReachabilityReport(
        account_id=account_id,
        max_hops=config.max_hops,
        assume_conditions_satisfiable=config.assume_conditions_satisfiable,
    )
    distances = admin_distances(graph, config.max_hops)

    for principal_id, data in graph.nodes(data=True):
        already_admin = principal_id in distances.admin_nodes
        hops = distances.distance.get(principal_id)
        shortest = None if already_admin else path_from(graph, principal_id, distances)

        report.findings.append(
            PrincipalFinding(
                principal_id=principal_id,
                principal_type=str(data.get("principal_type", "unknown")),
                tags=tuple(data.get("tags", ())),
                already_admin=already_admin,
                reaches_admin=shortest is not None,
                hops_to_admin=None if already_admin else hops,
                shortest_path=shortest,
                paths_found=distinct_first_steps(graph, principal_id, distances),
                reachable_within_max_hops=(
                    len(reachable_within(graph, principal_id, config.max_hops))
                    if with_blast_radius
                    else -1
                ),
                conditional_only=bool(shortest) and shortest.conditional,
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
