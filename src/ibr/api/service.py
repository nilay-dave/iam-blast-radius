"""Query service.

Reachability questions are interactive. During an incident somebody has a
principal and needs to know what it touches, and they need it in seconds rather
than after a batch job. The graph is built once at startup and queried per
request, which is the whole reason this is a service rather than a second CLI
verb.

The service is read only by construction. It never writes to AWS, never holds
credentials, and the account it answers about is a file loaded at startup. That
is a deliberate boundary: a service that could refresh itself from AWS would
need credentials with iam:List* across the account, which is a far more
attractive thing to compromise than the report it would produce.
"""

from __future__ import annotations

from pathlib import Path

import networkx as nx
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from ibr import __version__
from ibr.account.model import Account
from ibr.account.serialise import read_account
from ibr.config import Config, load_config
from ibr.graph.build import build_graph
from ibr.graph.reach import (
    admin_distances,
    analyse,
    path_from,
    paths_to_admin,
    reachable_within,
)
from ibr.logging import configure, get_logger

log = get_logger(__name__)


class StepModel(BaseModel):
    source: str
    target: str
    kind: str
    conditional: bool
    technique: str


class PathModel(BaseModel):
    hops: int
    principals: list[str]
    conditional: bool
    steps: list[StepModel]


class BlastRadiusModel(BaseModel):
    principal_id: str
    principal_type: str
    tags: list[str]
    already_admin: bool
    max_hops: int
    reachable_count: int = Field(description="Principals reachable within max_hops.")
    reachable: dict[str, int] = Field(description="Principal id to hop distance.")
    reaches_admin: bool
    hops_to_admin: int | None
    shortest_path: PathModel | None


class SummaryModel(BaseModel):
    account_id: str
    principals: int
    already_admin: int
    escalating: int
    escalating_pct: float
    labelled_least_privilege: int
    mislabelled: int
    mislabelled_pct: float
    by_hop: dict[int, int]
    max_hops: int


class ServiceState:
    """Graph and account held for the process lifetime."""

    def __init__(self) -> None:
        self.account: Account | None = None
        self.graph: nx.DiGraph | None = None
        self.config: Config = load_config()
        self.source_path: Path | None = None

    def load(self, path: Path | str, config: Config | None = None) -> None:
        self.config = config or self.config
        self.source_path = Path(path)
        self.account = read_account(path)
        self.graph = build_graph(self.account, self.config)
        log.info(
            "service loaded account",
            extra={
                "path": str(path),
                "principals": self.graph.number_of_nodes(),
                "edges": self.graph.number_of_edges(),
            },
        )

    def require(self) -> tuple[Account, nx.DiGraph]:
        if self.account is None or self.graph is None:
            raise HTTPException(status_code=503, detail="no account loaded")
        return self.account, self.graph


state = ServiceState()


def _to_path_model(path) -> PathModel | None:
    if path is None:
        return None
    return PathModel(
        hops=path.hops,
        principals=list(path.principals),
        conditional=path.conditional,
        steps=[
            StepModel(
                source=s.source, target=s.target, kind=s.kind,
                conditional=s.conditional, technique=s.technique,
            )
            for s in path.steps
        ],
    )


def create_app(account_path: Path | str | None = None, config: Config | None = None) -> FastAPI:
    """Build the application, optionally loading an account at import time."""
    configure("INFO")
    app = FastAPI(
        title="iam-blast-radius",
        description="Privilege reachability queries over a loaded AWS account snapshot.",
        version=__version__,
    )
    if account_path is not None:
        state.load(account_path, config)

    @app.get("/health")
    def health() -> dict:
        loaded = state.graph is not None
        return {
            "status": "ok" if loaded else "no account loaded",
            "account_loaded": loaded,
            "principals": state.graph.number_of_nodes() if loaded else 0,
            "source": str(state.source_path) if state.source_path else None,
        }

    @app.get("/summary", response_model=SummaryModel)
    def summary() -> SummaryModel:
        account, graph = state.require()
        report = analyse(graph, account.account_id, state.config)
        return SummaryModel(
            account_id=report.account_id,
            principals=report.principal_count,
            already_admin=len(report.admin_principals),
            escalating=len(report.escalating),
            escalating_pct=round(report.escalating_pct, 2),
            labelled_least_privilege=len(report.labelled_least_privilege),
            mislabelled=len(report.mislabelled),
            mislabelled_pct=round(report.mislabelled_pct, 2),
            by_hop={hop: len(report.at_hop(hop)) for hop in range(1, state.config.max_hops + 1)},
            max_hops=state.config.max_hops,
        )

    @app.get("/principals/{principal_id:path}/blast-radius", response_model=BlastRadiusModel)
    def blast_radius(
        principal_id: str,
        max_hops: int = Query(default=0, ge=0, le=10, description="0 uses the configured default."),
    ) -> BlastRadiusModel:
        """What a compromise of this principal reaches.

        The incident question. Hop distances are returned per principal so the
        caller can show the one hop set first, which is what gets contained
        first.
        """
        account, graph = state.require()
        if principal_id not in graph:
            raise HTTPException(status_code=404, detail=f"principal not found: {principal_id}")

        hops = max_hops or state.config.max_hops
        reachable = reachable_within(graph, principal_id, hops)
        distances = admin_distances(graph, hops)
        data = graph.nodes[principal_id]
        already_admin = principal_id in distances.admin_nodes
        path = None if already_admin else path_from(graph, principal_id, distances)

        return BlastRadiusModel(
            principal_id=principal_id,
            principal_type=str(data.get("principal_type", "unknown")),
            tags=list(data.get("tags", ())),
            already_admin=already_admin,
            max_hops=hops,
            reachable_count=len(reachable),
            reachable=reachable,
            reaches_admin=path is not None,
            hops_to_admin=None if already_admin else distances.distance.get(principal_id),
            shortest_path=_to_path_model(path),
        )

    @app.get("/principals/{principal_id:path}/paths-to-admin", response_model=list[PathModel])
    def paths(principal_id: str) -> list[PathModel]:
        """Every distinct escalation path, capped by configuration.

        Enumerated per request rather than precomputed, because enumerating
        simple paths for every principal is exponential while doing it for one
        principal on demand is cheap. The cap is a correctness requirement as
        much as a readability one.
        """
        _, graph = state.require()
        if principal_id not in graph:
            raise HTTPException(status_code=404, detail=f"principal not found: {principal_id}")
        found = paths_to_admin(graph, principal_id, state.config)
        return [m for m in (_to_path_model(p) for p in found if p.steps) if m is not None]

    return app
