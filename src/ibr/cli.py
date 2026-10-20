"""Command line interface.

Four verbs: generate a synthetic account, analyse one, gate CI on the result,
and serve the query API.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import typer

from ibr import __version__
from ibr.account.generate import generate as generate_account
from ibr.account.serialise import read_account
from ibr.config import load_config
from ibr.graph.build import build_graph
from ibr.graph.reach import analyse as analyse_graph
from ibr.logging import configure, get_logger
from ibr.report.render import render_html, render_json

app = typer.Typer(add_completion=False, help="Measure what a compromised IAM principal can actually reach.")
log = get_logger(__name__)

EXIT_OK = 0
EXIT_THRESHOLD_EXCEEDED = 2


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit(EXIT_OK)


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Print the version and exit."
    ),
    log_level: str = typer.Option("INFO", "--log-level", help="Level for the structured log on stderr."),
) -> None:
    configure(log_level.upper())


@app.command()
def generate(
    principals: int = typer.Option(2000, "--principals", min=10, help="Number of principals to generate."),
    out: Path = typer.Option(Path("data/generated/account.json"), "--out", help="Account JSON to write."),
    seed: int = typer.Option(7, "--seed", help="Seed, so an account is reproducible."),
) -> None:
    """Generate a synthetic account to evaluate the tool without a real one."""
    result = generate_account(out, principals, seed=seed)
    typer.echo(f"wrote {result.principals:,} principals to {result.path}")
    for shape, count in sorted(result.shapes.items(), key=lambda kv: -kv[1]):
        typer.echo(f"  {shape:16s} {count:>7,}")


@app.command()
def analyse(
    account: Path = typer.Option(..., "--account", exists=True, help="Account JSON."),
    out: Path | None = typer.Option(None, "--out", help="Write an HTML report here."),
    json_out: Path | None = typer.Option(None, "--json", help="Write the machine readable result here."),
    max_hops: int = typer.Option(0, "--max-hops", min=0, max=10, help="0 uses the configured default."),
    strict_conditions: bool = typer.Option(
        False, "--strict-conditions",
        help="Drop edges that rest on an unevaluated condition instead of flagging them.",
    ),
) -> None:
    """Compute privilege reachability for every principal in an account."""
    config = load_config()
    if max_hops:
        config = replace(config, max_hops=max_hops)
    if strict_conditions:
        config = replace(config, assume_conditions_satisfiable=False)

    loaded = read_account(account)
    graph = build_graph(loaded, config)
    report = analyse_graph(graph, loaded.account_id, config)

    typer.echo("")
    typer.echo(f"  account               {report.account_id}")
    typer.echo(f"  principals            {report.principal_count:,}")
    typer.echo(f"  already administrative {len(report.admin_principals):,}")
    typer.echo(f"  reach admin           {len(report.escalating):,} ({report.escalating_pct:.1f}% of non admin)")
    typer.echo("")
    for hop in range(1, config.max_hops + 1):
        typer.echo(f"    at {hop} hop(s)         {len(report.at_hop(hop)):,}")
    typer.echo("")
    typer.echo(f"  labelled least privilege {len(report.labelled_least_privilege):,}")
    typer.echo(
        f"  of those, reach admin    {len(report.mislabelled):,} ({report.mislabelled_pct:.1f}%)"
    )
    typer.echo("")

    for finding in report.escalating[:5]:
        path = finding.shortest_path.describe() if finding.shortest_path else ""
        typer.echo(f"    {finding.principal_id}  {finding.hops_to_admin} hop(s)  {path}")
    if len(report.escalating) > 5:
        typer.echo(f"    and {len(report.escalating) - 5:,} more")
    typer.echo("")

    if out:
        typer.echo(f"html report  {render_html(report, out)}")
    if json_out:
        typer.echo(f"json result  {render_json(report, json_out)}")


@app.command()
def gate(
    account: Path = typer.Option(..., "--account", exists=True, help="Account JSON."),
    max_one_hop: int = typer.Option(0, "--max-one-hop", min=0, help="Fail above this many one hop escalations."),
    max_mislabelled_pct: float = typer.Option(
        0.0, "--max-mislabelled-pct",
        help="Fail above this percentage of least-privilege labelled principals reaching admin.",
    ),
) -> None:
    """Exit non zero when reachability exceeds a threshold. For use in CI."""
    config = load_config()
    loaded = read_account(account)
    report = analyse_graph(build_graph(loaded, config), loaded.account_id, config)

    one_hop = len(report.at_hop(1))
    typer.echo(f"  one hop escalations      {one_hop:,}  (limit {max_one_hop:,})")
    typer.echo(
        f"  mislabelled least priv   {report.mislabelled_pct:.2f}%  (limit {max_mislabelled_pct:.2f}%)"
    )

    failures: list[str] = []
    if one_hop > max_one_hop:
        failures.append(f"{one_hop} principals reach admin in one hop, limit is {max_one_hop}")
    if report.mislabelled_pct > max_mislabelled_pct:
        failures.append(
            f"{report.mislabelled_pct:.2f}% of least-privilege labelled principals reach admin, "
            f"limit is {max_mislabelled_pct:.2f}%"
        )

    if failures:
        typer.echo("")
        for failure in failures:
            typer.echo(f"  FAIL  {failure}", err=True)
        raise typer.Exit(EXIT_THRESHOLD_EXCEEDED)

    typer.echo("")
    typer.echo("  PASS  reachability within thresholds")


@app.command()
def serve(
    account: Path = typer.Option(..., "--account", exists=True, help="Account JSON to load at startup."),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
    port: int = typer.Option(8000, "--port", min=1, max=65535, help="Bind port."),
) -> None:
    """Serve the reachability query API."""
    import uvicorn

    from ibr.api.service import create_app

    uvicorn.run(create_app(account, load_config()), host=host, port=port, log_config=None)


if __name__ == "__main__":  # pragma: no cover - entry point for `python -m ibr.cli`
    app()
