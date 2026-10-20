"""Render the reachability report as HTML and as JSON."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ibr.graph.reach import PrincipalFinding, ReachabilityReport

# Findings shown in the HTML table. The full set goes to JSON; a page listing
# twenty thousand principals is a page nobody reads.
TABLE_LIMIT = 100


def _finding_to_dict(finding: PrincipalFinding) -> dict:
    return {
        "principal_id": finding.principal_id,
        "principal_type": finding.principal_type,
        "tags": list(finding.tags),
        "claims_least_privilege": finding.claims_least_privilege,
        "already_admin": finding.already_admin,
        "reaches_admin": finding.reaches_admin,
        "hops_to_admin": finding.hops_to_admin,
        "first_steps_toward_admin": finding.paths_found,
        "conditional_only": finding.conditional_only,
        "shortest_path": (
            {
                "hops": finding.shortest_path.hops,
                "principals": list(finding.shortest_path.principals),
                "conditional": finding.shortest_path.conditional,
                "steps": [
                    {
                        "source": s.source,
                        "target": s.target,
                        "kind": s.kind,
                        "conditional": s.conditional,
                        "technique": s.technique,
                    }
                    for s in finding.shortest_path.steps
                ],
            }
            if finding.shortest_path
            else None
        ),
    }


def to_dict(report: ReachabilityReport) -> dict:
    return {
        "account": {
            "account_id": report.account_id,
            "max_hops": report.max_hops,
            "assume_conditions_satisfiable": report.assume_conditions_satisfiable,
            "principals": report.principal_count,
            "already_admin": len(report.admin_principals),
            "escalating": len(report.escalating),
            "escalating_pct": round(report.escalating_pct, 2),
            "labelled_least_privilege": len(report.labelled_least_privilege),
            "mislabelled": len(report.mislabelled),
            "mislabelled_pct": round(report.mislabelled_pct, 2),
            "by_hop": {str(hop): len(report.at_hop(hop)) for hop in range(1, report.max_hops + 1)},
            "conditional_only": sum(1 for f in report.escalating if f.conditional_only),
        },
        "findings": [_finding_to_dict(f) for f in report.findings],
    }


def render_json(report: ReachabilityReport, out_path: Path | str) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(to_dict(report), indent=2) + "\n", encoding="utf-8")
    return out_path


def render_html(report: ReachabilityReport, out_path: Path | str, template_dir: Path | None = None) -> Path:
    template_dir = template_dir or Path(__file__).parent / "templates"
    # autoescape unconditionally rather than through select_autoescape, which
    # decides by final file extension and would leave report.html.j2 unescaped.
    # Principal ids and tags come from somebody's AWS account.
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    payload = to_dict(report)
    shown = payload["findings"][:TABLE_LIMIT]
    html = env.get_template("report.html.j2").render(
        shown=shown, truncated=max(0, len(payload["findings"]) - len(shown)), **payload
    )
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return out_path
