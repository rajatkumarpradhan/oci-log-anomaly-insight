"""CLI: generate synthetic logs, mine templates, detect anomalies, report."""
from __future__ import annotations

import argparse
import json

from .detect import detect
from .drain import DrainMiner
from .report import summarize
from .synth import generate


def _pipeline(n_events: int, seed: str, incident: str | None) -> dict:
    events = generate(n_events=n_events, seed=seed,
                      incident_at=1400 if incident else None,
                      incident=incident or "credential-stuffing")
    miner = DrainMiner()
    ids = miner.parse_all([e.message for e in events])
    templates = [c.template_str for c in miner.clusters]
    anomalies = detect(ids, [e.ts for e in events], templates)
    report = summarize(anomalies, [e.message for e in events], ids)
    return {
        "events": len(events),
        "templates": [{"id": i, "template": c.template_str, "count": c.count}
                      for i, c in enumerate(miner.clusters)],
        "anomalies": [{"kind": a.kind, "cluster_id": a.cluster_id,
                       "window_count": a.window_count,
                       "template": a.template} for a in anomalies],
        "report": None if report is None else {
            "headline": report.headline,
            "severity": report.severity,
            "evidence": report.evidence,
            "citations": report.citations,
        },
        "ground_truth_incident_events": sum(1 for e in events if e.scenario != "normal"),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="log-anomaly",
                                description="Offline OCI-style log anomaly detection")
    p.add_argument("--events", type=int, default=2000)
    p.add_argument("--seed", default="audit")
    p.add_argument("--incident", default="credential-stuffing",
                   choices=["credential-stuffing", "destructive-actions", "none"])
    args = p.parse_args(argv)
    result = _pipeline(args.events, args.seed,
                       None if args.incident == "none" else args.incident)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
