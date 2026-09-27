"""Incident summarization with citations back to raw events.

Every claim in the summary cites concrete event indices so a reviewer can
verify it against the source stream. No LLM, no external calls: the
narrative is assembled from the anomaly evidence itself.
"""
from __future__ import annotations

from dataclasses import dataclass

from .detect import Anomaly


@dataclass
class IncidentReport:
    headline: str
    severity: str
    evidence: list[str]   # each line cites event indices
    citations: dict[int, list[int]]  # cluster_id -> event indices


def summarize(anomalies: list[Anomaly], messages: list[str],
              cluster_ids: list[int], max_cites: int = 5) -> IncidentReport | None:
    if not anomalies:
        return None
    top = max(anomalies, key=lambda a: a.window_count)
    idxs = [i for i, cid in enumerate(cluster_ids) if cid == top.cluster_id][:max_cites]
    severity = "high" if top.kind == "new-template" and top.window_count >= 10 else "medium"
    headline = (f"Suspicious new log pattern: '{top.template}' "
                f"({top.window_count} events in one window)")
    evidence = [
        f"Template first appeared at t={top.window_start}s with no baseline occurrence "
        f"(events {idxs[0]}-{idxs[-1]} cited)." if top.kind == "new-template"
        else f"Rate jumped from {top.baseline_rate}/window baseline to {top.window_count} "
             f"(events {idxs[0]}-{idxs[-1]} cited).",
        f"Example raw event [#{idxs[0]}]: {messages[idxs[0]]}",
    ]
    return IncidentReport(headline=headline, severity=severity,
                          evidence=evidence,
                          citations={top.cluster_id: idxs})
