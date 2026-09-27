"""Template-rate anomaly detection over a parsed event stream.

Two signals, both explainable:
1. new-template: a cluster first seen inside the window (never in baseline)
2. rate-spike: cluster events/hour in the window exceeds
   baseline_rate * ratio AND baseline + min_count
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Anomaly:
    cluster_id: int
    kind: str            # new-template | rate-spike
    window_start: int
    window_end: int
    window_count: int
    baseline_rate: float  # events per window in baseline
    window_rate: float
    template: str


def detect(cluster_ids: list[int], timestamps: list[int],
           templates: list[str], window: int = 900,
           baseline_frac: float = 0.6, ratio: float = 5.0,
           min_count: int = 10) -> list[Anomaly]:
    if not cluster_ids:
        return []
    n = len(cluster_ids)
    split = int(n * baseline_frac)
    base_ids = cluster_ids[:split]
    base_t0, base_t1 = timestamps[0], timestamps[split - 1] if split else timestamps[0]
    base_span = max(base_t1 - base_t0, 1)
    base_windows = max(base_span / window, 1e-9)
    base_counts: dict[int, int] = {}
    for cid in base_ids:
        base_counts[cid] = base_counts.get(cid, 0) + 1
    anomalies = []
    # sliding non-overlapping windows over the detection region
    t = timestamps[split] if split < n else timestamps[-1] + 1
    end = timestamps[-1]
    seen_new: set[int] = set()
    while t <= end:
        w_end = t + window
        window_counts: dict[int, int] = {}
        for cid, ts in zip(cluster_ids, timestamps):
            if t <= ts < w_end:
                window_counts[cid] = window_counts.get(cid, 0) + 1
        for cid, cnt in window_counts.items():
            b_rate = base_counts.get(cid, 0) / base_windows
            if cid not in base_counts and cid not in seen_new and cnt >= 3:
                anomalies.append(Anomaly(cid, "new-template", t, w_end, cnt,
                                         0.0, cnt, templates[cid]))
                seen_new.add(cid)
            elif cid in base_counts and cnt >= max(min_count, b_rate * ratio):
                anomalies.append(Anomaly(cid, "rate-spike", t, w_end, cnt,
                                         round(b_rate, 2), float(cnt),
                                         templates[cid]))
        t = w_end
    return anomalies
