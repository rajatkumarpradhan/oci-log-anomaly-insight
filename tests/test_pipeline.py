import pytest

from log_anomaly.detect import detect
from log_anomaly.drain import DrainMiner
from log_anomaly.report import summarize
from log_anomaly.synth import generate


def run_pipeline(**kw):
    events = generate(**kw)
    miner = DrainMiner()
    ids = miner.parse_all([e.message for e in events])
    templates = [c.template_str for c in miner.clusters]
    return events, ids, templates, detect(ids, [e.ts for e in events], templates)


def test_synth_deterministic():
    a = generate(200, seed="x")
    b = generate(200, seed="x")
    assert [(e.event_type, e.message) for e in a] == [(e.event_type, e.message) for e in b]


def test_incident_window_injected():
    events = generate(300, seed="s", incident_at=100, incident_len=20)
    flagged = [e for e in events if e.scenario != "normal"]
    assert len(flagged) == 20
    assert all("Authentication failed" in e.message for e in flagged)


def test_drain_merges_templates():
    miner = DrainMiner()
    miner.add("GetObject bucket alpha key f1")
    miner.add("GetObject bucket beta key f2")
    assert len(miner.clusters) == 1
    assert miner.clusters[0].template_str == "GetObject bucket <*> key <*>"
    assert miner.clusters[0].count == 2


def test_drain_keeps_distinct_lengths_separate():
    miner = DrainMiner()
    miner.add("a b c")
    miner.add("a b")
    assert len(miner.clusters) == 2


def test_detector_finds_injected_incident():
    events, ids, templates, anomalies = run_pipeline(n_events=2000, seed="audit")
    assert anomalies, "injected incident was missed"
    top = max(anomalies, key=lambda a: a.window_count)
    assert "Authentication failed" in top.template


def test_detector_quiet_on_clean_traffic():
    _, _, _, anomalies = run_pipeline(n_events=2000, seed="audit", incident_at=None)
    assert anomalies == []


def test_destructive_actions_incident_detected():
    _, _, _, anomalies = run_pipeline(n_events=2000, seed="audit",
                                      incident="destructive-actions")
    assert anomalies


def test_detection_precision_recall():
    """Eval gate: flagged clusters must cover the incident with no false clusters."""
    events = generate(n_events=2000, seed="audit")
    miner = DrainMiner()
    ids = miner.parse_all([e.message for e in events])
    templates = [c.template_str for c in miner.clusters]
    anomalies = detect(ids, [e.ts for e in events], templates)
    truth_clusters = {ids[i] for i, e in enumerate(events) if e.scenario != "normal"}
    found_clusters = {a.cluster_id for a in anomalies}
    assert truth_clusters <= found_clusters, "recall < 1.0"
    assert found_clusters <= truth_clusters, "false-positive clusters"


def test_report_cites_real_events():
    events, ids, templates, anomalies = run_pipeline(n_events=2000, seed="audit")
    report = summarize(anomalies, [e.message for e in events], ids)
    assert report is not None
    for cid, idxs in report.citations.items():
        for i in idxs:
            assert ids[i] == cid
    assert report.severity in {"medium", "high"}


def test_no_anomaly_no_report():
    events = generate(n_events=200, seed="q", incident_at=None)
    miner = DrainMiner()
    ids = miner.parse_all([e.message for e in events])
    assert summarize([], [e.message for e in events], ids) is None
