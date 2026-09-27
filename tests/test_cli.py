import json

from log_anomaly.cli import main


def test_cli_json(capsys):
    assert main(["--events", "2000"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["events"] == 2000
    assert out["anomalies"]
    assert out["report"]["severity"] == "high"
    assert out["ground_truth_incident_events"] == 60


def test_cli_no_incident(capsys):
    assert main(["--events", "1500", "--incident", "none"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["anomalies"] == []
    assert out["report"] is None
