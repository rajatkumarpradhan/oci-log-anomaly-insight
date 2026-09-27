"""Synthetic OCI audit-style log generator.

Emits JSON-ish audit events (OCI Audit shape: eventType, source, message)
for a set of normal services plus injectable incident scenarios that flood
the stream with rare templates. Deterministic per seed.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

NORMAL_TEMPLATES = [
    ("com.oraclecloud.identity.signin", "User <*> signed in from <*>"),
    ("com.oraclecloud.computeapi.launchinstance", "Launch instance <*> in compartment <*>"),
    ("com.oraclecloud.objectstorage.getobject", "GetObject bucket <*> key <*>"),
    ("com.oraclecloud.objectstorage.putobject", "PutObject bucket <*> bytes <*>"),
    ("com.oraclecloud.database.updateautonomousdatabase", "Update Autonomous Database <*> cpu <*>"),
    ("com.oraclecloud.virtualnetwork.createroutetable", "Create route table <*> vcn <*>"),
    ("com.oraclecloud.loadbalancer.updatebackendset", "Update backend set <*> health <*>"),
]
INCIDENT_TEMPLATES = [
    ("com.oraclecloud.identityauthentication.failures", "Authentication failed for <*> reason <*>"),
    ("com.oraclecloud.computeapi.terminateinstance", "Terminate instance <*> initiated by <*>"),
    ("com.oraclecloud.objectstorage.deletebucket", "DeleteBucket bucket <*> requested"),
    ("com.oraclecloud.identity.deleteuser", "Delete user <*> by <*>"),
]


@dataclass
class LogEvent:
    ts: int          # seconds since series start
    source: str      # emitting service
    event_type: str
    message: str
    scenario: str    # "normal" or incident name


def _rand(seed: str, i: int) -> float:
    d = hashlib.sha256(f"{seed}:{i}".encode()).digest()
    return int.from_bytes(d[:8], "big") / 2**64


def generate(n_events: int = 2000, seed: str = "audit",
             incident_at: int | None = 1400, incident_len: int = 60,
             incident: str = "credential-stuffing") -> list[LogEvent]:
    """Normal background traffic with one injected incident window."""
    events = []
    for i in range(n_events):
        in_incident = incident_at is not None and incident_at <= i < incident_at + incident_len
        if in_incident:
            if incident == "credential-stuffing":
                tpl = INCIDENT_TEMPLATES[0]
            elif incident == "destructive-actions":
                tpl = INCIDENT_TEMPLATES[int(_rand(seed + "inc", i) * 3) + 1]
            else:
                raise ValueError(f"unknown incident {incident}")
            etype, msg = tpl
            scenario = incident
        else:
            etype, msg = NORMAL_TEMPLATES[int(_rand(seed, i) * len(NORMAL_TEMPLATES))]
            scenario = "normal"
        events.append(LogEvent(ts=i * 30, source=etype.split(".")[2],
                               event_type=etype, message=msg, scenario=scenario))
    return events
