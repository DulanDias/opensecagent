# OpenSecAgent - Model tests
from opensecagent.models import Severity, Incident, Event, severity_from_str


def test_severity_from_str():
    assert severity_from_str("P1") == Severity.P1
    assert severity_from_str("P4") == Severity.P4
    assert severity_from_str("unknown") == Severity.P4


def test_incident_event_type_matches():
    ev = Event("e1", "drift", "config_drift", Severity.P2, "summary", {})
    inc = Incident(
        "inc-1", Severity.P2, "Title", "Narrative", [ev],
        {"k": "v"}, ["Review"]
    )
    assert inc.event_type_matches("config_drift") is True
    assert inc.event_type_matches("auth_failures") is False
