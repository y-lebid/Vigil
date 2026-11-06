from datetime import datetime, timezone

from vigil.models.event import Event


def test_event_creation():
    timestamp = datetime(
        2026, 11, 6, 8, 32, 15,
        tzinfo=timezone.utc
    )

    event = Event(
        timestamp=timestamp,
        host="server",
        service="sshd",
        event_type="failed_login",
        user="admin",
        source_ip="192.168.1.50",
        port=51234,
        raw="Failed password for admin from 192.168.1.50 port 51234"
    )

    assert event.timestamp == timestamp
    assert event.host == "server"
    assert event.service == "sshd"
    assert event.event_type == "failed_login"
    assert event.user == "admin"
    assert event.source_ip == "192.168.1.50"
    assert event.port == 51234


def test_event_optional_fields():
    event = Event(
        timestamp=datetime(2026, 11, 6, tzinfo=timezone.utc),
        host="server",
        service="sshd",
        event_type="connection_closed",
        user=None,
        source_ip=None,
        port=None,
        raw="Connection closed"
    )

    assert event.user is None
    assert event.source_ip is None
    assert event.port is None
