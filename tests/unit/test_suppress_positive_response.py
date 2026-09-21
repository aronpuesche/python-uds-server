"""Unit tests for the suppress-positive-response subfunction bit."""

import pytest

from uds_server import DiagnosticSession, RoutineDefinition, SecurityLevel, UdsServer

pytestmark = pytest.mark.unit


def test_suppress_positive_response_keeps_successful_service_side_effects() -> None:
    server = UdsServer(
        sessions=[DiagnosticSession(1), DiagnosticSession(3)],
        security_levels=[SecurityLevel(1, lambda: b"\xaa", lambda _seed, _: True)],
        routines=[RoutineDefinition(0x0203, start_callback=lambda _: b"done")],
    )

    assert server.handle_request(b"\x10\x83") == b""
    assert server.current_session == 3
    assert server.handle_request(b"\x27\x81") == b""
    assert server.handle_request(b"\x27\x82\x00") == b""
    assert server.is_security_level_unlocked(1)
    assert server.handle_request(b"\x31\x81\x02\x03") == b""
    assert server.handle_request(b"\x3e\x80") == b""


def test_suppress_positive_response_does_not_suppress_negative_responses() -> None:
    server = UdsServer()

    assert server.handle_request(b"\x10\xff") == b"\x7f\x10\x12"
    assert server.handle_request(b"\x27\x85") == b"\x7f\x27\x12"
    assert server.handle_request(b"\x31\x81\x00\x01") == b"\x7f\x31\x31"
    assert server.handle_request(b"\x3e\x81") == b"\x7f\x3e\x12"
