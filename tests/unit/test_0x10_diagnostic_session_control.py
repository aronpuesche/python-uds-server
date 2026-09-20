"""Unit tests for SID 0x10, DiagnosticSessionControl."""

import pytest
from unittest.mock import patch

from uds_server import DiagnosticSession, SecurityLevel, UdsServer

pytestmark = pytest.mark.unit


def test_diagnostic_session_control_changes_session_and_returns_timings() -> None:
    server = UdsServer(sessions=[DiagnosticSession(1), DiagnosticSession(3, 100, 5000)])

    assert server.handle_request(b"\x10\x03") == b"\x50\x03\x00\x64\x01\xf4"
    assert server.current_session == 3


def test_diagnostic_session_times_out_to_default_session() -> None:
    server = UdsServer(
        sessions=[DiagnosticSession(1), DiagnosticSession(3, s3_server_timeout_ms=10)]
    )

    server.handle_request(b"\x10\x03")
    with patch(
        "uds_server.server.monotonic", return_value=server._session_last_activity + 0.01
    ):
        assert server.current_session == 1


def test_diagnostic_session_timeout_revokes_security_access() -> None:
    server = UdsServer(
        sessions=[DiagnosticSession(1), DiagnosticSession(3, s3_server_timeout_ms=10)],
        security_levels=[SecurityLevel(1, lambda: b"\xaa", lambda _seed, _key: True)],
    )

    server.handle_request(b"\x10\x03")
    server.handle_request(b"\x27\x01")
    server.handle_request(b"\x27\x02\x00")
    assert server.is_security_level_unlocked(1)

    with patch(
        "uds_server.server.monotonic", return_value=server._session_last_activity + 0.01
    ):
        assert not server.is_security_level_unlocked(1)
