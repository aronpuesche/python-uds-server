"""Unit tests for SID 0x11, ECUReset."""

import pytest

from uds_server import (
    AccessRule,
    DiagnosticSession,
    EcuResetDefinition,
    ProgrammingFailure,
    SecurityLevel,
    UdsServer,
)

pytestmark = pytest.mark.unit


def test_ecu_reset_runs_callback_and_resets_diagnostic_state() -> None:
    callbacks: list[str] = []
    server = UdsServer(
        sessions=[DiagnosticSession(1), DiagnosticSession(3)],
        security_levels=[SecurityLevel(1, lambda: b"\xaa", lambda _seed, _key: True)],
        resets=[EcuResetDefinition(0x01, callback=lambda: callbacks.append("reset"))],
    )
    server.handle_request(b"\x10\x03")
    server.handle_request(b"\x27\x01")
    server.handle_request(b"\x27\x02\x00")

    assert server.handle_request(b"\x11\x01") == b"\x51\x01"
    assert callbacks == ["reset"]
    assert server.current_session == 1
    assert not server.is_security_level_unlocked(1)


def test_ecu_reset_enforces_access_and_maps_errors() -> None:
    blocked = UdsServer(
        resets=[EcuResetDefinition(1, condition=lambda: False)],
    )
    protected = UdsServer(
        resets=[EcuResetDefinition(1, access_rule=AccessRule(frozenset({3})))],
    )
    failed = UdsServer(
        resets=[
            EcuResetDefinition(
                1,
                callback=lambda: (_ for _ in ()).throw(ProgrammingFailure()),
            )
        ],
    )

    assert blocked.handle_request(b"\x11\x01") == b"\x7f\x11\x22"
    assert protected.handle_request(b"\x11\x01") == b"\x7f\x11\x7f"
    assert failed.handle_request(b"\x11\x01") == b"\x7f\x11\x72"
    assert blocked.handle_request(b"\x11") == b"\x7f\x11\x13"
    assert blocked.handle_request(b"\x11\x03") == b"\x7f\x11\x12"


def test_ecu_reset_supports_suppression_and_rapid_power_down_time() -> None:
    server = UdsServer(resets=[EcuResetDefinition(0x04, power_down_time=10)])

    assert server.handle_request(b"\x11\x84") == b""
    assert server.handle_request(b"\x11\x04") == b"\x51\x04\x0a"
