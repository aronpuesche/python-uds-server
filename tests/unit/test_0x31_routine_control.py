"""Unit tests for SID 0x31, RoutineControl."""

import pytest

from uds_server import AccessRule, ProgrammingFailure, RoutineDefinition, UdsServer

pytestmark = pytest.mark.unit


def test_routine_control_dispatches_callbacks_and_returns_status_record() -> None:
    received: list[bytes] = []
    server = UdsServer(
        routines=[
            RoutineDefinition(
                0x0203,
                start_callback=lambda option: received.append(option) or b"started",
                stop_callback=lambda option: b"stopped",
                results_callback=lambda option: b"results",
            )
        ]
    )

    assert server.handle_request(b"\x31\x01\x02\x03\xaa") == b"\x71\x01\x02\x03started"
    assert received == [b"\xaa"]
    assert server.handle_request(b"\x31\x02\x02\x03") == b"\x71\x02\x02\x03stopped"
    assert server.handle_request(b"\x31\x03\x02\x03") == b"\x71\x03\x02\x03results"


def test_routine_control_rejects_malformed_unknown_and_unsupported_requests() -> None:
    server = UdsServer(
        routines=[RoutineDefinition(0x0203, start_callback=lambda _: b"")]
    )

    assert server.handle_request(b"\x31") == b"\x7f\x31\x13"
    assert server.handle_request(b"\x31\x01\x02") == b"\x7f\x31\x13"
    assert server.handle_request(b"\x31\x04\x02\x03") == b"\x7f\x31\x12"
    assert server.handle_request(b"\x31\x01\x00\x01") == b"\x7f\x31\x31"
    assert server.handle_request(b"\x31\x02\x02\x03") == b"\x7f\x31\x12"


def test_routine_control_applies_access_conditions_and_callback_errors() -> None:
    blocked = UdsServer(
        routines=[
            RoutineDefinition(
                0x0203,
                start_callback=lambda _: b"",
                access_rule=AccessRule(allowed_sessions=frozenset({0x03})),
            )
        ]
    )
    unavailable = UdsServer(
        routines=[
            RoutineDefinition(
                0x0203, start_callback=lambda _: b"", condition=lambda: False
            )
        ]
    )
    failed = UdsServer(
        routines=[
            RoutineDefinition(
                0x0203,
                start_callback=lambda _: (_ for _ in ()).throw(ProgrammingFailure()),
            )
        ]
    )
    broken_condition = UdsServer(
        routines=[
            RoutineDefinition(
                0x0203,
                start_callback=lambda _: b"",
                condition=lambda: (_ for _ in ()).throw(RuntimeError()),
            )
        ]
    )

    assert blocked.handle_request(b"\x31\x01\x02\x03") == b"\x7f\x31\x7f"
    assert unavailable.handle_request(b"\x31\x01\x02\x03") == b"\x7f\x31\x22"
    assert failed.handle_request(b"\x31\x01\x02\x03") == b"\x7f\x31\x72"
    assert broken_condition.handle_request(b"\x31\x01\x02\x03") == b"\x7f\x31\x10"
