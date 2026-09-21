"""Unit tests for SID 0x2F, InputOutputControlByIdentifier."""

import pytest

from uds_server import IoControlDefinition, ProgrammingFailure, UdsServer

pytestmark = pytest.mark.unit


def test_short_term_io_adjustment_and_return_control_to_ecu() -> None:
    calls: list[tuple[int, bytes, bytes]] = []
    server = UdsServer(
        io_controls=[
            IoControlDefinition(
                0x1234,
                1,
                callback=lambda parameter, value, mask: calls.append(
                    (parameter, value, mask)
                )
                or b"S",
            )
        ]
    )

    assert server.handle_request(b"\x2f\x12\x34\x03A") == b"\x6f\x12\x34\x03S"
    assert server.get_io_control(0x1234).value == b"A"
    assert server.handle_request(b"\x2f\x12\x34\x00") == b"\x6f\x12\x34\x00S"
    assert not server.get_io_control(0x1234).is_controlled
    assert calls == [(3, b"A", b""), (0, b"A", b"")]


def test_io_control_applies_mask_and_maps_errors() -> None:
    server = UdsServer(
        io_controls=[IoControlDefinition(0x1234, 1, mask_length=1)],
    )
    failed = UdsServer(
        io_controls=[
            IoControlDefinition(
                0x1234,
                1,
                callback=lambda *_: (_ for _ in ()).throw(ProgrammingFailure()),
            )
        ]
    )

    server.handle_request(b"\x2f\x12\x34\x03\xaa")
    assert server.handle_request(b"\x2f\x12\x34\x03\x0f\x0f") == b"\x6f\x12\x34\x03"
    assert server.get_io_control(0x1234).value == b"\xaf"
    assert server.handle_request(b"\x2f\x12\x34\x03") == b"\x7f\x2f\x13"
    assert failed.handle_request(b"\x2f\x12\x34\x03A") == b"\x7f\x2f\x72"
