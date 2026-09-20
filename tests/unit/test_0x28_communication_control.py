"""Unit tests for SID 0x28, CommunicationControl."""

import pytest

from uds_server import CommunicationControlDefinition, UdsServer

pytestmark = pytest.mark.unit


def test_communication_control_invokes_callback_and_echoes_control_type() -> None:
    calls: list[tuple[int, int, int | None]] = []
    server = UdsServer(
        communication_controls=[
            CommunicationControlDefinition(0, lambda *args: calls.append(args)),
            CommunicationControlDefinition(4, lambda *args: calls.append(args)),
        ]
    )

    assert server.handle_request(b"\x28\x00\x03") == b"\x68\x00"
    assert server.handle_request(b"\x28\x04\x03\x12\x34") == b"\x68\x04"
    assert calls == [(0, 3, None), (4, 3, 0x1234)]


def test_communication_control_validates_request_and_suppresses_response() -> None:
    server = UdsServer(communication_controls=[CommunicationControlDefinition(0)])

    assert server.handle_request(b"\x28\x80\x03") == b""
    assert server.handle_request(b"\x28\x00") == b"\x7f\x28\x13"
    assert server.handle_request(b"\x28\x01\x03") == b"\x7f\x28\x12"
    assert server.handle_request(b"\x28\x00\x00") == b"\x7f\x28\x31"
