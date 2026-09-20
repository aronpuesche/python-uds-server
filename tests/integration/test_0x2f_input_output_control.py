"""Integration tests for InputOutputControlByIdentifier."""

import pytest

from uds_server import IoControlDefinition, UdsServer

pytestmark = pytest.mark.integration


def test_client_sends_io_control_request(uds_client) -> None:
    server = UdsServer(io_controls=[IoControlDefinition(0x1234, 1)])

    with uds_client(server) as uds:
        response = uds.request_raw(b"\x2f\x12\x34\x03A")

    assert response is not None
    assert response.original_payload == b"\x6f\x12\x34\x03"
