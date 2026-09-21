"""Integration tests for CommunicationControl."""

import pytest

from uds_server import CommunicationControlDefinition, UdsServer

pytestmark = pytest.mark.integration


def test_client_controls_communication(uds_client) -> None:
    calls: list[tuple[int, int, int | None]] = []
    server = UdsServer(
        communication_controls=[
            CommunicationControlDefinition(0, lambda *args: calls.append(args))
        ]
    )

    with uds_client(server) as uds:
        response = uds.client.communication_control(0, 3)

    assert response is not None
    assert response.service_data.control_type_echo == 0
    assert calls == [(0, 3, None)]
