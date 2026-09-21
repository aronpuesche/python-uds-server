"""Integration tests for RequestFileTransfer."""

import pytest

from uds_server import FileDefinition, UdsServer

pytestmark = pytest.mark.integration


def test_client_adds_and_reads_virtual_file(uds_client) -> None:
    server = UdsServer(
        files=[FileDefinition("new", None), FileDefinition("old", b"ABC")],
        max_transfer_block_length=5,
    )

    with uds_client(server) as uds:
        added = uds.client.request_file_transfer(1, "new", filesize=3)
        assert added is not None
        assert added.service_data.max_length == 5
        uds.client.transfer_data(1, b"ABC")
        assert uds.request_raw(b"\x37") is not None

        read = uds.client.request_file_transfer(4, "old")
        assert read is not None
        response = uds.client.transfer_data(1)
        assert response is not None
        assert response.service_data.parameter_records == b"ABC"
        assert uds.request_raw(b"\x37") is not None

    assert server.get_file("new").data == b"ABC"
