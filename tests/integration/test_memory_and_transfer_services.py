"""Integration tests for UDS memory access and transfer services."""

import pytest
from udsoncan.common.MemoryLocation import MemoryLocation

from uds_server import MemoryRegionDefinition, UdsServer

pytestmark = pytest.mark.integration


def memory_location(address: int, size: int) -> MemoryLocation:
    return MemoryLocation(address, size, address_format=16, memorysize_format=16)


def test_client_reads_and_writes_memory_by_address(uds_client) -> None:
    server = UdsServer(memory_regions=[MemoryRegionDefinition(0x1000, 16)])
    location = memory_location(0x1002, 3)

    with uds_client(server) as uds:
        uds.client.write_memory_by_address(location, b"ABC")
        response = uds.client.read_memory_by_address(location)

    assert response is not None
    assert response.service_data.memory_block == b"ABC"


def test_client_transfers_download_and_upload_blocks(uds_client) -> None:
    server = UdsServer(
        memory_regions=[MemoryRegionDefinition(0x1000, 16)], max_transfer_block_length=5
    )
    location = memory_location(0x1000, 3)

    with uds_client(server) as uds:
        download = uds.client.request_download(location)
        assert download is not None
        assert download.service_data.max_length == 5
        uds.client.transfer_data(1, b"ABC")
        assert uds.request_raw(b"\x37") is not None

        upload = uds.client.request_upload(location)
        assert upload is not None
        response = uds.client.transfer_data(1)
        assert response is not None
        assert response.service_data.parameter_records == b"ABC"
        assert uds.request_raw(b"\x37") is not None
