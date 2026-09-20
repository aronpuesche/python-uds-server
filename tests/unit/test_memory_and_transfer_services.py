"""Unit tests for memory access and upload/download transfer SIDs."""

import pytest

from uds_server import MemoryAccess, MemoryRegionDefinition, UdsServer

pytestmark = pytest.mark.unit


def test_read_and_write_memory_by_address() -> None:
    server = UdsServer(memory_regions=[MemoryRegionDefinition(0x1000, 8)])

    assert server.handle_request(b"\x3d\x22\x10\x00\x00\x03ABC") == (
        b"\x7d\x22\x10\x00\x00\x03"
    )
    assert server.handle_request(b"\x23\x22\x10\x00\x00\x03") == b"\x63ABC"
    assert server.handle_request(b"\x23\x22\x10\x06\x00\x03") == b"\x7f\x23\x31"
    assert server.handle_request(b"\x3d\x22\x10\x00\x00\x02A") == b"\x7f\x3d\x13"


def test_memory_access_mode_and_conditions_are_enforced() -> None:
    read_only = UdsServer(
        memory_regions=[MemoryRegionDefinition(0x1000, 1, access=MemoryAccess.READ)]
    )
    blocked = UdsServer(
        memory_regions=[MemoryRegionDefinition(0x1000, 1, condition=lambda: False)]
    )

    assert read_only.handle_request(b"\x3d\x22\x10\x00\x00\x01A") == b"\x7f\x3d\x31"
    assert blocked.handle_request(b"\x23\x22\x10\x00\x00\x01") == b"\x7f\x23\x22"


def test_download_and_upload_transfer_data() -> None:
    server = UdsServer(
        memory_regions=[MemoryRegionDefinition(0x1000, 8)], max_transfer_block_length=5
    )

    assert server.handle_request(b"\x34\x00\x22\x10\x00\x00\x03") == b"\x74\x10\x05"
    assert server.handle_request(b"\x36\x01ABC") == b"\x76\x01"
    assert server.handle_request(b"\x37") == b"\x77"
    assert server.handle_request(b"\x35\x00\x22\x10\x00\x00\x03") == b"\x75\x10\x05"
    assert server.handle_request(b"\x36\x01") == b"\x76\x01ABC"
    assert server.handle_request(b"\x37") == b"\x77"


def test_transfer_requires_ordered_blocks_and_complete_exit() -> None:
    server = UdsServer(memory_regions=[MemoryRegionDefinition(0x1000, 8)])

    assert server.handle_request(b"\x36\x01") == b"\x7f\x36\x24"
    server.handle_request(b"\x34\x00\x22\x10\x00\x00\x03")
    assert server.handle_request(b"\x36\x02A") == b"\x7f\x36\x73"
    assert server.handle_request(b"\x36\x01A") == b"\x76\x01"
    assert server.handle_request(b"\x37") == b"\x7f\x37\x24"
