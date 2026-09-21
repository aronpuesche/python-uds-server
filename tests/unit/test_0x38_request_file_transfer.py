"""Unit tests for SID 0x38, RequestFileTransfer."""

import pytest

from uds_server import FileDefinition, UdsServer

pytestmark = pytest.mark.unit


def test_add_file_transfers_data_into_a_reserved_virtual_path() -> None:
    server = UdsServer(files=[FileDefinition("new", None)], max_transfer_block_length=5)

    assert server.handle_request(b"\x38\x01\x00\x03new\x00\x01\x03\x03") == (
        b"\x78\x01\x01\x05\x00"
    )
    assert server.handle_request(b"\x36\x01ABC") == b"\x76\x01"
    assert server.handle_request(b"\x37") == b"\x77"
    assert server.get_file("new").data == b"ABC"


def test_read_and_delete_virtual_file() -> None:
    server = UdsServer(
        files=[FileDefinition("old", b"ABC")], max_transfer_block_length=5
    )

    assert server.handle_request(b"\x38\x04\x00\x03old\x00") == (
        b"\x78\x04\x01\x05\x00\x00\x01\x03\x03"
    )
    assert server.handle_request(b"\x36\x01") == b"\x76\x01ABC"
    assert server.handle_request(b"\x37") == b"\x77"
    assert server.handle_request(b"\x38\x02\x00\x03old") == b"\x78\x02"
    assert not server.get_file("old").exists


def test_file_transfer_rejects_unknown_operations_and_invalid_paths() -> None:
    server = UdsServer(files=[FileDefinition("old", b"A")])

    assert server.handle_request(b"\x38\x05\x00\x03old") == b"\x7f\x38\x12"
    assert server.handle_request(b"\x38\x04\x00\x03new\x00") == b"\x7f\x38\x31"
