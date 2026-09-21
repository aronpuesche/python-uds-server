"""Unit tests for UDS SID 0x22, ReadDataByIdentifier."""

import pytest

from uds_server import DidAccess, DidDefinition, UdsServer

pytestmark = pytest.mark.unit


def test_read_data_by_identifier_returns_did_and_value() -> None:
    server = UdsServer(dids=[DidDefinition(identifier=0x1234, length=2)])
    server.set_did_value(0x1234, b"\xab\xcd")

    assert server.handle_request(b"\x22\x12\x34") == b"\x62\x12\x34\xab\xcd"


def test_read_data_by_identifier_supports_multiple_dids() -> None:
    server = UdsServer(
        dids=[
            DidDefinition(identifier=0x1234, length=1, read_callback=lambda: b"A"),
            DidDefinition(identifier=0x5678, length=1, read_callback=lambda: b"B"),
        ]
    )

    assert server.handle_request(b"\x22\x12\x34\x56\x78") == b"\x62\x12\x34A\x56\x78B"


def test_read_data_by_identifier_rejects_unknown_or_unreadable_dids() -> None:
    server = UdsServer(
        dids=[
            DidDefinition(identifier=0x1234, length=1, access=DidAccess.WRITE),
        ]
    )

    assert server.handle_request(b"\x22\x12\x34") == b"\x7f\x22\x31"
    assert server.handle_request(b"\x22\x00\x01") == b"\x7f\x22\x31"


def test_read_data_by_identifier_rejects_malformed_requests() -> None:
    server = UdsServer()

    assert server.handle_request(b"\x22") == b"\x7f\x22\x13"
    assert server.handle_request(b"\x22\x12") == b"\x7f\x22\x13"
