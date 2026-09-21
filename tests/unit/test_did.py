"""Unit tests for DID definitions and storage."""

import pytest

from uds_server import DidAccess, DidDefinition, UdsServer

pytestmark = pytest.mark.unit


def test_default_did_storage_is_readable_and_writable() -> None:
    server = UdsServer(dids=[DidDefinition(identifier=0x1234, length=2)])

    did = server.get_did(0x1234)
    assert did.value == b"\x00\x00"

    server.set_did_value(0x1234, b"\x12\x34")
    assert did.value == b"\x12\x34"


def test_callbacks_have_independent_read_and_write_signatures() -> None:
    written: list[bytes] = []
    server = UdsServer(
        dids=[
            DidDefinition(
                identifier=0xF190,
                length=2,
                read_callback=lambda: b"OK",
                write_callback=written.append,
            )
        ]
    )

    assert server.get_did(0xF190).value == b"OK"
    server.set_did_value(0xF190, b"NO")
    assert written == [b"NO"]


def test_did_value_must_match_its_declared_length() -> None:
    server = UdsServer(dids=[DidDefinition(identifier=0x1234, length=2)])

    with pytest.raises(ValueError, match="requires 2 bytes"):
        server.set_did_value(0x1234, b"\x00")


def test_write_access_is_enforced() -> None:
    server = UdsServer(
        dids=[
            DidDefinition(
                identifier=0x1234,
                length=2,
                access=DidAccess.READ,
            )
        ]
    )

    with pytest.raises(PermissionError, match="not writable"):
        server.set_did_value(0x1234, b"\x12\x34")
