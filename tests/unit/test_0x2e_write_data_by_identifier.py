"""Unit tests for SID 0x2E, WriteDataByIdentifier."""

import pytest

from uds_server import DidDefinition, ProgrammingFailure, UdsServer

pytestmark = pytest.mark.unit


def test_write_data_by_identifier_updates_default_storage() -> None:
    server = UdsServer(dids=[DidDefinition(0x1234, 2)])

    assert server.handle_request(b"\x2e\x12\x34OK") == b"\x6e\x12\x34"
    assert server.handle_request(b"\x22\x12\x34") == b"\x62\x12\x34OK"


def test_write_data_by_identifier_reports_conditions_and_programming_failure() -> None:
    blocked = UdsServer(dids=[DidDefinition(0x1234, 2, condition=lambda: False)])
    failed = UdsServer(
        dids=[
            DidDefinition(
                0x1234,
                2,
                write_callback=lambda value: (_ for _ in ()).throw(
                    ProgrammingFailure()
                ),
            )
        ]
    )

    assert blocked.handle_request(b"\x2e\x12\x34OK") == b"\x7f\x2e\x22"
    assert failed.handle_request(b"\x2e\x12\x34OK") == b"\x7f\x2e\x72"
