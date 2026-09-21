"""Unit tests for ClearDiagnosticInformation and ReadDTCInformation."""

import pytest

from uds_server import DtcDefinition, DtcSnapshot, UdsServer

pytestmark = pytest.mark.unit


def test_read_dtc_information_filters_status_and_reports_count() -> None:
    server = UdsServer(
        dtcs=[DtcDefinition(0x123456, 0x09), DtcDefinition(0x654321, 0x20)]
    )

    assert server.handle_request(b"\x19\x01\x08") == b"\x59\x01\x29\x01\x00\x01"
    assert server.handle_request(b"\x19\x02\x20") == b"\x59\x02\x29\x65\x43\x21\x20"
    assert server.handle_request(b"\x19\x02") == b"\x7f\x19\x13"
    assert server.handle_request(b"\x19\x05") == b"\x7f\x19\x13"


def test_read_dtc_snapshot_information_and_record() -> None:
    server = UdsServer(
        dtcs=[
            DtcDefinition(
                0x123456,
                0x08,
                snapshots=(DtcSnapshot(1, {0xF190: b"VIN"}),),
            )
        ]
    )

    assert server.handle_request(b"\x19\x03") == b"\x59\x03\x12\x34\x56\x01"
    assert server.handle_request(b"\x19\x05\x01") == (
        b"\x59\x05\x12\x34\x56\x08\x01\x01\xf1\x90VIN"
    )
    assert server.handle_request(b"\x19\x04\x12\x34\x56\x01") == (
        b"\x59\x04\x12\x34\x56\x08\x01\x01\xf1\x90VIN"
    )
    assert server.handle_request(b"\x19\x04\x12\x34\x56\x02") == b"\x7f\x19\x31"


def test_clear_diagnostic_information_clears_matching_codes() -> None:
    server = UdsServer(
        dtcs=[DtcDefinition(0x123456, 0x08), DtcDefinition(0x654321, 0x20)]
    )

    assert server.handle_request(b"\x14\xff\xff\xff") == b"\x54"
    assert server.handle_request(b"\x19\x02\x08") == b"\x59\x02\x00"
    assert server.handle_request(b"\x14\xff") == b"\x7f\x14\x13"


def test_read_extended_data_supported_and_history_dtc_queries() -> None:
    server = UdsServer(
        dtcs=[
            DtcDefinition(0x111111, 0x09, extended_data={1: b"X"}),
            DtcDefinition(0x222222, 0x08, permanent=True, fault_detection_counter=4),
        ]
    )

    assert server.handle_request(b"\x19\x06\x11\x11\x11\x01") == (
        b"\x59\x06\x11\x11\x11\x09\x01X"
    )
    assert server.handle_request(b"\x19\x16\x01") == b"\x59\x16\x01\x11\x11\x11\x09X"
    assert server.handle_request(b"\x19\x0a") == (
        b"\x59\x0a\x09\x11\x11\x11\x09\x22\x22\x22\x08"
    )
    assert server.handle_request(b"\x19\x0c") == b"\x59\x0c\x09\x11\x11\x11\x09"
    assert server.handle_request(b"\x19\x15") == b"\x59\x15\x09\x22\x22\x22\x08"
    assert server.handle_request(b"\x19\x14") == (
        b"\x59\x14\x11\x11\x11\x00\x22\x22\x22\x04"
    )


def test_read_dtc_severity_information() -> None:
    server = UdsServer(
        dtcs=[DtcDefinition(0x123456, 0x08, severity=0x80, functional_unit=2)]
    )

    assert server.handle_request(b"\x19\x07\x80\x08") == b"\x59\x07\x08\x01\x00\x01"
    assert server.handle_request(b"\x19\x08\x80\x08") == (
        b"\x59\x08\x08\x80\x02\x12\x34\x56\x08"
    )
    assert server.handle_request(b"\x19\x09\x12\x34\x56") == (
        b"\x59\x09\x80\x02\x12\x34\x56\x08"
    )
