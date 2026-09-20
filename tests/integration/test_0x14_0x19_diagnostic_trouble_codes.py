"""Integration tests for UDS DTC services."""

import pytest

from uds_server import DtcDefinition, UdsServer

pytestmark = pytest.mark.integration


def test_client_reads_and_clears_diagnostic_trouble_codes(uds_client) -> None:
    server = UdsServer(
        dtcs=[DtcDefinition(0x123456, 0x09), DtcDefinition(0x654321, 0x20)]
    )

    with uds_client(server) as uds:
        count = uds.client.get_number_of_dtc_by_status_mask(0x08)
        dtcs = uds.client.get_dtc_by_status_mask(0x20)
        cleared = uds.client.clear_dtc()

    assert count is not None
    assert count.service_data.dtc_count == 1
    assert dtcs is not None
    assert [dtc.id for dtc in dtcs.service_data.dtcs] == [0x654321]
    assert cleared is not None


def test_client_reads_supported_and_first_confirmed_dtcs(uds_client) -> None:
    server = UdsServer(
        dtcs=[DtcDefinition(0x123456, 0x09), DtcDefinition(0x654321, 0x20)]
    )

    with uds_client(server) as uds:
        supported = uds.client.get_supported_dtc()
        confirmed = uds.client.get_first_confirmed_dtc()

    assert supported is not None
    assert [dtc.id for dtc in supported.service_data.dtcs] == [0x123456, 0x654321]
    assert confirmed is not None
    assert [dtc.id for dtc in confirmed.service_data.dtcs] == [0x123456]


def test_client_reads_extended_data_by_record_number(uds_client) -> None:
    server = UdsServer(dtcs=[DtcDefinition(0x123456, 0x08, extended_data={1: b"X"})])

    with uds_client(server) as uds:
        response = uds.client.get_dtc_extended_data_by_record_number(1, data_size=1)

    assert response is not None
    assert response.service_data.dtcs[0].id == 0x123456
    assert response.service_data.dtcs[0].extended_data[0].raw_data == b"X"
