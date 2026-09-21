"""Integration tests for ECUReset."""

import pytest
from udsoncan import ResponseCode
from udsoncan.exceptions import NegativeResponseException

from uds_server import EcuResetDefinition, UdsServer

pytestmark = pytest.mark.integration


def test_client_receives_ecu_reset_response(uds_client) -> None:
    server = UdsServer(resets=[EcuResetDefinition(0x01)])

    with uds_client(server) as uds:
        response = uds.client.ecu_reset(0x01)

    assert response is not None
    assert response.service_data.reset_type_echo == 0x01


def test_client_reports_unsupported_reset_type(uds_client) -> None:
    server = UdsServer(resets=[EcuResetDefinition(0x01)])

    with uds_client(server) as uds:
        with pytest.raises(NegativeResponseException) as error:
            uds.client.ecu_reset(0x03)

    assert (
        error.value.response.code == ResponseCode.ResponseCode.SubFunctionNotSupported
    )
