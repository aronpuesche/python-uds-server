"""Integration tests for TesterPresent."""

import pytest
from udsoncan import ResponseCode

from uds_server import UdsServer

pytestmark = pytest.mark.integration


class TestTesterPresent:
    def test_client_sends_tester_present(self, uds_client) -> None:
        with uds_client(UdsServer()) as uds:
            assert uds.client.tester_present().original_payload == b"\x7e\x00"

    def test_negative_responses_and_suppression(self, uds_client) -> None:
        with uds_client(UdsServer()) as uds:
            for raw, code in [
                (
                    b"\x3e",
                    ResponseCode.ResponseCode.IncorrectMessageLengthOrInvalidFormat,
                ),
                (b"\x3e\x01", ResponseCode.ResponseCode.SubFunctionNotSupported),
            ]:
                response = uds.request_raw(raw)
                assert response is not None
                assert response.code == code
            assert uds.request_raw(b"\x3e\x80") is None
