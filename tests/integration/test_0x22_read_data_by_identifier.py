"""Integration tests for ReadDataByIdentifier."""

import pytest
from udsoncan import ResponseCode
from udsoncan.exceptions import NegativeResponseException

from .conftest import BytesCodec
from uds_server import AccessRule, DidAccess, DidDefinition, UdsServer

pytestmark = pytest.mark.integration


class TestReadDataByIdentifier:
    def test_client_reads_multiple_dids(self, uds_client) -> None:
        server = UdsServer(dids=[DidDefinition(0x1234, 1), DidDefinition(0x5678, 2)])
        server.set_did_value(0x1234, b"A")
        server.set_did_value(0x5678, b"BC")
        with uds_client(server, {0x1234: BytesCodec(1), 0x5678: BytesCodec(2)}) as uds:
            response = uds.client.read_data_by_identifier([0x1234, 0x5678])
            assert response.service_data.values == {0x1234: b"A", 0x5678: b"BC"}

    def test_client_reports_semantic_negative_responses(self, uds_client) -> None:
        server = UdsServer(
            dids=[
                DidDefinition(0x1111, 1, access=DidAccess.WRITE),
                DidDefinition(0x2222, 1, condition=lambda: False),
                DidDefinition(
                    0x4444,
                    1,
                    read_callback=lambda: (_ for _ in ()).throw(RuntimeError()),
                ),
                DidDefinition(
                    0x3333,
                    1,
                    access_rule=AccessRule(allowed_security_levels=frozenset({1})),
                ),
            ]
        )
        codecs = {
            identifier: BytesCodec(1)
            for identifier in (0x0001, 0x1111, 0x2222, 0x3333, 0x4444)
        }
        with uds_client(server, codecs) as uds:
            for identifier, code in [
                (0x0001, ResponseCode.ResponseCode.RequestOutOfRange),
                (0x1111, ResponseCode.ResponseCode.RequestOutOfRange),
                (0x2222, ResponseCode.ResponseCode.ConditionsNotCorrect),
                (0x3333, ResponseCode.ResponseCode.SecurityAccessDenied),
                (0x4444, ResponseCode.ResponseCode.GeneralReject),
            ]:
                with pytest.raises(NegativeResponseException) as error:
                    uds.client.read_data_by_identifier(identifier)
                assert error.value.response.code == code

            for raw, code in [
                (
                    b"\x22",
                    ResponseCode.ResponseCode.IncorrectMessageLengthOrInvalidFormat,
                ),
            ]:
                response = uds.request_raw(raw)
                assert response is not None
                assert response.code == code
