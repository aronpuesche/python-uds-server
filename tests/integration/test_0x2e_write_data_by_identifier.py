"""Integration tests for WriteDataByIdentifier."""

import pytest
from udsoncan import ResponseCode
from udsoncan.exceptions import NegativeResponseException

from .conftest import BytesCodec
from uds_server import (
    AccessRule,
    DidAccess,
    DidDefinition,
    ProgrammingFailure,
    SecurityLevel,
    UdsServer,
)

pytestmark = pytest.mark.integration


class TestWriteDataByIdentifier:
    def test_client_writes_multiple_dids_sequentially(self, uds_client) -> None:
        server = UdsServer(
            dids=[
                DidDefinition(0x1234, 1),
                DidDefinition(0x5678, 2),
                DidDefinition(
                    0x7777,
                    1,
                    access_rule=AccessRule(allowed_security_levels=frozenset({1})),
                ),
            ],
            security_levels=[
                SecurityLevel(1, lambda: b"\xaa", lambda _seed, _key: True)
            ],
        )
        codecs = {0x1234: BytesCodec(1), 0x5678: BytesCodec(2), 0x7777: BytesCodec(1)}
        with uds_client(server, codecs) as uds:
            uds.client.write_data_by_identifier(0x1234, b"A")
            uds.client.write_data_by_identifier(0x5678, b"BC")
            assert uds.client.read_data_by_identifier(
                [0x1234, 0x5678]
            ).service_data.values == {0x1234: b"A", 0x5678: b"BC"}
            uds.client.request_seed(1)
            uds.client.send_key(2, b"\x00")
            uds.client.write_data_by_identifier(0x7777, b"S")
            assert uds.client.read_data_by_identifier(0x7777).service_data.values == {
                0x7777: b"S"
            }

    def test_client_reports_semantic_negative_responses(self, uds_client) -> None:
        server = UdsServer(
            dids=[
                DidDefinition(0x1111, 1, access=DidAccess.READ),
                DidDefinition(
                    0x6666,
                    1,
                    write_callback=lambda _: (_ for _ in ()).throw(
                        ProgrammingFailure()
                    ),
                ),
                DidDefinition(
                    0x7777,
                    1,
                    access_rule=AccessRule(allowed_security_levels=frozenset({1})),
                ),
            ],
            security_levels=[
                SecurityLevel(1, lambda: b"\xaa", lambda _seed, _key: True)
            ],
        )
        codecs = {
            identifier: BytesCodec(1) for identifier in (0x0001, 0x1111, 0x6666, 0x7777)
        }
        with uds_client(server, codecs) as uds:
            for identifier, code in [
                (0x0001, ResponseCode.ResponseCode.RequestOutOfRange),
                (0x1111, ResponseCode.ResponseCode.RequestOutOfRange),
                (0x6666, ResponseCode.ResponseCode.GeneralProgrammingFailure),
                (0x7777, ResponseCode.ResponseCode.SecurityAccessDenied),
            ]:
                with pytest.raises(NegativeResponseException) as error:
                    uds.client.write_data_by_identifier(identifier, b"A")
                assert error.value.response.code == code

            for raw, code in [
                (
                    b"\x2e",
                    ResponseCode.ResponseCode.IncorrectMessageLengthOrInvalidFormat,
                ),
            ]:
                response = uds.request_raw(raw)
                assert response is not None
                assert response.code == code
