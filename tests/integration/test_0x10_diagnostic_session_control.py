"""Integration tests for DiagnosticSessionControl."""

from time import sleep

import pytest
from udsoncan import ResponseCode
from udsoncan.exceptions import NegativeResponseException

from .conftest import BytesCodec
from uds_server import (
    AccessRule,
    DiagnosticSession,
    DidDefinition,
    SecurityLevel,
    ServiceConfig,
    UdsServer,
)

pytestmark = pytest.mark.integration


class TestDiagnosticSessionControl:
    def test_client_changes_session_and_receives_server_timings(
        self, uds_client
    ) -> None:
        server = UdsServer(
            sessions=[DiagnosticSession(1), DiagnosticSession(3, 100, 5000)]
        )
        with uds_client(server) as uds:
            response = uds.client.change_session(3)
            assert response.original_payload == b"\x50\x03\x00\x64\x01\xf4"

    def test_s3_timeout_and_negative_responses(self, uds_client) -> None:
        server = UdsServer(
            sessions=[
                DiagnosticSession(1),
                DiagnosticSession(3, s3_server_timeout_ms=20),
            ],
            dids=[
                DidDefinition(0x1234, 1, access_rule=AccessRule(frozenset({3}))),
                DidDefinition(
                    0x5678,
                    1,
                    access_rule=AccessRule(allowed_security_levels=frozenset({1})),
                ),
            ],
            security_levels=[
                SecurityLevel(1, lambda: b"\xaa", lambda _seed, _key: True)
            ],
            services=[ServiceConfig(0x3E, enabled=False)],
        )
        with uds_client(server, {0x1234: BytesCodec(1), 0x5678: BytesCodec(1)}) as uds:
            uds.client.change_session(3)
            uds.client.request_seed(1)
            uds.client.send_key(2, b"\x00")
            assert uds.client.read_data_by_identifier(0x5678).service_data.values == {
                0x5678: b"\x00"
            }
            sleep(0.03)
            for raw, code in [
                (
                    b"\x22\x12\x34",
                    ResponseCode.ResponseCode.ServiceNotSupportedInActiveSession,
                ),
                (
                    b"\x10",
                    ResponseCode.ResponseCode.IncorrectMessageLengthOrInvalidFormat,
                ),
            ]:
                response = uds.request_raw(raw)
                assert response is not None
                assert response.code == code
            with pytest.raises(NegativeResponseException) as error:
                uds.client.read_data_by_identifier(0x5678)
            assert (
                error.value.response.code
                == ResponseCode.ResponseCode.SecurityAccessDenied
            )
            with pytest.raises(NegativeResponseException) as error:
                uds.client.change_session(0x7F)
            assert (
                error.value.response.code
                == ResponseCode.ResponseCode.SubFunctionNotSupported
            )
            with pytest.raises(NegativeResponseException) as error:
                uds.client.tester_present()
            assert (
                error.value.response.code
                == ResponseCode.ResponseCode.ServiceNotSupported
            )
            assert uds.request_raw(b"\x10\x83") is None
