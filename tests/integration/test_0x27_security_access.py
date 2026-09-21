"""Integration tests for SecurityAccess."""

import pytest
from udsoncan import ResponseCode
from udsoncan.exceptions import NegativeResponseException

from uds_server import SecurityLevel, UdsServer

pytestmark = pytest.mark.integration


class TestSecurityAccess:
    def test_client_requests_seed_and_sends_key(self, uds_client) -> None:
        server = UdsServer(
            security_levels=[
                SecurityLevel(1, lambda: b"\xaa", lambda seed, key: key == seed[::-1])
            ]
        )
        with uds_client(server) as uds:
            assert uds.client.request_seed(1).service_data.seed == b"\xaa"
            uds.client.send_key(2, b"\xaa")
            assert server.is_security_level_unlocked(1)

    def test_client_reports_semantic_negative_responses(self, uds_client) -> None:
        server = UdsServer(
            security_levels=[
                SecurityLevel(
                    1,
                    lambda: b"\xaa",
                    lambda _seed, _key: False,
                    max_attempts=2,
                    delay_seconds=1,
                )
            ]
        )
        with uds_client(server) as uds:
            with pytest.raises(NegativeResponseException) as error:
                uds.client.request_seed(5)
            assert (
                error.value.response.code
                == ResponseCode.ResponseCode.SubFunctionNotSupported
            )
            with pytest.raises(NegativeResponseException) as error:
                uds.client.send_key(2, b"\x00")
            assert (
                error.value.response.code
                == ResponseCode.ResponseCode.RequestSequenceError
            )
            assert uds.request_raw(b"\x27\x81") is None
            with pytest.raises(NegativeResponseException) as error:
                uds.client.send_key(2, b"\x00")
            assert error.value.response.code == ResponseCode.ResponseCode.InvalidKey
            with pytest.raises(NegativeResponseException) as error:
                uds.client.send_key(2, b"\x00")
            assert (
                error.value.response.code
                == ResponseCode.ResponseCode.ExceedNumberOfAttempts
            )
            with pytest.raises(NegativeResponseException) as error:
                uds.client.request_seed(1)
            assert (
                error.value.response.code
                == ResponseCode.ResponseCode.RequiredTimeDelayNotExpired
            )

            for raw, code in [
                (
                    b"\x27",
                    ResponseCode.ResponseCode.IncorrectMessageLengthOrInvalidFormat,
                ),
            ]:
                response = uds.request_raw(raw)
                assert response is not None
                assert response.code == code
