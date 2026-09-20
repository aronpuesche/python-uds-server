"""Integration tests for RoutineControl."""

import pytest
from udsoncan import ResponseCode
from udsoncan.exceptions import NegativeResponseException

from uds_server import ProgrammingFailure, RoutineDefinition, UdsServer

pytestmark = pytest.mark.integration


class TestRoutineControl:
    def test_client_starts_stops_and_reads_results(self, uds_client) -> None:
        server = UdsServer(
            routines=[
                RoutineDefinition(
                    0x0203,
                    lambda option: b"start" + option,
                    lambda _: b"stop",
                    lambda _: b"result",
                )
            ]
        )
        with uds_client(server) as uds:
            assert (
                uds.client.start_routine(0x0203, b"\xaa").original_payload
                == b"\x71\x01\x02\x03start\xaa"
            )
            assert (
                uds.client.stop_routine(0x0203).original_payload
                == b"\x71\x02\x02\x03stop"
            )
            assert (
                uds.client.get_routine_result(0x0203).original_payload
                == b"\x71\x03\x02\x03result"
            )

    def test_client_reports_semantic_negative_responses(self, uds_client) -> None:
        server = UdsServer(
            routines=[
                RoutineDefinition(0x0203, start_callback=lambda _: b""),
                RoutineDefinition(
                    0x0204, start_callback=lambda _: b"", condition=lambda: False
                ),
                RoutineDefinition(
                    0x0205,
                    start_callback=lambda _: (_ for _ in ()).throw(
                        ProgrammingFailure()
                    ),
                ),
                RoutineDefinition(
                    0x0206,
                    start_callback=lambda _: (_ for _ in ()).throw(RuntimeError()),
                ),
            ]
        )
        with uds_client(server) as uds:
            for routine_id, code in [
                (0x0001, ResponseCode.ResponseCode.RequestOutOfRange),
                (0x0204, ResponseCode.ResponseCode.ConditionsNotCorrect),
                (0x0205, ResponseCode.ResponseCode.GeneralProgrammingFailure),
                (0x0206, ResponseCode.ResponseCode.GeneralReject),
            ]:
                with pytest.raises(NegativeResponseException) as error:
                    uds.client.start_routine(routine_id)
                assert error.value.response.code == code

            for raw, code in [
                (
                    b"\x31",
                    ResponseCode.ResponseCode.IncorrectMessageLengthOrInvalidFormat,
                ),
                (
                    b"\x31\x04\x02\x03",
                    ResponseCode.ResponseCode.SubFunctionNotSupported,
                ),
            ]:
                response = uds.request_raw(raw)
                assert response is not None
                assert response.code == code
            assert uds.request_raw(b"\x31\x81\x02\x03") is None
