"""Unit tests for SID 0x27, SecurityAccess."""

import pytest

from uds_server import SecurityLevel, UdsServer

pytestmark = pytest.mark.unit


def test_security_access_unlocks_a_configured_level() -> None:
    server = UdsServer(
        security_levels=[
            SecurityLevel(
                1,
                seed_callback=lambda: b"\x12\x34",
                key_validator=lambda seed, key: key == seed[::-1],
            )
        ]
    )

    assert server.handle_request(b"\x27\x01") == b"\x67\x01\x12\x34"
    assert server.handle_request(b"\x27\x02\x34\x12") == b"\x67\x02"
    assert server.is_security_level_unlocked(1)


def test_security_access_rejects_an_invalid_key() -> None:
    server = UdsServer(
        security_levels=[SecurityLevel(1, lambda: b"\xaa", lambda seed, key: False)]
    )

    server.handle_request(b"\x27\x01")
    assert server.handle_request(b"\x27\x02\x00") == b"\x7f\x27\x35"


def test_security_access_can_derive_a_key_with_level_specific_parameters() -> None:
    server = UdsServer(
        security_levels=[
            SecurityLevel(
                level=3,
                seed_callback=lambda: b"\x12\x34",
                key_algorithm=lambda level, seed, params: bytes(
                    value ^ params["mask"] for value in seed
                ),
                algorithm_params={"mask": 0xFF},
            )
        ]
    )

    assert server.handle_request(b"\x27\x03") == b"\x67\x03\x12\x34"
    assert server.handle_request(b"\x27\x04\xed\xcb") == b"\x67\x04"


def test_security_access_locks_after_configured_attempts() -> None:
    server = UdsServer(
        security_levels=[
            SecurityLevel(
                1,
                lambda: b"\xaa",
                lambda seed, key: False,
                max_attempts=2,
                delay_seconds=1.0,
            )
        ]
    )

    server.handle_request(b"\x27\x01")
    assert server.handle_request(b"\x27\x02\x00") == b"\x7f\x27\x35"
    assert server.handle_request(b"\x27\x02\x00") == b"\x7f\x27\x36"
    assert server.handle_request(b"\x27\x01") == b"\x7f\x27\x37"
