"""Unit tests for SID 0x3E, TesterPresent."""

import pytest

from uds_server import UdsServer

pytestmark = pytest.mark.unit


def test_tester_present_returns_a_positive_response() -> None:
    assert UdsServer().handle_request(b"\x3e\x00") == b"\x7e\x00"
