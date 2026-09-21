"""Smoke tests for the public package API."""

import pytest

from uds_server import UdsServer

pytestmark = pytest.mark.unit


def test_public_server_can_be_imported_and_started() -> None:
    """The documented import path exposes a usable server."""
    server = UdsServer()

    assert server.is_running is False

    server.start()
    assert server.is_running is True

    server.stop()
    assert server.is_running is False
