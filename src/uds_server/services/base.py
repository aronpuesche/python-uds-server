"""Protocol definitions for UDS services."""

from __future__ import annotations

from typing import Protocol


class UdsService(Protocol):
    """A service that handles one UDS request payload.

    Implementations will be registered with :class:`uds_server.UdsServer` in a
    future release.
    """

    def handle(self, request: bytes) -> bytes:
        """Return the UDS response payload for *request*."""
