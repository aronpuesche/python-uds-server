"""Protocol definitions for UDS transport adapters."""

from __future__ import annotations

from typing import Protocol


class Transport(Protocol):
    """A transport capable of exchanging complete UDS payloads."""

    def open(self) -> None:
        """Start accepting diagnostic traffic."""

    def close(self) -> None:
        """Stop accepting diagnostic traffic and release resources."""

    def receive(self, timeout: float | None = None) -> bytes | None:
        """Receive a complete request payload, if one is available."""

    def send(self, payload: bytes) -> None:
        """Send a complete response payload."""
