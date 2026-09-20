"""ISO-TP transport adapter backed by the can-isotp package."""

from __future__ import annotations

from typing import Any


class IsoTpTransport:
    """Adapt an ``isotp.TransportLayer`` to the server transport protocol."""

    def __init__(self, layer: Any) -> None:
        """Create an adapter around a configured can-isotp transport layer."""
        self._layer = layer

    def open(self) -> None:
        """Start the ISO-TP layer's background processing."""
        self._layer.start()

    def close(self) -> None:
        """Stop the ISO-TP layer's background processing."""
        self._layer.stop()

    def receive(self, timeout: float | None = None) -> bytes | None:
        """Return a complete received ISO-TP payload."""
        return self._layer.recv(block=True, timeout=timeout)

    def send(self, payload: bytes) -> None:
        """Send one complete UDS response through ISO-TP."""
        self._layer.send(payload)
