"""Core lifecycle for a configurable UDS test server."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .transport import Transport


class UdsServer:
    """A UDS server whose services and transport can be configured later.

    Concrete UDS services and transport backends are deliberately not supplied
    by this initial release. The class provides a stable public entry point and
    lifecycle that later implementations can extend.
    """

    def __init__(self, transport: Transport | None = None) -> None:
        """Create a server with an optional transport adapter."""
        self._transport = transport
        self._is_running = False

    @property
    def is_running(self) -> bool:
        """Whether the server lifecycle has been started."""
        return self._is_running

    def start(self) -> None:
        """Start the configured transport and mark the server as running."""
        if self._is_running:
            return

        if self._transport is not None:
            self._transport.open()
        self._is_running = True

    def stop(self) -> None:
        """Stop the configured transport and mark the server as stopped."""
        if not self._is_running:
            return

        if self._transport is not None:
            self._transport.close()
        self._is_running = False
