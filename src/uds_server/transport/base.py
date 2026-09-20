"""Protocol definitions for UDS transport adapters."""

from __future__ import annotations

from typing import Protocol


class Transport(Protocol):
    """The minimal lifecycle interface required by :class:`UdsServer`."""

    def open(self) -> None:
        """Start accepting diagnostic traffic."""

    def close(self) -> None:
        """Stop accepting diagnostic traffic and release resources."""
