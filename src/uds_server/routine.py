"""Routine definitions for UDS RoutineControl (SID ``0x31``)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .access import AccessRule

RoutineCallback = Callable[[bytes], bytes]
Condition = Callable[[], bool]


@dataclass(frozen=True, slots=True)
class RoutineDefinition:
    """Configuration for one two-byte UDS routine identifier.

    Each callback receives the request's optional routine-control option record
    and returns the optional routine-status record for the positive response.
    Leave a callback unset to declare its corresponding subfunction unsupported.
    """

    identifier: int
    start_callback: RoutineCallback | None = None
    stop_callback: RoutineCallback | None = None
    results_callback: RoutineCallback | None = None
    access_rule: AccessRule = field(default_factory=AccessRule)
    condition: Condition | None = None

    def __post_init__(self) -> None:
        """Validate the routine identifier's wire representation."""
        if not 0 <= self.identifier <= 0xFFFF:
            raise ValueError("Routine identifier must be between 0x0000 and 0xFFFF")


class Routine:
    """A configured routine with handlers for its control subfunctions."""

    def __init__(self, definition: RoutineDefinition) -> None:
        self.definition = definition

    @property
    def identifier(self) -> int:
        """The two-byte UDS routine identifier."""
        return self.definition.identifier

    def callback_for(self, subfunction: int) -> RoutineCallback | None:
        """Return the callback for a RoutineControl subfunction."""
        return {
            0x01: self.definition.start_callback,
            0x02: self.definition.stop_callback,
            0x03: self.definition.results_callback,
        }.get(subfunction)
