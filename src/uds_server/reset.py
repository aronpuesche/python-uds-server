"""Definitions for UDS ECUReset (SID ``0x11``)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .access import AccessRule

ResetCallback = Callable[[], None]
Condition = Callable[[], bool]


@dataclass(frozen=True, slots=True)
class EcuResetDefinition:
    """Configuration for one supported ECUReset type.

    The optional callback lets a test fixture simulate reset-specific hardware
    work.  The server always resets its diagnostic session, security and active
    transfer state after a successful reset request.
    """

    reset_type: int
    callback: ResetCallback | None = None
    access_rule: AccessRule = field(default_factory=AccessRule)
    condition: Condition | None = None
    power_down_time: int | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.reset_type <= 0x7F:
            raise ValueError("ECU reset type must be between 0x01 and 0x7F")
        if self.power_down_time is not None and not 0 <= self.power_down_time <= 0xFF:
            raise ValueError("Power-down time must fit in one byte")
        if self.reset_type != 0x04 and self.power_down_time is not None:
            raise ValueError("power_down_time is only valid for reset type 0x04")
