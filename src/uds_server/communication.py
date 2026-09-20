"""Definitions for UDS CommunicationControl (SID ``0x28``)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .access import AccessRule

CommunicationCallback = Callable[[int, int, int | None], None]
Condition = Callable[[], bool]


@dataclass(frozen=True, slots=True)
class CommunicationControlDefinition:
    """Configuration for one supported CommunicationControl control type."""

    control_type: int
    callback: CommunicationCallback | None = None
    access_rule: AccessRule = field(default_factory=AccessRule)
    condition: Condition | None = None

    def __post_init__(self) -> None:
        if not 0 <= self.control_type <= 0x7F:
            raise ValueError("Communication control type must be between 0x00 and 0x7F")
