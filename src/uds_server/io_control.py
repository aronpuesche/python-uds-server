"""Definitions for UDS InputOutputControlByIdentifier (SID ``0x2F``)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .access import AccessRule

ControlCallback = Callable[[int, bytes, bytes], bytes]
Condition = Callable[[], bool]


@dataclass(frozen=True, slots=True)
class IoControlDefinition:
    """Configuration for one controllable input/output DID.

    ``mask_length`` is either zero (no mask record) or equal to ``length``.
    In the latter case ShortTermAdjustment applies the mask bitwise to the
    retained control value.
    """

    identifier: int
    length: int
    default_value: bytes | None = None
    mask_length: int = 0
    callback: ControlCallback | None = None
    access_rule: AccessRule = field(default_factory=AccessRule)
    condition: Condition | None = None

    def __post_init__(self) -> None:
        if not 0 <= self.identifier <= 0xFFFF:
            raise ValueError("I/O control DID must be between 0x0000 and 0xFFFF")
        if self.length < 1:
            raise ValueError("I/O control length must be at least one byte")
        if self.mask_length not in (0, self.length):
            raise ValueError("mask_length must be zero or match the I/O control length")
        if self.default_value is not None and len(self.default_value) != self.length:
            raise ValueError("I/O control default_value must match length")


class IoControl:
    """Runtime state for a controllable I/O DID."""

    def __init__(self, definition: IoControlDefinition) -> None:
        self.definition = definition
        self._default_value = definition.default_value or bytes(definition.length)
        self.value = self._default_value
        self.is_controlled = False

    @property
    def identifier(self) -> int:
        return self.definition.identifier

    def apply(self, control_parameter: int, value: bytes, mask: bytes) -> bytes:
        if control_parameter == 0x00:
            self.is_controlled = False
        elif control_parameter == 0x01:
            self.value = self._default_value
            self.is_controlled = True
        elif control_parameter == 0x02:
            self.is_controlled = True
        elif control_parameter == 0x03:
            if mask:
                self.value = bytes(
                    (current & ~selected) | (requested & selected)
                    for current, requested, selected in zip(self.value, value, mask)
                )
            else:
                self.value = value
            self.is_controlled = True
        callback = self.definition.callback
        if callback is None:
            return b""
        response = callback(control_parameter, self.value, mask)
        if not isinstance(response, bytes):
            raise TypeError("I/O control callbacks must return bytes")
        return response
