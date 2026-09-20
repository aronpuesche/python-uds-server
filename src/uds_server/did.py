"""Data identifier definitions and storage for UDS services."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntFlag
from typing import Callable

from .access import AccessRule

ReadCallback = Callable[[], bytes]
WriteCallback = Callable[[bytes], None]
Condition = Callable[[], bool]


class DidAccess(IntFlag):
    """Allowed UDS operations for a data identifier."""

    READ = 1
    WRITE = 2
    READ_WRITE = READ | WRITE


@dataclass(frozen=True, slots=True)
class DidDefinition:
    """Configuration for one UDS data identifier (DID)."""

    identifier: int
    length: int
    access: DidAccess = DidAccess.READ_WRITE
    read_callback: ReadCallback | None = None
    write_callback: WriteCallback | None = None
    access_rule: AccessRule = field(default_factory=AccessRule)
    condition: Condition | None = None

    def __post_init__(self) -> None:
        """Validate fields which make a DID unambiguous on the wire."""
        if not 0 <= self.identifier <= 0xFFFF:
            raise ValueError("DID identifier must be between 0x0000 and 0xFFFF")
        if self.length < 1:
            raise ValueError("DID length must be at least one byte")


class DataIdentifier:
    """A configured DID with optional callbacks and default mutable storage."""

    def __init__(self, definition: DidDefinition) -> None:
        self.definition = definition
        self._value = bytearray(definition.length)

    @property
    def identifier(self) -> int:
        """The two-byte UDS data identifier."""
        return self.definition.identifier

    @property
    def length(self) -> int:
        """The fixed number of bytes in this DID's data record."""
        return self.definition.length

    @property
    def access(self) -> DidAccess:
        """The permitted UDS operations for this DID."""
        return self.definition.access

    @property
    def value(self) -> bytes:
        """Read the current value through the callback or default storage."""
        return self.read()

    @value.setter
    def value(self, value: bytes) -> None:
        self.write(value)

    def read(self) -> bytes:
        """Return this DID's fixed-length data record."""
        if not self.access & DidAccess.READ:
            raise PermissionError(f"DID 0x{self.identifier:04X} is not readable")

        callback = self.definition.read_callback
        value = callback() if callback is not None else bytes(self._value)
        self._validate_value(value)
        return value

    def write(self, value: bytes) -> None:
        """Update this DID through the callback or default storage."""
        if not self.access & DidAccess.WRITE:
            raise PermissionError(f"DID 0x{self.identifier:04X} is not writable")

        self._validate_value(value)
        callback = self.definition.write_callback
        if callback is not None:
            callback(value)
        else:
            self._value[:] = value

    def _validate_value(self, value: bytes) -> None:
        if not isinstance(value, bytes):
            raise TypeError("DID values must be bytes")
        if len(value) != self.length:
            raise ValueError(
                f"DID 0x{self.identifier:04X} requires {self.length} bytes, "
                f"got {len(value)}"
            )
