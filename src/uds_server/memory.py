"""Memory-region definitions used by UDS memory and transfer services."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntFlag
from typing import Callable

from .access import AccessRule

ReadCallback = Callable[[int, int], bytes]
WriteCallback = Callable[[int, bytes], None]
Condition = Callable[[], bool]


class MemoryAccess(IntFlag):
    """Allowed operations for a configured memory region."""

    READ = 1
    WRITE = 2
    READ_WRITE = READ | WRITE


@dataclass(frozen=True, slots=True)
class MemoryRegionDefinition:
    """Configuration for a contiguous, byte-addressable ECU memory region.

    Callback addresses are absolute addresses, matching the UDS request.  Without
    callbacks, the region provides mutable in-memory storage, which is convenient
    for diagnostic-client tests.
    """

    start_address: int
    length: int
    access: MemoryAccess = MemoryAccess.READ_WRITE
    read_callback: ReadCallback | None = None
    write_callback: WriteCallback | None = None
    access_rule: AccessRule = field(default_factory=AccessRule)
    condition: Condition | None = None

    def __post_init__(self) -> None:
        if self.start_address < 0:
            raise ValueError("Memory start address must not be negative")
        if self.length < 1:
            raise ValueError("Memory region length must be at least one byte")


class MemoryRegion:
    """Runtime memory region with optional callbacks and default storage."""

    def __init__(self, definition: MemoryRegionDefinition) -> None:
        self.definition = definition
        self._value = bytearray(definition.length)

    @property
    def start_address(self) -> int:
        return self.definition.start_address

    @property
    def length(self) -> int:
        return self.definition.length

    def contains(self, address: int, length: int) -> bool:
        return (
            length >= 0
            and self.start_address <= address
            and (address + length <= self.start_address + self.length)
        )

    def read(self, address: int, length: int) -> bytes:
        if not self.definition.access & MemoryAccess.READ:
            raise PermissionError("Memory region is not readable")
        if not self.contains(address, length):
            raise KeyError("Requested memory range is not configured")
        callback = self.definition.read_callback
        value = (
            callback(address, length)
            if callback is not None
            else bytes(
                self._value[
                    address - self.start_address : address - self.start_address + length
                ]
            )
        )
        if not isinstance(value, bytes) or len(value) != length:
            raise ValueError("Memory read callback returned an invalid value")
        return value

    def write(self, address: int, value: bytes) -> None:
        if not self.definition.access & MemoryAccess.WRITE:
            raise PermissionError("Memory region is not writable")
        if not isinstance(value, bytes) or not self.contains(address, len(value)):
            raise KeyError("Requested memory range is not configured")
        callback = self.definition.write_callback
        if callback is not None:
            callback(address, value)
        else:
            offset = address - self.start_address
            self._value[offset : offset + len(value)] = value
