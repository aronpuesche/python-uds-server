"""Diagnostic trouble code definitions for UDS diagnostic services."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping

from .access import AccessRule


@dataclass(frozen=True, slots=True)
class DtcSnapshot:
    """One DTC snapshot record, represented by its DIDs and their values."""

    record_number: int
    dids: Mapping[int, bytes]

    def __post_init__(self) -> None:
        if not 1 <= self.record_number <= 0xFF:
            raise ValueError("Snapshot record number must be between 1 and 0xFF")
        if not self.dids:
            raise ValueError("A snapshot record must contain at least one DID")
        for identifier, value in self.dids.items():
            if not 0 <= identifier <= 0xFFFF:
                raise ValueError("Snapshot DID must be between 0x0000 and 0xFFFF")
            if not isinstance(value, bytes):
                raise TypeError("Snapshot DID values must be bytes")


@dataclass(frozen=True, slots=True)
class DtcDefinition:
    """Configuration for one three-byte diagnostic trouble code."""

    identifier: int
    status: int = 0
    snapshots: tuple[DtcSnapshot, ...] = ()
    extended_data: Mapping[int, bytes] = field(default_factory=dict)
    severity: int = 0
    functional_unit: int = 0
    fault_detection_counter: int = 0
    permanent: bool = False
    access_rule: AccessRule = field(default_factory=AccessRule)
    condition: Callable[[], bool] | None = None

    def __post_init__(self) -> None:
        if not 0 <= self.identifier <= 0xFFFFFF:
            raise ValueError("DTC identifier must be between 0x000000 and 0xFFFFFF")
        if not 0 <= self.status <= 0xFF:
            raise ValueError("DTC status must fit in one byte")
        numbers = [snapshot.record_number for snapshot in self.snapshots]
        if len(numbers) != len(set(numbers)):
            raise ValueError("DTC snapshot record numbers must be unique")
        if not 0 <= self.severity <= 0xE0 or self.severity & 0x1F:
            raise ValueError("DTC severity must use the upper three bits")
        if not 0 <= self.functional_unit <= 0xFF:
            raise ValueError("DTC functional unit must fit in one byte")
        if not 0 <= self.fault_detection_counter <= 0xFF:
            raise ValueError("DTC fault detection counter must fit in one byte")
        for record_number, value in self.extended_data.items():
            if not 1 <= record_number <= 0xFF:
                raise ValueError(
                    "Extended-data record number must be between 1 and 0xFF"
                )
            if not isinstance(value, bytes):
                raise TypeError("Extended-data values must be bytes")


class DiagnosticTroubleCode:
    """Mutable runtime status for a configured DTC."""

    def __init__(self, definition: DtcDefinition) -> None:
        self.definition = definition
        self.status = definition.status

    @property
    def identifier(self) -> int:
        return self.definition.identifier

    def clear(self) -> None:
        """Clear all status bits while retaining configured snapshot metadata."""
        self.status = 0
