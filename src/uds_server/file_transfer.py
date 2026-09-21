"""Virtual file definitions for UDS RequestFileTransfer (SID ``0x38``)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntFlag
from typing import Callable

from .access import AccessRule

Condition = Callable[[], bool]


class FileAccess(IntFlag):
    """Allowed operations for a configured virtual file."""

    READ = 1
    WRITE = 2
    READ_WRITE = READ | WRITE


@dataclass(frozen=True, slots=True)
class FileDefinition:
    """A virtual file exposed through RequestFileTransfer.

    Set ``data`` to ``None`` to reserve a path that can be created with
    AddFile.  The server never accesses the host filesystem.
    """

    path: str
    data: bytes | None = b""
    access: FileAccess = FileAccess.READ_WRITE
    access_rule: AccessRule = field(default_factory=AccessRule)
    condition: Condition | None = None

    def __post_init__(self) -> None:
        if not self.path or not self.path.isascii():
            raise ValueError("Virtual file paths must be non-empty ASCII strings")
        if self.data is not None and not isinstance(self.data, bytes):
            raise TypeError("Virtual file data must be bytes or None")


class VirtualFile:
    """Mutable in-memory file backing a file-transfer definition."""

    def __init__(self, definition: FileDefinition) -> None:
        self.definition = definition
        self.data = definition.data

    @property
    def path(self) -> str:
        return self.definition.path

    @property
    def exists(self) -> bool:
        return self.data is not None

    def read(self, offset: int, length: int) -> bytes:
        if not self.definition.access & FileAccess.READ or self.data is None:
            raise PermissionError("Virtual file is not readable")
        return self.data[offset : offset + length]

    def begin_write(self, size: int) -> None:
        if not self.definition.access & FileAccess.WRITE:
            raise PermissionError("Virtual file is not writable")
        self.data = bytes(size)

    def write(self, offset: int, value: bytes) -> None:
        if not self.definition.access & FileAccess.WRITE or self.data is None:
            raise PermissionError("Virtual file is not writable")
        if offset + len(value) > len(self.data):
            raise ValueError("Virtual file write exceeds its requested size")
        self.data = self.data[:offset] + value + self.data[offset + len(value) :]

    def delete(self) -> None:
        if not self.definition.access & FileAccess.WRITE:
            raise PermissionError("Virtual file is not writable")
        self.data = None
