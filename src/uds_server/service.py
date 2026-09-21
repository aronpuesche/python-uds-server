"""Configuration for service availability."""

from dataclasses import dataclass, field

from .access import AccessRule


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    sid: int
    enabled: bool = True
    access: AccessRule = field(default_factory=AccessRule)

    def __post_init__(self) -> None:
        if not 0 <= self.sid <= 0xFF:
            raise ValueError("SID must be between 0x00 and 0xFF")
