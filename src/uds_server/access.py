"""Reusable session and security access rules."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AccessRule:
    """Restrict an object to sessions and/or unlocked security levels."""

    allowed_sessions: frozenset[int] | None = None
    allowed_security_levels: frozenset[int] | None = None

    def __post_init__(self) -> None:
        for name, values in (
            ("allowed_sessions", self.allowed_sessions),
            ("allowed_security_levels", self.allowed_security_levels),
        ):
            if values is not None and not values:
                raise ValueError(f"{name} must not be empty")

    def denial_code(self, session: int, unlocked_levels: set[int]) -> int | None:
        if self.allowed_sessions is not None and session not in self.allowed_sessions:
            return 0x7F
        if self.allowed_security_levels is not None and not (
            self.allowed_security_levels & unlocked_levels
        ):
            return 0x33
        return None
