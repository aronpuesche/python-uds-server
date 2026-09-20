"""SecurityAccess configuration for pluggable seed/key algorithms."""

from dataclasses import dataclass
from typing import Callable

SeedCallback = Callable[[], bytes]
KeyValidator = Callable[[bytes, bytes], bool]
KeyAlgorithm = Callable[[int, bytes, object], bytes]


@dataclass(frozen=True, slots=True)
class SecurityLevel:
    """One odd SecurityAccess level and its application-defined key check."""

    level: int
    seed_callback: SeedCallback
    key_validator: KeyValidator | None = None
    key_algorithm: KeyAlgorithm | None = None
    algorithm_params: object = None
    max_attempts: int | None = None
    delay_seconds: float = 0.0

    def __post_init__(self) -> None:
        if not 1 <= self.level <= 0x7D or not self.level % 2:
            raise ValueError(
                "SecurityAccess request-seed level must be odd (1 to 0x7D)"
            )
        if (self.key_validator is None) == (self.key_algorithm is None):
            raise ValueError("Configure exactly one of key_validator or key_algorithm")
        if self.max_attempts is not None and self.max_attempts < 1:
            raise ValueError("max_attempts must be at least one")
