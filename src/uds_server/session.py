"""Diagnostic-session configuration."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DiagnosticSession:
    """A session accepted by DiagnosticSessionControl (SID ``0x10``)."""

    identifier: int
    p2_server_max_ms: int = 50
    p2_star_server_max_ms: int = 5000
    s3_server_timeout_ms: int = 5000

    def __post_init__(self) -> None:
        if not 1 <= self.identifier <= 0x7F:
            raise ValueError("Session identifier must be between 1 and 0x7F")
        if not 0 <= self.p2_server_max_ms <= 0xFFFF:
            raise ValueError("P2 server maximum must fit in two bytes")
        if not 0 <= self.p2_star_server_max_ms <= 0xFFFF * 10:
            raise ValueError("P2* server maximum must fit in two bytes of 10 ms units")
        if self.s3_server_timeout_ms < 0:
            raise ValueError("S3 server timeout must not be negative")
