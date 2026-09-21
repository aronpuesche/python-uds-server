"""Core lifecycle for a configurable UDS test server."""

from __future__ import annotations

from collections.abc import Iterable
from threading import Event, Thread
from time import monotonic
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .transport import Transport

from .did import DataIdentifier, DidDefinition
from .communication import CommunicationControlDefinition
from .dtc import DiagnosticTroubleCode, DtcDefinition, DtcSnapshot
from .exceptions import ProgrammingFailure
from .file_transfer import FileAccess, FileDefinition, VirtualFile
from .memory import MemoryAccess, MemoryRegion, MemoryRegionDefinition
from .io_control import IoControl, IoControlDefinition
from .reset import EcuResetDefinition
from .routine import Routine, RoutineDefinition
from .security import SecurityLevel
from .service import ServiceConfig
from .session import DiagnosticSession


class UdsServer:
    """A UDS server whose services and transport can be configured later.

    The initial implementation supports ReadDataByIdentifier (SID ``0x22``).
    Other services can build on the DID registry and transport lifecycle.
    """

    def __init__(
        self,
        transport: Transport | None = None,
        dids: Iterable[DidDefinition] | None = None,
        files: Iterable[FileDefinition] | None = None,
        io_controls: Iterable[IoControlDefinition] | None = None,
        communication_controls: Iterable[CommunicationControlDefinition] | None = None,
        dtcs: Iterable[DtcDefinition] | None = None,
        sessions: Iterable[DiagnosticSession] | None = None,
        security_levels: Iterable[SecurityLevel] | None = None,
        routines: Iterable[RoutineDefinition] | None = None,
        memory_regions: Iterable[MemoryRegionDefinition] | None = None,
        resets: Iterable[EcuResetDefinition] | None = None,
        services: Iterable[ServiceConfig] | None = None,
        max_transfer_block_length: int = 0x100,
    ) -> None:
        """Create a server with an optional transport and DID definitions."""
        self._transport = transport
        self._is_running = False
        self._dids: dict[int, DataIdentifier] = {}
        self._files: dict[str, VirtualFile] = {}
        self._io_controls: dict[int, IoControl] = {}
        self._dtcs: dict[int, DiagnosticTroubleCode] = {}
        self._routines: dict[int, Routine] = {}
        self._memory_regions: list[MemoryRegion] = []
        if not 2 <= max_transfer_block_length <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("max_transfer_block_length must be at least 2")
        self._max_transfer_block_length = max_transfer_block_length
        self._transfer: dict[str, int | str] | None = None
        configured_resets = tuple(resets or ())
        self._resets = {
            definition.reset_type: definition for definition in configured_resets
        }
        if len(self._resets) != len(configured_resets):
            raise ValueError("ECU reset types must be unique")
        self._stop_event = Event()
        self._thread: Thread | None = None
        default_sessions = (
            DiagnosticSession(0x01),
            DiagnosticSession(0x02),
            DiagnosticSession(0x03),
        )
        configured_sessions = tuple(sessions or default_sessions)
        self._sessions = {
            session.identifier: session for session in configured_sessions
        }
        if 0x01 not in self._sessions:
            raise ValueError("A default diagnostic session (0x01) is required")
        self._current_session = self._sessions[0x01]
        self._session_last_activity = monotonic()
        self._security_levels = {level.level: level for level in security_levels or ()}
        self._pending_seeds: dict[int, bytes] = {}
        self._unlocked_security_levels: set[int] = set()
        self._security_attempts: dict[int, int] = {}
        self._security_locked_until: dict[int, float] = {}
        self._services = {config.sid: config for config in services or ()}
        configured_communications = tuple(communication_controls or ())
        self._communication_controls = {
            definition.control_type: definition
            for definition in configured_communications
        }
        if len(self._communication_controls) != len(configured_communications):
            raise ValueError("Communication control types must be unique")

        for definition in dids or ():
            self.register_did(definition)
        for definition in files or ():
            self.register_file(definition)
        for definition in io_controls or ():
            self.register_io_control(definition)
        for definition in dtcs or ():
            self.register_dtc(definition)
        for definition in routines or ():
            self.register_routine(definition)
        for definition in memory_regions or ():
            self.register_memory_region(definition)

    @property
    def is_running(self) -> bool:
        """Whether the server lifecycle has been started."""
        return self._is_running

    @property
    def current_session(self) -> int:
        """The active diagnostic session identifier."""
        self._expire_diagnostic_session()
        return self._current_session.identifier

    def is_security_level_unlocked(self, level: int) -> bool:
        """Whether an odd SecurityAccess level was unlocked in this session."""
        self._expire_diagnostic_session()
        return level in self._unlocked_security_levels

    def register_did(self, definition: DidDefinition) -> DataIdentifier:
        """Add a DID definition and return its mutable runtime object."""
        if definition.identifier in self._dids:
            raise ValueError(f"DID 0x{definition.identifier:04X} is already registered")

        did = DataIdentifier(definition)
        self._dids[did.identifier] = did
        return did

    def get_did(self, identifier: int) -> DataIdentifier:
        """Return the registered DID for *identifier*."""
        try:
            return self._dids[identifier]
        except KeyError as error:
            raise KeyError(f"DID 0x{identifier:04X} is not registered") from error

    def set_did_value(self, identifier: int, value: bytes) -> None:
        """Set the value of a writable DID."""
        self.get_did(identifier).write(value)

    def register_dtc(self, definition: DtcDefinition) -> DiagnosticTroubleCode:
        """Add a DTC definition and return its mutable runtime object."""
        if definition.identifier in self._dtcs:
            raise ValueError(f"DTC 0x{definition.identifier:06X} is already registered")
        dtc = DiagnosticTroubleCode(definition)
        self._dtcs[dtc.identifier] = dtc
        return dtc

    def get_dtc(self, identifier: int) -> DiagnosticTroubleCode:
        """Return a configured diagnostic trouble code."""
        try:
            return self._dtcs[identifier]
        except KeyError as error:
            raise KeyError(f"DTC 0x{identifier:06X} is not registered") from error

    def register_file(self, definition: FileDefinition) -> VirtualFile:
        """Add a virtual file available to RequestFileTransfer."""
        if definition.path in self._files:
            raise ValueError(f"Virtual file {definition.path!r} is already registered")
        file = VirtualFile(definition)
        self._files[file.path] = file
        return file

    def get_file(self, path: str) -> VirtualFile:
        """Return a configured virtual file by its ASCII path."""
        try:
            return self._files[path]
        except KeyError as error:
            raise KeyError(f"Virtual file {path!r} is not registered") from error

    def register_io_control(self, definition: IoControlDefinition) -> IoControl:
        """Add an I/O control DID and return its runtime state."""
        if definition.identifier in self._io_controls:
            raise ValueError(
                f"I/O control DID 0x{definition.identifier:04X} is already registered"
            )
        control = IoControl(definition)
        self._io_controls[control.identifier] = control
        return control

    def get_io_control(self, identifier: int) -> IoControl:
        """Return a configured I/O control DID."""
        try:
            return self._io_controls[identifier]
        except KeyError as error:
            raise KeyError(
                f"I/O control DID 0x{identifier:04X} is not registered"
            ) from error

    def register_routine(self, definition: RoutineDefinition) -> Routine:
        """Add a routine definition and return its runtime object."""
        if definition.identifier in self._routines:
            raise ValueError(
                f"Routine 0x{definition.identifier:04X} is already registered"
            )

        routine = Routine(definition)
        self._routines[routine.identifier] = routine
        return routine

    def register_memory_region(
        self, definition: MemoryRegionDefinition
    ) -> MemoryRegion:
        """Add a non-overlapping, byte-addressable memory region."""
        region = MemoryRegion(definition)
        if any(
            region.start_address < item.start_address + item.length
            and item.start_address < region.start_address + region.length
            for item in self._memory_regions
        ):
            raise ValueError("Memory regions must not overlap")
        self._memory_regions.append(region)
        return region

    def get_memory_region(self, address: int, length: int) -> MemoryRegion:
        """Return the one configured region containing the requested range."""
        for region in self._memory_regions:
            if region.contains(address, length):
                return region
        raise KeyError("Requested memory range is not configured")

    def get_routine(self, identifier: int) -> Routine:
        """Return the registered routine for *identifier*."""
        try:
            return self._routines[identifier]
        except KeyError as error:
            raise KeyError(f"Routine 0x{identifier:04X} is not registered") from error

    def start(self) -> None:
        """Start the configured transport and mark the server as running."""
        if self._is_running:
            return

        self._stop_event.clear()
        if self._transport is not None:
            self._transport.open()
            self._thread = Thread(target=self._serve, daemon=True)
            self._thread.start()
        self._is_running = True

    def stop(self) -> None:
        """Stop the configured transport and mark the server as stopped."""
        if not self._is_running:
            return

        self._stop_event.set()
        if self._transport is not None:
            self._transport.close()
        if self._thread is not None:
            self._thread.join(timeout=1)
            self._thread = None
        self._is_running = False

    def handle_request(self, request: bytes) -> bytes:
        """Handle a complete UDS request payload and return a response payload."""
        if not request:
            raise ValueError("UDS request payload must include a service identifier")

        request = bytes(request)
        self._expire_diagnostic_session()
        self._session_last_activity = monotonic()
        sid = request[0]
        config = self._services.get(sid)
        if config is not None:
            if not config.enabled:
                return self._negative_response(sid, 0x11)
            denial = config.access.denial_code(
                self.current_session, self._unlocked_security_levels
            )
            if denial is not None:
                return self._negative_response(sid, denial)
        if sid == 0x10:
            return self._diagnostic_session_control(request)
        if sid == 0x11:
            return self._ecu_reset(request)
        if sid == 0x14:
            return self._clear_diagnostic_information(request)
        if sid == 0x19:
            return self._read_dtc_information(request)
        if sid == 0x22:
            return self._read_data_by_identifier(request)
        if sid == 0x23:
            return self._read_memory_by_address(request)
        if sid == 0x27:
            return self._security_access(request)
        if sid == 0x28:
            return self._communication_control(request)
        if sid == 0x2E:
            return self._write_data_by_identifier(request)
        if sid == 0x2F:
            return self._input_output_control_by_identifier(request)
        if sid == 0x31:
            return self._routine_control(request)
        if sid == 0x34:
            return self._request_transfer(request, "download")
        if sid == 0x35:
            return self._request_transfer(request, "upload")
        if sid == 0x36:
            return self._transfer_data(request)
        if sid == 0x37:
            return self._request_transfer_exit(request)
        if sid == 0x38:
            return self._request_file_transfer(request)
        if sid == 0x3D:
            return self._write_memory_by_address(request)
        if sid == 0x3E:
            return self._tester_present(request)
        return self._negative_response(sid, 0x11)

    def _serve(self) -> None:
        """Receive ISO-TP payloads and reply until the server is stopped."""
        assert self._transport is not None
        while not self._stop_event.is_set():
            request = self._transport.receive(timeout=0.1)
            if request is not None:
                response = self.handle_request(request)
                if response:
                    self._transport.send(response)

    def _read_data_by_identifier(self, request: bytes) -> bytes:
        data = request[1:]
        if not data or len(data) % 2:
            return self._negative_response(0x22, 0x13)

        response = bytearray((0x62,))
        try:
            for index in range(0, len(data), 2):
                identifier = int.from_bytes(data[index : index + 2], "big")
                did = self.get_did(identifier)
                denial = did.definition.access_rule.denial_code(
                    self.current_session, self._unlocked_security_levels
                )
                if denial is not None:
                    return self._negative_response(0x22, denial)
                if (
                    did.definition.condition is not None
                    and not did.definition.condition()
                ):
                    return self._negative_response(0x22, 0x22)
                response.extend(data[index : index + 2])
                response.extend(did.read())
        except (KeyError, PermissionError):
            return self._negative_response(0x22, 0x31)
        except (TypeError, ValueError):
            return self._negative_response(0x22, 0x10)
        except Exception:
            return self._negative_response(0x22, 0x10)

        return bytes(response)

    def _write_data_by_identifier(self, request: bytes) -> bytes:
        data = request[1:]
        if len(data) < 3:
            return self._negative_response(0x2E, 0x13)
        identifier = int.from_bytes(data[:2], "big")
        try:
            did = self.get_did(identifier)
            denial = did.definition.access_rule.denial_code(
                self.current_session, self._unlocked_security_levels
            )
            if denial is not None:
                return self._negative_response(0x2E, denial)
            if did.definition.condition is not None and not did.definition.condition():
                return self._negative_response(0x2E, 0x22)
            did.write(data[2:])
        except (KeyError, PermissionError):
            return self._negative_response(0x2E, 0x31)
        except ValueError:
            return self._negative_response(0x2E, 0x13)
        except ProgrammingFailure:
            return self._negative_response(0x2E, 0x72)
        except Exception:
            return self._negative_response(0x2E, 0x10)
        return bytes((0x6E,)) + data[:2]

    def _communication_control(self, request: bytes) -> bytes:
        if len(request) < 3:
            return self._negative_response(0x28, 0x13)
        control_type = request[1] & 0x7F
        definition = self._communication_controls.get(control_type)
        if definition is None:
            return self._negative_response(0x28, 0x12)
        node_id: int | None = None
        if control_type in (0x04, 0x05):
            if len(request) != 5:
                return self._negative_response(0x28, 0x13)
            node_id = int.from_bytes(request[3:5], "big")
        elif len(request) != 3:
            return self._negative_response(0x28, 0x13)
        if not request[2] & 0x03:
            return self._negative_response(0x28, 0x31)
        denial = definition.access_rule.denial_code(
            self.current_session, self._unlocked_security_levels
        )
        if denial is not None:
            return self._negative_response(0x28, denial)
        try:
            if definition.condition is not None and not definition.condition():
                return self._negative_response(0x28, 0x22)
            if definition.callback is not None:
                definition.callback(control_type, request[2], node_id)
        except ProgrammingFailure:
            return self._negative_response(0x28, 0x72)
        except Exception:
            return self._negative_response(0x28, 0x10)
        return b"" if request[1] & 0x80 else bytes((0x68, control_type))

    def _input_output_control_by_identifier(self, request: bytes) -> bytes:
        if len(request) < 3:
            return self._negative_response(0x2F, 0x13)
        identifier = int.from_bytes(request[1:3], "big")
        try:
            control = self.get_io_control(identifier)
        except KeyError:
            return self._negative_response(0x2F, 0x31)
        definition = control.definition
        denial = definition.access_rule.denial_code(
            self.current_session, self._unlocked_security_levels
        )
        if denial is not None:
            return self._negative_response(0x2F, denial)
        try:
            if definition.condition is not None and not definition.condition():
                return self._negative_response(0x2F, 0x22)
        except Exception:
            return self._negative_response(0x2F, 0x10)
        if len(request) == 3:
            return bytes((0x6F,)) + request[1:3]
        control_parameter = request[3]
        if control_parameter not in (0x00, 0x01, 0x02, 0x03):
            return self._negative_response(0x2F, 0x12)
        option_record = request[4:]
        if control_parameter == 0x03:
            if len(option_record) == definition.length:
                value, mask = option_record, b""
            elif definition.mask_length and len(option_record) == (
                definition.length + definition.mask_length
            ):
                value = option_record[: definition.length]
                mask = option_record[definition.length :]
            else:
                return self._negative_response(0x2F, 0x13)
        elif option_record:
            return self._negative_response(0x2F, 0x13)
        else:
            value, mask = b"", b""
        try:
            status_record = control.apply(control_parameter, value, mask)
        except ProgrammingFailure:
            return self._negative_response(0x2F, 0x72)
        except Exception:
            return self._negative_response(0x2F, 0x10)
        return (
            bytes((0x6F,)) + request[1:3] + bytes((control_parameter,)) + status_record
        )

    def _parse_memory_location(
        self, request: bytes, offset: int
    ) -> tuple[int, int, bytes] | None:
        """Parse an ALFID and return address, size and its encoded fields."""
        if len(request) <= offset:
            return None
        alfid = request[offset]
        address_length, size_length = alfid & 0x0F, alfid >> 4
        if not address_length or not size_length:
            return None
        end = offset + 1 + address_length + size_length
        if len(request) < end:
            return None
        address_end = offset + 1 + address_length
        address = int.from_bytes(request[offset + 1 : address_end], "big")
        size = int.from_bytes(request[address_end:end], "big")
        if not size:
            return None
        return address, size, request[offset:end]

    def _memory_access_denial(
        self, sid: int, address: int, size: int
    ) -> tuple[MemoryRegion | None, bytes | None]:
        try:
            region = self.get_memory_region(address, size)
        except KeyError:
            return None, self._negative_response(sid, 0x31)
        denial = region.definition.access_rule.denial_code(
            self.current_session, self._unlocked_security_levels
        )
        if denial is not None:
            return None, self._negative_response(sid, denial)
        try:
            if (
                region.definition.condition is not None
                and not region.definition.condition()
            ):
                return None, self._negative_response(sid, 0x22)
        except Exception:
            return None, self._negative_response(sid, 0x10)
        return region, None

    def _read_memory_by_address(self, request: bytes) -> bytes:
        parsed = self._parse_memory_location(request, 1)
        if parsed is None or len(request) != 1 + len(parsed[2]):
            return self._negative_response(0x23, 0x13)
        address, size, _ = parsed
        region, error = self._memory_access_denial(0x23, address, size)
        if error is not None:
            return error
        assert region is not None
        try:
            return b"\x63" + region.read(address, size)
        except (KeyError, PermissionError):
            return self._negative_response(0x23, 0x31)
        except Exception:
            return self._negative_response(0x23, 0x10)

    def _write_memory_by_address(self, request: bytes) -> bytes:
        parsed = self._parse_memory_location(request, 1)
        if parsed is None:
            return self._negative_response(0x3D, 0x13)
        address, size, encoded = parsed
        value = request[1 + len(encoded) :]
        if len(value) != size:
            return self._negative_response(0x3D, 0x13)
        region, error = self._memory_access_denial(0x3D, address, size)
        if error is not None:
            return error
        assert region is not None
        try:
            region.write(address, value)
        except (KeyError, PermissionError):
            return self._negative_response(0x3D, 0x31)
        except ProgrammingFailure:
            return self._negative_response(0x3D, 0x72)
        except Exception:
            return self._negative_response(0x3D, 0x10)
        return b"\x7d" + encoded

    def _request_transfer(self, request: bytes, direction: str) -> bytes:
        sid = request[0]
        if len(request) < 4 or request[1] != 0:
            return self._negative_response(sid, 0x13)
        parsed = self._parse_memory_location(request, 2)
        if parsed is None or len(request) != 2 + len(parsed[2]):
            return self._negative_response(sid, 0x13)
        address, size, _ = parsed
        region, error = self._memory_access_denial(sid, address, size)
        if error is not None:
            return error
        assert region is not None
        required_access = (
            MemoryAccess.WRITE if direction == "download" else MemoryAccess.READ
        )
        if not region.definition.access & required_access:
            return self._negative_response(sid, 0x31)
        self._transfer = {
            "resource": "memory",
            "direction": direction,
            "address": address,
            "remaining": size,
            "sequence": 1,
        }
        length_bytes = max(1, (self._max_transfer_block_length.bit_length() + 7) // 8)
        return bytes(
            (sid + 0x40, length_bytes << 4)
        ) + self._max_transfer_block_length.to_bytes(length_bytes, "big")

    def _transfer_data(self, request: bytes) -> bytes:
        if self._transfer is None:
            return self._negative_response(0x36, 0x24)
        if len(request) < 2:
            return self._negative_response(0x36, 0x13)
        transfer = self._transfer
        sequence = request[1]
        if sequence != transfer["sequence"]:
            return self._negative_response(0x36, 0x73)
        remaining = transfer["remaining"]
        direction = transfer["direction"]
        address = transfer["address"]
        assert isinstance(direction, str)
        assert isinstance(address, int)
        assert isinstance(remaining, int)
        resource = transfer.get("resource", "memory")
        try:
            if resource == "memory":
                region = self.get_memory_region(address, remaining)
                read = region.read
                write = region.write
            elif resource == "file":
                path = transfer.get("path")
                assert isinstance(path, str)
                file = self.get_file(path)
                read = file.read
                write = file.write
            else:
                raise ValueError("Unknown transfer resource")
            if direction == "download":
                data = request[2:]
                if (
                    not data
                    or len(data) > remaining
                    or len(request) > self._max_transfer_block_length
                ):
                    return self._negative_response(0x36, 0x13)
                write(address, data)
                response = bytes((0x76, sequence))
                moved = len(data)
            else:
                if len(request) != 2:
                    return self._negative_response(0x36, 0x13)
                moved = min(remaining, self._max_transfer_block_length - 2)
                if not moved:
                    return self._negative_response(0x36, 0x13)
                response = bytes((0x76, sequence)) + read(address, moved)
            transfer["address"] += moved
            transfer["remaining"] -= moved
            transfer["sequence"] = (sequence + 1) & 0xFF
            return response
        except ProgrammingFailure:
            return self._negative_response(0x36, 0x72)
        except (KeyError, PermissionError):
            return self._negative_response(0x36, 0x31)
        except Exception:
            return self._negative_response(0x36, 0x10)

    def _file_access_denial(self, sid: int, file: VirtualFile) -> bytes | None:
        denial = file.definition.access_rule.denial_code(
            self.current_session, self._unlocked_security_levels
        )
        if denial is not None:
            return self._negative_response(sid, denial)
        try:
            if (
                file.definition.condition is not None
                and not file.definition.condition()
            ):
                return self._negative_response(sid, 0x22)
        except Exception:
            return self._negative_response(sid, 0x10)
        return None

    def _request_file_transfer(self, request: bytes) -> bytes:
        if len(request) < 4:
            return self._negative_response(0x38, 0x13)
        mode = request[1]
        path_length = int.from_bytes(request[2:4], "big")
        path_end = 4 + path_length
        if not path_length or len(request) < path_end:
            return self._negative_response(0x38, 0x13)
        try:
            path = request[4:path_end].decode("ascii")
            file = self.get_file(path)
        except (UnicodeDecodeError, KeyError):
            return self._negative_response(0x38, 0x31)
        denial = self._file_access_denial(0x38, file)
        if denial is not None:
            return denial
        data = request[path_end:]
        if mode in (0x01, 0x03):
            if len(data) < 2 or data[0] != 0:
                return self._negative_response(0x38, 0x13)
            width = data[1]
            if not width or len(data) != 2 + 2 * width:
                return self._negative_response(0x38, 0x13)
            size = int.from_bytes(data[2 : 2 + width], "big")
            compressed_size = int.from_bytes(data[2 + width :], "big")
            if not size or compressed_size != size:
                return self._negative_response(0x38, 0x31)
            if mode == 0x01 and file.exists:
                return self._negative_response(0x38, 0x31)
            if mode == 0x03 and not file.exists:
                return self._negative_response(0x38, 0x31)
            try:
                file.begin_write(size)
            except PermissionError:
                return self._negative_response(0x38, 0x31)
            direction = "download"
        elif mode == 0x04:
            if len(data) != 1 or data[0] != 0 or not file.exists:
                return self._negative_response(0x38, 0x31)
            if not file.definition.access & FileAccess.READ:
                return self._negative_response(0x38, 0x31)
            assert file.data is not None
            size = len(file.data)
            if not size:
                return self._negative_response(0x38, 0x31)
            direction = "upload"
        elif mode == 0x02:
            if data:
                return self._negative_response(0x38, 0x13)
            if not file.exists:
                return self._negative_response(0x38, 0x31)
            try:
                file.delete()
            except PermissionError:
                return self._negative_response(0x38, 0x31)
            return b"\x78\x02"
        else:
            return self._negative_response(0x38, 0x12)

        self._transfer = {
            "resource": "file",
            "path": path,
            "direction": direction,
            "address": 0,
            "remaining": size,
            "sequence": 1,
        }
        length_bytes = max(1, (self._max_transfer_block_length.bit_length() + 7) // 8)
        response = bytearray((0x78, mode, length_bytes))
        response.extend(self._max_transfer_block_length.to_bytes(length_bytes, "big"))
        response.append(0)
        if mode == 0x04:
            size_bytes = max(1, (size.bit_length() + 7) // 8)
            response.extend(size_bytes.to_bytes(2, "big"))
            response.extend(size.to_bytes(size_bytes, "big"))
            response.extend(size.to_bytes(size_bytes, "big"))
        return bytes(response)

    def _request_transfer_exit(self, request: bytes) -> bytes:
        if self._transfer is None:
            return self._negative_response(0x37, 0x24)
        if len(request) != 1 or self._transfer["remaining"]:
            return self._negative_response(0x37, 0x24)
        self._transfer = None
        return b"\x77"

    def _diagnostic_session_control(self, request: bytes) -> bytes:
        if len(request) != 2:
            return self._negative_response(0x10, 0x13)
        identifier = request[1] & 0x7F
        session = self._sessions.get(identifier)
        if session is None:
            return self._negative_response(0x10, 0x12)
        self._current_session = session
        self._reset_security_access()
        if request[1] & 0x80:
            return b""
        return (
            bytes((0x50, identifier))
            + session.p2_server_max_ms.to_bytes(2, "big")
            + (session.p2_star_server_max_ms // 10).to_bytes(2, "big")
        )

    def _ecu_reset(self, request: bytes) -> bytes:
        if len(request) != 2:
            return self._negative_response(0x11, 0x13)
        reset_type = request[1] & 0x7F
        definition = self._resets.get(reset_type)
        if definition is None:
            return self._negative_response(0x11, 0x12)
        denial = definition.access_rule.denial_code(
            self.current_session, self._unlocked_security_levels
        )
        if denial is not None:
            return self._negative_response(0x11, denial)
        try:
            if definition.condition is not None and not definition.condition():
                return self._negative_response(0x11, 0x22)
            if definition.callback is not None:
                definition.callback()
        except ProgrammingFailure:
            return self._negative_response(0x11, 0x72)
        except Exception:
            return self._negative_response(0x11, 0x10)

        self._current_session = self._sessions[0x01]
        self._session_last_activity = monotonic()
        self._reset_security_access()
        self._transfer = None
        if request[1] & 0x80:
            return b""
        response = bytes((0x51, reset_type))
        if definition.power_down_time is not None:
            response += bytes((definition.power_down_time,))
        return response

    def _dtc_access_denial(self, dtc: DiagnosticTroubleCode) -> int | None:
        denial = dtc.definition.access_rule.denial_code(
            self.current_session, self._unlocked_security_levels
        )
        if denial is not None:
            return denial
        try:
            if dtc.definition.condition is not None and not dtc.definition.condition():
                return 0x22
        except Exception:
            return 0x10
        return None

    def _matching_dtcs(self, status_mask: int) -> list[DiagnosticTroubleCode]:
        return [
            dtc
            for dtc in self._dtcs.values()
            if self._dtc_access_denial(dtc) is None
            and (not status_mask or dtc.status & status_mask)
        ]

    def _clear_diagnostic_information(self, request: bytes) -> bytes:
        if len(request) != 4:
            return self._negative_response(0x14, 0x13)
        group = int.from_bytes(request[1:], "big")
        matching = [
            dtc
            for dtc in self._dtcs.values()
            if group == 0xFFFFFF or dtc.identifier == group
        ]
        for dtc in matching:
            denial = self._dtc_access_denial(dtc)
            if denial is not None:
                return self._negative_response(0x14, denial)
        for dtc in matching:
            dtc.clear()
        return b"\x54"

    def _read_dtc_information(self, request: bytes) -> bytes:
        if len(request) < 2:
            return self._negative_response(0x19, 0x13)
        subfunction = request[1] & 0x7F
        if subfunction in (0x01, 0x02):
            if len(request) != 3:
                return self._negative_response(0x19, 0x13)
            matching = self._matching_dtcs(request[2])
            availability_mask = 0
            for dtc in self._dtcs.values():
                availability_mask |= dtc.status
            if subfunction == 0x01:
                return bytes((0x59, subfunction, availability_mask, 0x01)) + len(
                    matching
                ).to_bytes(2, "big")
            response = bytearray((0x59, subfunction, availability_mask))
            for dtc in matching:
                response.extend(dtc.identifier.to_bytes(3, "big"))
                response.append(dtc.status)
            return bytes(response)
        if subfunction == 0x03:
            if len(request) != 2:
                return self._negative_response(0x19, 0x13)
            response = bytearray((0x59, subfunction))
            for dtc in self._dtcs.values():
                if self._dtc_access_denial(dtc) is None:
                    for snapshot in dtc.definition.snapshots:
                        response.extend(dtc.identifier.to_bytes(3, "big"))
                        response.append(snapshot.record_number)
            return bytes(response)
        if subfunction == 0x04:
            if len(request) != 6:
                return self._negative_response(0x19, 0x13)
            identifier = int.from_bytes(request[2:5], "big")
            try:
                dtc = self.get_dtc(identifier)
            except KeyError:
                return self._negative_response(0x19, 0x31)
            denial = self._dtc_access_denial(dtc)
            if denial is not None:
                return self._negative_response(0x19, denial)
            records = dtc.definition.snapshots
            if request[5] != 0xFF:
                records = tuple(
                    item for item in records if item.record_number == request[5]
                )
            if not records:
                return self._negative_response(0x19, 0x31)
            response = bytearray((0x59, subfunction)) + dtc.identifier.to_bytes(
                3, "big"
            )
            response.append(dtc.status)
            for record in records:
                response.extend(self._encode_snapshot(record))
            return bytes(response)
        if subfunction == 0x05:
            if len(request) != 3:
                return self._negative_response(0x19, 0x13)
            for dtc in self._dtcs.values():
                if self._dtc_access_denial(dtc) is not None:
                    continue
                for record in dtc.definition.snapshots:
                    if record.record_number == request[2]:
                        return (
                            bytes((0x59, subfunction))
                            + dtc.identifier.to_bytes(3, "big")
                            + bytes((dtc.status,))
                            + self._encode_snapshot(record)
                        )
            return self._negative_response(0x19, 0x31)
        if subfunction == 0x06:
            if len(request) != 6:
                return self._negative_response(0x19, 0x13)
            identifier = int.from_bytes(request[2:5], "big")
            try:
                dtc = self.get_dtc(identifier)
            except KeyError:
                return self._negative_response(0x19, 0x31)
            denial = self._dtc_access_denial(dtc)
            if denial is not None:
                return self._negative_response(0x19, denial)
            records = dtc.definition.extended_data
            if request[5] != 0xFF:
                value = records.get(request[5])
                records = {} if value is None else {request[5]: value}
            if not records:
                return self._negative_response(0x19, 0x31)
            response = bytearray((0x59, subfunction)) + dtc.identifier.to_bytes(
                3, "big"
            )
            response.append(dtc.status)
            for record_number, value in records.items():
                response.append(record_number)
                response.extend(value)
            return bytes(response)
        if subfunction in (0x07, 0x08):
            if len(request) != 4:
                return self._negative_response(0x19, 0x13)
            severity_mask, status_mask = request[2:]
            matching = [
                dtc
                for dtc in self._matching_dtcs(status_mask)
                if dtc.definition.severity & severity_mask
            ]
            availability_mask = 0
            for dtc in self._dtcs.values():
                availability_mask |= dtc.status
            if subfunction == 0x07:
                return bytes((0x59, subfunction, availability_mask, 0x01)) + len(
                    matching
                ).to_bytes(2, "big")
            response = bytearray((0x59, subfunction, availability_mask))
            for dtc in matching:
                response.extend(
                    (dtc.definition.severity, dtc.definition.functional_unit)
                )
                response.extend(dtc.identifier.to_bytes(3, "big"))
                response.append(dtc.status)
            return bytes(response)
        if subfunction == 0x09:
            if len(request) != 5:
                return self._negative_response(0x19, 0x13)
            try:
                dtc = self.get_dtc(int.from_bytes(request[2:5], "big"))
            except KeyError:
                return self._negative_response(0x19, 0x31)
            denial = self._dtc_access_denial(dtc)
            if denial is not None:
                return self._negative_response(0x19, denial)
            return (
                bytes(
                    (
                        0x59,
                        subfunction,
                        dtc.definition.severity,
                        dtc.definition.functional_unit,
                    )
                )
                + dtc.identifier.to_bytes(3, "big")
                + bytes((dtc.status,))
            )
        if subfunction in (0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x15):
            if len(request) != 2:
                return self._negative_response(0x19, 0x13)
            matching = self._matching_dtcs(0)
            if subfunction == 0x0B:
                matching = [dtc for dtc in matching if dtc.status & 0x01][:1]
            elif subfunction == 0x0C:
                matching = [dtc for dtc in matching if dtc.status & 0x08][:1]
            elif subfunction == 0x0D:
                matching = [dtc for dtc in matching if dtc.status & 0x01][-1:]
            elif subfunction == 0x0E:
                matching = [dtc for dtc in matching if dtc.status & 0x08][-1:]
            elif subfunction == 0x15:
                matching = [dtc for dtc in matching if dtc.definition.permanent]
            availability_mask = 0
            for dtc in self._dtcs.values():
                availability_mask |= dtc.status
            response = bytearray((0x59, subfunction, availability_mask))
            for dtc in matching:
                response.extend(dtc.identifier.to_bytes(3, "big"))
                response.append(dtc.status)
            return bytes(response)
        if subfunction == 0x14:
            if len(request) != 2:
                return self._negative_response(0x19, 0x13)
            response = bytearray((0x59, subfunction))
            for dtc in self._matching_dtcs(0):
                response.extend(dtc.identifier.to_bytes(3, "big"))
                response.append(dtc.definition.fault_detection_counter)
            return bytes(response)
        if subfunction == 0x16:
            if len(request) != 3:
                return self._negative_response(0x19, 0x13)
            record_number = request[2]
            response = bytearray((0x59, subfunction, record_number))
            count = 0
            for dtc in self._matching_dtcs(0):
                value = dtc.definition.extended_data.get(record_number)
                if value is not None:
                    response.extend(dtc.identifier.to_bytes(3, "big"))
                    response.append(dtc.status)
                    response.extend(value)
                    count += 1
            if not count:
                return self._negative_response(0x19, 0x31)
            return bytes(response)
        return self._negative_response(0x19, 0x12)

    @staticmethod
    def _encode_snapshot(snapshot: DtcSnapshot) -> bytes:
        response = bytearray((snapshot.record_number, len(snapshot.dids)))
        for identifier, value in snapshot.dids.items():
            response.extend(identifier.to_bytes(2, "big"))
            response.extend(value)
        return bytes(response)

    def _routine_control(self, request: bytes) -> bytes:
        if len(request) < 4:
            return self._negative_response(0x31, 0x13)

        subfunction = request[1] & 0x7F
        if subfunction not in (0x01, 0x02, 0x03):
            return self._negative_response(0x31, 0x12)
        identifier = int.from_bytes(request[2:4], "big")
        try:
            routine = self.get_routine(identifier)
        except KeyError:
            return self._negative_response(0x31, 0x31)

        denial = routine.definition.access_rule.denial_code(
            self.current_session, self._unlocked_security_levels
        )
        if denial is not None:
            return self._negative_response(0x31, denial)
        try:
            condition_met = (
                routine.definition.condition is None or routine.definition.condition()
            )
        except Exception:
            return self._negative_response(0x31, 0x10)
        if not condition_met:
            return self._negative_response(0x31, 0x22)

        callback = routine.callback_for(subfunction)
        if callback is None:
            return self._negative_response(0x31, 0x12)
        try:
            status_record = callback(request[4:])
            if not isinstance(status_record, bytes):
                raise TypeError("Routine callbacks must return bytes")
        except ProgrammingFailure:
            return self._negative_response(0x31, 0x72)
        except Exception:
            return self._negative_response(0x31, 0x10)
        if request[1] & 0x80:
            return b""
        return bytes((0x71, subfunction)) + request[2:4] + status_record

    def _security_access(self, request: bytes) -> bytes:
        if len(request) < 2:
            return self._negative_response(0x27, 0x13)
        subfunction = request[1] & 0x7F
        level = subfunction if subfunction % 2 else subfunction - 1
        security_level = self._security_levels.get(level)
        if security_level is None:
            return self._negative_response(0x27, 0x12)
        if monotonic() < self._security_locked_until.get(level, 0):
            return self._negative_response(0x27, 0x37)
        if subfunction % 2:
            try:
                seed = security_level.seed_callback()
                if not isinstance(seed, bytes):
                    raise TypeError
            except Exception:
                return self._negative_response(0x27, 0x10)
            self._pending_seeds[level] = seed
            if request[1] & 0x80:
                return b""
            return bytes((0x67, subfunction)) + seed
        seed = self._pending_seeds.get(level)
        if seed is None:
            return self._negative_response(0x27, 0x24)
        try:
            if security_level.key_validator is not None:
                accepted = security_level.key_validator(seed, request[2:])
            else:
                assert security_level.key_algorithm is not None
                expected_key = security_level.key_algorithm(
                    level, seed, security_level.algorithm_params
                )
                accepted = request[2:] == expected_key
        except Exception:
            return self._negative_response(0x27, 0x10)
        if not accepted:
            attempts = self._security_attempts.get(level, 0) + 1
            self._security_attempts[level] = attempts
            if (
                security_level.max_attempts is not None
                and attempts >= security_level.max_attempts
            ):
                self._security_locked_until[level] = (
                    monotonic() + security_level.delay_seconds
                )
                return self._negative_response(0x27, 0x36)
            return self._negative_response(0x27, 0x35)
        self._unlocked_security_levels.add(level)
        self._security_attempts.pop(level, None)
        self._pending_seeds.pop(level, None)
        if request[1] & 0x80:
            return b""
        return bytes((0x67, subfunction))

    def _tester_present(self, request: bytes) -> bytes:
        if len(request) != 2:
            return self._negative_response(0x3E, 0x13)
        subfunction = request[1] & 0x7F
        if subfunction != 0x00:
            return self._negative_response(0x3E, 0x12)
        return b"" if request[1] & 0x80 else b"\x7e\x00"

    def _expire_diagnostic_session(self) -> None:
        """Return to the default session when the active session's S3 timer expires."""
        timeout_ms = self._current_session.s3_server_timeout_ms
        if (
            self._current_session.identifier != 0x01
            and timeout_ms
            and monotonic() - self._session_last_activity >= timeout_ms / 1000
        ):
            self._current_session = self._sessions[0x01]
            self._reset_security_access()

    def _reset_security_access(self) -> None:
        self._pending_seeds.clear()
        self._unlocked_security_levels.clear()

    @staticmethod
    def _negative_response(request_sid: int, response_code: int) -> bytes:
        return bytes((0x7F, request_sid, response_code))
