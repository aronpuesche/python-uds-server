# python-uds-server

A configurable UDS (ISO 14229) server for testing Python diagnostic clients
without physical ECU hardware.

`python-uds-server` uses `can-isotp` and `python-can` as its transport basis.
Implemented UDS services: DiagnosticSessionControl (`0x10`), ECUReset (`0x11`),
ClearDiagnosticInformation (`0x14`), ReadDTCInformation (`0x19`),
ReadDataByIdentifier (`0x22`), SecurityAccess (`0x27`), CommunicationControl
(`0x28`), WriteDataByIdentifier (`0x2E`), InputOutputControlByIdentifier
(`0x2F`), RoutineControl (`0x31`),
ReadMemoryByAddress (`0x23`), WriteMemoryByAddress (`0x3D`), RequestDownload
(`0x34`), RequestUpload (`0x35`), TransferData (`0x36`), RequestTransferExit
(`0x37`), RequestFileTransfer (`0x38`) and TesterPresent (`0x3E`).

The full documentation is built with Sphinx and configured for Read the Docs;
see [`docs/`](docs/index.rst) for a local build.
Release notes are maintained in [CHANGELOG.md](CHANGELOG.md).
Publishing is automated for version tags (`v*`) through GitHub Actions and
PyPI Trusted Publishing.

## Installation

```bash
pip install python-uds-server
```

For development:

```bash
python -m pip install -e ".[test]"
pre-commit install
pytest
python -m pip install -e ".[docs]"
python -m sphinx -b html docs docs/_build/html
```

Black now runs automatically on staged Python files before each commit. Run
`pre-commit run --all-files` to format the complete checkout on demand.

## Usage

```python
import can
import isotp

from uds_server import (
    AccessRule,
    DiagnosticSession,
    DidDefinition,
    MemoryRegionDefinition,
    RoutineDefinition,
    SecurityLevel,
    UdsServer,
)
from uds_server.transport import IsoTpTransport

# Use the CAN interface and bitrate appropriate for the test environment.
bus = can.Bus(interface="socketcan", channel="can0", bitrate=500_000)
isotp_layer = isotp.CanStack(
    bus=bus,
    address=isotp.Address(
        isotp.AddressingMode.Normal_11bits,
        txid=0x708,  # ECU response CAN ID
        rxid=0x700,  # Tester request CAN ID
    ),
)

server = UdsServer(
    transport=IsoTpTransport(isotp_layer),
    sessions=[DiagnosticSession(0x01), DiagnosticSession(0x03)],
    dids=[
        DidDefinition(
            identifier=0xF190,
            length=17,
            read_callback=lambda: b"DEMO-VIN-12345678",
        ),
        DidDefinition(
            identifier=0x1234,
            length=2,
            # Writing this DID requires extended session and SecurityAccess level 1.
            access_rule=AccessRule(
                allowed_sessions=frozenset({0x03}),
                allowed_security_levels=frozenset({0x01}),
            ),
        ),
    ],
    security_levels=[
        SecurityLevel(
            level=0x01,
            seed_callback=lambda: b"\x12\x34",
            # Demo-only validation; use a real application algorithm in production.
            key_validator=lambda seed, key: seed == b"\x12\x34" and key == b"\xbe\xef",
        ),
    ],
    routines=[
        RoutineDefinition(
            identifier=0x0203,
            access_rule=AccessRule(allowed_sessions=frozenset({0x03})),
            start_callback=lambda option_record: b"complete",
        ),
    ],
    memory_regions=[MemoryRegionDefinition(start_address=0x1000, length=0x1000)],
)

# The writable DID uses mutable in-memory storage after access is granted.
server.set_did_value(0x1234, b"\x00\x00")
server.start()

# The tester must request session 0x03, seed 0x01 and then send key b"\xbe\xef"
# before it can write DID 0x1234. Call server.stop() and bus.shutdown() on exit.
```

## Development status

The package currently supports a typed DID registry and ReadDataByIdentifier
(`0x22`). A `DidDefinition` has a fixed byte length and optional independent
read and write callbacks. The default `READ_WRITE` access uses internal mutable
storage, which is useful for test fixtures. Sessions define P2/P2* timing.
Non-default sessions additionally return to the default session after their
configurable S3 server timeout (5 seconds by default).
SecurityAccess levels use application-provided seed and key-validation callbacks;
this project deliberately does not prescribe a security algorithm. CDD import is
planned future work. RoutineControl routines have optional callbacks for start,
stop, and result requests; each receives the option record and returns the status
record.

## UDS implementation status

The table below covers the service catalogue currently exposed by the project's
`udsoncan` dependency. Exact service availability can vary by ISO 14229 edition
and ECU profile.

| SID | Service | Status |
| --- | --- | --- |
| `0x10` | DiagnosticSessionControl | Implemented; configured session IDs are supported. |
| `0x11` | ECUReset | Implemented; configured reset types are supported. |
| `0x14` | ClearDiagnosticInformation | Implemented. |
| `0x19` | ReadDTCInformation | See open subfunctions below. |
| `0x22`, `0x23`, `0x27`, `0x2E`, `0x31` | DID, memory, security, write-DID and routine services | Implemented. |
| `0x34`–`0x38`, `0x3D`, `0x3E` | Transfer, file transfer, memory write and TesterPresent | Implemented. |
| `0x24` | ReadScalingDataByIdentifier | Not implemented. |
| `0x28` | CommunicationControl | Implemented; invokes configured callbacks without disabling UDS responses. |
| `0x29` | Authentication | Not implemented. |
| `0x2A` | ReadDataByPeriodicIdentifier | Not implemented. |
| `0x2C` | DynamicallyDefineDataIdentifier | Not implemented. |
| `0x2F` | InputOutputControlByIdentifier | Implemented; configured I/O-control DIDs support standard control parameters. |
| `0x83`–`0x87` | Timing, secured transmission, DTC setting, events and link control | Not implemented. |

### Open `0x19 ReadDTCInformation` subfunctions

| Subfunction | Name |
| --- | --- |
| `0x0F`–`0x11` | Mirror-memory DTC reports |
| `0x12`, `0x13` | Emissions-related OBD DTC reports |
| `0x17`–`0x19` | User-defined-memory DTC reports |
| `0x1A` | ReportSupportedDTCExtDataRecord |
| `0x42`, `0x55`, `0x56` | WWH-OBD and readiness-group reports |

## Integration scenarios

Integration tests are pytest files in `tests/integration/`, with one file per
UDS service. They run a real `udsoncan` client against a virtual CAN server by
default. To run the same tests against a physical back-to-back setup, for
example a PCAN-USB Pro:

```powershell
$env:UDS_INTEGRATION_BACKEND = "hardware"
$env:UDS_CAN_INTERFACE = "pcan"
$env:UDS_CAN_CLIENT_CHANNEL = "PCAN_USBBUS1"
$env:UDS_CAN_SERVER_CHANNEL = "PCAN_USBBUS2"
$env:UDS_CAN_BITRATE = "500000"
python -m pytest -m integration
```

Both endpoints use normal 11-bit ISO-TP addressing. The fixture starts the test
server on the server channel and uses `udsoncan` from the client channel.
