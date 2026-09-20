# python-uds-server

A configurable UDS (ISO 14229) server for testing Python diagnostic clients
without physical ECU hardware.

`python-uds-server` is currently a foundation for a test-server implementation.
It exposes a small, typed public API and leaves individual UDS services and
transport adapters to later releases.

## Installation

```bash
pip install python-uds-server
```

For development:

```bash
python -m pip install -e ".[test]"
pytest
```

## Usage

```python
from uds_server import UdsServer

server = UdsServer()
server.start()
# Register services and attach a transport in a later version.
server.stop()
```

## Development status

The initial package structure includes a server lifecycle, service contracts,
and transport contracts. No UDS services or concrete transport backends have
been implemented yet.
