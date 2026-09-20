"""Shared virtual-CAN fixture for UDS client integration tests."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import os
from uuid import uuid4

import can
import isotp
import pytest
from udsoncan import DidCodec, Response
from udsoncan.client import Client
from udsoncan.connections import PythonIsoTpConnection
from udsoncan.exceptions import TimeoutException

from uds_server import UdsServer
from uds_server.transport import IsoTpTransport


class BytesCodec(DidCodec):
    """Encode and decode a fixed-size DID record as ``bytes``."""

    def __init__(self, length: int) -> None:
        self.length = length

    def encode(self, value: bytes) -> bytes:
        if not isinstance(value, bytes) or len(value) != self.length:
            raise ValueError(f"Expected exactly {self.length} bytes")
        return value

    def decode(self, payload: bytes) -> bytes:
        return payload

    def __len__(self) -> int:
        return self.length


@dataclass
class UdsTestClient:
    """Expose high-level udsoncan calls and byte-exact raw requests."""

    client: Client
    connection: PythonIsoTpConnection

    def request_raw(self, payload: bytes, timeout: float = 0.2) -> Response | None:
        """Send a raw request and parse a response, if the server sends one."""
        self.connection.specific_send(payload)
        try:
            response_payload = self.connection.specific_wait_frame(timeout=timeout)
        except TimeoutException:
            return None
        return Response.from_payload(response_payload)


@pytest.fixture
def uds_client():
    """Create a real udsoncan client connected to a supplied UDS server."""

    @contextmanager
    def connect(
        server: UdsServer, did_codecs: dict[int, DidCodec] | None = None
    ) -> Iterator[UdsTestClient]:
        if os.getenv("UDS_INTEGRATION_BACKEND", "virtual") == "hardware":
            interface = os.getenv("UDS_CAN_INTERFACE", "pcan")
            bitrate = int(os.getenv("UDS_CAN_BITRATE", "500000"))
            client_bus = can.Bus(
                interface=interface,
                channel=os.getenv("UDS_CAN_CLIENT_CHANNEL", "PCAN_USBBUS1"),
                bitrate=bitrate,
            )
            server_bus = can.Bus(
                interface=interface,
                channel=os.getenv("UDS_CAN_SERVER_CHANNEL", "PCAN_USBBUS2"),
                bitrate=bitrate,
            )
        else:
            channel = f"uds-server-test-{uuid4()}"
            client_bus = can.Bus(
                interface="virtual", channel=channel, receive_own_messages=False
            )
            server_bus = can.Bus(
                interface="virtual", channel=channel, receive_own_messages=False
            )
        client_notifier = can.Notifier(client_bus, [])
        server_notifier = can.Notifier(server_bus, [])
        client_stack = isotp.NotifierBasedCanStack(
            bus=client_bus,
            notifier=client_notifier,
            address=isotp.Address(
                isotp.AddressingMode.Normal_11bits, txid=0x700, rxid=0x708
            ),
        )
        server_stack = isotp.NotifierBasedCanStack(
            bus=server_bus,
            notifier=server_notifier,
            address=isotp.Address(
                isotp.AddressingMode.Normal_11bits, txid=0x708, rxid=0x700
            ),
        )
        server._transport = IsoTpTransport(server_stack)
        server.start()
        connection = PythonIsoTpConnection(client_stack)
        try:
            with Client(
                connection, config={"data_identifiers": did_codecs or {}}
            ) as client:
                yield UdsTestClient(client, connection)
        finally:
            server.stop()
            client_notifier.stop()
            server_notifier.stop()
            client_bus.shutdown()
            server_bus.shutdown()

    return connect
