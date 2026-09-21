Getting started
===============

Install the package:

.. code-block:: console

   pip install python-uds-server

This complete example creates an ECU simulation connected to a physical or
virtual CAN interface. It configures ISO-TP, two diagnostic sessions, a
security level, DIDs, a memory region and a routine. Definitions use mutable
in-memory storage unless a callback is supplied.

.. code-block:: python

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
               0xF190,
               length=17,
               read_callback=lambda: b"DEMO-VIN-12345678",
           ),
           DidDefinition(
               0x1234,
               length=2,
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
               key_validator=lambda seed, key: seed == b"\x12\x34" and key == b"\xbe\xef",
           ),
       ],
       routines=[
           RoutineDefinition(
               0x0203,
               access_rule=AccessRule(allowed_sessions=frozenset({0x03})),
               start_callback=lambda option_record: b"complete",
           ),
       ],
       memory_regions=[MemoryRegionDefinition(0x1000, length=0x100)],
   )
   server.set_did_value(0x1234, b"\x00\x00")
   server.start()

The client must select session ``0x03``, request SecurityAccess seed ``0x01``
and send the demo key ``b"\xbe\xef"`` before it may write DID ``0x1234``. Use a
real, application-specific key algorithm outside of tests. Call ``server.stop()``
and ``bus.shutdown()`` during application shutdown.
