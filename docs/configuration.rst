Configuration
=============

``UdsServer`` receives definition objects at construction time. Each definition
supports :class:`uds_server.AccessRule`, which can restrict access to diagnostic
sessions or unlocked security levels. A ``condition`` callback can reject a
request dynamically.

Data and memory
---------------

* :class:`uds_server.DidDefinition` configures fixed-length DIDs.
* :class:`uds_server.MemoryRegionDefinition` configures contiguous ECU memory.
* :class:`uds_server.IoControlDefinition` configures a controllable I/O DID.

Diagnostics and control
-----------------------

* :class:`uds_server.DiagnosticSession` configures sessions and timing values.
* :class:`uds_server.SecurityLevel` supplies seed/key validation.
* :class:`uds_server.EcuResetDefinition`,
  :class:`uds_server.CommunicationControlDefinition`, and
  :class:`uds_server.RoutineDefinition` configure callback-driven operations.
* :class:`uds_server.DtcDefinition` defines DTC status, snapshots, extended
  data, severity, fault counters, and permanent status.

Transfers
---------

* :class:`uds_server.MemoryRegionDefinition` is used by RequestDownload and
  RequestUpload.
* :class:`uds_server.FileDefinition` exposes an in-memory virtual file through
  RequestFileTransfer. It never reads or writes host files. A file with
  ``data=None`` reserves a path for ``AddFile``.
