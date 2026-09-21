Supported services
==================

The server currently implements these UDS services:

================= ================================================
SID               Service
================= ================================================
``0x10``          DiagnosticSessionControl
``0x11``          ECUReset
``0x14``          ClearDiagnosticInformation
``0x19``          ReadDTCInformation
``0x22`` / ``23`` ReadDataByIdentifier / ReadMemoryByAddress
``0x27``          SecurityAccess
``0x28``          CommunicationControl (callback-driven)
``0x2E`` / ``2F`` WriteDataByIdentifier / InputOutputControlByIdentifier
``0x31``          RoutineControl
``0x34``--``37``  Download, upload, TransferData, TransferExit
``0x38``          RequestFileTransfer
``0x3D`` / ``3E`` WriteMemoryByAddress / TesterPresent
================= ================================================

ReadDTCInformation
------------------

Implemented ``0x19`` subfunctions are ``0x01``--``0x0E``, ``0x14``--``0x16``.
Mirror-memory, user-defined-memory, OBD/WWH-OBD and readiness-group variants
remain unsupported. See the repository README for the complete outstanding-SID
matrix.

File transfer modes
-------------------

``RequestFileTransfer`` supports AddFile (``0x01``), DeleteFile (``0x02``),
ReplaceFile (``0x03``), and ReadFile (``0x04``). ReadDir and ResumeFile are not
implemented. File content uses no compression or encryption; the data-format
identifier must therefore be ``0x00``.
