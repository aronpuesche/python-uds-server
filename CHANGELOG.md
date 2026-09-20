# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-21

### Added

- Configurable UDS server lifecycle with CAN/ISO-TP transport support.
- DiagnosticSessionControl, ECUReset, ClearDiagnosticInformation and
  ReadDTCInformation services.
- Configurable DID, memory-region, virtual-file, DTC, routine, reset,
  communication-control and I/O-control registries.
- SecurityAccess with pluggable seed/key validation and session/security access
  rules.
- Read/WriteDataByIdentifier, Read/WriteMemoryByAddress, RoutineControl,
  CommunicationControl and InputOutputControlByIdentifier services.
- RequestDownload, RequestUpload, TransferData, RequestTransferExit and
  RequestFileTransfer for in-memory memory and file transfers.
- Unit tests and virtual-CAN integration tests using `udsoncan`.
- Sphinx documentation and Read the Docs build configuration.
