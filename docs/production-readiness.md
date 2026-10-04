# Production Readiness

ClamGuard.NET exposes `ClamGuard.Production.ProductionScanHost` as the deployment facade.

## Runtime hardening

- bounded admission: `MaxConcurrentScans + MaxQueuedScans`
- optional fail-closed health gate rejects scans when the active database is empty or unverified
- queue-wait timeout
- per-scan cancellation/timeout
- full-buffer materialization cap (`ScanLimits.MaxFullBufferSize`)
- existing archive depth/entry/expanded-byte/compression-ratio budgets
- bytecode instruction/call-depth/allocation/object limits
- scanner-owned effective options are cloned; caller-owned `ScanOptions` are not mutated
- YARA/ClamBC rule directories are cached per `ScannerEngine` instance instead of reparsed on every scan
- scan-limit validation rejects invalid/unsafe limit combinations before work is admitted
- graceful shutdown cancels queued/in-flight work and drains active operations before releasing synchronization resources
- observer callbacks are isolated from the scan path
- database state is atomically published by `DatabaseManager`

## Health and metrics

The production facade reports database generation, signature count, verified container databases, queue depth, in-flight scans, throughput bytes and verdict/error/timeout counters.

## Verification gates

- CVD/.info/detached signature verification remains required by the database updater when configured.
- Production health can require every active CVD/CLD/CUD database to be verified.

## CI

The repository CI builds on Windows and Linux and runs the existing regression executable after a warnings-as-errors Release build.

## Operational validation

The codebase now contains the production control plane and regression harness. A deployment should still establish environment-specific fuzz/performance baselines and service-level observability/certificate-store policy before declaring a particular host environment production-certified. These are deployment acceptance activities, not unimplemented scanner features.
