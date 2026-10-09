# Scan fix: `MaxFileSize` out-of-range

## Cause addressed

The user-facing `ScanOptions.MaxFileSize` and `MaxScanSize` were 32-bit `int` values even though they represent byte counts and the native-compatible per-file ceiling is 2 GiB. A zero, negative, or overflowed value could make option validation throw `ArgumentOutOfRangeException` before scanning began.

## Changes

- Changed public `MaxFileSize` and `MaxScanSize` to `long` so byte limits do not overflow at the 2 GiB boundary.
- Made the low-level `ScanLimits.MaxFileSize` validation recover from stale/zero/out-of-range values too, before effective parser budgets are derived.
- Kept the default values at 100 MiB (`MaxFileSize`) and 400 MiB (`MaxScanSize`).
- Normalized non-positive public limits to these safe defaults and capped `MaxFileSize` at 2 GiB before calculating effective parser limits.
- Changed the scan host to validate a private copy of `ScanOptions`, so normalization does not mutate the caller's object.
- Added regression tests for zero values, an `int.MinValue` overflow-like value, the 2 GiB ceiling, and an actual raw-signature scan with invalid `MaxFileSize`.

## Verification status

Static consistency checks passed. This environment does not contain the .NET SDK, so `dotnet build` and the test executable could not be run here. Please run the commands below on a machine with the SDK installed:

```powershell
dotnet build .\ClamGuard.Net.sln --configuration Release
dotnet run --project .	ests\ClamGuard.Tests\ClamGuard.Tests.csproj --configuration Release
```
