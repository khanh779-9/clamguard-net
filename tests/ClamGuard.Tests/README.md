# ClamGuard.Tests

This project is an executable regression harness for ClamGuard's database loading, signature parsing/matching, scanner, and specialized handlers.

## Layout

- `Program.cs` is the small entry point. It invokes smoke tests and topic suites in a stable sequence, then prints the success message only after all groups return.
- `Suites/` contains the tests grouped by subject:
  - `Program.DatabaseTests.cs` — hash patterns and CVD/database loading.
  - `Program.CompiledMatcherTests.cs` — compiled matcher behavior.
  - `Program.SignatureParsingTests.cs` — signature parser and specialized signature formats.
  - `Program.NdbPolicyTests.cs` — NDB offsets, targets, and policy-related behavior.
  - `Program.ContainerLayerTests.cs` — container ancestry, nested layers, normalization and LDB matching.
  - `Program.ExecutableTests.cs` — PE, ELF and Mach-O tests.
  - `Program.LdbParityTests.cs` — regression coverage for the `Win.Malware.Generic-9828792-0` LDB rule, its PE target, the required AND expression, negative controls, and an optional real-sample check.
  - `Program.ArchiveTests.cs` — archive/document formats and archive metadata.
  - `Program.YaraBytecodeTests.cs` — YARA and ClamBC integration.
  - `Program.MetadataTests.cs` — SDB self-protection and metadata signature formats.
- `Support/` contains shared assertions, fixture builders, executable/archive fixtures, smoke tests, and the test-only `SlowScanner` implementation.

The `Program.*.cs` files use one `internal static partial class Program` so helper methods can remain private while still being shared across suites. Fixture locals are created within the suite that consumes them; shared fixture creation is exposed through narrowly scoped helper methods.

## Run

From the repository root, with the .NET 8 SDK installed:

```powershell
dotnet build ClamGuard.Net.sln -c Release
dotnet run --project tests/ClamGuard.Tests/ClamGuard.Tests.csproj -c Release
```

To check the real `000.exe` sample against the exact rule line in an extracted ClamAV database, keep the sample outside the repository and set these environment variables before running the harness:

```powershell
$env:CLAMGUARD_REAL_000_EXE = "C:\Samples\000.exe"
$env:CLAMGUARD_DAILY_LDB_PATH = "C:\ClamAV\daily.ldb"
dotnet run --project tests/ClamGuard.Tests/ClamGuard.Tests.csproj -c Release
```

The optional check extracts only `Win.Malware.Generic-9828792-0` into a temporary test database. It does not embed, execute, or redistribute the sample.
