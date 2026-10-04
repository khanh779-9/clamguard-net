# Full Source-Code Audit — ClamGuard.NET

Date: 2026-10-02

## Scope

Audited all C# source files, tests, project files, solution metadata, scripts and repository text included in iteration-12.

## Findings fixed

1. `ClamGuard.Bytecode/ClamBcEngine.cs`
   - Added missing `System.IO.Compression` import for `GZipStream`, `DeflateStream`, `ZLibStream` and `CompressionMode`.
   - Added the missing VM fields `_runtime`, `_pdfObjects`, `_pdfPhase`, `_pdfFlags`, `_pdfDumpedObjectId`.
   - Fixed a missing closing parenthesis in `TryParsePeSections`.

2. `ClamGuard.Scanner/ScannerEngine.cs`
   - Added missing `System.Diagnostics` import for `Stopwatch`.

3. `ClamGuard.Signatures/Parsing/SignatureParser.cs`
   - Added missing `using ClamGuard.Signatures;` for signature model types in the parent namespace.

4. `ClamGuard.Signatures/Matching/CompiledSignatureSet.cs`
   - Added missing `using ClamGuard.Signatures;` for signature model types in the parent namespace.

5. `tests/ClamGuard.Tests/Program.cs`
   - Added missing `using ClamGuard.Signatures;` for `ContentMatchOptions`.

6. `ClamGuard.Update/CdiffPatchApplier.cs`
   - Corrected a wrong namespace reference from `ClamAv.Database.ClamAvSignatureVerifier` to `ClamGuard.Database.ClamAvSignatureVerifier`.

7. `ClamGuard.Net.sln`
   - Added Debug/Release project configuration mappings for all 10 projects.

## Static verification

- 37 C# source/test files scanned.
- C# delimiter lexer check: PASS.
- UTF-8 and NUL-byte check: PASS.
- All 10 `.csproj` files parse as valid XML.
- All project references resolve to an existing project.
- Project reference graph has no cycles.
- Solution contains all 10 projects represented on disk.
- No `<PackageReference>` entries remain; core builds use the .NET 8 framework plus explicitly documented external executables where required at runtime.
- No `TODO`, `FIXME`, `NotImplementedException` or obsolete CDIFF stub remains in source/tests.
- No definite missing project-namespace imports remain after the fixes.
- Framework-namespace audit has no definite missing imports; the only heuristic residual is the `SignatureType.Regex` enum member, which is not a type reference.
- No `ClamAv.*` vendor namespace references remain.
- Async methods were checked for the `CS1998` pattern (async without await); none were found.
- Internal project types were checked against public surfaces; the remaining matches are members of internal containing types or implementation initializers, not externally exposed signatures.

## Compiler limitation

The packaging environment has no `dotnet`, `csc`, `msbuild`, Mono, or Roslyn compiler installed. An actual `dotnet build` / `dotnet test` therefore could not be executed in this environment.

The repository CI is configured to run restore/build/regression on Windows and Linux with .NET 8.

## Runtime-only external dependencies

These are not compile-time NuGet dependencies:

- `openssl` for detached CMS/PKCS#7 database-signature verification.
- Optional archive executables: `7z`/`7zz`/`7za`, `unrar`, `bzip2`, and `xz`.

The code resolves these executables explicitly and applies argument, timeout and output/resource limits.
