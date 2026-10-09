# Full Source-Code Audit — ClamGuard.NET

Historical findings from 2026-10-02; structure refactor reviewed 2026-10-09

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

6. `ClamGuard.Database/Update/CdiffPatchApplier.cs`
   - Corrected a wrong namespace reference from `ClamAv.Database.ClamAvSignatureVerifier` to `ClamGuard.Database.ClamAvSignatureVerifier`.

7. `ClamGuard.Net.sln`
   - The solution project graph was simplified: `ClamGuard.Update` moved under `ClamGuard.Database/Update`, `ClamGuard.Production` moved under `ClamGuard.Scanner/Hosting`, and the independent CLI was removed.

## Static verification

- Existing historical audit checked 37 C# source/test files; the 2026-10-09 refactor adds/splits several source files.
- C# delimiter lexer check: PASS.
- UTF-8 and NUL-byte check: PASS.
- Current `.csproj` files were checked by the 2026-10-09 static structure pass; `ClamGuard.Cli`, `ClamGuard.Production` and `ClamGuard.Update` project files were removed as part of consolidation.
- All project references resolve to an existing project.
- Project reference graph has no cycles.
- The solution now contains the remaining core, signatures, database, scanner, tests, YARA, bytecode and WPF projects.
- `ClamGuard.Scanner` has one NuGet dependency (`SharpCompress`) for managed archive handling; other core projects primarily use .NET 8 libraries and project references. Optional archive decoders and CMS verification tools are runtime executables, not NuGet dependencies.
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


## 2026-10-09 refactor validation

This packaging environment does not include the .NET SDK/compiler. The refactor therefore uses static project/path/source checks and cannot claim a successful compiler build or runtime regression pass. Run `scripts/verify.ps1` on Windows (or `scripts/verify.sh` where WPF targeting is supported) to perform the real Release build and regression harness.
