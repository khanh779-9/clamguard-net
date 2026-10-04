# ClamGuard.NET Verification Report

Date: 2026-10-02

## Checked

- Solution and project reference graph
- Target framework and language settings
- Internal namespace/type references
- C# source brace/parenthesis balance
- CVD header field validation
- CVD archive path safety
- Database loader error propagation
- Hash functionality-level filtering
- False-positive handling
- NDB target validation
- LDB comparison parsing safety
- Hex-pattern backtracking bounds
- ZIP expansion limits
- PE32/PE32+ section hash and import hash matching
- ELF32/ELF64 executable metadata bounds and relative-entrypoint resolution
- Thin and universal Mach-O detection plus architecture-slice offset rebasing
- Mach-O 64-bit section metadata and LC_UNIXTHREAD/LC_MAIN entry-point resolution
- TAR/old-TAR, GZIP, CPIO newc/crc/ODC/old-binary, OLE2 stream, and PDF Flate/ASCIIHex/ASCII85/RunLength extraction
- Archive-family routing for ARJ/CAB/CHM/ISO/XAR/DMG/LHA with optional external 7-Zip member extraction
- Optional BZip2/XZ single-stream and RAR/7-Zip/ARJ/CAB/CHM/ISO/XAR/DMG/LHA member extraction via PATH-resolved external decoders
- Nested container depth, entry-count, expanded-byte, per-file, and compression-ratio limits
- Database generation replacement
- Updater temporary-file validation
- Database-name path traversal protection
- ClamBC 1.5.4 API-surface parity check: 107 native API names vs 107 managed dispatcher names, with zero missing/extra APIs
- ProductionScanHost queue admission, timeout accounting, health gating, observer isolation, option cloning, rule-engine cache, lifecycle drain/finalization paths, and regression smoke coverage

## Dependency review

Core parsing and matching use only the .NET 8 base class libraries plus project-to-project references. RAR/7-Zip/BZip2/XZ and 7-Zip-backed ARJ/CAB/CHM/ISO/XAR/DMG/LHA extraction is optional and uses compatible executables resolved from PATH; archive/member names are passed through ArgumentList and no shell command line is constructed.

No third-party NuGet package is required by the current projects.

## Runtime compilation limitation

The verification environment used for this review does not provide the `dotnet` SDK, `csc`, `msbuild`, or Mono compiler. Therefore an actual `dotnet build` / `dotnet test` execution could not be performed here.

The included test project remains executable with a standard .NET 8 SDK.

## Important compatibility status

This is not a ClamAV source-level port. The repository documents remaining compatibility limits separately from implemented feature gates: advanced YARA syntax, native-only ClamBC/JIT or codec integrations that cannot be safely reproduced in managed code, specialized PE packer/AuthentiCode/iShield behavior, selected deep archive/document semantics, and less-common auxiliary database families. CDIFF, database verification, YARA integration, ClamBC runtime, and the production runtime facade are implemented in this iteration series.
