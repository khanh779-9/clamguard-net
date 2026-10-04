# ClamGuard.Net — Iteration 48 Check Report

## Scope
Behavioral alignment with ClamAV 1.5.4 native specialized handlers, limited to the high-value managed paths implemented in this iteration.

## Implemented
- HWP3 pre-raw specialized scan.
  - 30-byte identity header.
  - 128-byte document info.
  - 1008-byte document summary boundary.
  - password-protected documents are not parsed.
  - optional info block is bounded.
  - compressed body uses raw DEFLATE and is rescanned as a new layer.
- HWP embedded OLE2 (HWPOLE2).
  - 4-byte uncompressed-size prefix is validated/warn-only semantics.
  - remaining bytes are rescanned as OLE2.
- HWP5 inside OLE2.
  - `FileHeader` recognition.
  - version/flags extraction.
  - compressed stream handling for `bin*`, `jscriptversion`, `defaultjscript`, `section`, `viewtext`, `docinfo`.
  - password flag causes scan-as-is instead of decompression.
  - raw DEFLATE bounded decompression.
- HTML specialized pre-raw scan.
  - normalized `nocomment.html`-style layer.
  - normalized `notags.html`-style layer.
  - extracted JavaScript scanned as HTML target and ASCII target.
  - normalization limits aligned to ClamAV 1.5.4 defaults: 40 MiB / 8 MiB / 20 MiB.
- HTML UTF-16 decode before HTML specialized handling.
- Specialized pre-raw dispatch is applied to root files and embedded child layers.
- Generic raw scan remains after specialized parsing, preserving the original layer.

## Intentionally not claimed as full native parity
- Full ClamAV HTML parser/DOM semantics, URI/data: extraction, CSS image extraction, and full JScript/VBScript.encode decoder.
- Full JavaScript token normalization (variable renaming, number normalization, eval reparsing, unescape semantics, packer handling).
- Full HWP3 paragraph/special-object reconstruction.
- Full OLE2 VBA/XLM/image/summary/AuthentiCode ecosystem.

## Verification
- Touched-file C# lexical brace validation: PASS.
- Specialized HTML regression fixture: added.
- Compressed HWP3 raw-DEFLATE regression fixture: added.
- Full `dotnet build/test`: NOT RUN; .NET SDK is unavailable in the execution environment.

# Iteration 49 Addendum

## Implemented
- OneNote specialized pre-raw fallback extraction.
  - validates `ONE_MAGIC` (`e4525c7b8cd8a74daeb15378d02996d3`)
  - locates `FILE_DATA_STORE_OBJECT` (`e716e3bd65261145a4c48d4d0b7a9eac`)
  - reads the low 32-bit `cbLength` at header offset 16
  - applies `MaxEmbeddedStreamSize`
  - rescans each extracted attachment as its own layer
- XDP specialized pre-raw extraction.
  - XML parsing with DTDs prohibited
  - `<chunk>` Base64 decoding
  - 1028-byte `%PDF-` candidate gate
  - embedded PDF rescan
  - malformed XML/Base64 does not block the ordinary raw layer
- HWPML specialized pre-raw extraction.
  - `bindata`, `scriptheader`, `scriptsource` callback elements
  - `Encoding=Base64`
  - `Compress=true` using zlib-wrapped DEFLATE
  - bounded decoded/decompressed output
  - child-layer rescan
- Regression fixtures for OneNote, XDP, and HWPML were added to the executable test harness.

## Native source alignment
- ClamAV 1.5.4 dispatches `CL_TYPE_ONENOTE` to `scan_onenote()`.
- ClamAV 1.5.4 dispatches `CL_TYPE_XDP` to `cli_scanxdp()`.
- ClamAV 1.5.4 dispatches `CL_TYPE_XML_HWP` to `cli_scanhwpml()`.
- ClamAV's OneNote scanner has a parser-backed path plus the older Office 2010 fallback that scans `FileDataStoreObject` payloads; Iteration 49 implements the latter managed path.

## Verification
- Balanced C# lexical delimiters on all touched files: PASS.
- New regression source blocks are present and balanced: PASS.
- `dotnet build/test`: NOT RUN because the execution environment has no .NET SDK/compiler.

## Explicit remaining gaps
- Full `onenote.rs` object graph extraction for every modern OneStore revision.
- OLE2 VBA project-directory reconstruction/decompression and XLM sheet extraction parity.
- Full native JavaScript token normalization/eval reparsing and HTML data-URI/CSS extraction.

## Iteration 49-r1 — Syntax/import audit

Fixed compile-time import omissions found during whole-tree audit:
- `src/ClamGuard.Scanner/ArchiveManagedDecoder.cs`: added `using ClamGuard.Core;` for `ScanLimits`.
- `src/ClamGuard.Scanner/SpecializedFileHandlers.cs`: added `using ClamGuard.Database;` for `CompiledState`.
- `src/ClamGuard.Signatures/Parsing/SignatureParser.cs`: added `using System.Text.RegularExpressions;` for `Regex`.

Verification:
- Structural C# delimiter scan across all 44 `.cs` files: PASS (0 unmatched/unclosed delimiters).
- Project-reference path audit across all 10 `.csproj`: PASS (0 missing references).
- ClamGuard using-directive namespace audit: PASS (0 unresolved project namespaces).
- SharpCompress package declaration: `SharpCompress` 0.50.4 present in `ClamGuard.Scanner.csproj`.
- No `TODO`, `FIXME`, `NotImplementedException`, or placeholder `NotSupportedException` found in C# source.
- Full Roslyn/.NET compilation: NOT RUN because the environment has no .NET SDK/compiler.
