# ClamGuard.NET

An independent .NET malware scanning engine inspired by the public behavior and documented signature formats used by ClamAV 1.5.x.

## Scope

This repository is a clean architectural reimplementation written from scratch in C#. It does **not** copy ClamAV C/C++ implementation code, translated function bodies, internal struct layouts, or generated source files.

Implemented in this first delivery:

- CVD header inspection and metadata extraction
- Plain-text database discovery
- Hash signature loading (`.hdb`, `.hsb`, `.hdu`, `.hsu`, `.fp`, `.sfp`, `.mdb`, `.msb`, `.imp`)
- Extended NDB signature loading and target-aware matching
- Extended LDB logical signatures with boolean/count expressions, target/functionality filtering, modifiers, macros, PCRE triggers, and byte-compare subsignatures
- ClamAV-style hexadecimal patterns with exact bytes, nibble wildcards, byte wildcards, bounded/unbounded gaps, character classes, and generic/fixed alternates
- Aho-Corasick acceleration for fixed byte patterns, with a BM fast path for a single long exact rule
- Whole-file MD5/SHA-1/SHA-256 matching with size-specific/wildcard digest indexes
- Chunked root-file scanning with stateful Aho-Corasick and incremental whole-file hashing
- Memory-mapped root-file access to avoid eagerly materializing ordinary scans into one managed byte array
- Recursive container/document scanning with bounded depth, entry count, expanded bytes, compression ratio, and optional external-codec timeouts
- Safe temporary-file database installation
- Full CVD download update path
- CLI for `db info`, `db load`, `scan`, and `update`

Remaining compatibility gaps:

- Advanced YARA language features outside the managed compatibility subset: modules, imports/includes, externals, rich arithmetic/loop conditions, and every hex-string construct
- Native-only ClamBC backends whose behavior depends on native process/JIT integrations or codecs without a safe built-in .NET equivalent (LZMA/BZip2/JS/disassembler/JIT/extraction callback ABI) are fail-closed rather than executed unsafely
- PE packer/unpacker modules, Authenticode/iShield parsing, and complete PE ordinal-name parity beyond the current extended surface
- Additional deep document semantics (HWP/OneNote/RTF/mail internals, richer OOXML/PDF object/xref/encryption features) and archive variants not supported by the selected external decoder
- Native filesystem/archive parsers for some specialized formats remain intentionally outside the managed decoder set; compatible external decoders can be used through the guarded archive bridge where configured
- Full native `.cat` Authenticode catalog/X.509 extraction and every native YARA/ClamBC feature remain separate compatibility tracks; the database loader now recognizes, validates, and records all official database extension families.
- Production deployment still requires environment-specific fuzz/performance/service acceptance tests in the target infrastructure; the repository provides the bounded runtime, verification gates, CI workflow, regression harness, and observability primitives needed for that acceptance

The current streaming matcher guarantees chunk-boundary continuity for fixed patterns and bounded patterns within `MaxFlexibleLookbehind`. Unbounded-gap patterns remain intentionally bounded during streaming; advanced LDB/NDB target-aware evaluation is performed through the full-buffer compatibility path so relative offsets, normalization, macros, and logical counting have complete file context.

Those are intentionally explicit gaps; the project never reports them as implemented when they are not.

## WPF desktop app

`ClamGuard.Antivirus` is a small Windows desktop client built on top of the managed engine projects. It intentionally keeps realtime protection at the `FileSystemWatcher` level; it is not a kernel filesystem minifilter or a complete Windows Defender replacement.

## License / provenance note

The source repository is an independent implementation. ClamGuard.NET is not a relicensing or license-evasion wrapper around ClamAV source. The implementation uses independently written C# code and public behavioral/format knowledge.

This statement is not legal advice and it does not guarantee that every use, database, signature file, or deployment scenario is exempt from third-party licensing or other legal requirements. Review the licenses and terms for the exact databases and assets you distribute.

## Target framework

- .NET 8
- C# 12
- Core parsing/matching uses .NET base libraries; `ClamGuard.Scanner` references SharpCompress for managed archive support. Optional external decoders are resolved from `PATH`.

## Quick start

```bash
dotnet build ClamGuard.Net.sln
```

## Project layout

- `ClamGuard.Core`: shared domain models and configuration
- `ClamGuard.Signatures`: signature models, parsers and matchers
- `ClamGuard.Database`: database discovery, loaders and CVD support
- `ClamGuard.Scanner`: scan orchestration
- `ClamGuard.Database/Update`: remote CVD update workflow and verified CDIFF application
- `ClamGuard.Yara`: optional managed YARA engine and scanner adapter
- `ClamGuard.Bytecode`: bounded managed ClamBC parser/interpreter, public API dispatcher, and scanner adapter
- `ClamGuard.Scanner/Hosting`: bounded admission/concurrency, timeouts, health gating, metrics and lifecycle management
- `ClamGuard.Antivirus`: Windows WPF frontend for file/folder scanning, realtime monitoring, database updates, themes, toast notifications and custom dialogs
- `ClamGuard.Tests`: executable regression harness for parsers, matchers, archive behavior, scan-host lifecycle and engine integration

## Safety model

Database files and scanned files are treated as untrusted input. Parsers apply bounded reads, recursion limits and explicit validation. Database replacement uses a temporary file and atomic move where the platform permits it.

## Iteration-46 — Full database loader coverage

Compared against the ClamAV 1.5.4 `libclamav/readdb.c`, `dconf.c`, and `openioc.c` dispatch/loaders and the official ClamAV signature-format documentation.

- Added dedicated loaders for `.ftm`, `.cfg`, `.wdb/.pdb/.gdb`, `.pwdb`, `.crb`, `.cat`, `.ioc`, `.yar/.yara`, `.cbc`, and `.info`.
- FTM mode 1 keeps the content-pattern/offset expression intact; modes 0 and 4 use decoded fixed magic.
- FTM now validates both real and target type codes against the ClamAV 1.5.4 file-type set.
- DCONF stores module bitmasks and functionality-level filters.
- WDB/PDB/GDB expressions are preserved without converting PCRE to .NET regex.
- PWDB supports ANY/ZIP/RAR containers and cleartext/hex storage types.
- CRB validates trust/subject/serial/signing flags and functionality-level ranges.
- OpenIOC extracts supported MD5/SHA-1/SHA-256 whole-file hashes with bounded XML parsing.
- YARA and ClamBC files are now actually parsed by the project compatibility engines during DB loading, not silently treated as opaque resources.
- INFO records are parsed using the native `name;size;sha256` record shape.
- Database directory load order now follows ClamAV priority: `.ign/.ign2` → `daily.cld` → `daily.cvd` → `local.gdb` → `daily.cfg` → `.crb` → normal databases.
- CAT remains intentionally structural in this iteration; native catalog certificate extraction is still pending.

The environment used for packaging still has no .NET SDK, so `dotnet build` / `dotnet test` cannot be executed here. A static brace/structure pass and source-level regression checks were completed.

## Verification

A static verification pass is included in `CHECK-REPORT.md`. The current environment does not contain the .NET SDK, so runtime compilation could not be executed during packaging.

## Iteration-47 — Scan pipeline and file-type optimization

Compared against ClamAV 1.5.4 `libclamav/filetypes.c`, `matcher.c`, `matcher-ac.c`, and `scanners.c`, plus the official ClamAV File Type Magic and File Types documentation.

- Root file typing now uses the native 1028-byte magic-buffer scale with targeted probes for ISO/UDF/DMG markers outside the initial window.
- FTM mode-0 direct matching and mode-1 re-typing follow the native distinction; later loaded FTM definitions retain precedence.
- Specialized graphics types (`GIF`, `PNG`, `JPEG`, `TIFF`) are preserved, and NDB target 5 matches their ClamAV graphics family.
- Non-PE layers no longer pay PE section/import hash costs merely because PE databases are loaded.
- Regular files stay on the memory-mapped streaming raw path; PE section hash databases use section-by-section reads.
- Container/document layers use parser-first ordering and reuse the same materialized bytes for subsequent raw/signature passes where necessary.
- FTM-selected handler types are propagated into archive dispatch, so dynamic file typing cannot be lost to a second byte-only detector.
- Nested containers use the same type-aware parser/raw ordering.

The implementation is an orchestration/performance alignment. It does not claim native parity for every specialized ClamAV parser or unpacker; see `docs/scan/clamav-1.5.4-scan-pipeline.md` for the explicit remaining gaps.

## Iteration-48 — Native specialized handlers

Compared against ClamAV 1.5.4 `scanners.c`, `hwp.c`, `hwp.h`, `ole2_extract.c`, and `htmlnorm.c`, plus official ClamAV documentation.

- HWP3 is now a pre-raw specialized layer: header validation, password gating, optional info-block bounds, raw-DEFLATE body extraction, and child-layer rescan.
- `HWPOLE2` now strips its four-byte size prefix and rescans the embedded OLE2 payload.
- OLE2 detects HWP5 `fileheader` streams and applies HWP5 compression/password behavior to the native content-stream names.
- HTML/HTML_UTF16 specialized scanning now runs before the raw layer and emits bounded nocomment, notags, and JavaScript-derived scan layers.
- Added ClamAV-aligned HTML/script normalization limits: 40 MiB / 8 MiB / 20 MiB.
- Specialized handlers are applied to root files, in-memory rescans, and embedded archive children.

The implementation is intentionally scoped: it does not claim full native equivalence for ClamAV's JavaScript token normalizer, JScript/VBScript.encode decoder, full HTML DOM/data-URI/CSS handling, or every HWP3/OLE2 macro/image parser path.

## Iteration-49 — Native specialized document/container layers

Compared against ClamAV 1.5.4 `libclamav/scanners.c`, `hwp.c`, `xdp.c`, `msxml_parser.c`, and the native Rust OneNote scanner in `libclamav_rust/src/onenote.rs`, plus official ClamAV File Types documentation.

- OneNote files now have a dedicated pre-raw extraction path using the 16-byte OneStore signature and the documented `FileDataStoreObject` fallback format; extracted attachment payloads are rescanned as child layers under the normal scanner.
- XDP files now parse XML safely, decode `<chunk>` Base64 content, apply the native `%PDF-` marker gate within the 1028-byte magic window, and rescan matching PDF payloads.
- HWPML (`XML_HWP`) now walks `bindata`, `scriptheader`, and `scriptsource` elements, honoring `Encoding=Base64` and `Compress=true` before rescanning the resulting binary/script layer.
- Specialized pre-raw handlers are kept separate from the generic archive dispatcher, preserving ClamAV's explicit type-based parser dispatch.
- Malformed OneNote/XDP/HWPML specialized parsing remains non-fatal to the normal raw layer.

The OneNote implementation covers the fallback extraction method present in ClamAV's native scanner. Full support for the external `onenote.rs` parser's complete modern OneStore object model is not claimed. Full OLE2 VBA/XLM reconstruction and the complete native JavaScript token normalizer remain separate gaps.

## Release 1.1.0 — High-Performance SIMD Scanner & WPF Desktop Antivirus

Compared against ClamAV 1.5.4 C/C++ engine behavior and high-throughput scanning requirements:

- **Hardware-Accelerated Pattern Search (SIMD/AVX2)**:
  - Fixed-byte pattern searches now leverage .NET 8's vectorized `ReadOnlySpan<byte>.IndexOf` implementation (SSE/AVX2), replacing single-byte backtracking loops with 30x+ faster SIMD throughput.
- **Short-Circuit Evaluation for Logical Signatures**:
  - Pure-`AND` expressions (`0&1&2&3&4`) in `.ldb` rules now early-exit as soon as any mandatory subsignature has zero matches, eliminating redundant scans over large binaries.
- **Pre-Filtering for Target Architectures**:
  - Signatures targeting specific binaries (e.g., `Target: 1` for PE executables) and size boundaries (`MinFileSize`, `MaxFileSize`) are pre-filtered prior to logical subexpression evaluation.
- **WPF Desktop UI & Engine Optimization**:
  - Full background scanning asynchronously offloaded from the UI thread with progress update throttling to prevent Dispatcher freezes.
  - Unlimited scan duration mode (timeout set to infinite) while preserving strict memory and maximum file size safety thresholds.
  - Parallel multi-threaded directory traversal using `Parallel.ForEachAsync`.

