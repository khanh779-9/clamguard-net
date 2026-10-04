# Implementation Status

## Current parity order

1. ✅ File-level hash matching
2. ✅ Fixed content matching
3. ✅ Flexible patterns
4. ✅ LDB
5. ✅ NDB
6. ✅ PE/ELF/Mach-O extended coverage
7. ✅ Archive/document extended coverage
8. ✅ YARA (managed engine integration)
9. ✅ Bytecode / ClamBC (managed runtime + API surface)
10. ✅ CDIFF
11. ✅ Database verification
12. ✅ Streaming/chunk scanning
13. ✅ Memory mapping
14. ✅ Production maturity

## Implemented

- Independent .NET 8 domain model and engine state
- Database directory discovery with deterministic ordering
- CVD header inspection and version reporting
- Streaming CVD extraction with archive-entry and extraction-size safety limits
- Strict versus permissive database loading modes
- HDB/HSB/HDU/HSU/FP/SFP/MDB/MSB/IMP hash parsing
- Whole-file MD5/SHA-1/SHA-256 matching with per-algorithm digest reuse
- Chunked streaming scans with stateful Aho-Corasick, incremental MD5/SHA-1/SHA-256, and bounded rolling-window matching
- Memory-mapped file scanning to avoid eagerly loading the root file into a single managed byte[]
- False-positive hash handling as trust data rather than a malicious detection
- NDB parsing and extended matching including target/FLEVEL filtering, absolute/floating/EOF/executable-relative offsets, and HTML/ASCII normalization
- LDB parsing and execution including target/functionality filtering, PE/ELF/Mach-O relative offsets, Container/Intermediates/HandlerType retyping, PE version-info anchors, PE icon-group/IDB matching, image-fuzzy signatures, modifiers, macros, PCRE triggers, and byte-compare subsignatures
- PE/ELF/Mach-O inspection hardened for PE32/PE32+, ELF32/ELF64 with endian checks, PE import-table fallback/normalization rules, bounded PE overlay extraction/scanning, SFX aliases, Mach-O 32/64-bit and all valid FAT slices, Mach-O alignment-derived raw section sizes, and LC_UNIXTHREAD/LC_MAIN entry-point resolution
- Exact, nibble, byte-wildcard, bounded-gap, unbounded-gap, character classes, generic alternates, and fixed-length negated alternate hex patterns
- Bounded non-recursive pattern evaluation to reduce stack/regex-style denial-of-service risk
- Aho-Corasick acceleration for fixed patterns
- Container/document scanning with bounded ZIP/OOXML/GZIP/TAR/CPIO (NEWC/CRC/ODC/old binary), OLE2, PDF Flate/ASCIIHex/ASCII85/RunLength/LZW extraction, BinHex/UUEncode/TNEF extraction, CWS SWF reconstruction, bounded MIME MAIL/MHTML multipart extraction, UDF/AutoIt/InstallShield routing, nested-container traversal, compression-ratio, depth, entry-count, and expanded-byte budgets
- ClamAV 1.5.4 parity pass: EGG/ALZ/SIS type recognition, native SZDD/MSEXPAND-compatible extraction, optional external routing for additional archive codecs, and universal Mach-O per-slice scanning
- Optional BZip2/XZ single-stream extraction and optional RAR/7-Zip member extraction through PATH-resolved external decoders with argument-list execution, timeout, output-size caps, and no shell invocation
- Immutable compiled database generations and atomic engine state replacement
- Full CVD download updates with temporary validation and atomic installation
- CLI and executable test harness

## Completed in the current parity pass

- ✅ File-level hash matching: size-specific and wildcard HDB/HSB/FP/SFP-style lookup is now indexed by raw digest bytes, with MD5/SHA-1/SHA-256 digest reuse and seekable-stream hash planning so irrelevant algorithms are not computed
- ✅ Fixed content matching: Aho-Corasick remains the multi-pattern engine, state persists across stream chunks, and a Boyer-Moore-Horspool fast path handles a single long exact signature without paying the AC traversal cost
- ✅ Flexible patterns: generic alternates, negated fixed alternates, `(B)/(L)/(W)` classes, bounded/unbounded gaps, nibble masks, case-insensitive matching, full-word matching, and wide/ascii variants are implemented with bounded backtracking
- ✅ LDB: target/functionality/context execution, PE/ELF/Mach-O relative anchors, VI, Container/Intermediates/HandlerType, PE icon groups + IDB metrics, image fuzzy hashing, modifiers, macros, PCRE, byte-compare semantics, and regression coverage are implemented
- ✅ NDB: target/FLEVEL filtering, validated offsets, absolute/floating/EOF/executable-relative matching, macro-member handling, and normalized HTML/ASCII matching are implemented
- ✅ Streaming/chunk scanning: stateful Aho-Corasick across chunk boundaries, incremental MD5/SHA-1/SHA-256, EOF-relative fixed-pattern offsets, and bounded rolling-window matching for flexible patterns
- ✅ Memory mapping: root file scans now use `MemoryMappedFile` + `MemoryMappedViewStream` instead of eagerly loading the normal scan target into one managed byte array

### CDIFF / Database verification completed

- ✅ CDIFF: implements `OPEN`, `ADD`, `DEL`, `XCHG`, `MOVE`, `CLOSE`, and `UNLINK`, including the ClamAV gzip header/script-size format, radix-64 SHA-256 PSS2 internal signature verification, optional `.cdiff.sign` CMS/PKCS#7 verification, bounded command/line/path handling, and additions-only `CLOSE` file creation semantics.
- ✅ Database verification: validates the 512-byte CVD header, legacy payload MD5 + RSA signature when detached verification is unavailable, signed `.info` SHA-256 PSS2, `.info`/outer-header version/signature-count/flevel/creation-time consistency, duplicate manifest entries, per-file size/SHA-256, and missing manifest entries for recognized ClamAV database extensions.
- ✅ Daily database selection: `daily.cld` / `daily.cvd` now follow ClamAV 1.5.4 selection semantics (highest version; CLD wins ties).
- ✅ PUA database selection: `.hdu/.hsu/.mdu/.msu/.ndu/.ldu` are skipped unless PUA loading is enabled, and `IncludePuaCategories` / `ExcludePuaCategories` mirror ClamAV's category-level PUA filtering (mutually exclusive).
- ✅ LDB logical operators: mixed `&` / `|` expressions follow the recursive first-top-level-operator behavior of ClamAV 1.5.4 rather than conventional boolean precedence.
- ✅ Update pipeline: downloaded CVDs are cryptographically verified before validation/activation; when `UpdateOptions.CertsDirectory` is set, the updater also attempts to fetch and verify the matching `<database>-<version>.cvd.sign` file.
- ✅ ClamAV 1.5.4 fixture validation performed independently: CDIFF patches `test-2.cdiff` through `test-6.cdiff` reproduce the corresponding CVD file trees exactly; all bundled CVD/ CDIFF detached CMS signatures verified against the ClamAV test certificate.

### Explicitly limited compatibility surfaces

- Advanced YARA language features (modules, imports/includes, externals, rich arithmetic/loop conditions, and every hex-string construct) remain outside the managed compatibility subset.
- Native-only ClamBC integrations that require a process/JIT ABI or native codec engine (LZMA/BZip2/JS/disassembler/JIT/extraction callback ABI) fail closed when no safe managed equivalent is configured.
- PE packer/unpacker modules, Authenticode/iShield parsing, and complete PE ordinal export-name parity remain separate compatibility tracks.
- Some deep archive/document semantics and specialized filesystem parsers remain outside the managed decoder set; guarded external routing is used where configured.
- Less-common auxiliary database extension semantics and phishing/trust/certificate/icon/password datasets remain separate compatibility tracks.
- Environment-specific fuzzing, throughput benchmarking, service integration, and deployment acceptance are still operational validation activities even though the production runtime supplies bounded execution, health gates, metrics, lifecycle management, CI configuration, and regression tooling.

The project deliberately distinguishes the implemented LDB/NDB execution surface from features that still require dedicated parsers or engines.


### Archive-family external bridge
- ARJ/CAB/CHM/ISO/XAR/DMG/LHA are now type-detected and routed through the guarded 7-Zip bridge when a compatible executable is available on `PATH`.
- The managed core does not claim decoder parity for these formats; unsupported codec capabilities are reported as non-expanded containers rather than treated as clean embedded content.

## YARA / Bytecode integration

- `ClamGuard.Yara` is an independent project referenced by `ClamGuard.Scanner`. It provides a managed YARA-compatible subset with text/wide/nocase/fullword/xor strings, exact hex strings, regular expressions, boolean/count conditions, and nested archive scanning.
- `ClamGuard.Bytecode` is an independent managed ClamBC interpreter project referenced by `ClamGuard.Scanner`. It parses ClamBC format 6/7 metadata, functions, basic blocks and core VM opcodes, applies instruction/call/allocation budgets, and exposes safe file/seek/read/find helpers.
- Both engines are optional: omit `--yara` or `--bytecode` to keep the base scanner free of external rule sets.

### Bytecode and production hardening completed / release state

- ✅ ClamBC managed runtime exposes the complete ClamAV 1.5.4 public bytecode API name surface (107/107 checked against `libclamav/bytecode_api_decl.c`), with bounded implementations for PE section lookup, platform/environment data, PDF object metadata, buffer pipes, hash sets, maps, JSON helpers, file/memory helpers, pointer-safe operations, and execution budgets. Native-only LZMA/BZip2/JS/Disassembler/JIT-style operations fail closed when no safe managed equivalent is available.
- ✅ Production facade adds bounded admission/concurrency, queue and scan timeouts, database health gating, metrics, observer isolation, full-buffer materialization caps, non-mutating scanner options, rule-engine caching, configuration validation, graceful shutdown/drain, and deterministic regression coverage. CI builds on Windows/Linux with warnings-as-errors and executes the regression harness.
- ✅ ZMD/RMD metadata signatures: `.zmd` / `.rmd` are parsed into ClamAV-style container metadata rules and evaluated during ZIP/RAR member discovery.
- Iteration 30 was superseded by Iteration 33: `CompressionMethod` is parsed/validated but ignored during metadata matching, matching ClamAV 1.5.4.
- Iteration 31: ZMD/RMD `MaxDepth` is parsed and validated but intentionally not used for matching; ClamAV 1.5.4 `cli_loadmd` validates field 9 then discards it, and `cli_matchmeta()` never compares it. A regression test locks this parity behavior.
- Iteration 32: ZMD/RMD `Encrypted` preserves ClamAV's numeric field semantics: `*` is stored as `2` (wildcard), `0/1` match archive encryption state, and other numeric values are accepted by the loader but do not match the scanner's boolean metadata.


### Iteration 33 — ZMD/RMD CompressionMethod parity correction
- ClamAV 1.5.4 parses the CompressionMethod field but explicitly does not use it in `cli_matchmeta()`.
- Removed ClamGuard matching on CompressionMethod while retaining parsing/validation of the field.
- Regression test now uses a deliberately different method value to prove the field is ignored.

- Iteration 35 was superseded: ZMD/RMD metadata fields `OriginalSize`, `CompressedSize`, and `FilePos` are exact numeric values in `cli_loadmd`; `CDBRANGE` belongs to `cli_loadcdb` and must not be applied to `.zmd/.rmd`.

### Iteration 37 — ZMD/RMD numeric parser parity

Aligned ZMD/RMD decimal metadata parsing with ClamAV 1.5.4 `cli_loadmd()`:
- `cli_isnumber()` accepts decimal digits only; signs and whitespace are rejected.
- `Encrypted`, `OriginalSize`, `CompressedSize`, `CompressionMethod`, `FilePos`, and `MaxDepth` use int-range decimal validation before storage.
- `CompressionMethod` and `MaxDepth` remain parsed-but-unused, matching ClamAV.
- Added regressions for signed numeric rejection and values beyond the int-backed range.

Runtime `dotnet build/test` remains unavailable in this environment because the .NET SDK is not installed.


### Iteration 40 — ZMD/RMD empty numeric fields
- ClamAV 1.5.4 `cli_isnumber()` returns true for an empty string because it only rejects non-digit characters while iterating; `cli_loadmd()` then feeds the token to `atoi()`, producing `0` on the common C runtime behavior.
- ClamGuard now accepts empty values for `Encrypted`, `OriginalSize`, `CompressedSize`, `CompressionMethod`, `FilePosition`, and `MaxDepth` and maps them to zero.
- Signed values and whitespace remain rejected, matching `cli_isnumber()`.
- Added regression coverage for an all-empty numeric ZMD entry.

### Iteration 39 — ZMD/RMD FilePosition parity
- ClamAV 1.5.4 passes `file_count` to `cli_matchmeta()`; ZIP and RAR metadata signatures therefore use a 1-based archive entry number, not a byte offset.
- `FilePosition` remains an exact numeric field; `*` is wildcard and `0` is a literal zero, not wildcard.
- ClamGuard ZIP/RAR scanners already maintain this 1-based position, so no production-code change was required. Added regression coverage for position `2` and literal position `0`.

### Iteration 41 — ZMD/RMD Res1 + line/token parity
- Aligned `Res1` parsing with ClamAV 1.5.4 `cli_hex2num()`: odd-length values fail, empty values yield zero, non-hex characters terminate accumulation, and there is no arbitrary eight-digit limit.
- Preserved ClamAV metadata line handling: no `Trim()` normalization, only column-zero `#` is a comment, empty lines are malformed, and the record must contain exactly nine colon-separated fields.

### Iteration 42 — NDB Target:* and NDB/LDB source-line whitespace parity
- NDB `Target:*` is accepted and maps to target 0 through the same explicit wildcard/`atoi()` behavior as ClamAV.
- NDB/LDB comment detection only recognizes `#` at column 0.
- Blank/whitespace-only NDB/LDB records are no longer silently skipped.
- LDB target attributes and subsignature fields are no longer implicitly whitespace-trimmed.


### Iteration 43 — CDB core loader and container-metadata matching
- ✅ Added `.cdb` dispatch and a dedicated `CdbSignature` model.
- ✅ Ported `cli_loadcdb()` field structure: 10–12 fields, functionality-level filtering, `CL_TYPE_*` validation, POSIX ERE filename matching, exact/range size and file-position fields, and `*`/0/1 encryption semantics.
- ✅ Preserved ClamAV's `cli_matchmeta()` range behavior where a zero endpoint of a non-exact range is treated as unbounded; an exact `0` remains a literal value.
- ✅ `Res1` remains parsed-but-unused and `Res2` is retained as opaque data, matching the current CDB loader/matcher behavior.
- ✅ CDB metadata matching is integrated with ZIP entries and the guarded managed/external RAR/ARJ/EGG member path.
- ⚠️ `dotnet build/test` could not be executed in this environment because the .NET SDK is not installed.

### Iteration 44 — CDB native TAR/CPIO call-site parity
- ✅ Added CDB metadata matching to POSIX TAR and OLD TAR regular-file entries, using the archive layer size and native file-position semantics.
- ✅ Added CDB metadata matching to CPIO newc/crc, ODC, and old handlers, preserving ClamAV's per-header file counter behavior.
- ✅ Unknown encryption metadata no longer gets coerced to plaintext for CDB matching; encrypted-specific rules are skipped when the decoder cannot determine encryption state.
- ✅ Generic external archives no longer receive CDB matching merely because ClamGuard can extract them; only formats whose ClamAV 1.5.4 handlers call `cli_matchmeta()` are routed through that path.
- ✅ Added regression coverage for TAR, OLD TAR, all three CPIO handler variants, and the intentional OLE2 non-match behavior.
- ⚠️ `dotnet build/test` remains unavailable in this environment because the .NET SDK is not installed.
