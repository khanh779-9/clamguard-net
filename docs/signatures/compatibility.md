# Signature Compatibility Matrix

The matrix describes the current implementation status. "Supported" means the parser and matcher are implemented in the current codebase, not that every edge case from ClamAV is guaranteed identical.

| Family | Parser | Matcher | Status |
|---|---:|---:|---|
| HDB / HSB / HDU / HSU | Yes | Whole-file MD5/SHA-1/SHA-256 | Supported baseline |
| FP / SFP | Yes | Hash lookup | Supported baseline; trust semantics are simplified |
| NDB / NDU | Yes | Target-aware content matching + offsets + normalization | Extended supported |
| SDB | Yes | NDB-format self-protection signatures with raw pre-parser matching | Supported baseline |
| LDB / LDU | Yes | Boolean/count + target/context + modifiers/macros/PCRE/byte-compare/image subsigs | Extended supported; .NET PCRE compatibility path |
| DB | Yes | Content matching | Supported baseline |
| MDB / MSB / MDU / MSU | Parsed through hash family | PE section integration with MD5/SHA-1/SHA-256 | Extended supported; PE-specialized matching |
| IMP | Parsed through hash family | PE import-table MD5 integration for PE32/PE32+ | Extended supported |
| CVD / CLD / CUD | Header read / CVD extraction | N/A | CVD baseline |
| YARA | Yes (managed subset) | Yes | Supported extension; full language parity remains |
| CBC / bytecode | Yes (format 6/7 managed core) | Yes | Supported core interpreter; native hook/JIT parity remains |
| Archive/document core | Partial | ZIP/OOXML, GZIP, TAR, all parsed CPIO variants, OLE2, PDF-Flate/ASCIIHex/ASCII85/RunLength, optional BZip2/XZ/RAR/7-Zip | Extended supported; additional codecs and deeper document semantics remain |


## Flexible body patterns and LDB

Flexible body matching now covers exact bytes, nibble masks, byte wildcards, bounded and unbounded gaps, `(B)`, `(L)`, `(W)` character classes, fixed-length negated alternates, and variable-length generic alternates. Generic alternates reject ClamAV-incompatible unbounded gaps and ranged gaps of 128 bytes or more. The `w`, `a`, `i`, and `f` LDB modifiers are represented explicitly; wide variants also scale bounded gaps.

LDB parsing/evaluation now understands functionality ranges, target blocks, macro subsignatures, boolean/count expressions, PCRE triggers with ClamAV engine flags, byte-compare subsignatures (hex/decimal/auto/raw binary, endian selection, exact length and comparison operators), container/intermediate context, PE/ELF/Mach-O relative anchors, version-info anchors, icon groups/IDB matching, and fuzzy-image matching. NDB evaluation now covers target/FLEVEL filtering, validated absolute/floating/EOF/executable-relative offsets, macro-member semantics, and HTML/ASCII normalization. PE-specialized hash matching now covers PE32/PE32+ section hashes and import hashes; executable inspection includes ELF32/ELF64 and Mach-O 32/64-bit/FAT metadata with bounds checks.


ClamGuard indexes whole-file MD5/SHA-1/SHA-256 hashes by `(algorithm, file size)` and also keeps wildcard-size buckets, mirroring the size-specific and size-agnostic split used by ClamAV's hash matcher. Matching is performed against the raw digest bytes rather than linearly walking every signature in a bucket.

For fixed exact content rules, ClamGuard keeps an Aho-Corasick multi-pattern trie and preserves the automaton state across stream chunks. When there is exactly one long fixed rule, a Boyer-Moore-Horspool fast path is selected for contiguous-buffer scans; multi-signature scans continue to use the shared AC automaton. This is an optimization layer, not a claim of source-level implementation identity with ClamAV.


### PUA database load gating and categories
ClamAV 1.5.4 only loads `.hdu`, `.hsu`, `.mdu`, `.msu`, `.ndu`, and `.ldu` when PUA loading is enabled. ClamGuard mirrors this with `DatabaseLoader.IncludePua` and `DatabaseManager.LoadAndCompile(..., includePua: true)`.

ClamAV also supports `IncludePUA CATEGORY` and `ExcludePUA CATEGORY`. ClamGuard exposes the same load-time filtering with `DatabaseLoader.IncludePuaCategories` / `ExcludePuaCategories` (and the corresponding `DatabaseManager.LoadAndCompile` arguments). The category is the second token of a `PUA.*` signature name, such as `Win` in `PUA.Win.Packer.*`. Include and exclude category modes are mutually exclusive, matching ClamAV's configuration rules.
