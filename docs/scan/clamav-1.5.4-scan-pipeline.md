# ClamAV 1.5.4 scan-pipeline alignment

This document records the scan-order and file-type dispatch decisions implemented in Iteration 47 of ClamGuard.NET, using the ClamAV 1.5.4 C/C++ source as the behavioral reference.

## Native flow used as the reference

ClamAV's `cli_magic_scan()` first determines the file type, then runs callbacks/cache checks, performs self-protection raw matching when enabled, dispatches the type-specific parser(s), performs the ordinary raw scan (including embedded file-type recognition), and finally runs the remaining type-specific stages such as script, PE, ELF, Mach-O, PDF, and other unpack/normalization stages.

The primary file-type mechanism is FTM. Direct mode-0 rules compare bytes at a fixed offset. Mode-1 rules use the body/content matcher and may re-type a layer when the previously detected type (`rtype`) is eligible. FTM mode-4 is used for partition types.

Official references:

- https://docs.clamav.net/manual/Signatures/FileTypeMagic.html
- https://docs.clamav.net/appendix/FileTypes.html
- ClamAV 1.5.4 source: `libclamav/filetypes.c`, `libclamav/readdb.c`, `libclamav/matcher.c`, `libclamav/matcher-ac.c`, `libclamav/scanners.c`

## Iteration 47 decisions

### 1. Initial file-type probe is bounded

The initial root probe is capped at ClamAV's `MAGIC_BUFFER_SIZE` of 1028 bytes. Formats whose identifying marker is intentionally outside that window use targeted reads rather than a large generic prefix:

- ISO9660: sector-16 `CD001` marker at offset 32769
- UDF: targeted descriptor probe around offset 32768
- DMG: 512-byte trailer probe for `koly`

This keeps ordinary files on the small-probe path.

### 2. Direct FTM before generic fallback

ClamGuard evaluates loaded mode-0 FTM rules before generic MIME/extension heuristics. Mode-0 intentionally does not reject on `rtype`, matching the native fixed-type list behavior. The last loaded matching FTM rule has precedence because ClamAV prepends definitions during `cli_loadftm()`.

Mode-1 FTM rules are evaluated through the content matcher using the currently detected layer type as `rtype`.

### 3. File-type-specific target filtering

The scan planner does not run PE-specialized work on non-PE layers.

Examples:

- `.mdb/.msb/.mdu/.msu`: PE section-hash pass only for PE/MSEXE layers
- `.imp`: full PE image materialization only for PE/MSEXE layers
- Mach-O fat-slice parsing only for Mach-O layers
- archive extraction only for recognized/forced archive layers
- HTML/ASCII normalization only for their corresponding normalized target types
- graphics target `5` covers `GRAPHICS`, `GIF`, `PNG`, `JPEG`, and `TIFF`, matching the native target-family table

### 4. Regular raw scanning stays streaming

For non-container files, the compiled signature matcher scans through a memory-mapped stream. Aho-Corasick state is preserved across chunks, hashes are calculated incrementally only for algorithms that can actually match a loaded bucket, and PE section-hash databases are evaluated section-by-section.

This avoids a whole-file heap buffer for the common case where only raw signatures are applicable.

### 5. Containers use parser-first, then raw

For container/document types supported by ClamGuard's current archive layer, the root layer is materialized once and the same byte array is reused:

1. false-positive/trust check
2. type-specific archive/document expansion
3. ordinary raw signature matching
4. NDB materialized pass when required
5. logical/normalized passes
6. PE/Mach-O specialized passes when the active type permits them

This mirrors the important ordering in `cli_magic_scan()`: parsers first, raw pattern matching afterwards, while executables remain raw-first before their specialized unpack stage.

Nested archive layers use the same parser-before-raw ordering and carry the FTM-determined type into the handler dispatch instead of re-detecting the layer and potentially discarding a dynamic FTM re-type.

### 6. Parser failures do not automatically suppress raw scanning

Malformed/truncated container parsing errors that correspond to ordinary parse/format failures are treated as non-fatal by the archive bridge, so the caller can continue with raw matching. This follows `result_should_goto_done()` in ClamAV, where parse/format/max conditions are not all terminal scan errors.

### 7. Specialized FTM aliases are normalized only at the handler boundary

Examples:

- `OOXML_*` / XML document types -> ZIP extraction handler
- `MSOLE2` / `HWPOLE2` -> OLE2 handler
- `MSSZDD` -> SZDD handler
- `MSCAB` / `CABSFX` -> CAB handler
- `MSCHM` -> CHM handler
- `LHA_LZH` -> LHA handler
- `SWF` -> FLASH handler

The scan-layer file type is still preserved for signature targeting and reporting.

## What is deliberately not claimed as native parity

The project still does not provide a native C-equivalent implementation for every specialized ClamAV parser. The following remain separate compatibility tracks:

- HWP3 / HWPOLE2 / OneNote native parser semantics
- GPT/APM/MBR partition parsers and HFS+ partition scanning
- full GIF/PNG/JPEG/TIFF broken-media heuristics and native fuzzy-image pipeline
- full HTML/script normalization semantics
- PE packer/unpacker modules and complete Authenticode/catalog processing
- full ELF/Mach-O unpacker behavior
- native YARA/ClamBC runtime parity

The Iteration 47 changes are therefore an orchestration and performance alignment, not a claim that every native scanner/parser has been recreated.

## Verification status

The repository includes regression coverage for:

- mode-0 FTM type selection
- mode-1 FTM re-typing
- later-definition FTM precedence
- specialized PE hash gating
- specialized PNG file-type preservation
- graphics-family target matching

The current audit environment has no .NET SDK/compiler, so `dotnet build` and the executable regression harness cannot be run locally. Static source checks, project-graph checks already present in the repository, and the new regression fixtures were reviewed.

## Iteration 48 — Specialized document handlers

Compared against ClamAV 1.5.4 `libclamav/scanners.c`, `libclamav/hwp.c`, `libclamav/hwp.h`, `libclamav/ole2_extract.c`, `libclamav/htmlnorm.c`, and the official ClamAV File Types / Signatures documentation.

### HWP3

- Added a pre-raw HWP3 parser path.
- Validates the native 30-byte identity + 128-byte document info + 1008-byte document summary layout before reading the body.
- Password-protected documents skip native body parsing and remain available to the raw scan.
- Optional information-block length is bounds checked.
- Compressed HWP3 body is raw-DEFLATE decoded with a managed output bound and rescanned as a child layer.

### HWP embedded OLE2 / HWP5

- `HWPOLE2` strips the four-byte uncompressed-size prefix and rescans the remaining bytes as an OLE2 layer.
- OLE2 scans now recognize the `fileheader` stream containing `HWP Document File` as HWP5.
- HWP5 version/flags are read from the header.
- With the HWP5 compressed flag set, streams named `bin*`, `jscriptversion`, `defaultjscript`, `section`, `viewtext`, and `docinfo` are raw-DEFLATE decoded before scanning.
- With the password flag set, those streams are scanned as-is instead of being forcibly decompressed.

### HTML / HTML UTF-16

- Added a pre-raw HTML specialized path.
- Produces bounded normalized `nocomment` and `notags` forms.
- Extracted script contents are scanned as both HTML target-3 and ASCII target-7 layers, matching the native dual scan descriptors.
- HTML UTF-16 is decoded before entering the HTML normalizer.
- Limits follow ClamAV 1.5.4 defaults: `MaxHTMLNormalize=40 MiB`, `MaxHTMLNoTags=8 MiB`, `MaxScriptNormalize=20 MiB`.

### Native-parity boundaries

The managed handler intentionally does not claim full byte-for-byte equivalence for the native HTML/JavaScript normalizer or the full HWP parser. The remaining work includes JScript/VBScript.encode decoding, JavaScript token normalization/eval reparsing, HTML `data:` extraction/CSS image handling, and full HWP3 paragraph/special-object reconstruction.

## Iteration 49 — OneNote / XDP / HWPML specialized layers

ClamAV 1.5.4 has explicit scanner dispatches for OneNote, XDP, and HWPML rather than routing those files through the generic archive parser. The managed implementation now mirrors those dispatch boundaries.

### OneNote

The native Rust scanner first attempts the `onenote.rs` parser. Its fallback verifies the OneStore 16-byte magic and walks `FileDataStoreObject` records; each recovered payload is passed back to the normal magic scanner. The managed path implements that fallback, with an output-size bound.

### XDP

`xdp.c` parses XML `<chunk>` elements, Base64-decodes the content, searches the first `MAGIC_BUFFER_SIZE` bytes for a case-insensitive `%PDF-` marker, and only then hands the decoded payload back to the normal scanner. The managed path preserves the 1028-byte marker window and non-fatal parse behavior.

### HWPML

`hwp.c` reuses the MSXML callback machinery for `bindata`, `scriptheader`, and `scriptsource`. Callback attributes control Base64 decoding and optional zlib decompression before rescanning. The managed implementation preserves those three callback element names, the two supported transformations, output bounds, and child-layer scan model.

These handlers are not included in the generic `ArchiveContainer` classification, because ClamAV's native dispatcher treats them as document-specialized layers and then continues with the ordinary raw layer.
