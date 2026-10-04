# ClamAV 1.5.4 parity review — criteria 6 and 7

This document records the comparison against the **ClamAV 1.5.4 source tree** supplied for this parity pass.

## 6. PE / ELF / Mach-O

### Implemented in ClamGuard.NET
- PE32/PE32+ section hash databases: `.mdb`, `.msb`, `.mdu`, `.msu`
- PE32/PE32+ import hash (`.imp`)
- PE import-table fallback from an invalid `OriginalFirstThunk` to `FirstThunk`
- ClamAV-compatible first-dot DLL normalization for import hashes
- Import name validation compatible with the native `validate_impname` character set
- ELF32/ELF64 endian/class validation and bounded program/section tables
- Mach-O 32/64-bit segment/section parsing
- Mach-O raw section size derivation from alignment and zero-fill section type
- Mach-O `LC_MAIN` and supported `LC_UNIXTHREAD` entry-point mapping
- Universal/FAT Mach-O scanning across every valid architecture slice, with detection offsets rebased into the parent file

### Still different from native ClamAV
- The native PE path contains many packer/unpacker modules (UPX, FSG, Petite, Aspack, NSPack, WWPack, MEW, etc.); these are not ported.
- PE overlay bytes are now scanned as a nested layer, including archive payloads; ClamAV-specific iShield overlay parsing and Authenticode/certificate validation are still not reproduced.
- ClamAV has a substantially larger PE ordinal export-name table. Unknown ordinals in ClamGuard remain deterministic `ordNNN`.
- ELF bytecode unpacking is intentionally left for criterion 9 (Bytecode).

## 7. Archive / document

### Implemented / routed
- ZIP, OOXML, GZIP, BZip2, XZ, RAR, 7-Zip, ARJ, CAB, CHM, ISO, UDF, XAR, DMG, LHA
- POSIX TAR, old TAR
- CPIO NEWC/CRC/ODC/old binary
- OLE2
- PDF Flate, ASCIIHex, ASCII85, RunLength, and LZW stream decoding
- Symbian SIS type recognition
- EGG and ALZ type recognition
- SZDD / Microsoft Expand compatible decompression
- Nested scanning with archive depth, entry-count, expanded-byte, file-size, and compression-ratio limits
- Optional 7-Zip bridge for codecs that are not available in the .NET base class library
- BinHex data/resource fork extraction, UUEncode decoding, and TNEF attachment extraction
- SWF type recognition plus CWS (zlib-compressed) reconstruction and payload scanning
- Basic MIME MAIL/MHTML multipart extraction with Base64 and quoted-printable decoding
- ClamAV-style AutoIt and InstallShield type recognition; these formats are routed conservatively and do not claim native decrypt/decompress parity
- UDF signature-based type recognition and bounded external decoder routing
- PE SFX compatibility aliases for ZIP/RAR/ARJ/CAB/7Z/EGG content found in PE overlays

### Remaining native-ClamAV gaps
ClamAV 1.5.4's scanner dispatch also contains dedicated handlers for EGG, ALZ, SIS, NSIS/SZDD, AutoIt, InstallShield MSI, UDF, GPT/APM/partition formats, BinHex, UUEncode, RTF, TNEF, MHTML/mail internals, OneNote, HWP variants, and other specialized document types. ClamGuard now covers BinHex/UUEncode/TNEF extraction, CWS SWF reconstruction, PE-overlay/SFX traversal, and UDF/AutoIt/InstallShield type routing, but does not yet provide the same native parser/decryptor semantics for the remaining specialized formats.

PDF handling remains intentionally narrower than ClamAV's full object/xref pipeline: the managed scanner focuses on bounded embedded stream extraction. Object-stream discovery, embedded-file metadata, document encryption/decryption, and the full JavaScript/document semantic pipeline are not yet equivalent.

## Source locations used during this pass

- `libclamav/pe.c`
- `libclamav/elf.c`
- `libclamav/macho.c`
- `libclamav/scanners.c`
- `libclamav/pdf.c`
- `libclamav/pdfdecode.c`
- `libclamav/egg.c`
- `libclamav/sis.c`
- `libclamav/msexpand.c`
- `libclamav/nsis/nulsft.c`
- `libclammspack/`
- related file-type maps and test inputs under `unit_tests/`


## 8. YARA integration

`ClamGuard.Yara` is a separate project referenced by the scanner. The managed engine supports a bounded compatibility subset covering text/hex/regex string definitions, common modifiers, boolean/count conditions, and `filesize` comparisons. The scanner adapter is invoked for root content, PE overlays, Mach-O slices, and nested materialized archive/document children.

This is intentionally not described as full YARA parity: imports/includes, modules, externals, advanced condition expressions, and the complete hex-string grammar remain outside the managed engine.

## 9. ClamBC bytecode

`ClamGuard.Bytecode` is a separate project referenced by the scanner. The managed interpreter parses ClamBC format 6/7 metadata, API tables, globals, function headers, basic blocks, and the core opcode set from `clambc.h`. It implements bounded arithmetic, control flow, memory operations, selected file APIs, functionality/file-kind gating, and execution budgets for instructions, calls, and allocations.

The implementation deliberately does not claim native ClamAV bytecode ABI parity. Specialized PE/PDF hooks, unpacking/extraction, JIT behavior, and complex map/hashset/buffer-pipe APIs remain outside the managed core.
