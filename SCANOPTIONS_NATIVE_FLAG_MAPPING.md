# ScanOptions: ClamAV 1.5.4 native flag split

This change aligns managed parser options with `libclamav/clamav.h` from the supplied ClamAV 1.5.4 source tree. It does not claim that ClamGuard.NET's parser implementations are feature-equivalent to libclamav.

## Parser options (`CL_SCAN_PARSE_*`)

| Native flag | `ScanOptions` property | Managed effect |
|---|---|---|
| `CL_SCAN_PARSE_ARCHIVE` | `ScanArchive` | Gates generic archive/container traversal (ZIP, GZIP, RAR, 7z, TAR, and other supported archive handlers). |
| `CL_SCAN_PARSE_ELF` | `ScanELF` | Gates supported ELF-specific metadata/target handling. Full native ELF parser parity is not implemented. |
| `CL_SCAN_PARSE_PDF` | `ScanPDF` | Gates PDF embedded-stream inspection and PDF-specific encrypted-document alerting. |
| `CL_SCAN_PARSE_SWF` | `ScanSWF` | Gates SWF/Flash expansion and recursive child scanning. |
| `CL_SCAN_PARSE_HWP3` | `ScanHWP3` | Gates HWP3-specific document traversal. |
| `CL_SCAN_PARSE_XMLDOCS` | `ScanXMLDocs` | Gates supported legacy MS Office XML (`XML_WORD`/`XML_XL`) embedded `binData` scanning and HWP-ML handling. In native ClamAV, OOXML-specific metadata processing uses this flag, but actual OOXML ZIP member extraction is independently controlled by `CL_SCAN_PARSE_ARCHIVE`; this managed engine has no metadata-collection result contract. |
| `CL_SCAN_PARSE_MAIL` | `ScanMail` | Gates MIME/TNEF/MHTML and supported mail/attachment extraction. |
| `CL_SCAN_PARSE_OLE2` | `ScanOLE2` | Gates OLE2/MSOLE2/HWPOLE2 and supported OLE-based document traversal. |
| `CL_SCAN_PARSE_HTML` | `ScanHTML` | Gates HTML normalization and specialized HTML scanning. |
| `CL_SCAN_PARSE_PE` | `ScanPE` | Gates PE-specific structure, import/section, and overlay logic while preserving raw signatures. |
| `CL_SCAN_PARSE_ONENOTE` | `ScanOneNote` | Gates OneNote attachment traversal. |
| `CL_SCAN_PARSE_IMAGE` | `ScanImage` | Acts as an explicit prerequisite for managed image fuzzy matching; other native image parsers are not implemented. |
| `CL_SCAN_PARSE_IMAGE_FUZZY_HASH` | `ScanImageFuzzyHash` | Independently enables/disables the LDB fuzzy-image-hash matcher. It is effective only when `ScanImage` is enabled. |

Additional native type routing: `XDP` uses `ScanPDF`; `RTF` and `BINHEX` use `ScanArchive`; UUENCODED decoding is controlled by native `DCONF_OTHER/OTHER_CONF_UUENC`, not by `CL_SCAN_PARSE_MAIL`. These assignments were confirmed against the `cli_magic_scan` dispatch in `libclamav/scanners.c`, not inferred only from extensions or MIME labels. OOXML member extraction requires `ScanArchive`, while `ScanXMLDocs` is a separate optional native OOXML metadata path.

The flags are passed through both `ScannerEngine`'s effective options and `ScanHost`'s per-scan copy. `ScanTypePolicy` selects the independent parser switch for each recognized type. The raw matching pass remains enabled when a parser flag is false.

## Implemented general/heuristic options

| Native flag | `ScanOptions` property | Managed effect |
|---|---|---|
| `CL_SCAN_GENERAL_ALLMATCHES` | `CollectAllMatches` | Returns all distinct detection names. |
| `CL_SCAN_GENERAL_HEURISTICS` | `EnableHeuristics` | Filters heuristic-only detections globally. |
| `CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE` | `HeuristicPrecedence` | Lets an enabled heuristic result win the single-result decision and stop early. |
| `CL_SCAN_HEURISTIC_EXCEEDS_MAX` | `HeuristicExceedsMax` | Controls heuristic alerts for file/buffer/archive/directory scan limits. |
| `CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE` | `HeuristicEncryptedArchive` | Controls encrypted archive member alerts when encryption metadata is available. |
| `CL_SCAN_HEURISTIC_ENCRYPTED_DOC` | `HeuristicEncryptedDoc` | Controls the existing PDF `/Encrypt` alert. |

Compatibility aliases remain: `HeuristicScan` maps to `EnableHeuristics`; `BlockEncrypted` maps to both encrypted-content flags. Prefer the individual flags for new code.

## Intentionally not represented as functional flags

The managed engine does not yet implement the following ClamAV 1.5.4 heuristic scanners, so the public model does not expose misleading switches for them: broken PE/ELF alerts, phishing SSL mismatch, phishing URL cloaking, macro alerts, partition-table inconsistency, structured-data/SSN/credit-card DLP, and broken-media detection. Similarly, native general metadata collection, HTML/PDF URI storage, extra-hash storage, unprivileged scan mode and development timing/hash flags are not represented as native-compatible features because the managed scan result/pipeline does not implement their contracts.

## Verification status

- Static source check: all 13 parse constants from the supplied `clamav-1.5.4/libclamav/clamav.h` have a distinct managed property.
- Regression coverage added for the new defaults, compatibility aliases, disabling heuristic alerts, heuristic precedence, and native-style separation between OOXML ZIP extraction (`ScanArchive`) and XML-document parser gating. The managed MS Office XML handler scans decoded `binData` payloads; it is a safe functional subset, not a complete port of `msxml.c` metadata handling.
- Runtime build/tests were not executed in this environment because no .NET SDK/compiler is installed. The actual differential recognition parity with native ClamAV remains unverified.
