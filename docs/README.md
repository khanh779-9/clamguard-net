# Documentation — ClamGuard.NET

This folder contains the project's **analysis and specification documents**. All documents are
written in English, using Markdown (CommonMark + GFM), and live directly in this folder.

## Document index

### Format specification

| Document | Content |
|----------|---------|
| [`daily_CVD_Signature_Format_Analysis.md`](./daily_CVD_Signature_Format_Analysis.md) | Specification of the `daily.cvd` format: the CVD container, its 23 database files, the syntax of every signature family (hash, NDB, LDB, CDB, IDB, CRB, FTM, phishing, DCONF...), pitfalls found in real data, C# implementation guidance and a test plan. Merged from two independent analyses and cross-checked against the ClamAV 1.5.4 sources. |

### Per-project architecture

| Document | Project | Content |
|----------|---------|---------|
| [`project-ClamGuard.Core.md`](./project-ClamGuard.Core.md) | `ClamGuard.Core` | Shared foundation: hex codec, domain models (ScanOptions/ScanLimits/Detection/ScanResult), PUA/heuristic filtering policy, scan limits. |
| [`project-ClamGuard.Signatures.md`](./project-ClamGuard.Signatures.md) | `ClamGuard.Signatures` | ClamAV signature parsing (.hdb/.ndb/.ldb/.cdb/.idb/...) plus the matching engine: Aho-Corasick, BMH, hex patterns, logical prefilter, streaming compiled set. |
| [`project-ClamGuard.Scanner.md`](./project-ClamGuard.Scanner.md) | `ClamGuard.Scanner` | The scan pipeline: file-type detection, archives/containers, PE, image fuzzy hashing, logical runtime, ScanHost hosting. |
| [`project-ClamGuard.Database.md`](./project-ClamGuard.Database.md) | `ClamGuard.Database` | CVD/CLD loading, special databases, ignore lists, DCONF, signature verification (RSA-PSS/CMS), CDIFF updates. |
| [`project-ClamGuard.Bytecode.md`](./project-ClamGuard.Bytecode.md) | `ClamGuard.Bytecode` | The ClamAV bytecode (.cbc) virtual machine: format parser, VM with fuel/depth/runtime caps, API layer. |
| [`project-ClamGuard.Yara.md`](./project-ClamGuard.Yara.md) | `ClamGuard.Yara` | YARA subset emulator (basic strings + conditions) with explicit warnings for unsupported constructs. |
| [`project-ClamGuard.Antivirus.md`](./project-ClamGuard.Antivirus.md) | `ClamGuard.Antivirus` | The WPF application: MVVM, services (engine, realtime, quarantine, memory scan, settings), i18n, theming, toolkit. |

## External references

- [`README.md`](../README.md) — project overview, features, build and test instructions.
- ClamAV 1.5.4 sources used for cross-checking: local installation (if available) or the
  [github.com/Cisco-Talos/clamav](https://github.com/Cisco-Talos/clamav) repository at the matching tag.

## Documentation conventions

Applies to every `.md` file added to this folder:

1. **Language**: English; keep technical terms (class names, formats, CLI flags) as-is.
2. **Structure**: exactly one `#` title per file; add a table of contents when the file is
   longer than ~200 lines; number sections with `##`.
3. **Provenance labels** when a document reports measured or derived facts:

   | Label | Meaning |
   |-------|---------|
   | `[measured]` | Counted directly on a specific object (state the build/source) |
   | `[docs]` | Semantics taken from official project/library documentation |
   | `[source]` | Verified directly in source code (ClamAV or this repository) |
   | `[ClamGuard]` | Implemented in this repository — points to the file/class |

4. **Code blocks** always declare a language: ```text for sample records, ```csharp for C#,
   ```bash for shell. Never leave a real code sample in a bare fenced block.
5. **Tables**: GFM tables; right-align numeric columns; state units in the column header.
6. **Links**: relative links between documents in this folder; absolute links for external docs.
7. **File names**: `snake_case.md`, descriptive, prefixed `project-` for architecture documents,
   no spaces.
8. **Updates**: when a document is superseded by a merged/newer version, record the state
   (Current / Archived) in the index above; delete superseded files instead of keeping duplicates.

## Quick contribution checklist

```bash
# Build and run the full test suite before committing docs that accompany code
dotnet build ClamGuard.Net.sln -c Debug
dotnet run --project tests/ClamGuard.Tests -c Debug --no-build
```
