# ClamGuard.NET

ClamGuard.NET is a managed malware-scanning engine and a Windows WPF desktop application written in C# on .NET 8. It loads ClamAV-style signature databases, matches files against supported signature formats, and scans supported archive and document layers under configured resource limits.

> **Compatibility note:** ClamGuard.NET is an independent managed implementation, not a drop-in replacement for ClamAV. Signature-format support and scanning behavior vary by feature. The regression harness covers implemented behavior, but it does not establish complete behavioral parity with the native ClamAV engine.

## Features

- Loads supported ClamAV database containers (`.cvd`, `.cld`, `.cud`) and signature database families.
- Parses and matches hash signatures, hexadecimal content patterns, NDB rules, logical LDB rules, metadata signatures, and selected specialized database formats.
- Uses a sparse Aho–Corasick matcher for fixed-byte patterns and a Boyer–Moore–Horspool fast path when a single suitable fixed pattern is present.
- Uses a logical-signature seed index that verifies the complete fixed anchor before scheduling an LDB rule for full evaluation, and evaluates only the macro groups needed by surviving logical candidates.
- Supports chunked scanning with matcher state preserved across read boundaries and incremental whole-file hashing.
- Includes target-aware file-type detection and dedicated handling for selected PE, archive, image, PDF/SWF, Office/OLE, mail, HTML, and document formats.
- Provides bounded archive expansion, parser depth, entry-count, decompression, and scan-size controls.
- Includes a database update component, a bounded scan host, and a Windows WPF user interface for scanning, updates, history, and quarantine workflows.
- Provides a regression harness for database loading, signature parsing, matchers, scan orchestration, and supported specialized handlers.

## Requirements

- .NET 8 SDK to build and run the regression harness.
- Windows for the WPF desktop application.
- Network access only when downloading or updating official database files.

The scanner uses [SharpCompress 0.50.4](https://github.com/adamhathcock/sharpcompress) for selected managed archive operations. Optional external decoders are only available when separately installed and discoverable through `PATH` and enabled by the relevant configuration.

## Build and test

Run these commands from the repository root:

```powershell
dotnet restore .\ClamGuard.Net.sln
dotnet build .\ClamGuard.Net.sln --configuration Release
dotnet run --project .\tests\ClamGuard.Tests\ClamGuard.Tests.csproj --configuration Release
```

The test project is an executable regression harness rather than a `dotnet test` test assembly. A successful run prints its success summary after all registered suites complete.

## `ScanOptions` behavior

`ScanOptions` is consumed by the scanner/host and by the folder-scanning service; its values are copied before execution so the host does not mutate a caller-owned options object. A typical library call is:

```csharp
var options = new ScanOptions
{
    DetectPUA = true,
    CollectAllMatches = true,
    ScanArchive = true,
    ScanPE = true,
    ScanELF = true,
    ScanOLE2 = true,
    ScanPDF = true,
    ScanSWF = true,
    ScanHWP3 = true,
    ScanXMLDocs = true,
    ScanOneNote = true,
    ScanImage = true,
    ScanImageFuzzyHash = true,
    ScanHTML = true,
    ScanMail = true,
    EnableHeuristics = true,
    HeuristicExceedsMax = true,
    HeuristicEncryptedArchive = false,
    HeuristicEncryptedDoc = false,
    MaxFileSize = 100 * 1024 * 1024,
    MaxScanSize = 250 * 1024 * 1024,
    MaxFiles = 10_000,
    MaxRecursion = 17,
    UseMultithreading = true,
    MaxThreads = Math.Max(1, Environment.ProcessorCount),
    Recursive = true,
    FollowSymlinks = false,
    ExcludeDirectories = ["cache", "node_modules"],
    ExcludeExtensions = [".tmp", ".bak"],
    InfectedOnly = false,
    ShowProgress = true,
    Verbose = false
};

var results = await antivirus.ScanFolderAsync(folderPath, options, progress, cancellationToken);
```

- `CollectAllMatches` controls whether all distinct alert names are returned or a single primary result is selected. Malware signatures take precedence over PUA and heuristic-only alerts.
- `DetectPUA` controls PUA visibility. The desktop service loads PUA databases so this can be selected per scan; PUA detections remain hidden when the option is `false`. Library callers loading the database directly must use `DatabaseManager.LoadAndCompile(..., includePua: true)` if they need PUA detection.
- The parser switches independently mirror all 13 `CL_SCAN_PARSE_*` bits in ClamAV 1.5.4: `ScanArchive`, `ScanELF`, `ScanPDF`, `ScanSWF`, `ScanHWP3`, `ScanXMLDocs`, `ScanMail`, `ScanOLE2`, `ScanHTML`, `ScanPE`, `ScanOneNote`, `ScanImage`, and `ScanImageFuzzyHash`. The managed dispatch follows native assignments for special types (for example, XDP is governed by `ScanPDF`; HWP3 by `ScanHWP3`; HWPOLE2 by `ScanOLE2`; legacy MS Office XML and HWP-ML document parsing by `ScanXMLDocs`; RTF and BinHex by `ScanArchive`). As in native ClamAV, scanning members inside OOXML containers is controlled by `ScanArchive`; `ScanXMLDocs` corresponds to the separate OOXML metadata-processing option, but the managed result model does not currently expose that native metadata-collection feature. UUENCODED decoding follows its native dynamic configuration rather than `ScanMail`. The managed implementation currently uses `ScanImage` and `ScanImageFuzzyHash` to gate the supported LDB fuzzy-image path; it does not claim to include every native image parser. Disabling a format parser does not disable the raw-byte signature pass. `ScanELF` controls supported executable metadata handling; it does not imply a full native-equivalent ELF parser.
- The implemented heuristic switches mirror the independent native options available in this managed scanner: `EnableHeuristics` (`CL_SCAN_GENERAL_HEURISTICS`), `HeuristicPrecedence` (`CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE`), `HeuristicExceedsMax` (`CL_SCAN_HEURISTIC_EXCEEDS_MAX`), `HeuristicEncryptedArchive` (`CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE`), and `HeuristicEncryptedDoc` (`CL_SCAN_HEURISTIC_ENCRYPTED_DOC`). The old `HeuristicScan` and `BlockEncrypted` members remain as compatibility aliases. `BlockEncrypted=true` enables both encrypted-content alerts; prefer the two individual settings for separate native-style control. Other libclamav heuristics (e.g., phishing cloak/SSL mismatch, macro alerts, partition inconsistency, structured-data DLP and broken-media checks) are not implemented by this managed engine and are intentionally not surfaced as no-op properties.
- The default public limits are aligned with ClamAV 1.5.x defaults for `MaxFileSize` (100 MiB), `MaxScanSize` (400 MiB), `MaxFiles` (10,000), and `MaxRecursion` (17). `MaxFileSize` and `MaxScanSize` use 64-bit byte counts; zero/negative public size values recover to the documented safe defaults, and `MaxFileSize` is capped at 2 GiB to avoid integer overflow at the native limit. `MaxFileSize`, `MaxScanSize`, `MaxFiles`, and `MaxRecursion` are merged with `Limits`: the more restrictive ceiling wins. `Limits` also controls full-buffer materialization, archive-entry/depth/expanded-byte budgets, decompression ratio and time, PDF/embedded stream sizes, HTML/script normalization, streaming chunk size and logical-match complexity. When a file is too large to materialize for a secondary parser, the raw signature pass continues and an incomplete-scan alert/error is returned instead of silently skipping raw scanning.
- Folder scanning applies `Recursive`, `FollowSymlinks`, `ExcludeDirectories`, `ExcludeExtensions`, `UseMultithreading`, `MaxThreads`, `ShowProgress`, `InfectedOnly`, and `Verbose`. If the directory contains more than `MaxFiles`, the first bounded set is scanned and an explicit limit result reports that additional files were skipped. Progress is emitted only when `ShowProgress` is enabled.
- `YaraRuleDirectory`, `BytecodeDirectory`, and custom `ContentScanners` attach their optional scanners to the scan pipeline. As elsewhere in this project, supported YARA/bytecode syntax and behavior depend on the managed implementations and are not a promise of full libclamav parity.

These controls make the options actionable, but they do **not** make ClamGuard.NET behavior identical to ClamAV native. Exact recognition parity has not been established here: it requires build/runtime tests and differential scans against the same native version, signature database, engine configuration, and clean/infected corpus. Unsupported formats and native parser/heuristic details can still produce different results.

## Run the desktop application

On Windows, with the .NET 8 SDK installed:

```powershell
dotnet run --project .\src\ClamGuard.Antivirus\ClamGuard.Antivirus.csproj --configuration Release
```

By default, the application stores its database and cache under the common application-data directory:

- Database: `%ProgramData%\ClamGuard\database`
- Extracted database cache: `%ProgramData%\ClamGuard\cache`
- YARA rules: `%ProgramData%\ClamGuard\yara`
- Bytecode files: `%ProgramData%\ClamGuard\bytecode`
- Per-user settings: `%LocalAppData%\ClamGuard\Antivirus\settings.json`

The database directory can be changed in application settings. Use valid database files from an authorized source. The small files under `samples/database/` are test fixtures, not a production malware database.

## Optional real-sample regression check

The harness can check a locally held `000.exe` against the exact `Win.Malware.Generic-9828792-0` LDB rule from an extracted ClamAV database. Keep the sample and database outside this repository; the project does not require malware samples to be committed.

```powershell
$env:CLAMGUARD_REAL_000_EXE = "C:\Samples\000.exe"
$env:CLAMGUARD_DAILY_LDB_PATH = "C:\ClamAV\daily.ldb"
dotnet run --project .\tests\ClamGuard.Tests\ClamGuard.Tests.csproj --configuration Release
```

This is an opt-in regression check, not a certification of full ClamAV parity. Do not execute unknown samples as part of testing; the scanner should inspect file content without launching the sample.

## Project layout

```text
ClamGuard.Net.sln
├── src/
│   ├── ClamGuard.Antivirus/       Windows WPF application, views, view models and services
│   ├── ClamGuard.Bytecode/        Bounded ClamBC parsing and managed runtime
│   │   ├── Models/                Bytecode data models
│   │   ├── Parsing/               Bytecode parser
│   │   ├── Runtime/               Engine, VM and host API
│   │   └── Scanning/              Scanner integration
│   ├── ClamGuard.Core/            Shared domain types and low-level utilities
│   ├── ClamGuard.Database/        Database loading, verification, storage and updates
│   │   ├── Loading/               Text/container loading and ignore rules
│   │   ├── Models/                Database load result/error models
│   │   ├── Storage/               Parsed database and runtime configuration
│   │   ├── Update/                CVD update and CDIFF patch support
│   │   └── Verification/          Container and signature verification
│   ├── ClamGuard.Scanner/         Scan pipeline and file/content handlers
│   │   ├── Archives/              Managed and guarded external archive decoding
│   │   ├── Containers/            Container/document traversal and extraction
│   │   ├── Content/Logical/       LDB evaluation and normalized scan layers
│   │   ├── Detection/             Magic-byte detection and scan-type policy
│   │   ├── Engine/                Scanner orchestration and pipeline stages
│   │   ├── Executable/            Executable metadata and version parsing
│   │   ├── Hosting/               Admission, concurrency, health and metrics
│   │   ├── Image/                 Icon/image decoding and fuzzy matching
│   │   ├── Pe/                    PE-specific matching and overlay scan
│   │   └── Specialized/             Type-specific scan handlers
│   ├── ClamGuard.Signatures/      Signature models, parsing, patterns and matchers
│   │   ├── Matching/              Fixed-pattern indexes and logical prefilter
│   │   ├── Models/                Strongly typed signature definitions
│   │   ├── Parsing/               Parsers grouped by signature family
│   │   └── Patterns/              Hex-pattern atoms and matching logic
│   └── ClamGuard.Yara/            Managed YARA-compatible subset
├── tests/ClamGuard.Tests/         Executable regression harness and fixtures
├── samples/                       Tiny non-production parser/matcher fixtures
├── scripts/                       Repository verification helpers
├── Directory.Build.props           Shared compiler and build settings
├── global.json                    .NET SDK selection
└── README.md
```

## Database loading and memory usage

ClamGuard.NET expands supported database containers to its configured cache or a temporary directory, parses supported entries into managed signature objects, and then builds in-memory matching indexes. The compressed size of a `.cvd` file is therefore **not** a reliable estimate of the resident memory needed by the scanner: parsed pattern atoms, signature models, hash buckets, matcher states, logical-signature indexes, and container-specific data add overhead.

The fixed-pattern matcher uses sparse transitions and shared integer-indexed edge/output tables rather than one `Dictionary<byte, int>` and one `List<int>` per automaton state. Exact-byte-only patterns are stored as byte arrays rather than one object per byte, and immutable exact-byte atoms are shared from a 256-value cache for patterns that need the polymorphic atom representation. Fixed-pattern checks use a direct byte comparison instead of allocating backtracking stacks and visited sets. The compiled matcher also separates fixed and flexible patterns, uses list-based pattern IDs, and avoids creating a temporary `ContentSignature` wrapper for every flexible NDB rule on every stream chunk. Original signature lines are retained only while `.ign`/`.ign2` rules are evaluated during loading, then cleared from retained signature objects; unused source-line copies are not kept in specialized metadata records. These choices reduce avoidable managed allocations; they do not eliminate the inherent memory cost of retaining parsed databases and their indexes.

ClamGuard.NET does not force a blocking, compacting full-generation garbage collection after loading. Such a pause is not a substitute for reducing retained data structures; the runtime collects temporary parsing objects according to normal GC policy. ClamAV's native engine and ClamGuard.NET use different implementations and data layouts, so their memory use should be measured rather than assumed equal. Also distinguish the two official scanning modes: `clamscan` creates an engine and loads the database for each invocation, while `clamdscan` is a client that submits work to a running `clamd` daemon whose engine and database stay resident. Compare process memory on equivalent workloads and include the daemon process when evaluating `clamdscan`.

Useful upstream references:

- [ClamAV scanning documentation](https://docs.clamav.net/manual/Usage/Scanning.html)
- [ClamAV 1.5.4 Aho–Corasick matcher source](https://fossies.org/linux/clamav/libclamav/matcher-ac.c)
- [ClamAV official source repository](https://github.com/Cisco-Talos/clamav)

No memory or throughput benchmark is claimed by this repository unless a benchmark result, test environment, database version, and measurement method are explicitly provided. For a meaningful comparison, record peak and steady-state working set/private bytes while loading the same database, then scan the same clean and matching samples using equivalent scan settings.

## Compatibility and safety boundaries

- The implementation targets the formats and scanner behaviors covered by its parsers and regression tests. It does not claim feature-for-feature parity with every native ClamAV signature, unpacker, YARA feature, ClamBC API, or specialized document parser.
- The YARA engine implements a managed compatibility subset; advanced modules/imports and language features outside that subset are not guaranteed.
- Native-only bytecode integrations, platform-specific JIT behavior, and decoders that are not available as safe managed components are not assumed to work.
- Archive recursion, expanded data, file counts, and specialized parsing are bounded. A scan can return an error or skip a specialized path when configured limits are exceeded.
- File-type recognition is a scanning hint, not proof that a file is valid or safe. Detection still depends on applicable signatures and supported scan logic.
- This project is not a kernel filesystem filter and is not a replacement for the operating system's built-in protection or a security review of a production deployment.

## License and third-party notices

ClamGuard.NET source code is distributed under the MIT License; see [`LICENSE`](LICENSE). ClamGuard.NET is an independently written managed implementation that uses public format documentation and observed behavior. It is not a wrapper intended to relicense or bypass the license of the ClamAV C/C++ source. Review the license and distribution terms of any database, signature set, decoder, or external tool you use.

### SharpCompress 0.50.4

ClamGuard.Scanner uses [SharpCompress](https://github.com/adamhathcock/sharpcompress) for selected archive operations.

License: MIT  
Copyright: (c) 2025 Adam Hathcock

```text
MIT License

Copyright (c) 2025 Adam Hathcock

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The upstream SharpCompress package also includes attribution/license notices for incorporated or derived components, including Bouncy Castle, managed-lzma, XZ.NET, and ZstdSharp. Consult the upstream package's current notices before redistributing binaries.
