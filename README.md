# ClamGuard.NET

ClamGuard.NET is a managed malware-scanning engine and a Windows WPF desktop application written in C# on .NET 8. It loads ClamAV-style signature databases, matches files against supported signature formats, and scans supported archive and document layers under configured resource limits.

> **Compatibility note:** ClamGuard.NET is an independent managed implementation, not a drop-in replacement for ClamAV. Signature-format support and scanning behavior vary by feature. The regression harness covers implemented behavior, but it does not establish complete behavioral parity with the native ClamAV engine.

## Features

- Loads supported ClamAV database containers (`.cvd`, `.cld`, `.cud`) and signature database families.
- Parses and matches hash signatures, hexadecimal content patterns, NDB rules, logical LDB rules, metadata signatures, and selected specialized database formats.
- Uses a sparse Aho–Corasick matcher for fixed-byte patterns and a Boyer–Moore–Horspool fast path when a single suitable fixed pattern is present.
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
