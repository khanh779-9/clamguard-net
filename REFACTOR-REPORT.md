# ClamGuard.NET — Refactor report

Date: 2026-10-09

## Summary

This refactor organizes the database/update, scanner, signature-parser, bytecode, desktop UI, and regression-test code into responsibility-focused files. The goal is to make navigation and future maintenance easier without deliberately changing production behavior.

### Project boundaries

- Removed the standalone `ClamGuard.Cli` project and its solution entry.
- Merged the former `ClamGuard.Update` implementation under `ClamGuard.Database/Update/` (`DatabaseUpdater` and `CdiffPatchApplier`). The thin `UpdateService` wrapper and the single-implementation `IIncrementalPatchApplier` abstraction were removed.
- Removed the `ClamGuard.Production` project without dropping its active scan-host feature: host/lifecycle functionality now lives in `ClamGuard.Scanner/Hosting/`, with options, health, metrics, and observer contracts split into focused files.
- Updated solution references, call sites, regression-harness naming, and architecture/update docs to reflect the new boundaries.

### `ClamGuard.Scanner`

- Split scanning responsibilities into `Engine/`, `Archives/`, `Containers/`, `Content/Logical/`, `Detection/`, `Executable/`, `Image/`, `Models/`, `Pe/`, `Specialized/`, and `Hosting/`.
- Split large partial implementations such as `ScannerEngine`, `ArchiveScanner`, `PeSpecializedMatcher`, and `SpecializedFileHandlers` into responsibility-focused files.
- Separated PNG, BMP, and GIF fallback decoders and the `RgbImage` model into individual files.
- Kept a public entrypoint/orchestration file instead of leaving every scanning algorithm in one giant class file.

### `ClamGuard.Signatures`

- Grouped parsers by format family: `Parsing/Hash/`, `Parsing/Content/Ndb/`, `Parsing/Content/Ldb/`, `Parsing/Container/`, `Parsing/Metadata/`, and shared helpers in `Parsing/Common/`.
- Separated signature models and pattern-atom variants into focused files instead of defining many unrelated types together.
- Kept parser namespaces stable where possible while changing physical file organization.
- Updated signature analysis/architecture notes to clarify that `.hdu`, `.hsu`, `.ndu`, `.ldu`, `.mdu`, and `.msu` belong to PUA-related database families; they are not generic incremental-update suffixes. Database update logic lives under `ClamGuard.Database/Update/`.

### `ClamGuard.Database`

- Split the large database loader into `DatabaseLoader.cs` and `DatabaseLoader.Specialized.cs` partial files.
- Moved loader result/error types into `Models/`.
- Kept update work under the same project, in the `Update/` subfolder.

### Bytecode and WPF files

- Split `ClamBcEngine.cs` into the public engine facade, `Parsing/ClamBcParser.cs`, partial VM core/API files, and one-type-per-file runtime models.
- Split WPF command implementations into `ViewModels/Commands/`, moved scan/update workflows to `MainViewModel.Scanning.cs`, and separated result/threat/quarantine lifecycle logic into `MainWindow.ThreatHandling.cs`.
- Split the 693-line `Theme/Controls.xaml` into eight focused resource dictionaries (converters, cards, buttons, status/navigation, scrolling, inputs, DataGrid, and miscellaneous controls). Kept `Controls.xaml` as the stable aggregator referenced by `App.xaml`; the merge order respects `StaticResource` dependencies.

### Regression tests

- Replaced the 2,634-line `tests/ClamGuard.Tests/Program.cs` monolith with a small runner that preserves the original test-group order.
- Split test coverage into `Suites/Program.*Tests.cs`: database/CVD, compiled matcher, signature parsing, NDB policy, container layers, executable formats, archive/document formats, YARA/bytecode, and metadata/self-protection.
- Moved reusable assertions, CVD/ClamBC fixtures, PE fixtures, archive fixtures, executable fixtures, and smoke tests into focused `Support/` files. `SlowScanner` is now its own file.
- Replaced two test cases' accidental dependency on top-level `htmlFile`/`asciiFile` locals with a shared fixture factory, so each suite owns the fixtures it uses.
- Added `Program.LdbParityTests.cs` for the documented `Win.Malware.Generic-9828792-0` rule, a synthetic PE positive case, a missing-required-marker negative case, and a non-PE target negative case.
- Added `tests/ClamGuard.Tests/README.md` describing the test-runner/suite layout and how to run it.

### Documentation

- Added `docs/architecture/source-structure.md` as the current directory/project map.
- Updated README, architecture, update-pipeline, audit and signature-planning documents to reflect the refactored layout.

## LDB matching audit and optimization

- Compared `EvaluateLogical` in the original single-file scanner with the refactored implementation. Apart from the candidate-prefilter call and a guard before evaluating indexed rules, the matching body is unchanged: target checks, data normalization, offset resolution, macro handling, individual subsignature matching, boolean-expression evaluation, handler retyping, and icon checks remain the final authority.
- Added `LogicalSignaturePrefilter`, which builds one shared Aho–Corasick index for safe fixed-byte anchors across pure-AND LDB rules. A rule can be skipped only when its required anchor is absent. It indexes only subsignatures referenced by the AND expression, and sends rules with non-content terms, expressions outside simple AND, short/no fixed anchors, or normalized targets 3/7 through the original evaluation path.
- The prefilter returns candidates only; it cannot emit a detection. Candidate anchors are stored as byte arrays with a content comparer rather than hex-encoded strings, avoiding extra anchor-key string allocations. The full LDB matcher still checks offsets, modifiers, all required subsignatures, targets, and the full expression.
- The new regression test uses the exact rule text documented in `CLAMAV_DATABASE_ARCHITECTURE.md` and creates a **synthetic** PE named `000.exe` containing the five required markers. The wide fifth marker is specifically `Creep.Properties.Resources` in UTF-16LE (not `Creep.Properties.Resources.resources`). The test checks prefilter eligibility/candidate inclusion, the expected detection name `Win.Malware.Generic-9828792-0`, and negative cases where a required marker is removed or the same strings are placed in a non-PE file.
- The uploaded repository does not include the user's real `000.exe` or a real `daily.ldb` (only a demo LDB is present), so this is a controlled regression fixture, not a result from the real sample. No throughput benchmark or compiler-backed test run was possible in this environment; no speedup percentage or real-sample parity is claimed.

## Static validation performed

- 223 code-oriented source/resource files checked across C#, XAML, SQL, scripts, project XML, and web assets; none exceeds 600 lines after splitting the control dictionary and adding the LDB prefilter/regression case.
- The longest checked code/resource file is `src/ClamGuard.Signatures/Matching/CompiledSignatureSet.cs` at 578 lines.
- All nine `Controls*.xaml` dictionaries parse as XML; 45 original top-level resources were retained across the eight focused dictionaries, and static-resource dependency checks found no references to later control dictionaries.
- No unbalanced `{}`, `()`, or `[]` delimiters were found in C# source files.
- All 8 `.csproj` files parse as XML, match the 8 solution entries, and have no missing `ProjectReference` targets.
- All test-runner calls resolve to a declared test/support method under a static source check.
- The test-project split contains 17 C# files; the largest test/support file is 440 lines.
- ZIP archive integrity was checked after packaging.

## Important validation limit

The execution environment does not have the .NET SDK (`dotnet`), `csc`, or `msbuild`. Therefore `dotnet build` and the regression harness **could not be run**. Static checks reduce obvious structural risks but do not prove successful compilation or runtime behavior. Before merging, run:

```powershell
dotnet build ClamGuard.Net.sln -c Release
dotnet run --project tests/ClamGuard.Tests/ClamGuard.Tests.csproj -c Release
```

No claim is made that compiler-backed build or runtime regression tests passed.
