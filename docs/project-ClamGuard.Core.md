# project-ClamGuard.Core

> The shared foundation of the whole system: the hex codec, domain models, scan configuration
> (`ScanOptions`/`ScanLimits`) and result-filtering policy. **Depends on nothing** — every other
> project depends on this one.

---

## 1. Project facts

| Property | Value |
|---|---|
| Target framework | `net8.0` (inherited from `Directory.Build.props`) |
| Dependencies | None (root of the dependency graph) |
| Compiler settings | `Nullable=enable`, `TreatWarningsAsErrors=true`, `Deterministic=true`, `LangVersion=latest` |
| Source files | 2 (`Hex.cs`, `Models.cs`) |

Position in the dependency graph:

```text
ClamGuard.Core   <- depends on nothing
+-- ClamGuard.Signatures
+-- ClamGuard.Yara
+-- ClamGuard.Bytecode
+-- ClamGuard.Database   (-> Signatures, Yara, Bytecode)
+-- ClamGuard.Scanner    (-> all of the above)
+-- ClamGuard.Antivirus  (-> Core, Database, Scanner)
```

---

## 2. Components

### 2.1. `Hex.cs` — static hex codec

| API | Role |
|-----|------|
| `HexCodec.TryDecode(string, out byte[])` | Hex to byte[]; fails on invalid characters or odd length |
| `HexCodec.ToLowerHex(byte[])` | byte[] to lowercase hex (display/manifest) |

Semantics match ClamAV hex: ASCII only, mixed case accepted. This is a hot path when loading a
database with hundreds of thousands of signatures.

### 2.2. `Models.cs` — domain model & policy

**Enums:**

| Enum | Meaning |
|------|---------|
| `ScanVerdict` | `Clean`, `Malicious`, `PotentiallyUnwanted`, `StrongIndicator`, `Trusted`, `Timeout`, `Error` — the final classification of one scan |
| `SignatureType` | Signature families: `Hash`, `Ndb`, `Logical`, `Content`, `Metadata`, `Trust`, ... |
| `HashAlgorithmKind` | `Md5`, `Sha1`, `Sha256` — selected by the **length** of the hex string in the database |
| `DatabaseFormat` | Database format on load |

**Core records:**

| Record | Notable fields |
|--------|----------------|
| `Detection(string Name, SignatureType Type, long? Offset, string SourceFile, string Detail)` | One finding; `Offset` is nullable (hash detections have no offset) |
| `ScanResult(ScanVerdict Verdict, string FilePath, string? FileType, IReadOnlyList<Detection> Detections, long BytesScanned, TimeSpan Duration, DatabaseInfo? Database)` | Complete immutable result — every layer returns this type |
| `DatabaseInfo` | Loaded database info (name, path, version) |

**Scan configuration:**

| Class | Role |
|-------|------|
| `ScanOptions` | User-facing switches: per-parser toggles (`ScanArchive`, `ScanPE`, `ScanPDF`, `ScanHTML`, `ScanOneNote`, `ScanImageFuzzyHash`, ...), heuristics (`EnableHeuristics`, `HeuristicExceedsMax`, `HeuristicEncryptedArchive/Doc`, `HeuristicPrecedence`), `DetectPUA`, `CollectAllMatches`, `MaxThreads`, `Recursive`, `FollowSymlinks`, `ExcludeDirectories/Extensions`, `YaraRuleDirectory`, `BytecodeDirectory`, `ContentScanners`. Defaults track ClamAV 1.5.x. `Default` returns a fresh instance on every access. |
| `ScanLimits` | Safety ceilings: `MaxArchiveDepth` (default 17, validated 1..100), `MaxFileSize`, `MaxScanSize`, `MaxFiles`, `MaxFullBufferSize`, `MaxArchiveEntries`, `MaxArchiveExpandedBytes`, `MaxArchiveCompressionRatio`, `MaxEmbeddedStreamSize`, `MaxHtmlNormalize`, `StreamChunkSize`, `MaxFlexibleLookbehind`, `MaxPatternMatchesPerSignature`, `MaxLogicalDepth`... `Validate()` **recovers** `MaxFileSize` into `[1GiB, 2GiB]` instead of failing. |
| `UpdateOptions` | Database update options. |

`ScanOptions.MaxRecursion` (default 17) is merged into the limits via `CreateEffectiveLimits()`:
`MaxArchiveDepth = min(limits, MaxRecursion)` — every effective limit flows through this single point.

**Extension contract:**

```csharp
public interface IContentScanner
{
    IReadOnlyList<Detection> Scan(byte[] data, string path, CancellationToken ct);
    string Directory { get; }
}
```

Lets external scanners (Yara, Bytecode) plug into the pipeline through `ScanOptions.ContentScanners`.

**Detection filtering policy:**

| Function | Role |
|----------|------|
| `IsPuaName(name)` | Detects the `PUA.` prefix |
| `IsHeuristicName(name)` / `IsHeuristic(detection)` | Detects heuristic detections (`Heuristics.*`) |
| `ScanOptions.FilterDetections(list)` | Applies PUA/heuristic policy: `DetectPUA=false` filters PUA but keeps malware; `HeuristicExceedsMax=false` filters heuristics; `HeuristicPrecedence` lets a heuristic win first |
| `ScanOptions.HasBlockingDetections(list)` | True when a "blocking" detection exists (malware, or PUA/heuristic when enabled) — used for early-exit short-circuits |
| `IsExcludedDirectory(root, fullPath, excludes)` | Matches **exact path segments** (not substrings), including descendants |

For the database formats behind these types, see
[`daily_CVD_Signature_Format_Analysis.md`](./daily_CVD_Signature_Format_Analysis.md).

---

## 3. Design rules

1. **Immutable results**: `Detection`/`ScanResult` are records — safe to pass across threads;
   nobody mutates someone else's result.
2. **Validate-recover, not throw**: `ScanLimits.Validate()` normalizes illogical values (<= 0,
   int overflow) back to safe defaults — scanning continues instead of crashing (behavior locked
   by `Program.ScanOptionsTests.cs`, including the negative `MaxFileSize` overflow case).
3. **Single configuration point**: root-level `Directory.Build.props` applies to every project;
   this project deliberately declares nothing extra so it inherits (`Nullable`,
   `TreatWarningsAsErrors`).
4. **No external dependencies**: keeps this project payload-free so every other layer can use it
   without pulling packages.

## 4. Testing

Covered indirectly by **every** suite in `tests/ClamGuard.Tests` (all pipelines flow through
`ScanOptions`/`ScanLimits`/`ScanVerdict`) and directly by `Program.ScanOptionsTests.cs`
(24 assertions: defaults vs ClamAV 1.5.x, limit merging, PUA precedence, exclusion semantics,
normalization overflow/2 GiB ceiling...).
