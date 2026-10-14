# project-ClamGuard.Signatures

> Parses every ClamAV signature format into structured models, then builds them into
> **compiled matchers** (Aho-Corasick, Boyer-Moore-Horspool, hash buckets, logical prefilter)
> that run in-memory and streaming over untrusted data.

---

## 1. Project facts

| Property | Value |
|---|---|
| Target framework | `net8.0` |
| Dependency | `ClamGuard.Core` |
| Source files | 43 (Matching 7, Patterns 8, Parsing 11, Models 16, csproj) |
| Formats parsed | `.hdb/.hdu/.hsb/.hsu/.mdb/.mdu/.msb/.msu/.fp/.sfp/.ndb/.ndu/.ldb/.ldu/.cdb/.zmd/.rmd/.idb/.db/.ign/.ign2` |

## 2. Layout

```text
Parsing/
  SignatureParser.cs            Facade dispatching by extension
  SignatureParserCommon.cs      Shared helpers (algorithm by hash length, ParseInt/Size, Engine range)
  Hash/HashSignatureParser.cs   .hdb/.hsb/.fp/.sfp/.mdb/.imp (size BEFORE hash for mdb/msb)
  Content/Ndb/NdbSignatureParser.cs     .ndb/.ndu/.sdb — offset validation (cli_caloff parity)
  Content/Ldb/LdbSignatureParser.cs     .ldb/.ldu — safe ';' splitting, subsig classification
  Content/Ldb/LdbSubsigParser.cs        hex::mods, PCRE, byte-compare, fuzzy_img, macro
  Content/Ldb/LdbTargetParser.cs        TDB (Target/Engine/Container/FileSize/IconGroup...)
  Metadata/IdbSignatureParser.cs        .idb — 62-byte metric, step-by-step bounds
  Container/ContainerSignatureParser.cs .cdb/.zmd/.rmd — bug-for-bug with cli_loadmd/cli_loadcdb
Patterns/
  PatternAtom.cs (+ ExactByte/MaskedByte/Gap/CharacterClass/Alternate)
  HexPattern.cs                 Dual representation: fixed byte[] <-> atoms; backtracking matcher
Matching/
  AhoCorasick.cs                Sparse trie -> frozen arrays -> dense int[256] for the first 8192 states
  BoyerMooreHorspoolMatcher.cs  Fast path for the exactly-one-fixed-pattern case
  CompiledSignatureSet(.MatchHelpers).cs   Aggregate index + Match/MatchStreamAsync
  LogicalSignaturePrefilter.cs  Fragment index (seed 4-byte balanced) for pure-AND logical signatures
  SignatureTargetGroups.cs      Mirror of cli_mtargets[] from ClamAV 1.5.4 (15 matcher roots)
  ByteArrayContentComparer.cs   EqualityComparer<byte[]> for digests (xxHash-based)
Models/
  Signature.cs, ContentSignature.cs, NdbSignature.cs, LogicalSignature.cs,
  HashSignature.cs, MetadataSignature.cs, CdbSignature.cs, LdbTargetDescription.cs,
  LdbRegexSubSignature.cs, LdbByteCompareSubSignature.cs, LdbFuzzyImageSubSignature.cs,
  ContentMatchOptions.cs, ByteCompareOptions.cs, ByteCompareComparison.cs,
  MetadataRange.cs, IconDatabase.cs
```

Format semantics are specified in [`daily_CVD_Signature_Format_Analysis.md`](./daily_CVD_Signature_Format_Analysis.md).

---

## 3. Flow

### 3.1. Load & build

```text
SignatureParser.ParseFile(path, flevel)        <- dispatches by extension
        |  (FLevel gate runs before hex parsing — saves work)
        v
IEnumerable<Signature>                         <- immutable models with SourceFile/SourceEntry
        |  SignatureDatabase.Add/Compile()  (in project Database)
        v
CompiledSignatureSet.Add(signature)            <- routed into the right structure
   +- fixed hex       -> AhoCorasickMatcher per target-group (NDB) or content-AC
   +- flexible hex    -> flexible-AC by anchor + the _unanchored* lists
   +- hash sigs       -> hash buckets by (algorithm, size?) — exact + wildcard
   +- .fp/.sfp        -> false-positive buckets
   +- logical         -> LogicalSignaturePrefilter (seed-balanced fragment index)
        |  Build()
        v
FROZEN: arrays frozen, dense transition tables, immutable state for scanning
```

### 3.2. Match (in-memory)

`Match(data, label, includeNdb, collectAllMatches, ndbFilter, ndbPatternCandidates,
ndbCandidateFilter, targetGroup)`:

1. **Target-group AC first** (like `cli_scan_buff`), then the generic root.
2. Each hit passes: `hits` dedupe -> NDB gate (`includeNdb` + `ndbFilter`) ->
   `OffsetAllows` (`cli_caloff` semantics: `N,M` = `[N, N+M]` inclusive; `EOF-n`; `*`) -> Detection.
3. An NDB rejected by the filter is still added to `ndbPatternCandidates` so the **context-aware
   EvaluateNdb** pass (offsets EP/SE/S/VI need executable info) can run at the Scanner layer.
4. Flexible content: candidates from the anchor AC -> collection caps (4096/pattern, 65,536 total)
   -> verification in offset order -> first-match or all-match.
5. Hash buckets: only hash algorithms that have buckets; a `.fp` hit turns the whole layer
   into **Trusted**.

### 3.3. MatchStreamAsync (streaming)

Chunked stream, **AC state preserved across chunk boundaries**, rolling window
`MaxFlexibleLookbehind` for flexible patterns, conditional `IncrementalHash` (`NeedsHash`),
`OffsetAllowsStreaming` mirroring the in-memory version. The method is deliberately structured to
**compile under both C# 12** (SDK 8) **and C# 14** (SDK 10) — the Span locals of the streaming
loop were extracted into the local function `MatchFlexibleChunk`.

---

## 4. Public API

| API | Notes |
|-----|-------|
| `SignatureParser.ParseFile / ParseLines / ParseHashFile / ParseNdbFile / ParseLdbFile / ParseCdbFile / ParseMetadataFile / ParseIdbFile` | Static; throws `FormatException` with `path:line` on malformed databases |
| `CompiledSignatureSet.Match(...)` | In-memory buffer scan |
| `CompiledSignatureSet.MatchStreamAsync(...)` | Stream scan (files larger than `MaxFullBufferSize`) |
| `CompiledSignatureSet.MatchesFalsePositive(data)` | `.fp/.sfp` trust check |
| `CompiledSignatureSet.FindLogicalCandidates(data) / IsLogicalSignaturePrefiltered(sig)` | Pure-AND logical prefilter |
| `AhoCorasickMatcher.Scan / ScanUntil / FindMatchingIds` | Standalone matcher (chunked, state-preserving) |
| `HexPattern.Parse / Matches / TryGetSearchAnchor / ToWideVariant` | Pattern engine |

---

## 5. Deliberate performance points

| Technique | Location | Reason |
|-----------|----------|--------|
| Sparse trie (int-indexed edge lists) -> **frozen arrays** -> **dense `int[256]`** for the first 8192 states | `AhoCorasick.cs` | Real databases have 500K-2M states; freezing + `TrimExcess` releases build-time lists |
| Flyweight of 256 instances | `ExactByteAtom.cs` | No per-byte allocation while parsing large databases |
| Anchor search (longest fixed run) for flexible patterns | `MatchHelpers.cs` `MatchFlexibleCore` | Avoids backtracking at every byte position |
| Seed-balanced fragment index | `LogicalSignaturePrefilter.cs` | Picks the rarest 4-byte seed by FNV rounds — cuts candidates before subsig counting |
| BMH fast path when the set has exactly one fixed pattern | `CompiledSignatureSet.cs` | Skips AC overhead; tries **every occurrence** like `cli_bm_scanbuff` |
| Candidate caps | `MaxCollectedCandidatesPerPattern=4096`, `MaxCollectedCandidatesTotal=65536` | Frequent anchors (zero runs, MZ pads) on large files cannot buffer O(filesize) positions |
| `MaxBacktrackingStates` (250K) + visited-set | `HexPattern.cs` | Bounds DoS from gap-heavy patterns; the visited set guarantees termination in O(atoms x length) |

## 6. ClamAV compatibility (verified against the 1.5.4 sources)

| Topic | Decision |
|-------|----------|
| Offset `N,M` | Max shift -> match in `[N, N+M]` **inclusive** (`cli_caloff` + `matcher-ac.c:1918`) |
| Bare `EOF` | **Rejected** (does not exist in `cli_caloff`) — only `EOF-n` |
| `VI` offset | Valid (VersionInfo) — executable targets only |
| Target gate | `EP+/EP-/SL+/SE/Sn/VI` **fail at load time** unless target is in {1, 6, 9} |
| `[n-m]` hex | Real gap syntax — `cli_ac_addsig` converts it (max 2 uses) |
| ICMP opcodes | 29 = SLE, 30 = SLT (matches `clambc.h`; consumed by the Bytecode project) |
| `.ldb` expression | Right-associative: `0&1|2` == `0&(1|2)` (evaluated by the Scanner layer) |
| `.ign`/`.ign2` | Filtered **before** hex parsing (FLevel-first like `cli_loadndb`) |

## 7. Thread-safety

- Parsers: static and pure — safe from any thread.
- `CompiledSignatureSet`: mutable during `Add()`, **immutable after `Build()`** (enforced by the
  `_built` flag); the scan path never mutates.
- `AhoCorasickMatcher.Build()` / `LogicalSignaturePrefilter.Build()`: lazy, **not thread-safe if
  Build is called concurrently from two threads** — the caller (CompiledSignatureSet) builds first.
- `HexPattern.ToWideVariant`: lazy cache with a benign race (duplicate compute, equal value).

## 8. Testing

- `Program.CompiledMatcherTests.cs` (50 asserts) — the deepest suite: AC overlap/suffix/
  chunk-boundary, streaming, FP suppression, BMH fast path, alternates, LDB modifiers.
- `Program.NdbPolicyTests.cs` (35) — every offset form, `.ign/.ign2`, PUA, normalized targets.
- `Program.SignatureParsingTests.cs` (17), `Program.MetadataTests.cs` (32),
  `Program.LdbParityTests.cs` (12, parity against a real LDB line via env opt-in).
