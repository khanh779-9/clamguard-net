# daily.cvd — ClamAV Signature Format Specification (merged edition)

> **Source**: a merge of two independent analyses (Claude and ChatGPT) of the same
> `daily.cvd` package (**build 28146**, 07 Oct 2026, 23,439,346 bytes, functionality level 90),
> then cross-checked against the **ClamAV 1.5.4 sources** and against this repository's
> **ClamGuard.NET** engine.
>
> **Provenance labels** used throughout:
>
> | Label | Meaning |
> |-------|---------|
> | `[measured]` | Counted directly on this daily.cvd build (changes with every update) |
> | `[docs]` | Semantics from the official ClamAV documentation (docs.clamav.net) |
> | `[source]` | Verified directly in the ClamAV 1.5.4 sources (`libclamav/`) |
> | `[ClamGuard]` | Implemented in this repository — points to the file/class |
>
> This document is the **rule book** for a C# engine: the structure of every database file, the
> record formats, matching semantics, and the pitfalls to avoid when writing parsers/matchers.

---

## Contents

1. [The CVD container](#1-the-cvd-container)
2. [Conventions shared by all database files](#2-conventions)
3. [Inventory of the 25 extracted files](#3-inventory)
4. [Whole-file hashes: `.hdb/.hdu/.hsb/.hsu`](#4-whole-file-hashes)
5. [PE section hashes: `.mdb/.mdu/.msb/.msu`](#5-pe-section-hashes)
6. [Hash allow-lists: `.fp/.sfp`](#6-hash-allow-lists)
7. [Body signatures: `.ndb/.ndu`](#7-body-signatures-ndbndu)
8. [Logical signatures: `.ldb/.ldu`](#8-logical-signatures-ldbldu)
9. [Container metadata: `.cdb`](#9-container-metadata-cdb)
10. [Icon signatures: `.idb`](#10-icon-signatures-idb)
11. [Certificates: `.crb`](#11-certificates-crb)
12. [File type magic: `.ftm`](#12-file-type-magic-ftm)
13. [Anti-phishing: `.pdb`, `.wdb`](#13-anti-phishing)
14. [Configuration & ignore: `.cfg`, `.ign`, `.ign2`](#14-configuration--ignore)
15. [`daily.info` and `COPYING`](#15-dailyinfo-and-copying)
16. [Pitfalls found in real data](#16-pitfalls)
17. [C# implementation guidance](#17-implementation-guidance)
18. [Test plan](#18-test-plan)
19. [Quick reference](#19-quick-reference)
20. [Appendix: one-line samples](#20-appendix-one-line-samples)
21. [Official references](#21-official-references)

---

## 1. The CVD container

A CVD is **not a ZIP**: the first 512 bytes are an ASCII header, everything after is a `tar.gz`.

```text
[0x000 .. 0x1FF]  512-byte ASCII header, space-padded (0x20) to exactly 512
[0x200 .. EOF  ]  Payload = gzip containing a tar archive (starts with 1F 8B 08)
```

The header splits on `:` into **9 fields**:

| # | Field | Value in this package | Notes |
|---|-------|------------------------|-------|
| 0 | Magic | `ClamAV-VDB` | fixed |
| 1 | Build time | `07 Oct 2026 06-24 +0000` | format `dd Mon yyyy HH-mm +zzzz` (a `-` between hour and minute) |
| 2 | Version | `28146` | build number |
| 3 | Signature count | `355728` | [measured] **not equal** to the total data-line count (356,255) — see section 16.1; do not assert against it |
| 4 | Functionality level | `90` | engines with FLevel < 90 must reject the database |
| 5 | Payload MD5 | `f035c4fd10fd33f9fadd5905acb78b7e` | [source] = MD5 of every byte from offset 512 (verified by both analyses) |
| 6 | DSIG (base64) | ~170 characters | RSA signature of the payload MD5 |
| 7 | Builder | `svc.clamav-publisher` | |
| 8 | Build time (epoch) | `1791354258` | = 2026-10-07 06:24:18 UTC |

**Integrity checks** (performed on this package):
- [measured] 23/23 database files listed in `daily.info` match **size + SHA-256**.
- [measured] The payload MD5 matches header field 5.
- Warning: the **DSIG was not verified** against ClamAV's public key — checksums only prove
  header/payload consistency, **not provenance**. Use `sigtool` or the ClamAV public keys.
  [ClamGuard] `ClamGuard.Database/Verification/ClamAvSignatureVerifier.cs` (RFC 8017 RSA-PSS for
  `.info`, raw-RSA/MD5 for the CVD dsig) + `DatabaseVerifier.cs` (manifest).

**Extraction**:

```bash
sigtool --info daily.cvd      # the official mechanism when ClamAV is installed
sigtool --unpack daily.cvd
# or manually:
tail -c +513 daily.cvd | tar -xzf -
```

Tar notes: members carry **mode 000** and mtime 1970 — on Linux you must `chmod` after
extraction; in C# use `System.Formats.Tar` + `GZipStream` to read the streams directly without
writing to disk.
[ClamGuard] `ClamGuard.Database/Loading/CvdReader.cs` (streamed, size-capped, bounds-checked header).

---

## 2. Conventions

[measured] across all 24 database files (build 28146):

- **ASCII only** (no byte >= 0x80), **LF** line endings (no CR anywhere), the last line ends
  with `\n`. Defensive: `TrimEnd('\r')` when reading — other databases may use CRLF.
- Lines starting with `#` are **comments**. Seen in: `.cdb`, `.cfg`, `.crb`, `.idb`
  (exactly one line: `# There must always be one line in the file`). No blank lines.
- Most files are `Field1:Field2:...` separated by **`:`**. `.ldb/.ldu/.crb` use **`;`**.
- **Optional FLevel suffix** at the end of a line: `:MinFLevel[:MaxFLevel]` — engines outside the
  (inclusive) range **skip that signature** (no file failure). Some formats allow an **empty**
  FLevel field (see section 12, `.ftm`).
- Hex is **case-insensitive** (`.ldb` mixes `6475706C` and `6475706c`); hashes in hash databases
  are lowercase but comparisons should be case-insensitive.
- Malware names follow `Platform.Category.Family-ID-Variant` (e.g. `Win.Ransomware.RansomHub-10037316-0`,
  `PUA.Win.Tool.ANVCracker-1`). The **`PUA.`** prefix = only detected when PUA scanning is on.
  Warning: names **may contain spaces** ([measured] one `.ldb` line: `Win.Loader. BadiisSet-10060291-1`)
  — never assume no-spaces, never use `\S+` in validation regexes.
- [docs] The **`u`** suffix (`.hdu .hsu .mdu .msu .ndu .ldu`) marks the **PUA/unofficial** variant
  of the same format — loaded separately, only when PUA detection is enabled.
  [ClamGuard] `ScanOptions` PUA flags + `IncludePuaCategories`.
- [docs] `.hsb/.msb/.hsu/.msu/.sfp` are the "**s**ha" variants: the **hex string length selects
  the algorithm** (32 = MD5, 40 = SHA-1, 64 = SHA-256) — never infer it from the extension.

---

## 3. Inventory

The archive contains **25 files**: the 23 database files listed in `daily.info`, plus
`daily.info` and `COPYING`.

| File | Size (bytes) | Lines | Delimiter | Fields | Signature type |
|------|-------------:|------:|-----------|--------|----------------|
| `daily.hdb` | 1,640 | 23 | `:` | 3 | Whole-file MD5 hash |
| `daily.hdu` | 2,525 | 39 | `:` | 3 | Whole-file MD5 hash (PUA) |
| `daily.hsb` | 3,883,885 | 54,681 | `:` | 3 or 4 | Whole-file MD5/SHA1/SHA256 (+FLevel) |
| `daily.hsu` | 89 | 1 | `:` | 3 | Like hsb (PUA) — only the EICAR line |
| `daily.mdb` | 744,257 | 11,575 | `:` | 3 | **PE section** MD5 hash |
| `daily.mdu` | 19,999 | 315 | `:` | 3 | Like mdb (PUA) |
| `daily.msb` | 161 | 2 | `:` | 3 or 4 | PE section hash (MD5/SHA) |
| `daily.msu` | 92 | 1 | `:` | 3 | Like msb (PUA) |
| `daily.fp` | 26,373 | 483 | `:` | 3 | MD5 hash allow-list (false positives) |
| `daily.sfp` | 87 | 1 | `:` | 3 | SHA hash allow-list |
| `daily.ndb` | 198,238 | 319 | `:` | 4/5/6 | Hex body/offset signatures |
| `daily.ndu` | 823,292 | 4,159 | `:` | 4/5/6 | Like ndb (PUA) |
| `daily.ldb` | 76,829,701 | 273,473 | `;` | 4 -> 66 | Logical signatures (96% of all signatures) |
| `daily.ldu` | 3,528,282 | 10,166 | `;` | 4 -> 23 | Like ldb (PUA) |
| `daily.cdb` | 491 | 6 | `:` | 10 | Container entry metadata |
| `daily.idb` | 36,469 | 223 | `:` | 4 | Icon signatures (fuzzy hash) |
| `daily.crb` | 21,363 | 31 | `;` | 11 | Certificates (trusted / revoked) |
| `daily.ftm` | 20,097 | 268 | `:` | 6/7/8 | File type magic |
| `daily.pdb` | 4,094 | 263 | `:` | 2 | Anti-phishing host list |
| `daily.wdb` | 10,745 | 185 | `:` | 3 | Anti-phishing URL allow-list |
| `daily.cfg` | 424 | 22 | `:` | 4 | DCONF configuration per FLevel |
| `daily.ign` | 29 | 1 | `:` | 3 | Legacy ignore (by DB:line) — only the fake line |
| `daily.ign2` | 554 | 22 | - | 1 | Ignore by signature name |
| `daily.info` | 2,285 | 25 | `:` | 3 | Manifest (size + SHA256 per file) |
| `COPYING` | 17,992 | 340 | - | - | GPLv2, not a signature database |

[docs] **Not present in this package** (but supported at the engine level): `.cbc` (bytecode),
`.gdb`, `.imp` (import hashes), `.yar/.yara`, `.wdb` `Y:` records... Their absence does not mean
an engine should skip them.
[ClamGuard] `.gdb`, `.imp`, `.cbc` and a (subset) `.yara` are already supported by the loader/engine.

---

## 4. Whole-file hashes

### 4.1 `.hdb` / `.hdu` — whole-file MD5

```text
MD5:FileSize:MalwareName
```

[measured] 23/23 and 39/39 lines: hash is exactly 32 hex, FileSize is a decimal number, no line
carries an FLevel suffix.

```text
44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature
```

**Rule**: compute the MD5 of the exact object being scanned; a matching `(size, md5)` pair
detects. Index as `Dictionary<(long size, string md5), ...>`, split by hash length.

### 4.2 `.hsb` / `.hsu` — whole-file MD5/SHA1/SHA256

```text
HASH:FileSize:MalwareName[:MinFL[:MaxFL]]
```

[measured] `.hsb` statistics (54,681 lines):

| Characteristic | Count |
|----------------|------:|
| 32-hex hash (MD5) | 54,584 |
| 40-hex hash (SHA-1) | 2 |
| 64-hex hash (SHA-256) | 95 |
| 3 fields (no FLevel) | 1 (the EICAR SHA-256 line) |
| MinFL = 73 / 90 / 74 / 81 | 54,614 / 49 / 15 / 2 |
| FileSize = `*` (any) | 2 (CVE_2020_1381, CVE_2020_1529) |

Warning: [docs] when the size is `*` the documentation **requires** a MinFLevel (FP protection) —
a line without one is rejected by the loader. No line in this package has a MaxFL.

Warning: [docs] for HTML/text that the engine normalizes before hashing, the hash must apply to
**the normalized form the engine hashes**, not the raw file — hashing raw bytes will not match
ClamAV results.
[ClamGuard] `HashSignatureParser.cs` (rejects wildcard-size without MinFL), buckets keyed by
`(algorithm, size)` in `CompiledSignatureSet.cs`.

### 4.3 Algorithm selection

| Hex length | Algorithm |
|---:|---|
| 32 | MD5 |
| 40 | SHA-1 |
| 64 | SHA-256 |

---

## 5. PE section hashes

### 5.1 `.mdb` / `.mdu` / `.msb` / `.msu`

```text
PESectionSize:SectionHash:MalwareName[:MinFL[:MaxFL]]
```

Warning: the field order is **reversed compared to `.hdb`** — size comes BEFORE the hash.

[measured] `.mdb`: 11,575 lines, all 3 fields, 32-hex hashes (MD5). `.mdu`: 315 lines, same.
[measured] `.msb`: 2 lines — one SHA-256 (EICAR, 3 fields), one MD5 with MinFL 73.
`.msu`: 1 EICAR SHA-256 line.

```text
45056:f9b304ced34fcce3ab75c6dc58ad59e4d62177ffed35494f79f09bc4e8986c16:Eicar-Test-Signature
91648:550a9b573224aa75418c852080b59af3:Win.Packer.Agent-6412293-0:73
```

[docs] The hash covers the **raw data of each PE section** (do not confuse file offsets with
RVA/virtual sizes).
[docs] ClamAV documents limitations on PE32+ 64-bit section hashing in some versions — verify
with the target engine instead of assuming 64-bit behaves like 32-bit.
[ClamGuard] `PeSpecializedMatcher.cs` (hashed once per algorithm per section) +
`PeSpecializedMatcher.Parsing.cs`.

---

## 6. Hash allow-lists

### 6.1 `.fp` / `.sfp`

```text
HASH:FileSize:SignatureID
```

[measured] `.fp`: 483 MD5 lines. `.sfp`: 1 SHA-256 line. The third field is **not a malware
name** but the **ID of the signature being excluded** (`sid25347313-1`, `sid177969901-1-6459222-0`).

```text
# daily.fp
332feab1435662fc6c672e25beb37be3:2871808:sid25347313-1
# daily.sfp — the same file, two hash types
6bed1a3a956a859ef4420feb2466c040800eaf01ef53214ef9dab53aeff1cff0:2871808:sid25347313-1
```

**Rule**: a matching `(size, hash)` clears **all detections** for that layer (and per ClamAV,
stops descending into children). Keep this flow separate from the detection tables.
[ClamGuard] trust semantics in `CompiledSignatureSet.cs` — a `.fp/.sfp` hit produces
`ScanVerdict.Trusted`, clears layer evidence and stops descending.

---

## 7. Body signatures: `.ndb`/`.ndu`

```text
MalwareName:TargetType:Offset:HexSignature[:MinFL[:MaxFL]]
```

[measured] Field distribution: `.ndb` 4 = 308, 5 = 6, 6 = 5; `.ndu` 4 = 4,147, 5 = 10, 6 = 2
(every 6-field line has MaxFL = 255). MinFL values seen: ndb {90, 70, 81, 74, 51};
ndu {19, 18, 58, 32, 73, 74}.

### 7.1 TargetType

[docs] ClamAV target table (= the index into `cli_mtargets[]` — [source] matches `matcher.h` 1.5.4):

| Value | Target file type |
|------:|------------------|
| 0 | Any file |
| 1 | PE (Windows exe/dll) |
| 2 | OLE2 (legacy doc/xls) |
| 3 | HTML |
| 4 | Mail |
| 5 | Graphics |
| 6 | ELF |
| 7 | ASCII text |
| 8 | (unused) |
| 9 | Mach-O |
| 10 | PDF |
| 11 | Flash |
| 12 | Java class |

[measured] Distribution: ndb 1->149, 2->42, 3->17, 5->1, 6->31, 7->50, 9->3, 10->3, 12->3, 0->20;
ndu 1->4,021, 0->42, 3->68, 7->18, 2->5, 6->2, 11->1, 12->2.

### 7.2 Offset — the real forms [source: `cli_caloff()` in `matcher.c` 1.5.4]

| Form | Example | Count (ndb/ndu) | Meaning |
|------|---------|-----------------|---------|
| `*` | `*` | 279 / 4,014 | Any position |
| `N` | `0` | 28 / 26 | Absolute offset |
| `N,M` | `120,136` | 3 / 3 | Start at N with **max shift** M -> matches `[N, N+M]` (inclusive) |
| `EP+N` / `EP-N` | `EP+192` | 3 / 112 | Entry point +/- N (executable targets only) |
| `EP+N,M` | `EP+0,100` | 2 / 2 | EP + N with a max shift of M |
| `SEn` | `SE0` | 2 / 0 | Entire section n (raw; extended by shift) |
| `Sn+M` | `S0+780912` | 0 / 1 | Section n + M bytes |
| `SL+N` | - | 0 / 0 | Last section + N ([docs] in the spec, not seen here) |
| `EOF-N` | `EOF-16015` | 1 / 0 | N bytes before EOF ([source] **only `EOF-n` exists; bare `EOF` is invalid**) |
| `EOF-N,M` | `EOF-500,500` | 1 / 1 | |
| `VI` | - | (in LDB) | Inside the PE VersionInfo region |

[source] **Comma semantics**: `cli_caloff()` splits on `,` into `offdata[2] = max shift`; a match
is valid when `offset_min <= offset <= offset_max` (inclusive — `matcher-ac.c` line 1918).
`"100,50"` matches `[100, 150]`. It is **not** a disjunct list, and there is **no `a-b` range
syntax** in NDB (`cli_isnumber("0-63")` fails -> `CL_EMALFDB`).
[source] **Target gate**: `EP/SL/SE/S/VI` offsets are **rejected at load time** unless the target
is in {1, 6, 9}.
[ClamGuard] validated in `NdbSignatureParser.cs` (1.5.4 parity incl. VI + the target gate),
evaluated in `LdbRuntime.ResolveOffset()` (context-aware for PE/ELF/Mach-O) and
`OffsetAllows/OffsetAllowsStreaming` on the streaming path.

Validation regex ([measured] ran over the whole package, 0 failures outside section 16):

```text
^(\*|\d+(,\d+)?|EP[+-]\d+(,\d+)?|S\d+\+\d+(,\d+)?|SE\d+(,\d+)?|SL\+\d+(,\d+)?|EOF-\d+(,\d+)?)$
```

### 7.3 HexSignature — pattern syntax

| Syntax | Meaning | ndb/ndu lines containing [measured] |
|--------|---------|-------------------------------------|
| `hh` | Hex byte (case-insensitive) | - |
| `??` | Any byte | 42 / 1,851 |
| `a?`, `?a` | Fixed high/low nibble, other nibble wild | 44 / 1,852 |
| `*` | Any number of bytes (>= 0) | 63 / 56 |
| `{n}` | [source] Exactly n bytes (1.5.4 rewrites it as `"??" x n`) | 36 / 1,728 |
| `{n-m}` | Between n and m bytes | 87 / 1,780 |
| `{-m}` | At most m bytes (0..m) | 18 / 44 |
| `{n-}` | At least n bytes ([docs] in the spec) | 0 / 0 |
| `[n-m]` | [source] A real gap — `cli_ac_addsig` converts it (max 2 uses, bounded by `AC_CH_MAXDIST`) | 0 / 1 (`eb0668[4-4]c3`) |
| `(aa|bb|...)` | Alternation (fixed-length rules for negated/generic forms) | 6 / 10 |
| `!(aa|bb)` | Negation ([docs] fixed-length form only) | 0 / 0 |
| `(B)` / `(L)` / `(W)` | Word boundary / line boundary (CR, CRLF, file edge) / non-alphanumeric | 0 / 0 |

Note: `{n}`, `{n-m}`, `*`, `{-m}` have **different semantics** — `*` is unbounded. Wildcards split
a pattern into segments; ClamAV requires a minimum number of fixed bytes for AC indexing.
[ClamGuard] `HexPatternParser.cs` + `HexPattern.cs` (atoms, dual fixed/atoms representation, the
`MaxBacktrackingStates` guard) + `AhoCorasick.cs`/`BoyerMooreHorspoolMatcher.cs` for matching.

**Matcher strategy** (both analyses agree): do not translate patterns into `string.Contains` or a
whole-block .NET regex — index the pure-hex segments (build an **Aho-Corasick**), evaluate
gaps/alternates with a bounded backtracker, and **reject unsupported patterns loudly** instead of
silently treating them as literals (that produces false negatives).

---

## 8. Logical signatures: `.ldb`/`.ldu`

The most complex family ([measured] 273,473 + 10,166 lines = **96% of all signatures**).

```text
SignatureName;TargetDescriptionBlock;LogicalExpression;Subsig0;Subsig1;...;SubsigN
```

[measured] Field counts: minimum 4; ldb 4 -> 66. Most common: 8 fields (5 subsigs) = 165,392;
6 fields = 93,269; 23 fields (20 subsigs) = 6,186. **Never assume a fixed field count.**

```text
Swf.Exploit.CVE-2016-1013-1;Engine:73-255,Target:11;(0&1&2);8e0f006f...;7374617274005217...;6475706C...
```

### 8.1 TargetDescriptionBlock (TDB)

A comma-separated list of `Key:Value` pairs — parse into a dictionary, **order-independent**
([measured] most common order: `Engine,Target` = 271,392 lines; 26 ldb lines have **no Engine**
-> the minimum FLevel applies).

| Key | Meaning | ldb/ldu lines [measured] | Example |
|-----|---------|--------------------------|---------|
| `Target` | File type (section 7.1 table) — **required** | 273,473 / 10,166 | `0..12` |
| `Engine` | FLevel range `min-max` | 273,447 / 9,838 | `51-255`, `73-255`, `150-255` |
| `Container` | Direct container type | 1,697 / 4 | `CL_TYPE_ZIP`, `CL_TYPE_PDF`, `CL_TYPE_OOXML_WORD` |
| `FileSize` | Byte range | 356 / 114 | `4096-16384` |
| `NumberOfSections` | PE section count | 7 / 0 | `5-15` |
| `HandlerType` | Re-typing handler (no alert — the engine re-scans as another type) | 3 / 1 | `CL_TYPE_PDF`, `CL_TYPE_SCRIPT` |
| `Intermediates` | Intermediate container chain | 1 / 0 | `CL_TYPE_MSEXE>CL_TYPE_AUTOIT` |
| `IconGroup1/2` | Icon groups linking to `.idb` | 0 / 1 | `SHARPHOUND` |
| `EntryPoint` | Entry point condition ([docs] in the spec) | 0 / 0 | |

### 8.2 LogicalExpression

Operands are subsig indices. [source] The ClamAV parser is **right-associative**:
`0&1|2` == `0&(1|2)` (per `cli_ac_chklsig`).

| Syntax | Meaning |
|--------|---------|
| `0` | Subsig 0 must match |
| `0&1&2` | AND ([measured] 269,585 pure-AND lines) |
| `(0|1)` | OR |
| `A=N` / `A=0` | Match count equals N; `=0` = negation (must not match) |
| `A>N` / `A<N` | Count comparison |
| `(...)>X,Y` | Group: total matches > X **and** at least Y distinct subsigs matched |
| Nested parentheses | Complex grouping |

Warning: [measured] a real irregular form exists — `2>2,3&(3|4|5|6|7|8)>2,3`
(`Win.Phishing.VbsAgent-10036542-0`) — the first operand has no parentheses; the parser must
tolerate it. Expressions may contain **spaces** (`0 & 1 > 200`, the Locky line) — strip
whitespace while lexing.

### 8.3 Subsignature types ([measured] ~1,352,000 across ldb+ldu)

| Type | Count | Syntax |
|------|------:|--------|
| Pure hex | 1,143,074 | as section 7.3 |
| Hex + modifiers | 207,117 | `hex::mod` |
| Hex with offset prefix | 2,007 | `Offset:hex[::mod]` |
| PCRE | 301 | `[Offset:]Trigger/regex/flags` |
| Fuzzy image hash | 109 | `fuzzy_img#16hex[#N]` |
| Byte-compare | 1 | `0(>>26#ib2#>512)` |
| Macro ([docs] `${min-max}group$`) | 0 in this package | references an NDB group |

**(a) Modifiers** — the `::` suffix + letters: `w` (wide UTF-16LE), `i` (case-insensitive),
`a` (ASCII), `f` (full word). [measured] 15 combinations seen (`w` 110,833, `i` 94,197,
`awi` 722, `f` 215, ...) — **read character by character**, never compare against fixed strings.
Warning: with `::w` the hex in the file is the ASCII form; the engine **generates** the wide
variant — do not pre-insert `00` bytes.

**(b) Offset prefix** — `Offset:hex`: [measured] `N` 1,930, `N,M` 36, `EOF-N` 9, `SEn` 6, `EP+N` 5,
**`VI` 10** (PE VersionInfo content in UTF-16LE, e.g. `500072006f00...` = "Pro..."), `*` 1.

**(c) PCRE** — `[Offset:]Trigger/regex/flags`:
- `Trigger` is a logical expression over **preceding** subsigs (`0&1`, `0`, `(0>150)&1`) — the
  PCRE only runs when the trigger is true (an important optimization).
- [measured] An offset may precede the trigger: 368 cases (e.g. `EOF-1:0&1/\./`).
- [measured] Flags seen: `i` 43, `s` 15, `m` 10, `g` 10, `U` 3; [docs] also `r` (rolling),
  `e`, `a`, `A`.
- The regex is **PCRE**: `(?P<name>...)` must become `(?<name>...)`, `(?P=name)` -> `\k<name>`;
  most of the rest is compatible with .NET Regex.
- Warning: a literal `;` inside the regex is written `\x3b` so field splitting does not break —
  see section 16.2.

**(d) Fuzzy image** — `fuzzy_img#hash16hex[#distance]` ([measured] 108 lines without distance,
1 with `#0`). The hash is a 64-bit perceptual hash of the image embedded in the document — never
a byte comparison.
[ClamGuard] `FuzzyImageHasher.cs` (64-bit pHash: Lanczos3 -> DCT) + `ImageDecoder.cs`
(capped at 4096px/64MiB).

**(e) Byte-compare** — [measured] 1 case: `0(>>26#ib2#>512)` = after subsig 0 matches, shift
`>>26` bytes, read an integer (`i`), big-endian (`b`), 2 bytes, compare `>512`. [docs] The full
syntax includes shifts `>>/<<`, options `h/d/a/i` + `l/b` + `e`, 1-2 comparisons.
[ClamGuard] `LdbSubsigParser.cs` + `TryReadByteCompareValue` (ScannerEngine.Normalization.cs).

**(f) Macro** — [docs] `${min-max}group$` referencing an NDB group; not present in this package.
[ClamGuard] fully supported (`MacroSubSignatures` + macro positions).

### 8.4 Evaluation flow

1. Check `Engine`, `Target` (+ Container/FileSize/Sections...) — fail -> skip.
2. Count matches per subsig (hex via AC; PCRE only when the trigger is true; fuzzy/byte-compare
   separately).
3. Substitute counts into `LogicalExpression` and evaluate the AST.
4. On true -> report `SignatureName`. Apply ignore-list/PUA in the policy layer.
[ClamGuard] `ScannerEngine.Content.cs` (`EvaluateLogical` — anchor prefilter, macro-on-demand,
parallel NDB/logical/PE groups) + `LogicalExpressionEvaluator.cs` (AST, right-associative,
future-reference rejection).

---

## 9. Container metadata: `.cdb`

```text
VirusName:ContainerType:ContainerSize:FileNameREGEX:FileSizeInContainer:FileSizeReal:IsEncrypted:FilePos:Res1:Res2[:MinFL[:MaxFL]]
```

[measured] 5 lines, all exactly 10 fields and **ending with `:`** (Res2 empty). All target
`CL_TYPE_ZIP` in this package.

| # | Field | Values seen |
|---|-------|-------------|
| 1 | VirusName | `Win.Trojan.Agent-1435085`, `Email.Trojan.Toa-1`... |
| 2 | ContainerType | `CL_TYPE_ZIP` ([docs] RAR/MAIL/7Z/TAR... are also valid) |
| 3 | ContainerSize | `*` or a number / `a-b` range |
| 4 | FileNameREGEX | PCRE over the child file name, e.g. `Courrt.{1,15}\.scr$`, `^[^/\\]+\.(doc|xls|ppt|pdf|png|gif|jpeg)\.js$` |
| 5 | FileSizeInContainer | `*` / number / range (usually the **compressed** size; [docs] MAIL/TAR/CPIO swap rules with field 6) |
| 6 | FileSizeReal | `*` / number / range (after extraction) |
| 7 | IsEncrypted | `*`, `0`, `1` |
| 8 | FilePos | `*` / number (1-based) |
| 9 | Res1 | [docs] For **ZIP/RAR = CRC32 hex**; ignored for other types. [measured] `*` in this package |
| 10 | Res2 | empty (unused) |

Parsing tip: the regex in field 4 may contain `:` — split the first 3 fields from the left and
the last 6 from the right; everything in between is the regex. Keep empty fields when splitting
on `:` (RemoveEmptyEntries would destroy Res2).
[ClamGuard] `ContainerSignatureParser.cs` (bug-for-bug with `cli_loadcdb`, including the
zero-endpoint quirk of `cli_matchmeta`) — matched in `ArchiveScanner.cs` (`MatchCdbSignatures`).

---

## 10. Icon signatures: `.idb`

```text
IconName:Group1:Group2:IconHash
```

[measured] 222 lines, all 4 fields; `IconHash` is always **124 hex characters = 62 bytes**.
`Group1/Group2` link to the `IconGroup1/IconGroup2` keys in the `.ldb` TDB; `UNUSED` = group not
used. [measured] Most common pairs: `DOCUMENT:BIFROSE` (48), `DOCUMENT:UNUSED` (43),
`FAVBI:UNUSED` (21). Warning: a group name can be a hex string
(`5375737061636b6564` = "Suspacked") — **do not decode it**, it is just a name.

The 62-byte fuzzy hash is a metric vector (color/gray/bright/dark/edge/noedge + r/g/b sums +
count) per `pe_icons.c` — an **approximate** image match to detect PE files disguised with
another file type's icon.
[ClamGuard] `IdbSignatureParser.cs` (metric bound validation) + `IconDecoder.cs` +
`IconMetrics.cs` (the `pe_icons.c` port: PrepareForClam, Sobel, Lab diff) + `HasIconGroup`
(gated by `PE_CONF_MATCHICON`).

---

## 11. Certificates: `.crb`

```text
Name;Trusted;Subject;Serial;Pubkey;Exponent;CodeSign;TimeSign;CertSign;NotBefore;Comment[;MinFL[;MaxFL]]
```

[measured] 30 lines, all 11 fields. Used for **Authenticode verification of PE files**
(trust / revocation), not for byte-level signature matching.

| # | Field | Values seen [measured] |
|---|-------|------------------------|
| 2 | Trusted | `1` (8 lines) = trusted; `0` (22 lines) = revoked/blocked |
| 3 | Subject | SHA-1, 40 hex (30/30) |
| 4 | Serial | SHA-1, 40 hex; **may be empty** (1 line) |
| 5 | Pubkey | RSA modulus hex, 258-1,026 characters |
| 6 | Exponent | always `010001` ([docs] the engine hardcodes/ignores it) |
| 7-9 | CodeSign/TimeSign/CertSign | `0`/`1` |
| 10 | NotBefore | empty in all 30 lines |
| 11 | Comment | empty or a description |

Note: `Split(';')` **without RemoveEmptyEntries** — empty fields are data.
[ClamGuard] signature verification via `ClamAvSignatureVerifier.cs`; certificate rules load in
`DatabaseLoader.Specialized.cs`.

---

## 12. File type magic: `.ftm`

```text
MagicType:Offset:HexMagic:TypeName:RequiredType:DetectedType[:MinFL[:MaxFL]]
```

[measured] 268 lines: 6 fields = 104, 7 = 152, 8 = 12.

| MagicType | Lines [measured] | Meaning [docs] |
|-----------|-----------------:|----------------|
| `0` | 197 | Direct byte comparison at a fixed offset |
| `1` | 69 | Body-signature magic (wildcards), searched within a region — offset may be `*` |
| `4` | 2 | Partition magic (HFS+/HFSX, offset 1024) |

- `RequiredType`: almost always `CL_TYPE_ANY`; `DetectedType` = `CL_TYPE_GZ`, `CL_TYPE_MAIL`,
  `CL_TYPE_HTML`, `CL_TYPE_MACHO_UNIBIN`, `CL_TYPE_IGNORED`...
- `HexMagic` uses the section 7.3 syntax: `?`, `(a|b)`, `{n-m}`, `{-n}`, `*`.
- Warning: [measured] 3 lines have an **empty MinFL**
  (`0:0:89504e47:PNG:CL_TYPE_ANY:CL_TYPE_GRAPHICS::121`) -> parsers must accept an empty FLevel.
- [docs] `CL_TYPE_IGNORED` = the engine skips this file type (no content scan).
[ClamGuard] `FileTypeMagicDetector.cs` (mode 0 direct + mode 1 content, `MaxSearchCandidates`
65,536, PatternCache) + loading in `DatabaseLoader.Specialized.cs`.

---

## 13. Anti-phishing

### 13.1 `.pdb` — monitored host list

```text
H:DisplayedHostname[:FuncLevelSpec]
R:DisplayedURLRegex[:FuncLevelSpec]
```

[measured] 263 lines, **all `H:`** (`H:searscard.com`, `H:capitalone.com`...). `H:` matches the
hostname simply (subdomains per ClamAV rules); `R:` is a URL regex.
[docs] These are **not** byte-scanning signatures — the engine runs them after parsing/
normalizing HTML/mail and extracting the (RealURL, DisplayedURL) pair. Searching for
`capitalone.com` in raw bytes is the **wrong semantics**.

### 13.2 `.wdb` — anti-FP phishing allow-list

```text
M:RealHostname:DisplayedHostname[:FL]
X:RealURLRegex:DisplayedURLRegex[:FL]
Y:RealURLRegex[:FL]        ([docs] ClamAV 1.6+)
```

[measured] 185 lines: `M:` 89, `X:` 96, no `Y:`.

```text
M:email.chase.com:www.chasefrauddetector.com
X:.+\.hvb\.de([/?].*)?:.+\.hypovereinsbank\.de
```

[docs] `X:` matching: **both URLs are concatenated with `:` into one string** before the regex
applies (not two independent regexes); the regex is anchored by default; the engine appends a
trailing `/` to both regex and input. A real URL matching side 1 plus a displayed URL matching
side 2 -> **legitimate, no phishing alert**.
[ClamGuard] loaded in `DatabaseLoader.Specialized.cs` (XXE-safe, blank lines rejected).

---

## 14. Configuration & ignore

### 14.1 `.cfg` (DCONF)

```text
Category:FlagsHex:MinFL:MaxFL
```

[measured] 21 lines, 5 categories: `PE` (7), `DOCUMENT` (7), `ARCHIVE` (2), `BYTECODE` (2),
`OTHER` (3). Examples: `PE:0xb4ff:13:23`, `BYTECODE:0x0:51:51`.

[docs] The mask = per-module on/off bits inside the category (bit definitions live in the sources
of each version — never guess them from the category name). Effective while the engine FLevel is
in `[MinFL, MaxFL]`.
[ClamGuard] `DynamicConfiguration.cs` (resolves "sequential assignments, later entry wins")
— flags are mapped through `DynamicConfigFlags` per the 1.5.4 sources.

### 14.2 `.ign` / `.ign2`

- [docs] `.ign` (legacy): `DBFile:LineNumber:SignatureName[:MD5]` — [measured] only the fake line
  `fake:1:Dont_remove_this_line`. Prefer `.ign2` for new designs.
- `.ign2`: one **signature name** per line to ignore ([measured] 22 lines: 1 fake
  `fake_dont_remove_this_line` + 21 real). [docs] May append `:MD5-of-entry` — ignore **only
  while the entry is unchanged**; once the signature is updated (checksum mismatch) it is no
  longer ignored.
- [docs] Policy: keep suppression in a separate layer; do not delete records from the parsed
  database (auditing reloads becomes impossible).
[ClamGuard] `IgnoreRuleSet.cs` (releases SourceEntry after filtering; conditional MD5 check).

---

## 15. `daily.info` and `COPYING`

[measured] `daily.info`, 25 lines:
1. A copy of the CVD header with MD5 + DSIG replaced by `X`:
   `ClamAV-VDB:07 Oct 2026 06-24 +0000:28146:355728:90:X:X:svc.clamav-publisher:1791354258`
2. 23 lines `FileName:Size:SHA256` — **all 23 verified** (does not list itself + COPYING).
3. A final `DSIG:<base64>` line.

[docs] Parsers must distinguish header/DSIG lines from 3-field records.
`COPYING` = GPLv2 (17,992 bytes), not a signature database.

---

## 16. Pitfalls in real data

[measured] + [docs], merged from both analyses:

1. **Header `sigs` = 355,728 != total lines** (356,255). ClamAV counts differently — do not
   assert against it. (Cross-check: ClamGuard displays **355,243** signatures after
   FLevel/PUA/ignore filtering — three different numbers, each with its own meaning.)
2. **A literal `;` inside LDB PCREs**: the `Win.Phishing.VbsAgent...` line contains `...|^^|;;)...`
   -> naive `;` splitting produces empty fragments. Recommendation: when the subsig count does
   not match the expression operands, log and skip the signature.
3. **Irregular expression without parentheses**: `2>2,3&(3|4|5|6|7|8)>2,3`.
4. **Names with spaces**: `Win.Loader. BadiisSet-10060291-1` -> do not use `\S+` in name regexes.
5. **Empty FLevel** in `.ftm` (`::121`).
6. **26 `.ldb` lines without `Engine:`** -> the minimum FLevel applies.
7. **FileSize = `*`** on 2 `.hsb` lines (must carry a MinFL).
8. **Empty Serial** on 1 `.crb` line.
9. `.cdb` ends with `:` -> keep the empty element when splitting.
10. LF is the standard, but defensively `TrimEnd('\r')` in case of CRLF variants.
11. `::` modifiers appear in many orders (`wa`/`aw`/`iaw`...) -> read character by character.
12. `.ldb` hex mixes upper/lower case.
13. **One parser per extension** — never a generic parser; `Split` without removing empty
    entries; never casually `Trim()` or strip trailing `:`/`;` (the phishing spec requires the
    colon).
14. **FLevel is not a version string** like `1.2.3` — it is an engine functionality level,
    compared inclusively per format (`.ldb/.ndb/.ftm/.cfg/.pdb/.wdb` rules are not interchangeable).
15. **`daily.ldb` is 76.8 MB** -> use a stream reader; report detection names verbatim (never
    lowercase them).
16. [docs] Do not assume PCRE constructs (`(?P<>)`) work in .NET without translation; .NET Regex
    may behave differently regarding anchors/flags.

---

## 17. Implementation guidance

### 17.1 Reading a CVD

```csharp
using System.Formats.Tar;
using System.IO.Compression;

byte[] head = new byte[512];
using var fs = File.OpenRead(path);
fs.ReadExactly(head);
var h = Encoding.ASCII.GetString(head).TrimEnd(' ', '\0').Split(':');
// h[0]="ClamAV-VDB", h[2]=version, h[3]=sigCount(metadata), h[4]=flevel, h[5]=payload MD5

fs.Position = 512;
var md5 = Convert.ToHexString(MD5.HashData(fs)).ToLowerInvariant();  // compare with h[5]

fs.Position = 512;
using var gz = new GZipStream(fs, CompressionMode.Decompress);
using var tar = new TarReader(gz);
while (tar.GetNextEntry() is { } e)
{
    if (e.DataStream is null) continue;
    using var sr = new StreamReader(e.DataStream, Encoding.Latin1);
    // e.Name = "daily.hdb" ... -> choose the parser by extension
}
```

[ClamGuard] `CvdReader.cs` — streaming, size caps, bounds-checked header.

### 17.2 Parser selection by extension

| Ext | Parser |
|-----|--------|
| hdb, hdu, hsb, hsu | `Hash:Size:Name[:min[:max]]` — algorithm by hash length |
| mdb, mdu, msb, msu | `Size:Hash:Name[:min[:max]]` — PE section hashes |
| fp, sfp | allow-list `Hash:Size:Id` |
| ndb, ndu | `Name:Target:Offset:Hex[:min[:max]]` |
| ldb, ldu | split `;` -> name, TDB, expression, subsigs |
| cdb | 10 fields, regex in the middle |
| idb | 4 fields, 124-hex hash |
| crb | split `;` (11 fields, keep empties) |
| ftm | `Type:Offset:Hex:Name:Req:Det[:min[:max]]` |
| pdb, wdb | `Type:Value[:Value2]` |
| cfg | `Cat:MaskHex:min:max` |
| ign / ign2 | ignore by (DB:line) / by name |
| info, COPYING | manifest check / skip |

### 17.3 Per-line validation regexes ([measured] ran over the whole build 28146)

```csharp
const string H32 = @"[0-9a-fA-F]{32}", H40 = @"[0-9a-fA-F]{40}", H64 = @"[0-9a-fA-F]{64}";
const string NAME = @"[^:;\s][^:;]*";   // do NOT use \S+ — names may contain spaces

var Rx = new Dictionary<string,string> {
 ["hdb"]=$@"^{H32}:\d+:{NAME}(:\d+){{0,2}}$",
 ["hsb"]=$@"^({H32}|{H40}|{H64}):(\d+|\*):{NAME}(:\d+){{0,2}}$",
 ["mdb"]=$@"^\d+:({H32}|{H40}|{H64}):{NAME}(:\d+){{0,2}}$",
 ["fp"] =$@"^({H32}|{H40}|{H64}):\d+:{NAME}$",
 ["ndb"]=$@"^{NAME}:\d+:(\*|\d+(,\d+)?|EP[+-]\d+(,\d+)?|S\d+\+\d+(,\d+)?|SE\d+(,\d+)?|SL\+\d+(,\d+)?|EOF-\d+(,\d+)?):[^:]+(:\d+){{0,2}}$",
 ["idb"]=$@"^{NAME}:[^:]+:[^:]+:[0-9a-fA-F]{{124}}$",
 ["ftm"]=@"^[014]:(\*|\d+|\d+,\d+|EOF-\d+):[^:]+:[^:]+:CL_TYPE_\w+:CL_TYPE_\w+(:\d*){{0,2}}$",
 ["cfg"]=@"^[A-Z]+:0x[0-9a-f]+:\d+:\d+$",
 ["wdb"]=@"^[MX]:[^:]+:[^:]+$",
 ["pdb"]=@"^[HRDSMXY]:[^:]+(:.*)?$",
 ["crb"]=@"^[^;]+;[01];[0-9a-f]{{40}};([0-9a-f]{{40}})?;[0-9a-fA-F]+;[0-9a-fA-F]+;[01];[01];[01];[^;]*;[^;]*(;\d+){{0,2}}$",
 ["ldb"]=@"^[^;:\s][^;:]*;[^;]+;[^;]+;[^;]+(;[^;]+)*$",
};
```

[measured] Verification results: hdb 23/23, hdu 39/39, hsb 54,681/54,681, mdb 11,575/11,575,
mdu 315/315, fp 483/483, ndb 319/319, idb 222/222, cdb 5/5, cfg 21/21, pdb 263/263, wdb 185/185,
ftm 268/268, ldu 10,166/10,166, crb 30/30, ign2 22/22, **ldb 273,471/273,473** (2 exceptions:
section 16.2 and the name-with-space line).

### 17.4 Matching order for one file

1. Determine the file type (`.ftm`) -> `CL_TYPE_*`.
2. Whole-file hashes + size -> `.fp/.sfp` (allow-list — a hit **stops** the scan), then
   `.hdb/.hsb`.
3. If PE: hash each section -> `.mdb/.msb`.
4. Hex scan `.ndb` (by Target/Offset).
5. Scan `.ldb` (count subsigs -> evaluate the expression).
6. If a container: `.cdb` over child metadata.
7. PE with icons: `.idb`; PE with digital signatures: `.crb`.
8. Apply `.ign2` / FLevel / PUA in the policy layer, after candidates exist.

### 17.5 Performance

- [measured] `.ldb` has ~1.35M subsigs: build **one** Aho-Corasick over the pure-hex segments
  (split at `*`/`{}`), run PCREs only when their trigger is true, lazy-load if needed.
- Hashes: index by `(algorithm, size)` or `(size, hash)`, split tables by hash length.
- [ClamGuard] all of this is implemented — AC frozen + dense tables, the logical anchor prefilter,
  normalize/context memoization, hash-once-per-section (see the `fix(scanner)`/`perf` commits).

### 17.6 Layered architecture (general recommendation)

```text
CvdReader (header/manifest/verify)  ->  SignatureDatabaseLoader (parser per ext)
  ->  CompiledSignatureSet (AC/hash buckets/prefilter)  ->  ScannerPipeline
  (file-type -> container -> normalize -> hash -> pattern -> logical -> PE -> policy)
  ->  DetectionResult (name, evidence, PUA/suppression context)
```

Practical build order: file hashes -> basic NDB -> FTM -> LDB -> containers -> PE sections/icons
-> phishing -> policy databases. [docs] **Parsing the whole database does not equal ClamAV
compatibility** — the hardest parts are normalization/preprocessing, nested unpacking, PE
parsing, phishing heuristics and per-version FLevels.

---

## 18. Test plan

- **Parsers**: correct record counts per extension as in the section 3 table; lines with empty
  fields, trailing delimiters, `*` sizes, empty FLevel, long names; variable `.ldb` subsig
  counts; malformed records -> errors carrying file+line+reason.
- **Hashes**: EICAR appears both as MD5 and SHA-256; a 1-byte size mismatch must not match;
  changing one byte of the file must break the match; `.mdb/.msb` hashes **sections**, not the
  whole file.
- **Body/Logical**: fixtures for every token `??`, `a?`, `?a`, `*`, `{n}`, `{n-m}`, `[n-m]`,
  alternation, offsets `EOF/EP/SE/S/VI`; LDB: AND/OR/negation/count/target/Engine ranges.
  Compare against `clamscan` with a custom test database when available.
- **Nesting/normalization**: ZIP with double-extension children (`.cdb`); PE 32/64-bit (section
  hashes); HTML/mail with display-URL != real-URL (`.pdb/.wdb`); HTML with whitespace/case
  differences (normalization).
- Use **EICAR only** for pipeline testing — never real malware samples outside an isolated
  environment.

---

## 19. Quick reference

| Extension | Structure | Role during scanning |
|---|---|---|
| `.hdb/.hdu` | `MD5:Size:Name` | Whole-file MD5; `.hdu` = PUA |
| `.hsb/.hsu` | `Hash:Size:Name[:FL]` | Whole-file hash by hash length |
| `.mdb/.mdu`, `.msb/.msu` | `SectionSize:SectionHash:Name[:FL]` | PE section hashes (size first) |
| `.fp/.sfp` | `Hash:Size:Label` | False-positive allow-list (clears detections) |
| `.ndb/.ndu` | `Name:Target:Offset:HexPattern[:FL]` | Byte patterns + wildcards + offsets |
| `.ldb/.ldu` | `Name;TDB;Expr;Subsig...` | Multiple subsigs + logical expression (AST) |
| `.idb` | `Name:Group1:Group2:FuzzyHash(124hex)` | Icon fuzzy match, linked via LDB IconGroup |
| `.cdb` | `Name:ContainerType:...:FileNameRegex:...` | Container child metadata |
| `.pdb` | `H:Host` / `R:Regex` | Phishing heuristics (after normalization) |
| `.wdb` | `M:RealHost:DisplayedHost`, `X:/Y:` | Phishing allow-list |
| `.ftm` | `Type:Offset:Magic:Name:Req:Det[:FL]` | File-type detection |
| `.cfg` | `Category:Flags:StartFL:EndFL` | Engine configuration per FLevel |
| `.crb` | `Name;Trusted;Subject;...` | PE certificate trust/revocation |
| `.ign2` / `.ign` | SigName [:MD5Entry] / legacy | Signature suppression |
| `.info` | `Name:Size:SHA256` + header/DSIG | Archive integrity manifest |

---

## 20. Appendix — one-line samples

```text
hdb : 943e487c31a3d7929cb19a433ff25329:11250688:Win.Ransomware.RansomHub-10037316-0
hdu : c43ac9caa088f1cf5e4c388feda73e5a:16920:PUA.Win.Tool.ANVCracker-1
hsb : b09c6279c1e0760c3e383f85d0488329:69488:Pdf.Dropper.Agent-8087615-0:73
hsb* : cb9e4424771c1f84279aceb0ca31f93e:*:Win.Exploit.CVE_2020_1381-8449591-1:73
hsb(sha256): 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:Eicar-Test-Signature
mdb : 51200:a87eeb45beeabc044bfeb435241dd164:Win.Trojan.Kronos-1
msb : 91648:550a9b573224aa75418c852080b59af3:Win.Packer.Agent-6412293-0:73
fp  : 332feab1435662fc6c672e25beb37be3:2871808:sid25347313-1
sfp : 6bed1a3a956a859ef4420feb2466c040800eaf01ef53214ef9dab53aeff1cff0:2871808:sid25347313-1
ndb : Win.Malware.Emotet-6450824-0:1:EP+0,15:83e0038935{4}893d{4}8925{4}892d{4}891d{4}a1{4}ffd0:70
ndu : PUA.Win.Packer.PECompact-3:1:EP+0:eb0668[4-4]c3:58
ldb : Js.Ransomware.Locky-30743;Engine:51-255,Target:7;0 & 1 > 200;222e73706c697428276d73656d736527293b;6d73656d7365
ldu : PUA.Win.Tool.Hacktool-1833;Engine:51-255,Target:1;(0&1&2);64756d705f75736564686173686573;6773656364756d70;2d2d69616d73657276696365
cdb : Email.Trojan.Toa-1:CL_TYPE_ZIP:*:Courrt.{1,15}\.scr$:*:*:*:*:*:
idb : Win.Trojan.GenericFD-2:DOCUMENT:BIFROSE:20bc70f03b0d02032ad0d100060017049000c073160bfb00...(124 hex)
crb : Trusted.CA.Microsoft-4546341-1;1;adf79877...(40);f5ceafcf...(40);a902bdc1...(modulus);010001;1;1;1;;Microsoft Root Authority MD5 1997-2020 00:c1:...
ftm : 1:*:3c5441424c45(3e|20|09|0a|0b|0c|0d|2f):HTML data:CL_TYPE_ANY:CL_TYPE_HTML
pdb : H:capitalone.com
wdb : X:.+\.commerzbank\.com([/?].*)?:.+\.commerzbank\.de
cfg : PE:0xb4ff:13:23
ign : fake:1:Dont_remove_this_line
ign2: Win.Trojan.Ramnit-6197
```

---

## 21. Official references

1. [Creating signatures / Database formats](https://docs.clamav.net/manual/Signatures.html)
2. [Body-based Signature Content Format](https://docs.clamav.net/manual/Signatures/BodySignatureFormat.html)
3. [Extended Signatures](https://docs.clamav.net/manual/Signatures/ExtendedSignatures.html)
4. [Logical Signatures](https://docs.clamav.net/manual/Signatures/LogicalSignatures.html)
5. [Hash-based Signatures](https://docs.clamav.net/manual/Signatures/HashSignatures.html)
6. [Container Metadata Signatures](https://docs.clamav.net/manual/Signatures/ContainerMetadata.html)
7. [Phishing Signatures](https://docs.clamav.net/manual/Signatures/PhishSigs.html)
8. [File Type Magic](https://docs.clamav.net/manual/Signatures/FileTypeMagic.html)
9. [Dynamic Configuration](https://docs.clamav.net/manual/Signatures/DynamicConfig.html)
10. [Trusted and Revoked EXE Certificates](https://docs.clamav.net/manual/Signatures/AuthenticodeRules.html)
11. [Allow List Databases](https://docs.clamav.net/manual/Signatures/AllowLists.html)
12. [Database Info](https://docs.clamav.net/manual/Signatures/DatabaseInfo.html)
13. [Signature Naming Guidelines](https://docs.clamav.net/manual/Signatures/SignatureNames.html)
14. [File Types and Target Types](https://docs.clamav.net/appendix/FileTypes.html)

> Final note: this document describes the records seen in build 28146, interpreted through the
> official documentation plus the 1.5.4 sources — it is the basis for designing parsers/matchers
> and **does not guarantee 100% ClamAV compatibility**. The hardest parts: normalization/
> preprocessing, nested unpacking, PE parsing, pattern grammar, logical expressions,
> icon/phishing handling, and FLevel differences between engine versions.
