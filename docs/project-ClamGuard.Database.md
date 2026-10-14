# project-ClamGuard.Database

> The layer that **loads, verifies and updates** signature databases: unpacks CVD/CLD containers,
> parses every database format (including FTM/DCONF/phishing/certificates), checks integrity
> (manifest + RSA signatures) and applies CDIFF patches during updates.

---

## 1. Project facts

| Property | Value |
|---|---|
| Target framework | `net8.0` |
| Dependencies | `ClamGuard.Core`, `ClamGuard.Signatures`, `ClamGuard.Yara` (.yar databases), `ClamGuard.Bytecode` (.cbc databases) |
| Source files | 15 |

```text
Loading/       CvdReader, DatabaseLoader, DatabaseLoader.Specialized, IgnoreRuleSet
Storage/       SignatureDatabase, SpecialDatabaseModels, DynamicConfiguration
Verification/  DatabaseVerifier, ClamAvSignatureVerifier, DetachedCmsVerifier
Update/        DatabaseUpdater, CdiffPatchApplier
DatabaseManager.cs
Models/        DatabaseLoadResult, DatabaseLoadError
```

## 2. Database load flow

```text
DatabaseManager.LoadAndCompile(directory, failOnInvalidFile, pua..., cacheDirectory)
  -> DatabaseLoader.LoadDirectory
       +- CvdReader: 512B/9-field header -> verify payload MD5 -> tar.gz extraction
       +- daily.cld vs daily.cvd selection by version (cld wins on ties — ClamAV parity)
       +- Persistent cache: reuse the old extraction folder (same version)
       +- Extension -> parser (project Signatures) or special-db loaders (section 3)
       +- IgnoreRuleSet (.ign/.ign2) filters BEFORE parsing
       +- DatabaseVerifier: manifest (header copy, dup-entry, size, sha256, unlisted-file)
  -> SignatureDatabase.Compile()  -> CompiledSignatureSet (project Signatures)
  -> published via Volatile.Write (monotonic generation) — in-flight scans keep the old state
```

## 3. Special database loaders (`DatabaseLoader.Specialized.cs`)

| File | Handling |
|------|----------|
| `.ftm` | File-type magic rules -> `SpecialDatabases.FileTypes` |
| `.cfg` | DCONF -> `DynamicConfiguration` (resolves "sequential assignments, later entry wins") |
| `.pdb/.wdb` | Phishing domain/allow-list (XML-safe) |
| `.crb` | Certificate trust/revoked (public-key hex validation) |
| `.cat/.ioc` | Other special databases |
| `.yar/.yara` | Through project Yara |
| `.cbc` | Through project Bytecode |
| `.info` | Manifest (header copy with MD5/DSIG replaced by `X`, 23 `name:size:sha256` lines) |

XML parsing always uses `DtdProcessing.Prohibit` + `XmlResolver = null` (XXE-safe); blank `.wdb`
lines are rejected deliberately.

## 4. Verification (`Verification/`)

| Class | Role | Technical detail |
|-------|------|------------------|
| `DatabaseVerifier` | Archive manifest check | Header copy matches, no duplicate entries, per-member size + SHA-256, detects **unlisted files**; legacy CVDs must carry a valid dsig |
| `ClamAvSignatureVerifier` | CVD/daily.info signatures | **PSS2**: RSA-PSS/SHA-256/salt-32 per **RFC 8017** (MGF1/EM layout traced); **legacy CVD**: raw RSA over the 16-byte MD5 with ClamAV's lowercase-first/little-endian radix-64 variant; 3 hardcoded ClamAV public keys |
| `DetachedCmsVerifier` | Detached certificates (online updates) | Runs `openssl cms -verify` — strict resolution: `AppContext.BaseDirectory` -> `C:\Program Files\OpenSSL*\bin` -> PATH (**exact name** `openssl.exe`, no PATHEXT); **not found = fail closed** (never treated as Verified); both stdout and stderr drained before `WaitForExit` (pipe-deadlock safe); timeout kills the entire process tree |

Note: only `.cvd` carries a dsig; `.cld/.cud` do not by ClamAV design. Detached verification runs
only inside `DatabaseUpdater` when a certificates folder is configured.

## 5. Update (`Update/`)

### 5.1. `DatabaseUpdater`

Flow: **download -> verify -> smoke-test -> atomic replace**. Official ClamAV URLs; temp files use
GUIDs; `File.Delete(temp)` is guarded.

### 5.2. `CdiffPatchApplier` — applying a `daily.cdiff` patch

Safety order (hardened):

1. **Parse metadata only**: header `ClamAV-Diff:v:len`, footer signature, digest
   `SHA256(patch[0..footer])` — computable **without decompressing**.
2. **Verify the signature BEFORE decompressing** + early-reject `expectedScriptBytes > MaxScriptBytes`.
3. **Bounded decompression**: 64KB chunk reads; exceeding `MaxScriptBytes` throws
   `InvalidDataException` immediately (~32MB + buffer in RAM at most — decompression bombs are
   neutralized).
4. The script is text: `OPEN/ CLOSE/ XCHG/ ADD/ MOVE/ UNLINK/` commands over database files.
5. **Staging + atomic publish**: `DatabaseUpdater.ApplyCdiffAsync` copies the live DB into a
   staging sibling (same volume), applies the patch there; only on success are files
   `File.Move(overwrite)`-d into place + UNLINK deletions synced; **any failure leaves the live
   directory untouched** and the staging folder cleaned.
6. **Line fidelity**: each file's newline style (`\r\n` vs `\n`) is detected and re-emitted —
   byte-identical to upstream `cdiff.rs` for standard LF databases.
7. Latent bug fixed: `Close()` used to call `File.Replace` while the `StreamWriter` handle was
   still open, so every CLOSE-with-edits failed on Windows; the writer is now disposed explicitly
   before replacing.

Reference logic: `libclamav_rust/src/cdiff.rs` (ClamAV 1.5.4) — pops `\n`, ADD keeps raw script
bytes, MOVE rewrites src in src style and appends in dst style.

## 6. `DatabaseManager` & `SignatureDatabase`

```csharp
var manager = new DatabaseManager();                 // empty state
var state = manager.LoadAndCompile(dir, true);       // load + compile + publish
state.Database; state.Compiled; state.Generation;    // immutable snapshot
manager.Current;                                     // Volatile.Read — scans always see a consistent state
```

- Publishing uses `Volatile.Write` — **scan is never blocked**: an in-flight scan holding the old
  `CompiledState` finishes with it; new scans see the new generation.
- `SignatureDatabase` caches typed arrays (`NdbSignatures`, `LogicalSignatures`, `MetadataSignatures`,
  `CdbSignatures`, `HashSignatures`) — invalidated on `Add`/`AddRange`; `Compile()` pre-materializes
  to avoid per-file LINQ loops.
- `HasSelfProtectionSignatures` is cached (`.sdb` self-protection — the engine scans itself).

## 7. Thread-safety & lifecycle

- `DatabaseManager.Current` is the single volatile read point — generation races between
  concurrent `LoadAndCompile` calls are tolerated (sequential publish, monotonic generation).
- Loading is heavy (bytes + AC compile) — run from a background thread; the UI layer (project
  Antivirus) wraps it in a single-flight.

## 8. Testing

`Program.DatabaseTests.cs` (13): hex parsing, HDB, valid + malformed CVD headers, raw-tar
extraction, cld/cvd selection (newer/older/tied), truncated payload, LDB precedence `0&1|2`.
Update/CDIFF + DetachedCmsVerifier are covered by a dedicated harness (13/13 PASS during
hardening: gzip-bomb rejection, staging rollback, newline fidelity, XCHG mismatch).
