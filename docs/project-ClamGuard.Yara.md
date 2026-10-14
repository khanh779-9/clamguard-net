# project-ClamGuard.Yara

> A managed **YARA subset emulator**: parses rules (basic strings + conditions), scans buffers
> and reports matches. This is not a libyara binding — the class names carry "Yara" to align with
> the concept, and the class documentation states the subset scope plus the warning mechanism for
> unsupported constructs.

---

## 1. Project facts

| Property | Value |
|---|---|
| Target framework | `net8.0` |
| Dependency | `ClamGuard.Core` |
| Source files | 3 (`YaraEngine.cs`, `YaraModels.cs`, `YaraContentScanner.cs`) |

## 2. Honest support matrix

| Group | Supported | Unsupported (-> warning, rule skipped with a reason) |
|-------|-----------|------------------------------------------------------|
| Strings | Plain `"..."`, plain hex | Hex wildcards `??`, jumps `{n}`/`{n-m}` |
| Modifiers | `nocase`, `ascii`, `xor` (xor over the original bytes, case-insensitive compare) | `wide` on **regex** (warns), unusual combos |
| Regex literals | `/.../ ` with correct `\/` escaping | |
| Conditions | `and/or/not`, count, `filesize` (bytes) | `filesize > 100KB` (KB/MB suffixes), `N of (...)`, globs `($a*)`, `for`, modules (`pe.`...), unrecognized conditions |
| Identifiers | **Case-sensitive** (matches YARA) | |
| Other | MaxRules truncation -> warning | |

## 3. Key technical points

### 3.1. Comment stripper as a state machine (critical fix)

The old implementation used `Regex.Replace(text, @"//.*?$")`, which destroyed string literals
containing `//` (`$a = "http://evil.com"` lost its closing quote -> rule parse failure ->
**mass false negatives**; URLs are extremely common in YARA rules). It is now a state machine
that respects:

- string literals `"..."` with `\` escapes; char literals `'...'`;
- regex literals `/.../` — a `/` only opens a regex at a **value boundary** (after `=`, `(`,
  whitespace, an operator); inside a regex `\/` is an escape;
- `//` and `/* */` are only removed outside literals; an unterminated `/*` keeps the text verbatim.

### 3.2. Warning mechanism (no more silent drops)

`YaraEngine.Warnings` (`IReadOnlyList<string>`, public) + `YaraMatch.Warnings` (per rule,
init-only, empty by default). Every case where a rule is skipped or silently false emits a
warning, for example:

```text
rule 'X': hex string '$a': wildcards ('?') unsupported; string ignored
rule 'X': unsupported condition 'filesize > 100KB' ignored
YARA rule limit reached (MaxRules = N); additional rules were ignored
```

Load-time validation (`ValidateConsume`) catches non-consumable tokens **before** scanning — an
unsupported rule is reported as "skipped with a reason", never as "no match".

### 3.3. Scanning

`YaraEngine` performs a naive O(rules x filesize) scan — acceptable for test/sample use cases,
not for large databases (nothing like the Aho-Corasick in project Signatures). Xor/nocase
variants are applied in the correct order. `YaraContentScanner` is the `IContentScanner` adapter
(attached via `ScanOptions.YaraRuleDirectory`); project Database loads `.yar` as a special
database.

## 4. Roadmap

1. Renaming/documentation is done (subset emulator). For full YARA: bind native libyara or
   translate rules into the engine's LDB/NDB formats.
2. Hex wildcards + `of` conditions are the most natural next extensions (the warning scaffolding
   is already in place).
3. Performance: for large rule sets, add a pattern index similar to the Signatures prefilter.

## 5. Testing

`Program.YaraBytecodeTests.cs`: the inline rule `condition: $mz and $hello` matches `$hello`
through a nested archive; a 27/27 behavioral harness ran during hardening (URLs inside strings
survive the comment stripper, xor+nocase, case-sensitive identifiers...).
