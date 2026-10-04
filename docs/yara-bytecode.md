# YARA and ClamBC integration

## YARA

`ClamGuard.Yara` is an optional project referenced by `ClamGuard.Scanner`. It provides a managed YARA-compatible subset without a mandatory native dependency. Supported rule features include text strings, `ascii`, `wide`, `nocase`, `fullword`, `xor`, exact hexadecimal strings, regular-expression strings with a timeout, boolean conditions, `any/all of them`, `N of (...)`, and basic `filesize` comparisons. YARA rules are executed for root files, PE overlays, Mach-O slices, and materialized nested archive/document children.

The project deliberately does not claim complete YARA language parity. Advanced modules, imports/includes, externals, rich arithmetic/loop conditions, and every hex-string construct remain outside the managed subset.

CLI example:

```bash
dotnet run --project src/ClamGuard.Cli -- scan sample.exe --db path/to/db --yara path/to/rules
```

## ClamBC

`ClamGuard.Bytecode` is a separate optional managed interpreter. It accepts ClamBC format 6/7 text files, applies functionality-level and file-kind gating, parses functions/basic blocks/core opcodes, and exposes a bounded file/memory API surface. Execution is constrained by instruction count, call depth, and per-rule allocation budgets.

The managed interpreter intentionally does not claim full native ClamAV bytecode ABI parity. PE/PDF hook structures, unpacking/extraction APIs, JIT behavior, complex hashset/map/buffer-pipe APIs, and other specialized native hooks remain separate work.

CLI example:

```bash
dotnet run --project src/ClamGuard.Cli -- scan sample.exe --db path/to/db --bytecode path/to/cbc
```
