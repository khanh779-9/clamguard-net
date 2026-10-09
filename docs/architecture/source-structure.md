# Source structure — ClamGuard.NET

This note describes module boundaries for the current solution. File extensions are grouped by **format family**; each parser receives the concrete extension/path and applies the family-specific rules.

## Projects

- `ClamGuard.Core`: shared scan results, options, enums and primitives.
- `ClamGuard.Signatures`: signature models, hex-pattern representation, parsers and matching indexes.
- `ClamGuard.Database`: database discovery/loading, CVD verification, atomic database generations and `Update/` (download/CDIFF application).
- `ClamGuard.Scanner`: scan orchestration, raw/logical matching, PE inspection, archive/document extraction and bounded host/lifecycle management in `Hosting/`.
- `ClamGuard.Yara`: supported YARA-compatible rule parser/evaluator.
- `ClamGuard.Bytecode`: ClamBC interpreter, with parser, virtual-machine API handlers and compact models separated by responsibility.
- `ClamGuard.Antivirus`: WPF UI.
- `tests/ClamGuard.Tests`: executable regression harness.

## Scanner layout

```text
ClamGuard.Scanner/
  ScannerEngine.cs                 Public scan entrypoints and streaming/file workflow
  Engine/                          Partial implementations split by responsibility
  Archives/                        Managed/external archive decoding helpers
  Containers/                      Container metadata matching and recursive scanning
  Content/Logical/                 Logical runtime, expression, content and regex matching
  Detection/                       File-type magic and scan-target policies
  Executable/                      PE/ELF/Mach-O executable inspection and version regions
  Image/                           Icon/resource image decoding and hashing
  Models/                          Small PE/LDB model types
  Pe/                              PE sections/imports/overlay and hash scans
  Specialized/                     Dispatcher plus embedded document, OneNote, XDP and HTML handlers
  Hosting/                         Scan admission, timeouts, health, metrics and shutdown
```

## Signature layout

```text
ClamGuard.Signatures/
  Signature.cs and ContentMatchOptions.cs
  Models/                          One signature/model per file
  Patterns/                        Pattern atoms and compiled byte pattern model
  Matching/                        Aho-Corasick, BMH, content comparer and indexed matcher
  Parsing/Common/                  Shared parsing helpers and ERE compatibility
  Parsing/Content/Ldb/             Logical signatures and logical subsignatures
  Parsing/Content/Ndb/             Extended/self-protection signatures
  Parsing/Hash/                    File, PE-section, import and false-positive hashes
  Parsing/Container/               Container and embedded-member signatures
  Parsing/Metadata/                Icon metadata/signature-family entrypoints
```


## Bytecode and WPF organization

```text
ClamGuard.Bytecode/
  ClamBcEngine.cs                   Public load/scan facade
  Parsing/ClamBcParser.cs           Text parser for ClamBC programs
  Runtime/ClamBcVirtualMachine.cs   Instruction execution and core memory operations
  Runtime/ClamBcVirtualMachine.Api.cs
                                    API handlers exposed to bytecode programs
  Models/                            Program, instruction, operand, and runtime-state models

ClamGuard.Antivirus/
  MainWindow.xaml.cs                Window setup, navigation and scan/update actions
  MainWindow.ThreatHandling.cs      Result presentation and quarantine lifecycle
  ViewModels/
    MainViewModel.cs                State, properties, event/command wiring
    MainViewModel.Scanning.cs       Scan workflows and database update entrypoint
    Commands/                       One relay-command type per file
  Theme/
    Controls.xaml                   Merges the focused control dictionaries in dependency order
    Controls.Converters.xaml        UI converters
    Controls.Cards.xaml             Card, typography and metric styles
    Controls.Buttons.xaml           Primary/secondary and window-button styles
    Controls.Status.xaml            Navigation, toggle and status styles
    Controls.Scrolling.xaml         ScrollBar and ScrollViewer templates
    Controls.Inputs.xaml            ComboBox and ComboBoxItem templates/styles
    Controls.DataGrid.xaml          Table, row, cell and header styles
    Controls.Misc.xaml              ProgressBar and ToolTip styles
```

## Current scope vs format inventory

Not every file extension in the ClamAV cache is a body-signature parser. CVD/CLD/CUD archives and update deltas belong to `Database/Update`; `.yar/.yara` rules belong to `ClamGuard.Yara`; `.cbc` rules belong to `ClamGuard.Bytecode`. Specialized families such as `.cfg`, `.ftm`, `.info`, `.ign/.ign2`, `.pdb/.wdb/.gdb`, `.crb/.cat`, `.fp/.sfp` and `.idb` are dispatched through the database loader or dedicated parser/model entrypoints. Keep their formats isolated in small, focused components rather than forcing them into the LDB/NDB parser logic.

`.ldu`, `.ndu`, `.hdu`, `.hsu`, `.mdu` and `.msu` are PUA-related database files in ClamAV's loader behavior, not a generic suffix meaning “all database updates”.
