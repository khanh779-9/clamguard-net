# Source Responsibility Mapping

This document maps high-level responsibilities identified during analysis of ClamAV 1.5.x to independently designed ClamGuard.NET components.

| Responsibility | ClamGuard.NET component |
|---|---|
| Database extension dispatch | `ClamGuard.Database.DatabaseLoader` + `ClamGuard.Signatures.Parsing.SignatureParser` |
| CVD header parsing | `ClamGuard.Database.CvdReader.ReadHeader` |
| Database metadata API | `ClamGuard.Database.DatabaseLoader.ReadInfo` |
| Hash signature ingestion | `ClamGuard.Signatures.Parsing.SignatureParser.ParseHashFile` |
| NDB ingestion | `SignatureParser.ParseNdbFile` |
| LDB ingestion | `SignatureParser.ParseLdbFile` |
| Fixed byte matching | `AhoCorasickMatcher` |
| Flexible hex matching | `HexPattern.Matches` |
| Whole-file hashing | `CompiledSignatureSet.Match` |
| Logical expression evaluation | `ScannerEngine` + `ExpressionEvaluator` |
| Scanner orchestration | `ScannerEngine` |
| Full database download | `ClamGuard.Database.Update.DatabaseUpdater` |
| Database smoke validation | temporary extraction + `DatabaseLoader` |
| Atomic activation | `DatabaseUpdater.AtomicReplace` |

The mapping is intentionally responsibility-oriented rather than source-line-oriented. ClamGuard.NET uses different type boundaries, state management and control flow.
