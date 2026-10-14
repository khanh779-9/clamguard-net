# project-ClamGuard.Antivirus

> The end-user WPF desktop application: the scanning UI, real-time protection, quarantine, the
> system inspector, the toolkit and database updates. MVVM-lite with an event broker, EN/VI
> localization, Light/Dark theming and custom-drawn toasts/dialogs (custom window chrome).

---

## 1. Project facts

| Property | Value |
|---|---|
| Target framework | `net8.0-windows`, `WinExe` |
| Dependencies | `ClamGuard.Core`, `ClamGuard.Database`, `ClamGuard.Scanner` |
| Source files | 58 (Views 9x2, Services 11, Controls 11, Theme 12, Localization 4, ViewModels 6, Models 6) |
| Cross-platform build | `EnableWindowsTargeting=true` (CI runs on ubuntu too) |
| Manifest | non-admin, `supportedOS` Win10; system-aware DPI |

## 2. Overall architecture

```text
App.xaml(.cs)                  Composition root: merges resources (Converters -> LightTheme -> Icons ->
                               Controls -> ClamGuardWindow), initializes Settings/Theme/Localization,
                               global exception handlers (Dispatcher/AppDomain/UnobservedTask)
MainWindow (.xaml/.cs)         Shell: sidebar nav (RadioButton+Tag), header, progress, ContentControl
MainWindow.ThreatHandling.cs   Scan-result handling: toasts, action policy, quarantine restore/delete
Views/                         Overview, Scan, Security, System, History, Quarantine, Tools, Update, Settings
ViewModels/                    MainViewModel (+partial Scanning) — state + 32 commands + 23 events
                               Commands: RelayCommand, AsyncRelayCommand (reentrancy guard), ParameterRelayCommand
Services/                      AntivirusEngineService, RealtimeProtectionService, QuarantineService,
                               MemoryScanService, StartupScanService, SystemInspectorService,
                               ActiveTaskTracker, ThemeService, LocalizationService, JsonSettingsStore, AppPaths
Models/                        ActiveTaskItem (INPC), QuarantineItem, ScanHistoryItem, ScanProgress,
                               ScanResultRowItem, SystemSnapshot
Controls/                      ClamGuardWindow (chrome+toast+dialog API), ClamGuardDialog, ClamGuardToast(+Host),
                               DesktopToastWindow, LoadingOverlay, ToastKind
Theme/                         DarkTheme/LightTheme (44 brushes, 1:1 parity), Controls.{Buttons,Cards,Inputs,
                               DataGrid,Scrolling,Status,Misc,Converters}, Icons (~30 geometries)
Localization/                  LocalizationService + LocExtension + en-US.lng + vi-VN.lng
```

**MVVM-lite flow**: views bind two-way into `MainViewModel`; the VM raises **events** (23,
e.g. `QuickScanRequested`) that the `MainWindow` code-behind handles (dialogs, navigation,
service calls). Async plumbing: `Progress<T>` marshals to the UI thread,
`SynchronizationContext.Post` in the memory scan, no `.Result/.Wait()` anywhere.

## 3. Services in detail

### 3.1. `AntivirusEngineService` — the engine facade

- Init is **single-flight** (a `Task` field): a second call during initialization returns the same
  Task instead of returning early while the database is not ready.
- `ScanFileAsync` / `ScanFolderAsync` (`Parallel.ForEachAsync`, MaxDegreeOfParallelism <= 4,
  symlink/reparse handling, directory dedupe) / `ScanMemoryBufferAsync` / `UpdateDatabaseAsync`.
- `EnumerateScanFiles` **enforces the advertised `options.MaxFiles`** (default 10,000 — streaming
  enumeration stops, `LimitReached=true` -> heuristic + UI notification).
- Changing `DatabaseDirectory` persists settings and reloads the engine.

### 3.2. `RealtimeProtectionService` — FileSystemWatcher

| Aspect | Detail |
|--------|--------|
| Watch | Single folder (`IncludeSubdirectories`), `InternalBufferSize = 64KB` |
| Debounce | `ConcurrentDictionary<path,CTS>` — a new event **cancels** the previous one (900ms delay); a generation token: a task that already passed the delay and is scanning still compares its entry after the scan and discards the result if replaced (no double-quarantine) |
| Wait for writes | `WaitUntilReadableAsync`: 5 attempts x ~300ms; scans once the length is stable; giving up raises Error |
| Watcher overflow | Error -> restart the watcher + **re-schedule the 500 newest files** (best-effort recovery) |
| Exclusions | The database folder (self-protection), dotfiles, directories |
| Lifecycle | Stop(): cancel + clear; CTS disposed in the owning task's `finally` |

### 3.3. `QuarantineService` — the encrypted quarantine

- **Seal**: the file body is encrypted with **streamed AES-256-CBC** (1MB chunks — large files
  never materialize in RAM); the 32B key + 16B IV are sealed with **DPAPI** (crypt32 via
  P/Invoke) — only the current user can decrypt; header `MCGQ` + version 2; legacy plaintext
  entries remain restorable.
- Index `index.json`: atomic write (`.tmp` + `File.Move(overwrite)`), RMW under a lock.
- `Restore`: validates the target is **not inside the store** (blocks the write-primitive from a
  tampered index), decrypts as a stream, `FileAttributes.Normal`.
- `Delete`: clears ReadOnly before `File.Delete` (the old bug made it fail 100% of the time).
- The realtime "Delete" action goes **through quarantine** (recoverable on false positives).

### 3.4. `MemoryScanService` — process memory scanning

`OpenProcess(VM_READ|QUERY_INFORMATION)` + a `VirtualQueryEx` walk (<= `0x7FFFFFFEFFFF`), only
MEM_PRIVATE regions or MEM_IMAGE regions with execute/copy flags; the budget gates **collection**
(no materialize-everything-then-check); all-zero regions are skipped; 1MB chunks + 4KB overlap
(catches signatures split across boundaries); Process handles are disposed. No admin required —
unreadable processes are skipped and counted.

### 3.5. `SystemInspectorService` — profile + file inspector

- Snapshot: OS/arch/CPU/RAM (`GlobalMemoryStatusEx`), drives, networks, processes, startup
  (Run/RunOnce HKLM/HKCU/WOW64, Startup folders, auto services).
- **File inspector**: SHA-256, version info, and a *real* signature check: validity window +
  **X509Chain** (online revocation, exclude-root) + the **code-signing EKU**
  (`1.3.6.1.5.5.7.3.3`) — self-signed certificates can no longer show "valid".

### 3.6. The rest

| Service | Main role |
|---------|-----------|
| `StartupScanService` | Collects autostart entries -> resolves executables (strips `\??\`, quoted paths, longest-prefix) |
| `ThemeService` | Swaps the Light/Dark dictionary in place; `Auto` reads the `AppsUseLightTheme` registry value |
| `LocalizationService` | Singleton; loads `.lng` **external first -> embedded fallback**; `Item[]` INPC indexer for `{loc:Loc}` bindings; `Format` with args |
| `JsonSettingsStore` | Atomic write (`.tmp` + move); Load falls back to `.tmp` when the main file is corrupt; migrates legacy paths |
| `AppPaths` | Paths: settings (LocalAppData), database/quarantine/cache (ProgramData), `EnsureDirectories` |
| `ActiveTaskTracker` | Registry of running tasks + aggregate progress; CTS lifecycle |

## 4. The Tools page — a six-tool toolkit

| Tool | Mechanism |
|------|-----------|
| **Checksum & Hash** | OpenFileDialog -> MD5/SHA-1/SHA-256 (Task.Run) + clipboard copy |
| **EICAR test file** | Confirmation dialog -> writes the standard 68-byte EICAR string to the Desktop -> opens Explorer with the file selected — a safe end-to-end protection test |
| **Temp file cleanup** | Scans `%TEMP%` + Windows\Temp (files **older than 24 hours**, skips locked/reparse/system-attribute files) -> total size -> confirm -> deletes, reports freed/skipped |
| **Signature tester** | Paste an NDB (`name:target:offset:hex`) or `.db` (`name=hex`) line -> temp file -> `SignatureParser.ParseFile` -> `SignatureDatabase` + `ScannerEngine` scans a sample file -> reports MATCH with the signature name @ offset |
| File Inspector | Via `InspectFileCommand` (system inspector) |
| System Profile | Via `RefreshSystemCommand` |

## 5. UI infrastructure

- **ClamGuardWindow**: custom WindowChrome, `PART_` template, `ShowToast` (in-app + desktop
  popup, desktop capped at 4), `ShowDialogAsync` (TaskCompletionSource with
  `RunContinuationsAsynchronously` — no deadlock), theme refresh via event.
- **Theming**: two 44-brush dictionaries in **1:1 parity**; every brush is a `DynamicResource` so
  swapping is clean; the indeterminate progress bar has a **pulse animation** (the custom
  template had removed WPF's default animation).
- **Localization**: normalized `[section]key=value` keys; a missing key displays itself
  (visible fallback); `common.on/off`, `history.*` complete in both languages; ToolsView is saved
  in correct UTF-8 (the mojibake placeholders were fixed).

## 6. Edge security

| Area | Measure |
|------|---------|
| Settings | Atomic write + fallback; paths from settings are not trusted blindly |
| CSV export | Escapes `"` + **neutralizes formula injection** (`=+-@\t\r` at cell start -> `'`) |
| Global exceptions | `DispatcherUnhandledException` (log + Handled), `AppDomain.UnhandledException`,
  `TaskScheduler.UnobservedTaskException` (log) |
| AsyncRelayCommand | Logs every swallowed exception (Trace) |
| Quarantine | DPAPI+AES, restore validation, index lock (section 3.3) |

## 7. Testing

This project is **not referenced by `ClamGuard.Tests`** (the harness covers the six library
projects only) — realtime/quarantine/memory-scan/toolkit currently have **no unit tests**.
Abstract logic is exercised indirectly through the engine; the I/O-heavy services (DPAPI, FSW)
need dedicated integration tests.
