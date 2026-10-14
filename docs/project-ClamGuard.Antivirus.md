# project-ClamGuard.Antivirus

> Ứng dụng desktop WPF của người dùng cuối: giao diện quét, bảo vệ thời gian thực, quarantine,
> system inspector, toolkit và cập nhật database. MVVM-lite với event-broker, i18n EN/VI,
> Light/Dark theme, toast/dialog tự vẽ (window chrome riêng).

---

## 1. Thông tin project

| Thuộc tính | Giá trị |
|---|---|
| Target framework | `net8.0-windows`, `WinExe` |
| Dependency | `ClamGuard.Core`, `ClamGuard.Database`, `ClamGuard.Scanner` |
| Số file | 58 (Views 9×2, Services 11, Controls 11, Theme 12, Localization 4, ViewModels 6, Models 6) |
| Build cross-platform | `EnableWindowsTargeting=true` (CI chạy cả ubuntu) |
| Manifest | `requireAdministrator`-neutral, `supportedOS` Win10; DPI: system-aware |

## 2. Kiến trúc tổng thể

```text
App.xaml(.cs)                  Composition root: merge resources (Converters → LightTheme → Icons →
                               Controls → ClamGuardWindow), khởi tạo Settings/Theme/Localization,
                               global exception handlers (Dispatcher/AppDomain/UnobservedTask)
MainWindow (.xaml/.cs)         Shell: sidebar nav (RadioButton+Tag), header, progress, ContentControl
MainWindow.ThreatHandling.cs   Xử lý kết quả scan: toast, policy thực thi, quarantine restore/delete
Views/                         Overview, Scan, Security, System, History, Quarantine, Tools, Update, Settings
ViewModels/                    MainViewModel (+partial Scanning) — state + 32 command + 23 event
                               Commands: RelayCommand, AsyncRelayCommand (reentrancy guard), ParameterRelayCommand
Services/                      AntivirusEngineService, RealtimeProtectionService, QuarantineService,
                               MemoryScanService, StartupScanService, SystemInspectorService,
                               ActiveTaskTracker, ThemeService, LocalizationService, JsonSettingsStore, AppPaths
Models/                        ActiveTaskItem (INPC), QuarantineItem, ScanHistoryItem, ScanProgress,
                               ScanResultRowItem, SystemSnapshot
Controls/                      ClamGuardWindow (chrome+toast+dialog API), ClamGuardDialog, ClamGuardToast(+Host),
                               DesktopToastWindow, LoadingOverlay, ToastKind
Theme/                         DarkTheme/LightTheme (44 brush parity), Controls.{Buttons,Cards,Inputs,
                               DataGrid,Scrolling,Status,Misc,Converters}, Icons (~30 geometry)
Localization/                  LocalizationService + LocExtension + en-US.lng + vi-VN.lng
```

**Luồng MVVM-lite**: View binding 2 chiều vào `MainViewModel`; VM phát **event** (23 cái,
`QuickScanRequested`…) → `MainWindow` code-behind xử lý hành vi (dialog, điều hướng, gọi service).
Async plumbing: `Progress<T>` marshal UI, `SynchronizationContext.Post` trong memory scan,
không `.Result/.Wait()`.

## 3. Services chi tiết

### 3.1. `AntivirusEngineService` — facade engine

- Init **single-flight** (`Task` field): lần gọi thứ hai trong lúc init trả về cùng Task, không
  trả sớm khi DB chưa sẵn sàng.
- `ScanFileAsync` / `ScanFolderAsync` (`Parallel.ForEachAsync`, MaxDegreeOfParallelism ≤ 4,
  symlink/reparse handling, dedupe dir) / `ScanMemoryBufferAsync` / `UpdateDatabaseAsync`.
- `EnumerateScanFiles` **enforce `options.MaxFiles` thật** (mặc định 10 000 — dừng duyệt streaming,
  `LimitReached=true` → heuristic + thông báo UI).
- Đổi `DatabaseDirectory` → lưu settings + reload engine.

### 3.2. `RealtimeProtectionService` — FileSystemWatcher

| Khía cạnh | Chi tiết |
|-----------|----------|
| Watch | Single folder (`IncludeSubdirectories`), `InternalBufferSize = 64KB` |
| Debounce | `ConcurrentDictionary<path,CTS>` — event mới **cancel** event cũ (delay 900ms); generation token: task cũ đã qua delay và đang scan vẫn bị **so sánh entry** sau scan, khác → bỏ kết quả (không double-quarantine) |
| Chờ file ghi xong | `WaitUntilReadableAsync`: 5 lần × ~300ms, ổn định chiều dài mới scan; bỏ cuộc → raise Error |
| Overflow watcher | Error → restart watcher + **re-schedule 500 file mới nhất** (best-effort recovery) |
| Loại trừ | Thư mục database (tự bảo vệ), dotfile, directory |
| Vòng đời | Stop(): cancel + clear, CTS dispose trong `finally` của chính task |

### 3.3. `QuarantineService` — kho cách ly mã hoá

- **Seal**: file body mã hoá **AES-256-CBC streamed** (1MB chunk, không materialize file lớn);
  key 32B + IV 16B seal bằng **DPAPI** (crypt32, P/Invoke) — chỉ user hiện tại giải được; header
  `MCGQ` + version 2; entry legacy plaintext vẫn restore được.
- Index `index.json`: ghi atomic (`.tmp` + `File.Move(overwrite)`), RMW có lock.
- `Restore`: validate target **không nằm trong store** (chặn write-primitive từ index bị giả mạo),
  decrypt stream, `FileAttributes.Normal`.
- `Delete`: reset ReadOnly trước `File.Delete` (bug cũ: fail 100 %).
- Realtime action "Delete" đi **qua quarantine** (recoverable với false-positive).

### 3.4. `MemoryScanService` — quét bộ nhớ tiến trình

`OpenProcess(VM_READ|QUERY_INFORMATION)` + `VirtualQueryEx` walk (≤ `0x7FFFFFFEFFFF`), chỉ region
MEM_PRIVATE hoặc MEM_IMAGE có execute/copy flag; **budget chặn lúc thu thập** (không materialize
hết mới kiểm); skip region toàn zero; chunk 1MB + overlap 4KB (chống signature cắt đôi); Process
handles được dispose. Không yêu cầu admin — tiến trình không đọc được bị skip có đếm.

### 3.5. `SystemInspectorService` — profile + file inspector

- Snapshot: OS/arch/CPU/RAM (`GlobalMemoryStatusEx`), drives, networks, processes, startup
  (Run/RunOnce HKLM/HKCU/WOW64, Startup folders, dịch vụ auto).
- **File inspector**: SHA-256, version info, và kiểm tra chữ ký số **đúng nghĩa**:
  validity window + **X509Chain** (revocation online, exclude-root) + **EKU code-signing**
  (`1.3.6.1.5.5.7.3.3`) — self-signed không thể hiện "valid".

### 3.6. Còn lại

| Service | Vai trò chính |
|---------|---------------|
| `StartupScanService` | Thu thập autostart → resolve exe (strip `\??\`, quoted-path, longest-prefix) |
| `ThemeService` | Swap dictionary Light/Dark tại đúng index; `Auto` đọc registry `AppsUseLightTheme` |
| `LocalizationService` | Singleton; load `.lng` **external ưu tiên → embedded fallback**; indexer `Item[]` INPC cho binding `{loc:Loc}`; `Format` có args |
| `JsonSettingsStore` | Ghi atomic `.tmp` + move; Load fallback `.tmp` khi file chính hỏng; migrate legacy path |
| `AppPaths` | Đường dẫn: settings (LocalAppData), database/quarantine/cache (ProgramData), `EnsureDirectories` |
| `ActiveTaskTracker` | Registry task đang chạy + aggregate progress; CTS lifecycle |

## 4. Trang Tools — toolkit 6 công cụ

| Tool | Cơ chế |
|------|--------|
| **Mã băm & Kiểm tra tổng** | OpenFileDialog → MD5/SHA-1/SHA-256 (Task.Run) + copy clipboard |
| **Tệp thử nghiệm EICAR** | Dialog xác nhận → ghi EICAR chuẩn (68 byte) ra Desktop → mở Explorer select — test đường realtime/scan an toàn |
| **Dọn dẹp tệp tạm** | Quét `%TEMP%` + Windows\Temp (file **cũ hơn 24 giờ**, skip locked/reparse/system-attr) → tổng dung lượng → confirm → xoá, báo freed/skipped |
| **Kiểm tra chữ ký mẫu** | Dán NDB (`name:target:offset:hex`) hoặc `.db` (`name=hex`) → temp file → `SignatureParser.ParseFile` → `SignatureDatabase` + `ScannerEngine` scan file mẫu → báo KHỚP/tên sig @ offset |
| File Inspector | Qua `InspectFileCommand` (system inspector) |
| System Profile | Qua `RefreshSystemCommand` |

## 5. UI infrastructure

- **ClamGuardWindow**: WindowChrome tự vẽ, `PART_` template, `ShowToast` (in-app + desktop popup,
  desktop cap 4), `ShowDialogAsync` (TaskCompletionSource `RunContinuationsAsynchronously` — không
  deadlock), theme refresh qua event.
- **Theme**: 2 dictionary 44 brush **parity 1-1**; mọi brush dùng `DynamicResource` → swap sạch;
  progress indeterminate có **animation pulse** (template custom đã bỏ animation mặc định của WPF).
- **i18n**: key chuẩn hoá `[section]key=value`; thiếu key hiển thị chính key (fallback hữu hình);
  `common.on/off`, `history.*` đầy đủ cả 2 ngôn ngữ; ToolsView encoding UTF-8 đúng (mojibake đã sửa).

## 6. An ninh biên

| Vùng | Biện pháp |
|------|-----------|
| Settings | Atomic write + fallback; không trust path từ settings khi dùng |
| CSV export | Escape `"` + **neutralize formula injection** (`=+-@\t\r` đầu cell → `'`) |
| Global exceptions | `DispatcherUnhandledException` (log + Handled), `AppDomain.UnhandledException`, `TaskScheduler.UnobservedTaskException` (log) |
| AsyncRelayCommand | Log mọi exception bị nuốt (Trace) |
| Quarantine | DPAPI+AES, validate restore, lock index (xem §3.3) |

## 7. Kiểm thử

⚠️ Project này **không được tham chiếu bởi `ClamGuard.Tests`** (test harness chỉ phủ 6 library
project) — realtime/quarantine/memory-scan/toolkit hiện **không có unit test**. Logic trừu tượng
được kiểm gián tiếp qua engine; các service I/O nặng (DPAPI, FSW) cần integration test riêng.
