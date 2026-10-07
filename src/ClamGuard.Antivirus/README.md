# ClamGuard Antivirus — WPF GUI

A WPF desktop GUI for the ClamGuard.NET antivirus libraries.

## GUI structure

The application keeps the window shell separate from the page content:

```text
MainWindow.xaml
    └── ClamGuardWindow (custom window frame + title bar + toast host)
            ├── Navigation rail
            └── Page workspace
                    ├── Overview
                    ├── Scan
                    ├── Update
                    ├── Security
                    ├── History
                    ├── Quarantine
                    ├── Tools
                    └── Settings
```

The UI uses shared resources in `Theme/Controls.xaml` and semantic color tokens in the light/dark theme dictionaries. Icons are centralized in `Theme/Icons.xaml` and use normalized 24×24 geometric path data.

Localization is driven by `.lng` files using an INI-style structure (`[section]` + `key=value`). The bundled `en-US.lng` and `vi-VN.lng` files are both embedded and copied beside the executable, so an installation can replace/add translation files without changing UI XAML.

## Interaction details

- Custom window chrome supports drag, minimize, maximize/restore and close.
- Window controls expose accessible names and visible keyboard focus states.
- Primary, secondary and ghost buttons share one visual state system.
- Navigation uses grouped sections with persistent selected/hover/focus states.
- Real-time protection uses a custom toggle switch with explicit on/off feedback.
- Scan history uses a focused DataGrid with selected-row styling and result badges.
- Theme switching replaces the active semantic resource dictionary at runtime; text, surfaces, borders, controls and security-state colors follow the selected theme.
- Navigation items are flat, square-edged controls with an in-bounds selection rail instead of an overflowing capsule.
- Custom dialogs and toast notifications are implemented as reusable controls under `Controls/`.
- The System page inspects memory, uptime, drives, processes, network adapters and Run startup entries through Windows/.NET APIs.
- File inspection computes SHA-256, version metadata and best-effort Authenticode certificate status.
- Quarantine moves a detected file into the local isolated store and supports restore/delete actions with explicit confirmation.
- Windows Security can be opened directly from the Tools surface.

## Project layout

```text
ClamGuard.Antivirus/
├── Controls/
│   ├── ClamGuardWindow.xaml
│   ├── ClamGuardWindow.xaml.cs
│   └── ToastKind.cs
├── Converters/
├── Theme/
│   ├── Controls.xaml
│   ├── DarkTheme.xaml
│   ├── Icons.xaml
│   └── LightTheme.xaml
├── Views/
│   ├── OverviewView.xaml
│   ├── ScanView.xaml
│   ├── UpdateView.xaml
│   ├── SecurityView.xaml
│   ├── HistoryView.xaml
│   ├── QuarantineView.xaml
│   ├── ToolsView.xaml
│   └── SettingsView.xaml
├── Services/
├── Models/
├── ViewModels/
├── Data/
├── MainWindow.xaml
├── MainWindow.xaml.cs
└── App.xaml(.cs)
```

## Build

This project references the ClamGuard.NET library projects from the parent `src` directory. Rebuild it from the full solution after replacing this folder.

```powershell
Remove-Item -Recurse -Force .\bin, .\obj -ErrorAction SilentlyContinue
dotnet restore ..\..\ClamGuard.Net.sln
dotnet build ..\..\ClamGuard.Net.sln
```
