using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using System.Security.Principal;
using ClamGuard.Antivirus.Models;
using System.IO;

namespace ClamGuard.Antivirus.Services;

public sealed class SystemInspectorService
{
    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatusEx
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhysicalMemory;
        public ulong AvailablePhysicalMemory;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtualMemory;
        public ulong AvailableVirtualMemory;
        public ulong AvailableExtendedVirtualMemory;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx lpBuffer);

    public SystemSnapshot Capture()
    {
        var memory = new MemoryStatusEx { Length = (uint)Marshal.SizeOf<MemoryStatusEx>() };
        GlobalMemoryStatusEx(ref memory);

        var drives = DriveInfo.GetDrives()
            .Where(x => x.IsReady)
            .Select(x =>
            {
                var total = x.TotalSize / 1_073_741_824d;
                var free = x.AvailableFreeSpace / 1_073_741_824d;
                var used = Math.Max(0, total - free);
                return new DriveSnapshotItem(x.Name, string.IsNullOrWhiteSpace(x.VolumeLabel) ? "Local disk" : x.VolumeLabel, used, free, total, total <= 0 ? 0 : used / total * 100d);
            })
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var processes = Process.GetProcesses()
            .Select(SafeProcess)
            .Where(x => x is not null)
            .Cast<ProcessSnapshotItem>()
            .OrderByDescending(x => x.MemoryMb)
            .Take(30)
            .ToArray();

        var networks = NetworkInterface.GetAllNetworkInterfaces()
            .Where(x => x.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(x => new NetworkSnapshotItem(
                x.Name,
                x.NetworkInterfaceType.ToString(),
                string.Join(", ", x.GetIPProperties().UnicastAddresses.Select(a => a.Address.ToString())),
                x.OperationalStatus.ToString()))
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new SystemSnapshot(
            RuntimeInformation.OSDescription,
            RuntimeInformation.OSArchitecture.ToString(),
            Environment.ProcessorCount,
            memory.TotalPhysicalMemory / 1_073_741_824d,
            memory.AvailablePhysicalMemory / 1_073_741_824d,
            TimeSpan.FromMilliseconds(Environment.TickCount64),
            drives,
            processes,
            networks,
            ReadStartupItems());
    }

    /// <summary>
    /// A "valid" signature means the certificate chains to a trusted root with
    /// chain building (revocation checked) AND carries the code-signing EKU — a
    /// bare validity-window check would bless self-signed certificates.
    /// </summary>
    private static string DescribeSignatureState(X509Certificate2 cert)
    {
        if (DateTime.UtcNow < cert.NotBefore.ToUniversalTime() || DateTime.UtcNow > cert.NotAfter.ToUniversalTime())
            return "Signed · certificate outside validity window";

        var isCodeSigning = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .Any(e => e.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == "1.3.6.1.5.5.7.3.3"));
        if (!isCodeSigning)
            return "Signed · certificate is not a code-signing certificate";

        using var chain = new X509Chain
        {
            ChainPolicy = new X509ChainPolicy
            {
                RevocationMode = X509RevocationMode.Online,
                RevocationFlag = X509RevocationFlag.ExcludeRoot,
                VerificationFlags = X509VerificationFlags.NoFlag
            }
        };
        if (!chain.Build(cert))
        {
            var status = chain.ChainStatus.Length > 0 ? chain.ChainStatus[0].StatusInformation.TrimEnd('.') : "untrusted";
            return $"Signed · chain not trusted ({status})";
        }
        return "Signed · certificate valid (chain trusted)";
    }

    public FileInspectionResult InspectFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)) throw new FileNotFoundException("File not found.", full);

        var info = new FileInfo(full);
        string hash;
        using (var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 128 * 1024, FileOptions.SequentialScan))
            hash = Convert.ToHexString(SHA256.HashData(stream));

        var versionInfo = FileVersionInfo.GetVersionInfo(full);
        var signatureSubject = string.Empty;
        var signatureStatus = "Unsigned / not detected";
        try
        {
            var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(full));
            signatureSubject = cert.Subject;
            signatureStatus = DescribeSignatureState(cert);
        }
        catch (CryptographicException)
        {
            // Not signed or unavailable to inspect without elevation.
        }

        return new FileInspectionResult(
            full,
            info.Name,
            info.Length,
            info.LastWriteTime,
            hash,
            versionInfo.FileVersion ?? string.Empty,
            versionInfo.CompanyName ?? string.Empty,
            versionInfo.ProductName ?? string.Empty,
            signatureSubject,
            signatureStatus);
    }

    public bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static ProcessSnapshotItem? SafeProcess(Process process)
    {
        try
        {
            using (process)
            {
                return new ProcessSnapshotItem(
                    process.ProcessName,
                    process.Id,
                    process.WorkingSet64 / 1_048_576d,
                    string.IsNullOrWhiteSpace(process.MainWindowTitle) ? string.Empty : process.MainWindowTitle,
                    GetExecutablePath(process));
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
        {
            process.Dispose();
            return null;
        }
    }

    private static string GetExecutablePath(Process process)
    {
        try
        {
            return process.MainModule?.FileName ?? string.Empty;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException or UnauthorizedAccessException)
        {
            return string.Empty;
        }
    }

    private static IReadOnlyList<StartupSnapshotItem> ReadStartupItems()
    {
        var result = new List<StartupSnapshotItem>();
        ReadRunKey(Registry.CurrentUser, "Current user", result);
        ReadRunKey(Registry.LocalMachine, "All users", result);
        return result.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static void ReadRunKey(RegistryKey root, string scope, List<StartupSnapshotItem> result)
    {
        try
        {
            using var key = root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: false);
            if (key is null) return;
            foreach (var name in key.GetValueNames())
            {
                var value = key.GetValue(name)?.ToString();
                if (!string.IsNullOrWhiteSpace(value))
                    result.Add(new StartupSnapshotItem(name, value, scope));
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Read-only best effort; some managed endpoints deny HKLM access.
        }
    }
}
