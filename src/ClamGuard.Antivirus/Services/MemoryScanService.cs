using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using ClamGuard.Core;

namespace ClamGuard.Antivirus.Services;

/// <summary>
/// Scans the committed memory of running processes. Regions are read with
/// ReadProcessMemory in bounded chunks and handed to a caller-provided scan
/// callback; inaccessible processes are counted and skipped.
/// </summary>
public sealed class MemoryScanService
{
    private readonly Func<byte[], string, CancellationToken, Task<ScanResult>> _scanChunk;

    private const int MaxProcesses = 128;
    private const long MaxBytesPerProcess = 64L * 1024 * 1024;
    private const int MaxRegionBytes = 32 * 1024 * 1024;
    private const int ChunkSize = 4 * 1024 * 1024;
    private const int ChunkOverlap = 4096;

    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessQueryInformation = 0x0400;
    private const uint MemCommit = 0x1000;
    private const uint MemPrivate = 0x20000;
    private const uint MemImage = 0x1000000;
    private const uint PageNoaccess = 0x01;
    private const uint PageGuard = 0x100;

    public MemoryScanService(Func<byte[], string, CancellationToken, Task<ScanResult>> scanChunk)
    {
        _scanChunk = scanChunk;
    }

    public async Task<MemoryScanSummary> ScanAsync(Action<string> progress, Action<ScanResult> threat, CancellationToken token)
    {
        var processes = Process.GetProcesses()
            .Where(p => p.Id != Environment.ProcessId)
            .OrderBy(p => p.Id)
            .Take(MaxProcesses)
            .ToArray();

        var scannedProcesses = 0;
        var skippedProcesses = 0;
        var scannedRegions = 0;
        long scannedBytes = 0;

        for (var i = 0; i < processes.Length; i++)
        {
            token.ThrowIfCancellationRequested();
            var process = processes[i];
            var name = SafeProcessName(process);
            progress($"{name} ({i + 1}/{processes.Length})");

            var (regions, opened) = ReadProcessRegions(process, token);
            if (!opened || regions.Count == 0)
            {
                skippedProcesses++;
                continue;
            }

            scannedProcesses++;
            foreach (var (label, data) in regions)
            {
                token.ThrowIfCancellationRequested();
                scannedRegions++;
                scannedBytes += data.LongLength;
                var result = await _scanChunk(data, label, token).ConfigureAwait(false);
                if (result.Verdict is ScanVerdict.Malicious or ScanVerdict.PotentiallyUnwanted or ScanVerdict.StrongIndicator)
                    threat(result);
            }

            progress($"{name} ({i + 1}/{processes.Length}) · {scannedRegions} regions");
        }

        return new MemoryScanSummary(
            processes.Length,
            scannedProcesses,
            skippedProcesses,
            scannedRegions,
            scannedBytes);
    }

    private static string SafeProcessName(Process process)
    {
        try { return process.ProcessName; }
        catch { return $"pid{process.Id}"; }
    }

    private static (List<(string Label, byte[] Data)> Regions, bool Opened) ReadProcessRegions(Process process, CancellationToken token)
    {
        var regions = new List<(string, byte[])>();
        var handle = NativeMethods.OpenProcess(ProcessVmRead | ProcessQueryInformation, false, process.Id);
        if (handle == IntPtr.Zero)
            return (regions, false);

        try
        {
            long address = 0x10000L;
            const long MaxUserAddress = 0x7FFFFFFEFFFFL; // practical user-mode ceiling on x64
            long processBytes = 0;
            while (address < MaxUserAddress)
            {
                token.ThrowIfCancellationRequested();
                if (!NativeMethods.VirtualQueryEx(handle, (IntPtr)address, out var mbi, (IntPtr)Marshal.SizeOf<NativeMethods.MemoryBasicInformation>()))
                    break;

                var regionSize = mbi.RegionSize.ToInt64();
                if (regionSize <= 0)
                    break;

                var start = mbi.BaseAddress.ToInt64();
                address = checked(start + regionSize);

                var readable = mbi.State == MemCommit && (mbi.Protect & PageNoaccess) == 0 && (mbi.Protect & PageGuard) == 0;
                var interesting = readable &&
                                  ((mbi.Type == MemPrivate) ||
                                   (mbi.Type == MemImage && (mbi.Protect & 0xF0) != 0)); // image regions with execute/copy flags
                if (!interesting)
                    continue;

                var length = (int)Math.Min(regionSize, MaxRegionBytes);
                if (length <= 0 || processBytes + length > MaxBytesPerProcess)
                    continue;

                var data = new byte[length];
                if (!NativeMethods.ReadProcessMemory(handle, (IntPtr)start, data, (IntPtr)length, out _))
                    continue;

                processBytes += length;
                var processName = SafeProcessName(process);
                if (length <= ChunkSize)
                {
                    regions.Add(($"memory://{process.Id}:{processName}@0x{start:X}", data));
                    continue;
                }

                // Large regions are scanned in overlapping chunks so a pattern
                // split across a chunk boundary is still observed.
                for (var offset = 0; offset < length; offset += ChunkSize)
                {
                    token.ThrowIfCancellationRequested();
                    var take = Math.Min(ChunkSize + ChunkOverlap, length - offset);
                    var chunk = new byte[take];
                    Buffer.BlockCopy(data, offset, chunk, 0, take);
                    regions.Add(($"memory://{process.Id}:{processName}@0x{(start + offset):X}", chunk));
                    if (offset + ChunkSize >= length)
                        break;
                }
            }

            return (regions, true);
        }
        finally
        {
            _ = NativeMethods.CloseHandle(handle);
        }
    }
}

public sealed record MemoryScanSummary(
    int DiscoveredProcesses,
    int ScannedProcesses,
    int SkippedProcesses,
    int ScannedRegions,
    long ScannedBytes);

internal static class NativeMethods
{
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MemoryBasicInformation lpBuffer, IntPtr dwLength);

    [DllImport("kernel32.dll")]
    internal static extern IntPtr CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    internal struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
}
