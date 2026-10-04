using System.Diagnostics;
using System.ComponentModel;
using System.Text;
using ClamGuard.Core;

namespace ClamGuard.Scanner;

internal sealed record ExternalArchiveMember(
    string Name,
    long Size,
    byte[] Data,
    long? CompressedSize,
    bool? Encrypted,
    uint? Crc32,
    uint FilePosition,
    bool IsDirectory = false,
    bool CanExtract = true,
    uint? CompressionMethod = null);

/// <summary>
/// Optional bridge for archive codecs that are not part of the .NET base class library.
/// No shell is involved; executable names are resolved through PATH and all untrusted
/// archive/member names are passed through ProcessStartInfo.ArgumentList.
/// </summary>
internal static class ArchiveExternalDecoder
{
    private const long MaxListOutput = 8L * 1024 * 1024;
    private const int MaxMembers = 10000;

    public static bool TryDecodeSingle(
        byte[] data,
        string format,
        ScanLimits limits,
        CancellationToken cancellationToken,
        out byte[] child)
    {
        child = [];
        var executable = format switch
        {
            "BZ" => FindExecutable("bzip2"),
            "XZ" => FindExecutable("xz"),
            _ => null
        };
        if (executable is null) return false;

        var extension = format == "BZ" ? ".bz2" : ".xz";
        var temp = Path.Combine(Path.GetTempPath(), "clamguard-" + Guid.NewGuid().ToString("N") + extension);
        try
        {
            File.WriteAllBytes(temp, data.ToArray());
            var args = new[] { "-dc", "--", temp };
            return TryRunToBytes(executable, args, limits.MaxFileSize, limits.MaxArchiveDecodeTime, cancellationToken, out child);
        }
        finally
        {
            TryDelete(temp);
        }
    }

    public static IEnumerable<ExternalArchiveMember> ExtractMembers(
        byte[] data,
        string format,
        ScanLimits limits,
        CancellationToken cancellationToken)
    {
        var sevenZip = FindExecutable("7z") ?? FindExecutable("7zz") ?? FindExecutable("7za");
        if (sevenZip is null)
        {
            var unrar = format == "RAR" ? FindExecutable("unrar") : null;
            if (unrar is null) yield break;
            foreach (var item in ExtractWithUnrar(unrar, data, limits, cancellationToken))
                yield return item;
            yield break;
        }

        foreach (var item in ExtractWith7Zip(sevenZip, data, format, limits, cancellationToken))
            yield return item;
    }

    private static IEnumerable<ExternalArchiveMember> ExtractWith7Zip(
        string executable,
        byte[] data,
        string format,
        ScanLimits limits,
        CancellationToken cancellationToken)
    {
        var ext = format switch
        {
            "7Z" => ".7z",
            "RAR" => ".rar",
            "ARJ" => ".arj",
            "CAB" => ".cab",
            "CHM" => ".chm",
            "ISO" => ".iso",
            "XAR" => ".xar",
            "DMG" => ".dmg",
            "LHA" => ".lzh",
            "EGG" => ".egg",
            "ALZ" => ".alz",
            "SIS" => ".sis",
            "NULSFT" or "AUTOIT" => ".exe",
            "ISHIELD_MSI" => ".msi",
            "UDF" => ".iso",
            "SZDD" => ".compressed",
            _ => ".archive"
        };
        var temp = Path.Combine(Path.GetTempPath(), "clamguard-" + Guid.NewGuid().ToString("N") + ext);
        try
        {
            File.WriteAllBytes(temp, data.ToArray());
            var args = new[] { "l", "-slt", "-ba", "-sccUTF-8", "-y", "--", temp };
            if (!TryRunToBytes(executable, args, MaxListOutput, limits.MaxArchiveDecodeTime, cancellationToken, out var listingBytes))
                yield break;

            var memberCount = 0;
            foreach (var entry in ParseSevenZipListing(Encoding.UTF8.GetString(listingBytes)))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (entry.IsDirectory || string.IsNullOrWhiteSpace(entry.Path)) continue;
                if (entry.Size is < 0 or > long.MaxValue) continue;
                if (entry.Size > limits.MaxFileSize) continue;
                if (memberCount++ >= Math.Min(MaxMembers, limits.MaxArchiveEntries)) yield break;

                var extractArgs = new[] { "e", "-so", "-y", "--", temp, entry.Path };
                if (!TryRunToBytes(executable, extractArgs, limits.MaxFileSize, limits.MaxArchiveDecodeTime, cancellationToken, out var child))
                    continue;
                if (child.LongLength != entry.Size)
                    continue;
                yield return new ExternalArchiveMember(
                    entry.Path,
                    entry.Size,
                    child,
                    entry.PackedSize,
                    entry.Encrypted,
                    entry.Crc32,
                    (uint)memberCount);
            }
        }
        finally
        {
            TryDelete(temp);
        }
    }

    private static IEnumerable<ExternalArchiveMember> ExtractWithUnrar(
        string executable,
        byte[] data,
        ScanLimits limits,
        CancellationToken cancellationToken)
    {
        var temp = Path.Combine(Path.GetTempPath(), "clamguard-" + Guid.NewGuid().ToString("N") + ".rar");
        try
        {
            File.WriteAllBytes(temp, data.ToArray());
            var args = new[] { "lb", "-idq", "--", temp };
            if (!TryRunToBytes(executable, args, MaxListOutput, limits.MaxArchiveDecodeTime, cancellationToken, out var listingBytes))
                yield break;

            var count = 0;
            foreach (var rawName in Encoding.UTF8.GetString(listingBytes).Split('\n'))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (count++ >= MaxMembers) yield break;
                var name = rawName.TrimEnd('\r');
                if (string.IsNullOrWhiteSpace(name)) continue;

                var extractArgs = new[] { "p", "-inul", "-y", "--", temp, name };
                if (!TryRunToBytes(executable, extractArgs, limits.MaxFileSize, limits.MaxArchiveDecodeTime, cancellationToken, out var child))
                    continue;
                yield return new ExternalArchiveMember(name, child.LongLength, child, null, null, null, (uint)count);
            }
        }
        finally
        {
            TryDelete(temp);
        }
    }

    private static IEnumerable<SevenZipMemberInfo> ParseSevenZipListing(string text)
    {
        string? path = null;
        long size = -1;
        long? packedSize = null;
        bool? encrypted = null;
        uint? crc32 = null;
        var directory = false;

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            if (line.Length == 0)
            {
                if (path is not null)
                    yield return new SevenZipMemberInfo(path, size, directory, packedSize, encrypted, crc32);
                path = null;
                size = -1;
                packedSize = null;
                encrypted = null;
                crc32 = null;
                directory = false;
                continue;
            }

            var separator = line.IndexOf(" = ", StringComparison.Ordinal);
            if (separator <= 0) continue;
            var key = line[..separator];
            var value = line[(separator + 3)..];
            switch (key)
            {
                case "Path": path = value; break;
                case "Size": long.TryParse(value, out size); break;
                case "Packed Size": if (long.TryParse(value, out var packed)) packedSize = packed; break;
                case "Encrypted": encrypted = value == "+" ? true : value == "-" ? false : null; break;
                case "CRC":
                    if (uint.TryParse(value, System.Globalization.NumberStyles.HexNumber, null, out var crc)) crc32 = crc;
                    break;
                case "Folder": directory = value == "+"; break;
            }
        }

        if (path is not null)
            yield return new SevenZipMemberInfo(path, size, directory, packedSize, encrypted, crc32);
    }

    private sealed record SevenZipMemberInfo(string Path, long Size, bool IsDirectory, long? PackedSize, bool? Encrypted, uint? Crc32);

    private static bool TryRunToBytes(
        string executable,
        IReadOnlyList<string> args,
        long maxBytes,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        out byte[] bytes)
    {
        try
        {
            bytes = TryRunToBytesAsync(executable, args, maxBytes, timeout, cancellationToken)
                .GetAwaiter().GetResult();
            return true;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            bytes = [];
            return false;
        }
        catch (InvalidDataException)
        {
            bytes = [];
            return false;
        }
    }

    private static async Task<byte[]> TryRunToBytesAsync(
        string executable,
        IReadOnlyList<string> args,
        long maxBytes,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (maxBytes < 0) return [];

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            }
        };
        foreach (var arg in args) process.StartInfo.ArgumentList.Add(arg);

        try
        {
            if (!process.Start()) return [];
        }
        catch (Win32Exception)
        {
            return [];
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (timeout > TimeSpan.Zero) timeoutCts.CancelAfter(timeout);

        var stdoutTask = ReadLimitedAsync(process.StandardOutput.BaseStream, maxBytes, timeoutCts.Token);
        // Drain stderr concurrently so a verbose decoder cannot deadlock on its error pipe.
        var stderrTask = ReadLimitedAsync(process.StandardError.BaseStream, 1L * 1024 * 1024, timeoutCts.Token);
        var exitTask = process.WaitForExitAsync(timeoutCts.Token);

        try
        {
            var first = await Task.WhenAny(stdoutTask, stderrTask, exitTask).ConfigureAwait(false);
            if (first == stdoutTask)
            {
                var stdout = await stdoutTask.ConfigureAwait(false);
                await exitTask.ConfigureAwait(false);
                await stderrTask.ConfigureAwait(false);
                if (process.ExitCode != 0) return [];
                return stdout;
            }

            if (first == stderrTask)
                await stderrTask.ConfigureAwait(false);

            await exitTask.ConfigureAwait(false);
            var completedStdout = await stdoutTask.ConfigureAwait(false);
            if (!stderrTask.IsCompleted) await stderrTask.ConfigureAwait(false);
            if (process.ExitCode != 0) return [];
            return completedStdout;
        }
        catch (InvalidDataException)
        {
            TryKill(process);
            throw;
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw;
        }
        catch (IOException)
        {
            TryKill(process);
            return [];
        }
    }

    private static async Task<byte[]> ReadLimitedAsync(Stream stream, long maxBytes, CancellationToken token)
    {
        using var output = new MemoryStream((int)Math.Min(maxBytes, 4L * 1024 * 1024));
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(), token).ConfigureAwait(false);
            if (read == 0) break;
            if (output.Length > maxBytes - read) throw new InvalidDataException("External decoder output exceeded the scan limit.");
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private static string? FindExecutable(string name)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(path)) return null;
        var names = OperatingSystem.IsWindows() && !name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? new[] { name + ".exe", name }
            : new[] { name };
        foreach (var dir in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var candidateName in names)
            {
                var candidate = Path.Combine(dir, candidateName);
                if (File.Exists(candidate)) return candidate;
            }
        }
        return null;
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch { }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch { }
    }
}
