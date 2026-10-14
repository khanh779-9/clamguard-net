using System.Diagnostics;
using System.Text;

namespace ClamGuard.Database;

public enum DetachedVerificationStatus
{
    Verified,
    Invalid,
    Unavailable
}

public sealed record DetachedVerificationResult(
    DetachedVerificationStatus Status,
    string? Signer,
    string Message);

public static class DetachedCmsVerifier
{
    private static readonly Lazy<string?> OpenSslExecutable = new(ResolveOpenSslExecutable);

    public static DetachedVerificationResult Verify(string signedFile, string signatureFile, string certsDirectory)
    {
        try
        {
            var lines = File.ReadAllLines(signatureFile);
            if (lines.Length == 0 || !lines[0].Equals("#clamsign-1.0", StringComparison.Ordinal))
                return new(DetachedVerificationStatus.Invalid, null, "Unsupported ClamAV detached signature format.");

            var payload = lines.Skip(1)
                .Select(x => x.Trim())
                .FirstOrDefault(x => x.Length > 0 && !x.StartsWith('#'));
            if (payload is null)
                return new(DetachedVerificationStatus.Invalid, null, "Detached signature payload is missing.");

            var parts = payload.Split(':', 4);
            if (parts.Length != 4 || !parts[2].Equals("pkcs7-pem", StringComparison.OrdinalIgnoreCase))
                return new(DetachedVerificationStatus.Invalid, null, "Unsupported ClamAV detached signature payload type.");

            byte[] der;
            try { der = Convert.FromBase64String(parts[3]); }
            catch (FormatException) { return new(DetachedVerificationStatus.Invalid, null, "Malformed detached CMS payload."); }
            if (der.Length == 0 || der.Length > 16 * 1024 * 1024)
                return new(DetachedVerificationStatus.Invalid, null, "Detached CMS payload is outside the supported range.");

            var caBundle = BuildCaBundle(certsDirectory);
            if (caBundle is null)
                return new(DetachedVerificationStatus.Unavailable, null, "No PEM certificates were found in the certificate directory.");

            var openssl = OpenSslExecutable.Value;
            if (openssl is null)
                return new(DetachedVerificationStatus.Unavailable, null,
                    "No OpenSSL executable was found next to the application, in a well-known install directory, or on PATH; detached signature verification cannot proceed.");

            var tempDir = Path.Combine(Path.GetTempPath(), $"clamguard-cms-{Guid.NewGuid():N}");
            Directory.CreateDirectory(tempDir);
            try
            {
                var derPath = Path.Combine(tempDir, "signature.der");
                var caPath = Path.Combine(tempDir, "ca-bundle.pem");
                var outputPath = Path.Combine(tempDir, "verified.bin");
                File.WriteAllBytes(derPath, der);
                File.WriteAllText(caPath, caBundle, new UTF8Encoding(false));

                var psi = new ProcessStartInfo
                {
                    FileName = openssl,
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };
                foreach (var arg in new[]
                {
                    "cms", "-verify", "-binary", "-inform", "DER",
                    "-in", derPath,
                    "-content", Path.GetFullPath(signedFile),
                    "-CAfile", caPath,
                    "-no-CApath",
                    "-purpose", "any",
                    "-out", outputPath
                })
                    psi.ArgumentList.Add(arg);

                using var process = Process.Start(psi);
                if (process is null)
                    return new(DetachedVerificationStatus.Unavailable, null, "OpenSSL could not be started.");

                // Drain both pipes concurrently while waiting, otherwise a full pipe buffer
                // can block the child process and deadlock the wait.
                var errorTask = process.StandardError.ReadToEndAsync();
                var outputTask = process.StandardOutput.ReadToEndAsync();
                if (!process.WaitForExit(15_000))
                {
                    try { process.Kill(entireProcessTree: true); } catch { }
                    return new(DetachedVerificationStatus.Unavailable, null, "Detached CMS verification timed out.");
                }

                var error = errorTask.GetAwaiter().GetResult().Trim();
                _ = outputTask.GetAwaiter().GetResult();
                return process.ExitCode == 0
                    ? new(DetachedVerificationStatus.Verified, "Detached ClamAV CMS/PKCS#7", "Detached CMS signature verified.")
                    : new(DetachedVerificationStatus.Invalid, null,
                        string.IsNullOrWhiteSpace(error) ? "Detached CMS signature verification failed." : $"Detached CMS signature verification failed: {error}");
            }
            finally
            {
                try { Directory.Delete(tempDir, recursive: true); } catch { }
            }
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return new(DetachedVerificationStatus.Unavailable, null, "OpenSSL is unavailable.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return new(DetachedVerificationStatus.Unavailable, null, ex.Message);
        }
    }

    private static string? ResolveOpenSslExecutable()
    {
        var fileName = OperatingSystem.IsWindows() ? "openssl.exe" : "openssl";
        var candidates = new List<string> { Path.Combine(AppContext.BaseDirectory, fileName) };
        if (OperatingSystem.IsWindows())
        {
            candidates.Add(@"C:\Program Files\OpenSSL-Win64\bin\openssl.exe");
            candidates.Add(@"C:\Program Files\OpenSSL\bin\openssl.exe");
        }
        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate)) return candidate;
        }

        var pathVariable = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(pathVariable)) return null;
        foreach (var directory in pathVariable.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var candidate = Path.Combine(directory, fileName);
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }

    private static string? BuildCaBundle(string directory)
    {
        var files = Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly)
            .Where(x => x.EndsWith(".crt", StringComparison.OrdinalIgnoreCase) ||
                        x.EndsWith(".pem", StringComparison.OrdinalIgnoreCase) ||
                        x.EndsWith(".cer", StringComparison.OrdinalIgnoreCase))
            .Take(128)
            .ToArray();
        if (files.Length == 0) return null;

        var bundle = new StringBuilder();
        long total = 0;
        foreach (var file in files)
        {
            total += new FileInfo(file).Length;
            if (total > 8L * 1024 * 1024)
                throw new InvalidDataException("Certificate bundle is too large.");
            var text = File.ReadAllText(file);
            if (text.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal))
                bundle.AppendLine(text.Trim());
        }
        return bundle.Length == 0 ? null : bundle.ToString();
    }
}
