using System.Net;
using ClamGuard.Core;
using ClamGuard.Database;

namespace ClamGuard.Update;

public enum UpdateStatus
{
    UpToDate,
    Updated,
    NoLocalDatabase,
    Failed
}

public sealed record UpdateResult(UpdateStatus Status, string DatabaseName, uint? LocalVersion, uint? RemoteVersion, string Message);

public sealed class DatabaseUpdater
{
    private readonly HttpClient _http;
    private readonly UpdateOptions _options;

    public DatabaseUpdater(HttpClient? httpClient = null, UpdateOptions? options = null)
    {
        _options = options ?? new UpdateOptions();
        _http = httpClient ?? new HttpClient();
        _http.Timeout = _options.Timeout;
        // Cisco Talos Cloudflare CDN strictly requires User-Agent in CVDUPDATE/<ver> (<uuid>) format; others return 403 Forbidden.
        var clientUuid = Guid.NewGuid().ToString("D");
        _http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", $"CVDUPDATE/1.1.1 ({clientUuid})");
    }

    public async Task<UpdateResult> UpdateCvdAsync(string databaseDirectory, string databaseName = "daily.cvd", CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(databaseName) || databaseName != Path.GetFileName(databaseName))
            throw new ArgumentException("Database name must be a simple file name.", nameof(databaseName));

        Directory.CreateDirectory(databaseDirectory);
        var localPath = Path.Combine(databaseDirectory, databaseName);
        uint? localVersion = null;
        if (File.Exists(localPath))
        {
            try { localVersion = CvdReader.ReadHeader(localPath).Version; }
            catch (Exception ex) when (ex is IOException or InvalidDataException or FormatException)
            {
                return new UpdateResult(UpdateStatus.Failed, databaseName, null, null, $"Local database is invalid: {ex.Message}");
            }
        }

        var remoteUri = new Uri(_options.BaseUri, databaseName);
        var ext = Path.GetExtension(databaseName);
        var temp = Path.Combine(databaseDirectory, $".{databaseName}.{Guid.NewGuid():N}{ext}");
        string? detachedSignatureTemp = null;
        try
        {
            uint? remoteVersion = null;
            Exception? last = null;
            for (var attempt = 1; attempt <= Math.Max(1, _options.MaxAttempts); attempt++)
            {
                try
                {
                    remoteVersion = await DownloadAndReadHeaderAsync(remoteUri, temp, cancellationToken);
                    break;
                }
                catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or FormatException)
                {
                    last = ex;
                    if (attempt == _options.MaxAttempts) throw;
                }
            }

            if (remoteVersion is null)
                return new UpdateResult(UpdateStatus.Failed, databaseName, localVersion, null, last?.Message ?? "Remote version is unavailable.");
            if (localVersion.HasValue && remoteVersion.Value <= localVersion.Value)
            {
                File.Delete(temp);
                return new UpdateResult(UpdateStatus.UpToDate, databaseName, localVersion, remoteVersion, "The local database is already current.");
            }

            if (!string.IsNullOrWhiteSpace(_options.CertsDirectory))
            {
                var dbBaseName = Path.GetFileNameWithoutExtension(databaseName);
                var signatureName = $"{dbBaseName}-{remoteVersion.Value}.cvd.sign";
                detachedSignatureTemp = Path.Combine(databaseDirectory, $".{signatureName}.{Guid.NewGuid():N}.tmp");
                if (!await TryDownloadSignatureAsync(new Uri(_options.BaseUri, signatureName), detachedSignatureTemp, cancellationToken))
                {
                    TryDeleteFile(detachedSignatureTemp);
                    detachedSignatureTemp = null;
                }
            }

            var verification = DatabaseVerifier.VerifyCvd(temp, _options.CertsDirectory, detachedSignatureTemp);
            if (verification.Status != DatabaseVerificationStatus.Verified)
                throw new InvalidDataException($"Downloaded CVD failed cryptographic verification: {verification.Message}");

            var validationDir = Path.Combine(databaseDirectory, $".validate-{Guid.NewGuid():N}");
            try
            {
                await CvdReader.ExtractAsync(temp, validationDir, cancellationToken);
                // Parsing the extracted database with strict validation is the activation smoke test.
                var validation = new DatabaseLoader().LoadDirectory(validationDir, failOnInvalidFile: true, verifyContainers: false);
                if (validation.SignatureCount == 0)
                    throw new InvalidDataException("The downloaded database contains no supported signatures.");
            }
            finally
            {
                TryDeleteDirectory(validationDir);
            }

            AtomicReplace(temp, localPath);
            if (detachedSignatureTemp is not null)
            {
                var installedSignature = Path.Combine(databaseDirectory, $"{Path.GetFileNameWithoutExtension(databaseName)}-{remoteVersion.Value}.cvd.sign");
                AtomicReplace(detachedSignatureTemp, installedSignature);
                detachedSignatureTemp = null;
            }
            return new UpdateResult(UpdateStatus.Updated, databaseName, localVersion, remoteVersion, "Database downloaded, cryptographically verified, validated, and installed.");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or FormatException)
        {
            return new UpdateResult(UpdateStatus.Failed, databaseName, localVersion, null, ex.Message);
        }
        finally
        {
            TryDeleteFile(temp);
            if (detachedSignatureTemp is not null) TryDeleteFile(detachedSignatureTemp);
        }
    }


    public Task ApplyCdiffAsync(string databaseDirectory, string patchFile, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databaseDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(patchFile);
        return new CdiffPatchApplier(_options.CertsDirectory).ApplyAsync(patchFile, Path.GetFullPath(databaseDirectory), cancellationToken);
    }

    private async Task<uint> DownloadAndReadHeaderAsync(Uri uri, string temp, CancellationToken cancellationToken)
    {
        using var response = await _http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotModified) throw new InvalidDataException("The remote endpoint returned 304 without a local conditional request.");
        response.EnsureSuccessStatusCode();
        await using (var input = await response.Content.ReadAsStreamAsync(cancellationToken))
        await using (var output = File.Create(temp))
            await input.CopyToAsync(output, cancellationToken);
        return CvdReader.ReadHeader(temp).Version;
    }

    private async Task<bool> TryDownloadSignatureAsync(Uri uri, string destination, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await _http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode == HttpStatusCode.NotFound || response.StatusCode == HttpStatusCode.NoContent)
                return false;
            response.EnsureSuccessStatusCode();
            await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
            await using var output = File.Create(destination);
            await input.CopyToAsync(output, cancellationToken);
            var length = new FileInfo(destination).Length;
            if (length is <= 0 or > 16 * 1024 * 1024)
                throw new InvalidDataException("Detached signature file is outside the supported range.");
            return true;
        }
        catch (HttpRequestException)
        {
            return false;
        }
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    private static void AtomicReplace(string source, string destination)
    {
        if (File.Exists(destination))
        {
            var backup = destination + ".old";
            try
            {
                File.Replace(source, destination, backup, ignoreMetadataErrors: true);
                if (File.Exists(backup)) File.Delete(backup);
                return;
            }
            catch (PlatformNotSupportedException) { }
            catch (IOException) { }
        }
        File.Move(source, destination, overwrite: true);
    }

    private static void TryDeleteDirectory(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); } catch { }
    }
}
