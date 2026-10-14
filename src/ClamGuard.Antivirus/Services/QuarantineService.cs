using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using ClamGuard.Antivirus.Models;

namespace ClamGuard.Antivirus.Services;

public sealed class QuarantineService
{
    private readonly string _metadataPath = Path.Combine(AppPaths.QuarantineDirectory, "index.json");
    private readonly object _indexLock = new();

    public QuarantineService()
    {
        Directory.CreateDirectory(AppPaths.QuarantineDirectory);
    }

    public IReadOnlyList<QuarantineItem> GetItems()
    {
        try
        {
            if (!File.Exists(_metadataPath)) return [];
            var items = JsonSerializer.Deserialize<List<QuarantineItem>>(File.ReadAllText(_metadataPath)) ?? [];
            return items.Where(x => File.Exists(x.StoredPath)).OrderByDescending(x => x.QuarantinedAt).ToArray();
        }
        catch (JsonException) { return []; }
        catch (IOException) { return []; }
    }

    public async Task<QuarantineItem> QuarantineAsync(string filePath, string detection, CancellationToken token = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        var fullPath = Path.GetFullPath(filePath);
        if (!File.Exists(fullPath)) throw new FileNotFoundException("File not found.", fullPath);
        ThrowIfInsideStore(fullPath, "quarantine");

        Directory.CreateDirectory(AppPaths.QuarantineDirectory);
        var id = Guid.NewGuid().ToString("N");
        var storedPath = Path.Combine(AppPaths.QuarantineDirectory, id + ".qtn");
        var info = new FileInfo(fullPath);

        await Task.Run(() =>
        {
            token.ThrowIfCancellationRequested();
            SealFile(fullPath, storedPath);
            try
            {
                File.Delete(fullPath);
            }
            catch
            {
                // Roll back the sealed copy so a failed quarantine does not
                // leave an unindexed orphan in the store.
                try
                {
                    File.SetAttributes(storedPath, FileAttributes.Normal);
                    File.Delete(storedPath);
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                throw;
            }
        }, token).ConfigureAwait(false);

        var item = new QuarantineItem(id, fullPath, storedPath, detection, info.Length, DateTimeOffset.Now);
        lock (_indexLock)
        {
            var items = GetItems().ToList();
            items.Add(item);
            Save(items);
        }
        return item;
    }

    public void Restore(QuarantineItem item)
    {
        if (File.Exists(item.OriginalPath))
            throw new IOException("The original location already contains a file.");
        if (!File.Exists(item.StoredPath))
            throw new FileNotFoundException("Quarantined file is missing.", item.StoredPath);

        // index.json lives in a world-writable directory; never let a tampered
        // entry direct the restore write into the quarantine store itself as a
        // local file-write primitive.
        var target = Path.GetFullPath(item.OriginalPath);
        ThrowIfInsideStore(target, "restore");

        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        using (var input = OpenStored(item.StoredPath, out var decryptor, out var ownerStream))
        using (var output = File.Create(target))
        using (decryptor)
        {
            if (decryptor is not null)
            {
                using var crypto = new CryptoStream(input, decryptor, CryptoStreamMode.Read);
                crypto.CopyTo(output, 1024 * 1024);
            }
            else
            {
                ownerStream!.Position = 0;
                ownerStream.CopyTo(output, 1024 * 1024);
            }
        }
        File.SetAttributes(target, FileAttributes.Normal);
        lock (_indexLock)
        {
            Remove(item.Id);
        }
    }

    public void Delete(QuarantineItem item)
    {
        if (File.Exists(item.StoredPath))
        {
            // Quarantined files carry Hidden|ReadOnly; File.Delete throws
            // UnauthorizedAccessException on a read-only file, so clear the
            // attributes first.
            File.SetAttributes(item.StoredPath, FileAttributes.Normal);
            File.Delete(item.StoredPath);
        }
        lock (_indexLock)
        {
            Remove(item.Id);
        }
    }

    private void Remove(string id)
    {
        var items = GetItems().Where(x => !string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase)).ToArray();
        Save(items);
    }

    private void Save(IReadOnlyCollection<QuarantineItem> items)
    {
        Directory.CreateDirectory(AppPaths.QuarantineDirectory);
        var temp = _metadataPath + ".tmp";
        var json = JsonSerializer.Serialize(items, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(temp, json);
        File.Move(temp, _metadataPath, overwrite: true);
    }

    private static void ThrowIfInsideStore(string fullPath, string operation)
    {
        var store = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppPaths.QuarantineDirectory))
                    + Path.DirectorySeparatorChar;
        if (fullPath.StartsWith(store, StringComparison.OrdinalIgnoreCase))
            throw new IOException($"Refusing to {operation} a file inside the quarantine store.");
    }

    // --- DPAPI-sealed storage -------------------------------------------------
    // Quarantined malware must not sit in a world-readable directory as an
    // executable plaintext blob. The file body is encrypted with a per-item
    // AES-256-CBC key (streamed, so large files never materialize in RAM) and
    // the 48-byte key||IV pair is sealed with DPAPI (crypt32), scoping
    // decryption to the current user without external key management.
    // Legacy entries written before this change (magic absent) are still
    // restorable as plaintext.

    private const uint QuarantineBlobMagic = 0x5147434Du; // "MCGQ"
    private const byte QuarantineBlobVersion = 2;
    private const uint CRYPTPROTECT_UI_FORBIDDEN = 0x1;
    private const int KeyMaterialLength = 48; // 32-byte AES key + 16-byte IV

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int CbData;
        public IntPtr PbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, EntryPoint = "CryptProtectData")]
    private static extern bool CryptProtectData(ref DataBlob dataIn, string? description, IntPtr optionalEntropy, IntPtr reserved, IntPtr prompt, uint flags, out DataBlob dataOut);

    [DllImport("crypt32.dll", SetLastError = true, EntryPoint = "CryptUnprotectData")]
    private static extern bool CryptUnprotectData(ref DataBlob dataIn, IntPtr description, IntPtr optionalEntropy, IntPtr reserved, IntPtr prompt, uint flags, out DataBlob dataOut);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr handle);

    private static void SealFile(string sourcePath, string storedPath)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();

        var keyMaterial = new byte[KeyMaterialLength];
        aes.Key.CopyTo(keyMaterial, 0);
        aes.IV.CopyTo(keyMaterial, 32);
        var header = Protect(keyMaterial);

        using (var output = File.Create(storedPath))
        {
            Span<byte> preamble = stackalloc byte[9];
            BitConverter.TryWriteBytes(preamble[..4], QuarantineBlobMagic);
            preamble[4] = QuarantineBlobVersion;
            BitConverter.TryWriteBytes(preamble.Slice(5, 4), header.Length);
            output.Write(preamble);
            output.Write(header);

            using var crypto = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write);
            using var input = File.OpenRead(sourcePath);
            input.CopyTo(crypto, 1024 * 1024);
        }
        File.SetAttributes(storedPath, FileAttributes.Hidden | FileAttributes.ReadOnly);
    }

    /// <summary>
    /// Opens a stored item for reading. Returns the decrypted stream (or the
    /// raw stream for legacy plaintext entries); the caller must dispose both
    /// the returned stream and the <paramref name="decryptor"/>.
    /// </summary>
    private static Stream OpenStored(string storedPath, out ICryptoTransform? decryptor, out FileStream? rawStream)
    {
        var input = File.OpenRead(storedPath);
        try
        {
            Span<byte> preamble = stackalloc byte[9];
            if (input.Read(preamble) != preamble.Length ||
                BitConverter.ToUInt32(preamble[..4]) != QuarantineBlobMagic)
            {
                // Legacy plaintext entry.
                decryptor = null;
                rawStream = input;
                input.Position = 0;
                return input;
            }

            if (preamble[4] != QuarantineBlobVersion)
                throw new IOException("Unsupported quarantine blob version.");

            Span<byte> lengthPrefix = stackalloc byte[4];
            input.ReadExactly(lengthPrefix);
            var headerLength = BitConverter.ToInt32(lengthPrefix);
            if (headerLength is < 16 or > 4096)
                throw new IOException("Corrupt quarantine header.");
            var header = new byte[headerLength];
            input.ReadExactly(header);
            var keyMaterial = Unprotect(header);
            if (keyMaterial.Length != KeyMaterialLength)
                throw new IOException("Corrupt quarantine key material.");

            // The transform stays valid after the Aes instance goes out of
            // scope; the caller disposes the transform.
            var aes = Aes.Create();
            aes.Key = keyMaterial[..32];
            aes.IV = keyMaterial[32..];
            decryptor = aes.CreateDecryptor();
            rawStream = null;
            return input;
        }
        catch
        {
            input.Dispose();
            throw;
        }
    }

    private static byte[] Protect(byte[] plaintext)
    {
        var input = IntPtr.Zero;
        var output = IntPtr.Zero;
        try
        {
            input = Marshal.AllocHGlobal(plaintext.Length);
            Marshal.Copy(plaintext, 0, input, plaintext.Length);
            var blobIn = new DataBlob { CbData = plaintext.Length, PbData = input };
            if (!CryptProtectData(ref blobIn, "ClamGuard quarantine", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, out var blobOut))
                throw new IOException("Failed to seal quarantine key (DPAPI).", Marshal.GetLastWin32Error());
            output = blobOut.PbData;
            var sealedBytes = new byte[blobOut.CbData];
            Marshal.Copy(output, sealedBytes, 0, blobOut.CbData);
            return sealedBytes;
        }
        finally
        {
            if (input != IntPtr.Zero) Marshal.FreeHGlobal(input);
            if (output != IntPtr.Zero) LocalFree(output);
        }
    }

    private static byte[] Unprotect(byte[] sealedBytes)
    {
        var input = IntPtr.Zero;
        var output = IntPtr.Zero;
        try
        {
            input = Marshal.AllocHGlobal(sealedBytes.Length);
            Marshal.Copy(sealedBytes, 0, input, sealedBytes.Length);
            var blobIn = new DataBlob { CbData = sealedBytes.Length, PbData = input };
            if (!CryptUnprotectData(ref blobIn, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, out var blobOut))
                throw new IOException("Failed to unseal quarantine key (DPAPI).", Marshal.GetLastWin32Error());
            output = blobOut.PbData;
            var plaintext = new byte[blobOut.CbData];
            Marshal.Copy(output, plaintext, 0, blobOut.CbData);
            return plaintext;
        }
        finally
        {
            if (input != IntPtr.Zero) Marshal.FreeHGlobal(input);
            if (output != IntPtr.Zero) LocalFree(output);
        }
    }
}
