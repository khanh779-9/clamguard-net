using System.IO;
using System.Text.Json;
using ClamGuard.Antivirus.Models;

namespace ClamGuard.Antivirus.Services;

public sealed class QuarantineService
{
    private readonly string _metadataPath = Path.Combine(AppPaths.QuarantineDirectory, "index.json");

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

        Directory.CreateDirectory(AppPaths.QuarantineDirectory);
        var id = Guid.NewGuid().ToString("N");
        var storedPath = Path.Combine(AppPaths.QuarantineDirectory, id + ".qtn");
        var info = new FileInfo(fullPath);

        await Task.Run(() =>
        {
            token.ThrowIfCancellationRequested();
            try
            {
                File.Move(fullPath, storedPath);
            }
            catch (IOException)
            {
                File.Copy(fullPath, storedPath, overwrite: false);
                File.Delete(fullPath);
            }
            File.SetAttributes(storedPath, FileAttributes.Hidden | FileAttributes.ReadOnly);
        }, token).ConfigureAwait(false);

        var item = new QuarantineItem(id, fullPath, storedPath, detection, info.Length, DateTimeOffset.Now);
        var items = GetItems().ToList();
        items.Add(item);
        Save(items);
        return item;
    }

    public void Restore(QuarantineItem item)
    {
        if (File.Exists(item.OriginalPath))
            throw new IOException("The original location already contains a file.");
        if (!File.Exists(item.StoredPath))
            throw new FileNotFoundException("Quarantined file is missing.", item.StoredPath);

        Directory.CreateDirectory(Path.GetDirectoryName(item.OriginalPath)!);
        File.SetAttributes(item.StoredPath, FileAttributes.Normal);
        File.Move(item.StoredPath, item.OriginalPath);
        Remove(item.Id);
    }

    public void Delete(QuarantineItem item)
    {
        if (File.Exists(item.StoredPath))
            File.Delete(item.StoredPath);
        Remove(item.Id);
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
}
