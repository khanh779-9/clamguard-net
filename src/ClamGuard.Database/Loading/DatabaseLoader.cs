using ClamGuard.Core;
using ClamGuard.Database.Storage;
using ClamGuard.Signatures.Parsing;

namespace ClamGuard.Database;

public sealed partial class DatabaseLoader
{
    // This is the signature functionality level used by ClamAV 1.5.4.
    // Keeping it configurable also allows future compatibility profiles.
    public int EngineFunctionalityLevel { get; init; } = 234;

    /// <summary>
    /// Include ClamAV Potentially Unwanted Application (PUA) signature databases
    /// (.hdu/.hsu/.mdu/.msu/.ndu/.ldu). ClamAV skips these unless PUA scanning is enabled.
    /// </summary>
    public bool IncludePua { get; init; }

    /// <summary>Only load PUA signatures whose second name token matches one of these categories.</summary>
    public IReadOnlyCollection<string> IncludePuaCategories { get; init; } = Array.Empty<string>();

    /// <summary>Load PUA signatures except those whose second name token matches one of these categories.</summary>
    public IReadOnlyCollection<string> ExcludePuaCategories { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Optional persistent cache directory for extracted container files (.cvd/.cld/.cud).
    /// If specified, archives are only extracted once per version/MD5, avoiding redundant disk I/O and temp extraction.
    /// </summary>
    public string? CacheDirectory { get; init; }

    public DatabaseLoadResult LoadDirectory(string directory, bool failOnInvalidFile = false, bool verifyContainers = true)
    {
        if (!Directory.Exists(directory)) throw new DirectoryNotFoundException(directory);
        ValidatePuaCategoryOptions();

        var db = new SignatureDatabase();
        var infos = new List<DatabaseInfo>();
        var errors = new List<DatabaseLoadError>();
        var tempRoots = new List<string>();
        var ignoreRules = new IgnoreRuleSet();
        var paths = Directory.EnumerateFiles(directory)
            .OrderBy(GetLoadPriority)
            .ThenBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        CvdHeader? dailyCldHeader = null;
        CvdHeader? dailyCvdHeader = null;
        var invalidDailyPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // ClamAV 1.5.4 loads all .ign/.ign2 files before normal signatures so
        // they can suppress signatures from every later database. Keep errors on
        // the same failOnInvalidFile path as other database files.
        foreach (var ignorePath in paths.Where(IsIgnoreDatabasePath).OrderBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                ignoreRules.LoadFile(ignorePath);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or FormatException)
            {
                errors.Add(new DatabaseLoadError(ignorePath, ex.Message));
                if (failOnInvalidFile)
                    throw new InvalidDataException($"Failed to load database '{ignorePath}': {ex.Message}", ex);
            }
        }

        var dailyClDPath = paths.FirstOrDefault(x =>
            string.Equals(Path.GetFileName(x), "daily.cld", StringComparison.Ordinal));
        var dailyCvDPath = paths.FirstOrDefault(x =>
            string.Equals(Path.GetFileName(x), "daily.cvd", StringComparison.Ordinal));

        void ReadDailyHeader(string? path, out CvdHeader? header)
        {
            header = null;
            if (path is null) return;
            try
            {
                header = CvdReader.ReadHeader(path);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or FormatException)
            {
                invalidDailyPaths.Add(path);
                errors.Add(new DatabaseLoadError(path, ex.Message));
                if (failOnInvalidFile)
                    throw new InvalidDataException($"Failed to load database '{path}': {ex.Message}", ex);
            }
        }

        // ClamAV 1.5.4 treats daily.cld/daily.cvd as a mutually-exclusive pair:
        // load the one with the highest header version, and prefer daily.cld on a tie.
        // Headers are inspected before the choice so the result is independent of
        // filesystem enumeration order.
        ReadDailyHeader(dailyClDPath, out dailyCldHeader);
        ReadDailyHeader(dailyCvDPath, out dailyCvdHeader);

        string? selectedDailyPath = null;
        if (dailyCldHeader is not null && dailyCvdHeader is not null)
        {
            selectedDailyPath = dailyCldHeader.Version >= dailyCvdHeader.Version
                ? dailyClDPath
                : dailyCvDPath;
        }
        else if (dailyCldHeader is not null)
        {
            selectedDailyPath = dailyClDPath;
        }
        else if (dailyCvdHeader is not null)
        {
            selectedDailyPath = dailyCvDPath;
        }

        try
        {
            foreach (var path in paths)
            {
                var extension = Path.GetExtension(path).ToLowerInvariant();
                try
                {
                    if (invalidDailyPaths.Contains(path))
                        continue;

                    if ((string.Equals(Path.GetFileName(path), "daily.cld", StringComparison.Ordinal) ||
                         string.Equals(Path.GetFileName(path), "daily.cvd", StringComparison.Ordinal)) &&
                        !string.Equals(path, selectedDailyPath, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    if (IsIgnoreDatabasePath(path))
                        continue;

                    if (IsPuaDatabasePath(path) && !ShouldLoadPuaDatabase())
                    {
                        continue;
                    }

                    if (extension is ".cvd" or ".cld" or ".cud")
                    {
                        var header = extension == ".cld" && string.Equals(path, dailyClDPath, StringComparison.OrdinalIgnoreCase) && dailyCldHeader is not null
                            ? dailyCldHeader
                            : extension == ".cvd" && string.Equals(path, dailyCvDPath, StringComparison.OrdinalIgnoreCase) && dailyCvdHeader is not null
                                ? dailyCvdHeader
                                : CvdReader.ReadHeader(path);
                        var verified = !verifyContainers;
                        if (verifyContainers && extension == ".cvd")
                        {
                            var verification = DatabaseVerifier.VerifyCvd(path);
                            if (verification.Status != DatabaseVerificationStatus.Verified)
                                throw new InvalidDataException($"Database verification failed: {verification.Message}");
                            verified = true;
                        }
                        infos.Add(ToInfo(Path.GetFileName(path), header, isVerified: verified));

                        var usePersistentCache = !string.IsNullOrWhiteSpace(CacheDirectory);
                        string containerExtractDir;
                        var isCacheValid = false;

                        if (usePersistentCache)
                        {
                            var safeName = Path.GetFileNameWithoutExtension(path);
                            containerExtractDir = Path.Combine(CacheDirectory!, $"{safeName}_{header.Version}_{header.Md5}");
                            var tagPath = Path.Combine(containerExtractDir, ".complete");
                            if (Directory.Exists(containerExtractDir) && File.Exists(tagPath))
                            {
                                isCacheValid = true;
                            }
                        }
                        else
                        {
                            containerExtractDir = Path.Combine(Path.GetTempPath(), $"clamguard-cvd-{Guid.NewGuid():N}");
                            tempRoots.Add(containerExtractDir);
                        }

                        if (!isCacheValid)
                        {
                            if (usePersistentCache && Directory.Exists(containerExtractDir))
                            {
                                try { Directory.Delete(containerExtractDir, true); } catch { /* Ignore */ }
                            }

                            CvdReader.Extract(path, containerExtractDir);

                            if (usePersistentCache)
                            {
                                try
                                {
                                    File.WriteAllText(Path.Combine(containerExtractDir, ".complete"), $"{header.Version}:{header.Md5}");
                                }
                                catch { /* Best-effort cache marker */ }
                            }
                        }

                        LoadTextFiles(containerExtractDir, db, infos, errors, failOnInvalidFile, ignoreRules);
                        continue;
                    }

                    LoadTextFile(path, db, infos, ignoreRules);
                }
                catch (Exception ex) when (ex is IOException or InvalidDataException or FormatException)
                {
                    errors.Add(new DatabaseLoadError(path, ex.Message));
                    if (failOnInvalidFile)
                        throw new InvalidDataException($"Failed to load database '{path}': {ex.Message}", ex);
                }
            }
        }
        finally
        {
            foreach (var temp in tempRoots)
            {
                try { if (Directory.Exists(temp)) Directory.Delete(temp, true); }
                catch { /* Best-effort cleanup. */ }
            }
        }

        db.Databases = infos;
        // cli_dconf_load(): resolve the per-module dconf masks for the engine
        // flevel once after every database file has been loaded.
        db.DynamicConfiguration = DynamicConfiguration.Resolve(db.SpecialDatabases.DynamicConfig, EngineFunctionalityLevel);
        return new DatabaseLoadResult
        {
            Database = db,
            Files = infos,
            Errors = errors
        };
    }

    private void LoadTextFiles(
        string directory,
        SignatureDatabase db,
        List<DatabaseInfo> infos,
        List<DatabaseLoadError> errors,
        bool failOnInvalidFile,
        IgnoreRuleSet ignoreRules)
    {
        // CVDs are processed as a sequence of database entries. ClamAV's
        // packaged databases place ignore files before the signatures they suppress;
        // preloading the extracted ignore files preserves that property regardless
        // of tar/filesystem enumeration order.
        foreach (var path in Directory.EnumerateFiles(directory).Where(IsIgnoreDatabasePath).OrderBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                ignoreRules.LoadFile(path);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or FormatException)
            {
                errors.Add(new DatabaseLoadError(path, ex.Message));
                if (failOnInvalidFile)
                    throw new InvalidDataException($"Failed to load database '{path}': {ex.Message}", ex);
            }
        }

        foreach (var path in Directory.EnumerateFiles(directory).OrderBy(GetLoadPriority).ThenBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                if (IsIgnoreDatabasePath(path))
                    continue;
                if (IsPuaDatabasePath(path) && !ShouldLoadPuaDatabase())
                    continue;
                LoadTextFile(path, db, infos, ignoreRules);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or FormatException)
            {
                errors.Add(new DatabaseLoadError(path, ex.Message));
                if (failOnInvalidFile)
                    throw new InvalidDataException($"Failed to load extracted database '{path}': {ex.Message}", ex);
            }
        }
    }

    private static int GetLoadPriority(string path)
    {
        var name = Path.GetFileName(path);
        var ext = Path.GetExtension(path);
        if (ext.Equals(".ign", StringComparison.OrdinalIgnoreCase) || ext.Equals(".ign2", StringComparison.OrdinalIgnoreCase)) return 1;
        if (name.Equals("daily.cld", StringComparison.Ordinal)) return 2;
        if (name.Equals("daily.cvd", StringComparison.Ordinal)) return 3;
        if (name.Equals("local.gdb", StringComparison.Ordinal)) return 4;
        if (name.Equals("daily.cfg", StringComparison.Ordinal)) return 5;
        if (ext.Equals(".crb", StringComparison.OrdinalIgnoreCase)) return 6;
        return 7;
    }

    private static bool IsIgnoreDatabasePath(string path)
    {
        var extension = Path.GetExtension(path);
        return extension.Equals(".ign", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".ign2", StringComparison.OrdinalIgnoreCase);
    }


    private void ValidatePuaCategoryOptions()
    {
        if (IncludePuaCategories.Count > 0 && ExcludePuaCategories.Count > 0)
            throw new ArgumentException("IncludePuaCategories and ExcludePuaCategories cannot both be configured.");

        foreach (var category in IncludePuaCategories.Concat(ExcludePuaCategories))
        {
            if (string.IsNullOrWhiteSpace(category) ||
                category.Any(char.IsWhiteSpace) ||
                category.Contains('.') ||
                category.Contains(':'))
            {
                throw new ArgumentException($"Invalid PUA category '{category}'.");
            }
        }
    }

    private bool ShouldLoadPuaDatabase()
        => IncludePua || IncludePuaCategories.Count > 0 || ExcludePuaCategories.Count > 0;

    private bool ShouldLoadPuaSignature(string signatureName)
    {
        // Without IncludePUA/ExcludePUA category filtering, DetectPUA simply loads
        // the PUA database as-is. Category filtering follows ClamAV's cli_chkpua:
        // the category is the second token in a name such as PUA.Win.Packer.X.
        if (IncludePuaCategories.Count == 0 && ExcludePuaCategories.Count == 0)
            return true;

        if (!signatureName.StartsWith("PUA.", StringComparison.Ordinal))
            return false;

        var remainder = signatureName[4..];
        var separator = remainder.IndexOf('.');
        if (separator <= 0)
            return false;

        var category = remainder[..separator];
        if (IncludePuaCategories.Count > 0)
            return IncludePuaCategories.Any(x => string.Equals(x, category, StringComparison.Ordinal));

        return !ExcludePuaCategories.Any(x => string.Equals(x, category, StringComparison.Ordinal));
    }

    private static bool IsPuaDatabasePath(string path)
    {
        var extension = Path.GetExtension(path);
        return extension.Equals(".hdu", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".hsu", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".mdu", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".msu", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".ndu", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".ldu", StringComparison.OrdinalIgnoreCase);
    }
}
