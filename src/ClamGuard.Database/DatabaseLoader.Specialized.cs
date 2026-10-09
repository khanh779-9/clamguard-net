using ClamGuard.Core;
using ClamGuard.Signatures;
using ClamGuard.Signatures.Parsing;
using ClamGuard.Yara;
using ClamGuard.Bytecode;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using ClamGuard.Database.Storage;

namespace ClamGuard.Database;

public sealed partial class DatabaseLoader
{
    private void LoadTextFile(string path, SignatureDatabase db, List<DatabaseInfo> infos, IgnoreRuleSet ignoreRules)
    {
        var ext = Path.GetExtension(path);
        if (string.Equals(Path.GetFileName(path), "COPYING", StringComparison.OrdinalIgnoreCase))
            return;

        if (ext.Equals(".ftm", StringComparison.OrdinalIgnoreCase))
        {
            LoadFtmFile(path, db, infos);
            return;
        }
        if (ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase))
        {
            LoadDconfFile(path, db, infos);
            return;
        }
        if (ext.Equals(".wdb", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".pdb", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".gdb", StringComparison.OrdinalIgnoreCase))
        {
            LoadPhishingFile(path, db, infos, allowList: ext.Equals(".wdb", StringComparison.OrdinalIgnoreCase));
            return;
        }
        if (ext.Equals(".pwdb", StringComparison.OrdinalIgnoreCase))
        {
            LoadPwdbFile(path, db, infos, ignoreRules);
            return;
        }
        if (ext.Equals(".crb", StringComparison.OrdinalIgnoreCase))
        {
            LoadCertificateFile(path, db, infos);
            return;
        }
        if (ext.Equals(".cat", StringComparison.OrdinalIgnoreCase))
        {
            LoadCatalogFile(path, db, infos);
            return;
        }
        if (ext.Equals(".ioc", StringComparison.OrdinalIgnoreCase))
        {
            LoadOpenIocFile(path, db, infos);
            return;
        }
        if (ext.Equals(".yar", StringComparison.OrdinalIgnoreCase) || ext.Equals(".yara", StringComparison.OrdinalIgnoreCase))
        {
            LoadYaraFile(path, db, infos);
            return;
        }
        if (ext.Equals(".cbc", StringComparison.OrdinalIgnoreCase))
        {
            LoadBytecodeFile(path, db, infos);
            return;
        }
        if (ext.Equals(".info", StringComparison.OrdinalIgnoreCase))
        {
            LoadInfoFile(path, db, infos);
            return;
        }

        if (string.Equals(Path.GetExtension(path), ".idb", StringComparison.OrdinalIgnoreCase))
        {
            var iconDatabase = SignatureParser.ParseIdbFile(path);
            if (iconDatabase.Entries.Count == 0)
                return;
            var filteredEntries = iconDatabase.Entries
                .Where(entry => !ignoreRules.ShouldIgnore(entry.Name, entry.SourceEntry))
                .ToArray();
            if (filteredEntries.Length == 0)
                return;
            if (db.IconDatabase is null)
            {
                db.IconDatabase = new IconDatabase();
                foreach (var entry in filteredEntries)
                    db.IconDatabase.Add(entry);
            }
            else
                foreach (var entry in filteredEntries)
                    db.IconDatabase.Add(entry);
            infos.Add(new DatabaseInfo(
                Path.GetFileName(path),
                DatabaseFormat.TextSignature,
                0,
                (uint)iconDatabase.Entries.Count,
                (uint)EngineFunctionalityLevel,
                null,
                null,
                null,
                false));
            return;
        }

        var isPuaDatabase = IsPuaDatabasePath(path);
        var count = 0;
        foreach (var signature in SignatureParser.ParseFile(path, EngineFunctionalityLevel))
        {
            if (isPuaDatabase && !ShouldLoadPuaSignature(signature.Name))
                continue;
            if (ignoreRules.ShouldIgnore(signature))
                continue;

            db.Add(signature);
            count++;
        }

        if (count == 0)
            return;

        infos.Add(new DatabaseInfo(
            Path.GetFileName(path),
            DatabaseFormat.TextSignature,
            0,
            (uint)count,
            (uint)EngineFunctionalityLevel,
            null,
            null,
            null,
            false));
    }


    private void AddSpecialInfo(string path, int count, List<DatabaseInfo> infos)
    {
        if (count <= 0) return;
        infos.Add(new DatabaseInfo(
            Path.GetFileName(path),
            DatabaseFormat.TextSignature,
            0,
            (uint)count,
            (uint)EngineFunctionalityLevel,
            null, null, null, false));
    }

    private void LoadFtmFile(string path, SignatureDatabase db, List<DatabaseInfo> infos)
    {
        var count = 0;
        foreach (var raw in File.ReadLines(path))
        {
            if (raw.StartsWith('#')) continue;
            var parts = raw.Split(':');
            if (parts.Length is < 6 or > 8)
                throw new FormatException($"Invalid FTM signature in {path}: {raw}");
            var mode = ParseUnsignedInt(parts[0], "FTM mode", path, raw);
            int? numericOffset = null;
            if (mode is 0 or 4)
            {
                numericOffset = ParseSignedInt(parts[1], "FTM offset", path, raw);
                if (numericOffset < 0) throw new FormatException($"Invalid FTM offset in {path}: {raw}");
            }
            else if (mode == 1 && string.IsNullOrEmpty(parts[1]))
            {
                throw new FormatException($"Invalid FTM content offset in {path}: {raw}");
            }
            if (string.IsNullOrEmpty(parts[3]))
                throw new FormatException($"Invalid FTM type name in {path}: {raw}");
            if (!IsKnownClamAvFileType(parts[4]) || !IsKnownClamAvFileType(parts[5]))
                throw new FormatException($"Invalid FTM file type code in {path}: {raw}");
            byte[]? magic = null;
            if (mode is 0 or 4)
            {
                if (parts[2].Length == 0 || (parts[2].Length & 1) != 0 || !TryHex(parts[2], out magic))
                    throw new FormatException($"Invalid FTM magic in {path}: {raw}");
            }
            else if (mode == 1 && parts[2].Length == 0)
            {
                throw new FormatException($"Invalid FTM content pattern in {path}: {raw}");
            }
            var min = parts.Length >= 7 ? ParseOptionalFlevel(parts[6], path, raw) : null;
            var max = parts.Length == 8 ? ParseOptionalFlevel(parts[7], path, raw) : null;
            if (min is not null && min > EngineFunctionalityLevel) continue;
            if (max is not null && max < EngineFunctionalityLevel) continue;
            if (mode is not 0 and not 1 and not 4) continue; // ClamAV logs unsupported modes and keeps loading.
            // cli_loadftm() prepends each definition to the engine list. Preserve
            // that precedence: later definitions in a database override earlier
            // definitions when their magic overlaps.
            db.SpecialDatabases.FileTypes.Insert(0, new FileTypeMagicRule(mode, parts[1], numericOffset, parts[2], magic, parts[4], parts[5], min, max, mode == 4));
            count++;
        }
        AddSpecialInfo(path, count, infos);
        if (count == 0) throw new InvalidDataException($"Empty or unsupported FTM database: {path}");
    }

    private static bool IsKnownClamAvFileType(string value) => value is
        "CL_TYPE_TEXT_ASCII" or "CL_TYPE_TEXT_UTF8" or "CL_TYPE_TEXT_UTF16LE" or "CL_TYPE_TEXT_UTF16BE" or
        "CL_TYPE_BINARY_DATA" or "CL_TYPE_IGNORED" or "CL_TYPE_ANY" or "CL_TYPE_MSEXE" or "CL_TYPE_ELF" or
        "CL_TYPE_MACHO" or "CL_TYPE_MACHO_UNIBIN" or "CL_TYPE_POSIX_TAR" or "CL_TYPE_OLD_TAR" or
        "CL_TYPE_CPIO_OLD" or "CL_TYPE_CPIO_ODC" or "CL_TYPE_CPIO_NEWC" or "CL_TYPE_CPIO_CRC" or
        "CL_TYPE_GZ" or "CL_TYPE_ZIP" or "CL_TYPE_BZ" or "CL_TYPE_RAR" or "CL_TYPE_ARJ" or
        "CL_TYPE_MSSZDD" or "CL_TYPE_MSOLE2" or "CL_TYPE_MSCAB" or "CL_TYPE_MSCHM" or "CL_TYPE_SIS" or
        "CL_TYPE_SCRENC" or "CL_TYPE_GRAPHICS" or "CL_TYPE_GIF" or "CL_TYPE_PNG" or "CL_TYPE_JPEG" or
        "CL_TYPE_TIFF" or "CL_TYPE_RIFF" or "CL_TYPE_BINHEX" or "CL_TYPE_TNEF" or "CL_TYPE_CRYPTFF" or
        "CL_TYPE_PDF" or "CL_TYPE_UUENCODED" or "CL_TYPE_HTML_UTF16" or "CL_TYPE_SCRIPT" or "CL_TYPE_RTF" or
        "CL_TYPE_HTML" or "CL_TYPE_MAIL" or "CL_TYPE_SFX" or "CL_TYPE_ZIPSFX" or "CL_TYPE_RARSFX" or
        "CL_TYPE_CABSFX" or "CL_TYPE_ARJSFX" or "CL_TYPE_NULSFT" or "CL_TYPE_AUTOIT" or "CL_TYPE_ISHIELD_MSI" or
        "CL_TYPE_7Z" or "CL_TYPE_7ZSFX" or "CL_TYPE_SWF" or "CL_TYPE_ISO9660" or "CL_TYPE_JAVA" or
        "CL_TYPE_DMG" or "CL_TYPE_MBR" or "CL_TYPE_GPT" or "CL_TYPE_APM" or "CL_TYPE_XAR" or
        "CL_TYPE_PART_ANY" or "CL_TYPE_PART_HFSPLUS" or "CL_TYPE_XZ" or "CL_TYPE_OOXML_WORD" or
        "CL_TYPE_OOXML_PPT" or "CL_TYPE_OOXML_XL" or "CL_TYPE_INTERNAL" or "CL_TYPE_XDP" or
        "CL_TYPE_XML_WORD" or "CL_TYPE_XML_XL" or "CL_TYPE_HWP3" or "CL_TYPE_XML_HWP" or "CL_TYPE_HWPOLE2" or
        "CL_TYPE_OOXML_HWP" or "CL_TYPE_PS" or "CL_TYPE_MHTML" or "CL_TYPE_LNK" or "CL_TYPE_EGG" or
        "CL_TYPE_EGGSFX" or "CL_TYPE_UDF" or "CL_TYPE_ALZ" or "CL_TYPE_ONENOTE" or
        "CL_TYPE_PYTHON_COMPILED" or "CL_TYPE_LHA_LZH" or "CL_TYPE_AI_MODEL";

    private void LoadDconfFile(string path, SignatureDatabase db, List<DatabaseInfo> infos)
    {
        var count = 0;
        foreach (var raw in File.ReadLines(path))
        {
            if (!TryParseDconf(raw, out var module, out var value, out var min, out var max))
                continue;
            if (min is not null && min > EngineFunctionalityLevel) continue;
            if (max is not null && max < EngineFunctionalityLevel) continue;
            db.SpecialDatabases.DynamicConfig.Add(new DynamicConfigEntry(module, value, min, max, path, raw));
            count++;
        }
        AddSpecialInfo(path, count, infos);
    }

    private static bool TryParseDconf(string line, out string module, out uint value, out int? min, out int? max)
    {
        module = string.Empty; value = 0; min = null; max = null;
        var parts = line.Split(':');
        if (parts.Length < 2 || parts.Length > 4) return false;
        module = parts[0];
        if (module is not ("PE" or "ELF" or "MACHO" or "ARCHIVE" or "DOCUMENT" or "MAIL" or "OTHER" or "PHISHING" or "BYTECODE" or "STATS" or "PCRE"))
            return false;
        if (parts[1].Length < 3 || !parts[1].StartsWith("0x", StringComparison.OrdinalIgnoreCase) ||
            !uint.TryParse(parts[1][2..], System.Globalization.NumberStyles.HexNumber, null, out value))
            throw new FormatException($"Invalid DCONF value: {line}");
        if (parts.Length >= 3) min = ParseOptionalFlevel(parts[2], "<dconf>", line);
        if (parts.Length == 4) max = ParseOptionalFlevel(parts[3], "<dconf>", line);
        return true;
    }

    private void LoadPhishingFile(string path, SignatureDatabase db, List<DatabaseInfo> infos, bool allowList)
    {
        var count = 0;
        foreach (var raw in File.ReadLines(path))
        {
            if (raw.StartsWith('#')) continue;
            if (raw.Length == 0) throw new FormatException($"Blank phishing database line in {path}");
            // ClamAV passes these lines into its PCRE-based regex matcher. Preserve
            // the source expression verbatim; do not reinterpret PCRE as .NET regex.
            db.SpecialDatabases.PhishingRules.Add(new PhishingDatabaseRule(raw, allowList, path, raw));
            count++;
        }
        AddSpecialInfo(path, count, infos);
    }

    private void LoadPwdbFile(string path, SignatureDatabase db, List<DatabaseInfo> infos, IgnoreRuleSet ignoreRules)
    {
        var count = 0;
        foreach (var raw in File.ReadLines(path))
        {
            if (raw.StartsWith('#')) continue;
            var parts = raw.Split(';');
            if (parts.Length != 4)
                throw new FormatException($"Invalid PWDB signature in {path}: {raw}");
            if (ignoreRules.ShouldIgnore(parts[0], parts[0])) continue;
            var attrs = parts[1];
            var container = ParsePwdbContainer(attrs, path, raw);
            if (!int.TryParse(parts[2], out var storageType) || storageType is not (0 or 1))
                continue; // Matches ClamAV's unsupported PWStorageType behavior.
            byte[] value;
            if (storageType == 0) value = Encoding.UTF8.GetBytes(parts[3]);
            else if (!TryHex(parts[3], out value)) throw new FormatException($"Invalid encoded PWDB password in {path}: {raw}");
            db.SpecialDatabases.Passwords.Add(new PasswordDatabaseEntry(parts[0], attrs, container, storageType, value, path, raw));
            count++;
        }
        AddSpecialInfo(path, count, infos);
    }

    private static string ParsePwdbContainer(string attrs, string path, string line)
    {
        if (string.IsNullOrWhiteSpace(attrs)) return "ANY";
        foreach (var token in attrs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!token.StartsWith("Container:", StringComparison.OrdinalIgnoreCase)) continue;
            var value = token[10..];
            if (value.Contains("ZIP", StringComparison.OrdinalIgnoreCase)) return "ZIP";
            if (value.Contains("RAR", StringComparison.OrdinalIgnoreCase)) return "RAR";
            if (value.Contains("ANY", StringComparison.OrdinalIgnoreCase)) return "ANY";
            throw new FormatException($"Invalid PWDB container in {path}: {line}");
        }
        return "ANY";
    }

    private void LoadCertificateFile(string path, SignatureDatabase db, List<DatabaseInfo> infos)
    {
        var count = 0;
        foreach (var raw in File.ReadLines(path))
        {
            if (raw.StartsWith('#')) continue;
            var parts = raw.Split(';');
            if (parts.Length is < 11 or > 13)
                throw new FormatException($"Invalid CRB signature in {path}: {raw}");
            if (!int.TryParse(parts[1], out var trust) || trust is not (0 or 1))
                throw new FormatException($"Invalid CRB trust value in {path}: {raw}");
            if (!TryHexSha1(parts[2], out var subject))
                throw new FormatException($"Invalid CRB subject SHA-1 field in {path}: {raw}");
            byte[] serial;
            if (parts[3].Length == 0) serial = Array.Empty<byte>();
            else if (!TryHexSha1(parts[3], out serial))
                throw new FormatException($"Invalid CRB serial SHA-1 field in {path}: {raw}");
            var min = parts.Length >= 12 ? ParseOptionalFlevel(parts[11], path, raw) : null;
            var max = parts.Length == 13 ? ParseOptionalFlevel(parts[12], path, raw) : null;
            if (min is not null && min > EngineFunctionalityLevel) continue;
            if (max is not null && max < EngineFunctionalityLevel) continue;
            if (!int.TryParse(parts[6], out var codeSign) || !int.TryParse(parts[7], out var timeSign) || !int.TryParse(parts[8], out var certSign) ||
                codeSign is not (0 or 1) || timeSign is not (0 or 1) || certSign is not (0 or 1))
                throw new FormatException($"Invalid CRB trust flags in {path}: {raw}");
            long? notBefore = null;
            if (parts[9].Length != 0 && long.TryParse(parts[9], out var nb)) notBefore = nb;
            db.SpecialDatabases.Certificates.Add(new CertificateDatabaseRule(
                parts[0], trust == 0, subject, serial, parts[4], codeSign == 1, timeSign == 1, certSign == 1,
                notBefore, min, max, path, raw));
            count++;
        }
        AddSpecialInfo(path, count, infos);
    }

    private void LoadCatalogFile(string path, SignatureDatabase db, List<DatabaseInfo> infos)
    {
        var data = File.ReadAllBytes(path);
        if (data.Length == 0) throw new InvalidDataException($"Empty CAT database: {path}");
        var sha256 = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
        var signedDataOid = new byte[] { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };
        var looksLikeSignedData = data.Length > 12 && data[0] == 0x30 && data.AsSpan().IndexOf(signedDataOid) >= 0;
        db.SpecialDatabases.Catalogs.Add(new CatalogDatabaseInfo(Path.GetFileName(path), data.LongLength, sha256, looksLikeSignedData, path));
        AddSpecialInfo(path, 1, infos);
    }

    private void LoadOpenIocFile(string path, SignatureDatabase db, List<DatabaseInfo> infos)
    {
        var count = 0;
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            IgnoreComments = true,
            IgnoreWhitespace = true,
            MaxCharactersInDocument = 16 * 1024 * 1024,
            MaxCharactersFromEntities = 0
        };
        try
        {
            using var reader = XmlReader.Create(path, settings);
            var contextHash = false;
            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.EndElement && reader.LocalName == "Context")
                {
                    contextHash = false;
                    continue;
                }
                if (reader.NodeType == XmlNodeType.Element && reader.LocalName == "Context")
                {
                    var document = reader.GetAttribute("document");
                    var search = reader.GetAttribute("search");
                    contextHash = string.Equals(document, "FileItem", StringComparison.Ordinal) &&
                        (string.Equals(search, "FileItem/Md5sum", StringComparison.Ordinal) ||
                         string.Equals(search, "FileItem/Sha1sum", StringComparison.Ordinal) ||
                         string.Equals(search, "FileItem/Sha256sum", StringComparison.Ordinal));
                    continue;
                }
                if (reader.NodeType != XmlNodeType.Element || reader.LocalName != "Content") continue;
                var type = reader.GetAttribute("type");
                if (!contextHash && type is not null &&
                    !(type.Equals("md5", StringComparison.OrdinalIgnoreCase) || type.Equals("sha1", StringComparison.OrdinalIgnoreCase) || type.Equals("sha256", StringComparison.OrdinalIgnoreCase)))
                    continue;
                var hashText = reader.ReadElementContentAsString().Trim();
                if (!IsValidHashHex(hashText)) continue;
                var sanitizedName = new string(path.Select(ch => ch is '\\' or '/' or '?' or '%' or '*' or ':' or '|' or '"' or '<' or '>' || char.IsWhiteSpace(ch) ? '_' : ch).ToArray());
                var name = $"{sanitizedName}.{hashText}";
                var algorithm = hashText.Length switch { 32 => HashAlgorithmKind.Md5, 40 => HashAlgorithmKind.Sha1, 64 => HashAlgorithmKind.Sha256, _ => throw new FormatException("Unsupported IOC hash length") };
                db.AddRange(new[] { new HashSignature(name, SignatureType.Hash, path, algorithm, Convert.FromHexString(hashText), null) { SourceEntry = hashText } });
                count++;
            }
        }
        catch (XmlException ex)
        {
            throw new FormatException($"Invalid OpenIOC XML in {path}: {ex.Message}", ex);
        }
        AddSpecialInfo(path, count, infos);
    }

    private static bool IsValidHashHex(string value) => (value.Length is 32 or 40 or 64) && value.All(Uri.IsHexDigit);

    private void LoadYaraFile(string path, SignatureDatabase db, List<DatabaseInfo> infos)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length == 0) throw new InvalidDataException($"Empty YARA database: {path}");
        if (info.Length > 64L * 1024 * 1024) throw new InvalidDataException($"YARA database exceeds supported metadata size: {path}");
        var engine = YaraEngine.LoadText(File.ReadAllText(path), path);
        var sha256 = ComputeSha256Hex(path);
        db.SpecialDatabases.AlternativeRuleFiles.Add(new AlternativeRuleFile(Path.GetFileName(path), "YARA", info.Length, sha256, engine.RuleCount, path));
        AddSpecialInfo(path, engine.RuleCount, infos);
        if (engine.RuleCount == 0) throw new InvalidDataException($"Empty or unsupported YARA database: {path}");
    }

    private void LoadBytecodeFile(string path, SignatureDatabase db, List<DatabaseInfo> infos)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length == 0) throw new InvalidDataException($"Empty bytecode database: {path}");
        if (info.Length > 64L * 1024 * 1024) throw new InvalidDataException($"Bytecode database exceeds supported metadata size: {path}");
        var engine = ClamBcEngine.LoadText(File.ReadAllText(path), path);
        var sha256 = ComputeSha256Hex(path);
        db.SpecialDatabases.AlternativeRuleFiles.Add(new AlternativeRuleFile(Path.GetFileName(path), "Bytecode", info.Length, sha256, engine.ProgramCount, path));
        AddSpecialInfo(path, engine.ProgramCount, infos);
        if (engine.ProgramCount == 0) throw new InvalidDataException($"Empty or unsupported bytecode database: {path}");
    }

    private void LoadInfoFile(string path, SignatureDatabase db, List<DatabaseInfo> infos)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length == 0) throw new InvalidDataException($"Empty INFO database: {path}");
        var lines = File.ReadLines(path).Where(static x => !string.IsNullOrWhiteSpace(x) && !x.StartsWith('#')).ToArray();
        if (lines.Length == 0 || !lines[0].StartsWith("ClamAV-VDB:", StringComparison.Ordinal))
            throw new FormatException($"Invalid INFO database header in {path}");

        var count = 0;
        foreach (var line in lines.Skip(1))
        {
            if (line.StartsWith("DSIG:", StringComparison.Ordinal)) break;
            var delimiter = line.Contains(':') ? ':' : ';';
            var parts = line.Split(delimiter, 3);
            if (parts.Length != 3) throw new FormatException($"Invalid INFO VDB line in {path}: {line}");
            if (string.IsNullOrWhiteSpace(parts[0]) || !long.TryParse(parts[1], out var size) || size < 0)
                throw new FormatException($"Invalid INFO size/name in {path}: {line}");
            if (parts[2].Length != 64 || !parts[2].All(Uri.IsHexDigit))
                throw new FormatException($"Invalid INFO SHA-256 in {path}: {line}");
            db.SpecialDatabases.InfoRecords.Add(new DatabaseInfoRecord(parts[0], size, parts[2].ToLowerInvariant(), path));
            count++;
        }
        AddSpecialInfo(path, count, infos);
    }

    private static string ComputeSha256Hex(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static int ParseUnsignedInt(string value, string field, string path, string line)
    {
        if (!int.TryParse(value, out var n) || n < 0) throw new FormatException($"Invalid {field} in {path}: {line}");
        return n;
    }

    private static int ParseSignedInt(string value, string field, string path, string line)
    {
        if (!int.TryParse(value, out var n)) throw new FormatException($"Invalid {field} in {path}: {line}");
        return n;
    }

    private static int? ParseOptionalFlevel(string value, string path, string line)
    {
        if (string.IsNullOrEmpty(value)) return 0;
        if (!int.TryParse(value, out var n) || n < 0) throw new FormatException($"Invalid functionality level in {path}: {line}");
        return n;
    }

    private static bool TryHex(string value, out byte[] bytes)
    {
        try
        {
            if ((value.Length & 1) != 0) { bytes = []; return false; }
            bytes = Convert.FromHexString(value);
            return true;
        }
        catch (FormatException) { bytes = []; return false; }
    }

    private static bool TryHexSha1(string value, out byte[] bytes)
    {
        if (value.Length != 40) { bytes = []; return false; }
        return TryHex(value, out bytes) && bytes.Length == 20;
    }

    private static DatabaseInfo ToInfo(string name, CvdHeader header, bool isVerified)
        => new(
            name,
            header.Format,
            header.Version,
            header.SignatureCount,
            header.FunctionalityLevel,
            header.CreationTimestamp > 0
                ? DateTimeOffset.FromUnixTimeSeconds(header.CreationTimestamp)
                : null,
            header.Builder,
            header.Md5,
            isVerified);

    public static DatabaseInfo ReadInfo(string path)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();
        if (extension is ".cvd" or ".cld" or ".cud")
        {
            var header = CvdReader.ReadHeader(path);
            return ToInfo(Path.GetFileName(path), header, isVerified: false);
        }

        var count = SignatureParser.ParseFile(path).Count();
        return new DatabaseInfo(
            Path.GetFileName(path),
            DatabaseFormat.TextSignature,
            0,
            (uint)count,
            0,
            null,
            null,
            null,
            false);
    }
}
