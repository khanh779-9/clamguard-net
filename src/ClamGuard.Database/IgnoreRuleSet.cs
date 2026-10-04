using System.Security.Cryptography;
using System.Text;
using ClamGuard.Signatures;

namespace ClamGuard.Database;

/// <summary>
/// Implements the ClamAV 1.5.4 .ign/.ign2 signature suppression database.
/// Rules are loaded before normal signature databases and can optionally be
/// constrained by the MD5 of the original database entry line.
/// </summary>
internal sealed class IgnoreRuleSet
{
    private sealed record Rule(string Name, byte[]? EntryMd5);

    private readonly Dictionary<string, List<Rule>> _rules = new(StringComparer.Ordinal);

    public int Count => _rules.Values.Sum(static x => x.Count);

    public void LoadFile(string path)
    {
        foreach (var raw in File.ReadLines(path))
        {
            if (raw.Length > 0 && raw[0] == '#')
                continue;

            var parts = raw.Split(':');
            if (parts.Length > 3)
                throw new FormatException($"Invalid IGN rule in {path}: {raw}");

            string signame;
            byte[]? entryMd5 = null;
            if (parts.Length == 1)
            {
                signame = raw;
            }
            else if (parts.Length == 2)
            {
                signame = parts[0];
                if (parts[1].Length != 32 || !TryDecodeHex(parts[1], out entryMd5))
                    throw new FormatException($"Malformed IGN MD5 in {path}: {raw}");
            }
            else
            {
                // ClamAV's legacy three-field form uses the third field as the signature name.
                signame = parts[2];
            }

            if (signame.Length == 0)
                throw new FormatException($"No signature name provided in {path}");

            signame = NormalizeIgnoreName(signame);
            if (!_rules.TryGetValue(signame, out var rules))
                _rules[signame] = rules = [];
            rules.Add(new Rule(signame, entryMd5));
        }
    }

    public bool ShouldIgnore(Signature signature)
    {
        ArgumentNullException.ThrowIfNull(signature);
        return ShouldIgnore(signature.Name, signature.SourceEntry);
    }

    public bool ShouldIgnore(string signame, string? entry)
    {
        var normalized = NormalizeSignatureName(signame);
        if (!_rules.TryGetValue(normalized, out var rules))
            return false;

        foreach (var rule in rules)
        {
            if (rule.EntryMd5 is null)
                return true;
            if (entry is null)
                continue;

            var digest = MD5.HashData(Encoding.UTF8.GetBytes(entry));
            if (CryptographicOperations.FixedTimeEquals(digest, rule.EntryMd5))
                return true;
        }

        return false;
    }

    private static string NormalizeIgnoreName(string name)
    {
        if (name.Length < 3)
            return name.PadRight(3, ' ');
        return name;
    }

    // Matches cli_signorm() in ClamAV 1.5.4: strip .UNOFFICIAL or a trailing
    // .{...} attribute clause before comparing against the ignore matcher.
    private static string NormalizeSignatureName(string signame)
    {
        var length = signame.Length;
        if (length > 3 && signame[^1] == '}')
        {
            var attribute = signame.IndexOf(".{", StringComparison.Ordinal);
            if (attribute >= 0)
                signame = signame[..attribute];
            else
                return signame;
        }
        else if (length > 11 && signame.EndsWith(".UNOFFICIAL", StringComparison.Ordinal))
        {
            signame = signame[..^11];
        }

        return signame.Length < 3 ? signame.PadRight(3, ' ') : signame;
    }

    private static bool TryDecodeHex(string value, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if ((value.Length & 1) != 0)
            return false;
        try
        {
            bytes = Convert.FromHexString(value);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
