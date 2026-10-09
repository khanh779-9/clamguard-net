using System.Numerics;
using System.Security.Cryptography;

namespace ClamGuard.Database;

/// <summary>Verification primitives matching the relevant ClamAV 1.5.4 signing formats.</summary>
public static class ClamAvSignatureVerifier
{
    private const int Sha256Size = 32;
    private const int PssBlockSize = 256;
    private const int PssMaskLength = PssBlockSize - Sha256Size - 1;
    private const string Radix64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

    private const string LegacyCvdModulus = "118640995551645342603070001658453189751527774412027743746599405743243142607464144767361060640655844749760788890022283424922762488917565551002467771109669598189410434699034532232228621591089508178591428456220796841621637175567590476666928698770143328137383952820383197532047771780196576957695822641224262693037";
    private const string LegacyCvdExponent = "100001027";
    private const string CdiffModulus = "14783905874077467090262228516557917570254599638376203532031989214105552847269687489771975792123442185817287694951949800908791527542017115600501303394778618535864845235700041590056318230102449612217458549016089313306591388590790796515819654102320725712300822356348724011232654837503241736177907784198700834440681124727060540035754699658105895050096576226753008596881698828185652424901921668758326578462003247906470982092298106789657211905488986281078346361469524484829559560886227198091995498440676639639830463593211386055065360288422394053998134458623712540683294034953818412458362198117811990006021989844180721010947";
    private const string CdiffExponent = "100002053";
    private const string InfoModulus = "11088894983048545473659556106627194923928941791795047620591658697413581043322715912172496806525381055880964520618400224333320534660299233983755341740679502866829909679955734391392668378361221524205396631090105151641270857277080310734320951653700508941717419168723942507890702904702707587451621691050754307850383399865346487203798464178537392211402786481359824461197231102895415093770394216666324484593935762408468516826633192140826667923494822045805347809932848454845886971706424360558667862775876072059437703365380209101697738577515476935085469455279994113145977994084618328482151013142393373316337519977244732747977";
    private const string InfoExponent = "100002049";

    private static readonly VerificationKey LegacyCvdKey = new(LegacyCvdModulus, LegacyCvdExponent);
    private static readonly VerificationKey CdiffKey = new(CdiffModulus, CdiffExponent);
    private static readonly VerificationKey InfoKey = new(InfoModulus, InfoExponent);

    public static bool VerifyLegacyCvdMd5(string md5Hex, string digitalSignature)
    {
        if (string.IsNullOrWhiteSpace(md5Hex) || md5Hex.Length != 32)
            return false;
        byte[] expected;
        try { expected = Convert.FromHexString(md5Hex); }
        catch (FormatException) { return false; }
        var decoded = DecodeSignature(digitalSignature, LegacyCvdKey, 16);
        return decoded is not null && CryptographicOperations.FixedTimeEquals(decoded, expected);
    }

    public static bool VerifyCdiffSha256Pss2(ReadOnlySpan<byte> sha256, string digitalSignature)
        => VerifySha256Pss2(sha256, digitalSignature, CdiffKey);

    public static bool VerifyInfoSha256Pss2(ReadOnlySpan<byte> sha256, string digitalSignature)
        => VerifySha256Pss2(sha256, digitalSignature, InfoKey);

    private static bool VerifySha256Pss2(ReadOnlySpan<byte> sha256, string digitalSignature, VerificationKey key)
    {
        if (sha256.Length != Sha256Size)
            return false;

        var decoded = DecodeSignature(digitalSignature, key, PssBlockSize);
        if (decoded is null || decoded[^1] != 0xBC)
            return false;

        var mask = decoded.AsSpan(0, PssMaskLength);
        var digest2 = decoded.AsSpan(PssMaskLength, Sha256Size);
        var db = new byte[PssMaskLength];
        var rounds = (PssMaskLength + Sha256Size - 1) / Sha256Size;
        Span<byte> input = stackalloc byte[Sha256Size + 4];
        digest2.CopyTo(input);
        input[32] = 0;
        input[33] = 0;
        for (var i = 0; i < rounds; i++)
        {
            input[34] = (byte)(i / 256);
            input[35] = (byte)i;
            var block = SHA256.HashData(input);
            block.AsSpan(0, Math.Min(Sha256Size, db.Length - i * Sha256Size))
                .CopyTo(db.AsSpan(i * Sha256Size));
        }

        for (var i = 0; i < db.Length; i++)
            db[i] ^= mask[i];
        db[0] &= 0x7F;

        var separator = Array.IndexOf(db, (byte)0x01);
        if (separator < 0 || db.Length - separator - 1 != 32)
            return false;
        for (var i = 0; i < separator; i++)
            if (db[i] != 0)
                return false;

        Span<byte> final = stackalloc byte[8 + Sha256Size + 32];
        sha256.CopyTo(final.Slice(8, Sha256Size));
        db.AsSpan(separator + 1, 32).CopyTo(final.Slice(40, 32));
        var digest1 = SHA256.HashData(final);
        return CryptographicOperations.FixedTimeEquals(digest1, digest2);
    }

    private static byte[]? DecodeSignature(string signature, VerificationKey key, int plainLength)
    {
        if (string.IsNullOrWhiteSpace(signature) || signature.Length > 700)
            return null;

        BigInteger value = BigInteger.Zero;
        for (var i = 0; i < signature.Length; i++)
        {
            var digit = Radix64.IndexOf(signature[i]);
            if (digit < 0)
                return null;
            value += new BigInteger(digit) << (6 * i);
        }

        var plainNumber = BigInteger.ModPow(value, key.Exponent, key.Modulus);
        var bigEndian = plainNumber.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bigEndian.Length > plainLength)
            return null;

        var result = new byte[plainLength];
        bigEndian.CopyTo(result, plainLength - bigEndian.Length);
        return result;
    }

    private sealed record VerificationKey(string ModulusText, string ExponentText)
    {
        public BigInteger Modulus { get; } = BigInteger.Parse(ModulusText);
        public BigInteger Exponent { get; } = BigInteger.Parse(ExponentText);
    }
}
