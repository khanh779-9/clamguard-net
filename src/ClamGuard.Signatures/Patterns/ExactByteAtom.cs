namespace ClamGuard.Signatures.Patterns;

/// <summary>
/// Represents one exact byte. Instances are shared because this immutable value
/// has only 256 possible values; database parsing should not allocate one object
/// for every byte in every signature.
/// </summary>
public sealed record ExactByteAtom(byte Value) : PatternAtom
{
    private static readonly ExactByteAtom[] Instances = CreateInstances();

    public override int MinLength => 1;
    public override int MaxLength => 1;

    public static ExactByteAtom From(byte value) => Instances[value];

    private static ExactByteAtom[] CreateInstances()
    {
        var instances = new ExactByteAtom[byte.MaxValue + 1];
        for (var value = 0; value < instances.Length; value++)
            instances[value] = new ExactByteAtom((byte)value);
        return instances;
    }
}
