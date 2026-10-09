namespace ClamGuard.Signatures;

public sealed record LdbTargetDescription(
    int Target = 0,
    long? MinFileSize = null,
    long? MaxFileSize = null,
    long? MinEntryPoint = null,
    long? MaxEntryPoint = null,
    int? MinSections = null,
    int? MaxSections = null,
    string? Container = null,
    IReadOnlyList<string>? Intermediates = null,
    string? HandlerType = null,
    string? IconGroup1 = null,
    string? IconGroup2 = null,
    int? MinimumFunctionalityLevel = null,
    int? MaximumFunctionalityLevel = null,
    bool TargetSpecified = false);
