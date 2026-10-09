global using System.Buffers.Binary;
global using System.Diagnostics;
global using System.Formats.Tar;
global using System.IO.Compression;
global using System.Text;
global using ClamGuard.Core;
global using ClamGuard.Signatures;
global using ClamGuard.Database;
global using ClamGuard.Scanner;
global using ClamGuard.Signatures.Parsing;
global using ClamGuard.Signatures.Patterns;

internal static partial class Program
{
    private static async Task Main()
    {
        await ScanHostSmokeAsync();
        await SpecializedHandlersSmokeAsync();
        await NativeSpecializedSmokeAsync();
        SpecialDatabaseLoadSmoke();
        await ScanPipelineFileTypeSmokeAsync();
        DatabaseAndCvdTests();
        await CompiledMatcherTestsAsync();
        SignatureParsingTests();
        NdbAndPolicyTests();
        ContainerLayerTests();
        ExecutableFormatTests();
        LdbSignatureParityTests();
        ArchiveDocumentTests();
        await YaraAndBytecodeTestsAsync();
        await SelfProtectionAndMetadataTestsAsync();
        Console.WriteLine("All tests passed.");
    }
}
