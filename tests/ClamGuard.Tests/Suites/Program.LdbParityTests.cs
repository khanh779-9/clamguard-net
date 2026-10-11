internal static partial class Program
{
    private static void LdbSignatureParityTests()
    {
        const string signatureLine = "Win.Malware.Generic-9828792-0;Engine:81-255,Target:1;0&1&2&3&4;3a3030302c2056657273696f6e3d302e302e302e302c2043756c747572653d6e65757472616c2c205075626c69634b6579546f6b656e3d6e756c6c;726e69772e657865::w;77696e646c2e626174::w;43726565702e50726f706572746965732e5265736f75726365732e7265736f7572636573;43726565702e50726f706572746965732e5265736f7572636573::w";
        var signatureLineToTest = signatureLine;
        var realDatabasePath = Environment.GetEnvironmentVariable("CLAMGUARD_DAILY_LDB_PATH");
        if (!string.IsNullOrWhiteSpace(realDatabasePath))
        {
            var fullDatabasePath = Path.GetFullPath(realDatabasePath);
            if (!File.Exists(fullDatabasePath))
                throw new FileNotFoundException("CLAMGUARD_DAILY_LDB_PATH does not exist.", fullDatabasePath);

            signatureLineToTest = File.ReadLines(fullDatabasePath).FirstOrDefault(
                line => line.StartsWith("Win.Malware.Generic-9828792-0;", StringComparison.Ordinal))
                ?? throw new InvalidDataException("The real daily.ldb does not contain Win.Malware.Generic-9828792-0.");
            Assert(string.Equals(signatureLineToTest, signatureLine, StringComparison.Ordinal),
                "the reference LDB signature matches the exact line in the supplied ClamAV daily.ldb");
        }
        const string assemblyVersionMarker = ":000, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null";
        const string wideExecutableMarker = "rniw.exe";
        const string wideBatchMarker = "windl.bat";
        const string resourceMarker = "Creep.Properties.Resources.resources";
        const string wideResourceMarker = "Creep.Properties.Resources";

        var root = Path.Combine(Path.GetTempPath(), "clamguard-ldb-parity-" + Guid.NewGuid().ToString("N"));
        var databaseDirectory = Path.Combine(root, "database");
        var samplesDirectory = Path.Combine(root, "samples");
        Directory.CreateDirectory(databaseDirectory);
        Directory.CreateDirectory(samplesDirectory);

        try
        {
            File.WriteAllText(Path.Combine(databaseDirectory, "daily.ldb"), signatureLineToTest + Environment.NewLine, Encoding.ASCII);
            var manager = new DatabaseManager();
            var state = manager.LoadAndCompile(databaseDirectory, failOnInvalidFile: true);
            var parsedSignature = state.Database.Signatures.OfType<LogicalSignature>().Single();

            Assert(parsedSignature.Name == "Win.Malware.Generic-9828792-0", "the reference LDB signature name is preserved");
            Assert(parsedSignature.Target is { Target: SignatureTargetType.Pe, MinimumFunctionalityLevel: 81, MaximumFunctionalityLevel: 255 },
                "the reference LDB Engine and PE target filter parse correctly");
            Assert(parsedSignature.Expression == "0&1&2&3&4" && parsedSignature.SubSignatures.Count == 5,
                "all five required reference LDB subsignatures are retained");
            Assert(parsedSignature.SubSignatures[1].MatchOptions.HasFlag(ContentMatchOptions.Wide) &&
                   parsedSignature.SubSignatures[2].MatchOptions.HasFlag(ContentMatchOptions.Wide) &&
                   parsedSignature.SubSignatures[4].MatchOptions.HasFlag(ContentMatchOptions.Wide),
                "reference wide-string subsignatures remain UTF-16LE matches");

            // This is a synthetic regression fixture named 000.exe, not the user's
            // real sample. It exercises the exact LDB rule without embedding malware.
            var payload = Encoding.ASCII.GetBytes(assemblyVersionMarker)
                .Concat(Encoding.Unicode.GetBytes(wideExecutableMarker))
                .Concat(Encoding.Unicode.GetBytes(wideBatchMarker))
                .Concat(Encoding.ASCII.GetBytes(resourceMarker))
                .Concat(Encoding.Unicode.GetBytes(wideResourceMarker))
                .ToArray();
            var syntheticPe = BuildPeWithImport(false).Concat(payload).ToArray();
            Assert(state.Compiled.IsLogicalSignaturePrefiltered(parsedSignature),
                "the reference pure-AND LDB signature is safely indexed by its required fixed-byte anchor");
            Assert(state.Compiled.FindLogicalCandidates(syntheticPe).Contains(parsedSignature),
                "the shared compact fragment index returns the reference signature when its anchor is present");
            var samplePath = Path.Combine(samplesDirectory, "000.exe");
            File.WriteAllBytes(samplePath, syntheticPe);

            var scanner = new ScannerEngine(manager);
            var result = scanner.Scan(samplePath, new ScanOptions { CollectAllMatches = true });
            Assert(result.Verdict == ScanVerdict.Malicious &&
                   result.Detections.Any(x => x.Name == "Win.Malware.Generic-9828792-0"),
                "the reference LDB signature detects a PE when all five subsignatures match");

            // Optional integration check against the user's real 000.exe sample. Keep the
            // sample outside the repository; set CLAMGUARD_REAL_000_EXE to its extracted path.
            var realSamplePath = Environment.GetEnvironmentVariable("CLAMGUARD_REAL_000_EXE");
            if (!string.IsNullOrWhiteSpace(realSamplePath))
            {
                var fullSamplePath = Path.GetFullPath(realSamplePath);
                if (!File.Exists(fullSamplePath))
                    throw new FileNotFoundException("CLAMGUARD_REAL_000_EXE does not exist.", fullSamplePath);

                var realSampleResult = scanner.Scan(fullSamplePath, new ScanOptions { CollectAllMatches = true });
                Assert(realSampleResult.Verdict == ScanVerdict.Malicious &&
                       realSampleResult.Detections.Any(x => x.Name == "Win.Malware.Generic-9828792-0"),
                    "the exact reference LDB rule detects the supplied real 000.exe sample");
            }

            var incompletePayload = Encoding.ASCII.GetBytes(assemblyVersionMarker)
                .Concat(Encoding.Unicode.GetBytes(wideExecutableMarker))
                .Concat(Encoding.ASCII.GetBytes(resourceMarker))
                .Concat(Encoding.Unicode.GetBytes(wideResourceMarker))
                .ToArray();
            var incompletePePath = Path.Combine(samplesDirectory, "000-missing-marker.exe");
            File.WriteAllBytes(incompletePePath, BuildPeWithImport(false).Concat(incompletePayload).ToArray());
            var incompleteResult = scanner.Scan(incompletePePath, new ScanOptions { CollectAllMatches = true });
            Assert(!incompleteResult.Detections.Any(x => x.Name == "Win.Malware.Generic-9828792-0"),
                "the reference LDB signature does not alert when one required AND subsignature is missing");

            var nonPePath = Path.Combine(samplesDirectory, "same-markers.bin");
            File.WriteAllBytes(nonPePath, payload);
            var nonPeResult = scanner.Scan(nonPePath, new ScanOptions { CollectAllMatches = true });
            Assert(!nonPeResult.Detections.Any(x => x.Name == "Win.Malware.Generic-9828792-0"),
                "the reference Target:1 signature does not alert on the same markers in a non-PE file");

            // Exercise a seed shared by more than one logical rule. The compact
            // fragment index stores collision chains in one flat array.
            var collisionDatabasePath = Path.Combine(databaseDirectory, "collision.ldb");
            const string sharedAnchor = "4142434445464748";
            File.WriteAllText(collisionDatabasePath,
                $"Demo.Collision.One;Engine:81-255,Target:1;0&1;{sharedAnchor};{sharedAnchor}{Environment.NewLine}" +
                $"Demo.Collision.Two;Engine:81-255,Target:1;0&1;{sharedAnchor};{sharedAnchor}{Environment.NewLine}",
                Encoding.ASCII);
            var collisionManager = new DatabaseManager();
            var collisionState = collisionManager.LoadAndCompile(databaseDirectory, failOnInvalidFile: true);
            var collisionSignatures = collisionState.Database.Signatures
                .OfType<LogicalSignature>()
                .Where(static signature => signature.Name.StartsWith("Demo.Collision.", StringComparison.Ordinal))
                .ToArray();
            var collisionCandidates = collisionState.Compiled.FindLogicalCandidates(
                BuildPeWithImport(false).Concat(Convert.FromHexString(sharedAnchor)).ToArray());
            Assert(collisionSignatures.Length == 2 && collisionSignatures.All(collisionCandidates.Contains),
                "logical prefilter returns every signature sharing the same fragment seed");
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }
}
