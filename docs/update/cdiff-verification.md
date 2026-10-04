# CDIFF and Database Verification

ClamGuard.NET implements the core ClamAV 1.5.4 CDIFF command set (`OPEN`, `ADD`, `DEL`, `XCHG`, `MOVE`, `CLOSE`, `UNLINK`). The implementation validates the `ClamAV-Diff:<version>:<uncompressed-size>:` header, gzip body, exact uncompressed script size, bounded command/line/path usage, and the internal ClamAV radix-64 SHA-256 PSS2 signature. When a certificate directory is configured, a matching `.cdiff.sign` file can be verified as detached CMS/PKCS#7 before falling back to the internal signature when the detached signature is unavailable.

CVD verification performs:

1. 512-byte `ClamAV-VDB` header parsing.
2. Detached `.cvd.sign` CMS/PKCS#7 verification when a configured ClamAV certificate store contains the matching signature; otherwise legacy payload MD5/RSA verification.
3. Extraction of the signed `.info` manifest.
4. `.info` SHA-256 PSS2 signature verification with ClamAV 1.5.4's INFO key.
5. `.info` header consistency checks against the outer CVD (version, signature count, functionality level, creation timestamp).
6. Every manifest entry's exact file size and SHA-256 digest.
7. Duplicate-entry and recognized-database-file coverage checks.

The updater performs cryptographic verification before database activation. Set `UpdateOptions.CertsDirectory` to the ClamAV certificate directory to enable detached `.cvd.sign` retrieval and verification; otherwise the updater uses the official legacy CVD signature path.

The implementation has been cross-checked against the ClamAV 1.5.4 `unit_tests/input/freshclam_testfiles` fixtures. The local environment does not have the .NET SDK, so `dotnet build/test` still needs to be run on a .NET 8 SDK host.
