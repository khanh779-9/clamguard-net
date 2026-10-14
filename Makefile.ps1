param([string]$Configuration = "Release")
$ErrorActionPreference = "Stop"

dotnet build .\ClamGuard.Net.sln -c $Configuration --nologo -m
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Windows PowerShell 5.1 does not apply $ErrorActionPreference to native
# commands: without these guards a red build still exits green.
dotnet run --project .\tests\ClamGuard.Tests -c $Configuration --no-build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
