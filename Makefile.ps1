param([string]$Configuration = "Release")
$ErrorActionPreference = "Stop"
dotnet build .\ClamGuard.Net.sln -c $Configuration
dotnet run --project .\tests\ClamGuard.Tests -c $Configuration
