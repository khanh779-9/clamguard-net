$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw 'dotnet SDK is required' }
dotnet restore ClamGuard.Net.sln
dotnet build ClamGuard.Net.sln --configuration Release --no-restore /p:TreatWarningsAsErrors=true
dotnet run --project tests/ClamGuard.Tests/ClamGuard.Tests.csproj --configuration Release --no-build
