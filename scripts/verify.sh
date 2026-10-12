#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v dotnet >/dev/null 2>&1 || { echo "dotnet SDK is required" >&2; exit 2; }
dotnet restore ClamGuard.Net.sln
dotnet build ClamGuard.Net.sln --configuration Release --no-restore /p:TreatWarningsAsErrors=true
dotnet run --project tests/ClamGuard.Tests/ClamGuard.Tests.csproj --configuration Release --no-build
