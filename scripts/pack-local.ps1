#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Builds and packs RASP.Net NuGet packages locally for development.

.DESCRIPTION
    This script builds all RASP packages and creates a local NuGet source
    that can be referenced by projects in the modules/ folder.
    Works on both Windows and Linux.

.PARAMETER Configuration
    Build configuration (Debug or Release). Default: Release

.PARAMETER Version
    Package version. Default: 1.0.0-local

.EXAMPLE
    ./pack-local.ps1
    ./pack-local.ps1 -Configuration Debug -Version 1.0.0-dev
#>

param(
    [string]$Configuration = "Release",
    [string]$Version = "1.0.0-local"
)

$ErrorActionPreference = "Stop"

# Paths - detect repo root from script location
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if (-not $ScriptDir) {
    $ScriptDir = Get-Location
}

$RepoRoot = Split-Path -Parent $ScriptDir
$SrcDir = Join-Path $RepoRoot "src"
$LocalPackagesDir = Join-Path $RepoRoot "local-packages"
$NuGetConfigPath = Join-Path $RepoRoot "modules" "nuget.config"

Write-Host "====================================" -ForegroundColor Cyan
Write-Host " RASP.Net Local Package Builder" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration: $Configuration"
Write-Host "Version: $Version"
Write-Host "Output: $LocalPackagesDir"
Write-Host ""

# Create local packages directory
if (-not (Test-Path $LocalPackagesDir)) {
    New-Item -ItemType Directory -Path $LocalPackagesDir -Force | Out-Null
    Write-Host "[+] Created local-packages directory" -ForegroundColor Green
}

# Clean old packages
Get-ChildItem -Path $LocalPackagesDir -Filter "*.nupkg" -ErrorAction SilentlyContinue | Remove-Item -Force
Write-Host "[+] Cleaned old packages" -ForegroundColor Green

# Projects to pack (in dependency order)
$Projects = @(
    "Rasp.Core",
    "Rasp.SourceGenerators",
    "Rasp.Instrumentation.Grpc",
    "Rasp.Instrumentation.AspNetCore",
    "Rasp.Bootstrapper"
)

# Build and pack each project
foreach ($project in $Projects) {
    $projectPath = Join-Path $SrcDir $project "$project.csproj"
    
    if (-not (Test-Path $projectPath)) {
        Write-Host "[!] Project not found: $projectPath" -ForegroundColor Yellow
        continue
    }
    
    Write-Host ""
    Write-Host "[*] Packing $project..." -ForegroundColor Cyan
    
    $packArgs = @(
        "pack"
        $projectPath
        "-c", $Configuration
        "-o", $LocalPackagesDir
        "-p:Version=$Version"
        "-p:PackageVersion=$Version"
        "--no-restore"
    )
    
    # First restore
    dotnet restore $projectPath --verbosity quiet
    
    # Then pack
    $output = & dotnet @packArgs 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Failed to pack $project" -ForegroundColor Red
        Write-Host $output
        # Try without --no-restore
        $packArgs = $packArgs | Where-Object { $_ -ne "--no-restore" }
        $output = & dotnet @packArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[X] Pack failed even with restore" -ForegroundColor Red
            Write-Host $output
            exit 1
        }
    }
    
    Write-Host "[+] Packed $project successfully" -ForegroundColor Green
}

# Create nuget.config for modules if not exists
$NuGetConfigContent = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="rasp-local" value="../local-packages" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
    <packageSource key="rasp-local">
      <package pattern="Rasp.*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
"@

if (-not (Test-Path $NuGetConfigPath)) {
    Set-Content -Path $NuGetConfigPath -Value $NuGetConfigContent -Encoding UTF8
    Write-Host ""
    Write-Host "[+] Created nuget.config in modules/" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "[i] nuget.config already exists in modules/" -ForegroundColor Yellow
}

$TargetProj = Join-Path $RepoRoot "modules" "dotnet-grpc-library-api" "LibrarySystem.Grpc" "LibrarySystem.Grpc.csproj"

if (Test-Path $TargetProj) {
    Write-Host ""
    Write-Host "💉 Auto-Injecting into Victim App..." -ForegroundColor Cyan
    
    # 1. Remove referências antigas (limpeza)
    dotnet remove $TargetProj reference (Join-Path $SrcDir "Rasp.Instrumentation.Grpc" "Rasp.Instrumentation.Grpc.csproj") 2>$null
    dotnet remove $TargetProj reference (Join-Path $SrcDir "Rasp.SourceGenerators" "Rasp.SourceGenerators.csproj") 2>$null

    # 2. Adicionar referência ao pacote local
    # Forçamos o uso da fonte local com --source
    $localSource = $LocalPackagesDir
    dotnet add $TargetProj package "Rasp.Instrumentation.Grpc" --version $Version --source $localSource
    dotnet add $TargetProj package "Rasp.Bootstrapper" --version $Version --source $localSource

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Dependencies injected successfully" -ForegroundColor Green
    } else {
        Write-Host "[!] Failed to inject dependencies" -ForegroundColor Red
    }
} else {
    Write-Host "[!] Victim app not found at $TargetProj (Skipping injection)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "====================================" -ForegroundColor Cyan
Write-Host " Build Complete!" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Packages created in: $LocalPackagesDir"
Write-Host ""
Write-Host "To use in your project, update your .csproj:" -ForegroundColor Yellow
Write-Host ""
Write-Host '  <PackageReference Include="Rasp.Instrumentation.Grpc" Version="' + $Version + '" />'
Write-Host '  <PackageReference Include="Rasp.Bootstrapper" Version="' + $Version + '" />'
Write-Host ""
Write-Host "Then run: dotnet restore" -ForegroundColor Yellow
Write-Host ""

# List created packages
Write-Host "Created packages:" -ForegroundColor Cyan
Get-ChildItem -Path $LocalPackagesDir -Filter "*.nupkg" | ForEach-Object {
    Write-Host "  - $($_.Name)" -ForegroundColor White
}
