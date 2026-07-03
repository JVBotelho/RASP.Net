# Builds Rasp.Native.Profiler.dll via CMake + Ninja.
#
# This project is intentionally NOT part of Rasp.sln / MSBuild - it is a native CLR
# profiler (COM DLL implementing ICorProfilerCallback8), built with a C++ toolchain, not
# the .NET SDK. This mirrors the existing convention for src/Rasp.Native.Guard (ADR-003):
# native components in this repo are built standalone, not through MSBuild.
#
# Usage:
#   pwsh src/Rasp.Native.Profiler/build.ps1
#   pwsh src/Rasp.Native.Profiler/build.ps1 -Configuration Release
#
# Requires: a C++17 toolchain (MSVC Build Tools, or MinGW-w64 via a bundled IDE such as
# CLion) plus CMake and Ninja (or another CMake generator) reachable on PATH, or pass
# -CxxCompilerPath/-CmakePath/-NinjaPath explicitly if they're not on PATH.

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [string]$CxxCompilerPath,
    [string]$CmakePath,
    [string]$NinjaPath
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir = Join-Path $scriptDir "build"

function Resolve-Tool([string]$explicitPath, [string]$commandName) {
    if ($explicitPath) { return $explicitPath }
    $found = Get-Command $commandName -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    return $null
}

$cmake = Resolve-Tool $CmakePath "cmake"
if (-not $cmake) {
    throw "cmake not found on PATH. Pass -CmakePath, or add your CMake install's bin directory to PATH (e.g. an IDE-bundled one under <IDE>\bin\cmake\...\bin)."
}

$ninja = Resolve-Tool $NinjaPath "ninja"

New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

$configureArgs = @("-S", $scriptDir, "-B", $buildDir)
if ($ninja) {
    $configureArgs += @("-G", "Ninja")
}
if ($CxxCompilerPath) {
    $configureArgs += "-DCMAKE_CXX_COMPILER=$CxxCompilerPath"
}
$configureArgs += "-DCMAKE_BUILD_TYPE=$Configuration"

Write-Host "Configuring: $cmake $($configureArgs -join ' ')"
& $cmake @configureArgs
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed (exit $LASTEXITCODE)." }

Write-Host "Building..."
& $cmake --build $buildDir --config $Configuration
if ($LASTEXITCODE -ne 0) { throw "Build failed (exit $LASTEXITCODE)." }

$dll = Get-ChildItem -Path $buildDir -Recurse -Filter "*Rasp.Native.Profiler.dll" | Select-Object -First 1
if ($dll) {
    Write-Host "Built: $($dll.FullName)"
} else {
    Write-Warning "Build reported success but no Rasp.Native.Profiler.dll was found under $buildDir."
}
