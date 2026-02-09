# 🚀 RASP.Net Quick Reference

**Essential commands for daily development and PR preparation**

---

## 📦 Setup (One-Time)

```bash
# Clone with submodules
git clone --recursive https://github.com/JVBotelho/RASP.Net.git
cd RASP.Net

# Install Python tools (for red team validation)
pip install grpcio grpcio-tools

# Build everything
dotnet restore Rasp.sln
dotnet build Rasp.sln -c Release
```

---

## 🔧 Daily Development

### Build & Test
```bash
# Quick build
dotnet build Rasp.sln

# Run all tests
dotnet test Rasp.sln

# Run specific test
dotnet test --filter "FullyQualifiedName~XssDetectionEngineTests"
```

### Format Code
```bash
# Auto-format
dotnet format Rasp.sln

# Check only (CI mode)
dotnet format Rasp.sln --verify-no-changes
```

---

## ⚡ Performance Validation

### Run Benchmarks
```bash
cd src/Rasp.Benchmarks
dotnet run -c Release

# Expected output:
# SourceGen_Clean_Scan   | 108.9 ns | 136 B
# SourceGen_Block_Attack | 4,090 ns | 1912 B
```

### Profile Allocations
```bash
# Monitor GC in real-time
dotnet-counters monitor --process-id <PID> System.Runtime

# Record trace
dotnet-trace collect --process-id <PID> --providers Microsoft-Windows-DotNETRuntime
```

---

## 🔴 Red Team Validation

### Generate Attack Protos (One-Time per Proto Change)
```bash
# Windows
python -m grpc_tools.protoc -I ./modules/dotnet-grpc-library-api/LibrarySystem.Contracts/Protos --python_out=./attack --grpc_python_out=./attack ./modules/dotnet-grpc-library-api/LibrarySystem.Contracts/Protos/library.proto

# Linux/macOS
python3 -m grpc_tools.protoc -I ./modules/dotnet-grpc-library-api/LibrarySystem.Contracts/Protos --python_out=./attack --grpc_python_out=./attack ./modules/dotnet-grpc-library-api/LibrarySystem.Contracts/Protos/library.proto
```

### Run Exploits
```bash
# Terminal 1: Start victim app
cd modules/dotnet-grpc-library-api
dotnet run --project LibrarySystem.Api

# Terminal 2: Attack!
python attack/exploit_xss.py localhost:5049
python attack/exploit_grpc.py localhost:5049

# Expected: ✅ 100% block rate, ❌ 0 bypasses
```

---

## 🛠️ Local NuGet Development

### Pack Local Packages
```bash
# Automated (recommended)
.\scripts\pack-local.ps1              # Windows
./scripts/pack-local.sh               # Linux/macOS

# Manual
dotnet pack src/Rasp.Core -o local-packages
dotnet pack src/Rasp.SourceGenerators -o local-packages
dotnet pack src/Rasp.Instrumentation.Grpc -o local-packages
dotnet pack src/Rasp.Bootstrapper -o local-packages
```

### Test Integration
```bash
cd modules/dotnet-grpc-library-api/LibrarySystem.Grpc
dotnet add package Rasp.Instrumentation.Grpc --version 1.0.0-local
dotnet restore
dotnet build
```

---

## 🔍 Debugging

### View Generated Code
```bash
# Enable emission
dotnet build /p:EmitCompilerGeneratedFiles=true

# View files
ls src/Rasp.Benchmarks/obj/Debug/net10.0/generated/
cat src/Rasp.Benchmarks/obj/Debug/net10.0/generated/**/*.g.cs
```

### Enable Verbose Logging
```json
// appsettings.Development.json
{
  "Logging": {
    "LogLevel": {
      "Rasp": "Debug",
      "Rasp.Core.Engine": "Trace"
    }
  }
}
```

### Attach Debugger to Tests
```bash
# Run tests with debugger wait
dotnet test --logger "console;verbosity=detailed" -- RunConfiguration.DebuggerWaitTime=60000
```

---

## 📊 CI/CD Simulation (Local)

### Full CI Pipeline
```bash
# Clean workspace
git clean -fdx
git restore .

# Build like CI
dotnet restore Rasp.sln
dotnet build Rasp.sln -c Release --no-restore /p:TreatWarningsAsErrors=true
dotnet test Rasp.sln -c Release --no-build --verbosity normal

# Format check (CI fails on this)
dotnet format Rasp.sln --verify-no-changes --verbosity diagnostic

# Security scan (CI does this)
dotnet list Rasp.sln package --vulnerable --include-transitive
```

---

## 🧹 Cleanup

### Remove Generated Files
```bash
# Clean build outputs
dotnet clean Rasp.sln

# Deep clean (removes obj, bin, packages)
git clean -fdx -e /.vs -e /.vscode

# Reset submodules
git submodule update --init --recursive
```

### Clear NuGet Cache
```bash
dotnet nuget locals all --clear
```

---

## 🚨 Emergency Fixes

### Restore to Working State
```bash
# Discard all changes
git restore .
git clean -fdx

# Update submodules
git submodule update --init --recursive

# Rebuild
dotnet restore Rasp.sln
dotnet build Rasp.sln
```

### Fix "Tests Won't Run"
```bash
# Kill stale processes
pkill -f dotnet
pkill -f LibrarySystem.Api

# Clear test cache
rm -rf **/TestResults/
dotnet test Rasp.sln --no-build --logger "console;verbosity=detailed"
```

---

## 📚 Useful Paths

| Resource | Path |
|:---------|:-----|
| **ADRs** | [`docs/ADR/`](./ADR/)|
| **Attack Scripts** | [`attack`](../attack/)`/*.py` |
| **Benchmarks** | [`src/Rasp.Benchmarks/`](../src/Rasp.Benchmarks/) |
| **Core Engine** | [`src/Rasp.Core/Engine/`](../src/Rasp.Core/Engine/) |
| **Generated Code** | `src/*/obj/Debug/net10.0/generated/` |
| **Victim App** | [`modules/dotnet-grpc-library-api/`](../modules/dotnet-grpc-library-api/) |

---

## 🎯 Performance Targets

| Metric | Target | Status |
|:-------|:-------|:-------|
| Clean Scan | <200ns | ✅ 108.9ns |
| Attack Block | <5,000ns | ✅ 4,090ns |
| Hot Path Alloc | 0 bytes | ✅ 136 bytes (acceptable - virtual 0) |
| Build Time | <30s | ✅ ~15s |

---

## 🔗 Links

- **GitHub:** https://github.com/JVBotelho/RASP.Net
- **Issues:** https://github.com/JVBotelho/RASP.Net/issues
- **Discussions:** https://github.com/JVBotelho/RASP.Net/discussions
- **CI/CD:** https://github.com/JVBotelho/RASP.Net/actions

---

## 💡 Pro Tips

### Faster Builds
```bash
# Parallel build
dotnet build -m

# Skip tests during build
dotnet build /p:BuildProjectReferences=false
```

### Better Test Output
```bash
# HTML test report
dotnet test --logger "html;LogFileName=test-results.html"

# Open in browser
start test-results.html  # Windows
open test-results.html   # macOS
```

### Monitor Performance Live
```bash
# Real-time counters
dotnet-counters monitor --process-id $(pgrep -f LibrarySystem.Api) \
  System.Runtime[gen-0-gc-count,gen-1-gc-count,alloc-rate]
```

---

**Last Updated:** 2025-02-09  
**For Questions:** Open a [Discussion](https://github.com/JVBotelho/RASP.Net/discussions)