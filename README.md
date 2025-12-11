# 🛡️ RASP.Net

![.NET 10](https://img.shields.io/badge/.NET%2010-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
![Security](https://img.shields.io/badge/Security-RASP-red?style=for-the-badge&logo=shield&logoColor=white)
![Architecture](https://img.shields.io/badge/Architecture-Composite-blue?style=for-the-badge)
![Build](https://img.shields.io/github/actions/workflow/status/YOUR_USERNAME/RASP.Net/build.yml?style=for-the-badge)
![Coverage](https://img.shields.io/codecov/c/github/YOUR_USERNAME/RASP.Net?style=for-the-badge)

> **Runtime Application Self-Protection (RASP) SDK for .NET 10.**  
> *Active defense residing inside the application process.*

---

## 🏗️ Architecture: Composite Solution

This repository utilizes a **Composite Architecture Strategy**.  
It is designed to develop and validate the Security SDK (`Rasp.*`) by instrumenting a real-world "Victim" application (`dotnet-grpc-library-api`) without polluting its source code.

### 📂 Structure

| Directory | Component | Description |
|:----------|:----------|:------------|
| **`src/`** | 🛡️ **The Defense (SDK)** | The RASP Source Code. |
| `├── Rasp.Core` | 🧠 *Kernel* | Detection engine & telemetry contracts |
| `├── Rasp.Instrumentation.Grpc` | 📡 *Sensor* | gRPC request interceptors |
| `├── Rasp.Bootstrapper` | ⚙️ *Loader* | DI extensions (`AddRasp()`) |
| **`modules/`** | 🎯 **The Victim (Target)** | Git submodules |
| `└── dotnet-grpc-library-api` | 🏛️ *App* | Clean Architecture sample |

---

## 🚀 Setup & Build

⚠️ **CRITICAL:** This repository relies on submodules. A standard clone will result in missing projects.

### 1. Clone Correctly

Use the `--recursive` flag to fetch the Target Application code:
```bash
git clone --recursive https://github.com/YOUR_USERNAME/RASP.Net.git
```

If you have already cloned without the flag:
```bash
git submodule update --init --recursive
```

### 2. Build the Composite Solution

We use a "God Mode" solution file (`Rasp_Dev.sln`) that links both the SDK and the Victim App for a unified debugging experience.
```bash
dotnet build Rasp_Dev.sln
```

---

## 🔧 Troubleshooting

**Problem**: `Submodule 'modules/dotnet-grpc-library-api' not found`  
**Solution**: Run `git submodule update --init --recursive`

**Problem**: `The type or namespace name 'Rasp' could not be found`  
**Solution**: Ensure you're opening `Rasp_Dev.sln`, not individual `.csproj` files

**Problem**: gRPC service not starting  
**Solution**: Check if port 5001 is already in use: `netstat -ano | findstr :5001`

---

## 🧪 Development Workflow

The Composite Solution allows you to debug the SDK as if it were part of the application, while keeping git histories separate.

1. Open `Rasp_Dev.sln` in Rider or Visual Studio.
2. **Set Startup Project**: Select `LibrarySystem.Api` (from the `modules` folder).
3. **Debug**: Breakpoints in `Rasp.Instrumentation.Grpc` will be hit when requests are sent to the API.

---

## 🛑 Rules of Engagement

- **Modify `src/`**: Commits go to this repository (`RASP.Net`).
- **Modify `modules/`**: Commits go to the `dotnet-grpc-library-api` repository. Do not modify the victim code unless necessary for integration hooks.

---

## 🛡️ Security & Performance Goals

- **Zero-Allocation Hot Paths**: Usage of `Span<T>` and frozen collections to minimize GC pressure during inspection.
- **Observability First**: Native OpenTelemetry integration (`System.Diagnostics.ActivitySource`).
- **Safe by Design**: Strict mode enabled (`<TreatWarningsAsErrors>true`).

---

## 🎯 Roadmap

- [ ] **Phase 1**: Setup & Vulnerability injection in Target App
- [ ] **Phase 2**: gRPC Interceptor with payload inspection
- [ ] **Phase 3**: EF Core Interceptor with SQL analysis
- [ ] **Phase 4**: Benchmarks & Documentation

---

## 🤝 Contributing

This is an educational/research project for **Advanced AppSec Training**.  
Contributions are welcome via pull requests. Please ensure:

- All tests pass (`dotnet test`)
- Code follows .NET conventions (`dotnet format`)
- Security improvements are documented

---

## 📖 References

- [OWASP RASP](https://owasp.org/www-community/controls/Runtime_Application_Self_Protection)
- [gRPC Interceptors in .NET](https://learn.microsoft.com/en-us/aspnet/core/grpc/interceptors)
- [EF Core Interceptors](https://learn.microsoft.com/en-us/ef/core/logging-events-diagnostics/interceptors)

---

## 📜 License

**MIT License** - Free and open source.
```
Copyright (c) 2025 RASP.Net Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software.
```

**TL;DR:**
- ✅ Use commercially, modify, distribute, private use
- ✅ No restrictions on derivative works
- ⚠️ Provided "as is" without warranty
- 📋 Must include license notice in copies

See [LICENSE](LICENSE) for full terms.

---

Found a security issue? See [SECURITY.md](SECURITY.md) for responsible disclosure.

---

**⚡ Built with .NET 10 Preview | Powered by Clean Architecture**