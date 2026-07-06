# Rasp.Net.AdoNet

ADO.NET SQL injection detection for [RASP.Net](https://github.com/JVBotelho/RASP.Net) via
`System.Diagnostics.DiagnosticListener`. Phase A: no runtime patching.

## Install

```
dotnet add package Rasp.Net.AdoNet
```

Most consumers should install [`Rasp.Net`](https://www.nuget.org/packages/Rasp.Net) instead, which
brings this in along with the other Phase A guards, wired up via `AddRasp()`.

## Setup

```csharp
builder.Services.AddRaspAdoNet();
```

That's the whole setup. `AddRaspAdoNet()` registers a hosted service that subscribes to
`System.Diagnostics.DiagnosticListener.AllListeners` at startup, so every `SqlCommand` executed
through any ADO.NET provider that emits `SqlClientDiagnosticListener` events is observed
automatically — no interceptor to attach, no `DbContext` to touch. If you're on Entity Framework
Core, use [`Rasp.Net.EntityFrameworkCore`](https://www.nuget.org/packages/Rasp.Net.EntityFrameworkCore)
instead (or as well, if part of your app uses raw ADO.NET directly).

## Documentation

See [docs/ADR](https://github.com/JVBotelho/RASP.Net/tree/main/docs/ADR) for the design rationale.
