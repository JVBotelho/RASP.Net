# Rasp.Net

Meta-package for [RASP.Net](https://github.com/JVBotelho/RASP.Net). Brings in `AddRasp()` plus the
full Phase A guard set:

- `Rasp.Net.Core` — detection engines, `RaspAlertBus`, `RaspContext`
- `Rasp.Net.AspNetCore` — middleware and security headers
- `Rasp.Net.Grpc` — gRPC interceptor
- `Rasp.Net.EntityFrameworkCore` — `SqlSinkGuard`
- `Rasp.Net.AdoNet` — ADO.NET SQL injection detection
- `Rasp.Net.HttpClient` — `SsrfGuard`
- `Rasp.Net.SystemTextJson` — `DeserializationGuard`

Installing `Rasp.Net` never pulls in runtime patching (`Rasp.Net.RuntimePatching`) or the native
profiler (`Rasp.Net.Profiler.Windows`) — those are separate, opt-in packages with a different risk
profile. See [ADR 006](https://github.com/JVBotelho/RASP.Net/blob/main/docs/ADR/006-sink-instrumentation-strategy.md)
for why.

## Install

```
dotnet add package Rasp.Net
```

## Quick start

```csharp
builder.Services.AddRasp(builder.Configuration);
```

Each guard package also exposes its own opt-in registration method (`AddRaspEntityFrameworkCore()`,
`AddRaspHttpClient()`, `AddRaspAspNetCore()`, `AddRaspAdoNet()`, `AddRaspSystemTextJson()`) — call
the ones relevant to your app.

## Documentation

See [docs/ADR](https://github.com/JVBotelho/RASP.Net/tree/main/docs/ADR) for the design rationale.
