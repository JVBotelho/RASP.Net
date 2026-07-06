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

`AddRasp()` only registers the shared substrate (`AddRaspCore()`: `RaspAlertBus`, the detection
engines, every guard class) plus the gRPC-perimeter scan and the alert-consuming background
service. It does **not** call any transport package's own registration method for you — each of
the six still needs its own explicit opt-in call, and two of them need one more line beyond that:

- **`AddRaspAspNetCore()`, `AddRaspHttpClient()`, `AddRaspAdoNet()`** — call these directly; each
  is otherwise zero-touch (no further wiring once called).
- **`AddGrpc().AddRaspSecurity()`** — chain this onto your existing `AddGrpc()` call. See
  [`Rasp.Net.Grpc`'s README](https://github.com/JVBotelho/RASP.Net/blob/main/src/Rasp.Instrumentation.Grpc/README.md).
- **`AddRaspEntityFrameworkCore()`** plus `options.UseRaspSqlGuard(serviceProvider)` inside the
  `AddDbContext<T>((serviceProvider, options) => ...)` overload, once per `DbContext` you want
  guarded. See [`Rasp.Net.EntityFrameworkCore`'s README](https://github.com/JVBotelho/RASP.Net/blob/main/src/Rasp.Instrumentation.EntityFrameworkCore/README.md).
- **`AddRaspSystemTextJson()`** plus `jsonSerializerOptions.AddRaspProtection(serviceProvider)`
  called on the actual `JsonSerializerOptions` instance you deserialize untrusted input with. See
  [`Rasp.Net.SystemTextJson`'s README](https://github.com/JVBotelho/RASP.Net/blob/main/src/Rasp.Instrumentation.SystemTextJson/README.md).

Installing `Rasp.Net` puts all six packages' registration methods within reach; it does not call
them for you. Check each package's README for the exact call(s) it needs.

## Documentation

See [docs/ADR](https://github.com/JVBotelho/RASP.Net/tree/main/docs/ADR) for the design rationale.
