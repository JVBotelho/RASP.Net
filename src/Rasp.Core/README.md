# Rasp.Net.Core

Core detection engines for [RASP.Net](https://github.com/JVBotelho/RASP.Net): SQL injection, XSS
and command injection heuristics, `RaspAlertBus`, and `RaspContext`. Zero-allocation, span-based,
AOT- and trim-compatible. No runtime patching — this package alone never modifies BCL behavior.

## Install

```
dotnet add package Rasp.Net.Core
```

Most consumers should install [`Rasp.Net`](https://www.nuget.org/packages/Rasp.Net) instead, which
brings in this package plus the ASP.NET Core, gRPC, EF Core, ADO.NET, `HttpClient` and
`System.Text.Json` guards and wires them up via `AddRasp()`.

## Setup

```csharp
builder.Services.AddRaspCore();
```

Every other `Rasp.Net.*` package calls `AddRaspCore()` internally (it's safe to call more than
once — every registration uses `TryAddSingleton`), so most apps never call this directly: it
happens transitively through `AddRasp()` or whichever per-guard `Add...()` method you use. Call
it yourself only if you're taking a direct dependency on `RaspAlertBus`, `RaspContext`, or a
detection engine without going through any of the transport-specific packages. On its own,
`AddRaspCore()` registers services but enables no interception — it's the shared substrate the
other packages build on, not something that does anything by itself.

## Documentation

See the [ADR index](https://github.com/JVBotelho/RASP.Net/tree/main/docs/ADR) for the design
rationale, in particular [ADR 006](https://github.com/JVBotelho/RASP.Net/blob/main/docs/ADR/006-sink-instrumentation-strategy.md)
(sink instrumentation phases) and [ADR 008](https://github.com/JVBotelho/RASP.Net/blob/main/docs/ADR/008-nuget-packaging.md)
(package boundaries).
