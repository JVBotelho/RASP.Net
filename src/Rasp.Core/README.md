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

## Documentation

See the [ADR index](https://github.com/JVBotelho/RASP.Net/tree/main/docs/ADR) for the design
rationale, in particular [ADR 006](https://github.com/JVBotelho/RASP.Net/blob/main/docs/ADR/006-sink-instrumentation-strategy.md)
(sink instrumentation phases) and [ADR 008](https://github.com/JVBotelho/RASP.Net/blob/main/docs/ADR/008-nuget-packaging.md)
(package boundaries).
