# Rasp.Net.Grpc

gRPC interceptor and generated-interceptor wiring for [RASP.Net](https://github.com/JVBotelho/RASP.Net),
including the `RaspGrpcGenerator` Roslyn analyzer. Phase A: no runtime patching.

## Install

```
dotnet add package Rasp.Net.Grpc
```

Most consumers should install [`Rasp.Net`](https://www.nuget.org/packages/Rasp.Net) instead, which
brings this in along with the other Phase A guards, wired up via `AddRasp()`.

## Setup

```csharp
builder.Services.AddRasp(builder.Configuration); // or AddRaspCore(), at minimum
builder.Services.AddGrpc().AddRaspSecurity();
```

`AddRaspSecurity()` isn't hand-written — it's emitted at compile time by the `RaspGrpcGenerator`
Roslyn analyzer bundled in this package, which scans your project for gRPC service base classes
and generates one `{Service}RaspInterceptor` per service plus this extension method to register
all of them. Nothing to configure for the generator itself: it runs automatically as long as
your `.proto`-generated service classes are compiled into the same project. `AddRasp()` (or at
least `AddRaspCore()`) must be registered first, since the generated interceptors resolve their
detection engines and `RaspAlertBus` from DI.

## Documentation

See [docs/ADR](https://github.com/JVBotelho/RASP.Net/tree/main/docs/ADR) for the design rationale.
