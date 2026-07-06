# Rasp.Net.Grpc

gRPC interceptor and generated-interceptor wiring for [RASP.Net](https://github.com/JVBotelho/RASP.Net),
including the `RaspGrpcGenerator` Roslyn analyzer. Phase A: no runtime patching.

## Install

```
dotnet add package Rasp.Net.Grpc
```

Most consumers should install [`Rasp.Net`](https://www.nuget.org/packages/Rasp.Net) instead, which
brings this in along with the other Phase A guards, wired up via `AddRasp()`.

## Documentation

See [docs/ADR](https://github.com/JVBotelho/RASP.Net/tree/main/docs/ADR) for the design rationale.
