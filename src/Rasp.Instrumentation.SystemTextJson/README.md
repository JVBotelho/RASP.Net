# Rasp.Net.SystemTextJson

`DeserializationGuard`: `System.Text.Json` deserialization threat detection for
[RASP.Net](https://github.com/JVBotelho/RASP.Net) via type-info modifiers. Phase A: no runtime
patching.

## Install

```
dotnet add package Rasp.Net.SystemTextJson
```

Most consumers should install [`Rasp.Net`](https://www.nuget.org/packages/Rasp.Net) instead, which
brings this in along with the other Phase A guards, wired up via `AddRasp()`.

## Documentation

See [docs/ADR](https://github.com/JVBotelho/RASP.Net/tree/main/docs/ADR) for the design rationale.
