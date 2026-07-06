# Rasp.Net.AspNetCore

ASP.NET Core middleware and security headers for [RASP.Net](https://github.com/JVBotelho/RASP.Net).
Phase A: supported public hooks only, no runtime patching.

## Install

```
dotnet add package Rasp.Net.AspNetCore
```

Most consumers should install [`Rasp.Net`](https://www.nuget.org/packages/Rasp.Net) instead, which
brings this in along with the other Phase A guards, wired up via `AddRasp()`.

## Documentation

See [docs/ADR](https://github.com/JVBotelho/RASP.Net/tree/main/docs/ADR) for the design rationale.
