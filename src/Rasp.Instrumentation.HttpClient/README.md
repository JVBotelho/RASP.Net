# Rasp.Net.HttpClient

`SsrfGuard`: outbound `HttpClient` SSRF detection for [RASP.Net](https://github.com/JVBotelho/RASP.Net)
via `DelegatingHandler` and `ConnectCallback`. Phase A: no runtime patching.

## Install

```
dotnet add package Rasp.Net.HttpClient
```

Most consumers should install [`Rasp.Net`](https://www.nuget.org/packages/Rasp.Net) instead, which
brings this in along with the other Phase A guards, wired up via `AddRasp()`.

## Setup

```csharp
builder.Services.AddRaspHttpClient();
```

That's the whole setup — `AddRaspHttpClient()` registers an `IHttpMessageHandlerBuilderFilter`
that injects `SsrfGuard`'s `DelegatingHandler` into every `HttpClient` built through
`IHttpClientFactory` (`AddHttpClient()`, named clients, typed clients). It does **not** cover an
`HttpClient` you construct yourself with `new HttpClient()` — that bypasses the factory pipeline
entirely, so route any outbound calls you want protected through `IHttpClientFactory`.

## Documentation

See [docs/ADR](https://github.com/JVBotelho/RASP.Net/tree/main/docs/ADR) for the design rationale.
