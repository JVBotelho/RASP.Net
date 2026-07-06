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

## Setup

Two steps: register the guard's dependencies, then wire `DeserializationGuard` into the actual
`JsonSerializerOptions` your app deserializes with. The second step needs a built
`IServiceProvider`, since `AddRaspProtection` resolves `DeserializationGuard` from DI.

```csharp
builder.Services.AddRaspSystemTextJson();

var app = builder.Build();

var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
jsonOptions.AddRaspProtection(app.Services);
```

Apply this to whichever `JsonSerializerOptions` instance your app actually deserializes
untrusted input with — for ASP.NET Core controllers that's the options object exposed by
`AddControllers().AddJsonOptions(...)`, for Minimal APIs it's `Microsoft.AspNetCore.Http.Json.JsonOptions`.
`AddRaspProtection` only supports a `null` or `DefaultJsonTypeInfoResolver`-based
`TypeInfoResolver`; if you've already replaced it with a fully custom resolver (e.g. a
source-generated `JsonSerializerContext`), it throws `NotSupportedException` rather than
silently skipping protection.

## Documentation

See [docs/ADR](https://github.com/JVBotelho/RASP.Net/tree/main/docs/ADR) for the design rationale.
