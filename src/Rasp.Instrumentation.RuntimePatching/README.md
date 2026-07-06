# Rasp.Net.RuntimePatching

> [!WARNING]
> **Risk Tier: Phase B (Runtime Patching)**
> 
> This package relies on `MonoMod` to intercept and patch BCL calls (`FileStream`, `Process.Start`) at runtime.
> - **Native AOT:** This package is fundamentally incompatible with Native AOT compilation.
> - **AV/EDR Flagging:** The runtime modification techniques used here are similar to those used by malware, which may cause your application to be flagged by Antivirus or Endpoint Detection and Response (EDR) solutions.

## Overview

This is an **opt-in** package that provides advanced instrumentation for RASP.Net. It includes:
- `PathTraversalGuard`
- `CommandInjectionGuard`

If you do not explicitly need these guards and the associated runtime patching, use the default `Rasp.Net` package instead, which includes only Phase A (safe) instrumentation.

## Install

```
dotnet add package Rasp.Net.RuntimePatching
```

Unlike the other guard packages, this one is never pulled in transitively by `Rasp.Net` — read
the warning above before adding it.

## Setup

`PathTraversalGuard` and `CommandInjectionGuard` are already registered by `AddRaspCore()` (and
therefore by `AddRasp()`) — this package doesn't add its own DI registration call. The one thing
it adds is `RaspRuntimePatching.Initialize`, which applies the MonoMod `ILHook`s that route
`FileStream`/`File.*` and `Process.Start` calls into those already-registered guards. Call it as
early as possible in your application's lifecycle — before any JIT inlining happens for the I/O
or `Process` APIs being patched, which in practice means right after building the app, before
`app.Run()`.

```csharp
builder.Services.AddRasp(builder.Configuration); // or AddRaspCore() - registers the guards

var app = builder.Build();

RaspRuntimePatching.Initialize(app.Services); // applies the MonoMod patches
```

Calling `Initialize` late (e.g. after the app has already started serving requests) risks the
patched methods having already been JIT-compiled without the hook in place, since MonoMod's
`ILHook` rewrites the method body — it does not retroactively patch already-JIT'd call sites.
`Initialize` is idempotent and a no-op under Native AOT (dynamic code generation unavailable),
logging a warning rather than throwing.
