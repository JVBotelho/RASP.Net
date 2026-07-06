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

## Setup

Call `RaspRuntimePatching.Initialize` as early as possible in your application lifecycle (e.g., at the very top of `Program.cs`), before any JIT inlining happens for I/O or Process operations.

```csharp
// Top of Program.cs
RaspRuntimePatching.Initialize(app.Services);
```
