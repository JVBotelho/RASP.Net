# Rasp.Net.EntityFrameworkCore

`SqlSinkGuard`: Entity Framework Core SQL injection detection for
[RASP.Net](https://github.com/JVBotelho/RASP.Net), using the public `IDbCommandInterceptor` hook.
Phase A: no runtime patching.

## Install

```
dotnet add package Rasp.Net.EntityFrameworkCore
```

Most consumers should install [`Rasp.Net`](https://www.nuget.org/packages/Rasp.Net) instead, which
brings this in along with the other Phase A guards, wired up via `AddRasp()`.

## Setup

Two steps: register the guard's dependencies, then attach the interceptor to your
`DbContextOptionsBuilder`. The second step needs the `IServiceProvider` overload of
`AddDbContext`, since `UseRaspSqlGuard` resolves the interceptor instance from DI.

```csharp
builder.Services.AddRaspEntityFrameworkCore();

builder.Services.AddDbContext<AppDbContext>((serviceProvider, options) =>
{
    options.UseNpgsql(connectionString); // or UseSqlServer, UseSqlite, etc.
    options.UseRaspSqlGuard(serviceProvider);
});
```

Forgetting `UseRaspSqlGuard` is silent: the DI registrations succeed, but no `DbContext` built
from this options builder is ever inspected, since `SqlSinkGuard` only runs from inside
`RaspDbCommandInterceptor`, and EF Core only calls interceptors that were actually added via
`AddInterceptors`.

## Documentation

See [docs/ADR](https://github.com/JVBotelho/RASP.Net/tree/main/docs/ADR) for the design rationale.
