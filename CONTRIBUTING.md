# Contributing to RASP.Net

Thank you for your interest in RASP.Net. This project explores the intersection of **extreme performance** and **active security** in .NET. Our goal is to prove that runtime protection doesn't require sacrificing throughput or latency.

We welcome contributions from all skill levels, but we hold code to strict engineering standards. This document explains our performance philosophy and technical requirements.

---

## 🎯 Why Performance Matters

RASP.Net operates in the **request path** of high-throughput applications. In production:

- A typical API responds in **2-5ms**
- Our total inspection budget must stay under **5% of response time** (~100-250μs)
- One poorly optimized detection can destroy SLA compliance

We benchmark against physics, not intuition.

### The Physics of Latency

Understanding hardware limits is essential:

| Operation | Latency |
|-----------|---------|
| L1 Cache Access | ~1 ns |
| L2 Cache Access | ~3-10 ns |
| Main Memory (RAM) | ~100 ns |
| Context Switch | ~1-2 μs |

Your code operates in the **microsecond realm**. Design accordingly.

---

## 📊 Performance Tiers

We classify inspection logic into tiers based on **added latency** (p99). These align with real-world SLA requirements.

| Tier | Latency Budget | Context | Examples |
|------|---------------|---------|----------|
| **🏎️ Tier 1 (Hot Path)** | **< 2 μs** | Header inspection, URL scanning, auth tokens | `SearchValues<byte>`, SIMD (AVX2/512), branchless logic |
| **🚀 Tier 2 (Standard)** | **< 20 μs** | JSON body inspection (<4KB), shallow parsing | `Utf8JsonReader`, zero-allocation parsers |
| **⚙️ Tier 3 (Deep)** | **< 100 μs** | Complex grammar analysis (SQL/XML), regex with backtracking | DFA regex, careful state machines |
| **❌ Rejected** | **> 200 μs** | Single-inspection overhead breaks user SLA | N/A |

**Note:** If your PR falls into Tier 3 for hot-path code, we'll work with you during code review to identify optimizations (hidden allocations, boxing, inlining opportunities).

---

## 🛡️ Code Standards

### 1. Zero Allocations on Hot Path

The **Hot Path** refers to the detection engine's core loops and interceptors where low-latency is critical. Any code triggered during request inspection must not allocate memory on the managed heap.

**Forbidden:**
- `new`, string concatenation (`+`), LINQ, or `Task` allocations
- `params object[]`, closures, boxing
- `async/await` state machines inside inspection loops

**Required:**
- `Span<T>`, `ReadOnlySpan<T>`, `stackalloc`, or `ArrayPool<T>`

#### 💡 Memory Management Pattern

When handling variable-sized buffers, always use the hybrid approach. Use the **Stack** for small payloads and the **ArrayPool** for larger ones. This avoids heap allocations while protecting against `StackOverflowException`.
```csharp
// Safety check: avoid invalid allocations or DoS attempts
// RASP should never inspect massive payloads in-memory.
const int MaxInspectionLimit = 32 * 1024; // 32KB Hard Limit
if (maxSize <= 0 || maxSize > MaxInspectionLimit) return;

// 2. Define a safe threshold for stack allocation
const int StackThreshold = 512;

Span<byte> buffer;
byte[]? rented = null;

if (maxSize <= StackThreshold)
{
    // Fast path: immediate allocation on the stack
    buffer = stackalloc byte[maxSize];
}
else
{
    // Safety path: rent from pool for larger payloads
    rented = ArrayPool<byte>.Shared.Rent(maxSize);
    buffer = rented.AsSpan(0, maxSize);
}

try
{
    // Logic goes here (e.g., _engine.Analyze(buffer))
}
finally
{
    // Critical: Always return rented memory to avoid leaks
    if (rented is not null)
    {
        // Use clearArray: true ONLY if the buffer contains sensitive data (e.g., passwords)
        ArrayPool<byte>.Shared.Return(rented, clearArray: false);
    }
}
```

> **Notes:**
> - The `maxSize <= 0` check is our "safety belt" against runtime exceptions and potential memory corruption triggers.
> - The 512-byte threshold is a conservative guard to avoid excessive stack usage and is not a hard rule.
> - Do not use `stackalloc` across `async/await` boundaries.
> - For `maxSize <= 0`, the operation is a no-op by design.

---

### 2. Benchmarks Are Mandatory

Every detection logic change **must** include a [BenchmarkDotNet](https://benchmarkdotnet.org/) report in the PR description. We prioritize **p95 and p99.9 latency**.

**Fail conditions:**
- Gen0/Gen1/Gen2 columns show anything other than `-` (zero) on hot path
- p99 latency regression > 10% vs baseline

**Pass criteria:**
- Overhead within ±5% of baseline
- Zero allocations confirmed

Run: `dotnet run -c Release --project src/Rasp.Benchmarks`

---

### 3. Security Test Suite

Run the exploit suite before opening a PR:
```bash
dotnet test
```

**Requirement:** 100% block rate on known attack vectors. Security is non-negotiable.

---

### 4. Thread Safety

The RASP engine is a singleton. All state must be:
- Immutable (`readonly`, `init`)
- Thread-safe (use `Interlocked`, `FrozenDictionary<T>`, or `ConcurrentDictionary<T>`)

---

### 5. English Only

All code documentation (XML docs), error messages, and commit messages must be in English. This ensures that all global contributors and users can understand and audit the security logic effectively.

---

## 🚀 Pull Request Process

1. **Branching:** Create your feature branch from `develop`. The `master` branch is reserved for stable releases.
2. **Draft PRs:** We encourage opening a **Draft PR** early in the process to discuss architectural decisions before finalizing the code.
3. **Code Quality:** Ensure [CodeQL](https://codeql.github.com/) scans pass without new security alerts.
4. **ADR Updates:** If your PR introduces structural changes, please update or create a new **ADR (Architecture Decision Record)** in the `docs/ADR` folder.

We value **collaboration over gatekeeping**. If your PR needs optimization, we'll help during code review.

---

## 🐛 Reporting Issues

If you found a bug or have a suggestion for improvement:

1. **Search existing issues** to see if it has already been reported.
2. **Provide a minimal reproducible example** (ideally a unit test or a small console app).
3. **Include your environment details**: .NET version, OS, and hardware (especially for performance-related issues).

When reporting bugs, please provide:
- **Full stack trace** with line numbers
- **Environment:** OS, architecture (x64/ARM64), .NET version
- **Minimal repro:** Failing unit test or small console app

---

## ⚠️ Common Pitfalls

These patterns will require revision before merge:

| Anti-Pattern | Why It's Problematic | Better Alternative |
|--------------|---------------------|-------------------|
| `input.Contains("<script>")` | Allocates, slow | `input.AsSpan().IndexOfAny(SearchValues)` |
| `Regex` without timeout | ReDoS vulnerability | Set `RegexOptions.NonBacktracking` or use timeout |
| `.ToList()` / `.ToArray()` in middleware | Heap allocation | `foreach` over `IEnumerable<T>` |
| `catch (Exception) { }` | Hides bugs, destroys observability | Log or rethrow |
| `Console.WriteLine` | Synchronous, blocks thread | Use `ILogger` abstraction |

---

## 💻 Development Environment

To ensure benchmark consistency, please use the following setup for performance testing:

- **SDK:** .NET 10.0.102 or newer
- **Mode:** Always run benchmarks in `Release` mode
- **Hardware:** Specify your CPU and RAM speed in the PR. (Our reference baseline is the AMD Ryzen 7 7800X3D)

---

## 🏆 Recognition

Contributors who optimize a critical path by >20% or identify a major security gap get recognition in `ELITE_CONTRIBUTORS.md`.

We respect engineers who understand the machine.

---

**Questions?** Open a discussion in GitHub Discussions. We're here to help you ship high-quality code.
