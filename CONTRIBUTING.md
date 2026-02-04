# Contributing to [RASP.Net](https://github.com/JVBotelho/RASP.Net)

First of all, thank you for being here! RASP.Net is a project focused on the intersection of **Extreme Performance** and **Active Security**. To maintain our technical integrity, we follow a set of strict engineering standards.

## 🛡️ The Golden Rules

### 1. Zero Allocations on Hot Path

The **Hot Path** refers to the detection engine's core loops and interceptors where <10ns overhead is critical. Any code triggered during request inspection must not allocate memory on the managed heap.

* **Avoid:** `new`, string concatenation (`+`), LINQ, or `Task` allocations.
* **Use:** `Span<T>`, `ReadOnlySpan<T>`, `stackalloc`, or `ArrayPool<T>`.

#### 💡  Memory Management Pattern

When handling variable-sized buffers, always use the hybrid approach. Use the **Stack** for small payloads and the **ArrayPool** for larger ones. This avoids heap allocations while protecting against `StackOverflowException`. 

```csharp
// 1. Safety check: avoid invalid or empty allocations
if (maxSize <= 0) return;

// 2. Define a safe threshold for stack allocation
const int StackThreshold = 256;

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
    // 3. Critical: Always return rented memory to avoid leaks
    if (rented is not null)
    {
        // Use clearArray: true ONLY if the buffer contains sensitive data (e.g., passwords)
        ArrayPool<byte>.Shared.Return(rented, clearArray: false);
    }
}
```
> **Notes:**
> - The maxSize <= 0 check is our "safety belt" against runtime exceptions and potential memory corruption triggers.
> - The 256-byte threshold is a conservative guard to avoid excessive stack usage and is not a hard rule.
> - Do not use stackalloc across async/await boundaries.
> - For maxSize <= 0, the operation is a no-op by design.

### 2. Benchmark or it didn't happen

Every detection logic change **must** include a [BenchmarkDotNet](https://benchmarkdotnet.org/) report in the Pull Request description. We prioritize **p95 and p99.9 latency**.

### 3. English Only

All code documentation (XML docs), error messages, and commit messages must be in English. This ensures that all global contributors and users can understand and audit the security logic effectively.

---

## 📊 Performance Tiers (The "Race Track")

We don't reject code simply because it doesn't hit the ideal nanoseconds on the first try. Instead, we classify contributions into **Tiers**. Our goal is to help you "tune" your code to Tier 1 through technical mentorship during Code Review.

| Tier | Latency Overhead | Status |
| --- | --- | --- |
| **🏎️ Elite (Tier 1)** | **< 10ns** | **Hot Path Ready.** Our gold standard. Essential for the core detection engine. |
| **🚀 Optimal (Tier 2)** | **10ns - 50ns** | **Feature Ready.** Acceptable for complex inspections, nested objects, or conditional logic. |
| **🐢 Standard (Tier 3)** | **> 50ns** | **Review Required.** Requires architectural discussion or optimization (e.g., SIMD or Source Generators). |

**How it works:**

* If your PR falls into **Tier 3**, we will work with you to identify bottlenecks (hidden allocations, boxing, lack of inlining).
* Every new feature should strive to move up the tiers before being merged into the `develop` branch.

---

## 🐛 Reporting Issues

If you found a bug or have a suggestion for improvement:

1. **Search existing issues** to see if it has already been reported.
2. **Provide a minimal reproducible example** (ideally a unit test or a small console app).
3. **Include your environment details**: .NET version, OS, and hardware (especially for performance-related issues).

---

## 🚀 Pull Request Process

1. **Branching**: Create your feature branch from `develop`. The `master` branch is reserved for stable releases.
2. **Draft PRs**: We encourage opening a **Draft PR** early in the process to discuss architectural decisions before finalizing the code.
3. **Code Quality**: Ensure [CodeQL](https://codeql.github.com/) scans pass without new security alerts.
4. **ADR Updates**: If your PR introduces structural changes, please update or create a new **ADR (Architecture Decision Record)** in the `docs/ADR` folder.

---

## 💻 Development Environment

To ensure benchmark consistency, please use the following setup for performance testing:

* **SDK**: .NET 10.0.102 or newer.
* **Mode**: Always run benchmarks in `Release` mode.
* **Hardware**: Specify your CPU and RAM speed in the PR. (Our reference baseline is the AMD Ryzen 7 7800X3D).
