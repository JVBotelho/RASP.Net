# ADR 002: Detection Engine Evolution (Phased Strategy)

**Status:** Partially Implemented

## Context
High-performance security requires balancing deep inspection with minimal latency. Traditional reflection-based approaches in .NET are too slow for hot-path execution. We need a strategy to evolve the engine from functional to ultra-performant.

## Decision
Implement a three-phase evolution strategy to achieve zero-allocation security.

* **Phase 1 (Deprecated):** Runtime Reflection. Validated logic but incurred high GC overhead.
* **Phase 2 (Current v1.0):** Zero-Allocation Engine using `Span<T>` and `SearchValues<T>` combined with `IMessage.Descriptor` for gRPC integration.
* **Phase 3 (Planned):** Source Generators to eliminate all allocations in the integration layer by generating static inspection methods at compile-time.

## Current State
The Core engine is **100% zero-alloc** (achieving ~4ns on hot paths). The gRPC interception layer currently uses `IMessage.Descriptor`, resulting in a ~75% reduction in allocations compared to standard `ToString()` serialization methods.

## Consequences
* **Performance:** Achieves nanosecond-scale latency for the detection logic.
* **Complexity:** Requires manual memory management using `stackalloc` and `ArrayPool`.
* **Future Proofing:** Sets the stage for Source Generators (Phase 3) without requiring a rewrite of the core detection logic.