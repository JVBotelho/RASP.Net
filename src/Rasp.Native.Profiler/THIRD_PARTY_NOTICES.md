# Third-Party Notices — Rasp.Native.Profiler

Commit-pinned provenance for the vendored files below, so a future audit can verify
they haven't drifted from upstream and reproduce exactly what was fetched.

## `dotnet/runtime` (MIT License, .NET Foundation)

Source: https://github.com/dotnet/runtime
Commit fetched: `8edc1cf5f0229b2bfd25445d5baac0ded07f615e` (`main` branch, fetched 2026-07-01)

Files vendored verbatim into `inc/`, no modifications:

| File | Path in `dotnet/runtime` |
|---|---|
| `inc/corprof.h` | `src/coreclr/pal/prebuilt/inc/corprof.h` |
| `inc/corprof_i.cpp` | `src/coreclr/pal/prebuilt/idl/corprof_i.cpp` |
| `inc/corerror.h` | `src/coreclr/pal/prebuilt/inc/corerror.h` |
| `inc/cor.h` | `src/coreclr/inc/cor.h` |
| `inc/corhdr.h` | `src/coreclr/inc/corhdr.h` |
| `inc/corhlpr.h` | `src/coreclr/inc/corhlpr.h` |
| `inc/opcode.def` | `src/coreclr/inc/opcode.def` |

`inc/corhlpr.cpp` was fetched but is **not** compiled/vendored into the build — it pulls
in `utilcode.h` (internal CoreCLR build infrastructure, not part of the public profiling
API surface). `ILRewriter.cpp` implements the small subset of `COR_ILMETHOD` decoding it
needs directly instead; see the comment on `ILRewriter::Import()`.

To re-vendor at a newer commit: fetch the same relative paths from the new commit's tree
and diff against what's here before replacing — do not hand-edit these files.

## `microsoft/clr-samples` (MIT License, .NET Foundation)

Source: https://github.com/microsoft/clr-samples
Path: `ProfilingAPI/ReJITEnterLeaveHooks`
Commit fetched: `5f9a631ecb4f558b7d5e1d17af7d4d93ea836cbc` (`master` branch, fetched 2026-07-01)

Used as the structural base for `src/RaspProfiler.h`/`.cpp` (formerly `CorProfiler.h`/
`.cpp`), `src/ILRewriter.h`/`.cpp`, `src/ClassFactory.h`/`.cpp`, `src/dllmain.cpp`, and
`src/CComPtr.h`/`src/profiler_pal.h` (the latter two copied unmodified). Each adapted file
carries a header comment describing what changed from the original sample and why - see
in particular `RaspProfiler.h`/`ILRewriter.h` for the divergence from the sample's
calli-to-native-function-pointer probe design to this project's CEE_CALL-to-managed-method
design (ADR-006 addendum point 4).
