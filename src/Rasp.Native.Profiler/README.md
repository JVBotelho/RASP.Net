# Rasp.Native.Profiler

Native CLR profiler for ADR-006 Phase C (taint propagation). Implements
`ICorProfilerCallback8` and rewrites IL via the classic `SetILFunctionBody` mechanism (not
ReJIT — see [docs/ADR/006-sink-instrumentation-strategy.md](../../docs/ADR/006-sink-instrumentation-strategy.md),
"Addendum: native implementation design notes", point 1, for why and the tiered-compilation
caveat that follows from it).

## Status: verified against a live CLR process — smoke test passed (3/3 runs).

### Hardening

- `LoadChainedProfilerIfConfigured` requires the resolved path to be inside this DLL's own
  installation directory *and* carry a valid Authenticode signature (`WinVerifyTrust`)
  before `LoadLibraryW`. See the comment above that function in `RaspProfiler.cpp`.
- `Rasp.Core` is strong-named (public-sign; see `src/Rasp.Core/Rasp.Core.csproj`), and the
  native `DefineAssemblyRef` call pins its public key token, so the injected `CEE_CALL` can
  only resolve against an assembly matching that key — not just anything named `Rasp.Core`.
  This pin is enforced unconditionally by the CLR loader itself.
- Optional, opt-in Authenticode check on the loaded `Rasp.Core.dll`
  (`RASP_REQUIRE_CORE_AUTHENTICODE=1`, off by default — no release build is signed yet).
  Detective, not preventive: `ModuleLoadFinished` logs loudly via `OutputDebugStringW` if the
  module satisfying the AssemblyRef isn't Authenticode-signed, but cannot gate the IL rewrite
  itself, because `JITCompilationStarted` for `String.Concat` routinely fires *before*
  `Rasp.Core.dll` has loaded (`Concat` is called all over the BCL well before an app's own
  reference to Rasp.Core resolves). See `CheckCoreAuthenticodeIfRaspCoreModule` in
  `RaspProfiler.cpp` and [ADR 006](../../docs/ADR/006-sink-instrumentation-strategy.md)
  addendum point 5 for the full reasoning and why a real Authenticode-signed release build is
  still pending a certificate decision.
- `dllmain.cpp` relies on the `extern IID_IUnknown`/`IID_IClassFactory` already provided by
  `<unknwn.h>` + `-luuid` instead of redefining them locally (the redefinition only linked
  correctly by accident of MinGW's `-fms-extensions`; it would fail under standard MSVC).
- Failure-path logging (`OutputDebugStringW`) throughout `LoadChainedProfilerIfConfigured`.
- `RASP_CHAINED_PROFILER_PATH` is read once, not twice independently; if set but longer than
  `MAX_PATH`, that now fails loudly (`LogChainFailure`) instead of being silently treated as
  unconfigured.
- A chained profiler's own `Initialize()` almost always calls `SetEventMask` itself, which
  *replaces* (not merges with) the process-wide mask — `LoadChainedProfilerIfConfigured` now
  re-asserts RASP's own required bits (JIT compilation monitoring, inlining/NGen disable, and
  module-load monitoring when `RASP_REQUIRE_CORE_AUTHENTICODE` is set) via `GetEventMask` +
  `SetEventMask` after the chained profiler initializes, so a downstream profiler can no
  longer silently disable the taint rewrite by claiming the event mask for itself.
- `DOTNET_TieredCompilation=0` was previously documented as required but not defended against:
  `g_rewrittenMethods` now tracks which `(ModuleID, mdMethodDef)` pairs have already been
  rewritten and skips (logging loudly) a second `SetILFunctionBody` call for the same method,
  since that API is not idempotent and a second application would stack a second probe on top
  of the first rather than throwing.
- Opt-in ASan/UBSan CMake option (`-DRASP_ENABLE_SANITIZERS=ON`). Compiles under the
  CLion-bundled MinGW used for dev-machine verification but does **not** link there — that
  MinGW distribution doesn't ship `libasan`/`libubsan`. Compiler-aware, should work under
  the CI job's real MSVC via `/fsanitize=address`, but that path hasn't been locally
  verified — treat it as present-but-unproven until a CI run exercises it.
- CI job building this project with real MSVC on every push
  (`.github/workflows/build.yml`, `native-profiler-build`).
- Commit-pinned provenance for the vendored headers/sample code
  (`THIRD_PARTY_NOTICES.md`).

**Still open / accepted for v1:** no fuzz/adversarial testing of
`ILRewriter`'s hand-written IL parser against malformed input; no second human reviewer
has looked at this code; the `LoadLibraryW` path-restriction assumes the installation
directory itself isn't writable by the profiled application's own identity — a deployment
concern, not something this code can enforce. Do not treat this component as
production-hardened beyond the specific v1 scope and fixes documented here.

**Last verified:** 2026-07-02, `net10.0`, Windows, MinGW-w64/GCC 13.1.0 build.
`libRasp.Native.Profiler.dll` built from the current `src/` (see `build.ps1`). Ran
`SmokeTest` 3 consecutive times with `CORECLR_ENABLE_PROFILING=1`,
`CORECLR_PROFILER={9c80f47f-0a8f-4f39-8205-4c605c739df7}`, `CORECLR_PROFILER_PATH` pointing
at the built DLL, `DOTNET_TieredCompilation=0`:

1. `RASP_REQUIRE_CORE_AUTHENTICODE` unset (default/regression): process loaded the profiler,
   `JITCompilationStarted` fired for `System.String::Concat(string, string)`, the
   `AssemblyRef`/`TypeRef`/`MemberRef` resolution against the already-loaded `Rasp.Core.dll`
   succeeded, the rewritten IL executed without corrupting the stack, and
   `RaspTaintSensor.IsTainted(concatResult)` correctly returned `true`. Exit code 0, no
   crash, no hang.
2. `RASP_REQUIRE_CORE_AUTHENTICODE=1`: same taint-propagation result as run 1 (confirms the
   detective check adds no functional side effect), **and**, captured with a throwaway
   DBWIN listener, the expected log line fired: `[Rasp.Native.Profiler] Rasp.Core.dll loaded
   from '...\Rasp.Core.dll' does not carry a valid Authenticode signature.` — correct, since
   this dev build isn't signed. First attempt at this specific run produced no log line at
   all; root cause was `COR_PRF_MONITOR_MODULE_LOADS` not being in the event mask unless
   chaining was also configured (a real bug, now fixed — see `Initialize()` in
   `RaspProfiler.cpp`), not a listener timing issue as first suspected.
3. `RASP_REQUIRE_CORE_AUTHENTICODE` unset again, re-run after the event-mask fix: same as
   run 1, confirming the fix didn't regress the default-off path.

**Re-verified 2026-07-02** after adding the chained-profiler event-mask merge and the
`g_rewrittenMethods` double-rewrite guard: run 1's scenario (`DOTNET_TieredCompilation=0`,
no chaining configured) still passes identically. Also ran once **without**
`DOTNET_TieredCompilation` set at all, to probe the double-rewrite guard - still passed, but
this is a weaker result than it sounds: the smoke test's process lifetime is too short to
reliably trigger a tier-0→tier-1 recompile (which is what would make
`JITCompilationStarted` fire twice for the same method and actually exercise the skip path),
so this run does not confirm `g_rewrittenMethods` correctly caught and skipped a real second
rewrite - only that its presence doesn't break the common single-rewrite case. Treat the
double-rewrite guard itself as unit-verified-in-design, not live-verified, until a test that
can force tiered recompilation within the smoke test's lifetime exists.

The negative case (neither operand tainted → result not tainted) is covered by
`RaspTaintSensorTests.PropagateTaint_NeitherOperandTainted_ResultNotTainted`
(xUnit, `Rasp.Core.Tests`) rather than re-verified live, since the native side's only job is
correctly forwarding `arg0`/`arg1` — which the passing positive-case run already
demonstrates — and the gating logic itself is pure C# already under test.

**Re-run this test after any change to `RaspProfiler.cpp`, `ILRewriter.cpp`, or the
`RaspTaintSensor.PropagateTaint` signature** — none of that is covered by the .NET test
suite; only this manual smoke test exercises the actual native/managed boundary.

### Live-attach smoke test

The fixture already exists at `SmokeTest/` (not part of `Rasp.sln` - throwaway
verification tool, not a shipped artifact). To re-run:

1. Build the native profiler: `pwsh src/Rasp.Native.Profiler/build.ps1`
2. Build the fixture: `dotnet build src/Rasp.Native.Profiler/SmokeTest/SmokeTest.csproj`
3. Run it with the profiler attached:
   ```powershell
   $env:CORECLR_ENABLE_PROFILING = "1"
   $env:CORECLR_PROFILER = "{9c80f47f-0a8f-4f39-8205-4c605c739df7}"
   $env:CORECLR_PROFILER_PATH = "<absolute path to build/libRasp.Native.Profiler.dll>"
   $env:DOTNET_TieredCompilation = "0"   # required - see ADR-006 addendum point 1
   dotnet exec src/Rasp.Native.Profiler/SmokeTest/bin/Debug/net10.0/SmokeTest.dll
   ```
4. Compare against the "Last verified" result above:
   - **PASS**, exit 0 → matches last verified behavior, update the date/hash above.
   - **FAIL** printed but process exits cleanly → token resolution or IL rewrite ran but
     propagation didn't take effect; check `RASP_CHAINED_PROFILER_PATH`/`_CLSID` aren't
     accidentally set, and that `Rasp.Core.dll` is actually loaded before `String.Concat`
     first JITs.
   - Process crashes / hangs / the CLR refuses to load the profiler → **regression**, do
     not treat any other part of this component as trustworthy until root-caused; this is
     exactly the failure mode ADR-006 warns is expensive to debug post-hoc. Capture the
     crash dump / CLR profiler log before doing anything else.

## Build

```powershell
pwsh src/Rasp.Native.Profiler/build.ps1
```

Not part of `Rasp.sln` / MSBuild — this is a native C++ COM DLL, built with CMake/Ninja, not
the .NET SDK. Same convention as `src/Rasp.Native.Guard` (ADR-003): native components in
this repo build standalone. Requires a C++17 toolchain, CMake, and a generator (Ninja
recommended) on `PATH`; pass `-CxxCompilerPath`/`-CmakePath`/`-NinjaPath` if not.

Headers under `inc/` and the original structural basis for `src/` are vendored from
`dotnet/runtime` and `microsoft/clr-samples` (both MIT licensed) — see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the exact commit SHAs, file mapping,
and re-vendoring instructions. Do not hand-edit the files under `inc/`.

## v1 scope

- **Taint mark/check are plain managed calls**, not IL-rewritten: `SecurityInterceptor` /
  `RaspContextMiddleware` (perimeter, ADR-007) call `RaspTaintSensor.MarkTainted`;
  `SqlSinkGuard` (Phase A sink) can call `RaspTaintSensor.IsTainted`. This profiler injects
  nothing there.
- **The only IL rewrite target is `System.String::Concat(string, string)`** — the single
  curated BCL method where taint would otherwise silently vanish across a transformation
  (string immutability means a concat result is never the same object as its operands).
  Widening to more BCL string-producing methods (`StringBuilder.Append/ToString`,
  `string.Format`, string interpolation's compiler-generated calls, etc.) is deferred; see
  `RaspProfiler::IsV1PropagationTarget` for where to add more matches, and
  `RaspTaintSensor.PropagateTaint` for the managed side each new target needs to call
  (widen the overload set, keep the native `mdMemberRef` signature blob in lockstep).
- **Methods with extra IL sections (EH clauses) are rejected, not mis-parsed.** See the
  comment on `ILRewriter::Import()`. Not a concern for `String.Concat` itself, but matters
  if the target list ever grows.
- **Profiler chaining is best-effort, not exhaustive.** Set `RASP_CHAINED_PROFILER_PATH`
  and `RASP_CHAINED_PROFILER_CLSID` (as `{xxxxxxxx-xxxx-...}`) to run alongside another
  profiler (Datadog, OpenTelemetry auto-instrumentation, etc.) — RASP becomes the only
  profiler actually registered with the CLR and forwards a curated subset of lifecycle/JIT
  callbacks to the downstream one. See the callback list forwarded in `RaspProfiler.cpp`
  (search `chainedProfiler->`) — not all ~70 `ICorProfilerCallback8` methods are forwarded,
  only the ones most APM/tracing agents rely on. Widening this is mechanical (copy the
  `if (this->chainedProfiler != nullptr) ...` pattern into more overrides) but untested
  against any specific real downstream profiler.
