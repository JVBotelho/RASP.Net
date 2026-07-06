# Good First Issues: Taint-Propagation Targets

Seeded backlog for [ADR 010](ADR/010-owasp-incubator-submission.md) item 1 (community
baseline) and item 2 (recruit a second project leader). Each entry below is one BCL
string-producing method the native profiler does not yet instrument, following the pattern
already shipped for `System.String::Concat(string, string)` ([ADR 006](ADR/006-sink-instrumentation-strategy.md),
"Scope discipline for v1"). Filing these as GitHub issues is blocked on the issue templates
in item 2 landing first; until then this file is the backlog. For .NET-only issues that
don't touch `Rasp.Native.Profiler` — OWASP Top 10 coverage gaps and the ADR 011 AI/LLM
boundary — see [good-first-issues-dotnet.md](good-first-issues-dotnet.md).

Each issue below has a "Ready-to-file issue" block: copy everything inside the fence as the
GitHub issue description (the first line is the suggested title).

## The existing pattern

Three places change together for `Concat(string, string)`, and change together for every
new target:

1. **Match the target** — `RaspProfiler::IsV1PropagationTarget` (`src/Rasp.Native.Profiler/src/RaspProfiler.cpp:443-483`)
   checks method name, declaring type, and the exact signature blob (calling convention,
   param count, return/param types) so only the one intended overload is rewritten.
2. **Rewrite the IL** — `DoJITCompilationStarted` (`RaspProfiler.cpp:606-648`) resolves the
   `PropagateTaint` `MemberRef` and calls `RewritePropagationProbe` with the operand count.
   `InsertPropagationCallBeforeRet` (`src/Rasp.Native.Profiler/src/ILRewriter.cpp:694-728`)
   emits `dup ; ldarg.0..N-1 ; call PropagateTaint` before every `ret`.
3. **Propagate in managed code** — `RaspTaintSensor.PropagateTaint` (`src/Rasp.Core/Context/RaspTaintSensor.cs:85-96`)
   marks the result tainted if any forwarded operand was tainted.

`ldarg.0..N-1` forwards the first N declared arguments in IL order. That works unmodified
only when every one of those N arguments is itself a `string` — true for every "Easy" issue
below. Once an operand is a non-`string` (an `int` index) or the string operands aren't
the leading arguments, the matcher and the probe both need a small extension — that's what
separates "Easy" from "Medium" below.

A unit test in `Rasp.Core.Tests/Context/RaspTaintSensorTests.cs` and, where practical, a
native smoke test alongside `src/Rasp.Native.Profiler/SmokeTest/Program.cs` (which already
covers `Concat`) are expected on every PR, per [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## Easy — same operand-count mechanism as `Concat`

### 1. `String.Concat(string, string, string)`

Three-argument overload. `IsV1PropagationTarget` needs a second signature check (param
count 3, three `ELEMENT_TYPE_STRING` params) alongside the existing 2-arg one, and
`RaspTaintSensor` needs a `PropagateTaint(string? result, string? arg0, string? arg1, string?
arg2)` overload. Call `RewritePropagationProbe` with an operand count of 3 — no changes to
`InsertPropagationCallBeforeRet` itself, since all three arguments are strings.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Taint propagation: `String.Concat(string, string, string)` (3-arg overload)

## Summary
Extend native taint propagation to the 3-argument `String.Concat(string, string, string)`
overload, following the pattern already shipped for `Concat(string, string)`.

## Background
[ADR 006](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/006-sink-instrumentation-strategy.md)
("Scope discipline for v1") ships taint propagation for exactly one BCL method: the 2-arg
`System.String::Concat(string, string)`. This issue widens that to the 3-arg overload. See
`docs/good-first-issues.md` for the shared explanation of how the three pieces below fit
together.

## What changes
- `RaspProfiler::IsV1PropagationTarget` (`src/Rasp.Native.Profiler/src/RaspProfiler.cpp:443-483`):
  add a second signature match for `Concat` — 3 declared params, all `ELEMENT_TYPE_STRING`,
  `DEFAULT` calling convention (static, no `HASTHIS`).
- `RaspTaintSensor` (`src/Rasp.Core/Context/RaspTaintSensor.cs:85-96`): add a
  `PropagateTaint(string? result, string? arg0, string? arg1, string? arg2)` overload —
  marks `result` tainted if any of the three operands is tainted.
- `RaspProfiler::DoJITCompilationStarted` (`RaspProfiler.cpp:606-648`): resolve the new
  overload's `MemberRef` and call `RewritePropagationProbe` with operand count 3 for this
  target. No change needed to `InsertPropagationCallBeforeRet` (`src/Rasp.Native.Profiler/src/ILRewriter.cpp:694-751`)
  — all three arguments are strings and are the leading arguments, so `ldarg.0..2` already
  works.

## Acceptance criteria
- [ ] Existing 2-arg `Concat(string, string)` propagation is unaffected.
- [ ] 3-arg `Concat(string, string, string)` propagates taint from any tainted operand to
      the result.
- [ ] Unit test added in `Rasp.Core.Tests/Context/RaspTaintSensorTests.cs` for the new
      `PropagateTaint` overload.
- [ ] (Nice to have) extend `src/Rasp.Native.Profiler/SmokeTest/Program.cs` to also exercise
      the 3-arg overload.

## Labels
`good-first-issue`, `taint-propagation`, `difficulty:easy`
```

</details>

### 2. `String.Concat(string, string, string, string)`

Four-argument overload. Same shape as #1, operand count 4.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Taint propagation: `String.Concat(string, string, string, string)` (4-arg overload)

## Summary
Extend native taint propagation to the 4-argument `String.Concat` overload. Same mechanism
as the 3-arg overload (see the companion issue) — only the operand count changes.

## Background
[ADR 006](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/006-sink-instrumentation-strategy.md)
ships v1 taint propagation for `String.Concat(string, string)` only. This issue is the 4-arg
sibling of the 3-arg `Concat` issue in the same backlog (`docs/good-first-issues.md`).

## What changes
- `RaspProfiler::IsV1PropagationTarget` (`src/Rasp.Native.Profiler/src/RaspProfiler.cpp:443-483`):
  add a signature match for `Concat` with 4 declared params, all `ELEMENT_TYPE_STRING`,
  `DEFAULT` calling convention.
- `RaspTaintSensor` (`src/Rasp.Core/Context/RaspTaintSensor.cs:85-96`): add a
  `PropagateTaint(string? result, string? arg0, string? arg1, string? arg2, string? arg3)`
  overload.
- `RaspProfiler::DoJITCompilationStarted` (`RaspProfiler.cpp:606-648`): resolve the new
  overload's `MemberRef` and call `RewritePropagationProbe` with operand count 4. No change
  needed to `InsertPropagationCallBeforeRet` (`src/Rasp.Native.Profiler/src/ILRewriter.cpp:694-751`)
  — all four arguments are strings and are the leading arguments.

## Acceptance criteria
- [ ] Existing `Concat` overloads (2-arg, and 3-arg if already merged) are unaffected.
- [ ] 4-arg `Concat(string, string, string, string)` propagates taint from any tainted
      operand to the result.
- [ ] Unit test added in `Rasp.Core.Tests/Context/RaspTaintSensorTests.cs`.
- [ ] (Nice to have) extend `src/Rasp.Native.Profiler/SmokeTest/Program.cs` to also exercise
      the 4-arg overload.

## Labels
`good-first-issue`, `taint-propagation`, `difficulty:easy`
```

</details>

### 3. `String.Trim()`

First instance-method target. `Trim()` takes no declared parameters, so the only
operand to forward is `this` (`ldarg.0`), operand count 1. Two differences from `Concat`
worth calling out in the PR: the signature's calling-convention byte must also test the
`IMAGE_CEE_CS_CALLCONV_HASTHIS` bit (`Concat` is static and doesn't set it), and
`RaspTaintSensor` needs a `PropagateTaint(string? result, string? operand)` two-argument
overload. This issue establishes the "instance method, operand is `this`" pattern that
`TrimStart()`, `TrimEnd()`, `ToUpperInvariant()`, and `ToLowerInvariant()` can each copy as
their own follow-up issue.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Taint propagation: `String.Trim()` (first instance-method target)

## Summary
Add native taint propagation for `String.Trim()` — the first *instance*-method propagation
target (every existing/other-queued target so far is `static`). Establishes the pattern for
`TrimStart()`, `TrimEnd()`, `ToUpperInvariant()`, `ToLowerInvariant()` as follow-up issues.

## Background
[ADR 006](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/006-sink-instrumentation-strategy.md)
ships v1 taint propagation for `String.Concat(string, string)` only, a static method. `Trim()`
is an instance method with zero declared parameters — the only operand to forward is `this`.

## What changes
- `RaspProfiler::IsV1PropagationTarget` (`src/Rasp.Native.Profiler/src/RaspProfiler.cpp:443-483`):
  add a signature match for `Trim` — 0 declared params, `System.String` return type, **and**
  the calling-convention byte must test the `IMAGE_CEE_CS_CALLCONV_HASTHIS` bit (this is the
  first target where that bit needs checking; `Concat` is static and never sets it).
- `RaspTaintSensor` (`src/Rasp.Core/Context/RaspTaintSensor.cs:85-96`): add a
  `PropagateTaint(string? result, string? operand)` two-argument overload — marks `result`
  tainted if `operand` (the original `this`) was tainted.
- `RaspProfiler::DoJITCompilationStarted` (`RaspProfiler.cpp:606-648`): resolve the new
  overload's `MemberRef` and call `RewritePropagationProbe` with operand count 1 (just
  `ldarg.0`, i.e. `this`).

## Acceptance criteria
- [ ] `Trim()` on a tainted string produces a tainted result.
- [ ] `Trim()` on an untainted string produces an untainted result.
- [ ] Existing `Concat` propagation is unaffected.
- [ ] Unit test added in `Rasp.Core.Tests/Context/RaspTaintSensorTests.cs`.
- [ ] PR description notes that `TrimStart()`, `TrimEnd()`, `ToUpperInvariant()`, and
      `ToLowerInvariant()` can each reuse this exact pattern as their own follow-up issue.

## Labels
`good-first-issue`, `taint-propagation`, `difficulty:easy`
```

</details>

---

## Medium — operand set isn't just "the leading N arguments"

### 4. `String.Replace(string, string)`

Instance method with three string operands (`this`, `oldValue`, `newValue`), all leading
arguments and all strings — mechanically like #1/#2 plus the `HASTHIS` signature bit from
#3. Grouped as Medium rather than Easy because it's the first target combining both
variations at once, a reasonable second issue for someone who already shipped one of the
Easy three.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Taint propagation: `String.Replace(string, string)`

## Summary
Add native taint propagation for the instance method `String.Replace(string oldValue,
string newValue)`. Combines two things already shipped separately elsewhere in this
backlog: multiple string operands (like the `Concat` overloads) and an instance method
whose `this` counts as an operand (like `Trim()`).

## Background
[ADR 006](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/006-sink-instrumentation-strategy.md)
ships v1 propagation for `String.Concat(string, string)` only. `Replace` has three string
operands to track: `this`, `oldValue`, `newValue` — if any is tainted, the result should be
tainted.

## What changes
- `RaspProfiler::IsV1PropagationTarget` (`src/Rasp.Native.Profiler/src/RaspProfiler.cpp:443-483`):
  add a signature match for `Replace` — 2 declared params (`oldValue`, `newValue`), both
  `ELEMENT_TYPE_STRING`, `System.String` return, and the calling-convention byte must test
  the `IMAGE_CEE_CS_CALLCONV_HASTHIS` bit (instance method).
- `RaspTaintSensor` (`src/Rasp.Core/Context/RaspTaintSensor.cs:85-96`): add a
  `PropagateTaint(string? result, string? arg0, string? arg1, string? arg2)` overload (or
  reuse the one from the 3-arg `Concat` issue if it already merged) sized for `this` +
  2 operands.
- `RaspProfiler::DoJITCompilationStarted` (`RaspProfiler.cpp:606-648`): resolve the
  overload's `MemberRef`, call `RewritePropagationProbe` with operand count 3 (`ldarg.0` =
  `this`, `ldarg.1` = `oldValue`, `ldarg.2` = `newValue`). No change to
  `InsertPropagationCallBeforeRet` — all three are strings and are the leading arguments.

## Acceptance criteria
- [ ] Taint on `this`, `oldValue`, or `newValue` (individually) each produce a tainted
      result.
- [ ] All-untainted inputs produce an untainted result.
- [ ] Unit test added in `Rasp.Core.Tests/Context/RaspTaintSensorTests.cs`.

## Labels
`good-first-issue`, `taint-propagation`, `difficulty:medium`
```

</details>

### 5. `String.Substring(int)`

Instance method where the second declared argument (`startIndex`) is an `int`, not a
`string`. Forwarding it as `ldarg.1` into a `PropagateTaint` overload typed `(string?,
string?, string?)` would push an integer where the JIT-verified signature expects an object
reference — this is the first target where `RewritePropagationProbe`'s operand count can't
just be "however many parameters the method declares." The fix is to forward only `this`
(operand count 1, same `PropagateTaint(string?, string?)` overload as `Trim()`) and skip
`startIndex` entirely — taint depends only on whether the substring's source string was
tainted, not on which slice was taken.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Taint propagation: `String.Substring(int)` — first non-string operand to skip

## Summary
Add native taint propagation for `String.Substring(int startIndex)`. This is the first
propagation target where a declared argument (`startIndex`) is not a `string` and must be
*excluded* from what gets forwarded to the managed sensor — forwarding it naively would
push an `int` where the sensor's signature expects a `string` reference.

## Background
[ADR 006](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/006-sink-instrumentation-strategy.md)
ships v1 propagation for `String.Concat(string, string)` only, where every operand is a
string. `Substring(int)` has one string operand (`this`) and one non-string operand
(`startIndex`) — taint depends only on whether the source string was tainted, not on which
slice was taken, so `startIndex` must never be forwarded.

## What changes
- `RaspProfiler::IsV1PropagationTarget` (`src/Rasp.Native.Profiler/src/RaspProfiler.cpp:443-483`):
  add a signature match for `Substring` — 1 declared param (`ELEMENT_TYPE_I4`, i.e. `int`),
  `System.String` return, `HASTHIS` set (instance method).
- `RaspProfiler::DoJITCompilationStarted` (`RaspProfiler.cpp:606-648`): call
  `RewritePropagationProbe` with operand count **1**, forwarding only `ldarg.0` (`this`) —
  not `ldarg.1` (`startIndex`). Reuses the same `PropagateTaint(string?, string?)` overload
  already added for `Trim()` (see that issue) — no new managed overload needed if `Trim()`
  has already merged; add it here otherwise.

## Acceptance criteria
- [ ] `Substring(int)` on a tainted string produces a tainted result, regardless of
      `startIndex`.
- [ ] `Substring(int)` on an untainted string produces an untainted result.
- [ ] Confirm (in the PR description or a comment) that `startIndex` is never pushed onto
      the stack ahead of the `PropagateTaint` call — this is the detail this issue exists
      to get right.
- [ ] Unit test added in `Rasp.Core.Tests/Context/RaspTaintSensorTests.cs`.

## Labels
`good-first-issue`, `taint-propagation`, `difficulty:medium`
```

</details>

### 6. `String.Insert(int, string)`

Instance method with three declared arguments (`this`, `startIndex: int`, `value: string`)
where the two string operands are not contiguous — `this` is `ldarg.0`, `value` is
`ldarg.2`, and `startIndex` (`ldarg.1`) sits between them and must be skipped.
`InsertPropagationCallBeforeRet` currently assumes the operands to forward are
`ldarg.0..N-1`; this issue needs it to accept an explicit list of argument indices instead
of a bare count. Once that lands, `Substring(int, int)` (skip both `int` arguments) becomes
a trivial follow-up.

<details>
<summary>Ready-to-file issue</summary>

```markdown
Title: Taint propagation: `String.Insert(int, string)` — non-contiguous string operands

## Summary
Add native taint propagation for `String.Insert(int startIndex, string value)`. This target
needs the IL-rewrite probe itself to change: the two string operands (`this` and `value`)
are not contiguous — `startIndex` (an `int`) sits between them and must be skipped, so the
existing "forward the first N arguments" assumption in `InsertPropagationCallBeforeRet` is
no longer sufficient.

## Background
[ADR 006](https://github.com/JVBotelho/RASP.Net/blob/develop/docs/ADR/006-sink-instrumentation-strategy.md)
ships v1 propagation for `String.Concat(string, string)`, where the operands to forward are
always the leading N arguments. `Insert(int, string)` breaks that: the string operands are
argument 0 (`this`) and argument 2 (`value`), with a non-string argument 1 in between.

## What changes
- `InsertPropagationCallBeforeRet` (`src/Rasp.Native.Profiler/src/ILRewriter.cpp:696-728`)
  and `AddPropagationProbes` (same file, `:733-751`): change the `argCount` parameter to an
  explicit list/array of argument indices to forward (e.g. `{0, 2}` for `Insert`), instead
  of assuming `ldarg.0..argCount-1`. Existing callers (`Concat`, and anything else merged by
  the time this lands) pass `{0, 1, ..., N-1}` — behaviorally unchanged for them.
- `RaspProfiler::IsV1PropagationTarget` (`src/Rasp.Native.Profiler/src/RaspProfiler.cpp:443-483`):
  add a signature match for `Insert` — 2 declared params (`ELEMENT_TYPE_I4` then
  `ELEMENT_TYPE_STRING`), `System.String` return, `HASTHIS` set.
- `RaspProfiler::DoJITCompilationStarted` (`RaspProfiler.cpp:606-648`): call the updated
  rewrite entry point with indices `{0, 2}` (skip index 1, `startIndex`). Reuses the 2-arg
  `PropagateTaint(string?, string?)` overload from the `Trim()`/`Substring(int)` issues.

## Acceptance criteria
- [ ] `Insert(int, string)` propagates taint from either `this` or `value` (independently)
      to the result.
- [ ] `startIndex` is confirmed never forwarded to `PropagateTaint`.
- [ ] Existing propagation targets (`Concat`, etc.) are unaffected by the `argCount` →
      explicit-indices signature change.
- [ ] Unit test added in `Rasp.Core.Tests/Context/RaspTaintSensorTests.cs`.
- [ ] PR description notes that `Substring(int, int)` (skip both `int` arguments) becomes a
      trivial follow-up once this lands.

## Labels
`good-first-issue`, `taint-propagation`, `difficulty:medium`
```

</details>

---

## Deliberately not seeded yet

`string.Format`, the `DefaultInterpolatedStringHandler` calls the compiler lowers string
interpolation to, `String.Join`, and `StringBuilder.Append`/`ToString` are the gap
[ADR 006](ADR/006-sink-instrumentation-strategy.md#addendum-2026-06-30-native-implementation-design-notes)
documents as v1's accepted scope limit, and [ROADMAP.md](ROADMAP.md) Stage 4 tracks them as
follow-on work. None of them fit the "small, well-scoped, existing pattern to copy" bar this
backlog is for:

- `String.Format` and interpolation take a `params object[]` (or an
  interpolated-string-handler struct) with boxed value types mixed with strings — no fixed
  operand count to forward at all.
- `String.Join` takes an array or `IEnumerable<string>` — propagation means iterating
  elements at the sink, not forwarding N `ldarg`s.
- `StringBuilder` is mutable. Taint would need to attach to the builder instance across
  repeated `Append` calls, not to an immutable `string` result — a different storage design
  from `RaspTaintSensor`'s `ConditionalWeakTable<string, object>`, not an extension of it.

These are real backlog items but belong in a design discussion (or their own ADR addendum)
before being filed as `good-first-issue`.

## Suggested labels

`good-first-issue`, `taint-propagation`, plus `difficulty:easy` or `difficulty:medium` — apply
once the issue templates from ADR 010 item 2 exist.
