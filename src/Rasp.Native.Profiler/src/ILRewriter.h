// Adapted from microsoft/clr-samples ProfilingAPI/ReJITEnterLeaveHooks (MIT License,
// Copyright (c) .NET Foundation and contributors).
// https://github.com/microsoft/clr-samples/tree/master/ProfilingAPI/ReJITEnterLeaveHooks
//
// Changes from the original sample:
//  - AddProbe/RewriteIL inject a CEE_CALL to a *managed* method resolved via an
//    mdMemberRef token (RaspTaintSensor.PropagateTaint), instead of a CEE_CALLI to a raw
//    native function pointer. This keeps taint logic entirely on the managed side per
//    ADR-006 addendum point 4 ("native IL injects calls into a small, stable managed
//    sensor API - never raw memory/shared-state interop").
//  - The probe additionally loads the method's arguments (ldarg.0..N) so the managed
//    sensor can inspect operands, not just a function id.

#pragma once

#include <vector>

// Rewrites a method's IL to insert, before every `ret`, a call to a managed taint
// propagation sensor. Stack shape at the insertion point:
//   dup                              ; duplicate the value about to be returned
//   ldarg.0 .. ldarg.(argCount-1)    ; reload the method's original arguments
//   call void RaspTaintSensor::PropagateTaint(string, string, ...)
//   ret                              ; original return value, untouched
//
// `propagateTaintMemberRef` must be an mdMemberRef already resolved (via
// IMetaDataEmit::DefineMemberRef) against the target module, pointing at a static
// managed method whose signature is `void PropagateTaint(string result, string arg0, ...,
// string argN-1)` - i.e. (1 + argCount) string parameters, void return.
HRESULT RewritePropagationProbe(
    ICorProfilerInfo * pICorProfilerInfo,
    ModuleID moduleID,
    mdMethodDef methodDef,
    mdMemberRef propagateTaintMemberRef,
    unsigned argCount);
