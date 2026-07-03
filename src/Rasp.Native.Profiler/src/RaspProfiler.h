// RASP.Net native CLR profiler (ADR-006 Phase C, v1 scope).
//
// Structural base adapted from microsoft/clr-samples ProfilingAPI/ReJITEnterLeaveHooks
// (MIT License, Copyright (c) .NET Foundation and contributors):
// https://github.com/microsoft/clr-samples/tree/master/ProfilingAPI/ReJITEnterLeaveHooks
//
// v1 scope (see docs/ADR/006-sink-instrumentation-strategy.md, "Addendum: native
// implementation design notes"):
//   - Taint MARK/CHECK happen entirely in managed code we already own (the source-generated
//     {Service}RaspInterceptor, registered via AddRaspSecurity() - not SecurityInterceptor, a
//     generic fallback used only by benchmarks - and RaspContextMiddleware mark; SqlSinkGuard
//     checks) - no IL rewriting needed there.
//   - This profiler's only job is taint PROPAGATION through a narrow, curated set of BCL
//     string-producing methods where a new string object is created from tainted inputs
//     and would otherwise silently lose its taint association. v1 targets exactly one:
//     System.String::Concat(string, string).
//   - The injected probe calls a MANAGED sensor method (Rasp.Core.Context.RaspTaintSensor
//     .PropagateTaint) via an mdMemberRef token, never a raw native function pointer -
//     all taint policy stays in C#, testable with the same xUnit harness as every other
//     RASP engine.
//
// Profiler chaining (ADR-006 addendum point 2): the CLR allows exactly one
// ICorProfilerCallback per process. If RASP_CHAINED_PROFILER_PATH and
// RASP_CHAINED_PROFILER_CLSID are set, RaspProfiler loads that profiler DLL as a
// downstream chain target and forwards the lifecycle/JIT callbacks most APM/tracing
// agents rely on (module/assembly/appdomain load, JIT compilation, thread lifecycle).
// This is a best-effort, curated forward list - not all ~70 ICorProfilerCallback8
// methods are forwarded. Widening coverage is a small, mechanical addition per method
// (query cache the chained pointer once, call the same method on it) as real coexistence
// needs surface; see ForwardXxx naming below for the pattern to copy.

#pragma once

#include <atomic>
#include <string>
#include "cor.h"
#include "corprof.h"

class RaspProfiler : public ICorProfilerCallback8
{
private:
    std::atomic<int> refCount;
    ICorProfilerInfo8* corProfilerInfo;

    // Non-null only if RASP_CHAINED_PROFILER_PATH/_CLSID are configured and the chained
    // profiler DLL loaded and initialized successfully. ICorProfilerCallback2 is used as
    // the common baseline most published .NET profilers implement.
    HMODULE chainedProfilerModule;
    ICorProfilerCallback2* chainedProfiler;

    // Read once in Initialize() from RASP_REQUIRE_CORE_AUTHENTICODE. Off by default - see
    // ModuleLoadFinished's doc comment for why this is a detective control (alert on a
    // mismatch), not a preventive one that can gate the AssemblyRef rewrite itself.
    bool requireCoreAuthenticode;

    // Resolves (defining fresh mdMemberRef tokens if needed) the managed
    // RaspTaintSensor.PropagateTaint(string, string, string) method against the metadata
    // scope of `moduleId`, so it can be called via CEE_CALL from IL rewritten in that
    // module. Returns the resolved token in `pMemberRef`.
    HRESULT ResolvePropagateTaintMemberRef(ModuleID moduleId, mdMemberRef* pMemberRef);

    // RASP's own v1 propagation-probe logic, factored out of the public
    // JITCompilationStarted override so that override can unconditionally forward the
    // event to a chained profiler afterward regardless of this method's outcome.
    HRESULT DoJITCompilationStarted(FunctionID functionId, BOOL fIsSafeToBlock);

    // True if `methodDef` in `moduleId` is System.String::Concat(string, string) - the
    // sole v1 instrumentation target.
    bool IsV1PropagationTarget(ModuleID moduleId, mdMethodDef methodDef, IMetaDataImport* pMetaDataImport);

    // If `moduleId` is Rasp.Core.dll, verifies its Authenticode signature and logs loudly
    // (never fails the module load) if it's missing or invalid. Only called when
    // requireCoreAuthenticode is set. See the .cpp for why this is necessarily a detective
    // control, not a gate on the AssemblyRef rewrite.
    void CheckCoreAuthenticodeIfRaspCoreModule(ModuleID moduleId);

    // Validates and, if valid, loads the downstream profiler named by
    // RASP_CHAINED_PROFILER_CLSID at `rawPath` (already read once by the caller from
    // RASP_CHAINED_PROFILER_PATH - not re-read here, so the event-mask decision in
    // Initialize() and this load attempt can never observe two different env var values).
    // Never fails RASP's own Initialize() - a rejected/misconfigured chain target is
    // logged via OutputDebugStringW (no structured logging sink exists this early in CLR
    // startup) and silently skipped, not fatal. Before LoadLibraryW, requires: (1) the
    // resolved absolute path is inside this DLL's own installation directory, and (2) the
    // target file has a valid, chain-verified Authenticode signature - see the note above
    // LoadChainedProfilerIfConfigured's definition in the .cpp. `requiredEventMask` is
    // re-applied via SetEventMask after the chained profiler's own Initialize() returns,
    // since most profilers call SetEventMask themselves and the CLR API has last-write-wins,
    // not additive, semantics - without this, a chained profiler can silently disable the
    // JIT-compilation monitoring RASP's own taint rewrite depends on.
    void LoadChainedProfilerIfConfigured(IUnknown* pICorProfilerInfoUnk, const std::wstring& rawPath, DWORD requiredEventMask);

public:
    RaspProfiler();
    virtual ~RaspProfiler();
    HRESULT STDMETHODCALLTYPE Initialize(IUnknown* pICorProfilerInfoUnk) override;
    HRESULT STDMETHODCALLTYPE Shutdown() override;
    HRESULT STDMETHODCALLTYPE AppDomainCreationStarted(AppDomainID appDomainId) override;
    HRESULT STDMETHODCALLTYPE AppDomainCreationFinished(AppDomainID appDomainId, HRESULT hrStatus) override;
    HRESULT STDMETHODCALLTYPE AppDomainShutdownStarted(AppDomainID appDomainId) override;
    HRESULT STDMETHODCALLTYPE AppDomainShutdownFinished(AppDomainID appDomainId, HRESULT hrStatus) override;
    HRESULT STDMETHODCALLTYPE AssemblyLoadStarted(AssemblyID assemblyId) override;
    HRESULT STDMETHODCALLTYPE AssemblyLoadFinished(AssemblyID assemblyId, HRESULT hrStatus) override;
    HRESULT STDMETHODCALLTYPE AssemblyUnloadStarted(AssemblyID assemblyId) override;
    HRESULT STDMETHODCALLTYPE AssemblyUnloadFinished(AssemblyID assemblyId, HRESULT hrStatus) override;
    HRESULT STDMETHODCALLTYPE ModuleLoadStarted(ModuleID moduleId) override;
    HRESULT STDMETHODCALLTYPE ModuleLoadFinished(ModuleID moduleId, HRESULT hrStatus) override;
    HRESULT STDMETHODCALLTYPE ModuleUnloadStarted(ModuleID moduleId) override;
    HRESULT STDMETHODCALLTYPE ModuleUnloadFinished(ModuleID moduleId, HRESULT hrStatus) override;
    HRESULT STDMETHODCALLTYPE ModuleAttachedToAssembly(ModuleID moduleId, AssemblyID AssemblyId) override;
    HRESULT STDMETHODCALLTYPE ClassLoadStarted(ClassID classId) override;
    HRESULT STDMETHODCALLTYPE ClassLoadFinished(ClassID classId, HRESULT hrStatus) override;
    HRESULT STDMETHODCALLTYPE ClassUnloadStarted(ClassID classId) override;
    HRESULT STDMETHODCALLTYPE ClassUnloadFinished(ClassID classId, HRESULT hrStatus) override;
    HRESULT STDMETHODCALLTYPE FunctionUnloadStarted(FunctionID functionId) override;
    HRESULT STDMETHODCALLTYPE JITCompilationStarted(FunctionID functionId, BOOL fIsSafeToBlock) override;
    HRESULT STDMETHODCALLTYPE JITCompilationFinished(FunctionID functionId, HRESULT hrStatus, BOOL fIsSafeToBlock) override;
    HRESULT STDMETHODCALLTYPE JITCachedFunctionSearchStarted(FunctionID functionId, BOOL* pbUseCachedFunction) override;
    HRESULT STDMETHODCALLTYPE JITCachedFunctionSearchFinished(FunctionID functionId, COR_PRF_JIT_CACHE result) override;
    HRESULT STDMETHODCALLTYPE JITFunctionPitched(FunctionID functionId) override;
    HRESULT STDMETHODCALLTYPE JITInlining(FunctionID callerId, FunctionID calleeId, BOOL* pfShouldInline) override;
    HRESULT STDMETHODCALLTYPE ThreadCreated(ThreadID threadId) override;
    HRESULT STDMETHODCALLTYPE ThreadDestroyed(ThreadID threadId) override;
    HRESULT STDMETHODCALLTYPE ThreadAssignedToOSThread(ThreadID managedThreadId, DWORD osThreadId) override;
    HRESULT STDMETHODCALLTYPE RemotingClientInvocationStarted() override;
    HRESULT STDMETHODCALLTYPE RemotingClientSendingMessage(GUID* pCookie, BOOL fIsAsync) override;
    HRESULT STDMETHODCALLTYPE RemotingClientReceivingReply(GUID* pCookie, BOOL fIsAsync) override;
    HRESULT STDMETHODCALLTYPE RemotingClientInvocationFinished() override;
    HRESULT STDMETHODCALLTYPE RemotingServerReceivingMessage(GUID* pCookie, BOOL fIsAsync) override;
    HRESULT STDMETHODCALLTYPE RemotingServerInvocationStarted() override;
    HRESULT STDMETHODCALLTYPE RemotingServerInvocationReturned() override;
    HRESULT STDMETHODCALLTYPE RemotingServerSendingReply(GUID* pCookie, BOOL fIsAsync) override;
    HRESULT STDMETHODCALLTYPE UnmanagedToManagedTransition(FunctionID functionId, COR_PRF_TRANSITION_REASON reason) override;
    HRESULT STDMETHODCALLTYPE ManagedToUnmanagedTransition(FunctionID functionId, COR_PRF_TRANSITION_REASON reason) override;
    HRESULT STDMETHODCALLTYPE RuntimeSuspendStarted(COR_PRF_SUSPEND_REASON suspendReason) override;
    HRESULT STDMETHODCALLTYPE RuntimeSuspendFinished() override;
    HRESULT STDMETHODCALLTYPE RuntimeSuspendAborted() override;
    HRESULT STDMETHODCALLTYPE RuntimeResumeStarted() override;
    HRESULT STDMETHODCALLTYPE RuntimeResumeFinished() override;
    HRESULT STDMETHODCALLTYPE RuntimeThreadSuspended(ThreadID threadId) override;
    HRESULT STDMETHODCALLTYPE RuntimeThreadResumed(ThreadID threadId) override;
    HRESULT STDMETHODCALLTYPE MovedReferences(ULONG cMovedObjectIDRanges, ObjectID oldObjectIDRangeStart[], ObjectID newObjectIDRangeStart[], ULONG cObjectIDRangeLength[]) override;
    HRESULT STDMETHODCALLTYPE ObjectAllocated(ObjectID objectId, ClassID classId) override;
    HRESULT STDMETHODCALLTYPE ObjectsAllocatedByClass(ULONG cClassCount, ClassID classIds[], ULONG cObjects[]) override;
    HRESULT STDMETHODCALLTYPE ObjectReferences(ObjectID objectId, ClassID classId, ULONG cObjectRefs, ObjectID objectRefIds[]) override;
    HRESULT STDMETHODCALLTYPE RootReferences(ULONG cRootRefs, ObjectID rootRefIds[]) override;
    HRESULT STDMETHODCALLTYPE ExceptionThrown(ObjectID thrownObjectId) override;
    HRESULT STDMETHODCALLTYPE ExceptionSearchFunctionEnter(FunctionID functionId) override;
    HRESULT STDMETHODCALLTYPE ExceptionSearchFunctionLeave() override;
    HRESULT STDMETHODCALLTYPE ExceptionSearchFilterEnter(FunctionID functionId) override;
    HRESULT STDMETHODCALLTYPE ExceptionSearchFilterLeave() override;
    HRESULT STDMETHODCALLTYPE ExceptionSearchCatcherFound(FunctionID functionId) override;
    HRESULT STDMETHODCALLTYPE ExceptionOSHandlerEnter(UINT_PTR __unused) override;
    HRESULT STDMETHODCALLTYPE ExceptionOSHandlerLeave(UINT_PTR __unused) override;
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFunctionEnter(FunctionID functionId) override;
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFunctionLeave() override;
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFinallyEnter(FunctionID functionId) override;
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFinallyLeave() override;
    HRESULT STDMETHODCALLTYPE ExceptionCatcherEnter(FunctionID functionId, ObjectID objectId) override;
    HRESULT STDMETHODCALLTYPE ExceptionCatcherLeave() override;
    HRESULT STDMETHODCALLTYPE COMClassicVTableCreated(ClassID wrappedClassId, REFGUID implementedIID, void* pVTable, ULONG cSlots) override;
    HRESULT STDMETHODCALLTYPE COMClassicVTableDestroyed(ClassID wrappedClassId, REFGUID implementedIID, void* pVTable) override;
    HRESULT STDMETHODCALLTYPE ExceptionCLRCatcherFound() override;
    HRESULT STDMETHODCALLTYPE ExceptionCLRCatcherExecute() override;
    HRESULT STDMETHODCALLTYPE ThreadNameChanged(ThreadID threadId, ULONG cchName, WCHAR name[]) override;
    HRESULT STDMETHODCALLTYPE GarbageCollectionStarted(int cGenerations, BOOL generationCollected[], COR_PRF_GC_REASON reason) override;
    HRESULT STDMETHODCALLTYPE SurvivingReferences(ULONG cSurvivingObjectIDRanges, ObjectID objectIDRangeStart[], ULONG cObjectIDRangeLength[]) override;
    HRESULT STDMETHODCALLTYPE GarbageCollectionFinished() override;
    HRESULT STDMETHODCALLTYPE FinalizeableObjectQueued(DWORD finalizerFlags, ObjectID objectID) override;
    HRESULT STDMETHODCALLTYPE RootReferences2(ULONG cRootRefs, ObjectID rootRefIds[], COR_PRF_GC_ROOT_KIND rootKinds[], COR_PRF_GC_ROOT_FLAGS rootFlags[], UINT_PTR rootIds[]) override;
    HRESULT STDMETHODCALLTYPE HandleCreated(GCHandleID handleId, ObjectID initialObjectId) override;
    HRESULT STDMETHODCALLTYPE HandleDestroyed(GCHandleID handleId) override;
    HRESULT STDMETHODCALLTYPE InitializeForAttach(IUnknown* pCorProfilerInfoUnk, void* pvClientData, UINT cbClientData) override;
    HRESULT STDMETHODCALLTYPE ProfilerAttachComplete() override;
    HRESULT STDMETHODCALLTYPE ProfilerDetachSucceeded() override;
    HRESULT STDMETHODCALLTYPE ReJITCompilationStarted(FunctionID functionId, ReJITID rejitId, BOOL fIsSafeToBlock) override;
    HRESULT STDMETHODCALLTYPE GetReJITParameters(ModuleID moduleId, mdMethodDef methodId, ICorProfilerFunctionControl* pFunctionControl) override;
    HRESULT STDMETHODCALLTYPE ReJITCompilationFinished(FunctionID functionId, ReJITID rejitId, HRESULT hrStatus, BOOL fIsSafeToBlock) override;
    HRESULT STDMETHODCALLTYPE ReJITError(ModuleID moduleId, mdMethodDef methodId, FunctionID functionId, HRESULT hrStatus) override;
    HRESULT STDMETHODCALLTYPE MovedReferences2(ULONG cMovedObjectIDRanges, ObjectID oldObjectIDRangeStart[], ObjectID newObjectIDRangeStart[], SIZE_T cObjectIDRangeLength[]) override;
    HRESULT STDMETHODCALLTYPE SurvivingReferences2(ULONG cSurvivingObjectIDRanges, ObjectID objectIDRangeStart[], SIZE_T cObjectIDRangeLength[]) override;
    HRESULT STDMETHODCALLTYPE ConditionalWeakTableElementReferences(ULONG cRootRefs, ObjectID keyRefIds[], ObjectID valueRefIds[], GCHandleID rootIds[]) override;
    HRESULT STDMETHODCALLTYPE GetAssemblyReferences(const WCHAR* wszAssemblyPath, ICorProfilerAssemblyReferenceProvider* pAsmRefProvider) override;
    HRESULT STDMETHODCALLTYPE ModuleInMemorySymbolsUpdated(ModuleID moduleId) override;
    HRESULT STDMETHODCALLTYPE DynamicMethodJITCompilationStarted(FunctionID functionId, BOOL fIsSafeToBlock, LPCBYTE ilHeader, ULONG cbILHeader) override;
    HRESULT STDMETHODCALLTYPE DynamicMethodJITCompilationFinished(FunctionID functionId, HRESULT hrStatus, BOOL fIsSafeToBlock) override;

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override
    {
        // IID_ICorProfilerCallback* come from corprof_i.cpp. Deliberately not using
        // __uuidof(): MinGW's -fms-extensions maps it to a __mingw_uuidof<T>() template
        // that needs an explicit per-type specialization we don't have for these
        // CoreCLR-defined interfaces (MSVC synthesizes them from DECLSPEC_UUID
        // automatically; MinGW does not).
        if (riid == IID_ICorProfilerCallback8 ||
            riid == IID_ICorProfilerCallback7 ||
            riid == IID_ICorProfilerCallback6 ||
            riid == IID_ICorProfilerCallback5 ||
            riid == IID_ICorProfilerCallback4 ||
            riid == IID_ICorProfilerCallback3 ||
            riid == IID_ICorProfilerCallback2 ||
            riid == IID_ICorProfilerCallback  ||
            riid == IID_IUnknown)
        {
            *ppvObject = this;
            this->AddRef();
            return S_OK;
        }

        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef(void) override
    {
        return std::atomic_fetch_add(&this->refCount, 1) + 1;
    }

    ULONG STDMETHODCALLTYPE Release(void) override
    {
        int count = std::atomic_fetch_sub(&this->refCount, 1) - 1;

        if (count <= 0)
        {
            delete this;
        }

        return count;
    }
};
