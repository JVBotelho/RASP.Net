// RASP.Net native CLR profiler (ADR-006 Phase C, v1 scope). See RaspProfiler.h for the
// design summary and provenance (adapted from microsoft/clr-samples, MIT licensed).

#include "RaspProfiler.h"
#include "CComPtr.h"
#include "ILRewriter.h"
#include "profiler_pal.h"
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <set>
#include <unordered_map>
#include <utility>
#include <mutex>
#include <string>
#include <softpub.h>
#include <wintrust.h>
#include <wincrypt.h>

// Local to this file (not corhlpr.h's IfFailRet, which expects a pre-existing `hr`
// variable in the caller's scope - a convention this file doesn't follow).
#define IfFailRet(EXPR) do { HRESULT _hr = (EXPR); if (FAILED(_hr)) { return _hr; } } while (0)

// Managed sensor coordinates. The AssemblyRef is version-agnostic (0.0.0.0) so it binds
// against whatever build of Rasp.Core.dll is already loaded in the target AppDomain,
// rather than requiring this native binary to be rebuilt whenever Rasp.Core's assembly
// version changes - but it IS pinned to Rasp.Core's public key token below. Resolving by
// simple name alone (no key) would let any assembly named "Rasp.Core" loaded earlier in
// the AppDomain intercept this call - see docs/ADR/006-sink-instrumentation-strategy.md
// addendum point 5.
static const WCHAR* kRaspCoreAssemblyName = L"Rasp.Core";
static const WCHAR* kRaspTaintSensorTypeName = L"Rasp.Core.Context.RaspTaintSensor";
static const WCHAR* kPropagateTaintMethodName = L"PropagateTaint";

// Public key TOKEN (not the full public key - afPublicKey flag is 0 in the
// DefineAssemblyRef call below, so this 8-byte buffer is interpreted as a token per
// corhdr.h's IsAfPublicKeyToken). Extracted from src/Rasp.Core/RaspCore.snk via
// `sn.exe -tp RaspCore.pub`. Must be regenerated here if that key is ever rotated.
static const BYTE kRaspCorePublicKeyToken[] = {
    0xD1, 0x0F, 0xA9, 0x70, 0x29, 0x9D, 0x49, 0xD5
};

// void PropagateTaint(string result, string arg0, string arg1)
static const COR_SIGNATURE kPropagateTaintSignature[] = {
    IMAGE_CEE_CS_CALLCONV_DEFAULT,
    0x03,                    // param count
    ELEMENT_TYPE_VOID,       // return type
    ELEMENT_TYPE_STRING,     // result
    ELEMENT_TYPE_STRING,     // arg0
    ELEMENT_TYPE_STRING,     // arg1
};

// Per-module cache so we only emit the AssemblyRef/TypeRef/MemberRef metadata once even if
// JITCompilationStarted fires for the target method more than once in the same module.
static std::mutex g_memberRefCacheMutex;
static std::unordered_map<ModuleID, mdMemberRef> g_memberRefCache;

// Tracks (ModuleID, mdMethodDef) pairs already rewritten. This profiler documents
// DOTNET_TieredCompilation=0 as a hard requirement (see docs/ADR/006-sink-instrumentation-strategy.md,
// addendum point 1) precisely because SetILFunctionBody is a "set it once" API: applying it a
// second time to a method that's already been rewritten stacks a second copy of the probe on
// top of the first, corrupting the method rather than throwing. The requirement was previously
// documented but never actually enforced or defended against - this set is the defense: if
// JITCompilationStarted somehow fires twice for the same method (the env var missing, a
// tiered-compilation edge case, anything), the second call is skipped and logged instead of
// silently double-rewriting.
static std::mutex g_rewrittenMethodsMutex;
static std::set<std::pair<ModuleID, mdMethodDef>> g_rewrittenMethods;

typedef HRESULT(STDMETHODCALLTYPE* DllGetClassObjectFn)(REFCLSID, REFIID, LPVOID*);

RaspProfiler::RaspProfiler() : refCount(0), corProfilerInfo(nullptr), chainedProfilerModule(nullptr), chainedProfiler(nullptr), requireCoreAuthenticode(false)
{
}

RaspProfiler::~RaspProfiler()
{
    if (this->chainedProfiler != nullptr)
    {
        this->chainedProfiler->Release();
        this->chainedProfiler = nullptr;
    }

    if (this->chainedProfilerModule != nullptr)
    {
        FreeLibrary(this->chainedProfilerModule);
        this->chainedProfilerModule = nullptr;
    }

    if (this->corProfilerInfo != nullptr)
    {
        this->corProfilerInfo->Release();
        this->corProfilerInfo = nullptr;
    }
}

// LoadLibraryW on an env-var-controlled path is a native-code-loading primitive, so two
// checks are required before any chained profiler loads:
//
// 1. The path must resolve inside this DLL's own installation directory (or a
//    subdirectory of it) - not an arbitrary absolute path. This assumes the install
//    directory itself is not writable by the application identity the profiled process
//    runs as; that assumption belongs to the deployment, not this code.
// 2. The file must carry a valid, chain-verified Authenticode signature (WinVerifyTrust,
//    WINTRUST_ACTION_GENERIC_VERIFY_V2) - "signed by *someone* with a trusted cert chain",
//    not pinned to one specific vendor, since we can't know in advance which APM/tracing
//    agent an operator might legitimately chain.
//
// Neither check replaces the deployment-level control (locking down who can write to the
// install directory / set these env vars); they're defense-in-depth on top of it.

// True if `candidatePath` (already an absolute, normalized path) is inside
// `trustedDirectory` (also absolute/normalized) or one of its subdirectories.
static bool IsPathInsideTrustedDirectory(const std::wstring& candidatePath, const std::wstring& trustedDirectory)
{
    if (candidatePath.size() <= trustedDirectory.size())
    {
        return false;
    }

    if (_wcsnicmp(candidatePath.c_str(), trustedDirectory.c_str(), trustedDirectory.size()) != 0)
    {
        return false;
    }

    // Boundary check so "C:\Rasp" doesn't match "C:\RaspEvilTwin\payload.dll".
    WCHAR boundaryChar = candidatePath[trustedDirectory.size()];
    return boundaryChar == L'\\' || boundaryChar == L'/';
}

// Returns this DLL's own installation directory (no trailing separator), or an empty
// string if it can't be determined - callers must treat an empty result as "trust
// nothing", never as "trust everything".
static std::wstring GetOwnModuleDirectory()
{
    HMODULE selfModule = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&GetOwnModuleDirectory),
            &selfModule))
    {
        return L"";
    }

    WCHAR selfPath[MAX_PATH];
    DWORD len = GetModuleFileNameW(selfModule, selfPath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
    {
        return L"";
    }

    std::wstring path(selfPath, len);
    size_t lastSep = path.find_last_of(L"\\/");
    if (lastSep == std::wstring::npos)
    {
        return L"";
    }

    return path.substr(0, lastSep);
}

// Verifies `filePath` carries a valid Authenticode signature with a trusted certificate
// chain, via the standard WinVerifyTrust pattern. Does not pin to a specific publisher -
// any validly-chained signature passes.
static bool HasValidAuthenticodeSignature(const WCHAR* filePath)
{
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath;

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.pFile = &fileInfo;

    LONG result = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &trustData);

    return result == ERROR_SUCCESS;
}

// OutputDebugStringW is deliberately minimal (no external logging sink exists this early
// in CLR startup) but makes a rejected/misconfigured chain target visible under a
// debugger/DebugView instead of failing completely silently.
static void LogChainFailure(const wchar_t* reason)
{
    std::wstring message = L"[Rasp.Native.Profiler] Chained profiler not loaded: ";
    message += reason;
    OutputDebugStringW(message.c_str());
}

void RaspProfiler::LoadChainedProfilerIfConfigured(IUnknown* pICorProfilerInfoUnk, const std::wstring& rawPath, DWORD requiredEventMask)
{
    if (rawPath.empty())
    {
        return; // Not configured - chaining is opt-in, no log needed.
    }

    WCHAR clsidBuf[64];
    DWORD clsidLen = GetEnvironmentVariableW(L"RASP_CHAINED_PROFILER_CLSID", clsidBuf, 64);
    if (clsidLen == 0 || clsidLen >= 64)
    {
        LogChainFailure(L"RASP_CHAINED_PROFILER_CLSID not set or too long");
        return;
    }

    CLSID chainedClsid;
    if (FAILED(CLSIDFromString(clsidBuf, &chainedClsid)))
    {
        LogChainFailure(L"RASP_CHAINED_PROFILER_CLSID is not a valid GUID string");
        return;
    }

    // Normalize to an absolute path before the trust checks below - a relative or
    // ..-laden path must not be able to escape the trusted directory boundary check.
    WCHAR normalizedPathBuf[MAX_PATH];
    DWORD normalizedLen = GetFullPathNameW(rawPath.c_str(), MAX_PATH, normalizedPathBuf, nullptr);
    if (normalizedLen == 0 || normalizedLen >= MAX_PATH)
    {
        LogChainFailure(L"RASP_CHAINED_PROFILER_PATH could not be normalized to an absolute path");
        return;
    }
    std::wstring normalizedPath(normalizedPathBuf, normalizedLen);

    std::wstring trustedDirectory = GetOwnModuleDirectory();
    if (trustedDirectory.empty() || !IsPathInsideTrustedDirectory(normalizedPath, trustedDirectory))
    {
        LogChainFailure(L"RASP_CHAINED_PROFILER_PATH is outside RASP's own installation directory - refusing to load");
        return;
    }

    if (!HasValidAuthenticodeSignature(normalizedPath.c_str()))
    {
        LogChainFailure(L"chain target failed Authenticode signature verification - refusing to load");
        return;
    }

    HMODULE module = LoadLibraryW(normalizedPath.c_str());
    if (module == nullptr)
    {
        LogChainFailure(L"LoadLibraryW failed for chain target");
        return;
    }

    auto getClassObject = reinterpret_cast<DllGetClassObjectFn>(GetProcAddress(module, "DllGetClassObject"));
    if (getClassObject == nullptr)
    {
        LogChainFailure(L"chain target does not export DllGetClassObject");
        FreeLibrary(module);
        return;
    }

    CComPtr<IClassFactory> classFactory;
    if (FAILED(getClassObject(chainedClsid, IID_IClassFactory, reinterpret_cast<LPVOID*>(&classFactory))))
    {
        LogChainFailure(L"DllGetClassObject failed for the configured CLSID");
        FreeLibrary(module);
        return;
    }

    ICorProfilerCallback2* chained = nullptr;
    if (FAILED(classFactory->CreateInstance(nullptr, IID_ICorProfilerCallback2, reinterpret_cast<void**>(&chained))))
    {
        LogChainFailure(L"chain target does not implement ICorProfilerCallback2");
        FreeLibrary(module);
        return; // Chained profiler doesn't implement even the common ICorProfilerCallback2 baseline.
    }

    if (FAILED(chained->Initialize(pICorProfilerInfoUnk)))
    {
        LogChainFailure(L"chain target's own Initialize() rejected the profiling session");
        chained->Release();
        FreeLibrary(module);
        return;
    }

    // The chained profiler almost certainly just called SetEventMask itself inside its own
    // Initialize() above - ICorProfilerInfo::SetEventMask replaces the process-wide mask
    // rather than merging with it, so whatever RASP set earlier in its own Initialize() may
    // already be gone. Re-assert the bits RASP's own instrumentation requires by OR-ing them
    // into whatever the chained profiler left behind, rather than blindly overwriting its
    // choices either.
    DWORD currentMask = 0;
    if (SUCCEEDED(this->corProfilerInfo->GetEventMask(&currentMask)))
    {
        DWORD mergedMask = currentMask | requiredEventMask;
        if (mergedMask != currentMask)
        {
            this->corProfilerInfo->SetEventMask(mergedMask);
        }
    }

    this->chainedProfilerModule = module;
    this->chainedProfiler = chained;
    OutputDebugStringW(L"[Rasp.Native.Profiler] Chained profiler loaded and initialized successfully.");
}

HRESULT STDMETHODCALLTYPE RaspProfiler::Initialize(IUnknown *pICorProfilerInfoUnk)
{
    HRESULT queryInterfaceResult = pICorProfilerInfoUnk->QueryInterface(IID_ICorProfilerInfo8, reinterpret_cast<void **>(&this->corProfilerInfo));

    if (FAILED(queryInterfaceResult))
    {
        return E_FAIL;
    }

    // COR_PRF_MONITOR_JIT_COMPILATION: the only event category v1 needs - IL rewrite
    // happens on first JIT of the (single, curated) target method.
    // COR_PRF_DISABLE_INLINING: prevents String.Concat(string,string) from being inlined
    // into its many BCL/app callers before we get a chance to rewrite it. Without this,
    // an already-inlined call site would silently bypass the probe.
    // COR_PRF_DISABLE_ALL_NGEN_IMAGES: forces JIT (not precompiled R2R/NGen code) for
    // instrumented modules so JITCompilationStarted actually fires for our target.
    //
    // Tracked separately from the chaining-forwarding superset below: these are the bits
    // RASP's own instrumentation cannot function without, so they're what gets re-asserted
    // after a chained profiler's own SetEventMask call (see LoadChainedProfilerIfConfigured).
    // The forwarding-superset bits exist only to give a downstream profiler more events via
    // RASP's own forwarding; losing those to a downstream's own SetEventMask is a coverage
    // gap for the downstream, not a functional break for RASP, so they're not re-asserted.
    DWORD requiredEventMask = COR_PRF_MONITOR_JIT_COMPILATION |
                               COR_PRF_DISABLE_INLINING |
                               COR_PRF_DISABLE_ALL_NGEN_IMAGES;
    DWORD eventMask = requiredEventMask;

    // RASP_CHAINED_PROFILER_PATH is read exactly once here (not re-read later in
    // LoadChainedProfilerIfConfigured) so the event-mask decision and the actual load
    // attempt can never observe two different values of the same env var.
    WCHAR chainedPathBuf[MAX_PATH];
    DWORD chainedPathLen = GetEnvironmentVariableW(L"RASP_CHAINED_PROFILER_PATH", chainedPathBuf, MAX_PATH);
    // GetEnvironmentVariableW returns the REQUIRED buffer size (>= MAX_PATH), not the actual
    // value, when the variable is set but too long for the buffer - distinguish that from
    // "not set" (0) so a too-long path fails loudly instead of being silently treated as
    // unconfigured (LoadChainedProfilerIfConfigured's empty-path check logs nothing, since an
    // empty path from an actually-unset var is the normal, expected, opt-in-not-taken case).
    if (chainedPathLen >= MAX_PATH)
    {
        LogChainFailure(L"RASP_CHAINED_PROFILER_PATH exceeds MAX_PATH - refusing to chain");
    }
    bool chainingRequested = chainedPathLen > 0 && chainedPathLen < MAX_PATH;
    std::wstring chainedPath = chainingRequested ? std::wstring(chainedPathBuf, chainedPathLen) : L"";

    // Off by default: no release build is Authenticode-signed yet (see
    // docs/ADR/006-sink-instrumentation-strategy.md addendum point 5), so requiring it
    // unconditionally would make every dev/CI run log a false alarm. Opt in once a signed
    // Rasp.Core.dll exists.
    WCHAR requireAuthenticodeBuf[8];
    DWORD requireAuthenticodeLen = GetEnvironmentVariableW(L"RASP_REQUIRE_CORE_AUTHENTICODE", requireAuthenticodeBuf, 8);
    this->requireCoreAuthenticode = requireAuthenticodeLen > 0 && requireAuthenticodeLen < 8 &&
        (wcscmp(requireAuthenticodeBuf, L"1") == 0 || _wcsicmp(requireAuthenticodeBuf, L"true") == 0);

    // Chaining note: only ONE profiler is ever actually registered with the CLR - RASP is
    // that profiler when RASP_CHAINED_PROFILER_PATH is set, and the downstream profiler's
    // callbacks only fire because we forward them ourselves (see ForwardXxx calls below).
    // We can't intercept the downstream's own SetEventMask call to compute a precise
    // union, so instead we OR in a conservative superset covering the lifecycle events
    // most APM/tracing profilers need. This is best-effort, not exact: a downstream
    // profiler requiring an event category outside this superset (e.g. GC or exception
    // callbacks) will not receive it in v1.
    if (chainingRequested)
    {
        eventMask |= COR_PRF_MONITOR_APPDOMAIN_LOADS |
                     COR_PRF_MONITOR_ASSEMBLY_LOADS   |
                     COR_PRF_MONITOR_MODULE_LOADS     |
                     COR_PRF_MONITOR_CLASS_LOADS      |
                     COR_PRF_MONITOR_THREADS;
    }

    // ModuleLoadFinished (where CheckCoreAuthenticodeIfRaspCoreModule runs) only fires at
    // all when COR_PRF_MONITOR_MODULE_LOADS is in the mask - independent of the chaining
    // superset above, which is conditioned on a different env var. Part of requiredEventMask
    // (not just eventMask): losing module-load monitoring to a chained profiler's own
    // SetEventMask would silently disable the Authenticode check, the same class of bug as
    // losing JIT-compilation monitoring would.
    if (this->requireCoreAuthenticode)
    {
        requiredEventMask |= COR_PRF_MONITOR_MODULE_LOADS;
        eventMask |= COR_PRF_MONITOR_MODULE_LOADS;
    }

    HRESULT hr = this->corProfilerInfo->SetEventMask(eventMask);
    if (FAILED(hr))
    {
        return hr;
    }

    // This profiler assumes DOTNET_TieredCompilation=0 is set on the target process. See
    // docs/ADR/006-sink-instrumentation-strategy.md, addendum point 1: without it,
    // JITCompilationStarted fires more than once per method (tier 0, then tier 1/OSR).
    // g_rewrittenMethods (see DoJITCompilationStarted) already makes a second rewrite a
    // no-op rather than a corrupt double-probe, but a misconfigured host silently loses
    // taint tracking on any method that gets re-JITted after the first rewrite - that's
    // worth surfacing loudly rather than only in a source comment, since nothing else
    // would tell an operator why propagation went quiet partway through a process's life.
    WCHAR tieredCompilationBuf[8];
    DWORD tieredCompilationLen = GetEnvironmentVariableW(L"DOTNET_TieredCompilation", tieredCompilationBuf, 8);
    bool tieredCompilationDisabled = tieredCompilationLen > 0 && tieredCompilationLen < 8 &&
        wcscmp(tieredCompilationBuf, L"0") == 0;
    if (!tieredCompilationDisabled)
    {
        OutputDebugStringW(L"[Rasp.Native.Profiler] WARNING: DOTNET_TieredCompilation is not set to "
            L"0. Re-JITted methods will silently skip taint re-propagation (idempotent by design, "
            L"not a crash) - taint tracking coverage will degrade over the process lifetime. Set "
            L"DOTNET_TieredCompilation=0.");
    }

    this->LoadChainedProfilerIfConfigured(pICorProfilerInfoUnk, chainedPath, requiredEventMask);

    return S_OK;
}

HRESULT STDMETHODCALLTYPE RaspProfiler::Shutdown()
{
    if (this->chainedProfiler != nullptr)
    {
        this->chainedProfiler->Shutdown();
        this->chainedProfiler->Release();
        this->chainedProfiler = nullptr;
    }

    if (this->chainedProfilerModule != nullptr)
    {
        FreeLibrary(this->chainedProfilerModule);
        this->chainedProfilerModule = nullptr;
    }

    if (this->corProfilerInfo != nullptr)
    {
        this->corProfilerInfo->Release();
        this->corProfilerInfo = nullptr;
    }

    return S_OK;
}

bool RaspProfiler::IsV1PropagationTarget(ModuleID moduleId, mdMethodDef methodDef, IMetaDataImport* pMetaDataImport)
{
    mdTypeDef classToken;
    WCHAR methodName[256];
    ULONG methodNameLen = 0;
    PCCOR_SIGNATURE pSig = nullptr;
    ULONG cbSig = 0;

    HRESULT hr = pMetaDataImport->GetMethodProps(
        methodDef, &classToken, methodName, 256, &methodNameLen,
        nullptr, &pSig, &cbSig, nullptr, nullptr);

    if (FAILED(hr))
        return false;

    if (wcscmp(methodName, L"Concat") != 0)
        return false;

    WCHAR typeName[256];
    ULONG typeNameLen = 0;
    DWORD typeFlags = 0;
    mdToken extends = 0;

    hr = pMetaDataImport->GetTypeDefProps(classToken, typeName, 256, &typeNameLen, &typeFlags, &extends);
    if (FAILED(hr))
        return false;

    if (wcscmp(typeName, L"System.String") != 0)
        return false;

    // Match the exact 2-string-argument overload only: DEFAULT calling convention,
    // 2 params, string return, string param x2.
    if (cbSig < 5)
        return false;

    return pSig[0] == IMAGE_CEE_CS_CALLCONV_DEFAULT &&
           pSig[1] == 0x02 &&
           pSig[2] == ELEMENT_TYPE_STRING &&
           pSig[3] == ELEMENT_TYPE_STRING &&
           pSig[4] == ELEMENT_TYPE_STRING;
}

HRESULT RaspProfiler::ResolvePropagateTaintMemberRef(ModuleID moduleId, mdMemberRef* pMemberRef)
{
    {
        std::lock_guard<std::mutex> lock(g_memberRefCacheMutex);
        auto it = g_memberRefCache.find(moduleId);
        if (it != g_memberRefCache.end())
        {
            *pMemberRef = it->second;
            return S_OK;
        }
    }

    CComPtr<IMetaDataEmit> metadataEmit;
    IfFailRet(this->corProfilerInfo->GetModuleMetaData(
        moduleId, ofRead | ofWrite, IID_IMetaDataEmit, reinterpret_cast<IUnknown**>(&metadataEmit)));

    CComPtr<IMetaDataAssemblyEmit> assemblyEmit;
    IfFailRet(metadataEmit->QueryInterface(IID_IMetaDataAssemblyEmit, reinterpret_cast<void**>(&assemblyEmit)));

    ASSEMBLYMETADATA assemblyMetadata = {};
    assemblyMetadata.usMajorVersion = 0;
    assemblyMetadata.usMinorVersion = 0;
    assemblyMetadata.usBuildNumber = 0;
    assemblyMetadata.usRevisionNumber = 0;

    mdAssemblyRef assemblyRef;
    IfFailRet(assemblyEmit->DefineAssemblyRef(
        kRaspCorePublicKeyToken, sizeof(kRaspCorePublicKeyToken),
        kRaspCoreAssemblyName,
        &assemblyMetadata,
        nullptr, 0,                    // no hash
        0,                             // afPublicKey not set: pbPublicKeyOrToken above is
                                        // the TOKEN, not the full key (see corhdr.h
                                        // IsAfPublicKeyToken) - CLR requires the resolved
                                        // assembly's actual public key to hash to this
                                        // token, closing the call-hijack gap a nameonly/
                                        // wildcard-version reference would leave open.
        &assemblyRef));

    mdTypeRef typeRef;
    IfFailRet(metadataEmit->DefineTypeRefByName(assemblyRef, kRaspTaintSensorTypeName, &typeRef));

    mdMemberRef memberRef;
    IfFailRet(metadataEmit->DefineMemberRef(
        typeRef,
        kPropagateTaintMethodName,
        kPropagateTaintSignature,
        sizeof(kPropagateTaintSignature),
        &memberRef));

    {
        std::lock_guard<std::mutex> lock(g_memberRefCacheMutex);
        g_memberRefCache[moduleId] = memberRef;
    }

    *pMemberRef = memberRef;
    return S_OK;
}

// Detective, not preventive: JITCompilationStarted for String.Concat - the point where the
// public-key-token-pinned AssemblyRef actually gets exercised - routinely fires *before*
// Rasp.Core.dll itself has loaded (Concat is called all over the BCL well before an app's
// own reference to Rasp.Core resolves), so there is no correct place to gate the IL rewrite
// on this check without silently skipping instrumentation in the common case. The CLR's own
// loader is what actually refuses to bind that AssemblyRef to an assembly with the wrong
// public key token - that enforcement is unconditional and already in effect. What this can
// add: once the module satisfying the AssemblyRef has actually loaded, verify it also
// carries a valid Authenticode signature, and log loudly if it doesn't - a second,
// independent signal about whatever is actually running under that name once it's loaded.
void RaspProfiler::CheckCoreAuthenticodeIfRaspCoreModule(ModuleID moduleId)
{
    WCHAR modulePath[MAX_PATH];
    ULONG pathLen = 0;
    LPCBYTE baseLoadAddress = nullptr;
    AssemblyID assemblyId = 0;

    HRESULT hr = this->corProfilerInfo->GetModuleInfo(
        moduleId, &baseLoadAddress, MAX_PATH, &pathLen, modulePath, &assemblyId);
    if (FAILED(hr) || pathLen == 0)
    {
        return;
    }

    // pathLen includes the null terminator on success; trim it before scanning for the
    // filename so std::wstring::find_last_of doesn't include an embedded NUL.
    std::wstring path(modulePath, pathLen > 0 ? pathLen - 1 : 0);
    size_t lastSep = path.find_last_of(L"\\/");
    std::wstring fileName = (lastSep == std::wstring::npos) ? path : path.substr(lastSep + 1);

    if (_wcsicmp(fileName.c_str(), L"Rasp.Core.dll") != 0)
    {
        return; // Not the module we care about.
    }

    if (!HasValidAuthenticodeSignature(path.c_str()))
    {
        std::wstring message =
            L"[Rasp.Native.Profiler] Rasp.Core.dll loaded from '";
        message += path;
        message += L"' does not carry a valid Authenticode signature. "
                    L"The public-key-token pin (kRaspCorePublicKeyToken) still applies and "
                    L"is enforced by the CLR loader independently of this check.";
        OutputDebugStringW(message.c_str());
    }
}

HRESULT STDMETHODCALLTYPE RaspProfiler::JITCompilationStarted(FunctionID functionId, BOOL fIsSafeToBlock)
{
    HRESULT hr = this->DoJITCompilationStarted(functionId, fIsSafeToBlock);

    // Forwarded regardless of RASP's own outcome above - a downstream tracer's interest in
    // this event (e.g. to record a span) is independent of whether this happened to be our
    // curated propagation target.
    if (this->chainedProfiler != nullptr)
    {
        this->chainedProfiler->JITCompilationStarted(functionId, fIsSafeToBlock);
    }

    return hr;
}

HRESULT RaspProfiler::DoJITCompilationStarted(FunctionID functionId, BOOL fIsSafeToBlock)
{
    HRESULT hr;
    mdToken token;
    ClassID classId;
    ModuleID moduleId;

    IfFailRet(this->corProfilerInfo->GetFunctionInfo(functionId, &classId, &moduleId, &token));

    CComPtr<IMetaDataImport> metadataImport;
    IfFailRet(this->corProfilerInfo->GetModuleMetaData(moduleId, ofRead | ofWrite, IID_IMetaDataImport, reinterpret_cast<IUnknown **>(&metadataImport)));

    if (!IsV1PropagationTarget(moduleId, token, metadataImport))
    {
        // Not our curated v1 target - leave every other method's IL untouched.
        return S_OK;
    }

    {
        std::lock_guard<std::mutex> lock(g_rewrittenMethodsMutex);
        auto insertResult = g_rewrittenMethods.emplace(moduleId, token);
        if (!insertResult.second)
        {
            // Already rewritten - JITCompilationStarted fired again for this exact method
            // (tiered compilation still enabled despite the documented requirement, an OSR
            // recompile, or something else entirely). SetILFunctionBody is not idempotent;
            // applying it again would stack a second probe on top of the first. Skip, don't
            // silently corrupt, and say so loudly since this means the deployment is missing
            // DOTNET_TieredCompilation=0.
            OutputDebugStringW(L"[Rasp.Native.Profiler] JITCompilationStarted fired again for an "
                L"already-rewritten method - skipping re-rewrite. This means DOTNET_TieredCompilation=0 "
                L"is not set on this process; see docs/ADR/006-sink-instrumentation-strategy.md addendum point 1.");
            return S_OK;
        }
    }

    mdMemberRef propagateTaintMemberRef;
    IfFailRet(ResolvePropagateTaintMemberRef(moduleId, &propagateTaintMemberRef));

    // System.String::Concat(string, string) takes 2 arguments; the probe reloads both via
    // ldarg.0/ldarg.1 alongside the duplicated return value.
    return RewritePropagationProbe(this->corProfilerInfo, moduleId, token, propagateTaintMemberRef, 2);
}

HRESULT STDMETHODCALLTYPE RaspProfiler::JITCompilationFinished(FunctionID functionId, HRESULT hrStatus, BOOL fIsSafeToBlock)
{
    if (this->chainedProfiler != nullptr) this->chainedProfiler->JITCompilationFinished(functionId, hrStatus, fIsSafeToBlock);
    return S_OK;
}
HRESULT STDMETHODCALLTYPE RaspProfiler::JITCachedFunctionSearchStarted(FunctionID functionId, BOOL *pbUseCachedFunction) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::JITCachedFunctionSearchFinished(FunctionID functionId, COR_PRF_JIT_CACHE result) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::JITFunctionPitched(FunctionID functionId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::JITInlining(FunctionID callerId, FunctionID calleeId, BOOL *pfShouldInline) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::AppDomainCreationStarted(AppDomainID appDomainId)
{
    if (this->chainedProfiler != nullptr) this->chainedProfiler->AppDomainCreationStarted(appDomainId);
    return S_OK;
}
HRESULT STDMETHODCALLTYPE RaspProfiler::AppDomainCreationFinished(AppDomainID appDomainId, HRESULT hrStatus)
{
    if (this->chainedProfiler != nullptr) this->chainedProfiler->AppDomainCreationFinished(appDomainId, hrStatus);
    return S_OK;
}
HRESULT STDMETHODCALLTYPE RaspProfiler::AppDomainShutdownStarted(AppDomainID appDomainId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::AppDomainShutdownFinished(AppDomainID appDomainId, HRESULT hrStatus) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::AssemblyLoadStarted(AssemblyID assemblyId)
{
    if (this->chainedProfiler != nullptr) this->chainedProfiler->AssemblyLoadStarted(assemblyId);
    return S_OK;
}
HRESULT STDMETHODCALLTYPE RaspProfiler::AssemblyLoadFinished(AssemblyID assemblyId, HRESULT hrStatus)
{
    if (this->chainedProfiler != nullptr) this->chainedProfiler->AssemblyLoadFinished(assemblyId, hrStatus);
    return S_OK;
}
HRESULT STDMETHODCALLTYPE RaspProfiler::AssemblyUnloadStarted(AssemblyID assemblyId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::AssemblyUnloadFinished(AssemblyID assemblyId, HRESULT hrStatus) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ModuleLoadStarted(ModuleID moduleId)
{
    if (this->chainedProfiler != nullptr) this->chainedProfiler->ModuleLoadStarted(moduleId);
    return S_OK;
}
HRESULT STDMETHODCALLTYPE RaspProfiler::ModuleLoadFinished(ModuleID moduleId, HRESULT hrStatus)
{
    if (this->requireCoreAuthenticode && SUCCEEDED(hrStatus))
    {
        this->CheckCoreAuthenticodeIfRaspCoreModule(moduleId);
    }

    if (this->chainedProfiler != nullptr) this->chainedProfiler->ModuleLoadFinished(moduleId, hrStatus);
    return S_OK;
}
HRESULT STDMETHODCALLTYPE RaspProfiler::ModuleUnloadStarted(ModuleID moduleId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ModuleUnloadFinished(ModuleID moduleId, HRESULT hrStatus) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ModuleAttachedToAssembly(ModuleID moduleId, AssemblyID AssemblyId)
{
    if (this->chainedProfiler != nullptr) this->chainedProfiler->ModuleAttachedToAssembly(moduleId, AssemblyId);
    return S_OK;
}
HRESULT STDMETHODCALLTYPE RaspProfiler::ClassLoadStarted(ClassID classId)
{
    if (this->chainedProfiler != nullptr) this->chainedProfiler->ClassLoadStarted(classId);
    return S_OK;
}
HRESULT STDMETHODCALLTYPE RaspProfiler::ClassLoadFinished(ClassID classId, HRESULT hrStatus)
{
    if (this->chainedProfiler != nullptr) this->chainedProfiler->ClassLoadFinished(classId, hrStatus);
    return S_OK;
}
HRESULT STDMETHODCALLTYPE RaspProfiler::ClassUnloadStarted(ClassID classId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ClassUnloadFinished(ClassID classId, HRESULT hrStatus) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::FunctionUnloadStarted(FunctionID functionId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ThreadCreated(ThreadID threadId)
{
    if (this->chainedProfiler != nullptr) this->chainedProfiler->ThreadCreated(threadId);
    return S_OK;
}
HRESULT STDMETHODCALLTYPE RaspProfiler::ThreadDestroyed(ThreadID threadId)
{
    if (this->chainedProfiler != nullptr) this->chainedProfiler->ThreadDestroyed(threadId);
    return S_OK;
}
HRESULT STDMETHODCALLTYPE RaspProfiler::ThreadAssignedToOSThread(ThreadID managedThreadId, DWORD osThreadId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RemotingClientInvocationStarted() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RemotingClientSendingMessage(GUID *pCookie, BOOL fIsAsync) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RemotingClientReceivingReply(GUID *pCookie, BOOL fIsAsync) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RemotingClientInvocationFinished() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RemotingServerReceivingMessage(GUID *pCookie, BOOL fIsAsync) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RemotingServerInvocationStarted() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RemotingServerInvocationReturned() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RemotingServerSendingReply(GUID *pCookie, BOOL fIsAsync) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::UnmanagedToManagedTransition(FunctionID functionId, COR_PRF_TRANSITION_REASON reason) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ManagedToUnmanagedTransition(FunctionID functionId, COR_PRF_TRANSITION_REASON reason) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RuntimeSuspendStarted(COR_PRF_SUSPEND_REASON suspendReason) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RuntimeSuspendFinished() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RuntimeSuspendAborted() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RuntimeResumeStarted() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RuntimeResumeFinished() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RuntimeThreadSuspended(ThreadID threadId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RuntimeThreadResumed(ThreadID threadId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::MovedReferences(ULONG cMovedObjectIDRanges, ObjectID oldObjectIDRangeStart[], ObjectID newObjectIDRangeStart[], ULONG cObjectIDRangeLength[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ObjectAllocated(ObjectID objectId, ClassID classId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ObjectsAllocatedByClass(ULONG cClassCount, ClassID classIds[], ULONG cObjects[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ObjectReferences(ObjectID objectId, ClassID classId, ULONG cObjectRefs, ObjectID objectRefIds[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RootReferences(ULONG cRootRefs, ObjectID rootRefIds[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionThrown(ObjectID thrownObjectId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionSearchFunctionEnter(FunctionID functionId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionSearchFunctionLeave() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionSearchFilterEnter(FunctionID functionId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionSearchFilterLeave() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionSearchCatcherFound(FunctionID functionId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionOSHandlerEnter(UINT_PTR __unused) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionOSHandlerLeave(UINT_PTR __unused) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionUnwindFunctionEnter(FunctionID functionId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionUnwindFunctionLeave() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionUnwindFinallyEnter(FunctionID functionId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionUnwindFinallyLeave() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionCatcherEnter(FunctionID functionId, ObjectID objectId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionCatcherLeave() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::COMClassicVTableCreated(ClassID wrappedClassId, REFGUID implementedIID, void *pVTable, ULONG cSlots) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::COMClassicVTableDestroyed(ClassID wrappedClassId, REFGUID implementedIID, void *pVTable) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionCLRCatcherFound() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ExceptionCLRCatcherExecute() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ThreadNameChanged(ThreadID threadId, ULONG cchName, WCHAR name[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::GarbageCollectionStarted(int cGenerations, BOOL generationCollected[], COR_PRF_GC_REASON reason) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::SurvivingReferences(ULONG cSurvivingObjectIDRanges, ObjectID objectIDRangeStart[], ULONG cObjectIDRangeLength[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::GarbageCollectionFinished() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::FinalizeableObjectQueued(DWORD finalizerFlags, ObjectID objectID) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::RootReferences2(ULONG cRootRefs, ObjectID rootRefIds[], COR_PRF_GC_ROOT_KIND rootKinds[], COR_PRF_GC_ROOT_FLAGS rootFlags[], UINT_PTR rootIds[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::HandleCreated(GCHandleID handleId, ObjectID initialObjectId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::HandleDestroyed(GCHandleID handleId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::InitializeForAttach(IUnknown *pCorProfilerInfoUnk, void *pvClientData, UINT cbClientData) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ProfilerAttachComplete() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ProfilerDetachSucceeded() { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ReJITCompilationStarted(FunctionID functionId, ReJITID rejitId, BOOL fIsSafeToBlock) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::GetReJITParameters(ModuleID moduleId, mdMethodDef methodId, ICorProfilerFunctionControl *pFunctionControl) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ReJITCompilationFinished(FunctionID functionId, ReJITID rejitId, HRESULT hrStatus, BOOL fIsSafeToBlock) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ReJITError(ModuleID moduleId, mdMethodDef methodId, FunctionID functionId, HRESULT hrStatus) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::MovedReferences2(ULONG cMovedObjectIDRanges, ObjectID oldObjectIDRangeStart[], ObjectID newObjectIDRangeStart[], SIZE_T cObjectIDRangeLength[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::SurvivingReferences2(ULONG cSurvivingObjectIDRanges, ObjectID objectIDRangeStart[], SIZE_T cObjectIDRangeLength[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ConditionalWeakTableElementReferences(ULONG cRootRefs, ObjectID keyRefIds[], ObjectID valueRefIds[], GCHandleID rootIds[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::GetAssemblyReferences(const WCHAR *wszAssemblyPath, ICorProfilerAssemblyReferenceProvider *pAsmRefProvider) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::ModuleInMemorySymbolsUpdated(ModuleID moduleId) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::DynamicMethodJITCompilationStarted(FunctionID functionId, BOOL fIsSafeToBlock, LPCBYTE ilHeader, ULONG cbILHeader) { return S_OK; }
HRESULT STDMETHODCALLTYPE RaspProfiler::DynamicMethodJITCompilationFinished(FunctionID functionId, HRESULT hrStatus, BOOL fIsSafeToBlock) { return S_OK; }
