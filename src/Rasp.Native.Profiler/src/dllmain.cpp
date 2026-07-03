// Adapted from microsoft/clr-samples ProfilingAPI/ReJITEnterLeaveHooks (MIT License,
// Copyright (c) .NET Foundation and contributors). CLSID replaced with one generated for
// this project; class instantiated is ClassFactory -> RaspProfiler.
//
// NOTE: the original sample redefined IID_IUnknown/IID_IClassFactory as local `const IID`
// globals here. Removed: <unknwn.h> (transitively included via ClassFactory.h) already
// declares `extern "C" const IID IID_IUnknown;` / `IID_IClassFactory;`, backed by
// -luuid (Uuid.lib) in CMakeLists.txt. Under MinGW's -fms-extensions, a file-scope `const`
// unexpectedly gets external linkage, so the sample's redefinitions happened to satisfy
// every other translation unit's reference by accident instead of linking against -luuid
// as intended - which would fail to link under standard MSVC, where top-level `const`
// has internal linkage by default (ISO C++ rules).

#include "ClassFactory.h"

// {9c80f47f-0a8f-4f39-8205-4c605c739df7} - CLSID for RaspProfiler. Must match the value
// used when setting CORECLR_PROFILER on the target process.
const GUID CLSID_RaspProfiler = { 0x9c80f47f, 0x0a8f, 0x4f39, { 0x82, 0x05, 0x4c, 0x60, 0x5c, 0x73, 0x9d, 0xf7 } };

BOOL STDMETHODCALLTYPE DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    return TRUE;
}

extern "C" HRESULT STDMETHODCALLTYPE DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    if (ppv == nullptr || rclsid != CLSID_RaspProfiler)
    {
        return E_FAIL;
    }

    auto factory = new ClassFactory;
    if (factory == nullptr)
    {
        return E_FAIL;
    }

    return factory->QueryInterface(riid, ppv);
}

extern "C" HRESULT STDMETHODCALLTYPE DllCanUnloadNow()
{
    return S_OK;
}
