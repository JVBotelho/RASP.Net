// Adapted from microsoft/clr-samples ProfilingAPI/ReJITEnterLeaveHooks (MIT License,
// Copyright (c) .NET Foundation and contributors). Unchanged except for the class it
// instantiates (RaspProfiler instead of the sample's CorProfiler).

#pragma once

#include "unknwn.h"
#include <atomic>

class ClassFactory : public IClassFactory
{
private:
    std::atomic<int> refCount;
public:
    ClassFactory();
    virtual ~ClassFactory();
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override;
    ULONG   STDMETHODCALLTYPE AddRef(void) override;
    ULONG   STDMETHODCALLTYPE Release(void) override;
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown *pUnkOuter, REFIID riid, void **ppvObject) override;
    HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock) override;
};
