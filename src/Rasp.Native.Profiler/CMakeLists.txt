cmake_minimum_required(VERSION 3.20)
project(Rasp.Native.Profiler CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT WIN32)
    message(FATAL_ERROR "Rasp.Native.Profiler currently targets Windows only (see ADR-003).")
endif()

# Opt-in sanitizer instrumentation: `cmake -DRASP_ENABLE_SANITIZERS=ON`. Off by default -
# ASan changes the DLL's memory layout/ABI enough that it should never be what ships, only
# what's used to smoke-test changes to ILRewriter.cpp/RaspProfiler.cpp.
option(RASP_ENABLE_SANITIZERS "Build with AddressSanitizer/UndefinedBehaviorSanitizer instrumentation" OFF)

add_library(Rasp.Native.Profiler SHARED
    src/dllmain.cpp
    src/ClassFactory.cpp
    src/RaspProfiler.cpp
    src/ILRewriter.cpp
    inc/corprof_i.cpp
    src/RaspProfiler.def
)

target_include_directories(Rasp.Native.Profiler PRIVATE inc src)

target_compile_definitions(Rasp.Native.Profiler PRIVATE
    UNICODE
    _UNICODE
)

# -fms-extensions/-fpermissive are GCC/Clang flags needed for __uuidof()/DECLSPEC_UUID
# support (dev-machine verification used MinGW-w64/GCC). Under real MSVC (the CI
# toolchain, see .github/workflows/build.yml) neither flag applies or is understood by
# cl.exe - MS extensions are cl.exe's native behavior, no flag needed.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(Rasp.Native.Profiler PRIVATE -fms-extensions -fpermissive)
endif()

if(RASP_ENABLE_SANITIZERS)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        # NOTE: not verified to link on every MinGW-w64 distribution - the CLion-bundled
        # one used for dev-machine verification does not ship libasan/libubsan, so this
        # path currently only compiles, not links, there. Untested with a MinGW
        # distribution that does ship them (e.g. full MSYS2).
        target_compile_options(Rasp.Native.Profiler PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(Rasp.Native.Profiler PRIVATE -fsanitize=address,undefined)
    elseif(MSVC)
        # MSVC only supports ASan (no UBSan under cl.exe).
        target_compile_options(Rasp.Native.Profiler PRIVATE /fsanitize=address)
    endif()
endif()

# ole32/oleaut32/rpcrt4: base COM/RPC support. uuid: standard IID/CLSID constants (see the
# note in dllmain.cpp about relying on this instead of redefining them locally). wintrust:
# WinVerifyTrust, used to validate a chained profiler's Authenticode signature before
# LoadLibraryW (RaspProfiler.cpp, LoadChainedProfilerIfConfigured).
target_link_libraries(Rasp.Native.Profiler PRIVATE ole32 oleaut32 rpcrt4 uuid wintrust)
