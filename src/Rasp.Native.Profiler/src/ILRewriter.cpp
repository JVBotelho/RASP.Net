// Adapted from microsoft/clr-samples ProfilingAPI/ReJITEnterLeaveHooks (MIT License,
// Copyright (c) .NET Foundation and contributors).
// https://github.com/microsoft/clr-samples/tree/master/ProfilingAPI/ReJITEnterLeaveHooks
//
// The IL parsing/export core (ILInstr, ILRewriter::Import/Export) is unchanged from the
// original sample - it is generic bytecode plumbing, not tied to what the probe does.
// The probe-insertion logic at the bottom is rewritten: instead of AddEnterProbe/
// AddExitProbe calling a raw native function pointer via CEE_CALLI, RewritePropagationProbe
// emits a CEE_CALL against a managed mdMemberRef token, per ADR-006 addendum point 4.

#include "cor.h"
#include "corprof.h"
#include "ILRewriter.h"
// Only corhlpr.h is needed: COR_ILMETHOD_DECODER and friends are defined inline there.
// The .cpp counterpart pulls in utilcode.h (internal CoreCLR build infra we don't vendor
// and don't need - nothing this file calls lives there).
#include "corhlpr.h"
#include <cassert>
#include <stdexcept>

#undef IfFailRet
#define IfFailRet(EXPR) do { HRESULT hr = (EXPR); if(FAILED(hr)) { return (hr); } } while (0)

#undef IfNullRet
#define IfNullRet(EXPR) do { if ((EXPR) == NULL) return E_OUTOFMEMORY; } while (0)

struct ILInstr
{
    ILInstr *       m_pNext;
    ILInstr *       m_pPrev;

    unsigned        m_opcode;
    unsigned        m_offset;

    union
    {
        ILInstr *   m_pTarget;
        INT8        m_Arg8;
        INT16       m_Arg16;
        INT32       m_Arg32;
        INT64       m_Arg64;
    };
};

struct EHClause
{
    CorExceptionFlag            m_Flags;
    ILInstr *                   m_pTryBegin;
    ILInstr *                   m_pTryEnd;
    ILInstr *                   m_pHandlerBegin;
    ILInstr *                   m_pHandlerEnd;
    union
    {
        DWORD                   m_ClassToken;
        ILInstr *               m_pFilter;
    };
};

typedef enum
{
#define OPDEF(c,s,pop,push,args,type,l,s1,s2,ctrl) c,
#include "opcode.def"
#undef OPDEF
    CEE_COUNT,
    CEE_SWITCH_ARG,
} OPCODE;

#define OPCODEFLAGS_SizeMask        0x0F
#define OPCODEFLAGS_BranchTarget    0x10
#define OPCODEFLAGS_Switch          0x20

static const BYTE s_OpCodeFlags[] =
{
#define InlineNone           0
#define ShortInlineVar       1
#define InlineVar            2
#define ShortInlineI         1
#define InlineI              4
#define InlineI8             8
#define ShortInlineR         4
#define InlineR              8
#define ShortInlineBrTarget  1 | OPCODEFLAGS_BranchTarget
#define InlineBrTarget       4 | OPCODEFLAGS_BranchTarget
#define InlineMethod         4
#define InlineField          4
#define InlineType           4
#define InlineString         4
#define InlineSig            4
#define InlineRVA            4
#define InlineTok            4
#define InlineSwitch         0 | OPCODEFLAGS_Switch

#define OPDEF(c,s,pop,push,args,type,l,s1,s2,flow) args,
#include "opcode.def"
#undef OPDEF

#undef InlineNone
#undef ShortInlineVar
#undef InlineVar
#undef ShortInlineI
#undef InlineI
#undef InlineI8
#undef ShortInlineR
#undef InlineR
#undef ShortInlineBrTarget
#undef InlineBrTarget
#undef InlineMethod
#undef InlineField
#undef InlineType
#undef InlineString
#undef InlineSig
#undef InlineRVA
#undef InlineTok
#undef InlineSwitch
    0,                              // CEE_COUNT
    4 | OPCODEFLAGS_BranchTarget,   // CEE_SWITCH_ARG
};

static int k_rgnStackPushes[] = {

#define OPDEF(c,s,pop,push,args,type,l,s1,s2,ctrl) \
     push ,

#define Push0    0
#define Push1    1
#define PushI    1
#define PushI4   1
#define PushR4   1
#define PushI8   1
#define PushR8   1
#define PushRef  1
#define VarPush  1

#include "opcode.def"

#undef Push0
#undef Push1
#undef PushI
#undef PushI4
#undef PushR4
#undef PushI8
#undef PushR8
#undef PushRef
#undef VarPush
#undef OPDEF
    0,  // CEE_COUNT
    0   // CEE_SWITCH_ARG
};

class ILRewriter
{
private:
    ICorProfilerInfo * m_pICorProfilerInfo;
    ICorProfilerFunctionControl * m_pICorProfilerFunctionControl;

    ModuleID    m_moduleId;
    mdToken     m_tkMethod;

    mdToken     m_tkLocalVarSig;
    unsigned    m_maxStack;
    unsigned    m_flags;
    bool        m_fGenerateTinyHeader;

    ILInstr m_IL;

    unsigned    m_nEH;
    EHClause *  m_pEH;

    ILInstr **  m_pOffsetToInstr;
    unsigned    m_CodeSize;

    unsigned    m_nInstrs;

    BYTE *      m_pOutputBuffer;

    IMethodMalloc * m_pIMethodMalloc;

public:
    ILRewriter(ICorProfilerInfo * pICorProfilerInfo, ICorProfilerFunctionControl * pICorProfilerFunctionControl, ModuleID moduleID, mdToken tkMethod)
        : m_pICorProfilerInfo(pICorProfilerInfo), m_pICorProfilerFunctionControl(pICorProfilerFunctionControl),
        m_moduleId(moduleID), m_tkMethod(tkMethod), m_fGenerateTinyHeader(false),
        m_pEH(nullptr), m_pOffsetToInstr(nullptr), m_pOutputBuffer(nullptr), m_pIMethodMalloc(nullptr)
    {
        m_IL.m_pNext = &m_IL;
        m_IL.m_pPrev = &m_IL;

        m_nInstrs = 0;
    }

    ~ILRewriter()
    {
        ILInstr * p = m_IL.m_pNext;
        while (p != &m_IL)
        {
            ILInstr * t = p->m_pNext;
            delete p;
            p = t;
        }
        delete[] m_pEH;
        delete[] m_pOffsetToInstr;
        delete[] m_pOutputBuffer;

        if (m_pIMethodMalloc)
            m_pIMethodMalloc->Release();
    }

    // NOTE: deliberately does not use COR_ILMETHOD_DECODER. That class's constructor calls
    // DecoderInit/SectEH_EHClause, which are declared (not defined) in corhlpr.h and only
    // implemented deep in CoreCLR's internal utilcode - not part of the public profiling
    // API surface we vendor. COR_ILMETHOD_TINY/COR_ILMETHOD_FAT are fully inline in
    // corhlpr.h though, so we branch on the format byte ourselves and read through those
    // directly. v1 scope limitation: methods with extra IL sections (EH clauses) are
    // rejected rather than mis-parsed - acceptable because the only v1 instrumentation
    // target, System.String::Concat(string,string), has no try/catch in its body.
    HRESULT Import()
    {
        LPCBYTE pMethodBytes;

        IfFailRet(m_pICorProfilerInfo->GetILFunctionBody(
            m_moduleId, m_tkMethod, &pMethodBytes, NULL));

        COR_ILMETHOD* pMethod = (COR_ILMETHOD*)pMethodBytes;

        if (pMethod->Fat.IsFat())
        {
            m_tkLocalVarSig = pMethod->Fat.GetLocalVarSigTok();
            m_maxStack = pMethod->Fat.GetMaxStack();
            m_flags = (pMethod->Fat.GetFlags() & CorILMethod_InitLocals);
            m_CodeSize = pMethod->Fat.GetCodeSize();

            if (pMethod->Fat.More())
            {
                // Extra sections (EH clauses, etc.) - out of v1 scope, see note above.
                return E_NOTIMPL;
            }

            IfFailRet(ImportIL(pMethod->Fat.GetCode()));
        }
        else
        {
            m_tkLocalVarSig = mdTokenNil;
            m_maxStack = pMethod->Tiny.GetMaxStack();
            m_flags = 0;
            m_CodeSize = pMethod->Tiny.GetCodeSize();

            IfFailRet(ImportIL(pMethod->Tiny.GetCode()));
        }

        IfFailRet(ImportEH(nullptr, 0));

        return S_OK;
    }

    HRESULT ImportIL(LPCBYTE pIL)
    {
        m_pOffsetToInstr = new ILInstr*[m_CodeSize + 1];
        IfNullRet(m_pOffsetToInstr);

        ZeroMemory(m_pOffsetToInstr, m_CodeSize * sizeof(ILInstr*));

        m_pOffsetToInstr[m_CodeSize] = &m_IL;
        m_IL.m_opcode = -1;

        bool fBranch = false;
        unsigned offset = 0;
        while (offset < m_CodeSize)
        {
            unsigned startOffset = offset;
            unsigned opcode = pIL[offset++];

            if (opcode == CEE_PREFIX1)
            {
                if (offset >= m_CodeSize)
                {
                    assert(false);
                    return COR_E_INVALIDPROGRAM;
                }
                opcode = 0x100 + pIL[offset++];
            }

            if ((CEE_PREFIX7 <= opcode) && (opcode <= CEE_PREFIX2))
            {
                assert(false);
                return COR_E_INVALIDPROGRAM;
            }

            if (opcode >= CEE_COUNT)
            {
                assert(false);
                return COR_E_INVALIDPROGRAM;
            }

            BYTE flags = s_OpCodeFlags[opcode];

            int size = (flags & OPCODEFLAGS_SizeMask);
            if (offset + size > m_CodeSize)
            {
                assert(false);
                return COR_E_INVALIDPROGRAM;
            }

            ILInstr * pInstr = NewILInstr();
            IfNullRet(pInstr);

            pInstr->m_opcode = opcode;

            InsertBefore(&m_IL, pInstr);

            m_pOffsetToInstr[startOffset] = pInstr;

            switch (flags)
            {
            case 0:
                break;
            case 1:
                pInstr->m_Arg8 = *(UNALIGNED INT8 *)&(pIL[offset]);
                break;
            case 2:
                pInstr->m_Arg16 = *(UNALIGNED INT16 *)&(pIL[offset]);
                break;
            case 4:
                pInstr->m_Arg32 = *(UNALIGNED INT32 *)&(pIL[offset]);
                break;
            case 8:
                pInstr->m_Arg64 = *(UNALIGNED INT64 *)&(pIL[offset]);
                break;
            case 1 | OPCODEFLAGS_BranchTarget:
                pInstr->m_Arg32 = offset + 1 + *(UNALIGNED INT8 *)&(pIL[offset]);
                fBranch = true;
                break;
            case 4 | OPCODEFLAGS_BranchTarget:
                pInstr->m_Arg32 = offset + 4 + *(UNALIGNED INT32 *)&(pIL[offset]);
                fBranch = true;
                break;
            case 0 | OPCODEFLAGS_Switch:
            {
                if (offset + sizeof(INT32) > m_CodeSize)
                {
                    assert(false);
                    return COR_E_INVALIDPROGRAM;
                }

                unsigned nTargets = *(UNALIGNED INT32 *)&(pIL[offset]);
                pInstr->m_Arg32 = nTargets;
                offset += sizeof(INT32);

                unsigned base = offset + nTargets * sizeof(INT32);

                for (unsigned iTarget = 0; iTarget < nTargets; iTarget++)
                {
                    if (offset + sizeof(INT32) > m_CodeSize)
                    {
                        assert(false);
                        return COR_E_INVALIDPROGRAM;
                    }

                    pInstr = NewILInstr();
                    IfNullRet(pInstr);

                    pInstr->m_opcode = CEE_SWITCH_ARG;

                    pInstr->m_Arg32 = base + *(UNALIGNED INT32 *)&(pIL[offset]);
                    offset += sizeof(INT32);

                    InsertBefore(&m_IL, pInstr);
                }
                fBranch = true;
                break;
            }
            default:
                assert(false);
                break;
            }
            offset += size;
        }
        assert(offset == m_CodeSize);

        if (fBranch)
        {
            for (ILInstr * pInstr = m_IL.m_pNext; pInstr != &m_IL; pInstr = pInstr->m_pNext)
            {
                if (s_OpCodeFlags[pInstr->m_opcode] & OPCODEFLAGS_BranchTarget)
                    pInstr->m_pTarget = GetInstrFromOffset(pInstr->m_Arg32);
            }
        }

        return S_OK;
    }

    // v1 scope only ever calls this with (nullptr, 0) - Import() already rejects any
    // method with extra IL sections (EH clauses) before reaching here. Deliberately not
    // implementing the EH-clause-parsing path: it would call
    // COR_ILMETHOD_SECT_EH::EHClause(), whose inline body depends on the extern
    // SectEH_EHClause symbol (see the note on Import() above - not part of the header
    // set we vendor). Revisit if/when a v2 instrumentation target needs EH-bearing
    // methods.
    HRESULT ImportEH(const COR_ILMETHOD_SECT_EH* pILEH, unsigned nEH)
    {
        assert(m_pEH == NULL);
        assert(pILEH == nullptr && nEH == 0);

        m_nEH = 0;
        return S_OK;
    }

    ILInstr* NewILInstr()
    {
        m_nInstrs++;
        return new ILInstr();
    }

    ILInstr* GetInstrFromOffset(unsigned offset)
    {
        ILInstr * pInstr = NULL;

        if (offset <= m_CodeSize)
            pInstr = m_pOffsetToInstr[offset];

        assert(pInstr != NULL);
        return pInstr;
    }

    void InsertBefore(ILInstr * pWhere, ILInstr * pWhat)
    {
        pWhat->m_pNext = pWhere;
        pWhat->m_pPrev = pWhere->m_pPrev;

        pWhat->m_pNext->m_pPrev = pWhat;
        pWhat->m_pPrev->m_pNext = pWhat;

        AdjustState(pWhat);
    }

    void InsertAfter(ILInstr * pWhere, ILInstr * pWhat)
    {
        pWhat->m_pNext = pWhere->m_pNext;
        pWhat->m_pPrev = pWhere;

        pWhat->m_pNext->m_pPrev = pWhat;
        pWhat->m_pPrev->m_pNext = pWhat;

        AdjustState(pWhat);
    }

    void AdjustState(ILInstr * pNewInstr)
    {
        m_maxStack += k_rgnStackPushes[pNewInstr->m_opcode];
    }

    ILInstr * GetILList()
    {
        return &m_IL;
    }

    HRESULT Export()
    {
        unsigned maxSize = m_nInstrs * 10;

        m_pOutputBuffer = new BYTE[maxSize];
        IfNullRet(m_pOutputBuffer);

    again:
        BYTE * pIL = m_pOutputBuffer;

        bool fBranch = false;
        unsigned offset = 0;

        for (ILInstr * pInstr = m_IL.m_pNext; pInstr != &m_IL; pInstr = pInstr->m_pNext)
        {
            assert(offset < maxSize);
            pInstr->m_offset = offset;

            unsigned opcode = pInstr->m_opcode;
            if (opcode < CEE_COUNT)
            {
                if (opcode >= 0x100)
                    m_pOutputBuffer[offset++] = CEE_PREFIX1;

                m_pOutputBuffer[offset++] = (opcode & 0xFF);
            }

            BYTE flags = s_OpCodeFlags[pInstr->m_opcode];
            switch (flags)
            {
            case 0:
                break;
            case 1:
                *(UNALIGNED INT8 *)&(pIL[offset]) = pInstr->m_Arg8;
                break;
            case 2:
                *(UNALIGNED INT16 *)&(pIL[offset]) = pInstr->m_Arg16;
                break;
            case 4:
                *(UNALIGNED INT32 *)&(pIL[offset]) = pInstr->m_Arg32;
                break;
            case 8:
                *(UNALIGNED INT64 *)&(pIL[offset]) = pInstr->m_Arg64;
                break;
            case 1 | OPCODEFLAGS_BranchTarget:
                fBranch = true;
                break;
            case 4 | OPCODEFLAGS_BranchTarget:
                fBranch = true;
                break;
            case 0 | OPCODEFLAGS_Switch:
                *(UNALIGNED INT32 *)&(pIL[offset]) = pInstr->m_Arg32;
                offset += sizeof(INT32);
                break;
            default:
                assert(false);
                break;
            }
            offset += (flags & OPCODEFLAGS_SizeMask);
        }
        m_IL.m_offset = offset;

        if (fBranch)
        {
            bool fTryAgain = false;
            unsigned switchBase = 0;

            for (ILInstr * pInstr = m_IL.m_pNext; pInstr != &m_IL; pInstr = pInstr->m_pNext)
            {
                unsigned opcode = pInstr->m_opcode;

                if (pInstr->m_opcode == CEE_SWITCH)
                {
                    switchBase = pInstr->m_offset + 1 + sizeof(INT32) * (pInstr->m_Arg32 + 1);
                    continue;
                }
                if (opcode == CEE_SWITCH_ARG)
                {
                    *(UNALIGNED INT32 *)&(pIL[pInstr->m_offset]) = pInstr->m_pTarget->m_offset - switchBase;
                    continue;
                }

                BYTE flags = s_OpCodeFlags[pInstr->m_opcode];

                if (flags & OPCODEFLAGS_BranchTarget)
                {
                    int delta = pInstr->m_pTarget->m_offset - pInstr->m_pNext->m_offset;

                    switch (flags)
                    {
                    case 1 | OPCODEFLAGS_BranchTarget:
                        if ((INT8)delta != delta)
                        {
                            if (opcode == CEE_LEAVE_S)
                            {
                                pInstr->m_opcode = CEE_LEAVE;
                            }
                            else
                            {
                                assert(opcode >= CEE_BR_S && opcode <= CEE_BLT_UN_S);
                                pInstr->m_opcode = opcode - CEE_BR_S + CEE_BR;
                                assert(pInstr->m_opcode >= CEE_BR && pInstr->m_opcode <= CEE_BLT_UN);
                            }
                            fTryAgain = true;
                            continue;
                        }
                        *(UNALIGNED INT8 *)&(pIL[pInstr->m_pNext->m_offset - sizeof(INT8)]) = delta;
                        break;
                    case 4 | OPCODEFLAGS_BranchTarget:
                        *(UNALIGNED INT32 *)&(pIL[pInstr->m_pNext->m_offset - sizeof(INT32)]) = delta;
                        break;
                    default:
                        assert(false);
                        break;
                    }
                }
            }

            if (fTryAgain)
                goto again;
        }

        unsigned codeSize = offset;
        unsigned totalSize;
        LPBYTE pBody = NULL;
        if (m_fGenerateTinyHeader)
        {
            if (codeSize >= 64)
                return E_FAIL;

            totalSize = sizeof(IMAGE_COR_ILMETHOD_TINY) + codeSize;
            pBody = AllocateILMemory(totalSize);
            IfNullRet(pBody);

            BYTE * pCurrent = pBody;

            *pCurrent = (BYTE)(CorILMethod_TinyFormat | (codeSize << 2));
            pCurrent += sizeof(IMAGE_COR_ILMETHOD_TINY);

            CopyMemory(pCurrent, m_pOutputBuffer, codeSize);
        }
        else
        {
            unsigned alignedCodeSize = (offset + 3) & ~3;

            totalSize = sizeof(IMAGE_COR_ILMETHOD_FAT) + alignedCodeSize +
                (m_nEH ? (sizeof(IMAGE_COR_ILMETHOD_SECT_FAT) + sizeof(IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT) * m_nEH) : 0);

            pBody = AllocateILMemory(totalSize);
            IfNullRet(pBody);

            BYTE * pCurrent = pBody;

            IMAGE_COR_ILMETHOD_FAT *pHeader = (IMAGE_COR_ILMETHOD_FAT *)pCurrent;
            pHeader->Flags = m_flags | (m_nEH ? CorILMethod_MoreSects : 0) | CorILMethod_FatFormat;
            pHeader->Size = sizeof(IMAGE_COR_ILMETHOD_FAT) / sizeof(DWORD);
            pHeader->MaxStack = m_maxStack;
            pHeader->CodeSize = offset;
            pHeader->LocalVarSigTok = m_tkLocalVarSig;

            pCurrent = (BYTE*)(pHeader + 1);

            CopyMemory(pCurrent, m_pOutputBuffer, codeSize);
            pCurrent += alignedCodeSize;

            if (m_nEH != 0)
            {
                IMAGE_COR_ILMETHOD_SECT_FAT *pEH = (IMAGE_COR_ILMETHOD_SECT_FAT *)pCurrent;
                pEH->Kind = CorILMethod_Sect_EHTable | CorILMethod_Sect_FatFormat;
                pEH->DataSize = (unsigned)(sizeof(IMAGE_COR_ILMETHOD_SECT_FAT) + sizeof(IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT) * m_nEH);

                pCurrent = (BYTE*)(pEH + 1);

                for (unsigned iEH = 0; iEH < m_nEH; iEH++)
                {
                    EHClause *pSrc = &(m_pEH[iEH]);
                    IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT * pDst = (IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT *)pCurrent;

                    pDst->Flags = pSrc->m_Flags;
                    pDst->TryOffset = pSrc->m_pTryBegin->m_offset;
                    pDst->TryLength = pSrc->m_pTryEnd->m_offset - pSrc->m_pTryBegin->m_offset;
                    pDst->HandlerOffset = pSrc->m_pHandlerBegin->m_offset;
                    pDst->HandlerLength = pSrc->m_pHandlerEnd->m_pNext->m_offset - pSrc->m_pHandlerBegin->m_offset;
                    if ((pSrc->m_Flags & COR_ILEXCEPTION_CLAUSE_FILTER) == 0)
                        pDst->ClassToken = pSrc->m_ClassToken;
                    else
                        pDst->FilterOffset = pSrc->m_pFilter->m_offset;

                    pCurrent = (BYTE*)(pDst + 1);
                }
            }
        }

        IfFailRet(SetILFunctionBody(totalSize, pBody));
        DeallocateILMemory(pBody);

        return S_OK;
    }

    HRESULT SetILFunctionBody(unsigned size, LPBYTE pBody)
    {
        if (m_pICorProfilerFunctionControl != NULL)
        {
            IfFailRet(m_pICorProfilerFunctionControl->SetILFunctionBody(size, pBody));
        }
        else
        {
            IfFailRet(m_pICorProfilerInfo->SetILFunctionBody(m_moduleId, m_tkMethod, pBody));
        }

        return S_OK;
    }

    LPBYTE AllocateILMemory(unsigned size)
    {
        if (m_pICorProfilerFunctionControl != NULL)
        {
            return new BYTE[size];
        }

        if (FAILED(m_pICorProfilerInfo->GetILFunctionBodyAllocator(m_moduleId, &m_pIMethodMalloc)))
            return NULL;

        return (LPBYTE)m_pIMethodMalloc->Alloc(size);
    }

    void DeallocateILMemory(LPBYTE pBody)
    {
        if (m_pICorProfilerFunctionControl == NULL)
        {
            return;
        }

        delete[] pBody;
    }
};

// --- RASP-specific probe insertion (replaces the sample's calli-based Enter/Exit probes) ---

// Inserts, before a single RET instruction: dup ; ldarg.0..N-1 ; call <propagateTaintMemberRef>
// Leaves the original return value on the stack for the (untouched) `ret` that follows.
static HRESULT InsertPropagationCallBeforeRet(
    ILRewriter * pilr,
    mdMemberRef propagateTaintMemberRef,
    unsigned argCount,
    ILInstr * pRet)
{
    ILInstr * pNewInstr = pilr->NewILInstr();
    pNewInstr->m_opcode = CEE_DUP;
    pilr->InsertBefore(pRet, pNewInstr);

    for (unsigned i = 0; i < argCount; i++)
    {
        pNewInstr = pilr->NewILInstr();
        // ldarg.0 .. ldarg.3 have dedicated short opcodes; beyond that, use ldarg.s.
        if (i <= 3)
        {
            pNewInstr->m_opcode = CEE_LDARG_0 + i;
        }
        else
        {
            pNewInstr->m_opcode = CEE_LDARG_S;
            pNewInstr->m_Arg8 = (INT8)i;
        }
        pilr->InsertBefore(pRet, pNewInstr);
    }

    pNewInstr = pilr->NewILInstr();
    pNewInstr->m_opcode = CEE_CALL;
    pNewInstr->m_Arg32 = propagateTaintMemberRef;
    pilr->InsertBefore(pRet, pNewInstr);

    return S_OK;
}

// Finds every RET in the method and inserts a propagation probe before each, following the
// same "split RET into NOP+RET, insert epilog between them" technique as the original sample
// so that any branch/leave targeting the original RET still lands on our probe.
static HRESULT AddPropagationProbes(
    ILRewriter * pilr,
    mdMemberRef propagateTaintMemberRef,
    unsigned argCount)
{
    BOOL fAtLeastOneProbeAdded = FALSE;

    for (ILInstr * pInstr = pilr->GetILList()->m_pNext; pInstr != pilr->GetILList(); pInstr = pInstr->m_pNext)
    {
        if (pInstr->m_opcode != CEE_RET)
            continue;

        pInstr->m_opcode = CEE_NOP;

        ILInstr * pNewRet = pilr->NewILInstr();
        pNewRet->m_opcode = CEE_RET;
        pilr->InsertAfter(pInstr, pNewRet);

        HRESULT hr = InsertPropagationCallBeforeRet(pilr, propagateTaintMemberRef, argCount, pNewRet);
        if (FAILED(hr))
            return hr;

        fAtLeastOneProbeAdded = TRUE;
        pInstr = pNewRet;
    }

    if (!fAtLeastOneProbeAdded)
        return E_FAIL;

    return S_OK;
}

HRESULT RewritePropagationProbe(
    ICorProfilerInfo * pICorProfilerInfo,
    ModuleID moduleID,
    mdMethodDef methodDef,
    mdMemberRef propagateTaintMemberRef,
    unsigned argCount)
{
    // Classic-style (first-JIT) instrumentation: no ICorProfilerFunctionControl, so
    // ILRewriter::SetILFunctionBody falls back to ICorProfilerInfo::SetILFunctionBody.
    ILRewriter rewriter(pICorProfilerInfo, nullptr, moduleID, methodDef);

    IfFailRet(rewriter.Import());
    IfFailRet(AddPropagationProbes(&rewriter, propagateTaintMemberRef, argCount));
    IfFailRet(rewriter.Export());

    return S_OK;
}
