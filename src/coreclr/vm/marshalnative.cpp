// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
//
// File: MarshalNative.cpp
//

//
// FCall's for the PInvoke classlibs
//


#include "common.h"
#include "clsload.hpp"
#include "method.hpp"
#include "class.h"
#include "object.h"
#include "field.h"
#include "util.hpp"
#include "excep.h"
#include "siginfo.hpp"
#include "threads.h"
#include "stublink.h"
#include "dllimport.h"
#include "jitinterface.h"
#include "eeconfig.h"
#include "log.h"
#include "fieldmarshaler.h"
#include "cgensys.h"
#include "gcheaputilities.h"
#include "dbginterface.h"
#include "marshalnative.h"
#include "distributedidentity.h"
#include "fcall.h"
#include "dllimportcallback.h"
#include "comdelegate.h"
#include "typestring.h"
#include "appdomain.inl"
#include "stubhelpers.h"

#ifdef FEATURE_COMINTEROP
#include "comcallablewrapper.h"
#include "commtmemberinfomap.h"
#include "runtimecallablewrapper.h"
#include "olevariant.h"
#include "interoputil.h"
#endif // FEATURE_COMINTEROP

#ifdef FEATURE_JAVAMARSHAL
#include "interoplibinterface.h"
#endif // FEATURE_JAVAMARSHAL

#include <atomic>
#include <cstdint>

namespace
{
// Private DC-006 probe state. A single atomic word arbitrates native worker
// replies against closing the real EE-suspension window.
constexpr uint64_t GcProbePhaseMask = 0x3;
constexpr uint64_t GcProbePhaseClosed = 0;
constexpr uint64_t GcProbePhaseRequest = 1;
constexpr uint64_t GcProbePhaseReplied = 2;
constexpr uint64_t GcProbeMaximumEpoch = (UINT64_MAX >> 2);
constexpr uint32_t GcProbeCounterMask = 0x000fffff;


// Compile-time lock-free guarantees avoid a libatomic fallback in the worker/callback.
constexpr bool GcProbeAtomicsAreLockFree = ATOMIC_LONG_LOCK_FREE == 2 &&
    ATOMIC_LLONG_LOCK_FREE == 2 && ATOMIC_INT_LOCK_FREE == 2 && ATOMIC_BOOL_LOCK_FREE == 2;
std::atomic<uint64_t> s_gcProbeState{0};
std::atomic<uint64_t> s_gcProbeNextEpoch{0};
std::atomic<uint32_t> s_gcProbeWindows{0};
std::atomic<uint32_t> s_gcProbeReplies{0};
std::atomic<uint32_t> s_gcProbeMisses{0};
std::atomic<uint32_t> s_gcProbeFailures{0};
std::atomic<bool> s_gcProbeActive{false};
HANDLE s_gcProbeThread = INVALID_HANDLE_VALUE;
// The private fixture serializes Start/Stop on one managed controller thread.
// This state is intentionally not a general multi-controller lifecycle API.

constexpr uint64_t MakeGcProbeState(uint64_t epoch, uint64_t phase)
{
    return (epoch << 2) | phase;
}

constexpr uint64_t GetGcProbeEpoch(uint64_t state)
{
    return state >> 2;
}

constexpr uint64_t GetGcProbePhase(uint64_t state)
{
    return state & GcProbePhaseMask;
}

DWORD WINAPI DistributedRuntime_GcProgressProbeWorker(LPVOID)
{
    while (s_gcProbeActive.load(std::memory_order_acquire))
    {
        uint64_t state = s_gcProbeState.load(std::memory_order_acquire);
        if (GetGcProbePhase(state) == GcProbePhaseRequest)
        {
            uint64_t reply = MakeGcProbeState(GetGcProbeEpoch(state), GcProbePhaseReplied);
            if (s_gcProbeState.compare_exchange_weak(state, reply,
                    std::memory_order_acq_rel, std::memory_order_acquire))
            {
                s_gcProbeReplies.fetch_add(1, std::memory_order_relaxed);
            }
        }
        else
        {
            // Worker is bounded by the fixture's external watchdog and explicit stop.
            SwitchToThread();
        }
    }

    return 0;
}
} // namespace

extern "C" void DistributedRuntime_GcProbeAfterSuspendForTest()
{
    if (!s_gcProbeActive.load(std::memory_order_acquire))
        return;

    uint64_t epoch = s_gcProbeNextEpoch.fetch_add(1, std::memory_order_relaxed) + 1;
    if (epoch == 0 || epoch > GcProbeMaximumEpoch)
    {
        s_gcProbeFailures.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    uint64_t previous = s_gcProbeState.load(std::memory_order_acquire);
    if (GetGcProbePhase(previous) != GcProbePhaseClosed ||
        !s_gcProbeState.compare_exchange_strong(previous,
            MakeGcProbeState(epoch, GcProbePhaseRequest),
            std::memory_order_acq_rel, std::memory_order_acquire))
    {
        s_gcProbeFailures.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    s_gcProbeWindows.fetch_add(1, std::memory_order_relaxed);
}

extern "C" void DistributedRuntime_GcProbeBeforeResumeForTest()
{
    if (!s_gcProbeActive.load(std::memory_order_acquire))
        return;

    uint64_t previous = s_gcProbeState.load(std::memory_order_acquire);
    for (int attempt = 0; attempt < 2; attempt++)
    {
        if (GetGcProbePhase(previous) == GcProbePhaseClosed)
            return;
        uint64_t closed = MakeGcProbeState(GetGcProbeEpoch(previous), GcProbePhaseClosed);
        if (s_gcProbeState.compare_exchange_strong(previous, closed,
                std::memory_order_acq_rel, std::memory_order_acquire))
        {
            if (GetGcProbePhase(previous) == GcProbePhaseRequest)
                s_gcProbeMisses.fetch_add(1, std::memory_order_relaxed);
            else if (GetGcProbePhase(previous) != GcProbePhaseReplied)
                s_gcProbeFailures.fetch_add(1, std::memory_order_relaxed);
            return;
        }
    }

    s_gcProbeFailures.fetch_add(1, std::memory_order_relaxed);
}

#ifdef FEATURE_DISTRIBUTED_CONTROL
extern "C" int DistributedIdentityExportForTest(OBJECTREF root, BYTE* buffer, int capacity);
extern "C" int DistributedIdentityImportForTest(const BYTE* wire, int len, QCall::ObjectHandleOnStack result);
extern "C" INT32 QCALLTYPE DistributedRuntime_IdentityExportForTest(BYTE* buffer, INT32 capacity, QCall::ObjectHandleOnStack root)
{
    QCALL_CONTRACT;
    INT32 written = -1;
    BEGIN_QCALL;
    GCX_COOP();
    EX_TRY
    {
        written = DistributedIdentityExportForTest(root.Get(), buffer, capacity);
    }
    EX_CATCH
    {
        written = -1;
    }
    EX_END_CATCH
    END_QCALL;
    return written;
}
extern "C" INT32 QCALLTYPE DistributedRuntime_IdentityImportForTest(BYTE* wire, INT32 len, QCall::ObjectHandleOnStack result)
{
    QCALL_CONTRACT;
    INT32 status = -1;
    BEGIN_QCALL;
    GCX_COOP();
    EX_TRY
    {
        status = DistributedIdentityImportForTest(wire, len, result);
    }
    EX_CATCH
    {
        status = -1;
    }
    EX_END_CATCH
    END_QCALL;
    return status;
}
extern "C" int64_t DistributedControlNative(int command, int argument, unsigned char* buffer, int length);
extern "C" INT64 QCALLTYPE DistributedRuntime_ControlForTest(INT32 command, INT32 argument, BYTE* buffer, INT32 length)
{
    QCALL_CONTRACT;
    INT64 result = -1;
    BEGIN_QCALL;
    result = DistributedControlNative(command, argument, buffer, length);
    END_QCALL;
    return result;
}
#endif

extern "C" INT32 QCALLTYPE DistributedRuntime_StartGcProgressProbeForTest()
{
    QCALL_CONTRACT;
    INT32 result = 0;

    BEGIN_QCALL;
    if (!GcProbeAtomicsAreLockFree)
        result = 3;
    else if (s_gcProbeThread != INVALID_HANDLE_VALUE || s_gcProbeActive.load(std::memory_order_acquire))
    {
        result = 1;
    }
    else
    {
        s_gcProbeState.store(0, std::memory_order_relaxed);
        s_gcProbeNextEpoch.store(0, std::memory_order_relaxed);
        s_gcProbeWindows.store(0, std::memory_order_relaxed);
        s_gcProbeReplies.store(0, std::memory_order_relaxed);
        s_gcProbeMisses.store(0, std::memory_order_relaxed);
        s_gcProbeFailures.store(0, std::memory_order_relaxed);
        s_gcProbeActive.store(true, std::memory_order_release);
        s_gcProbeThread = Thread::CreateUtilityThread(Thread::StackSize_Small,
            DistributedRuntime_GcProgressProbeWorker, nullptr, W("DC006 GC progress probe"));
        if (s_gcProbeThread == INVALID_HANDLE_VALUE || s_gcProbeThread == nullptr)
        {
            s_gcProbeActive.store(false, std::memory_order_release);
            s_gcProbeThread = INVALID_HANDLE_VALUE;
            result = 2;
        }
    }
    END_QCALL;

    return result;
}

extern "C" UINT64 QCALLTYPE DistributedRuntime_StopGcProgressProbeForTest()
{
    QCALL_CONTRACT;
    UINT64 result = UINT64_C(1) << 63;

    BEGIN_QCALL;
    if (s_gcProbeThread != INVALID_HANDLE_VALUE && s_gcProbeActive.exchange(false, std::memory_order_acq_rel))
    {
        DWORD waitResult = WaitForSingleObject(s_gcProbeThread, 10000);
        if (waitResult == WAIT_OBJECT_0)
        {
            CloseHandle(s_gcProbeThread);
            s_gcProbeThread = INVALID_HANDLE_VALUE;
            UINT64 windows = s_gcProbeWindows.load(std::memory_order_acquire);
            UINT64 replies = s_gcProbeReplies.load(std::memory_order_acquire);
            UINT64 misses = s_gcProbeMisses.load(std::memory_order_acquire);
            UINT64 failures = s_gcProbeFailures.load(std::memory_order_acquire);
            uint64_t finalState = s_gcProbeState.load(std::memory_order_acquire);
            if (windows > GcProbeCounterMask || replies > GcProbeCounterMask || misses > GcProbeCounterMask ||
                failures != 0 || GetGcProbePhase(finalState) != GcProbePhaseClosed ||
                windows != replies + misses)
            {
                result = UINT64_C(1) << 63;
            }
            else
            {
                result = (windows << 40) | (misses << 20) | replies;
            }
        }
        // Timeout/failure leaves the handle owned and start permanently rejected;
        // the fixture process watchdog bounds cleanup. Never detach or restart.
    }
    END_QCALL;

    return result;
}

// Prelink
// Does advance loading of an PInvoke library
extern "C" VOID QCALLTYPE MarshalNative_Prelink(MethodDesc * pMD)
{
    QCALL_CONTRACT;

    // Arguments are check on managed side
    PRECONDITION(pMD != NULL);

    // If the code is already ready, we are done. Else, we need to execute the prestub
    // This is a perf thing since it's always safe to execute the prestub twice.
    if (!pMD->IsPointingToPrestub())
        return;

    // Silently ignore if not PInvoke and not runtime generated.
    if (!(pMD->IsPInvoke()) && !(pMD->IsRuntimeSupplied()))
        return;

    BEGIN_QCALL;

    pMD->CheckRestore();
    pMD->DoPrestub(NULL);

    END_QCALL;
}

// IsBuiltInComSupported
// Built-in COM support is only checked from the native side to ensure the runtime
// is in a consistent state
extern "C" BOOL QCALLTYPE MarshalNative_IsBuiltInComSupported()
{
    QCALL_CONTRACT;

    BOOL ret = TRUE;

    BEGIN_QCALL;

#ifdef FEATURE_COMINTEROP
    ret = g_pConfig->IsBuiltInCOMSupported();
#else // FEATURE_COMINTEROP
    ret = FALSE;
#endif // FEATURE_COMINTEROP

    END_QCALL;

    return ret;
}

extern "C" BOOL QCALLTYPE MarshalNative_TryGetStructMarshalStub(void* enregisteredTypeHandle, PCODE* pStructMarshalStub, SIZE_T* pSize)
{
    QCALL_CONTRACT;

    BOOL ret = FALSE;

    BEGIN_QCALL;

    TypeHandle th = TypeHandle::FromPtr(enregisteredTypeHandle);

    if (th.IsBlittable())
    {
        *pStructMarshalStub = (PCODE)NULL;
        *pSize = th.GetMethodTable()->GetNativeSize();
        ret = TRUE;
    }
    else if (th.HasLayout())
    {
        MethodTable* pMT = th.GetMethodTable();
        MethodDesc* structMarshalStub = NULL;

        EEMarshalingData* pEEMarshalingData = pMT->GetLoaderAllocator()->GetMarshalingDataIfAvailable();
        if (pEEMarshalingData != NULL)
        {
            GCX_COOP();
            structMarshalStub = pEEMarshalingData->LookupStructILStubSpeculative(pMT);
        }

        if (structMarshalStub == NULL)
        {
            structMarshalStub = PInvoke::CreateStructMarshalILStub(pMT);
        }

        *pStructMarshalStub = structMarshalStub->GetSingleCallableAddrOfCode();
        *pSize = 0;
        ret = TRUE;
    }
    else
    {
        *pStructMarshalStub = (PCODE)NULL;
        *pSize = 0;
    }

    END_QCALL;

    return ret;
}

/************************************************************************
 * PInvoke.SizeOf(Class)
 */
extern "C" INT32 QCALLTYPE MarshalNative_SizeOfHelper(QCall::TypeHandle t, BOOL throwIfNotMarshalable)
{
    QCALL_CONTRACT;

    INT32 rv = 0;

    BEGIN_QCALL;

    // refClass is validated to be non-NULL RuntimeType by callers
    TypeHandle th = t.AsTypeHandle();

    if (throwIfNotMarshalable && (!th.IsBlittable() || th.IsArray()))
    {
        // Determine if the type is marshalable
        if (!IsStructMarshalable(th))
        {
            // It isn't marshalable so throw an ArgumentException.
            StackSString strTypeName;
            TypeString::AppendType(strTypeName, th);
            COMPlusThrow(kArgumentException, IDS_CANNOT_MARSHAL, strTypeName.GetUnicode(), NULL, NULL);
        }
    }

    // The type is marshalable or we don't care so return its size.
    rv = th.GetMethodTable()->GetNativeSize();

    END_QCALL;
    return rv;
}

extern "C" SIZE_T QCALLTYPE MarshalNative_OffsetOf(FieldDesc* pFD)
{
    CONTRACTL
    {
        QCALL_CHECK;
        PRECONDITION(pFD != NULL);
    }
    CONTRACTL_END;

    SIZE_T offset = 0;

    BEGIN_QCALL;

    TypeHandle th = TypeHandle(pFD->GetApproxEnclosingMethodTable());

    if (th.IsBlittable())
    {
        offset = pFD->GetOffset();
    }
    else
    {
        // Verify the type can be marshalled.
        if (!IsStructMarshalable(th))
        {
            SString strTypeName;
            TypeString::AppendType(strTypeName, th);
            COMPlusThrow(kArgumentException, IDS_CANNOT_MARSHAL, strTypeName.GetUnicode(), NULL, NULL);
        }

        EEClassNativeLayoutInfo const* pNativeLayoutInfo = th.GetMethodTable()->GetNativeLayoutInfo();
        NativeFieldDescriptor const* pNFD = pNativeLayoutInfo->GetNativeFieldDescriptors();
        UINT numReferenceFields = pNativeLayoutInfo->GetNumFields();

        INDEBUG(bool foundField = false;)
        while (numReferenceFields--)
        {
            if (pNFD->GetFieldDesc() == pFD)
            {
                offset = pNFD->GetExternalOffset();
                INDEBUG(foundField = true);
                break;
            }
            pNFD++;
        }
        CONSISTENCY_CHECK_MSG(foundField, "We should never hit this point since we already verified that the requested field was present from managed code");
    }

    END_QCALL;

    return offset;
}

extern "C" void QCALLTYPE MarshalNative_GetDelegateForFunctionPointerInternal(PVOID FPtr, QCall::TypeHandle t, QCall::ObjectHandleOnStack retDelegate)
{
    QCALL_CONTRACT;

    BEGIN_QCALL;

    GCX_COOP();

    // Retrieve the method table from the RuntimeType. We already verified in managed
    // code that the type was a RuntimeType that represented a delegate.
    MethodTable* pMT = t.AsTypeHandle().AsMethodTable();
    OBJECTREF refDelegate = COMDelegate::ConvertToDelegate(FPtr, pMT);
    retDelegate.Set(refDelegate);

    END_QCALL;
}

extern "C" PVOID QCALLTYPE MarshalNative_GetFunctionPointerForDelegateInternal(QCall::ObjectHandleOnStack d)
{
    QCALL_CONTRACT;

    PVOID pFPtr = NULL;

    BEGIN_QCALL;

    GCX_COOP();
    pFPtr = COMDelegate::ConvertToCallback(d.Get());

    END_QCALL;

    return pFPtr;
}

#ifdef _DEBUG
namespace
{
    BOOL STDMETHODCALLTYPE IsInCooperativeGCMode()
    {
        return GetThread()->PreemptiveGCDisabled();
    }
}

extern "C" IsInCooperativeGCMode_fn QCALLTYPE MarshalNative_GetIsInCooperativeGCModeFunctionPointer()
{
    QCALL_CONTRACT;

    IsInCooperativeGCMode_fn ret = NULL;

    BEGIN_QCALL;

    ret = IsInCooperativeGCMode;

    END_QCALL;

    return ret;
}
#endif

/************************************************************************
 * Support for the last PInvoke error
 */
static thread_local int t_lastPInvokeError;

FCIMPL0(int, MarshalNative::GetLastPInvokeError)
{
    FCALL_CONTRACT;

    return t_lastPInvokeError;
}
FCIMPLEND

FCIMPL1(void, MarshalNative::SetLastPInvokeError, int error)
{
    FCALL_CONTRACT;

    t_lastPInvokeError = error;
}
FCIMPLEND

FCIMPL0(void, StubHelpers::SetLastError)
{
    // Make sure this is the first thing we do after returning from the target, as almost everything can cause the last error to get trashed
    DWORD lastError = ::GetLastError();

    FCALL_CONTRACT;

    t_lastPInvokeError = lastError;
}
FCIMPLEND

#ifdef FEATURE_IJW
// GetLastError override for C++/CLI
DWORD STDMETHODCALLTYPE FalseGetLastError()
{
    WRAPPER_NO_CONTRACT;

    return t_lastPInvokeError;
}
#endif // FEATURE_IJW

/************************************************************************
 * Support for the GCHandle class.
 */

extern "C" OBJECTHANDLE QCALLTYPE GCHandle_InternalAllocWithGCTransition(QCall::ObjectHandleOnStack obj, int type)
{
    QCALL_CONTRACT;

    OBJECTHANDLE hnd = NULL;

    BEGIN_QCALL;

    GCX_COOP();
    hnd = GetAppDomain()->CreateTypedHandle(obj.Get(), static_cast<HandleType>(type));

    END_QCALL;

    return hnd;
}

// Private M01 diagnostic. The returned address stays local and is never serialized.
extern "C" UINT_PTR QCALLTYPE DistributedRuntime_GetAddressForTest(QCall::ObjectHandleOnStack obj)
{
    QCALL_CONTRACT;

    UINT_PTR address = 0;
    BEGIN_QCALL;

    GCX_COOP();
    address = reinterpret_cast<UINT_PTR>(OBJECTREFToObject(obj.Get()));

    END_QCALL;

    return address;
}

FCIMPL2(LPVOID, MarshalNative::GCHandleInternalAlloc, Object *obj, int type)
{
    FCALL_CONTRACT;

    assert(type >= HNDTYPE_WEAK_SHORT && type <= HNDTYPE_DEPENDENT);

    if (CORProfilerTrackGC())
        return NULL;

    return GetAppDomain()->GetHandleStore()->CreateHandleOfType(obj, static_cast<HandleType>(type));
}
FCIMPLEND

extern "C" void QCALLTYPE GCHandle_InternalFreeWithGCTransition(OBJECTHANDLE handle)
{
    QCALL_CONTRACT;

    _ASSERTE(handle != NULL);

    BEGIN_QCALL;

    GCX_COOP();
    DestroyTypedHandle(handle);

    END_QCALL;
}

// Free a GC handle.
FCIMPL1(FC_BOOL_RET, MarshalNative::GCHandleInternalFree, OBJECTHANDLE handle)
{
    FCALL_CONTRACT;

    if (CORProfilerTrackGC())
        FC_RETURN_BOOL(false);

    GCHandleUtilities::GetGCHandleManager()->DestroyHandleOfUnknownType(handle);
    FC_RETURN_BOOL(true);
}
FCIMPLEND

// Get the object referenced by a GC handle.
FCIMPL1(LPVOID, MarshalNative::GCHandleInternalGet, OBJECTHANDLE handle)
{
    FCALL_CONTRACT;

    OBJECTREF objRef;

    objRef = ObjectFromHandle(handle);

    return *((LPVOID*)&objRef);
}
FCIMPLEND

#ifdef FEATURE_JAVAMARSHAL
// Get the object referenced by a GC handle, also waiting for bridge procesing to finish.
// Used by WeakReference
FCIMPL2(FC_BOOL_RET, MarshalNative::GCHandleInternalTryGetBridgeWait, OBJECTHANDLE handle, Object **pObjResult)
{
    FCALL_CONTRACT;

    if (Interop::IsGCBridgeActive())
    {
        FC_RETURN_BOOL(false);
    }

    *pObjResult = OBJECTREFToObject(ObjectFromHandle(handle));
    FC_RETURN_BOOL(true);
}
FCIMPLEND

// Unlike the fast call above, this can block
extern "C" void QCALLTYPE GCHandle_InternalGetBridgeWait(OBJECTHANDLE handle, QCall::ObjectHandleOnStack result)
{
    QCALL_CONTRACT;

    _ASSERTE(handle != NULL);

    BEGIN_QCALL;

    {
        GCX_COOP();

        Interop::WaitForGCBridgeFinish();
        // No GC can happen between the wait and obtaining of the reference, so the
        // bridge processing status can't change, guaranteeing the nulling of weak refs
        // took place in the bridge processing finish stage.
        result.Set(ObjectFromHandle(handle));
    }

    END_QCALL;
}
#endif // FEATURE_JAVAMARSHAL

// Update the object referenced by a GC handle.
FCIMPL2(VOID, MarshalNative::GCHandleInternalSet, OBJECTHANDLE handle, Object *obj)
{
    FCALL_CONTRACT;

    OBJECTREF objRef(obj);
    StoreObjectInHandle(handle, objRef);
}
FCIMPLEND

// Update the object referenced by a GC handle.
FCIMPL3(Object*, MarshalNative::GCHandleInternalCompareExchange, OBJECTHANDLE handle, Object *obj, Object* oldObj)
{
    FCALL_CONTRACT;

    OBJECTREF newObjref(obj);
    OBJECTREF oldObjref(oldObj);
    LPVOID ret = NULL;
    // Update the stored object reference.
    ret = InterlockedCompareExchangeObjectInHandle(handle, newObjref, oldObjref);
    return (Object*)ret;
}
FCIMPLEND

//====================================================================
// *** Interop Helpers ***
//====================================================================

extern "C" void QCALLTYPE MarshalNative_GetExceptionForHR(INT32 errorCode, LPVOID errorInfo, QCall::ObjectHandleOnStack retVal)
{
    CONTRACTL
    {
        QCALL_CHECK;
        PRECONDITION(FAILED(errorCode));
        PRECONDITION(CheckPointer(errorInfo, NULL_OK));
    }
    CONTRACTL_END;

    BEGIN_QCALL;

#ifdef FEATURE_COMINTEROP
    // Retrieve the IErrorInfo to use.
    IErrorInfo* pErrorInfo = (IErrorInfo*)errorInfo;
    if (pErrorInfo == (IErrorInfo*)(-1))
    {
        pErrorInfo = NULL;
    }
    else if (!pErrorInfo)
    {
        if (SafeGetErrorInfo(&pErrorInfo) != S_OK)
            pErrorInfo = NULL;
    }
#endif // FEATURE_COMINTEROP

    GCX_COOP();

    OBJECTREF exceptObj = NULL;
    GCPROTECT_BEGIN(exceptObj);
#ifdef FEATURE_COMINTEROP
    ::GetExceptionForHR(errorCode, pErrorInfo, &exceptObj);
#else
    ::GetExceptionForHR(errorCode, &exceptObj);
#endif // FEATURE_COMINTEROP
    retVal.Set(exceptObj);
    GCPROTECT_END();

    END_QCALL;
}

#ifdef FEATURE_COMINTEROP
extern "C" int32_t QCALLTYPE MarshalNative_GetHRForException(QCall::ObjectHandleOnStack obj)
{
    CONTRACTL
    {
        QCALL_CHECK;
        NOTHROW;    // Used by reverse COM IL stubs, so we must not throw exceptions back to COM
    }
    CONTRACTL_END;

    int32_t hr = E_FAIL;

    BEGIN_QCALL;

    GCX_COOP();

    hr = SetupErrorInfo(obj.Get());

    END_QCALL;

    return hr;
}

//====================================================================
// return the IUnknown* for an Object.
//====================================================================
extern "C" IUnknown* QCALLTYPE MarshalNative_GetIUnknownForObject(QCall::ObjectHandleOnStack o)
{
    QCALL_CONTRACT;

    IUnknown* retVal = NULL;

    BEGIN_QCALL;

    // Ensure COM is started up.
    EnsureComStarted();

    GCX_COOP();

    OBJECTREF oref = o.Get();
    GCPROTECT_BEGIN(oref);
    retVal = GetComIPFromObjectRef(&oref, ComIpType_OuterUnknown, NULL);
    GCPROTECT_END();

    END_QCALL;
    return retVal;
}

//====================================================================
// return the IDispatch* for an Object.
//====================================================================
extern "C" IDispatch* QCALLTYPE MarshalNative_GetIDispatchForObject(QCall::ObjectHandleOnStack o)
{
    QCALL_CONTRACT;

    IDispatch* retVal = NULL;

    BEGIN_QCALL;

    // Ensure COM is started up.
    EnsureComStarted();

    GCX_COOP();

    OBJECTREF oref = o.Get();
    GCPROTECT_BEGIN(oref);
    retVal = (IDispatch*)GetComIPFromObjectRef(&oref, ComIpType_Dispatch, NULL);
    GCPROTECT_END();

    END_QCALL;
    return retVal;
}

//====================================================================
// return the IUnknown* or IDispatch* for an Object.
//====================================================================
extern "C" void* QCALLTYPE MarshalNative_GetIUnknownOrIDispatchForObject(QCall::ObjectHandleOnStack o, BOOL* isIDispatch)
{
    QCALL_CONTRACT;

    void* retVal = NULL;

    BEGIN_QCALL;

    // Ensure COM is started up.
    EnsureComStarted();

    GCX_COOP();

    OBJECTREF oref = o.Get();
    GCPROTECT_BEGIN(oref);
    ComIpType fetchedIpType = ComIpType_None;
    retVal = GetComIPFromObjectRef(&oref, ComIpType_Both, &fetchedIpType);
    *isIDispatch = fetchedIpType == ComIpType_Dispatch;
    GCPROTECT_END();

    END_QCALL;
    return retVal;
}

//====================================================================
// return the IUnknown* representing the interface for the Object
// Object o should support Type T
//====================================================================
extern "C" IUnknown* QCALLTYPE MarshalNative_GetComInterfaceForObject(QCall::ObjectHandleOnStack o, QCall::TypeHandle t, BOOL bEnableCustomizedQueryInterface)
{
    QCALL_CONTRACT;

    IUnknown* retVal  = NULL;

    BEGIN_QCALL;

    // Ensure COM is started up.
    EnsureComStarted();

    GCX_COOP();

    OBJECTREF oref = o.Get();
    GCPROTECT_BEGIN(oref);

    TypeHandle th = t.AsTypeHandle();

    if (th.HasInstantiation())
        COMPlusThrowArgumentException(W("T"), W("Argument_NeedNonGenericType"));

    if (oref->GetMethodTable()->HasInstantiation())
        COMPlusThrowArgumentException(W("o"), W("Argument_NeedNonGenericObject"));

    // If the IID being asked for does not represent an interface then
    // throw an argument exception.
    if (!th.IsInterface())
        COMPlusThrowArgumentException(W("T"), W("Arg_MustBeInterface"));

    // If the interface being asked for is not visible from COM then
    // throw an argument exception.
    if (!::IsTypeVisibleFromCom(th))
        COMPlusThrowArgumentException(W("T"), W("Argument_TypeMustBeVisibleFromCom"));

    retVal = GetComIPFromObjectRef(&oref, th.GetMethodTable(), bEnableCustomizedQueryInterface);

    GCPROTECT_END();

    END_QCALL;

    return retVal;
}

//====================================================================
// return an Object for IUnknown
//====================================================================
extern "C" void QCALLTYPE MarshalNative_GetObjectForIUnknown(IUnknown* pUnk, QCall::ObjectHandleOnStack retObject)
{
    CONTRACTL
    {
        QCALL_CHECK;
        PRECONDITION(CheckPointer(pUnk));
    }
    CONTRACTL_END;

    BEGIN_QCALL;

    // Ensure COM is started up.
    EnsureComStarted();

    GCX_COOP();

    OBJECTREF oref = NULL;
    GCPROTECT_BEGIN(oref);
    GetObjectRefFromComIP(&oref, pUnk);
    retObject.Set(oref);
    GCPROTECT_END();

    END_QCALL;
}

extern "C" void QCALLTYPE MarshalNative_GetUniqueObjectForIUnknown(IUnknown* pUnk, QCall::ObjectHandleOnStack retObject)
{
    CONTRACTL
    {
        QCALL_CHECK;
        PRECONDITION(CheckPointer(pUnk));
    }
    CONTRACTL_END;

    BEGIN_QCALL;

    // Ensure COM is started up.
    EnsureComStarted();

    GCX_COOP();

    OBJECTREF oref = NULL;
    GCPROTECT_BEGIN(oref);
    GetObjectRefFromComIP(&oref, pUnk, NULL, ObjFromComIP::UNIQUE_OBJECT);
    retObject.Set(oref);
    GCPROTECT_END();

    END_QCALL;
}

//====================================================================
// return an Object for IUnknown, using the Type T,
//  NOTE:
//  Type T should be either a COM imported Type or a sub-type of COM imported Type
//====================================================================
extern "C" void QCALLTYPE MarshalNative_GetTypedObjectForIUnknown(IUnknown* pUnk, QCall::TypeHandle t, QCall::ObjectHandleOnStack retObject)
{
    CONTRACTL
    {
        QCALL_CHECK;
        PRECONDITION(CheckPointer(pUnk));
    }
    CONTRACTL_END;

    BEGIN_QCALL;

    TypeHandle th = t.AsTypeHandle();

    if (th.HasInstantiation())
        COMPlusThrowArgumentException(W("t"), W("Argument_NeedNonGenericType"));

    MethodTable* pMTClass = th.GetMethodTable();

    // Ensure COM is started up.
    EnsureComStarted();

    GCX_COOP();

    OBJECTREF oref = NULL;
    GCPROTECT_BEGIN(oref);
    GetObjectRefFromComIP(&oref, pUnk, pMTClass);
    retObject.Set(oref);
    GCPROTECT_END();

    END_QCALL;
}

extern "C" IUnknown* QCALLTYPE MarshalNative_CreateAggregatedObject(IUnknown* pOuter, QCall::ObjectHandleOnStack o)
{
    CONTRACTL
    {
        QCALL_CHECK;
        PRECONDITION(CheckPointer(pOuter));
    }
    CONTRACTL_END;

    IUnknown* pInner = NULL;

    BEGIN_QCALL;

    HRESULT hr = S_OK;

    // Ensure COM is started up.
    EnsureComStarted();

    GCX_COOP();

    OBJECTREF oref = o.Get();
    GCPROTECT_BEGIN(oref);

    if (NULL != ComCallWrapper::GetWrapperForObject(oref))
        COMPlusThrowArgumentException(W("o"), W("Argument_AlreadyACCW"));

    //get wrapper for the object, this could enable GC
    CCWHolder pWrap =  ComCallWrapper::InlineGetWrapper(&oref);

    // Aggregation support,
    pWrap->InitializeOuter(pOuter);
    IfFailThrow(pWrap->GetInnerUnknown((LPVOID*)&pInner));

    GCPROTECT_END();

    END_QCALL;

    return pInner;
}

//====================================================================
// Free unused RCWs in the current CLR context.
//====================================================================
extern "C" void QCALLTYPE MarshalNative_CleanupUnusedObjectsInCurrentContext()
{
    QCALL_CONTRACT;

    BEGIN_QCALL;

    if (g_pRCWCleanupList)
    {
        g_pRCWCleanupList->CleanupWrappersInCurrentCtxThread(
            TRUE,       // fWait
            TRUE,       // fManualCleanupRequested
            TRUE        // bIgnoreComObjectEagerCleanupSetting
            );
    }

    END_QCALL;
}

//====================================================================
// Checks whether there are RCWs from any context available for cleanup.
//====================================================================
FCIMPL0(FC_BOOL_RET, MarshalNative::AreComObjectsAvailableForCleanup)
{
    FCALL_CONTRACT;

    BOOL retVal = FALSE;
    if (g_pRCWCleanupList)
    {
        retVal = !g_pRCWCleanupList->IsEmpty();
    }

    FC_RETURN_BOOL(retVal);
}
FCIMPLEND

//====================================================================
// free the COM component and zombie this object if the ref count hits 0
// further usage of this Object might throw an exception,
//====================================================================
extern "C" INT32 QCALLTYPE MarshalNative_ReleaseComObject(QCall::ObjectHandleOnStack objUNSAFE)
{
    QCALL_CONTRACT;

    INT32 retVal = 0;

    BEGIN_QCALL;

    GCX_COOP();

    OBJECTREF obj = objUNSAFE.Get();
    GCPROTECT_BEGIN(obj);

    MethodTable* pMT = obj->GetMethodTable();
    _ASSERTE(pMT != NULL);
    if(!pMT->IsComObjectType())
        COMPlusThrow(kArgumentException, IDS_EE_SRC_OBJ_NOT_COMOBJECT);

    // remove the wrapper from the object
    retVal = RCW::ExternalRelease(&obj);

    GCPROTECT_END();

    END_QCALL;

    return retVal;
}

//====================================================================
// free the COM component and zombie this object
// further usage of this Object might throw an exception,
//====================================================================
extern "C" void QCALLTYPE MarshalNative_FinalReleaseComObject(QCall::ObjectHandleOnStack objUNSAFE)
{
    QCALL_CONTRACT;

    BEGIN_QCALL;

    GCX_COOP();

    OBJECTREF obj = objUNSAFE.Get();
    GCPROTECT_BEGIN(obj);

    MethodTable* pMT = obj->GetMethodTable();
    _ASSERTE(pMT != NULL);
    if(!pMT->IsComObjectType())
        COMPlusThrow(kArgumentException, IDS_EE_SRC_OBJ_NOT_COMOBJECT);

    // remove the wrapper from the object
    RCW::FinalExternalRelease(&obj);

    GCPROTECT_END();

    END_QCALL;
}

//====================================================================
// This method takes the given COM object and wraps it in an object
// of the specified type. The type must be derived from __ComObject.
//====================================================================
extern "C" void QCALLTYPE MarshalNative_InternalCreateWrapperOfType(QCall::ObjectHandleOnStack o, QCall::TypeHandle t, QCall::ObjectHandleOnStack retObject)
{
    QCALL_CONTRACT;

    BEGIN_QCALL;

    GCX_COOP();

    // Retrieve the class of the COM object.
    MethodTable *pObjMT = o.Get()->GetMethodTable();

    // Retrieve the method table for new wrapper type.
    MethodTable *pNewWrapMT = t.AsTypeHandle().GetMethodTable();

    // Validate that the destination type is a COM object.
    _ASSERTE(pNewWrapMT->IsComObjectType());

    // Start by checking if we can cast the obj to the wrapper type.
    if (TypeHandle(pObjMT).CanCastTo(TypeHandle(pNewWrapMT)))
    {
        retObject.Set(o.Get());
    }
    else
    {
        // Validate that the source object is a valid COM object.
        _ASSERTE(pObjMT->IsComObjectType());

        RCWHolder pRCW(GetThread());

        RCWPROTECT_BEGIN(pRCW, o.Get());

        // Make sure the COM object supports all the COM imported interfaces that the new
        // wrapper class implements.
        MethodTable::InterfaceMapIterator it = pNewWrapMT->IterateInterfaceMap();
        while (it.Next())
        {
            MethodTable *pItfMT = it.GetInterfaceApprox(); // ComImport interfaces cannot be generic
            if (pItfMT->IsComImport())
            {
                if (!Object::SupportsInterface(o.Get(), pItfMT))
                    COMPlusThrow(kInvalidCastException, IDS_EE_CANNOT_COERCE_COMOBJECT);
            }
        }

        // Create the duplicate wrapper object.
        {
            RCWHolder pNewRCW(GetThread());
            pRCW->CreateDuplicateWrapper(pNewWrapMT, &pNewRCW);

            retObject.Set(pNewRCW->GetExposedObject());
        }

        RCWPROTECT_END(pRCW);
    }

    END_QCALL;
}


//====================================================================
// check if the type is visible from COM.
//====================================================================
extern "C" BOOL QCALLTYPE MarshalNative_IsTypeVisibleFromCom(QCall::TypeHandle t)
{
    QCALL_CONTRACT;

    BOOL retVal = FALSE;

    BEGIN_QCALL;

    // Call the internal version of IsTypeVisibleFromCom.
    retVal = ::IsTypeVisibleFromCom(t.AsTypeHandle());

    END_QCALL;

    return retVal;
}

extern "C" void QCALLTYPE MarshalNative_GetNativeVariantForObject(QCall::ObjectHandleOnStack ObjUNSAFE, LPVOID pDestNativeVariant)
{
    CONTRACTL
    {
        QCALL_CHECK;
        PRECONDITION(CheckPointer(pDestNativeVariant));
    }
    CONTRACTL_END;

    BEGIN_QCALL;

    GCX_COOP();

    OBJECTREF Obj = ObjUNSAFE.Get();
    GCPROTECT_BEGIN(Obj);

    if (Obj == NULL)
    {
        // Will return empty variant in MarshalOleVariantForObject
    }
    else if (Obj->GetMethodTable()->HasInstantiation())
    {
        COMPlusThrowArgumentException(W("obj"), W("Argument_NeedNonGenericObject"));
    }

    // initialize the output variant
    SafeVariantInit((VARIANT*)pDestNativeVariant);
    OleVariant::MarshalOleVariantForObject(&Obj, (VARIANT*)pDestNativeVariant);

    GCPROTECT_END();

    END_QCALL;
}

extern "C" void QCALLTYPE MarshalNative_GetObjectForNativeVariant(LPVOID pSrcNativeVariant, QCall::ObjectHandleOnStack retObject)
{
    CONTRACTL
    {
        QCALL_CHECK;
        PRECONDITION(CheckPointer(pSrcNativeVariant));
    }
    CONTRACTL_END;

    BEGIN_QCALL;

    GCX_COOP();

    OBJECTREF Obj = NULL;
    GCPROTECT_BEGIN(Obj);
    OleVariant::MarshalObjectForOleVariant((VARIANT*)pSrcNativeVariant, &Obj);
    retObject.Set(Obj);
    GCPROTECT_END();

    END_QCALL;

}

extern "C" void QCALLTYPE MarshalNative_GetObjectsForNativeVariants(VARIANT* aSrcNativeVariant, int cVars, QCall::ObjectHandleOnStack retArray)
{
    CONTRACTL
    {
        QCALL_CHECK;
        PRECONDITION(CheckPointer(aSrcNativeVariant));
    }
    CONTRACTL_END;

    BEGIN_QCALL;

    GCX_COOP();

    struct {
        PTRARRAYREF Array;
        OBJECTREF Obj;
    } gc;
    gc.Array = NULL;
    gc.Obj = NULL;

    GCPROTECT_BEGIN(gc)

    // Allocate the array of objects.
    gc.Array = (PTRARRAYREF)AllocateObjectArray(cVars, g_pObjectClass);

    // Convert each VARIANT in the array into an object.
    for (int i = 0; i < cVars; i++)
    {
        OleVariant::MarshalObjectForOleVariant(&aSrcNativeVariant[i], &gc.Obj);
        gc.Array->SetAt(i, gc.Obj);
    }

    retArray.Set(gc.Array);

    GCPROTECT_END();

    END_QCALL;
}

//====================================================================
// Helper function used in the COM slot to method info mapping.
//====================================================================
static int GetComSlotInfo(MethodTable *pMT, MethodTable **ppDefItfMT)
{
    CONTRACTL
    {
        STANDARD_VM_CHECK;
        PRECONDITION(CheckPointer(pMT));
        PRECONDITION(CheckPointer(ppDefItfMT));
    }
    CONTRACTL_END;

    *ppDefItfMT = NULL;

    // If a class was passed in then retrieve the default interface.
    if (!pMT->IsInterface())
    {
        TypeHandle hndDefItfClass;
        DefaultInterfaceType DefItfType = GetDefaultInterfaceForClassWrapper(TypeHandle(pMT), &hndDefItfClass);

        if (DefItfType == DefaultInterfaceType_AutoDual || DefItfType == DefaultInterfaceType_Explicit)
        {
            pMT = hndDefItfClass.GetMethodTable();
            _ASSERTE(pMT != NULL);
        }
        else
        {
            // The default interface does not have any user defined methods.
            return -1;
        }
    }

    // Set the default interface class.
    *ppDefItfMT = pMT;

    if (pMT->IsInterface())
    {
        // Return the right number of slots depending on interface type.
        return ComMethodTable::GetNumExtraSlots(pMT->GetComInterfaceType());
    }
    else
    {
        // We are dealing with an IClassX which are always IDispatch based.
        return ComMethodTable::GetNumExtraSlots(ifDispatch);
    }
}

extern "C" INT32 QCALLTYPE MarshalNative_GetStartComSlot(QCall::TypeHandle t)
{
    QCALL_CONTRACT;

    int retVal = 0;

    BEGIN_QCALL;

    MethodTable *pMT = t.AsTypeHandle().GetMethodTable();
    if (NULL == pMT)
        COMPlusThrow(kArgumentNullException);

    // The service does not make any sense to be called for non COM visible types.
    if (!::IsTypeVisibleFromCom(TypeHandle(pMT)))
        COMPlusThrowArgumentException(W("t"), W("Argument_TypeMustBeVisibleFromCom"));

    retVal = GetComSlotInfo(pMT, &pMT);

    END_QCALL;

    return retVal;
}

extern "C" INT32 QCALLTYPE MarshalNative_GetEndComSlot(QCall::TypeHandle t)
{
    QCALL_CONTRACT;

    int retVal = 0;

    BEGIN_QCALL;

    int StartSlot = -1;

    MethodTable *pMT = t.AsTypeHandle().GetMethodTable();
    if (NULL == pMT)
        COMPlusThrow(kArgumentNullException);

    // The service does not make any sense to be called for non COM visible types.
    if (!::IsTypeVisibleFromCom(TypeHandle(pMT)))
        COMPlusThrowArgumentException(W("t"), W("Argument_TypeMustBeVisibleFromCom"));

    // Retrieve the start slot and the default interface class.
    StartSlot = GetComSlotInfo(pMT, &pMT);
    if (StartSlot == -1)
    {
        retVal = StartSlot;
    }
    else
    {
        // Retrieve the map of members.
        ComMTMemberInfoMap MemberMap(pMT);
        MemberMap.Init(sizeof(void*));

        // The end slot is the start slot plus the number of user defined methods.
        retVal = int(StartSlot + MemberMap.GetMethods().Size() - 1);
    }

    END_QCALL;

    return retVal;
}

extern "C" VOID QCALLTYPE MarshalNative_ChangeWrapperHandleStrength(QCall::ObjectHandleOnStack otp, BOOL fIsWeak)
{
    QCALL_CONTRACT;

    BEGIN_QCALL;

    GCX_COOP();

    if (!otp.Get()->GetMethodTable()->IsComImport())
    {
        OBJECTREF oref = otp.Get();
        GCPROTECT_BEGIN(oref);

        CCWHolder pWrap = ComCallWrapper::InlineGetWrapper(&oref);

        if (fIsWeak)
            pWrap->MarkHandleWeak();
        else
            pWrap->ResetHandleStrength();

        GCPROTECT_END();
    }

    END_QCALL;
}

extern "C" void QCALLTYPE MarshalNative_GetTypeFromCLSID(REFCLSID clsid, PCWSTR wszServer, QCall::ObjectHandleOnStack retType)
{
    QCALL_CONTRACT;

    BEGIN_QCALL;

    // Ensure COM is started up.
    EnsureComStarted();

    GCX_COOP();

    OBJECTREF orType = NULL;
    GCPROTECT_BEGIN(orType);
    GetComClassFromCLSID(clsid, wszServer, &orType);
    retType.Set(orType);
    GCPROTECT_END();

    END_QCALL;
}

#endif // FEATURE_COMINTEROP
