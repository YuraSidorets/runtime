// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#include "common.h"
#include "assembly.hpp"
#include "ceeload.h"
#include "memberload.h"
#include "comdelegate.h"
#include "gchelpers.h"
#include "callhelpers.h"
#include "distributedthread.h"
#include "distributedapplicationactionadmission.h"
#include "distributedaccess.h"
#include "distributedadmission.h"
#include "distributedidentity.h"
#include "distributedthreadterminal.h"
#include <atomic>
#include <cstdio>
#include <cstring>

namespace
{
constexpr mdTypeDef AdmittedType = 0x02000002;
constexpr mdMethodDef AdmittedMethod = 0x06000001;

Module* s_module = nullptr;
MethodDesc* s_workerMethod = nullptr;
unsigned s_localNode = 0;
DistributedIdentityContext s_admissionIdentity{}; // Immutable after initialized release.
std::atomic<bool> s_initialized{false};
std::atomic<bool> s_sourceReserved{false};
std::atomic<bool> s_sourceStarting{false};
std::atomic<bool> s_sourceStarted{false};
enum class SourceCompletionState : unsigned char { Pending, Completed, Aborted };
std::atomic<SourceCompletionState> s_sourceCompletionState{SourceCompletionState::Pending};
static_assert(__atomic_always_lock_free(sizeof(s_sourceCompletionState), 0),
    "SourceCompletionState atomic must be lock-free while Access::Abort holds s_lock");
static_assert(sizeof(s_sourceCompletionState) == sizeof(SourceCompletionState),
    "SourceCompletionState atomic must not use an expanded representation");
static_assert(alignof(std::atomic<SourceCompletionState>) >= alignof(SourceCompletionState),
    "SourceCompletionState atomic alignment must support its lock-free primitive");
std::atomic<bool> s_workerPrepared{false};
std::atomic<bool> s_executionClaimed{false};
std::atomic<bool> s_callbackReturned{false};
std::atomic<bool> s_workerJoined{false};
using ApplicationAdmissionGate = dcg01_terminal_admission::Gate;
ApplicationAdmissionGate s_applicationGate{1};
ApplicationAdmissionGate::Ticket s_mainActionTicket;
ApplicationAdmissionGate::Ticket s_sourceStartTicket;
ApplicationAdmissionGate::Ticket s_workerCallbackTicket;
std::atomic<Thread*> s_mainActionOwner{nullptr};
std::atomic<Thread*> s_sourceStartOwner{nullptr};
std::atomic<Thread*> s_workerCallbackOwner{nullptr};
Thread* s_sourceNative = nullptr;
Thread* s_workerNative = nullptr;
OBJECTHANDLE s_sourceThreadRoot = nullptr;
OBJECTHANDLE s_workerThreadRoot = nullptr;
OBJECTHANDLE s_workerDelegateRoot = nullptr;
CLREventStatic s_sourceCompletion;

bool RetireSourceStartTicket()
{
    // Only the Thread that reserved this private ticket can retire it. Retire
    // exactly one valid state: Reserved on cancellation or Active on completion.
    Thread* current = GetThread();
    if (current == nullptr || current != s_sourceStartOwner.load(std::memory_order_acquire))
        return false;
    return s_applicationGate.CancelReservation(s_sourceStartTicket) ||
        s_applicationGate.CompleteActive(s_sourceStartTicket);
}

bool RetireWorkerCallbackTicket()
{
    // Cancellation is Reserved-only; callback completion is Active-only.
    return s_applicationGate.CancelReservation(s_workerCallbackTicket) ||
        s_applicationGate.CompleteActive(s_workerCallbackTicket);
}

void ThrowDistributedInvalidOperation()
{
    COMPlusThrow(kInvalidOperationException);
}

bool ValidateAdmittedMethod(MethodDesc* method)
{
    if (method == nullptr ||
        method->GetModule() != s_module ||
        method->GetMemberDef() != AdmittedMethod ||
        method->GetMethodTable()->GetCl() != AdmittedType ||
        method->IsStatic() ||
        method->IsVirtual() ||
        !method->IsIL() ||
        method->HasMethodInstantiation())
    {
        return false;
    }

    PCCOR_SIGNATURE signature = nullptr;
    DWORD signatureLength = 0;
    method->GetSig(&signature, &signatureLength);
    const BYTE expected[] = {
        IMAGE_CEE_CS_CALLCONV_HASTHIS, 0, ELEMENT_TYPE_VOID
    };
    return signatureLength == sizeof(expected) &&
        memcmp(signature, expected, sizeof(expected)) == 0;
}

void ValidateInvocation(OBJECTREF delegateObject, OBJECTREF* targetOut)
{
    GCPROTECT_BEGIN(delegateObject);
    MethodTable* delegateType = CoreLibBinder::GetClass(CLASS__THREADSTART);
    DELEGATEREF delegate = (DELEGATEREF)delegateObject;
    if (delegate == nullptr ||
        delegate->GetMethodTable() != delegateType ||
        delegate->GetInvocationCount() != 0 ||
        delegate->GetInvocationList() != nullptr)
    {
        ThrowDistributedInvalidOperation();
    }

    // Store the target directly in the caller's protected slot before resolving
    // the MethodDesc, which may trigger a GC.
    *targetOut = COMDelegate::GetTargetObject(delegateObject);
    MethodDesc* method = COMDelegate::GetMethodDesc(delegateObject);
    if (*targetOut == nullptr || method != s_workerMethod ||
        (*targetOut)->GetMethodTable()->GetCl() != AdmittedType ||
        (*targetOut)->GetMethodTable()->GetModule() != s_module)
    {
        ThrowDistributedInvalidOperation();
    }
    GCPROTECT_END();
}
}

bool DistributedThreadInitialize(Assembly* assembly, const DistributedIdentityContext& context)
{
    if (!DistributedAdmissionIsThreadProbe())
    {
        return true;
    }

    if (assembly == nullptr || context.localNode < 1 || context.localNode > 2 ||
        !s_sourceCompletion.CreateManualEventNoThrow(FALSE))
    {
        return false;
    }

    Module* module = assembly->GetModule();
    if (module == nullptr)
    {
        return false;
    }

    MethodDesc* method = MemberLoader::GetMethodDescFromMethodDef(module, AdmittedMethod, TRUE);
    if (method == nullptr)
    {
        return false;
    }

    s_module = module;
    s_workerMethod = method;
    s_localNode = context.localNode;
    if (!ValidateAdmittedMethod(method))
    {
        s_module = nullptr;
        s_workerMethod = nullptr;
        s_localNode = 0;
        return false;
    }

    s_admissionIdentity = context;
    s_initialized.store(true, std::memory_order_release);
    return true;
}

bool DistributedThreadBeginMain(Thread* thread)
{
    if (!s_initialized.load(std::memory_order_acquire) || s_localNode != 1 ||
        thread == nullptr || thread != GetThread() || !DistributedIdentityAccessCaller())
        return false;
    Thread* noOwner = nullptr;
    if (!s_mainActionOwner.compare_exchange_strong(noOwner, thread,
            std::memory_order_acq_rel, std::memory_order_acquire))
        return false;
    if (!s_applicationGate.TryEnter(s_mainActionTicket))
    {
        s_mainActionOwner.store(nullptr, std::memory_order_release);
        return false;
    }
    return true;
}

bool DistributedThreadHasApplicationAction()
{
    if (!s_initialized.load(std::memory_order_acquire))
        return false;
    Thread* current = GetThread();
    return current != nullptr &&
        ((current == s_mainActionOwner.load(std::memory_order_acquire) &&
          s_applicationGate.IsAuthorized(s_mainActionTicket)) ||
         (current == s_sourceStartOwner.load(std::memory_order_acquire) &&
          s_applicationGate.IsAuthorized(s_sourceStartTicket)) ||
         (current == s_workerCallbackOwner.load(std::memory_order_acquire) &&
          s_applicationGate.IsAuthorized(s_workerCallbackTicket)));
}

bool DistributedThreadCaptureClosedAdmission(DistributedThreadAdmissionSnapshot* output)
{
    if (output == nullptr || !s_initialized.load(std::memory_order_acquire) ||
        (s_localNode != 1 && s_localNode != 2) ||
        (s_localNode == 2 && !s_workerJoined.load(std::memory_order_acquire)))
        return false;
    ApplicationAdmissionGate::ClosedSnapshot closed{};
    if (!s_applicationGate.CaptureClosed(&closed))
        return false;
    DistributedThreadAdmissionSnapshot captured{};
    captured.identity = s_admissionIdentity;
    captured.generation = closed.generation;
    *output = captured;
    return true;
}

bool DistributedThreadCloseMainAndDrain()
{
    if (!s_initialized.load(std::memory_order_acquire) || s_localNode != 1)
        return false;
    Thread* owner = s_mainActionOwner.load(std::memory_order_acquire);
    if (owner != nullptr && owner != GetThread())
        return false;
    const std::uint64_t generation = s_applicationGate.Close();
    if (generation == 0)
        return false; // Fail closed, but exhaustion is not terminal evidence.
    if (!s_applicationGate.CompleteActive(s_mainActionTicket) && owner != nullptr)
        return false;
    s_mainActionOwner.store(nullptr, std::memory_order_release);
    // Main's synchronous Start call stack has returned too; retire any stale
    // nested reservation at this post-Main boundary before waiting for drain.
    if (RetireSourceStartTicket())
        s_sourceStartOwner.store(nullptr, std::memory_order_release);
    const bool drained = s_applicationGate.WaitForDrain();
    DistributedThreadAdmissionSnapshot snapshot{};
    const bool captured = drained && DistributedThreadCaptureClosedAdmission(&snapshot);
    if (captured && owner != nullptr)
        std::fprintf(stderr,
            "DC_THREAD phase=local-admission-close-diagnostic node=1 generation=%llu drained=1\n",
            static_cast<unsigned long long>(snapshot.generation));
    return captured;
}

bool DistributedThreadCloseAfterWorkerJoin()
{
    if (!s_initialized.load(std::memory_order_acquire) || s_localNode != 2 ||
        !s_workerJoined.load(std::memory_order_acquire))
        return false;
    const std::uint64_t generation = s_applicationGate.Close();
    if (generation == 0)
        return false; // Fail closed, but exhaustion is not terminal evidence.
    // Physical Join proves the child can no longer use its callback ticket.
    // This control cleanup covers startup/entry exceptions that bypass managed
    // callback notifications without treating them as successful completion.
    RetireWorkerCallbackTicket();
    const bool drained = s_applicationGate.WaitForDrain();
    DistributedThreadAdmissionSnapshot snapshot{};
    const bool captured = drained && DistributedThreadCaptureClosedAdmission(&snapshot);
    if (captured)
        std::fprintf(stderr,
            "DC_THREAD phase=local-admission-close-diagnostic node=2 generation=%llu drained=1\n",
            static_cast<unsigned long long>(snapshot.generation));
    return captured;
}

bool DistributedThreadTryReserveSource(QCall::ObjectHandleOnStack thread)
{
    if (!s_initialized.load(std::memory_order_acquire))
    {
        return false;
    }

    Thread* current = GetThread();
    if (s_localNode != 1 || !DistributedIdentityAccessCaller() ||
        current == nullptr || current != s_mainActionOwner.load(std::memory_order_acquire) ||
        !s_applicationGate.IsAuthorized(s_mainActionTicket))
    {
        DistributedAccessThreadAbort("thread-start-caller");
        ThrowDistributedInvalidOperation();
    }

    THREADBASEREF source = (THREADBASEREF)thread.Get();
    if (source == nullptr || source->GetInternal() == nullptr)
    {
        DistributedAccessThreadAbort("thread-start-source");
        ThrowDistributedInvalidOperation();
    }

    GCPROTECT_BEGIN(source);
    Thread* native = source->GetInternal();
    if (s_sourceReserved.load(std::memory_order_acquire))
    {
        if (native == s_sourceNative)
        {
            COMPlusThrow(kThreadStateException, W("ThreadState_AlreadyStarted"));
        }
        DistributedAccessThreadAbort("thread-start-second-thread");
        ThrowDistributedInvalidOperation();
    }

    Wrapper<OBJECTHANDLE, DoNothing<OBJECTHANDLE>, DestroyStrongHandle> root;
    root = GetAppDomain()->CreateStrongHandle(source);
    if (root == nullptr)
    {
        DistributedAccessThreadAbort("thread-start-root");
        COMPlusThrowOM();
    }

    if (!s_applicationGate.TryReserveChild(s_mainActionTicket, s_sourceStartTicket))
    {
        DistributedAccessThreadAbort("thread-start-admission-closed");
        ThrowDistributedInvalidOperation();
    }
    if (!DistributedThreadTerminalLifecycle(static_cast<unsigned>(DCG01Events::Lifecycle::Admitted), 0))
    {
        s_applicationGate.CancelReservation(s_sourceStartTicket);
        DistributedAccessThreadAbort("thread-admission-event");
        ThrowDistributedInvalidOperation();
    }
    s_sourceStartOwner.store(current, std::memory_order_release);
    s_sourceThreadRoot = root.Extract();
    s_sourceNative = native;
    s_sourceReserved.store(true, std::memory_order_release);
    GCPROTECT_END();
    return true;
}

void DistributedThreadStartSource(QCall::ObjectHandleOnStack thread,
    QCall::ObjectHandleOnStack startDelegate)
{
    THREADBASEREF source = (THREADBASEREF)thread.Get();
    if (source != nullptr && source->GetInternal() == s_sourceNative &&
        s_sourceStarting.load(std::memory_order_acquire))
    {
        // Repeated Start on the one reserved source keeps ordinary Thread semantics.
        COMPlusThrow(kThreadStateException, W("ThreadState_AlreadyStarted"));
    }

    EX_TRY
    {
        if (!s_initialized.load(std::memory_order_acquire) ||
            s_localNode != 1 ||
            !s_sourceReserved.load(std::memory_order_acquire) ||
            source == nullptr ||
            source->GetInternal() != s_sourceNative ||
            GetThread() != s_sourceStartOwner.load(std::memory_order_acquire) ||
            !s_applicationGate.ActivateReserved(s_sourceStartTicket))
        {
            ThrowDistributedInvalidOperation();
        }

        if (s_sourceStarting.exchange(true, std::memory_order_acq_rel))
        {
            ThrowDistributedInvalidOperation();
        }

        struct
        {
            DELEGATEREF delegate;
            OBJECTREF target;
        } gc;
        gc.delegate = (DELEGATEREF)startDelegate.Get();
        gc.target = nullptr;
        GCPROTECT_BEGIN(gc);
        ValidateInvocation(gc.delegate, &gc.target);

        {
            // AccessStart may wait; keep managed references rooted while running preemptively.
            GCX_PREEMP();
            DistributedAccessThreadStart(&gc.target);
        }
        if (!s_applicationGate.CompleteActive(s_sourceStartTicket))
            ThrowDistributedInvalidOperation();
        s_sourceStartOwner.store(nullptr, std::memory_order_release);
        s_sourceStarted.store(true, std::memory_order_release);
        GCPROTECT_END();
    }
    EX_CATCH
    {
        if (GetThread() == s_sourceStartOwner.load(std::memory_order_acquire))
        {
            RetireSourceStartTicket();
            s_sourceStartOwner.store(nullptr, std::memory_order_release);
        }
        else
        {
            // A failed/foreign QCall must not retire or clear the real owner’s ticket.
            DistributedAccessThreadAbort("thread-start-failure-owner");
        }
        DistributedThreadNotifyAbort();
        DistributedAccessThreadAbort("thread-start-failed");
        EX_RETHROW;
    }
    EX_END_CATCH
}

void DistributedThreadRejectSourceStart()
{
    Thread* current = GetThread();
    if (current == nullptr || current != s_sourceStartOwner.load(std::memory_order_acquire) ||
        !s_applicationGate.CancelReservation(s_sourceStartTicket))
    {
        // Managed profile rejection occurs before DistributedStart activates
        // this reservation. Do not complete an active ticket or mutate its owner.
        DistributedAccessThreadAbort("thread-start-reject-owner");
        ThrowDistributedInvalidOperation();
    }
    s_sourceStartOwner.store(nullptr, std::memory_order_release);
    DistributedThreadNotifyAbort();
    DistributedAccessThreadAbort("thread-start-rejected");
}

void DistributedThreadPrepareWorker(OBJECTREF target)
{
    if (!s_initialized.load(std::memory_order_acquire) ||
        s_localNode != 2 || target == nullptr ||
        s_workerPrepared.load(std::memory_order_acquire))
    {
        ThrowDistributedInvalidOperation();
    }

    OBJECTREF targetRoot = target;
    DELEGATEREF delegate = nullptr;
    OBJECTREF worker = nullptr;
    OBJECTREF firstArg = nullptr;
    GCPROTECT_BEGIN(targetRoot);
    GCPROTECT_BEGIN(delegate);
    GCPROTECT_BEGIN(worker);
    GCPROTECT_BEGIN(firstArg);

    if (!ValidateAdmittedMethod(s_workerMethod))
    {
        ThrowDistributedInvalidOperation();
    }
    if (targetRoot->GetMethodTable()->GetCl() != AdmittedType ||
        targetRoot->GetMethodTable()->GetModule() != s_module)
    {
        ThrowDistributedInvalidOperation();
    }

    MethodTable* delegateType = CoreLibBinder::GetClass(CLASS__THREADSTART);
    MethodDesc* invoke = COMDelegate::FindDelegateInvokeMethod(delegateType);
    bool openDelegate = true;
    if (!COMDelegate::IsMethodDescCompatible(
            TypeHandle(targetRoot->GetMethodTable()),
            TypeHandle(s_workerMethod->GetMethodTable()),
            s_workerMethod,
            TypeHandle(delegateType),
            invoke,
            DBF_InstanceMethodOnly | DBF_ClosedDelegateOnly,
            &openDelegate) ||
        openDelegate)
    {
        ThrowDistributedInvalidOperation();
    }

    delegate = (DELEGATEREF)AllocateObject(delegateType);
    firstArg = targetRoot;
    COMDelegate::BindToMethod(&delegate, &firstArg, s_workerMethod,
        s_workerMethod->GetMethodTable(), FALSE);
    if (delegate == nullptr ||
        COMDelegate::GetMethodDesc(delegate) != s_workerMethod ||
        COMDelegate::GetTargetObject(delegate) != targetRoot)
    {
        ThrowDistributedInvalidOperation();
    }

    MethodDescCallSite createWorker(METHOD__THREAD__DISTRIBUTED_CREATE_WORKER);
    ARG_SLOT createArgs[] = { ObjToArgSlot(delegate) };
    worker = createWorker.Call_RetOBJECTREF(createArgs);
    if (worker == nullptr)
    {
        COMPlusThrowOM();
    }

    THREADBASEREF workerBase = (THREADBASEREF)worker;
    Thread* workerNative = workerBase->GetInternal();
    if (workerNative == nullptr)
    {
        ThrowDistributedInvalidOperation();
    }

    s_workerDelegateRoot = GetAppDomain()->CreateStrongHandle(delegate);
    s_workerThreadRoot = GetAppDomain()->CreateStrongHandle(worker);
    if (s_workerDelegateRoot == nullptr || s_workerThreadRoot == nullptr)
    {
        DistributedAccessThreadAbort("thread-worker-root");
        COMPlusThrowOM();
    }

    s_workerNative = workerNative;
    s_workerPrepared.store(true, std::memory_order_release);
    GCPROTECT_END();
    GCPROTECT_END();
    GCPROTECT_END();
    GCPROTECT_END();
}

void DistributedThreadRunWorker()
{
    if (!s_initialized.load(std::memory_order_acquire) ||
        s_localNode != 2 ||
        !s_workerPrepared.load(std::memory_order_acquire) ||
        s_sourceCompletionState.load(std::memory_order_acquire) == SourceCompletionState::Aborted)
    {
        ThrowDistributedInvalidOperation();
    }

    {
        GCX_COOP();
        OBJECTREF worker = ObjectFromHandle(s_workerThreadRoot);
        GCPROTECT_BEGIN(worker);
        MethodDescCallSite runWorker(METHOD__THREAD__DISTRIBUTED_RUN_WORKER);
        ARG_SLOT arguments[] = { ObjToArgSlot(worker) };
        runWorker.Call(arguments);
        GCPROTECT_END();
    }

    // RunDistributedWorker returns only after ordinary local Join on the physical
    // child succeeds. The caller entered this function preemptively; the nested
    // cooperative scope has ended before the close/drain wait.
    s_workerJoined.store(true, std::memory_order_release);
    if (!DistributedThreadCloseAfterWorkerJoin())
    {
        DistributedAccessThreadAbort("thread-admission-drain");
        ThrowDistributedInvalidOperation();
    }
    if (!s_callbackReturned.load(std::memory_order_acquire) ||
        s_sourceCompletionState.load(std::memory_order_acquire) == SourceCompletionState::Aborted)
    {
        DistributedAccessThreadAbort("thread-child-not-complete");
        ThrowDistributedInvalidOperation();
    }
}

bool DistributedThreadWorkerJoined()
{
    return s_workerJoined.load(std::memory_order_acquire);
}

bool DistributedThreadIsReservedSource(Thread* thread)
{
    return s_initialized.load(std::memory_order_acquire) &&
        s_sourceReserved.load(std::memory_order_acquire) &&
        thread == s_sourceNative;
}

bool DistributedThreadBeforeCreate(Thread* thread)
{
    if (!s_initialized.load(std::memory_order_acquire))
    {
        return true;
    }

    if (thread == s_sourceNative)
    {
        DistributedAccessThreadAbort("reserved-source-local-start");
        return false;
    }

    if (s_localNode != 2 || !s_workerPrepared.load(std::memory_order_acquire) ||
        thread != s_workerNative)
    {
        // Unrelated runtime-internal Threads keep their local behavior. Application
        // Start calls are rejected by the managed reservation gate before mutation.
        return true;
    }

    if (s_executionClaimed.exchange(true, std::memory_order_acq_rel) ||
        !DistributedAccessThreadClaimExecution())
    {
        DistributedAccessThreadAbort("thread-execution-claim");
        return false;
    }

    if (!DistributedIdentityHandoffThreadOwner(thread))
    {
        DistributedAccessThreadAbort("thread-owner-handoff");
        return false;
    }

    s_workerCallbackOwner.store(thread, std::memory_order_release);
    if (!s_applicationGate.TryReserve(s_workerCallbackTicket))
    {
        s_workerCallbackOwner.store(nullptr, std::memory_order_release);
        DistributedAccessThreadAbort("thread-callback-admission-closed");
        return false;
    }
    return true;
}

void DistributedThreadEnterCallback(QCall::ObjectHandleOnStack thread)
{
    THREADBASEREF managed = (THREADBASEREF)thread.Get();
    GCPROTECT_BEGIN(managed);
    Thread* current = GetThread();
    if (!s_initialized.load(std::memory_order_acquire) ||
        s_localNode != 2 ||
        !s_workerPrepared.load(std::memory_order_acquire) ||
        current == nullptr ||
        current != s_workerNative ||
        managed == nullptr ||
        managed->GetInternal() != current ||
        current != s_workerCallbackOwner.load(std::memory_order_acquire) ||
        s_sourceCompletionState.load(std::memory_order_acquire) == SourceCompletionState::Aborted ||
        !s_applicationGate.ActivateReserved(s_workerCallbackTicket))
    {
        DistributedAccessThreadAbort("thread-entry-owner");
        ThrowDistributedInvalidOperation();
    }

    {
        // The entry handshake may wait for the coordinator; keep the managed Thread rooted.
        GCX_PREEMP();
        DistributedAccessThreadEnter();
    }
    GCPROTECT_END();
}

void DistributedThreadCallbackReturned()
{
    if (!s_initialized.load(std::memory_order_acquire) ||
        s_localNode != 2 ||
        GetThread() != s_workerNative ||
        GetThread() != s_workerCallbackOwner.load(std::memory_order_acquire))
    {
        DistributedAccessThreadAbort("thread-callback-return-owner");
        ThrowDistributedInvalidOperation();
    }

    if (s_sourceCompletionState.load(std::memory_order_acquire) == SourceCompletionState::Aborted)
    {
        s_applicationGate.CompleteActive(s_workerCallbackTicket);
        s_workerCallbackOwner.store(nullptr, std::memory_order_release);
        return;
    }

    if (s_callbackReturned.load(std::memory_order_acquire))
    {
        DistributedAccessThreadAbort("thread-callback-return");
        ThrowDistributedInvalidOperation();
    }

    EX_TRY
    {
        // Capture portable completion facts before publishing callback success.
        DistributedAccessThreadReturned();
        // This is a source-owned diagnostic snapshot, not the terminal cut.
        if (!DistributedIdentityPublishWorkerSnapshot())
            ThrowDistributedInvalidOperation();
        if (!s_applicationGate.CompleteActive(s_workerCallbackTicket))
            ThrowDistributedInvalidOperation();
        s_workerCallbackOwner.store(nullptr, std::memory_order_release);
        s_callbackReturned.store(true, std::memory_order_release);
    }
    EX_CATCH
    {
        s_applicationGate.CompleteActive(s_workerCallbackTicket);
        s_workerCallbackOwner.store(nullptr, std::memory_order_release);
        DistributedThreadNotifyAbort();
        DistributedAccessThreadAbort("thread-callback-publish");
        EX_RETHROW;
    }
    EX_END_CATCH
}

void DistributedThreadCallbackFailed()
{
    if (s_initialized.load(std::memory_order_acquire) &&
        s_localNode == 2 &&
        GetThread() == s_workerNative)
    {
        RetireWorkerCallbackTicket();
        s_workerCallbackOwner.store(nullptr, std::memory_order_release);
        DistributedThreadNotifyAbort();
        DistributedAccessThreadAbort("thread-callback-failed");
    }
}

void DistributedThreadCancelWorkerCallbackStart(Thread* thread)
{
    if (s_initialized.load(std::memory_order_acquire) && s_localNode == 2 &&
        thread == s_workerNative)
    {
        if (s_applicationGate.CancelReservation(s_workerCallbackTicket))
            s_workerCallbackOwner.store(nullptr, std::memory_order_release);
    }
}

void DistributedThreadNotifyComplete()
{
    auto expected = SourceCompletionState::Pending;
    if (s_sourceCompletionState.compare_exchange_strong(expected, SourceCompletionState::Completed,
        std::memory_order_acq_rel, std::memory_order_acquire) ||
        expected == SourceCompletionState::Completed)
    {
        s_sourceCompletion.Set();
    }
}

void DistributedThreadMarkAbort()
{
    s_sourceCompletionState.exchange(SourceCompletionState::Aborted, std::memory_order_acq_rel);
}

void DistributedThreadSignalAbort()
{
    s_sourceCompletion.Set();
}

void DistributedThreadNotifyAbort()
{
    DistributedThreadMarkAbort();
    DistributedThreadSignalAbort();
}

bool DistributedThreadWaitForCompletion(Thread* thread, DWORD timeout, BOOL* completed)
{
    if (completed == nullptr || !DistributedThreadIsReservedSource(thread))
    {
        return false;
    }
    if (!s_sourceStarted.load(std::memory_order_acquire))
    {
        COMPlusThrow(kThreadStateException, W("ThreadState_NotStarted"));
    }

    DWORD result = s_sourceCompletion.Wait(timeout, TRUE);
    if (result == WAIT_TIMEOUT)
    {
        *completed = FALSE;
        return true;
    }
    if (result == WAIT_IO_COMPLETION)
    {
        COMPlusThrow(kThreadInterruptedException);
    }
    if (result != WAIT_OBJECT_0)
    {
        DistributedThreadNotifyAbort();
        DistributedAccessThreadAbort("thread-completion-wait");
        ThrowDistributedInvalidOperation();
    }

    auto expected = SourceCompletionState::Completed;
    if (s_sourceCompletionState.compare_exchange_strong(expected, SourceCompletionState::Completed,
        std::memory_order_acq_rel, std::memory_order_acquire))
    {
        if (!DistributedAccessRecordThreadJoin())
        {
            DistributedAccessThreadAbort("thread-join-event");
            ThrowDistributedInvalidOperation();
        }
        *completed = TRUE;
        return true;
    }

    if (expected == SourceCompletionState::Aborted)
        ThrowDistributedInvalidOperation();

    // A signaled event with Pending state is an invariant violation. Fail the whole run closed.
    DistributedThreadNotifyAbort();
    DistributedAccessThreadAbort("thread-completion-state");
    ThrowDistributedInvalidOperation();
    return true;
}
