// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#ifndef __DISTRIBUTEDTHREAD_H__
#define __DISTRIBUTEDTHREAD_H__

#include "distributedidentity.h"

class Assembly;
class Thread;
class MethodDesc;
class FieldDesc;

// Owned by this module. Managed references are held by strong handles.
bool DistributedThreadInitialize(Assembly* assembly, const DistributedIdentityContext& context);
void DistributedThreadPrepareWorker(OBJECTREF target);
void DistributedThreadRunWorker();
bool DistributedThreadWorkerJoined();
bool DistributedThreadBeginMain(Thread* thread);
bool DistributedThreadCloseMainAndDrain();
bool DistributedThreadCloseAfterWorkerJoin();
bool DistributedThreadHasApplicationAction();

// Plain values from this member's immutable admitted identity and one-way gate.
// This says nothing about Main outcome, roots, effects, or terminal eligibility.
struct DistributedThreadAdmissionSnapshot
{
    DistributedIdentityContext identity;
    uint64_t generation;
};
// Nonblocking, no managed allocation, output unchanged on refusal.
bool DistributedThreadCaptureClosedAdmission(DistributedThreadAdmissionSnapshot* output);

void DistributedThreadCancelWorkerCallbackStart(Thread* thread);
void DistributedThreadNotifyComplete();
void DistributedThreadMarkAbort();
void DistributedThreadSignalAbort();
void DistributedThreadNotifyAbort();

// Called by the access and identity owners. These functions must remain bounded,
// nonblocking and free of managed allocation where stated by the lifecycle contract.
// target points to the caller's GC-protected slot; dereference only cooperatively.
void DistributedAccessThreadStart(OBJECTREF* target);
bool DistributedAccessThreadClaimExecution();
void DistributedAccessThreadEnter();
void DistributedAccessThreadReturned();
void DistributedAccessThreadAbort(const char* reason);
bool DistributedIdentityHandoffThreadOwner(Thread* thread);

// Native Thread/QCall integration.
bool DistributedThreadTryReserveSource(QCall::ObjectHandleOnStack thread);
void DistributedThreadStartSource(QCall::ObjectHandleOnStack thread,
    QCall::ObjectHandleOnStack startDelegate);
void DistributedThreadRejectSourceStart();
void DistributedThreadEnterCallback(QCall::ObjectHandleOnStack thread);
void DistributedThreadCallbackReturned();
void DistributedThreadCallbackFailed();

bool DistributedThreadIsReservedSource(Thread* thread);
bool DistributedThreadBeforeCreate(Thread* thread);
bool DistributedThreadWaitForCompletion(Thread* thread, DWORD timeout, BOOL* completed);

#endif // __DISTRIBUTEDTHREAD_H__
