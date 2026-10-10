// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#ifndef __DISTRIBUTEDIDENTITY_H__
#define __DISTRIBUTEDIDENTITY_H__

#include "distributedidentity_snapshot.h"

class Assembly;
class Thread;

struct DistributedIdentityContext
{
    unsigned char run[16];
    unsigned localNode;
    unsigned peerNode;
    unsigned char localInc[16];
    unsigned char peerInc[16];
    unsigned char assemblyHash[32];
    unsigned char mvid[16];
};

bool DistributedIdentityInitialize(Assembly* assembly, const DistributedIdentityContext& context);
// Owner-thread diagnostic copy only. Root census and access-side publication remain open.
bool DistributedIdentityCaptureSnapshot(dcg01_identity_snapshot::Snapshot* output,
    unsigned outputEntryCapacity);
// Freeze a full plain-value copy on the child owner after its managed callback returns.
bool DistributedIdentityPublishWorkerSnapshot();
// The staging owner consumes the frozen copy only after its real local child Join.
bool DistributedIdentityTakeWorkerSnapshotAfterJoin(
    dcg01_identity_snapshot::Snapshot* output);
// One-way worker staging-to-child transfer, before OS-thread creation; no GC, wait or allocation.
bool DistributedIdentityHandoffThreadOwner(Thread* next);
int DistributedIdentityProcessGraph(const unsigned char* wire, int len, unsigned char* reply, int capacity);

#endif
