// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#ifndef __DISTRIBUTEDACCESS_H__
#define __DISTRIBUTEDACCESS_H__

#include "distributedidentity.h"

// Portable data only. A zero ID denotes null; no runtime address leaves a GC-aware lookup.
struct DistributedObjectId { BYTE bytes[44]; };
struct DistributedAccessSeed
{
    DistributedObjectId id;
    UINT32 kind; // 0: the admitted node, 1: exact int32 SZARRAY
    UINT32 length;
    UINT32 values[32];
    DistributedObjectId references[2];
};

constexpr unsigned DistributedPublicationMaxObjects = 16;
struct DistributedPublicationBatch
{
    UINT64 transaction;
    UINT64 sourceFrontier;
    unsigned count;
    DistributedObjectId root;
    DistributedAccessSeed seeds[DistributedPublicationMaxObjects];
    unsigned gcCollections;
    unsigned moved;
    unsigned stagedTransferRoots;
};

bool DistributedAccessInitialize(Assembly* assembly, const DistributedIdentityContext& context);
bool DistributedAccessIsMethod(MethodDesc* method);
bool DistributedAccessIsField(FieldDesc* field);
int DistributedAccessWorker();
namespace DCG01Output { struct ArtifactInfo; }
bool DistributedAccessThreadFinishApplication(INT32 result, const DCG01Output::ArtifactInfo* output);
bool DistributedAccessRecordThreadJoin();
void DistributedAccessShutdown();

// Source-owned values after local admission drains. This is not a root census,
// immutable terminal commitment, output-custody proof, or successful Main result.
struct DistributedAccessQuiescentSnapshot
{
    DistributedIdentityContext identity;
    UINT64 admissionGeneration;
    UINT64 lastAcceptedOperationSequence;
    UINT64 authorityFrontier; // Total committed at authority; last validated reply at worker.
    UINT64 publicationFrontier;
};
// No allocation or network wait. Copies under the local access lock; unchanged on refusal.
bool DistributedAccessCaptureQuiescentSnapshot(DistributedAccessQuiescentSnapshot* output);

int DistributedIdentityExportArray(OBJECTREF array, BYTE* wire, int capacity);
bool DistributedIdentityImportArray(const BYTE* wire, int length, OBJECTREF* result);
bool DistributedIdentityImportAccessGraph(const BYTE* wire, int length, OBJECTREF* result);
bool DistributedIdentityFreeze(DistributedAccessSeed* seeds, unsigned* count);
// Source owner in cooperative mode, only after authenticated Ready binds this exact seed set.
// Retires transfer obligations atomically as a set; preserves every physical handle.
bool DistributedIdentityCompleteInitialThreadTransfer(const DistributedAccessSeed* seeds, unsigned count);
int DistributedIdentityAccessTarget(OBJECTREF target, UINT_PTR location, bool array,
    DistributedObjectId* id, unsigned* slot);
bool DistributedIdentityAccessReference(OBJECTREF value, DistributedObjectId* id);
bool DistributedIdentityResolveReference(const DistributedObjectId& id, OBJECTREF* result);
bool DistributedIdentityAccessCaller();
bool DistributedIdentityPublicationFinishCaller();
unsigned DistributedIdentityLocalNode();
bool DistributedIdentityIsFrozen();

bool DistributedIdentityPreparePublication(OBJECTREF root, UINT64 transaction, UINT64 sourceFrontier,
    BYTE* wire, unsigned capacity, unsigned* length, DistributedPublicationBatch* batch);
bool DistributedIdentityImportPublication(const BYTE* wire, unsigned length, DistributedPublicationBatch* batch);
bool DistributedIdentityActivatePublication(UINT64 transaction);
bool DistributedIdentityCompletePublication(UINT64 transaction);
unsigned DistributedIdentityPendingPublicationRoots();

#endif
