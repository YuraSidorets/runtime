// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#ifndef DISTRIBUTED_THREAD_TERMINAL_H
#define DISTRIBUTED_THREAD_TERMINAL_H

#include "distributedadmission.h"
#include "distributedthreadevents.h"
#include "distributedparticipantcommit.h"
#include "distributedphysicaldisconnect.h"
#include "distributedrecordpublication.h"
#include <pthread.h>
#include <string.h>

namespace DCG01Terminal
{
enum class Origin : unsigned { Transport = 1, Admission = 2, Access = 3, Evidence = 4 };
// Both published outcomes retain record authority; exported copies have separate availability.
enum class PublicationResult : unsigned { Failed, Complete, ExportIncomplete };
using HashFunction = bool (*)(const unsigned char*, size_t, unsigned char*);
struct FailureSnapshot
{
    DistributedAdmissionThreadIdentity identity{};
    bool configured = false;
    bool failed = false;
    bool reasonOverflow = false;
    Origin origin = Origin::Transport;
    unsigned code = 0;
    uint64_t failureOrder = 0;
    uint64_t abortOrder = 0;
    char reason[128]{};
    size_t sourceEvidenceLength = 0;
    unsigned char sourceEvidence[768]{}, sourceEvidenceDigest[32]{};
    bool failureEventsRecorded = false;
};

struct DisconnectSnapshot
{
    bool informational=false;
    uint64_t transition=0;
    size_t length=0;
    unsigned char bytes[2048]{}, digest[32]{};
};

struct PublicationSnapshot
{
    bool started=false,finished=false,published=false;
    uint64_t transition=0;
    DCG01Record::Witness witness{};
};

// One admitted run; no reset. Extend this same lock for retirement/seal, rather
// than treating a separate Healthy() observation as an atomic terminal decision.
class FailureOrder
{
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    FailureSnapshot state{};
    DCG01Events::Stream events;
    HashFunction hashSource = nullptr;
    uint64_t coordinatorOrder = 0;
    DCG01Commit::Worker workerCommit;
    DCG01Commit::Receipt workerReceipt;
    DisconnectSnapshot disconnect{};
    PublicationSnapshot publication{};
    bool transportDrainStarted=false;

    static bool Nonzero(const unsigned char* bytes, size_t length)
    {
        for (size_t i = 0; i < length; ++i) if (bytes[i]) return true;
        return false;
    }
    void LatchLocked(Origin origin, unsigned code, const char* reason)
    {
        if (!state.configured || state.failed) return;
        state.origin = origin; state.code = code;
        if (reason)
        {
            const size_t length = strnlen(reason,sizeof(state.reason));
            state.reasonOverflow = length == sizeof(state.reason);
            if (!state.reasonOverflow) memcpy(state.reason,reason,length + 1);
        }
        // One transition counter, under this same mutex, is reserved for all
        // future retirement/seal decisions. Trace collection order is separate.
        if (coordinatorOrder <= UINT64_MAX - 2)
        { state.failureOrder = ++coordinatorOrder; state.abortOrder = ++coordinatorOrder; }
        state.failed = true; // Evidence failure must never undo the abort latch.
        if (state.reasonOverflow || state.failureOrder == 0) return;
        DC022Canonical::Writer w(state.sourceEvidence,sizeof(state.sourceEvidence));
        bool ok = w.BeginObject() && w.Key("code") && w.UInt(code) && w.Key("incarnation_id") &&
            w.Hex(state.identity.memberIncarnations[state.identity.localNode - 1],16) &&
            w.Key("local_member_id") && w.UInt(state.identity.localNode) && w.Key("origin") &&
            w.UInt(static_cast<unsigned>(origin)) && w.Key("reason_hex") &&
            (reason ? w.Hex(reinterpret_cast<const unsigned char*>(state.reason),strlen(state.reason)) : w.Null()) && w.Key("run_id") &&
            w.Hex(state.identity.run,16) && w.Key("schema") && w.String("dcg01-source-failure") &&
            w.Key("version") && w.UInt(1) && w.EndObject() && w.Finish();
        if (!ok) return;
        state.sourceEvidenceLength = w.Size();
        if (!hashSource || !hashSource(w.Data(),w.Size(),state.sourceEvidenceDigest) || state.identity.localNode != 1) return;
        const char* kind = origin == Origin::Evidence ? "evidence_failure" :
            origin == Origin::Admission ? "protocol_failure" : origin == Origin::Transport ?
            ((code == 9 || code == 12) ? "participant_failure" : "protocol_failure") :
            (reason && (!strcmp(reason,"thread-main-exception") || !strcmp(reason,"thread-callback-failed"))) ?
            "application_exception" : "unknown";
        state.failureEventsRecorded = events.RecordFailure(kind,state.sourceEvidenceDigest,state.failureOrder,state.abortOrder);
    }
public:
    FailureOrder() = default;
    FailureOrder(const FailureOrder&) = delete;
    FailureOrder& operator=(const FailureOrder&) = delete;
    ~FailureOrder() { pthread_mutex_destroy(&lock); }

    bool Configure(const DistributedAdmissionThreadIdentity* identity, HashFunction hash = nullptr)
    {
        if (!identity || (identity->localNode != 1 && identity->localNode != 2) ||
            !Nonzero(identity->run, 16) || !Nonzero(identity->runManifestSha256, 32) ||
            !Nonzero(identity->buildManifestSha256, 32) ||
            !Nonzero(identity->memberIncarnations[0], 16) ||
            !Nonzero(identity->memberIncarnations[1], 16) ||
            memcmp(identity->memberIncarnations[0], identity->memberIncarnations[1], 16) == 0)
            return false;
        pthread_mutex_lock(&lock);
        const bool accepted = !state.configured &&
            (identity->localNode == 2 || events.Configure(*identity));
        if (accepted)
        {
            state.identity = *identity;
            hashSource = hash;
            state.configured = true;
        }
        pthread_mutex_unlock(&lock);
        return accepted;
    }

    void Fail(Origin origin, unsigned code, const char* reason)
    {
        pthread_mutex_lock(&lock);
        LatchLocked(origin,code,reason);
        pthread_mutex_unlock(&lock);
    }

    bool Healthy()
    {
        pthread_mutex_lock(&lock);
        const bool healthy = state.configured && !state.failed;
        pthread_mutex_unlock(&lock);
        return healthy;
    }

    bool PhysicalDisconnect(const DCG01Disconnect::Notice& notice)
    {
        pthread_mutex_lock(&lock);
        DisconnectSnapshot candidate{};
        bool accepted=state.configured && !state.failed && state.identity.localNode==1 &&
            notice.localMember==1 && notice.peerMember==2 && notice.authenticated && !notice.sessionReused &&
            notice.tlsVersion==TLS1_3_VERSION && Nonzero(notice.peerCertificate,32) &&
            !memcmp(notice.peerCertificate,notice.expectedPeerCertificate,32) &&
            !memcmp(notice.run,state.identity.run,16) && !memcmp(notice.manifest,state.identity.runManifestSha256,32) &&
            !memcmp(notice.localIncarnation,state.identity.memberIncarnations[0],16) &&
            !memcmp(notice.peerIncarnation,state.identity.memberIncarnations[1],16) &&
            DCG01Disconnect::Encode(notice,candidate.bytes,sizeof(candidate.bytes),&candidate.length) &&
            hashSource && hashSource(candidate.bytes,candidate.length,candidate.digest);
        if (accepted && disconnect.informational)
            accepted=candidate.length==disconnect.length && !memcmp(candidate.bytes,disconnect.bytes,candidate.length);
        else if (accepted)
        {
            accepted=workerReceipt.HasCommitment() && events.WorkerRetired() && events.Sealed() &&
                coordinatorOrder<UINT64_MAX && events.PhysicalDisconnect(candidate.digest,coordinatorOrder+1);
            if (accepted)
            {
                candidate.informational=true;candidate.transition=++coordinatorOrder;disconnect=candidate;
            }
        }
        if (!accepted) LatchLocked(Origin::Transport,12,"physical-disconnect-not-informational");
        pthread_mutex_unlock(&lock);return accepted;
    }

    bool PeerDisconnected()
    {
        pthread_mutex_lock(&lock);
        const bool informational=state.configured && !state.failed && state.identity.localNode==1 &&
            disconnect.informational && events.Sealed() && events.WorkerRetired();
        pthread_mutex_unlock(&lock);return informational;
    }

    // Diagnostic copy remains available after a later fatal failure.
    bool CopyDisconnect(DisconnectSnapshot* output)
    {
        if (!output) return false;
        pthread_mutex_lock(&lock);
        const bool copied=disconnect.informational;
        if (copied) *output=disconnect;
        pthread_mutex_unlock(&lock);return copied;
    }

    bool Copy(FailureSnapshot* output)
    {
        if (!output) return false;
        pthread_mutex_lock(&lock);
        const bool configured = state.configured;
        if (configured) *output = state;
        pthread_mutex_unlock(&lock);
        return configured;
    }

    bool RecordLifecycle(DCG01Events::Lifecycle kind, uint64_t frontier)
    {
        pthread_mutex_lock(&lock);
        const bool accepted = !state.configured ||
            (!state.failed && state.identity.localNode == 1 && events.Record(kind, frontier));
        if (!accepted) LatchLocked(Origin::Evidence,1,"thread-event-order-or-bound");
        pthread_mutex_unlock(&lock);
        return accepted;
    }

    bool CopyTrace(unsigned char* output, size_t capacity, size_t* length, uint64_t* count)
    {
        pthread_mutex_lock(&lock);
        const bool copied = state.configured && state.identity.localNode == 1 &&
            events.Copy(output, capacity, length, count);
        pthread_mutex_unlock(&lock);
        return copied;
    }

    bool ArtifactEvent(unsigned id, unsigned role, const unsigned char* bytes, size_t length, const unsigned char* digest)
    {
        pthread_mutex_lock(&lock);
        const bool accepted = state.configured && !state.failed && state.identity.localNode == 1 &&
            events.CaptureArtifact(id,role,bytes,length,digest);
        if (!accepted) LatchLocked(Origin::Evidence,6,"artifact-custody-event");
        pthread_mutex_unlock(&lock);
        return accepted;
    }

    bool CommitWorker(uint64_t operations, uint64_t authority, uint64_t publications,
                      const DCG01Custody::Bundle* sent, const unsigned char* ack, size_t ackLength,
                      DCG01Commit::Frame* output)
    {
        pthread_mutex_lock(&lock);
        DCG01Preimage::Identity id{};
        memcpy(id.runId,state.identity.run,16); memcpy(id.buildDigest,state.identity.buildManifestSha256,32);
        memcpy(id.runManifestDigest,state.identity.runManifestSha256,32);
        memcpy(id.incarnation,state.identity.memberIncarnations,sizeof(id.incarnation));
        const bool accepted = state.configured && !state.failed && state.identity.localNode == 2 && sent &&
            workerCommit.Commit(id,operations,authority,publications,*sent,ack,ackLength,hashSource,output);
        if (!accepted) LatchLocked(Origin::Evidence,9,"worker-terminal-commitment");
        pthread_mutex_unlock(&lock);
        return accepted;
    }

    bool ReceiveWorkerCommit(const DCG01Custody::Bundle* custody, const unsigned char* wire, size_t length)
    {
        pthread_mutex_lock(&lock);
        const bool accepted = state.configured && !state.failed && state.identity.localNode == 1 && custody &&
            events.LocalCommitted() &&
            events.MatchesPreparedWorkerCustody(custody->bytes,custody->length) &&
            workerReceipt.Accept(*custody,wire,length) && events.ObserveWorkerCommitment();
        if (!accepted) LatchLocked(Origin::Evidence,10,"worker-terminal-commitment-receipt");
        pthread_mutex_unlock(&lock);
        return accepted;
    }

    bool RetireWorker()
    {
        pthread_mutex_lock(&lock);
        bool accepted = state.configured && !state.failed && state.identity.localNode == 1 && workerReceipt.HasCommitment();
        if (accepted && !events.WorkerRetired())
        {
            accepted = coordinatorOrder < UINT64_MAX && events.RetireWorker(coordinatorOrder+1);
            if (accepted) ++coordinatorOrder;
        }
        if (!accepted) LatchLocked(Origin::Evidence,12,"worker-terminal-retirement");
        pthread_mutex_unlock(&lock);
        return accepted;
    }

    // Standalone component seal; the finish path seals through PrepareTransportDrain.
    // CopySeal remains diagnostic evidence, not publication authorization.
    bool Seal()
    {
        pthread_mutex_lock(&lock);
        bool accepted=state.configured && !state.failed && state.identity.localNode==1 &&
            workerReceipt.HasCommitment() && events.WorkerRetired();
        if (accepted && !events.Sealed())
        {
            accepted=coordinatorOrder<UINT64_MAX && events.Seal(coordinatorOrder+1,hashSource);
            if (accepted) ++coordinatorOrder;
        }
        if (!accepted) LatchLocked(Origin::Evidence,13,"terminal-seal");
        pthread_mutex_unlock(&lock);return accepted;
    }

    bool CopySeal(DCG01Events::SealArtifacts* output)
    {
        pthread_mutex_lock(&lock);
        const bool copied=state.configured && state.identity.localNode==1 && events.CopySeal(output);
        pthread_mutex_unlock(&lock);return copied;
    }

    bool PrepareTransportDrain()
    {
        pthread_mutex_lock(&lock);
        bool accepted=state.configured && !state.failed && state.identity.localNode==1 &&
            !publication.started && workerReceipt.HasCommitment() && events.WorkerRetired();
        if(accepted && !events.Sealed())
        {
            accepted=coordinatorOrder<UINT64_MAX && events.Seal(coordinatorOrder+1,hashSource);
            if(accepted) ++coordinatorOrder;
        }
        if(accepted) transportDrainStarted=true;
        else LatchLocked(Origin::Evidence,16,"terminal-transport-drain");
        pthread_mutex_unlock(&lock);return accepted;
    }

    bool DrainingRetiredService()
    {
        pthread_mutex_lock(&lock);
        const bool draining=transportDrainStarted && state.configured && !state.failed &&
            state.identity.localNode==1 && events.Sealed() && events.WorkerRetired();
        pthread_mutex_unlock(&lock);return draining;
    }

    // One attempt only. The caller performs durable local I/O outside this lock
    // and returns the actual readback witness; a copied seal alone cannot publish.
    bool BeginRecordPublication(DCG01Events::SealArtifacts* output)
    {
        pthread_mutex_lock(&lock);
        const bool accepted=state.configured && !state.failed && state.identity.localNode==1 &&
            !publication.started && events.CopySeal(output);
        if(accepted) publication.started=true;
        else LatchLocked(Origin::Evidence,14,"record-publication-start");
        pthread_mutex_unlock(&lock);return accepted;
    }

    bool CompleteRecordPublication(const DCG01Record::Witness* witness)
    {
        pthread_mutex_lock(&lock);
        bool accepted=false;
        if(state.configured && state.identity.localNode==1 && publication.started && !publication.finished && witness)
        {
            publication.finished=true;publication.witness=*witness;
            DCG01Events::SealArtifacts sealed{};
            bool valid=events.CopySeal(&sealed) && witness->failure==DCG01Record::Failure::None &&
                witness->errorNumber==0 && witness->fileFlushed && witness->renamed && witness->directoryFlushed &&
                witness->readbackMatched && witness->directoryInode && witness->fileInode &&
                witness->written==sealed.recordBytes && witness->length==sealed.recordBytes &&
                !memcmp(witness->digest,sealed.recordDigest,32) && !memcmp(witness->readback,sealed.record,sealed.recordBytes);
            if(valid && !state.failed && coordinatorOrder<UINT64_MAX && events.PublishRecord(coordinatorOrder+1))
            {
                publication.published=true;publication.transition=++coordinatorOrder;accepted=true;
            }
            else if(!valid || (!state.failed && !publication.published))
            {
                const char* kind=witness->failure==DCG01Record::Failure::Create?"create":
                    witness->failure==DCG01Record::Failure::Write?"write":
                    witness->failure==DCG01Record::Failure::Flush?"flush":
                    witness->failure==DCG01Record::Failure::AtomicPublish?"atomic_publish":
                    witness->failure==DCG01Record::Failure::Readback?"readback":"unknown";
                if(coordinatorOrder<UINT64_MAX && events.RecordWriteFailed(kind,coordinatorOrder+1)) ++coordinatorOrder;
            }
        }
        if(!accepted) LatchLocked(Origin::Evidence,15,"record-publication-incomplete");
        pthread_mutex_unlock(&lock);return accepted;
    }

    bool CopyPublication(PublicationSnapshot* output)
    {
        if(!output) return false;
        pthread_mutex_lock(&lock);
        const bool copied=publication.started;
        if(copied) *output=publication;
        pthread_mutex_unlock(&lock);return copied;
    }

    bool CommitLocal()
    {
        pthread_mutex_lock(&lock);
        const bool accepted = state.configured && !state.failed && state.identity.localNode == 1 && events.CommitLocal();
        if (!accepted) LatchLocked(Origin::Evidence,11,"coordinator-terminal-commitment");
        pthread_mutex_unlock(&lock);
        return accepted;
    }

    bool PrepareEvent(unsigned member, const unsigned char* body, size_t length)
    {
        pthread_mutex_lock(&lock);
        const bool accepted = state.configured && !state.failed && state.identity.localNode == 1 &&
            events.Prepare(member,body,length,hashSource);
        if (!accepted) LatchLocked(Origin::Evidence,8,"terminal-preparation-event");
        pthread_mutex_unlock(&lock);
        return accepted;
    }

    bool MainReturned(int32_t result, uint64_t operation, uint64_t authority, uint64_t publication)
    {
        pthread_mutex_lock(&lock);
        const bool accepted = state.configured && !state.failed && state.identity.localNode == 1 &&
            events.MainReturned(result,operation,authority,publication);
        if (!accepted) LatchLocked(Origin::Evidence,7,"main-return-event");
        pthread_mutex_unlock(&lock);
        return accepted;
    }

    bool RootEvent(unsigned kind, const unsigned char* objects, unsigned count)
    {
        pthread_mutex_lock(&lock);
        const bool accepted = state.configured && !state.failed && state.identity.localNode == 1 &&
            (kind == 1 ? events.InitialRootSet(objects,count) :
             !objects && count == 0 && (kind == 2 ? events.InitialRootsReady() :
             kind == 3 ? events.CaptureRootCut(1) : kind == 4 && events.CaptureRootCut(2)));
        if (!accepted) LatchLocked(Origin::Evidence,5,"root-event-or-obligation");
        pthread_mutex_unlock(&lock);
        return accepted;
    }

    bool AdmissionClosed(unsigned actor, uint64_t generation, uint64_t sequence)
    {
        pthread_mutex_lock(&lock);
        const bool accepted = state.configured && !state.failed && state.identity.localNode == 1 &&
            events.CloseAdmission(actor, generation, sequence);
        if (!accepted) LatchLocked(Origin::Evidence,4,"admission-close-event");
        pthread_mutex_unlock(&lock);
        return accepted;
    }

    bool PublicationEvent(DCG01Events::Publication kind, uint64_t id, const unsigned char* root,
                          const unsigned char* objects, unsigned count)
    {
        pthread_mutex_lock(&lock);
        const bool accepted = state.configured && !state.failed && state.identity.localNode == 1 &&
            events.RecordPublication(kind, id, root, objects, count);
        if (!accepted) LatchLocked(Origin::Evidence,3,"publication-event-or-order");
        pthread_mutex_unlock(&lock);
        return accepted;
    }

    bool AccessEvent(unsigned actor, const unsigned char* request, const unsigned char* reply, size_t length,
                    uint64_t before, DCG01Events::AccessDiagnostic* diagnostic = nullptr)
    {
        if (diagnostic) { *diagnostic = {}; diagnostic->actor = actor; }
        pthread_mutex_lock(&lock);
        const bool accepted = state.configured && !state.failed && state.identity.localNode == 1 &&
            (request ? (length == 120 && events.CommitAccess(actor, request, reply, before, diagnostic)) :
                events.ObserveAccess(actor, reply, length, diagnostic));
        if (!accepted && diagnostic)
        {
            if (state.configured) diagnostic->node = state.identity.localNode;
            if (!state.configured) { diagnostic->phase = "terminal"; diagnostic->check = "unconfigured"; }
            else if (state.failed) { diagnostic->phase = "terminal"; diagnostic->check = "already-failed"; }
            else if (state.identity.localNode != 1) { diagnostic->phase = "terminal"; diagnostic->check = "wrong-node"; }
            else if (request && length != 120) { diagnostic->phase = "request-precondition"; diagnostic->check = "request-length"; }
            else if (!diagnostic->check || !strcmp(diagnostic->check,"none"))
            { diagnostic->phase = "terminal"; diagnostic->check = "unclassified-rejection"; }
            events.SnapshotAccessDiagnostic(diagnostic);
        }
        if (!accepted) LatchLocked(Origin::Evidence,2,"access-event-or-observation");
        pthread_mutex_unlock(&lock);
        return accepted;
    }
};
}

extern "C" bool DistributedThreadTerminalConfigure(const DistributedAdmissionThreadIdentity* identity);
extern "C" void DistributedThreadTerminalFailure(unsigned origin, unsigned code, const char* reason);
extern "C" bool DistributedThreadTerminalHealthy();
extern "C" bool DistributedThreadTerminalPeerDisconnected();
extern "C" bool DistributedThreadTerminalPrepareDrain();
extern "C" bool DistributedThreadTerminalDraining();
extern "C" DCG01Terminal::PublicationResult DistributedThreadTerminalPublishRecord();
extern "C" bool DistributedThreadTerminalPersistFailure();
extern "C" bool DistributedThreadTerminalCopyFailure(DCG01Terminal::FailureSnapshot* output);
extern "C" bool DistributedThreadTerminalLifecycle(unsigned kind, uint64_t frontier);
extern "C" bool DistributedThreadTerminalCopyTrace(unsigned char* output, size_t capacity, size_t* length, uint64_t* count);
extern "C" bool DistributedThreadTerminalAccess(unsigned actor, const unsigned char* request, const unsigned char* reply, size_t length, uint64_t before);
extern "C" bool DistributedThreadTerminalPublication(unsigned kind, uint64_t id, const unsigned char* root, const unsigned char* objects, unsigned count);
extern "C" bool DistributedThreadTerminalAdmissionClosed(unsigned actor, uint64_t generation, uint64_t sequence);
extern "C" bool DistributedThreadTerminalRoots(unsigned kind, const unsigned char* objects, unsigned count);
extern "C" bool DistributedThreadTerminalArtifact(unsigned id, unsigned role, const unsigned char* bytes, size_t length);
extern "C" bool DistributedThreadTerminalMainReturned(int32_t result, uint64_t operation, uint64_t authority, uint64_t publication);
extern "C" bool DistributedThreadTerminalPrepared(unsigned member, const unsigned char* body, size_t length);
extern "C" bool DistributedThreadTerminalCommitWorker(uint64_t operations, uint64_t authority, uint64_t publications,
    const DCG01Custody::Bundle* sent, const unsigned char* ack, size_t ackLength, DCG01Commit::Frame* output);
extern "C" bool DistributedThreadTerminalReceiveWorkerCommit(const DCG01Custody::Bundle* custody,
    const unsigned char* wire, size_t length);
extern "C" bool DistributedThreadTerminalCommitLocal();
extern "C" bool DistributedThreadTerminalRetireWorker();

#endif
