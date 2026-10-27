// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#ifndef DISTRIBUTED_THREAD_EVENTS_H
#define DISTRIBUTED_THREAD_EVENTS_H
#include "distributedadmission.h"
#include "distributedcanonicalwriter.h"
#include "distributedrootobligations.h"
#include "distributedterminalpreimages.h"
#include <string.h>

namespace DCG01Events
{
struct AccessDiagnostic
{
    const char* phase = "terminal";
    const char* check = "none";
    unsigned actor = 0, node = 0;
    uint64_t events = 0, eventLimit = 0;
    size_t used = 0, byteLimit = 0;
};
enum class Lifecycle : unsigned { Admitted = 1, Authorized = 2, Entered = 3, Completed = 4, JoinReturned = 5 };
enum class Publication : unsigned { Prepared = 1, Acknowledged = 2, Activated = 3, Completed = 4 };

// Owned sealing evidence and complete-record preimage; no filesystem publication
// or consumer receipt is implied by these bytes.
struct SealArtifacts
{
    uint64_t prefixEvents = 0, transition = 0;
    size_t prefixBytes = 0, certificateBytes = 0, sealBytes = 0, recordBytes = 0;
    unsigned char certificate[16384]{}, seal[8192]{}, record[16384]{};
    unsigned char certificateDigest[32]{}, recordDigest[32]{};
};

// Coordinator collection order is not cross-member happens-before. Remote lifecycle
// observations enter only after the authenticated protocol ledger accepts their frame.
class Stream
{
public:
    static const size_t MaxBytes = 1024 * 1024;
    static const uint64_t MaxEvents = 2048;
private:
    unsigned char bytes[MaxBytes]{};
    size_t used = 0;
    uint64_t events = 0, memberEvents[2]{}, admitted = 0, authorized = 0, entered = 0, joined = 0, joinCalls = 0;
    unsigned stage = 0;
    uint64_t lastJoinReturned = 0;
    DistributedAdmissionThreadIdentity identity{};
    unsigned char threadId[44]{};
    struct Access
    {
        bool active = false;
        unsigned char request[112]{}, reply[120]{};
        uint64_t before = 0, commitEvent = 0;
    } pending[2];
    uint64_t nextOperation[2]{1, 1}, observedFrontier[2]{}, observedEvent[2]{}, lastAuthority = 0, lastCommitEvent = 0;
    unsigned char lastObservedReply[2][120]{};
    uint64_t publicationId = 0, publicationEvent[2]{}, publicationStoreAuthority = 0;
    unsigned publicationStage = 0, publicationCount = 0;
    unsigned char publicationRoot[44]{}, publicationObjects[16][44]{};
    bool admissionClosed[2]{};
    uint64_t closeGeneration[2]{}, closeSequence[2]{};
    DCG01Roots::Obligations roots;
    bool rootsStarted = false, rootsReady = false, rootCut[2]{};
    unsigned char initialRoots[16][44]{};
    unsigned initialRootCount = 0, rootCauseCount = 0;
    struct RootCause { unsigned char id[44]{}; uint64_t last[2]{}; } rootCauses[64];
    uint64_t lastRoot[2]{}, closeEvent[2]{};
    uint64_t rootCutEvent[2]{}, mainReturnEvent = 0;
    bool failureRecorded = false;
    struct Preparation
    {
        DCG01Preimage::Participant snapshot{};
        uint64_t event = 0;
        size_t length = 0;
        unsigned char body[16384]{}, digest[32]{}, frontier[32]{}, root[32]{}, custody[32]{};
    } preparations[2];
    uint64_t localCommitEvent = 0, workerReceiptEvent = 0;
    uint64_t workerRetirementEvent = 0, workerRetirementOrder = 0;
    DCG01Preimage::MainReturn mainReturn{};
    SealArtifacts sealArtifacts;
    uint64_t recordPublishedEvent=0,recordWriteFailedEvent=0,physicalNoticeEvent=0;
    struct Artifact
    {
        unsigned role = 0;
        size_t length = 0;
        uint64_t event = 0;
        unsigned char digest[32]{}, content[16384]{};
    } artifacts[4]; // Output 1, coordinator evidence 2, worker evidence 3, received commitment body 4.

    bool EmitRootChanges(unsigned member, const DCG01Roots::Changes& changes, bool acquire,
                         uint64_t cause, uint64_t publication = 0)
    {
        for (unsigned i = 0; i < changes.count; ++i)
        {
            unsigned index = 0;
            while (index < rootCauseCount && memcmp(rootCauses[index].id, changes.ids[i], 44)) ++index;
            if (index == rootCauseCount)
            {
                if (rootCauseCount == 64) return false;
                memcpy(rootCauses[index].id, changes.ids[i], 44); ++rootCauseCount;
            }
            if (events >= MaxEvents || cause > events) return false;
            unsigned char record[2048]{};
            DC022Canonical::Writer w(record, sizeof(record));
            uint64_t causes[] = {cause, lastRoot[member - 1], rootCauses[index].last[member - 1]};
            bool ok = w.BeginObject() && w.Key("causes") && w.BeginArray();
            for (unsigned j = 0; j < 3; ++j)
            {
                bool duplicate = false;
                for (unsigned k = 0; k < j; ++k) if (causes[k] == causes[j]) duplicate = true;
                if (causes[j] && !duplicate) ok = ok && w.UInt(causes[j]);
            }
            ok = ok && w.EndArray() && w.Key("incarnation_id") && w.Hex(identity.memberIncarnations[member - 1],16) &&
                w.Key("kind") && w.String("root.owner_transition") && w.Key("member_id") && w.UInt(member) &&
                w.Key("member_seq") && w.UInt(memberEvents[member - 1] + 1) && w.Key("payload") && w.BeginObject() &&
                w.Key("from_member_id") && (acquire ? w.Null() : w.UInt(member)) &&
                w.Key("object_id") && w.Hex(changes.ids[i],44) && w.Key("publication_id") &&
                (publication ? w.UInt(publication) : w.Null()) && w.Key("to_member_id") &&
                (acquire ? w.UInt(member) : w.Null()) && w.Key("transition") &&
                (acquire ? w.String("acquire") : w.String("release")) &&
                w.Key("transition_id") && w.UInt(events + 1) && w.EndObject() && w.Key("record") &&
                w.String("event") && w.Key("trace_seq") && w.UInt(events + 1) && w.EndObject() && w.Finish();
            if (!ok || w.Size() > MaxBytes - used) return false;
            memcpy(bytes + used,w.Data(),w.Size()); used += w.Size(); ++events; ++memberEvents[member - 1];
            lastRoot[member - 1] = events; rootCauses[index].last[member - 1] = events;
        }
        return true;
    }

    bool PublicationRoots(unsigned member, unsigned reason, bool acquire, uint64_t cause)
    {
        if (!rootsStarted) return true; // Legacy component probes do not request root capture.
        DCG01Roots::Changes changes;
        return rootsReady && (acquire ? roots.Acquire(member,publicationObjects[0],publicationCount,reason,&changes) :
            roots.Release(member,publicationObjects[0],publicationCount,reason,&changes)) &&
            EmitRootChanges(member,changes,acquire,cause,publicationId);
    }

    uint64_t ActorCause(unsigned actor) const
    {
        uint64_t cause = observedEvent[actor - 1];
        if (publicationEvent[actor - 1] > cause) cause = publicationEvent[actor - 1];
        if (actor == 1 && lastJoinReturned > cause) cause = lastJoinReturned;
        if (actor == 1 && mainReturnEvent > cause) cause = mainReturnEvent;
        return cause ? cause : actor == 1 ? authorized : entered;
    }

    static uint64_t U64(const unsigned char* p)
    { uint64_t value = 0; for (unsigned i = 0; i != 8; ++i) value |= uint64_t(p[i]) << (i * 8); return value; }
    static uint32_t U32(const unsigned char* p)
    { uint32_t value = 0; for (unsigned i = 0; i != 4; ++i) value |= uint32_t(p[i]) << (i * 8); return value; }
    bool Logical(const unsigned char* id, bool allowNull) const
    {
        unsigned nonzero = 0; for (unsigned i = 0; i != 44; ++i) nonzero |= id[i];
        if (!nonzero) return allowNull;
        const unsigned creator = U32(id + 16);
        return creator >= 1 && creator <= 2 && memcmp(id, identity.run, 16) == 0 &&
            memcmp(id + 20, identity.memberIncarnations[creator - 1], 16) == 0 &&
            U64(id + 36) >= 1 && U64(id + 36) <= 64;
    }
    static void RejectAccess(AccessDiagnostic* diagnostic, const char* phase, const char* check)
    {
        if (diagnostic) { diagnostic->phase = phase; diagnostic->check = check; }
    }
    const char* CommitAccessPrecondition(unsigned actor, const unsigned char* request,
                                         const unsigned char* reply, uint64_t before) const
    {
        if (!used) return "not-started";
        if (actor < 1 || actor > 2) return "actor-range";
        if (!request) return "request-null";
        if (!reply) return "reply-null";
        if (stage < 2) return "stage-before-authorized";
        if (actor == 2 && stage != 3) return "worker-stage";
        if (actor == 1 && mainReturnEvent) return "main-returned";
        if (admissionClosed[actor - 1]) return "admission-closed";
        if (pending[actor - 1].active) return "operation-pending";
        if (memcmp(request, "DAO1", 4)) return "request-magic";
        if (U32(request + 4) != 1) return "request-version";
        if (memcmp(reply, "DAP1", 4)) return "reply-magic";
        if (U32(reply + 4) != 1) return "reply-version";
        if (U64(request + 8) != nextOperation[actor - 1]) return "operation-sequence";
        if (U64(reply + 8) != U64(request + 8)) return "reply-operation-sequence";
        if (U64(reply + 16) != lastAuthority + 1) return "authority-sequence";
        if (before != observedFrontier[actor - 1]) return "observed-frontier";
        if (before >= U64(reply + 16)) return "authority-not-advanced";
        if (U32(request + 16) > 5) return "operation-kind";
        if (U32(reply + 24) != U32(request + 16)) return "reply-operation-kind";
        if (U32(reply + 28) != U32(request + 20)) return "reply-slot";
        if (memcmp(request + 24, reply + 32, 44)) return "reply-object";
        if (!Logical(request + 24, false)) return "object-identity";
        const unsigned operation = U32(request + 16);
        if (actor == 1 && publicationStage && (publicationStage != 3 || publicationStoreAuthority ||
            operation != 3 || memcmp(request + 68, publicationRoot, 44))) return "publication-store";
        const bool reference = operation == 2 || operation == 3;
        if (reference && (!Logical(request + 68, true) || !Logical(reply + 76, true))) return "reference-identity";
        for (unsigned i = (operation & 1) ? (reference ? 44 : 4) : 0; i != 44; ++i)
            if (request[68 + i]) return "request-value-padding";
        if (!reference) for (unsigned i = 4; i != 44; ++i)
            if (reply[76 + i]) return "reply-value-padding";
        if ((operation & 1) && memcmp(request + 68, reply + 76, 44)) return "write-value";
        return nullptr;
    }
    bool EmitAccess(unsigned phase, unsigned actor, const Access& a, uint64_t cause, uint64_t otherCause,
                    AccessDiagnostic* diagnostic)
    {
        const char* phaseName = phase == 0 ? "request-event" : phase == 1 ? "commit-event" : "observation-event";
        const unsigned member = phase == 1 ? 1 : actor;
        if (events >= MaxEvents) { RejectAccess(diagnostic, phaseName, "event-capacity"); return false; }
        if (cause > events || otherCause > events) { RejectAccess(diagnostic, phaseName, "causal-bound"); return false; }
        unsigned char record[2048]{};
        DC022Canonical::Writer w(record, sizeof(record));
        const unsigned operation = U32(a.request + 16);
        const bool reference = operation == 2 || operation == 3;
        const char* name = phase == 0 ? "access.requested" : phase == 1 ? "access.committed" : "access.observed";
        const char* op = reference ? ((operation & 1) ? "write_ref" : "read_ref") :
            ((operation & 1) ? "write_i32" : "read_i32");
        bool ok = w.BeginObject() && w.Key("causes") && w.BeginArray();
        if (cause) ok = ok && w.UInt(cause);
        if (otherCause && otherCause != cause) ok = ok && w.UInt(otherCause);
        ok = ok && w.EndArray() && w.Key("incarnation_id") && w.Hex(identity.memberIncarnations[member - 1], 16) &&
            w.Key("kind") && w.String(name, strlen(name)) && w.Key("member_id") && w.UInt(member) &&
            w.Key("member_seq") && w.UInt(memberEvents[member - 1] + 1) && w.Key("payload") && w.BeginObject() &&
            w.Key("actor") && w.BeginObject() && w.Key("kind");
        if (actor == 1) ok = ok && w.String("main");
        else ok = ok && w.String("thread") && w.Key("thread_id") && w.Hex(threadId, 44);
        ok = ok && w.EndObject() && w.Key("authority_frontier_before") && w.UInt(a.before);
        if (phase != 0) ok = ok && w.Key("authority_sequence") && w.UInt(U64(a.reply + 16));
        ok = ok && w.Key("member_operation_sequence") && w.UInt(U64(a.request + 8)) &&
            w.Key("object_id") && w.Hex(a.request + 24, 44) && w.Key("operation") && w.String(op, strlen(op)) &&
            w.Key("slot") && w.UInt(U32(a.request + 20));
        if (phase != 0 || (operation & 1))
        {
            const unsigned char* value = phase == 0 ? a.request + 68 : a.reply + 76;
            ok = ok && w.Key("value");
            if (!reference) ok = ok && w.Int(static_cast<int32_t>(U32(value)));
            else
            {
                unsigned nonzero = 0; for (unsigned i = 0; i != 44; ++i) nonzero |= value[i];
                ok = ok && (nonzero ? w.Hex(value, 44) : w.Null());
            }
        }
        ok = ok && w.EndObject() && w.Key("record") && w.String("event") &&
            w.Key("trace_seq") && w.UInt(events + 1) && w.EndObject() && w.Finish();
        if (!ok) { RejectAccess(diagnostic, phaseName, "encoding"); return false; }
        if (w.Size() > MaxBytes - used) { RejectAccess(diagnostic, phaseName, "byte-capacity"); return false; }
        memcpy(bytes + used, w.Data(), w.Size()); used += w.Size(); ++events; ++memberEvents[member - 1];
        return true;
    }

    bool EmitPublication(unsigned kind, unsigned member, uint64_t cause, uint64_t otherCause = 0)
    {
        if (events >= MaxEvents || cause > events || otherCause > events) return false;
        static const char* const names[] = {"", "publication.prepared", "publication.sent",
            "publication.received", "publication.imported", "publication.activated", "publication.completed"};
        if (kind < 1 || kind > 6 || member < 1 || member > 2) return false;
        unsigned char record[2048]{};
        DC022Canonical::Writer w(record, sizeof(record));
        bool ok = w.BeginObject() && w.Key("causes") && w.BeginArray();
        if (cause) ok = ok && w.UInt(cause);
        if (otherCause && otherCause != cause) ok = ok && w.UInt(otherCause);
        ok = ok && w.EndArray() && w.Key("incarnation_id") && w.Hex(identity.memberIncarnations[member - 1], 16) &&
            w.Key("kind") && w.String(names[kind], strlen(names[kind])) && w.Key("member_id") && w.UInt(member) &&
            w.Key("member_seq") && w.UInt(memberEvents[member - 1] + 1) && w.Key("payload") && w.BeginObject();
        if (kind == 1 || kind == 4)
        {
            ok = ok && w.Key("object_ids") && w.BeginArray();
            for (unsigned i = 0; i < publicationCount; ++i) ok = ok && w.Hex(publicationObjects[i], 44);
            ok = ok && w.EndArray();
        }
        else ok = ok && w.Key("object_count") && w.UInt(publicationCount);
        if (kind == 2 || kind == 3) ok = ok && w.Key("peer_member_id") && w.UInt(member == 1 ? 2 : 1);
        ok = ok && w.Key("publication_id") && w.UInt(publicationId);
        if (kind != 2 && kind != 3) ok = ok && w.Key("root_id") && w.Hex(publicationRoot, 44);
        ok = ok && w.EndObject() && w.Key("record") && w.String("event") && w.Key("trace_seq") &&
            w.UInt(events + 1) && w.EndObject() && w.Finish();
        if (!ok || w.Size() > MaxBytes - used) return false;
        memcpy(bytes + used, w.Data(), w.Size()); used += w.Size(); ++events; ++memberEvents[member - 1];
        return true;
    }

    bool Emit(unsigned kind, unsigned member, uint64_t cause, uint64_t frontier, uint64_t otherCause = 0)
    {
        if (events >= MaxEvents || cause > events || otherCause > events) return false;
        unsigned char record[2048]{};
        DC022Canonical::Writer w(record, sizeof(record));
        static const char* const names[] = {"", "thread.admitted", "thread.start_authorized",
            "thread.callback_entered", "thread.callback_returned", "thread.physical_join_observed", "thread.join_returned"};
        if (kind < 1 || kind > 6 || member < 1 || member > 2) return false;
        bool ok = w.BeginObject() && w.Key("causes") && w.BeginArray();
        if (cause) ok = ok && w.UInt(cause);
        if (otherCause && otherCause != cause) ok = ok && w.UInt(otherCause);
        ok = ok && w.EndArray() && w.Key("incarnation_id") && w.Hex(identity.memberIncarnations[member - 1], 16) &&
            w.Key("kind") && w.String(names[kind], strlen(names[kind])) &&
            w.Key("member_id") && w.UInt(member) && w.Key("member_seq") && w.UInt(memberEvents[member - 1] + 1) &&
            w.Key("payload") && w.BeginObject();
        if (kind == 1)
            ok = ok && w.Key("parent_actor") && w.BeginObject() && w.Key("kind") && w.String("main") && w.EndObject();
        if (kind == 2) ok = ok && w.Key("authorization_id") && w.UInt(1);
        if (kind == 4) ok = ok && w.Key("outcome") && w.String("returned");
        if (kind == 6)
            ok = ok && w.Key("abort_latch_id") && w.Null() && w.Key("caller_actor") && w.BeginObject() &&
                w.Key("kind") && w.String("main") && w.EndObject() &&
                w.Key("completion_frontier") && w.UInt(frontier) && w.Key("join_call_id") && w.UInt(joinCalls + 1) &&
                w.Key("outcome") && w.String("returned");
        ok = ok && w.Key("thread_id") && w.Hex(threadId, sizeof(threadId)) && w.EndObject() &&
            w.Key("record") && w.String("event") && w.Key("trace_seq") && w.UInt(events + 1) && w.EndObject() && w.Finish();
        if (!ok || w.Size() > MaxBytes - used) return false;
        memcpy(bytes + used, w.Data(), w.Size());
        used += w.Size(); ++events; ++memberEvents[member - 1];
        return true;
    }
public:
    void SnapshotAccessDiagnostic(AccessDiagnostic* diagnostic) const
    {
        if (!diagnostic) return;
        diagnostic->events = events; diagnostic->eventLimit = MaxEvents;
        diagnostic->used = used; diagnostic->byteLimit = MaxBytes;
    }
    bool Configure(const DistributedAdmissionThreadIdentity& id)
    {
        if (used || id.localNode != 1) return false;
        unsigned char header[2048]{};
        DC022Canonical::Writer w(header, sizeof(header));
        bool ok = w.BeginObject() && w.Key("build_manifest_sha256") && w.Hex(id.buildManifestSha256, 32) &&
            w.Key("coordinator_member_id") && w.UInt(1) && w.Key("members") && w.BeginArray();
        for (unsigned i = 0; i != 2; ++i)
            ok = ok && w.BeginObject() && w.Key("incarnation_id") && w.Hex(id.memberIncarnations[i], 16) &&
                w.Key("member_id") && w.UInt(i + 1) && w.Key("role") &&
                (i == 0 ? w.String("coordinator") : w.String("worker")) && w.EndObject();
        ok = ok && w.EndArray() && w.Key("record") && w.String("header") && w.Key("run_id") && w.Hex(id.run, 16) &&
            w.Key("run_manifest_sha256") && w.Hex(id.runManifestSha256, 32) &&
            w.Key("runtime_profile") && w.String("dc013-instance-thread-linux-x64-v1") &&
            w.Key("schema") && w.String("dc022-thread-trace") && w.Key("trace_profile") && w.String("thread-object-v1") &&
            w.Key("version") && w.UInt(1) && w.EndObject() && w.Finish();
        if (!ok) return false;
        identity = id;
        memcpy(threadId, id.run, 16); threadId[16] = 1;
        memcpy(threadId + 20, id.memberIncarnations[0], 16); threadId[36] = 1;
        memcpy(bytes, w.Data(), w.Size()); used = w.Size();
        return true;
    }

    bool Record(Lifecycle kind, uint64_t frontier)
    {
        if (!used) return false;
        switch (kind)
        {
            case Lifecycle::Admitted:
                if (stage != 0 || !Emit(1, 1, 0, 0)) return false;
                admitted = events; stage = 1; return true;
            case Lifecycle::Authorized:
                if (stage != 1 || !Emit(2, 1, admitted, 0)) return false;
                authorized = events; stage = 2; return true;
            case Lifecycle::Entered:
                if (stage != 2 || !Emit(3, 2, authorized, 0)) return false;
                entered = events; stage = 3; return true;
            case Lifecycle::Completed:
                if (stage != 3 || pending[1].active || !Emit(4, 2, entered, 0, ActorCause(2)) || !Emit(5, 1, events, 0)) return false;
                joined = events; stage = 4; return true;
            case Lifecycle::JoinReturned:
                if (stage != 4 || mainReturnEvent || admissionClosed[0] || pending[0].active || publicationStage || !Emit(6, 1, joined, frontier, ActorCause(1))) return false;
                lastJoinReturned = events; ++joinCalls; return true;
        }
        return false;
    }

    bool CommitAccess(unsigned actor, const unsigned char* request, const unsigned char* reply, uint64_t before,
                      AccessDiagnostic* diagnostic = nullptr)
    {
        if (!used || actor < 1 || actor > 2 || !request || !reply || stage < 2 ||
            (actor == 2 && stage != 3) || (actor == 1 && mainReturnEvent) || admissionClosed[actor - 1] || pending[actor - 1].active ||
            memcmp(request, "DAO1", 4) || U32(request + 4) != 1 ||
            memcmp(reply, "DAP1", 4) || U32(reply + 4) != 1 ||
            U64(request + 8) != nextOperation[actor - 1] || U64(reply + 8) != U64(request + 8) ||
            U64(reply + 16) != lastAuthority + 1 || before != observedFrontier[actor - 1] ||
            before >= U64(reply + 16) || U32(request + 16) > 5 ||
            U32(reply + 24) != U32(request + 16) || U32(reply + 28) != U32(request + 20) ||
            memcmp(request + 24, reply + 32, 44) || !Logical(request + 24, false))
        {
            RejectAccess(diagnostic, "commit-precondition", CommitAccessPrecondition(actor, request, reply, before));
            return false;
        }
        const unsigned operation = U32(request + 16);
        if (actor == 1 && publicationStage && (publicationStage != 3 || publicationStoreAuthority ||
            operation != 3 || memcmp(request + 68, publicationRoot, 44)))
        { RejectAccess(diagnostic, "commit-precondition", "publication-store"); return false; }
        const bool reference = operation == 2 || operation == 3;
        if (reference && (!Logical(request + 68, true) || !Logical(reply + 76, true)))
        { RejectAccess(diagnostic, "commit-precondition", "reference-identity"); return false; }
        for (unsigned i = (operation & 1) ? (reference ? 44 : 4) : 0; i != 44; ++i)
            if (request[68 + i]) { RejectAccess(diagnostic, "commit-precondition", "request-value-padding"); return false; }
        if (!reference) for (unsigned i = 4; i != 44; ++i)
            if (reply[76 + i]) { RejectAccess(diagnostic, "commit-precondition", "reply-value-padding"); return false; }
        if ((operation & 1) && memcmp(request + 68, reply + 76, 44))
        { RejectAccess(diagnostic, "commit-precondition", "write-value"); return false; }
        Access a{}; a.active = true; a.before = before;
        memcpy(a.request, request, 112); memcpy(a.reply, reply, 120);
        const uint64_t cause = ActorCause(actor);
        if (!EmitAccess(0, actor, a, cause, 0, diagnostic)) return false;
        const uint64_t requested = events;
        if (!EmitAccess(1, actor, a, requested, lastCommitEvent, diagnostic)) return false;
        a.commitEvent = events; pending[actor - 1] = a;
        lastCommitEvent = events; lastAuthority = U64(reply + 16); ++nextOperation[actor - 1];
        if (actor == 1 && publicationStage == 3) publicationStoreAuthority = lastAuthority;
        return true;
    }

    bool ObserveAccess(unsigned actor, const unsigned char* reply, size_t length, AccessDiagnostic* diagnostic = nullptr)
    {
        if (actor < 1 || actor > 2 || !reply || length != 120 || !used)
        {
            const char* check = actor < 1 || actor > 2 ? "actor-range" : !reply ? "reply-null" :
                length != 120 ? "reply-length" : "not-started";
            RejectAccess(diagnostic, "observation-precondition", check);
            return false;
        }
        const unsigned index = actor - 1;
        if (observedEvent[index] && memcmp(lastObservedReply[index], reply, 120) == 0) return true;
        Access& a = pending[index];
        if (!a.active) { RejectAccess(diagnostic, "observation-precondition", "no-pending-operation"); return false; }
        if (memcmp(a.reply, reply, 120)) { RejectAccess(diagnostic, "observation-precondition", "reply-mismatch"); return false; }
        if (!EmitAccess(2, actor, a, a.commitEvent, publicationEvent[index], diagnostic)) return false;
        observedFrontier[index] = U64(reply + 16); observedEvent[index] = events;
        memcpy(lastObservedReply[index], reply, 120); a.active = false;
        return true;
    }

    bool RecordPublication(Publication kind, uint64_t id, const unsigned char* root,
                           const unsigned char* objects, unsigned count)
    {
        if (!used || stage < 3 || mainReturnEvent || admissionClosed[0] || id == 0 || id > 64) return false;
        if (kind == Publication::Prepared)
        {
            if (stage != 3 || publicationStage || pending[0].active || id != publicationId + 1 ||
                !root || !objects || count == 0 || count > 16 || !Logical(root, false)) return false;
            bool found = false;
            for (unsigned i = 0; i < count; ++i)
            {
                const unsigned char* object = objects + i * 44;
                if (!Logical(object, false) || U32(object + 16) != 1) return false;
                if (memcmp(root, object, 44) == 0) found = true;
                for (unsigned j = 0; j < i; ++j) if (memcmp(object, objects + j * 44, 44) == 0) return false;
            }
            if (!found) return false;
            publicationId = id; publicationCount = count; publicationStoreAuthority = 0;
            memcpy(publicationRoot, root, 44); memcpy(publicationObjects, objects, count * 44);
            if (!EmitPublication(1, 1, ActorCause(1))) return false;
            publicationEvent[0] = events; publicationStage = 1;
            return PublicationRoots(1, DCG01Roots::Application | DCG01Roots::InFlight, true, publicationEvent[0]);
        }
        if (id != publicationId || root || objects || count) return false;
        switch (kind)
        {
            case Publication::Acknowledged:
                // Called only for the first validated DPA1 receipt. Its exact offer
                // digest corroborates send, receive and completed receiver import.
                if (publicationStage != 1 || !EmitPublication(2, 1, publicationEvent[0])) return false;
                publicationEvent[0] = events;
                if (!EmitPublication(3, 2, events, ActorCause(2)) || !EmitPublication(4, 2, events)) return false;
                publicationEvent[1] = events; publicationStage = 2;
                return PublicationRoots(2, DCG01Roots::Application, true, publicationEvent[1]);
            case Publication::Activated:
                if (publicationStage != 2 || !EmitPublication(5, 1, publicationEvent[1], ActorCause(1))) return false;
                publicationEvent[0] = events; publicationStage = 3; return true;
            case Publication::Completed:
                if (publicationStage != 3 || pending[0].active || publicationStoreAuthority == 0 ||
                    observedFrontier[0] != publicationStoreAuthority || !EmitPublication(6, 1, ActorCause(1))) return false;
                publicationEvent[0] = events; publicationStage = 0;
                return PublicationRoots(1, DCG01Roots::InFlight, false, publicationEvent[0]);
            default: return false;
        }
    }

    bool CloseAdmission(unsigned actor, uint64_t generation, uint64_t sequence)
    {
        if (!used || actor < 1 || actor > 2 || generation != 2 || stage != 4) return false;
        const unsigned index = actor - 1;
        if (admissionClosed[index]) return generation == closeGeneration[index] && sequence == closeSequence[index];
        if (pending[index].active || sequence != nextOperation[index] - 1 ||
            (actor == 1 && (publicationStage || !lastJoinReturned)) || events >= MaxEvents) return false;
        unsigned char record[2048]{};
        DC022Canonical::Writer w(record, sizeof(record));
        const uint64_t cause = ActorCause(actor);
        bool ok = w.BeginObject() && w.Key("causes") && w.BeginArray() && w.UInt(cause);
        if (actor == 2 && joined != cause) ok = ok && w.UInt(joined);
        ok = ok && w.EndArray() && w.Key("incarnation_id") && w.Hex(identity.memberIncarnations[index], 16) &&
            w.Key("kind") && w.String("member.admission_closed") && w.Key("member_id") && w.UInt(actor) &&
            w.Key("member_seq") && w.UInt(memberEvents[index] + 1) && w.Key("payload") && w.BeginObject() &&
            w.Key("admission_generation") && w.UInt(generation) && w.Key("last_accepted_operation_sequence") &&
            w.UInt(sequence) && w.Key("terminal_epoch") && w.UInt(1) && w.EndObject() && w.Key("record") &&
            w.String("event") && w.Key("trace_seq") && w.UInt(events + 1) && w.EndObject() && w.Finish();
        if (!ok || w.Size() > MaxBytes - used) return false;
        memcpy(bytes + used, w.Data(), w.Size()); used += w.Size(); ++events; ++memberEvents[index];
        admissionClosed[index] = true; closeGeneration[index] = generation; closeSequence[index] = sequence;
        closeEvent[index] = events;
        return true;
    }

    bool InitialRootSet(const unsigned char* objects, unsigned count)
    {
        if (!used || stage != 1 || rootsStarted || !objects || count != 2 ||
            !roots.Configure(identity.run,identity.memberIncarnations[0])) return false;
        for (unsigned i = 0; i < count; ++i)
            if (!Logical(objects + i * 44,false) || U32(objects + i * 44 + 16) != 1) return false;
        DCG01Roots::Changes changes;
        if (!roots.Acquire(1,objects,count,DCG01Roots::Application | DCG01Roots::InFlight,&changes) ||
            !EmitRootChanges(1,changes,true,admitted)) return false;
        memcpy(initialRoots,objects,count * 44); initialRootCount = count; rootsStarted = true;
        return true;
    }

    bool InitialRootsReady()
    {
        if (!used || stage != 1 || !rootsStarted || rootsReady) return false;
        DCG01Roots::Changes changes;
        if (!roots.Acquire(2,initialRoots[0],initialRootCount,DCG01Roots::Application,&changes) ||
            !EmitRootChanges(2,changes,true,lastRoot[0]) ||
            !roots.Release(1,initialRoots[0],initialRootCount,DCG01Roots::InFlight,&changes) || changes.count) return false;
        rootsReady = true;
        return true;
    }

    bool CaptureRootCut(unsigned member)
    {
        if (member < 1 || member > 2 || !rootsReady || !admissionClosed[member - 1] ||
            rootCauseCount != 4 || roots.HistoricalObjects() != 4 || !roots.Healthy()) return false;
        if (rootCut[member - 1]) return true; // Only after exact upstream custody deduplication.
        for (unsigned i = 0; i < rootCauseCount; ++i)
            if (roots.Reasons(member,rootCauses[i].id) != DCG01Roots::Application) return false;
        DCG01Roots::Changes changes;
        if (!roots.CloseApplication(member,&changes) || changes.count != 4 ||
            !EmitRootChanges(member,changes,false,closeEvent[member - 1]) || events >= MaxEvents) return false;
        unsigned char record[2048]{};
        DC022Canonical::Writer w(record,sizeof(record));
        bool ok = w.BeginObject() && w.Key("causes") && w.BeginArray() &&
            w.UInt(lastRoot[member - 1]) && w.UInt(closeEvent[member - 1]) && w.EndArray() &&
            w.Key("incarnation_id") && w.Hex(identity.memberIncarnations[member - 1],16) &&
            w.Key("kind") && w.String("root.inventory_chunk") && w.Key("member_id") && w.UInt(member) &&
            w.Key("member_seq") && w.UInt(memberEvents[member - 1] + 1) && w.Key("payload") && w.BeginObject() &&
            w.Key("chunk_count") && w.UInt(0) && w.Key("chunk_index") && w.UInt(0) &&
            w.Key("object_ids") && w.BeginArray() && w.EndArray() &&
            w.Key("owner_member_id") && w.UInt(member) && w.Key("snapshot_id") && w.UInt(1) &&
            w.EndObject() && w.Key("record") && w.String("event") && w.Key("trace_seq") &&
            w.UInt(events + 1) && w.EndObject() && w.Finish();
        if (!ok || w.Size() > MaxBytes - used) return false;
        memcpy(bytes + used,w.Data(),w.Size()); used += w.Size(); ++events; ++memberEvents[member - 1];
        rootCut[member - 1] = true;
        rootCutEvent[member - 1] = events;
        return true;
    }

    // Digest is computed from the immutable input bytes by the native control entry.
    bool CaptureArtifact(unsigned id, unsigned role, const unsigned char* content, size_t length,
                         const unsigned char* digest)
    {
        if (!used || id < 1 || id > 3 || !content || !digest || length > 16384 ||
            role != (id == 1 ? 1u : 2u)) return false;
        Artifact& artifact = artifacts[id - 1];
        const bool owned = artifact.role != 0;
        if (owned && (artifact.role != role || artifact.length != length ||
            memcmp(artifact.digest,digest,32) || memcmp(artifact.content,content,length))) return false;
        if (artifact.event) return true;
        if (id == 1 && !mainReturnEvent)
        {
            if (stage != 4 || !lastJoinReturned || pending[0].active || publicationStage) return false;
            // Retain the actual published bytes before CorHost releases them.
            // Canonical custody is observed only after the Main-return record.
            if (!owned)
            {
                artifact.role = role; artifact.length = length;
                memcpy(artifact.digest,digest,32); memcpy(artifact.content,content,length);
            }
            return true;
        }
        const uint64_t cause = id == 1 ? mainReturnEvent : rootCutEvent[id - 2];
        if (!mainReturnEvent || !cause || events >= MaxEvents) return false;
        unsigned char record[32768]{};
        DC022Canonical::Writer w(record,sizeof(record));
        bool ok = w.BeginObject() && w.Key("causes") && w.BeginArray() && w.UInt(cause);
        if (cause != mainReturnEvent) ok = ok && w.UInt(mainReturnEvent);
        ok = ok && w.EndArray() &&
            w.Key("incarnation_id") && w.Hex(identity.memberIncarnations[0],16) &&
            w.Key("kind") && w.String("artifact.custodied") && w.Key("member_id") && w.UInt(1) &&
            w.Key("member_seq") && w.UInt(memberEvents[0] + 1) && w.Key("payload") && w.BeginObject() &&
            w.Key("artifact_id") && w.UInt(id) && w.Key("content_b64") && w.Base64(content,length) &&
            w.Key("content_bytes") && w.UInt(length) && w.Key("role") &&
            (role == 1 ? w.String("application_output") : w.String("terminal_evidence")) &&
            w.Key("sha256") && w.Hex(digest,32) && w.EndObject() && w.Key("record") && w.String("event") &&
            w.Key("trace_seq") && w.UInt(events + 1) && w.EndObject() && w.Finish();
        if (!ok || w.Size() > MaxBytes - used) return false;
        memcpy(bytes + used,w.Data(),w.Size()); used += w.Size(); ++events; ++memberEvents[0];
        artifact.role = role; artifact.length = length; artifact.event = events;
        if (!owned) { memcpy(artifact.digest,digest,32); memcpy(artifact.content,content,length); }
        return true;
    }

    bool MatchesPreparedWorkerCustody(const unsigned char* bundle, size_t length) const
    {
        if (!bundle || length < 16 || length > 4096 || memcmp(bundle,"DCB1",4) || U32(bundle+4) != 1)
            return false;
        const size_t bodyLength = U32(bundle+8), evidenceLength = U32(bundle+12);
        const Preparation& p = preparations[1];
        return p.event && artifacts[2].event && bodyLength == p.length && evidenceLength == artifacts[2].length &&
            bodyLength <= length - 16 && evidenceLength == length - 16 - bodyLength &&
            !memcmp(bundle+16,p.body,bodyLength) && !memcmp(bundle+16+bodyLength,artifacts[2].content,evidenceLength);
    }

    bool Prepare(unsigned member, const unsigned char* body, size_t length, DCG01Preimage::HashFunction hash)
    {
        if (!used || failureRecorded || member < 1 || member > 2 || !body || !length || length > 16384 || !hash)
            return false;
        const unsigned index = member - 1;
        Preparation& saved = preparations[index];
        if (saved.event) return saved.length == length && !memcmp(saved.body,body,length);
        if (stage != 4 || !admissionClosed[index] || !rootCut[index] || pending[index].active ||
            !artifacts[member].event || (member == 1 && (!mainReturnEvent || publicationStage)) ||
            events >= MaxEvents) return false;
        DCG01Preimage::Identity id{};
        memcpy(id.runId,identity.run,16); memcpy(id.buildDigest,identity.buildManifestSha256,32);
        memcpy(id.runManifestDigest,identity.runManifestSha256,32);
        memcpy(id.incarnation,identity.memberIncarnations,sizeof(id.incarnation));
        DCG01Preimage::Participant participant{};
        participant.memberId = member; participant.snapshotId = 1;
        DCG01Preimage::Prepared& p = participant.prepared;
        p.terminalEpoch = 1; p.lastOperation = closeSequence[index];
        p.authorityFrontier = member == 1 ? lastAuthority : observedFrontier[index];
        p.publicationFrontier = publicationId;
        p.joinedCount = 1; memcpy(p.joinedThreadIds[0].bytes,threadId,44);
        if (member == 1) { p.resultArtifactCount = 1; p.resultArtifactIds[0] = 1; }
        p.evidenceArtifactId = member + 1; p.evidenceBytes = artifacts[member].content;
        p.evidenceLength = artifacts[member].length; memcpy(p.evidenceDigest,artifacts[member].digest,32);
        unsigned char root[512]{}, expected[16384]{}, digest[32]{}, frontier[32]{}, custody[32]{};
        DCG01Preimage::Artifact owned[2]{};
        owned[0] = {member + 1, DCG01Preimage::TerminalEvidence, artifacts[member].content, artifacts[member].length};
        if (member == 1) owned[1] = {1, DCG01Preimage::ApplicationOutput, artifacts[0].content, artifacts[0].length};
        size_t rootLength = 0, expectedLength = 0;
        if (!DCG01Preimage::RootInventory(id,participant,hash,root,sizeof(root),&rootLength,p.rootInventoryDigest) ||
            !DCG01Preimage::EncodeParticipant(id,participant,hash,expected,sizeof(expected),&expectedLength,digest) ||
            expectedLength != length || memcmp(expected,body,length) ||
            !DCG01Preimage::FrontierDigest(id,participant,hash,frontier) ||
            !DCG01Preimage::OutputEvidenceCustodyDigest(id,participant,owned,member == 1 ? 2 : 1,hash,custody)) return false;
        unsigned char record[4096]{};
        DC022Canonical::Writer w(record,sizeof(record));
        bool ok = w.BeginObject() && w.Key("causes") && w.BeginArray() &&
            w.UInt(closeEvent[index]) && w.UInt(rootCutEvent[index]);
        // Remote preparation predates receipt: local custody validates its bytes,
        // but is not a causal predecessor of the worker's snapshot transition.
        if (member == 1) ok = ok && w.UInt(artifacts[member].event) && w.UInt(mainReturnEvent) && w.UInt(artifacts[0].event);
        ok = ok && w.EndArray() && w.Key("incarnation_id") && w.Hex(identity.memberIncarnations[index],16) &&
            w.Key("kind") && w.String("member.terminal_prepared") && w.Key("member_id") && w.UInt(member) &&
            w.Key("member_seq") && w.UInt(memberEvents[index] + 1) && w.Key("payload") && w.BeginObject() &&
            w.Key("authority_frontier") && w.UInt(p.authorityFrontier) &&
            w.Key("evidence_artifact_id") && w.UInt(p.evidenceArtifactId) &&
            w.Key("evidence_bytes") && w.UInt(p.evidenceLength) && w.Key("evidence_sha256") && w.Hex(p.evidenceDigest,32) &&
            w.Key("joined_thread_ids") && w.BeginArray() && w.Hex(threadId,44) && w.EndArray() &&
            w.Key("last_member_operation_sequence") && w.UInt(p.lastOperation) &&
            w.Key("open_operation_sequences") && w.BeginArray() && w.EndArray() &&
            w.Key("open_publication_ids") && w.BeginArray() && w.EndArray() &&
            w.Key("publication_frontier") && w.UInt(p.publicationFrontier) &&
            w.Key("result_artifact_ids") && w.BeginArray();
        if (member == 1) ok = ok && w.UInt(1);
        ok = ok && w.EndArray() && w.Key("root_inventory_sha256") && w.Hex(p.rootInventoryDigest,32) &&
            w.Key("terminal_epoch") && w.UInt(1) && w.EndObject() && w.Key("record") && w.String("event") &&
            w.Key("trace_seq") && w.UInt(events + 1) && w.EndObject() && w.Finish();
        if (!ok || w.Size() > MaxBytes - used) return false;
        memcpy(bytes + used,w.Data(),w.Size()); used += w.Size(); ++events; ++memberEvents[index];
        memcpy(saved.body,body,length); saved.length = length; saved.event = events;
        memcpy(saved.digest,digest,32); memcpy(saved.frontier,frontier,32); memcpy(saved.root,p.rootInventoryDigest,32);
        memcpy(saved.custody,custody,32);
        saved.snapshot = participant;
        saved.snapshot.prepared.evidenceBytes = nullptr; // Resolve only to owned artifact bytes at sealing.
        return true;
    }

    bool LocalCommitted() const { return localCommitEvent != 0; }

    bool CommitLocal()
    {
        if (!used || failureRecorded || !preparations[0].event || !preparations[1].event) return false;
        if (localCommitEvent) return true;
        if (events >= MaxEvents) return false;
        const Preparation& p = preparations[0];
        unsigned char record[2048]{};DC022Canonical::Writer w(record,sizeof(record));
        bool ok = w.BeginObject() && w.Key("causes") && w.BeginArray() && w.UInt(p.event) && w.EndArray() &&
            w.Key("incarnation_id") && w.Hex(identity.memberIncarnations[0],16) &&
            w.Key("kind") && w.String("member.terminal_committed") && w.Key("member_id") && w.UInt(1) &&
            w.Key("member_seq") && w.UInt(memberEvents[0] + 1) && w.Key("payload") && w.BeginObject() &&
            w.Key("commitment_digest") && w.Hex(p.digest,32) && w.Key("final_frontiers_digest") && w.Hex(p.frontier,32) &&
            w.Key("output_evidence_custody_digest") && w.Hex(p.custody,32) && w.Key("root_inventory_sha256") && w.Hex(p.root,32) &&
            w.Key("terminal_epoch") && w.UInt(1) && w.EndObject() && w.Key("record") && w.String("event") &&
            w.Key("trace_seq") && w.UInt(events + 1) && w.EndObject() && w.Finish();
        if (!ok || w.Size() > MaxBytes - used) return false;
        memcpy(bytes+used,w.Data(),w.Size());used+=w.Size();++events;++memberEvents[0];localCommitEvent=events;
        return true;
    }

    // Called only after exact authenticated DCM1 validation under the failure
    // serializer. DCM1 can be sent only after the worker's irrevocable commit;
    // its receipt corroborates the remote commit/send, not just collection order.
    bool ObserveWorkerCommitment()
    {
        if (!used || failureRecorded || !localCommitEvent || !preparations[1].event) return false;
        if (workerReceiptEvent) return true;
        if (events > MaxEvents - 4) return false;
        const Preparation& p = preparations[1];
        unsigned char committed[2048]{}, sent[2048]{}, custody[32768]{}, received[2048]{};
        DC022Canonical::Writer c(committed,sizeof(committed)), s(sent,sizeof(sent)),
            a(custody,sizeof(custody)), r(received,sizeof(received));
        bool ok = c.BeginObject() && c.Key("causes") && c.BeginArray() && c.UInt(p.event) &&
            c.UInt(localCommitEvent) && c.UInt(artifacts[2].event) && c.EndArray() && c.Key("incarnation_id") && c.Hex(identity.memberIncarnations[1],16) &&
            c.Key("kind") && c.String("member.terminal_committed") && c.Key("member_id") && c.UInt(2) &&
            c.Key("member_seq") && c.UInt(memberEvents[1] + 1) && c.Key("payload") && c.BeginObject() &&
            c.Key("commitment_digest") && c.Hex(p.digest,32) && c.Key("final_frontiers_digest") && c.Hex(p.frontier,32) &&
            c.Key("output_evidence_custody_digest") && c.Hex(p.custody,32) && c.Key("root_inventory_sha256") && c.Hex(p.root,32) &&
            c.Key("terminal_epoch") && c.UInt(1) && c.EndObject() && c.Key("record") && c.String("event") &&
            c.Key("trace_seq") && c.UInt(events + 1) && c.EndObject() && c.Finish();
        ok = ok && s.BeginObject() && s.Key("causes") && s.BeginArray() && s.UInt(p.event) && s.UInt(events + 1) && s.EndArray() &&
            s.Key("incarnation_id") && s.Hex(identity.memberIncarnations[1],16) &&
            s.Key("kind") && s.String("member.commitment_sent") && s.Key("member_id") && s.UInt(2) &&
            s.Key("member_seq") && s.UInt(memberEvents[1] + 2) && s.Key("payload") && s.BeginObject() &&
            s.Key("commitment_bytes") && s.UInt(p.length) && s.Key("commitment_digest") && s.Hex(p.digest,32) &&
            s.Key("evidence_artifact_id") && s.UInt(3) && s.Key("final_frontiers_digest") && s.Hex(p.frontier,32) &&
            s.Key("terminal_epoch") && s.UInt(1) && s.EndObject() && s.Key("record") && s.String("event") &&
            s.Key("trace_seq") && s.UInt(events + 2) && s.EndObject() && s.Finish();
        ok = ok && a.BeginObject() && a.Key("causes") && a.BeginArray() && a.UInt(events + 2) &&
            a.UInt(mainReturnEvent) && a.EndArray() && a.Key("incarnation_id") && a.Hex(identity.memberIncarnations[0],16) &&
            a.Key("kind") && a.String("artifact.custodied") && a.Key("member_id") && a.UInt(1) &&
            a.Key("member_seq") && a.UInt(memberEvents[0] + 1) && a.Key("payload") && a.BeginObject() &&
            a.Key("artifact_id") && a.UInt(4) && a.Key("content_b64") && a.Base64(p.body,p.length) &&
            a.Key("content_bytes") && a.UInt(p.length) && a.Key("role") && a.String("commitment_frame") &&
            a.Key("sha256") && a.Hex(p.digest,32) && a.EndObject() && a.Key("record") && a.String("event") &&
            a.Key("trace_seq") && a.UInt(events + 3) && a.EndObject() && a.Finish();
        ok = ok && r.BeginObject() && r.Key("causes") && r.BeginArray() && r.UInt(events + 2) &&
            r.UInt(events + 3) && r.EndArray() && r.Key("incarnation_id") && r.Hex(identity.memberIncarnations[0],16) &&
            r.Key("kind") && r.String("member.commitment_received") && r.Key("member_id") && r.UInt(1) &&
            r.Key("member_seq") && r.UInt(memberEvents[0] + 2) && r.Key("payload") && r.BeginObject() &&
            r.Key("commitment_bytes") && r.UInt(p.length) && r.Key("commitment_digest") && r.Hex(p.digest,32) &&
            r.Key("participant_incarnation_id") && r.Hex(identity.memberIncarnations[1],16) &&
            r.Key("participant_member_id") && r.UInt(2) && r.Key("receipt_artifact_id") && r.UInt(4) &&
            r.Key("terminal_epoch") && r.UInt(1) && r.Key("validated_frontiers_digest") && r.Hex(p.frontier,32) &&
            r.EndObject() && r.Key("record") && r.String("event") && r.Key("trace_seq") && r.UInt(events + 4) &&
            r.EndObject() && r.Finish();
        const size_t total = c.Size() + s.Size() + a.Size() + r.Size();
        if (!ok || total > MaxBytes - used) return false;
        // Publish the entire chain or none of it; no operation below can fail.
        memcpy(bytes+used,c.Data(),c.Size());used+=c.Size();
        memcpy(bytes+used,s.Data(),s.Size());used+=s.Size();
        memcpy(bytes+used,a.Data(),a.Size());used+=a.Size();
        memcpy(bytes+used,r.Data(),r.Size());used+=r.Size();
        Artifact& frame = artifacts[3];frame.role=3;frame.length=p.length;frame.event=events+3;
        memcpy(frame.content,p.body,p.length);memcpy(frame.digest,p.digest,32);
        events+=4;memberEvents[0]+=2;memberEvents[1]+=2;workerReceiptEvent=events;
        return true;
    }

    bool WorkerRetired() const { return workerRetirementEvent != 0; }

    bool RetireWorker(uint64_t transition)
    {
        if (!used || failureRecorded || !transition || !localCommitEvent || !workerReceiptEvent) return false;
        if (workerRetirementEvent) return transition == workerRetirementOrder;
        if (stage != 4 || !mainReturnEvent || !lastJoinReturned || !admissionClosed[0] || !admissionClosed[1] ||
            pending[0].active || pending[1].active || publicationStage || !rootsReady || !roots.Healthy() ||
            !roots.Closed(1) || !roots.Closed(2) || !rootCut[0] || !rootCut[1] ||
            rootCauseCount != 4 || roots.HistoricalObjects() != 4 || events >= MaxEvents) return false;
        for (unsigned i = 0; i < rootCauseCount; ++i)
            if (roots.Reasons(1,rootCauses[i].id) || roots.Reasons(2,rootCauses[i].id)) return false;
        const Preparation& p = preparations[1];
        const Artifact& frame = artifacts[3];
        if (!p.event || !artifacts[0].event || !artifacts[1].event || !artifacts[2].event ||
            !frame.event || frame.role != 3 || frame.length != p.length ||
            memcmp(frame.digest,p.digest,32) || memcmp(frame.content,p.body,p.length)) return false;
        unsigned char record[2048]{};DC022Canonical::Writer w(record,sizeof(record));
        bool ok = w.BeginObject() && w.Key("causes") && w.BeginArray() && w.UInt(workerReceiptEvent) &&
            w.UInt(rootCutEvent[1]) && w.UInt(closeEvent[1]) && w.EndArray() &&
            w.Key("incarnation_id") && w.Hex(identity.memberIncarnations[0],16) &&
            w.Key("kind") && w.String("member.retired") && w.Key("member_id") && w.UInt(1) &&
            w.Key("member_seq") && w.UInt(memberEvents[0]+1) && w.Key("payload") && w.BeginObject() &&
            w.Key("commitment_digest") && w.Hex(p.digest,32) && w.Key("coordinator_transition_seq") && w.UInt(transition) &&
            w.Key("participant_incarnation_id") && w.Hex(identity.memberIncarnations[1],16) &&
            w.Key("participant_member_id") && w.UInt(2) && w.Key("terminal_epoch") && w.UInt(1) &&
            w.EndObject() && w.Key("record") && w.String("event") && w.Key("trace_seq") && w.UInt(events+1) &&
            w.EndObject() && w.Finish();
        if (!ok || w.Size() > MaxBytes-used) return false;
        memcpy(bytes+used,w.Data(),w.Size());used+=w.Size();++events;++memberEvents[0];
        workerRetirementEvent=events;workerRetirementOrder=transition;
        return true;
    }

    bool Sealed() const { return sealArtifacts.transition != 0; }

    bool Seal(uint64_t transition, DCG01Preimage::HashFunction hash)
    {
        if (!used || failureRecorded || !hash || !workerRetirementEvent || !transition) return false;
        if (Sealed()) return transition == sealArtifacts.transition;
        if (workerRetirementOrder == UINT64_MAX || transition != workerRetirementOrder+1 || events >= MaxEvents ||
            !localCommitEvent || !workerReceiptEvent || !mainReturnEvent || mainReturn.resultI32 != 0 ||
            !admissionClosed[0] || !admissionClosed[1] || !roots.Healthy() || !roots.Closed(1) || !roots.Closed(2) ||
            pending[0].active || pending[1].active || publicationStage) return false;
        for (unsigned i=0;i<rootCauseCount;++i)
            if (roots.Reasons(1,rootCauses[i].id) || roots.Reasons(2,rootCauses[i].id)) return false;
        DCG01Preimage::Identity id{};
        memcpy(id.runId,identity.run,16);memcpy(id.buildDigest,identity.buildManifestSha256,32);
        memcpy(id.runManifestDigest,identity.runManifestSha256,32);memcpy(id.incarnation,identity.memberIncarnations,32);
        DCG01Preimage::Participant participants[2]{preparations[0].snapshot,preparations[1].snapshot};
        DCG01Preimage::Artifact owned[3]{};
        for (unsigned i=0;i<3;++i)
        {
            if (!artifacts[i].event) return false;
            owned[i] = {i+1, i == 0 ? DCG01Preimage::ApplicationOutput : DCG01Preimage::TerminalEvidence,
                artifacts[i].content,artifacts[i].length};
        }
        // Reconstruct each immutable commitment from the saved semantic snapshot
        // and current owned evidence before constructing the whole-run certificate.
        for (unsigned i=0;i<2;++i)
        {
            participants[i].prepared.evidenceBytes=artifacts[i+1].content;
            unsigned char body[16384]{},digest[32]{};size_t length=0;
            if (!DCG01Preimage::EncodeParticipant(id,participants[i],hash,body,sizeof(body),&length,digest) ||
                length != preparations[i].length || memcmp(body,preparations[i].body,length) ||
                memcmp(digest,preparations[i].digest,32)) return false;
        }
        SealArtifacts candidate{};candidate.prefixBytes=used;candidate.prefixEvents=events;candidate.transition=transition;
        DCG01Preimage::Prefix prefix{bytes,used,events};
        if (!DCG01Preimage::BuildCertificate(id,1,mainReturn,hash,participants,owned,3,prefix,
            candidate.certificate,sizeof(candidate.certificate),&candidate.certificateBytes,candidate.certificateDigest)) return false;
        DC022Canonical::Writer w(candidate.seal,sizeof(candidate.seal));
        uint64_t causes[]={mainReturnEvent,preparations[0].event,preparations[1].event,localCommitEvent,workerReceiptEvent,workerRetirementEvent};
        for (unsigned i=1;i<6;++i) {uint64_t value=causes[i];unsigned j=i;while(j&&causes[j-1]>value){causes[j]=causes[j-1];--j;}causes[j]=value;}
        bool ok=w.BeginObject() && w.Key("causes") && w.BeginArray();
        for (unsigned i=0;i<6;++i) ok=ok && w.UInt(causes[i]);
        ok=ok && w.EndArray() && w.Key("incarnation_id") && w.Hex(identity.memberIncarnations[0],16) &&
            w.Key("kind") && w.String("run.sealed") && w.Key("member_id") && w.UInt(1) &&
            w.Key("member_seq") && w.UInt(memberEvents[0]+1) && w.Key("payload") && w.BeginObject() &&
            w.Key("coordinator_transition_seq") && w.UInt(transition) && w.Key("cut_id") && w.UInt(1) &&
            w.Key("participant_cuts") && w.BeginArray();
        for (unsigned i=0;i<2;++i) ok=ok && DCG01Preimage::PutCut(w,id,participants[i],preparations[i].digest);
        ok=ok && w.EndArray() && w.Key("required_evidence_artifact_ids") && w.BeginArray() && w.UInt(2) && w.UInt(3) && w.EndArray() &&
            w.Key("required_output_artifact_ids") && w.BeginArray() && w.UInt(1) && w.EndArray() &&
            w.Key("terminal_certificate_sha256") && w.Hex(candidate.certificateDigest,32) && w.EndObject() &&
            w.Key("record") && w.String("event") && w.Key("trace_seq") && w.UInt(events+1) && w.EndObject() && w.Finish();
        if (!ok || w.Size()>MaxBytes-used) return false;
        candidate.sealBytes=w.Size();
        if (!DCG01Preimage::BuildCompleteRecord(id,1,mainReturn,hash,participants,owned,3,prefix,
            candidate.certificate,candidate.certificateBytes,candidate.seal,candidate.sealBytes,
            candidate.record,sizeof(candidate.record),&candidate.recordBytes,candidate.recordDigest)) return false;
        // The serializer publishes both the state and its immutable evidence only
        // after every preimage and byte-capacity check succeeds. No I/O occurs here.
        memcpy(bytes+used,candidate.seal,candidate.sealBytes);used+=candidate.sealBytes;++events;++memberEvents[0];
        sealArtifacts=candidate;
        return true;
    }

    bool CopySeal(SealArtifacts* output) const
    {
        if (!output || !Sealed()) return false;
        *output=sealArtifacts;return true;
    }

    bool MainReturned(int32_t result, uint64_t operation, uint64_t authority, uint64_t publication)
    {
        if (!used || mainReturnEvent || stage != 4 || !lastJoinReturned || pending[0].active || pending[1].active ||
            admissionClosed[0] || publicationStage || artifacts[0].role != 1 ||
            operation != nextOperation[0] - 1 || authority != lastAuthority || publication != publicationId || events >= MaxEvents)
            return false;
        unsigned char record[2048]{};
        DC022Canonical::Writer w(record,sizeof(record));
        const uint64_t cause = ActorCause(1);
        bool ok = w.BeginObject() && w.Key("causes") && w.BeginArray() && w.UInt(cause);
        ok = ok && w.EndArray() && w.Key("incarnation_id") && w.Hex(identity.memberIncarnations[0],16) &&
            w.Key("kind") && w.String("run.main_returned") && w.Key("member_id") && w.UInt(1) &&
            w.Key("member_seq") && w.UInt(memberEvents[0] + 1) && w.Key("payload") && w.BeginObject() &&
            w.Key("final_authority_frontier") && w.UInt(authority) && w.Key("final_operation_frontier") && w.UInt(operation) &&
            w.Key("final_publication_frontier") && w.UInt(publication) && w.Key("outcome") && w.String("returned") &&
            w.Key("output_artifact_ids") && w.BeginArray() && w.UInt(1) && w.EndArray() &&
            w.Key("result_i32") && w.Int(result) && w.EndObject() && w.Key("record") && w.String("event") &&
            w.Key("trace_seq") && w.UInt(events + 1) && w.EndObject() && w.Finish();
        if (!ok || w.Size() > MaxBytes - used) return false;
        memcpy(bytes + used,w.Data(),w.Size()); used += w.Size(); ++events; ++memberEvents[0];
        mainReturnEvent = events;
        mainReturn.resultI32=result;mainReturn.outputArtifactCount=1;mainReturn.outputArtifactIds[0]=1;
        mainReturn.finalOperationFrontier=operation;mainReturn.finalAuthorityFrontier=authority;
        mainReturn.finalPublicationFrontier=publication;
        return CaptureArtifact(1,1,artifacts[0].content,artifacts[0].length,artifacts[0].digest);
    }

    bool PublishRecord(uint64_t transition)
    {
        if (!used || failureRecorded || !Sealed() || recordPublishedEvent || !transition ||
            transition<=sealArtifacts.transition || events>MaxEvents-2) return false;
        unsigned char custody[32768]{},published[2048]{};
        DC022Canonical::Writer c(custody,sizeof(custody)),p(published,sizeof(published));
        const uint64_t seal=sealArtifacts.prefixEvents+1;
        bool ok=c.BeginObject() && c.Key("causes") && c.BeginArray() && c.UInt(seal) && c.EndArray() &&
            c.Key("incarnation_id") && c.Hex(identity.memberIncarnations[0],16) && c.Key("kind") && c.String("artifact.custodied") &&
            c.Key("member_id") && c.UInt(1) && c.Key("member_seq") && c.UInt(memberEvents[0]+1) && c.Key("payload") && c.BeginObject() &&
            c.Key("artifact_id") && c.UInt(5) && c.Key("content_b64") && c.Base64(sealArtifacts.record,sealArtifacts.recordBytes) &&
            c.Key("content_bytes") && c.UInt(sealArtifacts.recordBytes) && c.Key("role") && c.String("complete_record") &&
            c.Key("sha256") && c.Hex(sealArtifacts.recordDigest,32) && c.EndObject() && c.Key("record") && c.String("event") &&
            c.Key("trace_seq") && c.UInt(events+1) && c.EndObject() && c.Finish();
        ok=ok && p.BeginObject() && p.Key("causes") && p.BeginArray() && p.UInt(seal) && p.UInt(events+1) && p.EndArray() &&
            p.Key("incarnation_id") && p.Hex(identity.memberIncarnations[0],16) && p.Key("kind") && p.String("complete_record.published") &&
            p.Key("member_id") && p.UInt(1) && p.Key("member_seq") && p.UInt(memberEvents[0]+2) && p.Key("payload") && p.BeginObject() &&
            p.Key("coordinator_transition_seq") && p.UInt(transition) && p.Key("cut_id") && p.UInt(1) &&
            p.Key("publication_generation") && p.UInt(1) && p.Key("record_artifact_id") && p.UInt(5) &&
            p.Key("record_bytes") && p.UInt(sealArtifacts.recordBytes) && p.Key("record_sha256") && p.Hex(sealArtifacts.recordDigest,32) &&
            p.EndObject() && p.Key("record") && p.String("event") && p.Key("trace_seq") && p.UInt(events+2) && p.EndObject() && p.Finish();
        if (!ok || c.Size()>MaxBytes-used || p.Size()>MaxBytes-used-c.Size()) return false;
        memcpy(bytes+used,c.Data(),c.Size());used+=c.Size();memcpy(bytes+used,p.Data(),p.Size());used+=p.Size();
        events+=2;memberEvents[0]+=2;recordPublishedEvent=events;return true;
    }

    bool RecordWriteFailed(const char* kind,uint64_t transition)
    {
        if (!used || !Sealed() || !kind || recordPublishedEvent || recordWriteFailedEvent ||
            transition<=sealArtifacts.transition || events>=MaxEvents) return false;
        unsigned char record[1024]{};DC022Canonical::Writer w(record,sizeof(record));
        const bool ok=w.BeginObject() && w.Key("causes") && w.BeginArray() && w.UInt(sealArtifacts.prefixEvents+1) && w.EndArray() &&
            w.Key("incarnation_id") && w.Hex(identity.memberIncarnations[0],16) && w.Key("kind") && w.String("complete_record.write_failed") &&
            w.Key("member_id") && w.UInt(1) && w.Key("member_seq") && w.UInt(memberEvents[0]+1) && w.Key("payload") && w.BeginObject() &&
            w.Key("coordinator_transition_seq") && w.UInt(transition) && w.Key("cut_id") && w.UInt(1) &&
            w.Key("failure_kind") && w.String(kind,strlen(kind)) && w.EndObject() && w.Key("record") && w.String("event") &&
            w.Key("trace_seq") && w.UInt(events+1) && w.EndObject() && w.Finish();
        if (!ok || w.Size()>MaxBytes-used) return false;
        memcpy(bytes+used,w.Data(),w.Size());used+=w.Size();++events;++memberEvents[0];recordWriteFailedEvent=events;return true;
    }

    bool PhysicalDisconnect(const unsigned char* digest, uint64_t transition)
    {
        if (!used || failureRecorded || !digest || !Sealed() || !workerRetirementEvent ||
            physicalNoticeEvent || transition<=sealArtifacts.transition || events>=MaxEvents) return false;
        unsigned char record[1024]{};DC022Canonical::Writer w(record,sizeof(record));
        const bool ok=w.BeginObject() && w.Key("causes") && w.BeginArray() && w.UInt(workerRetirementEvent) &&
            w.UInt(sealArtifacts.prefixEvents+1) && w.EndArray() && w.Key("incarnation_id") &&
            w.Hex(identity.memberIncarnations[0],16) && w.Key("kind") && w.String("participant.failure_notice_processed") &&
            w.Key("member_id") && w.UInt(1) && w.Key("member_seq") && w.UInt(memberEvents[0]+1) &&
            w.Key("payload") && w.BeginObject() && w.Key("coordinator_transition_seq") && w.UInt(transition) &&
            w.Key("notice_digest") && w.Hex(digest,32) && w.Key("notice_kind") && w.String("physical_disconnect") &&
            w.Key("participant_incarnation_id") && w.Hex(identity.memberIncarnations[1],16) &&
            w.Key("participant_member_id") && w.UInt(2) && w.EndObject() && w.Key("record") && w.String("event") &&
            w.Key("trace_seq") && w.UInt(events+1) && w.EndObject() && w.Finish();
        if (!ok || w.Size()>MaxBytes-used) return false;
        memcpy(bytes+used,w.Data(),w.Size());used+=w.Size();++events;++memberEvents[0];physicalNoticeEvent=events;return true;
    }

    bool RecordFailure(const char* kind, const unsigned char* digest, uint64_t failureOrder, uint64_t abortOrder)
    {
        if (!used || failureRecorded || !kind || !digest || failureOrder == 0 ||
            failureOrder == UINT64_MAX || abortOrder != failureOrder + 1 || events > MaxEvents - 2) return false;
        unsigned char failure[1024]{}, abort[1024]{};
        DC022Canonical::Writer f(failure,sizeof(failure)), a(abort,sizeof(abort));
        bool ok = f.BeginObject() && f.Key("causes") && f.BeginArray() && f.EndArray() &&
            f.Key("incarnation_id") && f.Hex(identity.memberIncarnations[0],16) && f.Key("kind") &&
            f.String("run.failure_processed") && f.Key("member_id") && f.UInt(1) && f.Key("member_seq") &&
            f.UInt(memberEvents[0] + 1) && f.Key("payload") && f.BeginObject() &&
            f.Key("coordinator_transition_seq") && f.UInt(failureOrder) && f.Key("failure_evidence_artifact_id") && f.Null() &&
            f.Key("failure_kind") && f.String(kind,strlen(kind)) && f.Key("source_event_digest") && f.Hex(digest,32) &&
            f.EndObject() && f.Key("record") && f.String("event") && f.Key("trace_seq") && f.UInt(events + 1) && f.EndObject() && f.Finish();
        ok = ok && a.BeginObject() && a.Key("causes") && a.BeginArray() && a.UInt(events + 1) && a.EndArray() &&
            a.Key("incarnation_id") && a.Hex(identity.memberIncarnations[0],16) && a.Key("kind") &&
            a.String("run.abort_latched") && a.Key("member_id") && a.UInt(1) && a.Key("member_seq") &&
            a.UInt(memberEvents[0] + 2) && a.Key("payload") && a.BeginObject() &&
            a.Key("coordinator_transition_seq") && a.UInt(abortOrder) && a.Key("reason") && a.String(kind,strlen(kind)) &&
            a.Key("trigger_trace_seq") && a.UInt(events + 1) && a.EndObject() && a.Key("record") &&
            a.String("event") && a.Key("trace_seq") && a.UInt(events + 2) && a.EndObject() && a.Finish();
        // Publish both records together or neither; the owning serializer latches
        // failure regardless of this bounded evidence writer's outcome.
        if (!ok || f.Size() > MaxBytes - used || a.Size() > MaxBytes - used - f.Size()) return false;
        memcpy(bytes + used,f.Data(),f.Size()); used += f.Size();
        memcpy(bytes + used,a.Data(),a.Size()); used += a.Size();
        events += 2; memberEvents[0] += 2; failureRecorded = true;
        return true;
    }

    bool Copy(unsigned char* output, size_t capacity, size_t* length, uint64_t* count) const
    {
        if (!used || !output || !length || !count || capacity < used) return false;
        memcpy(output, bytes, used); *length = used; *count = events;
        return true;
    }
};
}
#endif
