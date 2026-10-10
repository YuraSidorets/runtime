// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#include "common.h"
#include "assembly.hpp"
#include "ceeload.h"
#include "field.h"
#include "gchelpers.h"
#include "gcheaputilities.h"
#include "memberload.h"
#include "callhelpers.h"
#include "distributedaccess.h"
#include "distributedadmission.h"
#include "distributedthread.h"
#include "distributedthreadprotocol.h"
#include "distributedcanonicalwriter.h"
#include "distributedterminalpreimages.h"
#include "distributedterminalcustody.h"
#include "distributedthreadterminal.h"
#include "application_output_custody_v2.h"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <unistd.h>
#include <openssl/sha.h>

extern "C" int64_t DistributedControlNative(int command, int argument, BYTE* buffer, int length);
extern "C" int DistributedIdentityExportForTest(OBJECTREF root, BYTE* buffer, int capacity);

namespace
{
constexpr unsigned MaxSeeds = 64, MaxOps = 2048, SeedBytes = 268;
constexpr unsigned RequestBytes = 112, ReplyBytes = 120, EventBytes = 4 + RequestBytes + ReplyBytes;
constexpr unsigned HeaderBytes = 88;
constexpr unsigned PublicationHeaderBytes = 96, PublicationRecordBytes = 88, PublicationAckBytes = 72;
constexpr unsigned MaxHistoryBytes = PublicationHeaderBytes + MaxSeeds * (SeedBytes + 8) +
    MaxSeeds * PublicationRecordBytes + MaxOps * EventBytes;
using Clock = std::chrono::steady_clock;
Module* s_module = nullptr;
MethodDesc* s_body = nullptr;
unsigned s_node = 0;
DistributedAccessSeed s_seeds[MaxSeeds]{}, s_values[MaxSeeds]{};
unsigned s_count = 0, s_committed = 0;
BYTE s_history[MaxOps][EventBytes]{}, s_seedDigest[32]{};
UINT64 s_next[2]{1, 1}, s_lastCommit[2]{}, s_request = 0, s_lastReply = 0;
// Application-owner writes; closed admission and physical Join publish them to capture.
UINT64 s_completedRequest = 0, s_completedPublication = 0;
int s_workerResult = -1;
std::atomic<bool> s_open{false}, s_aborted{false}, s_finished{false}, s_workerDone{false}, s_shutdown{false};
pthread_t s_service{};
bool s_created = false;
pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
std::atomic<unsigned> s_delayedReplies{0};
bool s_workerMoved = false;
unsigned s_workerGcWaits = 0;
bool s_publicationMode = false;
bool s_threadMode = false;
bool s_threadRootProfile = false; // Exact positive Thread fixture, never the negative corpus.
// Worker staging initializes this exact retained set; only its admitted child extends it.
// Physical Join publishes the final plain values back to staging. The worker's s_seeds
// remains the initial admission graph; it is not the coordinator's publication history.
DistributedObjectId s_receiverRetainedIds[MaxSeeds]{};
unsigned s_receiverRetainedCount = 0;
struct ThreadRootInventory
{
    DistributedAccessQuiescentSnapshot cut;
    unsigned retainedCount;
    unsigned retainedBytes;
    unsigned length;
    BYTE canonical[512];
    BYTE digest[32];
};
ThreadRootInventory s_threadRootInventory{};
std::atomic<bool> s_threadRootInventoryPublished{false};
struct ThreadParticipantPreimage
{
    unsigned node;
    size_t rootPayloadLength, evidenceLength, commitmentLength;
    BYTE rootPayload[256], evidence[1024], commitment[DCG01Preimage::kMaxBytes];
    BYTE evidenceDigest[32], commitmentDigest[32];
};
ThreadParticipantPreimage s_threadParticipantPreimage{};
std::atomic<bool> s_threadParticipantPreimagePublished{false};
DCG01Custody::Receiver s_workerCustody{}; // Coordinator Service owns writes, under s_lock.
std::atomic<bool> s_workerCustodyReceived{false};
DCG01Custody::Bundle s_workerSentCustody{}; // Worker post-Join owner; never replayed.
DCG01Commit::Frame s_workerSentCommitment{}; // Written after exact custody ACK and irreversible local commit.
std::atomic<bool> s_workerCommitmentReceived{false};
std::atomic<bool> s_coordinatorCommitted{false};
std::atomic<bool> s_mainReturnObserved{false};
namespace TP = DistributedThreadProtocol;
TP::ExpectedIdentity s_threadIdentity{};
TP::Ledger* s_threadLedger = nullptr; // One bounded run; no reset, takeover or replay.
BYTE s_threadDigest[32]{}, s_threadRoot[44]{};
std::atomic<bool> s_threadEntered{false}, s_callbackReturned{false};
TP::LocalCompletionFacts s_returnFacts{};
unsigned s_initialSeedCount = 0, s_publicationCount = 0;
UINT64 s_publicationTransaction = 0, s_receivedPublication = 0;
UINT64 s_introduced[MaxSeeds]{};
BYTE s_publicationHistory[MaxSeeds][PublicationRecordBytes]{};
BYTE s_publicationAcks[MaxSeeds][PublicationAckBytes]{}, s_receiverAcks[MaxSeeds][PublicationAckBytes]{};
struct PendingPublication
{
    bool active = false, acknowledged = false;
    UINT64 transaction = 0, sourceFrontier = 0;
    unsigned count = 0;
    BYTE digest[32]{}, ack[PublicationAckBytes]{};
};
PendingPublication s_publication{}; // Portable state only; protected by s_lock.

// ponytail: one bounded authority and one application thread per node; DC-013 must add
// thread admission/demultiplexing before this profile can serve multiple callers.
UINT32 U32(const BYTE* p) { UINT32 v = 0; for (unsigned i = 0; i < 4; i++) v |= UINT32(p[i]) << (8 * i); return v; }
UINT64 U64(const BYTE* p) { UINT64 v = 0; for (unsigned i = 0; i < 8; i++) v |= UINT64(p[i]) << (8 * i); return v; }
void P32(BYTE* p, UINT32 v) { for (unsigned i = 0; i < 4; i++) p[i] = BYTE(v >> (8 * i)); }
void P64(BYTE* p, UINT64 v) { for (unsigned i = 0; i < 8; i++) p[i] = BYTE(v >> (8 * i)); }
bool Same(const BYTE* a, const BYTE* b, unsigned n) { return std::memcmp(a, b, n) == 0; }
bool Zero(const BYTE* p, unsigned n) { for (unsigned i = 0; i < n; i++) if (p[i]) return false; return true; }
bool Ready()
{
    return DistributedControlNative(3, 0, nullptr, 0) == 2 &&
        (!s_threadRootProfile || DistributedThreadTerminalHealthy());
}

bool Abort(const char* reason)
{
    // Record before taking the access lock; the serializer makes no runtime callbacks.
    DistributedThreadTerminalFailure(static_cast<unsigned>(DCG01Terminal::Origin::Access), 0, reason);
    pthread_mutex_lock(&s_lock);
    const bool threadMode = s_threadMode;
    if (threadMode)
        DistributedThreadMarkAbort();
    bool first = !s_aborted.exchange(true);
    pthread_mutex_unlock(&s_lock);
    if (threadMode)
    {
        DistributedThreadSignalAbort();
        if (first && s_node == 1)
            std::fprintf(stderr, "DC_THREAD phase=source-abort-published reason=%s node=%u\n", reason, s_node);
    }
    if (first)
        std::fprintf(stderr, "DC_ACCESS phase=aborted reason=%s node=%u\n", reason, s_node);
    DistributedControlNative(5, 0, nullptr, 0);
    return false;
}

void Reject(const char* reason)
{
    Abort(reason);
    COMPlusThrow(kInvalidOperationException);
}

void CheckCaller()
{
    if (s_module == nullptr || !DistributedIdentityAccessCaller() || s_aborted.load() ||
        s_finished.load() || (DistributedIdentityIsFrozen() && !s_open.load()) ||
        (s_threadMode && !DistributedThreadHasApplicationAction()))
        Reject("helper-state-or-thread");
}

bool RetiredReplyUnneeded()
{
    return s_threadRootProfile && s_node==1 &&
        (DistributedThreadTerminalDraining() || DistributedThreadTerminalPeerDisconnected());
}

bool SendUntil(BYTE* bytes, unsigned length, unsigned kind, Clock::time_point deadline, bool retiredDuplicate=false)
{
    const auto queueDeadline = Clock::now() + std::chrono::seconds(10);
    if (queueDeadline < deadline) deadline = queueDeadline;
    while (!s_aborted.load() && Ready() && Clock::now() < deadline)
    {
        if(retiredDuplicate && RetiredReplyUnneeded()) return true;
        int64_t status = DistributedControlNative(1, kind, bytes, length);
        if (status == 0) return true; // Accepted once; never retransmit an accepted operation.
        if (status != 1 || Clock::now() >= deadline) break;
        usleep(1000); // Queue-full means no enqueue occurred.
    }
    if(retiredDuplicate && !s_aborted.load() && RetiredReplyUnneeded()) return true;
    return Abort("send");
}

bool Send(BYTE* bytes, unsigned length, unsigned kind)
{
    return SendUntil(bytes, length, kind, Clock::now() + std::chrono::seconds(10));
}

template <size_t Capacity>
int Receive(BYTE (&payload)[Capacity], unsigned expectedKind, Clock::time_point deadline, bool* gcWhileAwaiting = nullptr)
{
    BYTE frame[4112]{};
    bool awaiting = false;
    unsigned collectionsBefore = 0;
    if (gcWhileAwaiting != nullptr) *gcWhileAwaiting = false;
    while (!s_aborted.load() && !s_shutdown.load())
    {
        const bool ready=Ready();
        const bool disconnected=s_threadRootProfile && s_node==1 && DistributedThreadTerminalPeerDisconnected();
        const bool draining=s_threadRootProfile && s_node==1 && DistributedThreadTerminalDraining();
        const bool producerStopped=draining && DistributedControlNative(3,0,nullptr,0)==4 &&
            DistributedControlNative(3,12,nullptr,0)==0;
        if ((!ready && !disconnected && !draining) || (!disconnected && !draining && s_threadMode && Clock::now() >= deadline)) break;
        int64_t size = DistributedControlNative(2, 0, frame, sizeof(frame));
        if (size < 0 || size > 4096 || static_cast<size_t>(size) > Capacity) break;
        if (size != 0)
        {
            UINT64 kind = 0;
            for (unsigned i = 0; i < 8; i++) kind = (kind << 8) | frame[8 + i];
            if (kind != expectedKind) break;
            std::memcpy(payload, frame + 16, size);
            if (gcWhileAwaiting != nullptr && awaiting)
                *gcWhileAwaiting = GCHeapUtilities::GetGCHeap()->GetGcCount() != collectionsBefore;
            return static_cast<int>(size);
        }
        // Drain and validate every already authenticated frame. Only an empty
        // queue after the serialized post-seal physical notice ends normally.
        if (disconnected || producerStopped) return -1;
        if(draining && DistributedControlNative(3,0,nullptr,0)==4 && DistributedControlNative(3,12,nullptr,0)==0)
            continue; // A frame may have arrived before the producer stopped.
        // A newly processed notice can race this empty read. Re-read the queue
        // after observing it; a frame may have arrived before the transport ended.
        if (s_threadRootProfile && s_node==1 && DistributedThreadTerminalPeerDisconnected()) continue;
        // Measure only an observed empty reply queue, excluding send/queue-full waits.
        if (gcWhileAwaiting != nullptr && !awaiting)
        {
            collectionsBefore = GCHeapUtilities::GetGCHeap()->GetGcCount();
            awaiting = true;
        }
        if (!draining && Clock::now() >= deadline) break;
        usleep(1000);
    }
    if (s_shutdown.load()) return -1;
    Abort("receive-kind-state-or-deadline");
    return -1;
}

int Find(const BYTE* id)
{
    for (unsigned i = 0; i < s_count; i++)
        if (Same(id, s_values[i].id.bytes, 44)) return i;
    return -1;
}

void EncodeSeed(BYTE* p, const DistributedAccessSeed& seed)
{
    std::memcpy(p, seed.id.bytes, 44);
    P32(p + 44, seed.kind);
    P32(p + 48, seed.length);
    for (unsigned i = 0; i < 32; i++) P32(p + 52 + i * 4, seed.values[i]);
    std::memcpy(p + 180, seed.references[0].bytes, 44);
    std::memcpy(p + 224, seed.references[1].bytes, 44);
}

bool RecordReceiverRetainedSeeds(const DistributedAccessSeed* seeds, unsigned count)
{
    if (!s_threadRootProfile || s_node != 2 || s_aborted.load() || s_shutdown.load() ||
        seeds == nullptr || count == 0 || count > MaxSeeds || s_receiverRetainedCount > MaxSeeds ||
        count > MaxSeeds - s_receiverRetainedCount)
        return false;
    // Imported identities are already validated by the owner directory. Independently
    // bind this bookkeeping to the admitted creator and reject all duplicate additions
    // before changing the set. No handle, allocation, GC, IO or network wait here.
    for (unsigned i = 0; i < count; i++)
    {
        const BYTE* id = seeds[i].id.bytes;
        if (!Same(id, s_threadIdentity.run, 16) || U32(id + 16) != 1 ||
            !Same(id + 20, s_threadIdentity.creatorIncarnation, 16) ||
            U64(id + 36) == 0 || U64(id + 36) > MaxSeeds)
            return false;
        for (unsigned j = 0; j < s_receiverRetainedCount; j++)
            if (Same(id, s_receiverRetainedIds[j].bytes, 44)) return false;
        for (unsigned j = 0; j < i; j++)
            if (Same(id, seeds[j].id.bytes, 44)) return false;
    }
    for (unsigned i = 0; i < count; i++)
        s_receiverRetainedIds[s_receiverRetainedCount + i] = seeds[i].id;
    s_receiverRetainedCount += count;
    return true;
}

bool SealDirectory()
{
    if (!DistributedIdentityFreeze(s_seeds, &s_count) || s_count > MaxSeeds) return false;
    BYTE encoded[MaxSeeds * SeedBytes]{};
    for (unsigned i = 0; i < s_count; i++)
    {
        s_values[i] = s_seeds[i];
        EncodeSeed(encoded + i * SeedBytes, s_seeds[i]);
    }
    SHA256(encoded, s_count * SeedBytes, s_seedDigest);
    s_initialSeedCount = s_count;
    if (s_threadRootProfile && s_node == 2 &&
        (s_receiverRetainedCount != 0 || !RecordReceiverRetainedSeeds(s_seeds, s_count)))
        return false;
    return true;
}

// Called preemptively or by the unattached native service. No GC, allocation or IO under lock.
bool Commit(unsigned node, const BYTE* request, BYTE* response,
    const DistributedPublicationBatch* publication = nullptr, unsigned acknowledgementGc = 0)
{
    bool accepted = false;
    const char* rejectedCheck = "none";
    pthread_mutex_lock(&s_lock);
    do
    {
        if (s_aborted.load()) { rejectedCheck = "aborted"; break; }
        if (s_finished.load()) { rejectedCheck = "finished"; break; }
        if (node < 1 || node > 2) { rejectedCheck = "actor"; break; }
        if (!s_open.load()) { rejectedCheck = "closed"; break; }
        if (node == 2 && s_workerDone.load()) { rejectedCheck = "worker-done"; break; }
        if (s_committed == MaxOps) { rejectedCheck = "history-capacity"; break; }
        if (std::memcmp(request, "DAO1", 4) != 0) { rejectedCheck = "request-magic"; break; }
        if (U32(request + 4) != 1) { rejectedCheck = "request-version"; break; }
        if (U64(request + 8) != s_next[node - 1]) { rejectedCheck = "operation-sequence"; break; }
        unsigned operation = U32(request + 16), slot = U32(request + 20);
        int entry = Find(request + 24);
        if (operation > 5 || entry < 0) { rejectedCheck = "operation-or-object"; break; }
        DistributedAccessSeed& record = s_values[entry];
        bool write = (operation & 1) != 0, reference = operation == 2 || operation == 3;
        if (operation < 2 && (record.kind != 0 || slot != 0)) { rejectedCheck = "scalar-slot"; break; }
        if (reference && (record.kind != 0 || slot < 1 || slot > 2)) { rejectedCheck = "reference-slot"; break; }
        if (operation >= 4 && (record.kind != 1 || slot >= record.length)) { rejectedCheck = "array-slot"; break; }
        const BYTE* input = request + 68;
        bool validPublication = publication == nullptr;
        if (publication != nullptr)
        {
            validPublication = s_publicationMode && node == 1 && operation == 3 &&
                s_publication.active && s_publication.acknowledged &&
                publication->transaction == s_publication.transaction &&
                publication->sourceFrontier == s_publication.sourceFrontier &&
                publication->count == s_publication.count && publication->count > 0 &&
                publication->count <= DistributedPublicationMaxObjects &&
                s_count + publication->count <= MaxSeeds && s_publicationCount < MaxSeeds &&
                Same(input, publication->root.bytes, 44) &&
                Same(input, publication->seeds[0].id.bytes, 44);
            for (unsigned i = 0; i < publication->count && validPublication; i++)
            {
                const auto& seed = publication->seeds[i];
                validPublication = seed.kind == 0 && seed.length == 0 && Find(seed.id.bytes) < 0 &&
                    !Zero(seed.id.bytes, 44);
                for (unsigned j = 0; j < i && validPublication; j++)
                    validPublication = !Same(seed.id.bytes, publication->seeds[j].id.bytes, 44);
                for (unsigned edge = 0; edge < 2 && validPublication; edge++)
                {
                    const BYTE* id = seed.references[edge].bytes;
                    if (Zero(id, 44)) continue;
                    int existing = Find(id);
                    bool found = existing >= 0 && s_values[existing].kind == 0;
                    for (unsigned j = 0; j < publication->count && !found; j++)
                        found = Same(id, publication->seeds[j].id.bytes, 44);
                    validPublication = found;
                }
            }
        }
        if (!validPublication) { rejectedCheck = "publication"; break; }
        if (!write && !Zero(input, 44)) { rejectedCheck = "read-input"; break; }
        if (write && !reference && !Zero(input + 4, 40)) { rejectedCheck = "write-input"; break; }
        if (write && reference && !Zero(input, 44))
        {
            int target = Find(input);
            if ((target < 0 && publication == nullptr) || (target >= 0 && s_values[target].kind != 0))
            { rejectedCheck = "reference-target"; break; }
        }
        if (publication != nullptr)
        {
            // The receiver has custody. No allocation or network wait occurs at this cut.
            BYTE* published = s_publicationHistory[s_publicationCount++];
            P64(published, publication->transaction); P64(published + 8, publication->sourceFrontier);
            P64(published + 16, s_committed + 1); P32(published + 24, s_count);
            P32(published + 28, publication->count);
            std::memcpy(published + 32, s_publication.digest, 32);
            P32(published + 64, publication->gcCollections); P32(published + 68, publication->moved);
            P32(published + 72, U32(s_publication.ack + 28));
            P32(published + 76, U32(s_publication.ack + 32));
            P32(published + 80, acknowledgementGc);
            P32(published + 84, publication->stagedTransferRoots);
            for (unsigned i = 0; i < publication->count; i++)
            {
                s_seeds[s_count] = s_values[s_count] = publication->seeds[i];
                s_introduced[s_count++] = s_committed + 1;
            }
        }
        std::atomic_thread_fence(std::memory_order_seq_cst);
        BYTE value[44]{};
        if (reference)
        {
            if (write) std::memcpy(record.references[slot - 1].bytes, input, 44);
            std::memcpy(value, record.references[slot - 1].bytes, 44);
        }
        else
        {
            if (write) record.values[slot] = U32(input);
            P32(value, record.values[slot]);
        }
        std::memcpy(response, "DAP1", 4); P32(response + 4, 1);
        P64(response + 8, U64(request + 8)); P64(response + 16, s_committed + 1);
        P32(response + 24, operation); P32(response + 28, slot);
        std::memcpy(response + 32, request + 24, 44);
        std::memcpy(response + 76, value, 44);
        if (s_threadRootProfile && !DistributedThreadTerminalAccess(node, request, response, ReplyBytes, s_lastCommit[node - 1]))
        { rejectedCheck = "terminal-event"; break; }
        BYTE* event = s_history[s_committed++];
        P32(event, node);
        std::memcpy(event + 4, request, RequestBytes);
        std::memcpy(event + 4 + RequestBytes, response, ReplyBytes);
        s_next[node - 1]++;
        s_lastCommit[node - 1] = s_committed;
        if (publication != nullptr) s_publication.active = false;
        std::atomic_thread_fence(std::memory_order_seq_cst);
        accepted = true;
    } while (false);
    pthread_mutex_unlock(&s_lock);
    if (!accepted)
    {
        std::fprintf(stderr, "DC_ACCESS phase=commit-rejected check=%s node=%u\n", rejectedCheck, node);
        if (std::strcmp(rejectedCheck, "terminal-event") == 0)
        {
            DCG01Terminal::FailureSnapshot failure{};
            if (DistributedThreadTerminalCopyFailure(&failure) &&
                failure.sourceEvidenceLength <= sizeof(failure.sourceEvidence))
            {
                char sourceHex[sizeof(failure.sourceEvidence) * 2 + 1]{}, digestHex[65]{};
                const char digits[] = "0123456789abcdef";
                for (size_t i = 0; i < failure.sourceEvidenceLength; ++i)
                {
                    sourceHex[2 * i] = digits[failure.sourceEvidence[i] >> 4];
                    sourceHex[2 * i + 1] = digits[failure.sourceEvidence[i] & 15];
                }
                for (size_t i = 0; i < sizeof(failure.sourceEvidenceDigest); ++i)
                {
                    digestHex[2 * i] = digits[failure.sourceEvidenceDigest[i] >> 4];
                    digestHex[2 * i + 1] = digits[failure.sourceEvidenceDigest[i] & 15];
                }
                std::fprintf(stderr, "DC_ACCESS phase=terminal-failure-snapshot node=%u failed=%u origin=%u code=%u failure_order=%llu abort_order=%llu events=%u reason_overflow=%u source_bytes=%zu source_sha256=%s source_hex=%s\n",
                    node, failure.failed ? 1u : 0u, static_cast<unsigned>(failure.origin), failure.code,
                    static_cast<unsigned long long>(failure.failureOrder), static_cast<unsigned long long>(failure.abortOrder),
                    failure.failureEventsRecorded ? 1u : 0u, failure.reasonOverflow ? 1u : 0u,
                    failure.sourceEvidenceLength, digestHex, sourceHex);
            }
            else
                std::fprintf(stderr, "DC_ACCESS phase=terminal-failure-snapshot node=%u status=unavailable\n", node);
        }
    }
    return accepted || Abort("operation-capability-sequence-or-bound");
}

bool AcceptPublicationAck(const BYTE* ack, unsigned length)
{
    if (!s_publicationMode || length != PublicationAckBytes || std::memcmp(ack, "DPA1", 4) != 0 ||
        U32(ack + 4) != 1) return Abort("publication-ack-shape");
    UINT64 transaction = U64(ack + 8);
    bool valid = false;
    pthread_mutex_lock(&s_lock);
    if (transaction > 0 && transaction <= MaxSeeds)
    {
        BYTE* prior = s_publicationAcks[transaction - 1];
        if (!Zero(prior, PublicationAckBytes))
            valid = Same(prior, ack, PublicationAckBytes); // Exact duplicates never vote twice.
        else if (s_publication.active && transaction == s_publication.transaction &&
            U64(ack + 16) == s_publication.sourceFrontier && U32(ack + 24) == s_publication.count &&
            U32(ack + 28) > 0 && U32(ack + 32) <= 1 && U32(ack + 36) == s_publication.count &&
            Same(ack + 40, s_publication.digest, 32))
        {
            valid = !s_threadRootProfile || DistributedThreadTerminalPublication(
                static_cast<unsigned>(DCG01Events::Publication::Acknowledged), transaction, nullptr, nullptr, 0);
            if (valid)
            {
                std::memcpy(prior, ack, PublicationAckBytes);
                std::memcpy(s_publication.ack, ack, PublicationAckBytes);
                s_publication.acknowledged = true;
            }
        }
    }
    pthread_mutex_unlock(&s_lock);
    if (valid)
        std::fprintf(stderr, "DC_PUBLICATION phase=ack-validated node=1 transaction=%llu\n",
            static_cast<unsigned long long>(transaction));
    return valid || Abort("publication-ack-custody-or-identity");
}

// Diagnostic bytes bind the runtime ledger to the independent verifier. They do not
// certify application completion and contain no native addresses.
void TraceThreadFrame(const char* direction, const BYTE* wire, size_t length)
{
    char encoded[TP::MaxPrepareBytes * 2 + 1]{};
    const char digits[] = "0123456789abcdef";
    if (length > TP::MaxPrepareBytes) return;
    for (size_t i = 0; i < length; i++)
    {
        encoded[i * 2] = digits[wire[i] >> 4];
        encoded[i * 2 + 1] = digits[wire[i] & 15];
    }
    std::fprintf(stderr, "DC_THREAD phase=frame node=%u direction=%s bytes=%zu hex=%s\n",
        s_node, direction, length, encoded);
}

bool IsThreadFrame(const BYTE* wire, unsigned length)
{
    const char* names[] = {"DTP1", "DTR1", "DTG1", "DTE1", "DTA1", "DTC1", "DTD1"};
    for (const char* name : names)
        if (length >= 4 && std::memcmp(wire, name, 4) == 0) return true;
    return false;
}

// Serialized by the current lifecycle owner. Before grant this is the staging/source
// thread; afterwards coordinator Service, or worker child and then its physical joiner.
bool ThreadRecord(const BYTE* wire, size_t length, const TP::LocalCompletionFacts* facts = nullptr)
{
    TP::Observation observation{};
    if (s_aborted.load() || s_threadLedger == nullptr ||
        !s_threadLedger->RecordLocal(wire, length, facts, &observation))
        return Abort("thread-local-ledger");
    TraceThreadFrame("local", wire, length);
    return true;
}

bool ThreadCachedReply(const TP::Observation& observation, Clock::time_point deadline)
{
    if (!observation.hasCachedReply) return true;
    BYTE reply[TP::MaxPrepareBytes]{};
    size_t length = 0;
    if (!s_threadLedger->CopyRecord(observation.cachedReplyKind, reply, sizeof(reply), &length))
        return Abort("thread-cached-reply");
    return SendUntil(reply, static_cast<unsigned>(length), s_node == 1 ? 23 : 22, deadline);
}

bool ThreadServiceFrame(const BYTE* wire, unsigned length, Clock::time_point deadline)
{
    TP::Observation observation{};
    BYTE reply[TP::MaxPrepareBytes]{};
    size_t replyLength = 0;
    bool completed = false, entered = false, valid;
    pthread_mutex_lock(&s_lock);
    TP::AuthorityCompletionFacts facts{!s_publication.active, !s_aborted.load(),
        s_next[1] - 1, s_lastCommit[1]};
    valid = s_threadLedger->AcceptRemote(wire, length, &facts, &observation);
    if (valid && observation.disposition == TP::Disposition::Recorded)
    {
        entered = std::memcmp(wire, "DTE1", 4) == 0;
        completed = std::memcmp(wire, "DTC1", 4) == 0;
        valid = entered || completed;
        if (valid)
        {
            TP::Observation recorded{};
            valid = TP::BuildAcknowledgement(entered ? TP::Kind::EntryAck : TP::Kind::CompletionAck,
                reply, sizeof(reply), &replyLength, s_threadIdentity, s_threadDigest, wire, length) &&
                s_threadLedger->RecordLocal(reply, replyLength, nullptr, &recorded);
        }
        if (valid && entered) s_threadEntered.store(true, std::memory_order_release);
    }
    else if (valid && observation.hasCachedReply)
        valid = s_threadLedger->CopyRecord(observation.cachedReplyKind, reply, sizeof(reply), &replyLength);
    pthread_mutex_unlock(&s_lock);
    if (!valid) return Abort("thread-remote-ledger");
    if ((entered || completed) && s_threadRootProfile &&
        !DistributedThreadTerminalLifecycle(static_cast<unsigned>(entered ? DCG01Events::Lifecycle::Entered :
            DCG01Events::Lifecycle::Completed), 0)) return Abort("thread-remote-event");
    TraceThreadFrame("remote", wire, length);
    if (replyLength != 0)
    {
        TraceThreadFrame("local", reply, replyLength);
        if (!SendUntil(reply, static_cast<unsigned>(replyLength), 23, deadline,
                       observation.disposition != TP::Disposition::Recorded)) return false;
    }
    if (completed)
    {
        s_workerResult = 0;
        s_workerDone.store(true, std::memory_order_release);
        DistributedThreadNotifyComplete();
        std::fprintf(stderr, "DC_THREAD phase=completion-validated node=1\n");
    }
    return true;
}

bool HashThreadCustody(const unsigned char* bytes, size_t length, unsigned char digest[32])
{
    return SHA256(bytes, length, digest) != nullptr;
}

void TraceThreadCustody(const char* phase, const BYTE* bytes, size_t length, bool duplicate)
{
    char encoded[DCG01Custody::MaxWire * 2 + 1]{}, digestText[65]{};
    BYTE digest[32]{};
    SHA256(bytes, length, digest);
    const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i)
    { encoded[2*i] = digits[bytes[i] >> 4]; encoded[2*i+1] = digits[bytes[i] & 15]; }
    for (size_t i = 0; i < 32; ++i)
    { digestText[2*i] = digits[digest[i] >> 4]; digestText[2*i+1] = digits[digest[i] & 15]; }
    std::fprintf(stderr,
        "DC_THREAD phase=custody-%s-diagnostic node=%u bytes=%zu sha256=%s hex=%s duplicate=%u terminal=0\n",
        phase, s_node, length, digestText, encoded, duplicate ? 1u : 0u);
}

bool ThreadAdmissionClosedFrame(const BYTE* wire, unsigned length)
{
    if (!s_threadRootProfile || s_node != 1 || length != 32 || std::memcmp(wire, "DCL1", 4) != 0 ||
        U32(wire + 4) != 1 || U64(wire + 8) != 2 || U64(wire + 24) != 1)
        return Abort("thread-admission-close-shape");
    pthread_mutex_lock(&s_lock);
    const bool valid = !s_aborted.load() && !s_shutdown.load() && s_workerDone.load(std::memory_order_acquire) &&
        s_next[1] > 0 && U64(wire + 16) == s_next[1] - 1;
    pthread_mutex_unlock(&s_lock);
    return (valid && DistributedThreadTerminalAdmissionClosed(2, U64(wire + 8), U64(wire + 16))) ||
        Abort("thread-admission-close-state");
}

bool ThreadCustodyServiceFrame(const BYTE* wire, unsigned length, Clock::time_point deadline)
{
    DistributedAdmissionThreadIdentity admission{};
    if (!s_threadRootProfile || s_node != 1 || !DistributedAdmissionCopyThreadIdentity(&admission) ||
        admission.localNode != 1 || !Same(admission.run, s_threadIdentity.run, 16) ||
        s_threadIdentity.creatorNode != 1 || s_threadIdentity.threadCounter != 1 ||
        !Same(admission.memberIncarnations[0], s_threadIdentity.creatorIncarnation, 16))
        return Abort("thread-custody-identity");

    UINT64 operations = 0, authority = 0, publications = 0;
    BYTE completionAck[120]{}; size_t completionAckLength = 0;
    pthread_mutex_lock(&s_lock);
    bool valid = !s_aborted.load() && !s_shutdown.load() && s_workerDone.load(std::memory_order_acquire) &&
        s_workerResult == 0 && !s_publication.active && s_publicationCount == 1 &&
        s_publicationTransaction == s_publicationCount && s_next[1] > 1 && s_next[1] <= MaxOps + 1 &&
        s_threadLedger != nullptr && !s_threadLedger->IsAborted() &&
        s_threadLedger->CopyRecord(TP::Kind::CompletionAck, completionAck, sizeof(completionAck),
                                  &completionAckLength) && completionAckLength == 120;
    if (valid)
    { operations = s_next[1] - 1; authority = s_lastCommit[1]; publications = s_publicationCount; }
    pthread_mutex_unlock(&s_lock);
    if (!valid) return Abort("thread-custody-before-completion");

    DCG01Preimage::Identity identity{};
    std::memcpy(identity.runId, admission.run, 16);
    std::memcpy(identity.buildDigest, admission.buildManifestSha256, 32);
    std::memcpy(identity.runManifestDigest, admission.runManifestSha256, 32);
    std::memcpy(identity.incarnation, admission.memberIncarnations, sizeof(identity.incarnation));
    DCG01Preimage::LogicalId joined{};
    std::memcpy(joined.bytes, s_threadIdentity.run, 16);
    P32(joined.bytes + 16, s_threadIdentity.creatorNode);
    std::memcpy(joined.bytes + 20, s_threadIdentity.creatorIncarnation, 16);
    P64(joined.bytes + 36, s_threadIdentity.threadCounter);
    DCG01Custody::WorkerPreimage expectedPreimage{};
    DCG01Custody::Bundle expected{};
    if (!DCG01Custody::BuildExpectedWorker(identity, joined, operations, authority, publications,
                                         HashThreadCustody, &expectedPreimage) ||
        !DCG01Custody::EncodeBundle(expectedPreimage.commitment, expectedPreimage.commitmentLength,
                                    expectedPreimage.evidence, expectedPreimage.evidenceLength, &expected))
        return Abort("thread-custody-expected-preimage");

    BYTE ack[DCG01Custody::AckBytes]{};
    DCG01Custody::Accepted accepted = DCG01Custody::Accepted::Failed;
    pthread_mutex_lock(&s_lock);
    valid = !s_aborted.load() && !s_shutdown.load() && s_workerDone.load() &&
        !s_publication.active && s_next[1] - 1 == operations && s_lastCommit[1] == authority &&
        s_publicationCount == publications && !s_threadLedger->IsAborted();
    if (valid) accepted = DCG01Custody::Accept(&s_workerCustody, expected, wire, length, HashThreadCustody, ack);
    pthread_mutex_unlock(&s_lock);
    if (!valid || accepted == DCG01Custody::Accepted::Failed) return Abort("thread-custody-conflict-or-state");
    if (accepted==DCG01Custody::Accepted::Duplicate)
    {
        TraceThreadCustody("received",wire,length,true);
        return SendUntil(ack,sizeof(ack),23,deadline,true);
    }
    // Exact DCB1 bytes bind the worker's closed, empty logical-root snapshot.
    // Observe that cut only after authenticated custody validation and outside s_lock.
    if (!DistributedThreadTerminalRoots(4, nullptr, 0)) return Abort("thread-worker-root-cut-event");
    // Physical custody is already owned above. Defer its canonical observation
    // until Main return; no access/failure lock is held while awaiting that cut.
    const auto mainDeadline = Clock::now() + std::chrono::seconds(10);
    while (!s_mainReturnObserved.load(std::memory_order_acquire) && !s_aborted.load() &&
           Ready() && Clock::now() < mainDeadline) usleep(1000);
    if (!s_mainReturnObserved.load(std::memory_order_acquire) || s_aborted.load() || !Ready())
        return Abort("thread-custody-before-main-return");
    if (!DistributedThreadTerminalArtifact(3, 2, wire + DCG01Custody::HeaderBytes + U32(wire + 8), U32(wire + 12)))
        return Abort("thread-worker-evidence-custody-event");
    if (!DistributedThreadTerminalPrepared(2, wire + DCG01Custody::HeaderBytes, U32(wire + 8)))
        return Abort("thread-worker-preparation-event");
    // Exact received bytes are already owned by the coordinator. ACK enqueue is not retirement.
    TraceThreadCustody("received", wire, length, accepted == DCG01Custody::Accepted::Duplicate);
    s_workerCustodyReceived.store(true, std::memory_order_release);
    // Main can now validate both preparations and commit locally. The ACK then
    // orders that transition before the worker's commitment, without a lock wait.
    const auto commitDeadline = Clock::now() + std::chrono::seconds(10);
    while (!s_coordinatorCommitted.load(std::memory_order_acquire) && !s_aborted.load() &&
           Ready() && Clock::now() < commitDeadline) usleep(1000);
    if (!s_coordinatorCommitted.load(std::memory_order_acquire) || s_aborted.load() || !Ready())
        return Abort("thread-custody-before-coordinator-commit");
    if (!SendUntil(ack, sizeof(ack), 23, deadline)) return false;
    return true;
}

bool ThreadSendCustody()
{
    if (s_node != 2 || !s_threadRootProfile || !s_threadParticipantPreimagePublished.load(std::memory_order_acquire) ||
        s_workerSentCustody.length != 0 || s_aborted.load() || s_shutdown.load()) return false;
    const ThreadParticipantPreimage& own = s_threadParticipantPreimage;
    if (own.node != 2 || !DCG01Custody::EncodeBundle(own.commitment, own.commitmentLength,
                                                   own.evidence, own.evidenceLength, &s_workerSentCustody)) return false;
    if (!Send(s_workerSentCustody.bytes, static_cast<unsigned>(s_workerSentCustody.length), 22)) return false;
    TraceThreadCustody("sent", s_workerSentCustody.bytes, s_workerSentCustody.length, false);
    return true;
}

bool ThreadConsumeCustodyAck(const BYTE* wire, unsigned length)
{
    if (s_node != 2 || s_aborted.load() || s_shutdown.load() ||
        !DCG01Custody::VerifyAck(s_workerSentCustody, wire, length, HashThreadCustody))
        return Abort("thread-custody-ack");
    TraceThreadCustody("acknowledged", wire, length, false);
    // The closed application/root cut and exact owned preimage were captured
    // before custody send. Its matching ACK proves that those bytes are owned
    // by the coordinator before this irrevocable local transition.
    if (!s_threadRootInventoryPublished.load(std::memory_order_acquire) ||
        !s_threadParticipantPreimagePublished.load(std::memory_order_acquire))
        return Abort("thread-commitment-before-closed-cut");
    const auto& cut = s_threadRootInventory.cut;
    DCG01Commit::Frame committed{};
    if (!DistributedThreadTerminalCommitWorker(cut.lastAcceptedOperationSequence,cut.authorityFrontier,
        cut.publicationFrontier,&s_workerSentCustody,wire,length,&committed))
        return Abort("thread-worker-terminal-commitment");
    if (s_workerSentCommitment.length)
    {
        // Identical ACK traffic is harmless; an accepted send is never replayed.
        if (s_workerSentCommitment.length != committed.length ||
            !Same(s_workerSentCommitment.bytes,committed.bytes,static_cast<unsigned>(committed.length)))
            return Abort("thread-worker-terminal-commitment-conflict");
        return true;
    }
    if (!Send(committed.bytes,static_cast<unsigned>(committed.length),22)) return false;
    s_workerSentCommitment = committed;
    TraceThreadCustody("commitment-sent",committed.bytes,static_cast<unsigned>(committed.length),false);
    return true;
}

bool ThreadCommitmentServiceFrame(const BYTE* wire, unsigned length)
{
    DCG01Custody::Bundle custody{};
    pthread_mutex_lock(&s_lock);
    const bool valid = s_node == 1 && !s_aborted.load() && !s_shutdown.load() &&
        s_workerCustodyReceived.load(std::memory_order_acquire) && s_workerCustody.hasCustody && !s_workerCustody.failed;
    if (valid) custody = s_workerCustody.received;
    pthread_mutex_unlock(&s_lock);
    if (!valid || !DistributedThreadTerminalReceiveWorkerCommit(&custody,wire,length))
        return Abort("thread-worker-terminal-commitment-receipt");
    const bool duplicate = s_workerCommitmentReceived.exchange(true,std::memory_order_acq_rel);
    TraceThreadCustody("commitment-received",wire,length,duplicate);
    return true;
}

void* Service(void*)
{
    const auto entryDeadline = Clock::now() + std::chrono::seconds(10);
    while (!s_shutdown.load() && !s_aborted.load())
    {
        BYTE message[4096]{}, response[ReplyBytes]{};
        // After entry there is no outstanding receive obligation while application code runs.
        // Liveness loss still aborts. Each reply/ACK send retains its own bounded queue wait.
        auto deadline = s_threadMode ? (s_threadEntered.load() ? Clock::time_point::max() : entryDeadline) :
            Clock::now() + std::chrono::seconds(30);
        int size = Receive(message, 22, deadline);
        if (size < 0) break;
        if (s_threadMode && IsThreadFrame(message, static_cast<unsigned>(size)))
        {
            if (!ThreadServiceFrame(message, static_cast<unsigned>(size), deadline)) break;
        }
        else if (s_threadRootProfile && DCG01Custody::IsBundle(message, static_cast<unsigned>(size)))
        {
            if (!ThreadCustodyServiceFrame(message, static_cast<unsigned>(size), deadline)) break;
        }
        else if (s_threadRootProfile && DCG01Commit::IsFrame(message, static_cast<unsigned>(size)))
        {
            if (!ThreadCommitmentServiceFrame(message, static_cast<unsigned>(size))) break;
        }
        else if (size == RequestBytes && std::memcmp(message, "DAO1", 4) == 0)
        {
            if (s_threadMode && (!s_threadEntered.load() || s_workerDone.load()))
            { Abort("thread-access-before-entry-or-after-completion"); break; }
            if (!Commit(2, message, response)) break;
            // Fixed test-profile delay makes the GC-across-wait contract observable.
            // This happens after commit and outside the authority/transport locks.
            usleep(2000);
            s_delayedReplies++;
            if (!Send(response, sizeof(response), 23)) break;
        }
        else if (s_threadRootProfile && size >= 4 && std::memcmp(message, "DCL1", 4) == 0)
        {
            if (!ThreadAdmissionClosedFrame(message, static_cast<unsigned>(size))) break;
        }
        else if (s_threadRootProfile && size == 8 + ReplyBytes && std::memcmp(message, "DCO1", 4) == 0)
        {
            if (U32(message + 4) != 1 || s_workerDone.load() ||
                !DistributedThreadTerminalAccess(2, nullptr, message + 8, ReplyBytes, 0))
            { Abort("thread-reply-observation"); break; }
        }
        else if (s_publicationMode && size >= 4 && std::memcmp(message, "DPA1", 4) == 0)
        {
            if (!AcceptPublicationAck(message, static_cast<unsigned>(size))) break;
        }
        else if (!s_threadMode && size == 32 && std::memcmp(message, "DAF1", 4) == 0 &&
            U32(message + 4) == 1 && U32(message + 28) <= U64(message + 8))
        {
            bool valid;
            pthread_mutex_lock(&s_lock);
            valid = !s_publication.active && !s_workerDone.load() && U64(message + 8) == s_next[1] - 1 &&
                U64(message + 16) == s_lastCommit[1] && U32(message + 24) == 0;
            if (valid)
            {
                s_workerResult = static_cast<int>(U32(message + 24));
                s_workerGcWaits = U32(message + 28);
                s_workerDone.store(true, std::memory_order_release);
            }
            pthread_mutex_unlock(&s_lock);
            if (!valid || s_workerResult != 0) { Abort("worker-body-result"); break; }
            std::fprintf(stderr, "DC_ACCESS phase=worker-body-returned node=2\n");
        }
        else { Abort("service-frame"); break; }
    }
    return nullptr;
}

bool ReceivePublication(const BYTE* wire, unsigned length, Clock::time_point deadline)
{
    if (!s_publicationMode || s_node != 2 || length < 76 || std::memcmp(wire, "DGP1", 4) != 0 ||
        U32(wire + 4) != 1) return Abort("publication-offer-shape");
    UINT64 transaction = U64(wire + 8);
    BYTE digest[32]{};
    SHA256(wire, length, digest);
    if (transaction == 0 || transaction > MaxSeeds) return Abort("publication-offer-transaction");
    BYTE* ack = s_receiverAcks[transaction - 1];
    if (transaction <= s_receivedPublication)
    {
        if (!Same(ack + 40, digest, 32)) return Abort("publication-offer-conflict");
        return SendUntil(ack, PublicationAckBytes, 22, deadline);
    }
    if (transaction != s_receivedPublication + 1) return Abort("publication-offer-sequence");
    DistributedPublicationBatch batch{};
    bool imported;
    {
        GCX_COOP();
        imported = DistributedIdentityImportPublication(wire, length, &batch);
    }
    if (!imported || batch.transaction != transaction || batch.count == 0 ||
        batch.count > DistributedPublicationMaxObjects || batch.stagedTransferRoots != batch.count ||
        batch.gcCollections == 0 || batch.moved > 1)
        return Abort("publication-import-custody");
    std::memcpy(ack, "DPA1", 4); P32(ack + 4, 1);
    P64(ack + 8, transaction); P64(ack + 16, batch.sourceFrontier);
    P32(ack + 24, batch.count); P32(ack + 28, batch.gcCollections);
    P32(ack + 32, batch.moved); P32(ack + 36, batch.stagedTransferRoots);
    std::memcpy(ack + 40, digest, 32);
    s_receivedPublication = transaction;
    // Bounded diagnostic window for source GC while custody exists but ACK is not sent.
    // Preemptive mode, no runtime/authority lock; this is not a performance experiment.
    usleep(20000);
    if (!SendUntil(ack, PublicationAckBytes, 22, deadline)) return false;
    // The ACK does not retire receiver custody. Force a collection before resuming
    // the interrupted ordinary access and re-resolve the same canonical root.
    bool retained = false;
    {
        GCX_COOP();
        OBJECTREF root = NULL;
        GCPROTECT_BEGIN(root);
        if (DistributedIdentityResolveReference(batch.root, &root))
        {
            GCHeapUtilities::GetGCHeap()->GarbageCollect(2, false, collection_compacting | collection_blocking);
            OBJECTREF again = NULL;
            retained = DistributedIdentityResolveReference(batch.root, &again) && again == root;
        }
        GCPROTECT_END();
    }
    if (!retained) return Abort("publication-post-ack-root");
    if (s_threadRootProfile && !RecordReceiverRetainedSeeds(batch.seeds, batch.count))
        return Abort("publication-receiver-retained-set");
    s_completedPublication = transaction;
    std::fprintf(stderr, "DC_PUBLICATION phase=post-ack-root node=2 transaction=%llu retained=1\n",
        static_cast<unsigned long long>(transaction));
    return true;
}

bool ThreadConsumeDuplicate(const BYTE* wire, unsigned length, Clock::time_point deadline)
{
    TP::Observation observation{};
    if (!s_threadLedger->AcceptRemote(wire, length, nullptr, &observation) ||
        observation.disposition == TP::Disposition::Recorded)
        return Abort("thread-unexpected-lifecycle");
    TraceThreadFrame("remote", wire, length);
    return ThreadCachedReply(observation, deadline);
}

int ThreadWait(const char* expected, BYTE (&wire)[4096], Clock::time_point deadline)
{
    while (!s_aborted.load())
    {
        int length = Receive(wire, s_node == 1 ? 22 : 23, deadline);
        if (length < 0) return -1;
        // Only the actual child may import publication during its entry-ACK wait.
        // Staging waits before grant or after physical Join cannot touch the directory.
        if (s_node == 2 && std::strcmp(expected, "DTA1") == 0 && length >= 4 &&
            std::memcmp(wire, "DGP1", 4) == 0)
        {
            if (!ReceivePublication(wire, static_cast<unsigned>(length), deadline)) return -1;
            continue;
        }
        TP::Observation observation{};
        if (!s_threadLedger->AcceptRemote(wire, static_cast<unsigned>(length), nullptr, &observation))
        { Abort("thread-await-ledger"); return -1; }
        TraceThreadFrame("remote", wire, static_cast<unsigned>(length));
        if (observation.disposition == TP::Disposition::Recorded)
        {
            if (std::memcmp(wire, expected, 4) == 0) return length;
            Abort("thread-await-kind");
            return -1;
        }
        if (!ThreadCachedReply(observation, deadline)) return -1;
    }
    return -1;
}

int ReceiveAccessReply(BYTE (&message)[4096], bool* gcWhileAwaiting)
{
    auto deadline = Clock::now() + std::chrono::seconds(10);
    *gcWhileAwaiting = false;
    while (true)
    {
        if (Clock::now() >= deadline)
        {
            Abort("publication-reply-deadline");
            return -1;
        }
        bool collected = false;
        int size = Receive(message, 23, deadline, &collected);
        *gcWhileAwaiting = *gcWhileAwaiting || collected;
        if (size < 0) return size;
        if (s_threadMode && IsThreadFrame(message, static_cast<unsigned>(size)))
        {
            if (!ThreadConsumeDuplicate(message, static_cast<unsigned>(size), deadline)) return -1;
            continue;
        }
        if (s_publicationMode && size >= 4 && std::memcmp(message, "DGP1", 4) == 0)
        {
            auto publicationDeadline = s_threadMode ? deadline : Clock::now() + std::chrono::seconds(10);
            if (!ReceivePublication(message, static_cast<unsigned>(size), publicationDeadline)) return -1;
            continue; // Preserve the original request ID and deadline; never replay it.
        }
        return size;
    }
}

void Request(unsigned operation, unsigned slot, const DistributedObjectId& id, const BYTE* value, BYTE* reply,
    const DistributedPublicationBatch* publication = nullptr, unsigned acknowledgementGc = 0)
{
    BYTE request[RequestBytes]{};
    std::memcpy(request, "DAO1", 4); P32(request + 4, 1);
    P64(request + 8, ++s_request); P32(request + 16, operation); P32(request + 20, slot);
    std::memcpy(request + 24, id.bytes, 44);
    if (value) std::memcpy(request + 68, value, 44);
    bool accepted, gcWhileAwaiting = false;
    if (s_node == 1) accepted = Commit(1, request, reply, publication, acknowledgementGc);
    else
    {
        BYTE message[4096]{};
        accepted = Send(request, sizeof(request), 22) &&
            ReceiveAccessReply(message, &gcWhileAwaiting) == ReplyBytes;
        if (accepted) std::memcpy(reply, message, ReplyBytes);
    }
    if (!accepted || std::memcmp(reply, "DAP1", 4) != 0 || U32(reply + 4) != 1 ||
        U64(reply + 8) != s_request || U64(reply + 16) <= s_lastReply ||
        U64(reply + 16) > MaxOps || U32(reply + 24) != operation || U32(reply + 28) != slot ||
        !Same(reply + 32, id.bytes, 44) ||
        ((operation != 2 && operation != 3) && !Zero(reply + 80, 40)) ||
        ((operation & 1) && !Same(reply + 76, value, 44)))
        Reject("response-identity-or-uncertainty");
    if (gcWhileAwaiting) s_workerGcWaits++;
    s_lastReply = U64(reply + 16);
    s_completedRequest = s_request;
    if (s_threadRootProfile)
    {
        if (s_node == 1)
        {
            if (!DistributedThreadTerminalAccess(1, nullptr, reply, ReplyBytes, 0)) Reject("local-reply-observation");
        }
        else
        {
            BYTE observed[8 + ReplyBytes]{};
            std::memcpy(observed, "DCO1", 4); P32(observed + 4, 1);
            std::memcpy(observed + 8, reply, ReplyBytes);
            if (!Send(observed, sizeof(observed), 22)) Reject("remote-reply-observation");
        }
    }
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

void PublishReference(QCall::ObjectHandleOnStack value, const DistributedObjectId& target, unsigned slot)
{
    UINT64 transaction = 0, frontier = 0;
    bool permitted;
    pthread_mutex_lock(&s_lock);
    permitted = s_publicationMode && s_node == 1 && !s_publication.active && !s_workerDone.load() &&
        !s_aborted.load() && !s_finished.load() && s_committed < MaxOps &&
        s_publicationTransaction < MaxSeeds;
    if (permitted)
    {
        transaction = ++s_publicationTransaction;
        frontier = s_committed;
    }
    pthread_mutex_unlock(&s_lock);
    if (!permitted) Reject("publication-state-or-bound");

    BYTE wire[4096]{};
    unsigned length = 0;
    DistributedPublicationBatch batch{};
    bool prepared;
    {
        GCX_COOP();
        prepared = DistributedIdentityPreparePublication(value.Get(), transaction, frontier,
            wire, sizeof(wire), &length, &batch);
    }
    if (!prepared || length < 76 || length > sizeof(wire) || batch.transaction != transaction ||
        batch.sourceFrontier != frontier || batch.count == 0 ||
        batch.count > DistributedPublicationMaxObjects || batch.stagedTransferRoots != batch.count)
        Reject("publication-export");
    BYTE digest[32]{};
    SHA256(wire, length, digest);
    pthread_mutex_lock(&s_lock);
    permitted = !s_aborted.load() && !s_workerDone.load() && !s_publication.active;
    if (permitted)
    {
        s_publication = {};
        s_publication.active = true;
        s_publication.transaction = transaction;
        s_publication.sourceFrontier = frontier;
        s_publication.count = batch.count;
        std::memcpy(s_publication.digest, digest, 32);
    }
    pthread_mutex_unlock(&s_lock);
    if (permitted && s_threadRootProfile)
    {
        BYTE objectIds[DistributedPublicationMaxObjects * 44]{};
        for (unsigned i = 0; i < batch.count; ++i) std::memcpy(objectIds + i * 44, batch.seeds[i].id.bytes, 44);
        permitted = DistributedThreadTerminalPublication(static_cast<unsigned>(DCG01Events::Publication::Prepared),
            transaction, batch.root.bytes, objectIds, batch.count);
    }
    if (!permitted || !Send(wire, length, 23)) Reject("publication-offer");
    std::fprintf(stderr, "DC_PUBLICATION phase=offered node=1 transaction=%llu count=%u frontier=%llu\n",
        static_cast<unsigned long long>(transaction), batch.count,
        static_cast<unsigned long long>(frontier));

    bool acknowledged = false, awaiting = false;
    unsigned collectionsBefore = 0, acknowledgementGc = 0;
    auto deadline = Clock::now() + std::chrono::seconds(10);
    while (!s_aborted.load() && Ready() && Clock::now() < deadline)
    {
        pthread_mutex_lock(&s_lock);
        acknowledged = s_publication.active && s_publication.transaction == transaction &&
            s_publication.acknowledged && !s_workerDone.load();
        pthread_mutex_unlock(&s_lock);
        if (acknowledged) break;
        if (!awaiting)
        {
            collectionsBefore = GCHeapUtilities::GetGCHeap()->GetGcCount();
            awaiting = true;
        }
        usleep(1000);
    }
    if (!acknowledged || !Ready()) Reject("publication-ack-uncertainty");
    if (awaiting)
        acknowledgementGc = GCHeapUtilities::GetGCHeap()->GetGcCount() - collectionsBefore;
    {
        GCX_COOP();
        if (!DistributedIdentityActivatePublication(transaction)) Reject("publication-source-custody");
    }
    if (s_threadRootProfile && !DistributedThreadTerminalPublication(
        static_cast<unsigned>(DCG01Events::Publication::Activated), transaction, nullptr, nullptr, 0))
        Reject("publication-activation-event");
    BYTE response[ReplyBytes]{};
    Request(3, slot, target, batch.root.bytes, response, &batch, acknowledgementGc);
    {
        GCX_COOP();
        if (!DistributedIdentityCompletePublication(transaction)) Reject("publication-root-handoff");
    }
    if (s_threadRootProfile && !DistributedThreadTerminalPublication(
        static_cast<unsigned>(DCG01Events::Publication::Completed), transaction, nullptr, nullptr, 0))
        Reject("publication-completion-event");
    s_completedPublication = transaction;
    std::fprintf(stderr, "DC_PUBLICATION phase=committed node=1 transaction=%llu sequence=%llu wait_gc=%u\n",
        static_cast<unsigned long long>(transaction), static_cast<unsigned long long>(s_lastReply),
        acknowledgementGc);
}

int Target(QCall::ObjectHandleOnStack target, UINT_PTR location, bool array,
    DistributedObjectId* id, unsigned* slot)
{
    if (target.Get() == NULL) COMPlusThrow(kNullReferenceException);
    int entry = DistributedIdentityAccessTarget(target.Get(), location, array, id, slot);
    if (entry == -3) COMPlusThrow(kIndexOutOfRangeException);
    if (entry == -2) Reject("target-capability");
    return entry;
}
}

bool DistributedAccessCaptureQuiescentSnapshot(DistributedAccessQuiescentSnapshot* output)
{
    DistributedThreadAdmissionSnapshot admission{};
    if (output == nullptr || !DistributedThreadCaptureClosedAdmission(&admission))
        return false;
    DistributedAccessQuiescentSnapshot captured{};
    pthread_mutex_lock(&s_lock);
    bool valid = s_threadMode && s_open.load() && !s_aborted.load() && !s_shutdown.load() &&
        admission.identity.localNode == s_node && (s_node == 1 || s_node == 2) &&
        !s_publication.active && s_request == s_completedRequest && s_request <= MaxOps &&
        s_lastReply <= MaxOps && ((s_request == 0) == (s_lastReply == 0)) &&
        s_completedPublication <= MaxSeeds;
    if (valid && s_node == 1)
    {
        // Worker completion is published after its final reply and completion ACK enqueue.
        valid = s_finished.load() && s_workerDone.load(std::memory_order_acquire) &&
            s_workerResult == 0 && s_next[0] == s_completedRequest + 1 &&
            s_next[1] > 0 && s_next[1] <= MaxOps + 1 && s_committed <= MaxOps &&
            s_committed == s_completedRequest + s_next[1] - 1 &&
            s_lastCommit[0] == s_lastReply && s_lastCommit[0] <= s_committed &&
            s_lastCommit[1] <= s_committed && ((s_next[1] == 1) == (s_lastCommit[1] == 0)) &&
            s_completedPublication == s_publicationTransaction &&
            s_completedPublication == s_publicationCount;
    }
    else if (valid)
    {
        valid = s_callbackReturned.load(std::memory_order_acquire) &&
            s_returnFacts.workerSequence == s_completedRequest &&
            s_returnFacts.authorityFrontier == s_lastReply &&
            s_completedPublication == s_receivedPublication;
    }
    if (valid)
    {
        captured.identity = admission.identity;
        captured.admissionGeneration = admission.generation;
        captured.lastAcceptedOperationSequence = s_completedRequest;
        captured.authorityFrontier = s_node == 1 ? s_committed : s_lastReply;
        captured.publicationFrontier = s_completedPublication;
    }
    pthread_mutex_unlock(&s_lock);
    if (valid) *output = captured;
    return valid;
}

// Only called at the two source-owned post-application cuts below: successful Main
// return on the coordinator, or the immutable child snapshot after actual worker Join.
// The hash-admitted profile has no application statics or other application frames.
// Runtime strong handles (including the staged target) remain physical retention.
static bool CaptureClosedThreadRootInventory(const dcg01_identity_snapshot::Snapshot& identity)
{
    using namespace dcg01_identity_snapshot;
    if (!s_threadRootProfile || s_threadRootInventoryPublished.load(std::memory_order_acquire))
        return false;
    ThreadRootInventory captured{};
    if (!DistributedAccessCaptureQuiescentSnapshot(&captured.cut)) return false;
    const DistributedIdentityContext& context = captured.cut.identity;
    if (identity.schemaVersion != 1 || identity.failed != 0 || identity.frozen != 1 ||
        identity.localNode != context.localNode || identity.peerNode != context.peerNode ||
        !Same(identity.run, context.run, 16) || !Same(identity.localInc, context.localInc, 16) ||
        !Same(identity.peerInc, context.peerInc, 16) || !Same(identity.assemblyHash, context.assemblyHash, 32) ||
        !Same(identity.mvid, context.mvid, 16) || Zero(context.run, 16) ||
        Zero(context.localInc, 16) || Zero(context.peerInc, 16) ||
        context.peerNode != (context.localNode == 1 ? 2u : 1u) ||
        identity.entryCount != 4 || identity.publication.phase != Idle ||
        identity.pendingPublicationRootCount != 0 || !IdlePublicationIsZero(identity.publication) ||
        captured.cut.admissionGeneration != 2 || captured.cut.publicationFrontier != 1)
        return false;

    SourceState source{};
    std::memcpy(source.run, identity.run, 16);
    source.localNode = identity.localNode; source.peerNode = identity.peerNode;
    std::memcpy(source.localInc, identity.localInc, 16);
    std::memcpy(source.peerInc, identity.peerInc, 16);
    source.entryCount = identity.entryCount; source.retainedBytes = identity.retainedBytes;
    std::memcpy(source.entries, identity.entries, sizeof(source.entries));
    if (!Valid(source)) return false;

    // Compare the exact retained set with the access authority/receiver set, under its
    // local lock. Counts alone cannot discharge missing/duplicate transfer identities.
    pthread_mutex_lock(&s_lock);
    const unsigned retainedCount = s_node == 1 ? s_count : s_receiverRetainedCount;
    bool valid = !s_aborted.load() && !s_shutdown.load() && retainedCount == 4 &&
        s_initialSeedCount == 2 && (s_node == 1 || s_count == s_initialSeedCount);
    bool seen[4]{};
    for (unsigned i = 0; valid && i < identity.entryCount; i++)
    {
        const Entry& entry = identity.entries[i];
        const UINT64 counter = U64(entry.id + 36);
        valid = entry.owner == 1 && entry.retention == (s_node == 1 ? 1u : 4u) &&
            counter >= 1 && counter <= 4;
        if (!valid) break;
        int index = -1;
        for (unsigned j = 0; j < retainedCount; j++)
        {
            const BYTE* retainedId = s_node == 1 ? s_seeds[j].id.bytes : s_receiverRetainedIds[j].bytes;
            if (Same(entry.id, retainedId, 44)) { index = static_cast<int>(j); break; }
        }
        if (index < 0 || seen[index]) { valid = false; break; }
        seen[index] = true;
    }
    pthread_mutex_unlock(&s_lock);
    if (!valid) return false;

    // R3 canonical root-inventory bytes, without a domain prefix. This bounded run has
    // one epoch and one inventory per member; publication below is one-way. This is not
    // the immutable terminal commitment or an output/evidence custody certificate.
    DC022Canonical::Writer writer(captured.canonical, sizeof(captured.canonical));
    const auto key = [&writer](const char* name) { return writer.Key(name, std::strlen(name)); };
    const char schema[] = "dc022-root-inventory";
    if (!writer.BeginObject() ||
        !key("incarnation_id") || !writer.Hex(context.localInc, 16) ||
        !key("member_id") || !writer.UInt(context.localNode) ||
        !key("object_ids") || !writer.BeginArray() || !writer.EndArray() ||
        !key("run_id") || !writer.Hex(context.run, 16) ||
        !key("schema") || !writer.String(schema, sizeof(schema) - 1) ||
        !key("snapshot_id") || !writer.UInt(1) ||
        !key("terminal_epoch") || !writer.UInt(1) ||
        !key("version") || !writer.UInt(2) || !writer.EndObject() || !writer.Finish())
        return false;
    captured.length = static_cast<unsigned>(writer.Size());
    if (SHA256(captured.canonical, captured.length, captured.digest) == nullptr) return false;
    captured.retainedCount = identity.entryCount;
    captured.retainedBytes = identity.retainedBytes;
    s_threadRootInventory = captured;
    s_threadRootInventoryPublished.store(true, std::memory_order_release);
    return true;
}

static bool HashThreadPreimage(const unsigned char* bytes, size_t length, unsigned char digest[32])
{
    return SHA256(bytes, length, digest) != nullptr;
}

// Called once by the source owner at the same closed cut as the root inventory.
// These immutable preimages are preparation, not terminal custody, retirement or seal.
static bool CaptureThreadParticipantPreimage(const DCG01Output::ArtifactInfo* output)
{
    if (!s_threadRootProfile || !s_threadRootInventoryPublished.load(std::memory_order_acquire) ||
        s_threadParticipantPreimagePublished.load(std::memory_order_acquire) ||
        s_aborted.load() || s_shutdown.load()) return false;
    const ThreadRootInventory& roots = s_threadRootInventory;
    const DistributedIdentityContext& context = roots.cut.identity;
    DistributedAdmissionThreadIdentity admission{};
    if (!DistributedAdmissionCopyThreadIdentity(&admission) ||
        (context.localNode != 1 && context.localNode != 2) ||
        admission.localNode != context.localNode || context.peerNode != 3 - context.localNode ||
        !Same(admission.run, context.run, 16) || Zero(admission.run, 16) ||
        Zero(admission.runManifestSha256, 32) || Zero(admission.buildManifestSha256, 32) ||
        Zero(admission.memberIncarnations[0], 16) || Zero(admission.memberIncarnations[1], 16) ||
        Same(admission.memberIncarnations[0], admission.memberIncarnations[1], 16) ||
        !Same(admission.memberIncarnations[context.localNode - 1], context.localInc, 16) ||
        !Same(admission.memberIncarnations[context.peerNode - 1], context.peerInc, 16) ||
        !Same(s_threadIdentity.run, context.run, 16) || s_threadIdentity.creatorNode != 1 ||
        s_threadIdentity.threadCounter != 1 ||
        !Same(s_threadIdentity.creatorIncarnation, admission.memberIncarnations[0], 16) ||
        !Same(s_threadIdentity.assemblySha256, context.assemblyHash, 32) ||
        !Same(s_threadIdentity.mvid, context.mvid, 16)) return false;

    DistributedAccessQuiescentSnapshot current{};
    if (!DistributedAccessCaptureQuiescentSnapshot(&current) ||
        current.admissionGeneration != roots.cut.admissionGeneration || current.admissionGeneration != 2 ||
        current.lastAcceptedOperationSequence != roots.cut.lastAcceptedOperationSequence ||
        current.authorityFrontier != roots.cut.authorityFrontier ||
        current.publicationFrontier != roots.cut.publicationFrontier || current.publicationFrontier != 1 ||
        current.identity.localNode != context.localNode || current.identity.peerNode != context.peerNode ||
        !Same(current.identity.run, context.run, 16) ||
        !Same(current.identity.localInc, context.localInc, 16) ||
        !Same(current.identity.peerInc, context.peerInc, 16) ||
        !Same(current.identity.assemblyHash, context.assemblyHash, 32) ||
        !Same(current.identity.mvid, context.mvid, 16)) return false;

    // CopyRecord succeeds only after the validated seven-frame lifecycle reached ACK.
    // No network operation or wait occurs while this local lock is held.
    BYTE acknowledgement[120]{};
    size_t acknowledgementLength = 0;
    pthread_mutex_lock(&s_lock);
    bool acknowledged = !s_aborted.load() && !s_shutdown.load() && s_threadLedger != nullptr &&
        !s_threadLedger->IsAborted() && s_threadLedger->CopyRecord(TP::Kind::CompletionAck,
            acknowledgement, sizeof(acknowledgement), &acknowledgementLength) && acknowledgementLength == 120;
    pthread_mutex_unlock(&s_lock);
    if (!acknowledged) return false;

    // This profile reserves output ID1 for the actual CorHost publisher. Evidence IDs
    // 2 and 3 name these members' bounded local evidence bytes; custody is still pending.
    if (context.localNode == 1)
    {
        if (output == nullptr || output->artifactId != 1 || output->contentBytes == 0 ||
            output->contentBytes > DCG01Preimage::kMaxArtifactBytes || Zero(output->sha256, 32)) return false;
    }
    else if (output != nullptr) return false;

    ThreadParticipantPreimage captured{};
    captured.node = context.localNode;
    DC022Canonical::Writer rootPayload(captured.rootPayload, sizeof(captured.rootPayload));
    if (!rootPayload.BeginObject() || !rootPayload.Key("chunk_count") || !rootPayload.UInt(0) ||
        !rootPayload.Key("chunk_index") || !rootPayload.UInt(0) ||
        !rootPayload.Key("object_ids") || !rootPayload.BeginArray() || !rootPayload.EndArray() ||
        !rootPayload.Key("owner_member_id") || !rootPayload.UInt(context.localNode) ||
        !rootPayload.Key("snapshot_id") || !rootPayload.UInt(1) || !rootPayload.EndObject() ||
        !rootPayload.Finish()) return false;
    captured.rootPayloadLength = rootPayload.Size();

    // Opaque R3 evidence artifact, versioned locally. Output metadata is copied from
    // successful Publish, not reconstructed from stdout or an expected fixture string.
    DC022Canonical::Writer evidence(captured.evidence, sizeof(captured.evidence));
    if (!evidence.BeginObject() || !evidence.Key("admission_generation") ||
        !evidence.UInt(current.admissionGeneration) || !evidence.Key("application_output")) return false;
    if (output != nullptr)
    {
        if (!evidence.BeginObject() || !evidence.Key("artifact_id") || !evidence.UInt(output->artifactId) ||
            !evidence.Key("content_bytes") || !evidence.UInt(output->contentBytes) ||
            !evidence.Key("sha256") || !evidence.Hex(output->sha256, 32) || !evidence.EndObject()) return false;
    }
    else if (!evidence.Null()) return false;
    if (!evidence.Key("root_inventory_sha256") || !evidence.Hex(roots.digest, 32) ||
        !evidence.Key("schema") || !evidence.String("dcg01-closed-thread-evidence") ||
        !evidence.Key("version") || !evidence.UInt(1) || !evidence.EndObject() || !evidence.Finish()) return false;
    captured.evidenceLength = evidence.Size();
    if (!HashThreadPreimage(captured.evidence, captured.evidenceLength, captured.evidenceDigest)) return false;

    DCG01Preimage::Identity identity{};
    std::memcpy(identity.runId, admission.run, 16);
    std::memcpy(identity.buildDigest, admission.buildManifestSha256, 32);
    std::memcpy(identity.runManifestDigest, admission.runManifestSha256, 32);
    std::memcpy(identity.incarnation, admission.memberIncarnations, sizeof(identity.incarnation));
    DCG01Preimage::Participant participant{};
    participant.memberId = context.localNode;
    participant.snapshotId = 1;
    DCG01Preimage::Prepared& prepared = participant.prepared;
    prepared.terminalEpoch = 1;
    prepared.lastOperation = current.lastAcceptedOperationSequence;
    prepared.authorityFrontier = current.authorityFrontier;
    prepared.publicationFrontier = current.publicationFrontier;
    prepared.joinedCount = 1;
    BYTE* joined = prepared.joinedThreadIds[0].bytes;
    std::memcpy(joined, s_threadIdentity.run, 16);
    P32(joined + 16, s_threadIdentity.creatorNode);
    std::memcpy(joined + 20, s_threadIdentity.creatorIncarnation, 16);
    P64(joined + 36, s_threadIdentity.threadCounter);
    std::memcpy(prepared.rootInventoryDigest, roots.digest, 32);
    if (output != nullptr) { prepared.resultArtifactCount = 1; prepared.resultArtifactIds[0] = output->artifactId; }
    prepared.evidenceArtifactId = context.localNode + 1;
    prepared.evidenceBytes = captured.evidence;
    prepared.evidenceLength = captured.evidenceLength;
    std::memcpy(prepared.evidenceDigest, captured.evidenceDigest, 32);

    BYTE canonicalRoots[512]{}, rootDigest[32]{};
    size_t rootLength = 0;
    if (!DCG01Preimage::RootInventory(identity, participant, HashThreadPreimage, canonicalRoots,
            sizeof(canonicalRoots), &rootLength, rootDigest) || rootLength != roots.length ||
        !Same(canonicalRoots, roots.canonical, rootLength) || !Same(rootDigest, roots.digest, 32) ||
        !DCG01Preimage::EncodeParticipant(identity, participant, HashThreadPreimage, captured.commitment,
            sizeof(captured.commitment), &captured.commitmentLength, captured.commitmentDigest)) return false;

    pthread_mutex_lock(&s_lock);
    bool valid = !s_aborted.load() && !s_shutdown.load() && !s_threadLedger->IsAborted() &&
        !s_threadParticipantPreimagePublished.load(std::memory_order_acquire);
    if (valid)
    {
        s_threadParticipantPreimage = captured; // Bytes only; no pointer to the stack is retained.
        s_threadParticipantPreimagePublished.store(true, std::memory_order_release);
    }
    pthread_mutex_unlock(&s_lock);
    return valid;
}

static void TraceThreadParticipantPreimage()
{
    const ThreadParticipantPreimage& captured = s_threadParticipantPreimage;
    char rootPayload[sizeof(captured.rootPayload) * 2 + 1]{};
    char evidence[sizeof(captured.evidence) * 2 + 1]{};
    char commitment[sizeof(captured.commitment) * 2 + 1]{};
    char digest[65]{};
    const auto hex = [](const BYTE* bytes, size_t length, char* out) {
        const char digits[] = "0123456789abcdef";
        for (size_t i = 0; i < length; ++i) { out[2*i] = digits[bytes[i] >> 4]; out[2*i+1] = digits[bytes[i] & 15]; }
    };
    hex(captured.rootPayload, captured.rootPayloadLength, rootPayload);
    hex(captured.evidence, captured.evidenceLength, evidence);
    hex(captured.commitment, captured.commitmentLength, commitment);
    hex(captured.commitmentDigest, 32, digest);
    std::fprintf(stderr,
        "DC_THREAD phase=participant-preimage-diagnostic node=%u root_payload_hex=%s evidence_hex=%s commitment_bytes=%zu commitment_sha256=%s commitment_hex=%s terminal=0\n",
        captured.node, rootPayload, evidence, captured.commitmentLength, digest, commitment);
}

static void TraceThreadRootInventory()
{
    const ThreadRootInventory& inventory = s_threadRootInventory;
    char encoded[sizeof(inventory.canonical) * 2 + 1]{};
    char digest[65]{};
    const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < inventory.length; i++)
    {
        encoded[2 * i] = digits[inventory.canonical[i] >> 4];
        encoded[2 * i + 1] = digits[inventory.canonical[i] & 15];
    }
    for (unsigned i = 0; i < 32; i++)
    {
        digest[2 * i] = digits[inventory.digest[i] >> 4];
        digest[2 * i + 1] = digits[inventory.digest[i] & 15];
    }
    std::fprintf(stderr,
        "DC_THREAD phase=root-inventory-diagnostic node=%u generation=%llu roots=0 transfers=0 retained=%u retained_bytes=%u bytes=%u sha256=%s hex=%s terminal=0\n",
        inventory.cut.identity.localNode, static_cast<unsigned long long>(inventory.cut.admissionGeneration),
        inventory.retainedCount, inventory.retainedBytes, inventory.length, digest, encoded);
}

bool DistributedAccessInitialize(Assembly* assembly, const DistributedIdentityContext& context)
{
    GCX_COOP();
    s_threadMode = DistributedAdmissionIsThreadProbe();
    // Exact finite corpus, independently built/decoded before inclusion. Changing the fixture
    // requires a new reviewed hash and build; a manifest alone cannot admit arbitrary IL.
    const BYTE fixtureHash[32] = {
        0x99,0x65,0x2b,0xfb,0x45,0xa0,0x8a,0x73,0x05,0xf9,0x38,0xc3,0xc2,0x33,0x50,0x2b,
        0xd8,0x72,0xbb,0xbc,0x1d,0x2e,0xd5,0x34,0xf6,0x3b,0xd7,0x61,0x29,0xc6,0x98,0x55 };
    const BYTE publicationFixtureHash[32] = {
        0x1a,0x7b,0x9b,0x1c,0x3b,0x21,0x6a,0x92,0xfc,0x87,0x15,0x87,0xf9,0xa3,0xfe,0x55,
        0x8d,0x5c,0xe9,0x14,0x8c,0xa5,0xbf,0x9c,0x01,0xe5,0x83,0xfb,0xc5,0x38,0x67,0x13 };
    const BYTE threadFixtureHash[32] = {
        0x25,0x8c,0x03,0xf3,0x4d,0x0b,0x34,0x5c,0xa1,0x5e,0x84,0x9f,0xa2,0x33,0xfc,0x3a,
        0x80,0x0f,0xf7,0x6d,0x40,0xb1,0xca,0x27,0x6f,0x13,0x78,0xd8,0x0d,0x2c,0x01,0x9b };
    const BYTE threadNegativeFixtureHashes[4][32] = {
        { 0x61,0xdd,0xcc,0xf5,0x73,0x9f,0x63,0xb9,0xb9,0x98,0x2e,0x17,0xc1,0xa0,0x8c,0xd7,
          0x93,0x16,0xae,0x86,0x17,0x44,0xe3,0x1b,0x8b,0x7c,0xad,0x96,0xf9,0x2d,0xd3,0xc4 },
        { 0x7a,0x80,0xd7,0x1b,0x07,0xdc,0xfa,0x96,0x55,0x0e,0x3b,0xc6,0x31,0xe2,0x57,0xbc,
          0x0a,0x2f,0x6d,0xb0,0xf3,0x9e,0x0b,0x99,0x07,0xbd,0x11,0x3c,0x5c,0xa5,0x1b,0xb3 },
        { 0xeb,0x5b,0x50,0x6c,0xee,0x8b,0x8a,0xc4,0x68,0x8c,0x57,0xce,0x25,0xde,0xe6,0xa6,
          0xe8,0xdb,0xfa,0x52,0x86,0xce,0x61,0x40,0x85,0x6e,0xea,0xa4,0xea,0x8c,0x11,0x77 },
        { 0xba,0xbc,0x65,0xe4,0x65,0x9f,0x73,0x30,0x21,0x97,0x74,0xa7,0x75,0xcc,0x39,0x6b,
          0x7e,0x31,0x05,0xb6,0xbf,0x02,0xb0,0x2a,0xc2,0x76,0x89,0x5e,0xfd,0x54,0x81,0xf3 }
    };
    bool negativeFixtureAllowed = false;
    if (DistributedAdmissionIsThreadNegativeProbe())
    {
        negativeFixtureAllowed =
            Same(context.assemblyHash, threadNegativeFixtureHashes[0], 32) ||
            Same(context.assemblyHash, threadNegativeFixtureHashes[1], 32) ||
            Same(context.assemblyHash, threadNegativeFixtureHashes[2], 32) ||
            Same(context.assemblyHash, threadNegativeFixtureHashes[3], 32);
    }
    else
    {
        const BYTE* expectedFixture = s_threadMode ? threadFixtureHash :
            DistributedAdmissionIsPublicationProbe() ? publicationFixtureHash : fixtureHash;
        negativeFixtureAllowed = Same(context.assemblyHash, expectedFixture, 32);
    }
    if (s_module != nullptr || assembly == nullptr || !negativeFixtureAllowed)
        return false;
    s_threadRootProfile = s_threadMode && !DistributedAdmissionIsThreadNegativeProbe() &&
        Same(context.assemblyHash, threadFixtureHash, 32);
    s_module = assembly->GetModule();
    s_node = context.localNode;
    s_publicationMode = DistributedAdmissionIsPublicationProbe();
    if (s_threadMode)
    {
        std::memcpy(s_threadIdentity.run, context.run, 16);
        std::memcpy(s_threadIdentity.creatorIncarnation, s_node == 1 ? context.localInc : context.peerInc, 16);
        s_threadIdentity.creatorNode = 1;
        s_threadIdentity.threadCounter = 1;
        std::memcpy(s_threadIdentity.assemblySha256, context.assemblyHash, 32);
        std::memcpy(s_threadIdentity.mvid, context.mvid, 16);
        s_threadIdentity.typeDefToken = 0x02000002;
        s_threadIdentity.methodDefToken = 0x06000001;
        s_threadLedger = new TP::Ledger(s_node == 1 ? TP::Role::Coordinator : TP::Role::Worker, s_threadIdentity);
        return DistributedThreadInitialize(assembly, context);
    }
    s_body = MemberLoader::GetMethodDescFromMethodDef(s_module, 0x06000007, TRUE);
    PCCOR_SIGNATURE sig = nullptr;
    DWORD size = 0;
    s_body->GetSig(&sig, &size);
    const BYTE expected[] = {0,3,8,0x1c,0x1c,8};
    return s_body->IsStatic() && s_body->IsIL() && size == sizeof(expected) &&
        Same(sig, expected, sizeof(expected));
}

bool DistributedAccessIsMethod(MethodDesc* method)
{
    return s_module != nullptr && method != nullptr && method->GetModule() == s_module;
}

bool DistributedAccessIsField(FieldDesc* field)
{
    return s_module != nullptr && field != nullptr && field->GetModule() == s_module &&
        !field->IsStatic() && field->GetEnclosingMethodTable()->GetCl() == 0x02000002 &&
        field->GetMemberDef() >= 0x04000001 && field->GetMemberDef() <= 0x04000003;
}

extern "C" INT32 QCALLTYPE DistributedRuntime_AccessReadInt32(QCall::ObjectHandleOnStack target,
    INT_PTR location, INT32 kind)
{
    QCALL_CONTRACT;
    INT32 value = 0;
    BEGIN_QCALL;
    CheckCaller();
    if (kind != 0 && kind != 1) Reject("int-kind");
    DistributedObjectId id{};
    unsigned slot = 0;
    int entry;
    std::atomic_thread_fence(std::memory_order_seq_cst);
    {
        GCX_COOP();
        entry = Target(target, static_cast<UINT_PTR>(location), kind == 1, &id, &slot);
        if (kind == 0 && slot != 0) Reject("int-field");
        if (entry < 0)
            value = kind == 0 ? static_cast<FieldDesc*>(reinterpret_cast<void*>(location))->GetValue32(target.Get()) :
                reinterpret_cast<INT32*>(((BASEARRAYREF)target.Get())->GetDataPtr())[slot];
    }
    if (entry >= 0)
    {
        BYTE response[ReplyBytes]{};
        Request(kind == 0 ? 0 : 4, slot, id, nullptr, response);
        value = static_cast<INT32>(U32(response + 76));
    }
    std::atomic_thread_fence(std::memory_order_seq_cst);
    END_QCALL;
    return value;
}

extern "C" void QCALLTYPE DistributedRuntime_AccessWriteInt32(QCall::ObjectHandleOnStack target,
    INT_PTR location, INT32 kind, INT32 value)
{
    QCALL_CONTRACT;
    BEGIN_QCALL;
    CheckCaller();
    if (kind != 0 && kind != 1) Reject("int-kind");
    DistributedObjectId id{};
    unsigned slot = 0;
    int entry;
    std::atomic_thread_fence(std::memory_order_seq_cst);
    {
        GCX_COOP();
        entry = Target(target, static_cast<UINT_PTR>(location), kind == 1, &id, &slot);
        if (kind == 0 && slot != 0) Reject("int-field");
        if (entry < 0)
        {
            if (kind == 0) reinterpret_cast<FieldDesc*>(location)->SetValue32(target.Get(), value);
            else reinterpret_cast<INT32*>(((BASEARRAYREF)target.Get())->GetDataPtr())[slot] = value;
        }
    }
    if (entry >= 0)
    {
        BYTE input[44]{}, response[ReplyBytes]{};
        P32(input, value);
        Request(kind == 0 ? 1 : 5, slot, id, input, response);
    }
    std::atomic_thread_fence(std::memory_order_seq_cst);
    END_QCALL;
}

extern "C" void QCALLTYPE DistributedRuntime_AccessReadReference(QCall::ObjectHandleOnStack target,
    INT_PTR field, QCall::ObjectHandleOnStack result)
{
    QCALL_CONTRACT;
    BEGIN_QCALL;
    CheckCaller();
    DistributedObjectId id{};
    unsigned slot = 0;
    int entry;
    std::atomic_thread_fence(std::memory_order_seq_cst);
    {
        GCX_COOP();
        entry = Target(target, static_cast<UINT_PTR>(field), false, &id, &slot);
        if (slot == 0) Reject("ref-field");
        if (entry < 0) result.Set(reinterpret_cast<FieldDesc*>(field)->GetRefValue(target.Get()));
    }
    if (entry >= 0)
    {
        BYTE response[ReplyBytes]{};
        Request(2, slot, id, nullptr, response);
        DistributedObjectId returned{};
        std::memcpy(returned.bytes, response + 76, 44);
        GCX_COOP();
        OBJECTREF object = NULL;
        if (!DistributedIdentityResolveReference(returned, &object)) Reject("reply-reference-custody");
        result.Set(object);
    }
    std::atomic_thread_fence(std::memory_order_seq_cst);
    END_QCALL;
}

extern "C" void QCALLTYPE DistributedRuntime_AccessWriteReference(QCall::ObjectHandleOnStack target,
    INT_PTR field, QCall::ObjectHandleOnStack value)
{
    QCALL_CONTRACT;
    BEGIN_QCALL;
    CheckCaller();
    DistributedObjectId id{}, outgoing{};
    unsigned slot = 0;
    int entry;
    bool publish = false;
    std::atomic_thread_fence(std::memory_order_seq_cst);
    {
        GCX_COOP();
        entry = Target(target, static_cast<UINT_PTR>(field), false, &id, &slot);
        if (slot == 0 || (value.Get() != NULL &&
            value.Get()->GetMethodTable() != target.Get()->GetMethodTable())) Reject("ref-field-or-type");
        if (entry < 0) reinterpret_cast<FieldDesc*>(field)->SetRefValue(target.Get(), value.Get());
        else if (!DistributedIdentityAccessReference(value.Get(), &outgoing))
        {
            if (!s_publicationMode || s_node != 1) Reject("unretained-reference");
            publish = true;
        }
    }
    if (entry >= 0)
    {
        if (publish) PublishReference(value, id, slot);
        else
        {
            BYTE response[ReplyBytes]{};
            Request(3, slot, id, outgoing.bytes, response);
        }
    }
    std::atomic_thread_fence(std::memory_order_seq_cst);
    END_QCALL;
}

extern "C" void QCALLTYPE DistributedRuntime_AccessStartForTest(QCall::ObjectHandleOnStack root,
    QCall::ObjectHandleOnStack array, INT32 testCase)
{
    QCALL_CONTRACT;
    BEGIN_QCALL;
    CheckCaller();
    if (s_node != 1 || s_open.load() || testCase < 0 || testCase > 5) Reject("start-state");
    BYTE bootstrap[4096]{};
    std::memcpy(bootstrap, "DAS1", 4); P32(bootstrap + 4, 1); P32(bootstrap + 8, testCase);
    int graphSize, arraySize;
    {
        GCX_COOP();
        graphSize = DistributedIdentityExportForTest(root.Get(), bootstrap + 20, 3050);
        if (graphSize < 0) Reject("bootstrap-graph");
        arraySize = DistributedIdentityExportArray(array.Get(), bootstrap + 20 + graphSize, 184);
        if (arraySize < 0) Reject("bootstrap-array");
    }
    P32(bootstrap + 12, graphSize); P32(bootstrap + 16, arraySize);
    if (!Send(bootstrap, 20 + graphSize + arraySize, 22)) Reject("bootstrap-send");
    BYTE ready[4096]{};
    if (Receive(ready, 23, Clock::now() + std::chrono::seconds(10)) != 44 ||
        std::memcmp(ready, "DAR1", 4) != 0 || U32(ready + 4) != 1 ||
        U32(ready + 40) > 1) Reject("bootstrap-ready");
    {
        GCX_COOP();
        if (!SealDirectory()) Reject("coordinator-directory-seal");
    }
    if (!Same(ready + 8, s_seedDigest, 32)) Reject("bootstrap-set-digest");
    s_workerMoved = U32(ready + 40) == 1;
    s_open.store(true, std::memory_order_release);
    if (pthread_create(&s_service, nullptr, Service, nullptr) != 0) Reject("service-thread");
    s_created = true;
    BYTE grant[40]{};
    std::memcpy(grant, "DAG1", 4); P32(grant + 4, 1); std::memcpy(grant + 8, s_seedDigest, 32);
    if (!Send(grant, sizeof(grant), 22)) Reject("start-grant");
    std::fprintf(stderr, "DC_ACCESS phase=open node=1 retained=%u worker_gc_moved=%u\n", s_count, s_workerMoved);
    END_QCALL;
}

void DistributedAccessThreadStart(OBJECTREF* target)
{
    CheckCaller();
    if (!s_threadMode || s_node != 1 || s_open.load()) Reject("thread-start-state");
    BYTE graph[TP::MaxGraphBytes]{}, prepare[TP::MaxPrepareBytes]{}, response[4096]{};
    int graphLength;
    {
        GCX_COOP();
        graphLength = DistributedIdentityExportForTest(*target, graph, sizeof(graph));
    }
    if (graphLength < 198 || std::memcmp(graph, "DID1", 4) != 0 ||
        graph[4] != 1 || graph[5] == 0 || graph[5] > TP::MaxSeeds)
        Reject("thread-target-graph");
    std::memcpy(s_threadRoot, graph + 8, 44); // DID1 exporter puts its protected root first.
    if (s_threadRootProfile)
    {
        // DID1's source-owned export has exactly two initial nodes in this pinned profile.
        if (graph[5] != 2 || graphLength != 8 + 2 * 190) Reject("thread-initial-root-shape");
        BYTE objects[2][44]{};
        for (unsigned i = 0; i < 2; ++i) std::memcpy(objects[i], graph + 8 + i * 190, 44);
        if (!DistributedThreadTerminalRoots(1, objects[0], 2)) Reject("thread-initial-root-event");
    }
    size_t length = 0;
    if (!TP::BuildPrepare(prepare, sizeof(prepare), &length, s_threadIdentity, s_threadRoot,
        graph, static_cast<unsigned>(graphLength)) || !ThreadRecord(prepare, length))
        Reject("thread-prepare");
    std::memcpy(s_threadDigest, prepare + 52, 32);
    auto deadline = Clock::now() + std::chrono::seconds(10);
    if (!SendUntil(prepare, static_cast<unsigned>(length), 23, deadline) ||
        ThreadWait("DTR1", response, deadline) != 136) Reject("thread-ready");
    {
        GCX_COOP();
        DistributedObjectId id{};
        if (!SealDirectory() || !DistributedIdentityAccessReference(*target, &id) ||
            !Same(id.bytes, s_threadRoot, 44)) Reject("thread-source-root-seal");
    }
    if (!Same(response + 84, s_seedDigest, 32) || U32(response + 116) != s_count)
        Reject("thread-ready-seed-set");
    {
        GCX_COOP();
        if (!DistributedIdentityCompleteInitialThreadTransfer(s_seeds, s_count))
            Reject("thread-initial-transfer-complete");
    }
    std::fprintf(stderr, "DC_THREAD phase=initial-transfer-complete node=1 count=%u retained=%u\n", s_count, s_count);
    if (s_threadRootProfile && !DistributedThreadTerminalRoots(2, nullptr, 0))
        Reject("thread-initial-root-ready-event");
    s_workerMoved = U32(response + 128) == 1;
    BYTE grant[124]{};
    if (!TP::BuildGrant(grant, sizeof(grant), &length, s_threadIdentity,
        s_threadDigest, s_seedDigest, s_count) || !ThreadRecord(grant, length))
        Reject("thread-grant");
    if (s_threadRootProfile && !DistributedThreadTerminalLifecycle(
        static_cast<unsigned>(DCG01Events::Lifecycle::Authorized), 0)) Reject("thread-authorized-event");
    s_open.store(true, std::memory_order_release);
    // Transfer receive ownership before granting execution. No other source receiver remains.
    if (pthread_create(&s_service, nullptr, Service, nullptr) != 0) Reject("thread-service-create");
    s_created = true;
    if (!SendUntil(grant, static_cast<unsigned>(length), 23, deadline)) Reject("thread-grant-send");
    std::fprintf(stderr, "DC_THREAD phase=start-authorized node=1 retained=%u\n", s_count);
}

bool DistributedAccessThreadClaimExecution()
{
    // Called solely by worker staging, before CreateNewThread. No wait/GC/allocation/IO.
    return s_threadMode && s_node == 2 && s_open.load(std::memory_order_acquire) &&
        !s_aborted.load() && s_threadLedger != nullptr && s_threadLedger->ClaimExecution();
}

void DistributedAccessThreadEnter()
{
    CheckCaller();
    if (!s_threadMode || s_node != 2 || s_threadEntered.load()) Reject("thread-entry-state");
    BYTE entry[144]{}, response[4096]{};
    size_t length = 0;
    if (!TP::BuildEntry(entry, sizeof(entry), &length, s_threadIdentity, s_threadDigest,
        s_threadRoot, GetThread()->GetOSThreadId64(), 1) || !ThreadRecord(entry, length))
        Reject("thread-entry");
    const auto deadline = Clock::now() + std::chrono::seconds(10);
    if (!SendUntil(entry, static_cast<unsigned>(length), 22, deadline) ||
        ThreadWait("DTA1", response, deadline) != 120) Reject("thread-entry-ack");
    s_threadEntered.store(true, std::memory_order_release);
    std::fprintf(stderr, "DC_THREAD phase=callback-enter node=2 os_thread=%llu\n",
        static_cast<unsigned long long>(GetThread()->GetOSThreadId64()));
}

void DistributedAccessThreadReturned()
{
    CheckCaller();
    if (!s_threadMode || s_node != 2 || !s_threadEntered.load() || s_callbackReturned.load())
        Reject("thread-return-state");
    unsigned pending = DistributedIdentityPendingPublicationRoots();
    if (pending != 0) Reject("thread-return-transfer-roots");
    s_returnFacts = {true, true, false, s_request, s_lastReply};
    s_callbackReturned.store(true, std::memory_order_release);
    std::fprintf(stderr, "DC_THREAD phase=callback-return node=2 worker_sequence=%llu frontier=%llu\n",
        static_cast<unsigned long long>(s_request), static_cast<unsigned long long>(s_lastReply));
}

void DistributedAccessThreadAbort(const char* reason) { Abort(reason); }

int DistributedAccessThreadWorker()
{
    if (s_node != 2 || !s_threadMode || s_open.load()) return -1;
    GCX_COOP();
    DebuggerU2MCatchHandlerFrame catchFrame(true /* catchesAllExceptions */);
    EX_TRY
    {
        GCX_PREEMP();
        BYTE prepare[4096]{}, ready[136]{};
        const auto prepareDeadline = Clock::now() + std::chrono::seconds(10);
        int size = ThreadWait("DTP1", prepare, prepareDeadline);
        if (size < 197) Reject("thread-worker-prepare");
        std::memcpy(s_threadDigest, prepare + 52, 32);
        std::memcpy(s_threadRoot, prepare + 144, 44);
        {
            GCX_COOP();
            OBJECTREF root = NULL;
            GCPROTECT_BEGIN(root);
            if (!DistributedIdentityImportAccessGraph(prepare + 196, U32(prepare + 188), &root))
                Reject("thread-worker-import");
            UINT_PTR before = reinterpret_cast<UINT_PTR>(OBJECTREFToObject(root));
            unsigned gcBefore = GCHeapUtilities::GetGCHeap()->GetGcCount();
            GCHeapUtilities::GetGCHeap()->GarbageCollect(2, false, collection_compacting | collection_blocking);
            unsigned collections = GCHeapUtilities::GetGCHeap()->GetGcCount() - gcBefore;
            s_workerMoved = before != reinterpret_cast<UINT_PTR>(OBJECTREFToObject(root));
            DistributedObjectId id{};
            if (!SealDirectory() || !DistributedIdentityAccessReference(root, &id) ||
                !Same(id.bytes, s_threadRoot, 44)) Reject("thread-worker-root-seal");
            DistributedThreadPrepareWorker(root); // GC-aware delegate and actual Thread; no callback yet.
            {
                GCX_PREEMP();
                size_t length = 0;
                if (!TP::BuildReady(ready, sizeof(ready), &length, s_threadIdentity, s_threadDigest,
                    s_seedDigest, s_count, s_count, collections, s_workerMoved ? 1 : 0) ||
                    !ThreadRecord(ready, length)) Reject("thread-worker-ready");
                const auto grantDeadline = Clock::now() + std::chrono::seconds(10);
                BYTE grant[4096]{};
                if (!SendUntil(ready, static_cast<unsigned>(length), 22, grantDeadline) ||
                    ThreadWait("DTG1", grant, grantDeadline) != 124) Reject("thread-worker-grant");
                s_open.store(true, std::memory_order_release);
                // Child claims once and takes directory ownership before OS-thread creation.
                // Staging performs a real local Join; it does not receive while child runs.
                DistributedThreadRunWorker();
                if (!DistributedThreadWorkerJoined() ||
                    !s_callbackReturned.load(std::memory_order_acquire) || s_aborted.load())
                    Reject("thread-worker-join-or-callback");
                dcg01_identity_snapshot::Snapshot workerSnapshot{};
                if (!DistributedIdentityTakeWorkerSnapshotAfterJoin(&workerSnapshot))
                    Reject("thread-worker-identity-snapshot");
                std::fprintf(stderr,
                    "DC_THREAD phase=identity-snapshot-after-join entries=%u retained=%u publication=%u terminal=%u\n",
                    workerSnapshot.entryCount, workerSnapshot.retainedBytes,
                    workerSnapshot.publication.phase, workerSnapshot.terminalEligible);
                TP::LocalCompletionFacts facts = s_returnFacts;
                facts.physicalChildJoined = true;
                BYTE complete[120]{}, acknowledgement[4096]{};
                if (!TP::BuildCompletion(complete, sizeof(complete), &length, s_threadIdentity,
                    s_threadDigest, facts.workerSequence, facts.authorityFrontier, 0, 1, 1, 1) ||
                    !ThreadRecord(complete, length, &facts)) Reject("thread-worker-completion");
                const auto completionDeadline = Clock::now() + std::chrono::seconds(10);
                if (!SendUntil(complete, static_cast<unsigned>(length), 22, completionDeadline) ||
                    ThreadWait("DTD1", acknowledgement, completionDeadline) != 120)
                    Reject("thread-worker-completion-ack");
                std::fprintf(stderr, "DC_THREAD phase=physical-join-acknowledged node=2\n");
                DistributedAccessQuiescentSnapshot accessSnapshot{};
                if (!DistributedAccessCaptureQuiescentSnapshot(&accessSnapshot))
                    Reject("thread-worker-access-snapshot");
                if (s_threadRootProfile)
                {
                    BYTE closed[32]{};
                    std::memcpy(closed, "DCL1", 4); P32(closed + 4, 1);
                    P64(closed + 8, accessSnapshot.admissionGeneration);
                    P64(closed + 16, accessSnapshot.lastAcceptedOperationSequence); P64(closed + 24, 1);
                    if (!Send(closed, sizeof(closed), 22)) Reject("thread-worker-admission-close-send");
                }
                std::fprintf(stderr,
                    "DC_THREAD phase=access-snapshot-diagnostic node=2 generation=%llu operations=%llu authority=%llu publications=%llu\n",
                    static_cast<unsigned long long>(accessSnapshot.admissionGeneration),
                    static_cast<unsigned long long>(accessSnapshot.lastAcceptedOperationSequence),
                    static_cast<unsigned long long>(accessSnapshot.authorityFrontier),
                    static_cast<unsigned long long>(accessSnapshot.publicationFrontier));
                if (!CaptureClosedThreadRootInventory(workerSnapshot))
                    Reject("thread-worker-root-inventory");
                TraceThreadRootInventory();
                if (!CaptureThreadParticipantPreimage(nullptr))
                    Reject("thread-worker-participant-preimage");
                TraceThreadParticipantPreimage();
                if (!ThreadSendCustody()) Reject("thread-worker-custody-send");
                // Diagnostic local experiment only. Retain graph/roots and control liveness;
                // no terminal retirement or authoritative DC-022 completed record exists yet.
                const auto retentionDeadline = Clock::time_point::max();
                while (Ready() && !s_aborted.load() && !s_shutdown.load())
                {
                    BYTE duplicate[4096]{};
                    int duplicateLength = Receive(duplicate, 23, retentionDeadline);
                    if (duplicateLength < 0) break;
                    if (DCG01Custody::IsAck(duplicate, static_cast<unsigned>(duplicateLength)))
                    {
                        if (!ThreadConsumeCustodyAck(duplicate, static_cast<unsigned>(duplicateLength))) break;
                    }
                    else if (!ThreadConsumeDuplicate(duplicate,
                             static_cast<unsigned>(duplicateLength), retentionDeadline)) break;
                }
                Abort("thread-worker-staged-ended");
            }
            GCPROTECT_END();
        }
    }
    EX_CATCH
    {
        GCX_PREEMP();
        Abort("thread-worker-managed-exception");
    }
    EX_END_CATCH
    catchFrame.Pop();
    return -1;
}

int DistributedAccessWorker()
{
    if (s_threadMode) return DistributedAccessThreadWorker();
    if (s_node != 2 || s_body == nullptr || s_open.load()) return -1;
    int status = -1;
    EX_TRY
    {
        BYTE bootstrap[4096]{}, ready[44]{};
        int size = Receive(bootstrap, 22, Clock::now() + std::chrono::seconds(10));
        if (size < 20 || std::memcmp(bootstrap, "DAS1", 4) != 0 || U32(bootstrap + 4) != 1 ||
            U32(bootstrap + 8) > 5 || U32(bootstrap + 12) > 3050 || U32(bootstrap + 16) > 184 ||
            static_cast<UINT32>(size) != 20 + U32(bootstrap + 12) + U32(bootstrap + 16))
            Reject("worker-bootstrap");
        int testCase = static_cast<int>(U32(bootstrap + 8));
        GCX_COOP();
        OBJECTREF root = NULL, array = NULL;
        GCPROTECT_BEGIN(root);
        GCPROTECT_BEGIN(array);
        {
            GCX_COOP();
            if (!DistributedIdentityImportAccessGraph(bootstrap + 20, U32(bootstrap + 12), &root) ||
                !DistributedIdentityImportArray(bootstrap + 20 + U32(bootstrap + 12), U32(bootstrap + 16), &array))
                Reject("worker-import");
            UINT_PTR beforeRoot = reinterpret_cast<UINT_PTR>(OBJECTREFToObject(root));
            UINT_PTR beforeArray = reinterpret_cast<UINT_PTR>(OBJECTREFToObject(array));
            GCHeapUtilities::GetGCHeap()->GarbageCollect(2, false, collection_compacting | collection_blocking);
            s_workerMoved = beforeRoot != reinterpret_cast<UINT_PTR>(OBJECTREFToObject(root)) ||
                beforeArray != reinterpret_cast<UINT_PTR>(OBJECTREFToObject(array));
            if (!SealDirectory()) Reject("worker-directory-seal");
        }
        {
        GCX_PREEMP();
        std::memcpy(ready, "DAR1", 4); P32(ready + 4, 1);
        std::memcpy(ready + 8, s_seedDigest, 32); P32(ready + 40, s_workerMoved ? 1 : 0);
        if (!Send(ready, sizeof(ready), 23)) Reject("worker-ready");
        BYTE grant[4096]{};
        if (Receive(grant, 22, Clock::now() + std::chrono::seconds(10)) != 40 ||
            std::memcmp(grant, "DAG1", 4) != 0 || U32(grant + 4) != 1 ||
            !Same(grant + 8, s_seedDigest, 32)) Reject("worker-grant");
        }
        s_open.store(true, std::memory_order_release);
        std::fprintf(stderr, "DC_ACCESS phase=open node=2 retained=%u gc_moved=%u\n", s_count, s_workerMoved);
        int result;
        {
            GCX_COOP();
            // Activation/entrypoint resolution may GC; materialize arguments only afterward.
            s_body->EnsureActive();
            PCODE localEntry = s_body->GetMultiCallableAddrOfCode();
            MethodDescCallSite call(METHOD__OBJECT__DISTRIBUTED_ACCESS_INVOKE);
            ARG_SLOT arguments[] = {ObjToArgSlot(root), ObjToArgSlot(array),
                static_cast<ARG_SLOT>((testCase << 1) | 1), static_cast<ARG_SLOT>(localEntry)};
            result = call.Call_RetI4(arguments);
        }
        {
        GCX_PREEMP();
        if (result != 0 || s_aborted.load())
            Abort("worker-body-result");
        else
        {
        BYTE done[32]{};
        std::memcpy(done, "DAF1", 4); P32(done + 4, 1);
        P64(done + 8, s_request); P64(done + 16, s_lastReply); P32(done + 24, result);
        P32(done + 28, s_workerGcWaits);
        if (!Send(done, sizeof(done), 22)) Reject("worker-done");
        // Returning the test body discharges no terminal obligations. Retain everything
        // and keep native transport alive until coordinator teardown/abort; no replay.
        auto deadline = Clock::now() + std::chrono::seconds(30);
        while (Ready() && !s_aborted.load() && !s_shutdown.load() && Clock::now() < deadline) usleep(1000);
        Abort("worker-staged-ended");
        }
        }
        GCPROTECT_END();
        GCPROTECT_END();
    }
    EX_CATCH { Abort("worker-managed-exception"); }
    EX_END_CATCH
    return status;
}

static unsigned BuildAccessHistory(BYTE* bytes, INT32 coordinatorResult,
    bool directoryHealthy, unsigned pendingRoots, bool* success)
{
    unsigned length;
    unsigned headerBytes = s_publicationMode ? PublicationHeaderBytes : HeaderBytes;
    unsigned seedBytes = SeedBytes + (s_publicationMode ? 8 : 0);
    pthread_mutex_lock(&s_lock);
    s_finished.store(true, std::memory_order_release);
    std::memset(bytes, 0, headerBytes);
    std::memcpy(bytes, s_publicationMode ? "DAH2" : "DAH1", 4);
    P32(bytes + 4, s_publicationMode ? 2 : 1);
    bool localResult = directoryHealthy && !s_aborted.load() && s_workerDone.load() &&
        coordinatorResult == 0 && s_workerResult == 0 && !s_publication.active && pendingRoots == 0;
    P32(bytes + 8, localResult ? 1 : 0); // Diagnostic cut; never DC-022 completion.
    P32(bytes + 12, s_node); P32(bytes + 16, s_count); P32(bytes + 20, s_committed);
    P32(bytes + 24, coordinatorResult); P32(bytes + 28, s_workerResult);
    P64(bytes + 32, s_lastCommit[1]); P32(bytes + 40, s_delayedReplies.load());
    P32(bytes + 44, s_workerMoved ? 1 : 0); std::memcpy(bytes + 48, s_seedDigest, 32);
    P32(bytes + 80, s_workerGcWaits);
    for (unsigned i = 0; i < s_count; i++)
    {
        BYTE* seed = bytes + headerBytes + i * seedBytes;
        EncodeSeed(seed, s_seeds[i]);
        if (s_publicationMode) P64(seed + SeedBytes, s_introduced[i]);
    }
    unsigned eventsOffset = headerBytes + s_count * seedBytes;
    if (s_publicationMode)
    {
        P32(bytes + 84, pendingRoots); P32(bytes + 88, s_publicationCount);
        P32(bytes + 92, s_initialSeedCount);
        SHA256(bytes + headerBytes, s_count * seedBytes, bytes + 48);
        std::memcpy(bytes + eventsOffset, s_publicationHistory, s_publicationCount * PublicationRecordBytes);
        eventsOffset += s_publicationCount * PublicationRecordBytes;
    }
    length = eventsOffset + s_committed * EventBytes;
    std::memcpy(bytes + eventsOffset, s_history, s_committed * EventBytes);
    pthread_mutex_unlock(&s_lock);
    *success = localResult;
    return length;
}

extern "C" void QCALLTYPE DistributedRuntime_AccessFinishForTest(INT32 coordinatorResult,
    QCall::ObjectHandleOnStack artifact)
{
    QCALL_CONTRACT;
    BEGIN_QCALL;
    bool directoryHealthy = DistributedIdentityAccessCaller();
    bool diagnosticCaller = s_publicationMode ? DistributedIdentityPublicationFinishCaller() : directoryHealthy;
    if (s_node != 1 || !diagnosticCaller || !s_open.load() || s_finished.load())
        Reject("finish-state");
    auto deadline = Clock::now() + std::chrono::seconds(30);
    while (!s_workerDone.load(std::memory_order_acquire) && !s_aborted.load() && Ready() && Clock::now() < deadline)
        usleep(1000);
    if (coordinatorResult != 0 || !s_workerDone.load() || !Ready()) Abort("finish-result-or-peer");
    unsigned pendingRoots = 0;
    if (s_publicationMode)
    {
        GCX_COOP();
        pendingRoots = DistributedIdentityPendingPublicationRoots();
    }
    NewArrayHolder<BYTE> bytes(new BYTE[MaxHistoryBytes]);
    bool localResult = false;
    unsigned length = BuildAccessHistory(bytes, coordinatorResult, directoryHealthy, pendingRoots, &localResult);
    {
        GCX_COOP();
        OBJECTREF result = AllocatePrimitiveArray(ELEMENT_TYPE_U1, length);
        std::memcpy(((BASEARRAYREF)result)->GetDataPtr(), bytes, length);
        artifact.Set(result);
    }
    std::fprintf(stderr, "DC_ACCESS phase=history status=%s operations=%u bytes=%u\n",
        localResult ? "LOCAL_EXPERIMENT" : "ABORTED", s_committed, length);
    END_QCALL;
}

bool DistributedAccessRecordThreadJoin()
{
    if (!s_threadRootProfile) return true;
    pthread_mutex_lock(&s_lock);
    const bool valid = s_node == 1 && s_workerDone.load() && !s_aborted.load() && !s_shutdown.load();
    const UINT64 frontier = s_next[0] - 1;
    pthread_mutex_unlock(&s_lock);
    return valid && DistributedThreadTerminalLifecycle(static_cast<unsigned>(DCG01Events::Lifecycle::JoinReturned), frontier);
}

bool DistributedAccessThreadFinishApplication(INT32 result, const DCG01Output::ArtifactInfo* output)
{
    bool success = false;
    bool recordPublished = false;
    EX_TRY
    {
        if (!s_threadMode || s_node != 1 || !s_open.load() || s_finished.load() ||
            !DistributedIdentityAccessCaller()) Reject("thread-main-finish-state");
        auto deadline = Clock::now() + std::chrono::seconds(30);
        while (!s_workerDone.load(std::memory_order_acquire) && !s_aborted.load() &&
            Ready() && Clock::now() < deadline) usleep(1000);
        if (result != 0 || !s_workerDone.load() || !Ready()) Abort("thread-main-result-or-peer");
        NewArrayHolder<BYTE> history(new BYTE[MaxHistoryBytes]);
        unsigned length = BuildAccessHistory(history, result, DistributedIdentityAccessCaller(),
            DistributedIdentityPendingPublicationRoots(), &success);
        if (success)
        {
            DistributedAccessQuiescentSnapshot accessSnapshot{};
            if (!DistributedAccessCaptureQuiescentSnapshot(&accessSnapshot))
                Reject("thread-main-access-snapshot");
            if (s_threadRootProfile && !DistributedThreadTerminalMainReturned(result,
                accessSnapshot.lastAcceptedOperationSequence, accessSnapshot.authorityFrontier,
                accessSnapshot.publicationFrontier))
                Reject("thread-main-return-event");
            if (s_threadRootProfile) s_mainReturnObserved.store(true,std::memory_order_release);
            if (s_threadRootProfile && !DistributedThreadTerminalAdmissionClosed(1,
                accessSnapshot.admissionGeneration, accessSnapshot.lastAcceptedOperationSequence))
                Reject("thread-main-admission-close-event");
            std::fprintf(stderr,
                "DC_THREAD phase=access-snapshot-diagnostic node=1 generation=%llu operations=%llu authority=%llu publications=%llu\n",
                static_cast<unsigned long long>(accessSnapshot.admissionGeneration),
                static_cast<unsigned long long>(accessSnapshot.lastAcceptedOperationSequence),
                static_cast<unsigned long long>(accessSnapshot.authorityFrontier),
                static_cast<unsigned long long>(accessSnapshot.publicationFrontier));
            dcg01_identity_snapshot::Snapshot identitySnapshot{};
            {
                GCX_COOP();
                if (!DistributedIdentityCaptureSnapshot(&identitySnapshot, dcg01_identity_snapshot::kMaxEntries))
                    Reject("thread-main-identity-snapshot");
            }
            if (!CaptureClosedThreadRootInventory(identitySnapshot))
                Reject("thread-main-root-inventory");
            if (s_threadRootProfile && !DistributedThreadTerminalRoots(3, nullptr, 0))
                Reject("thread-main-root-cut-event");
            TraceThreadRootInventory();
            if (!CaptureThreadParticipantPreimage(output))
                Reject("thread-main-participant-preimage");
            if (s_threadRootProfile && !DistributedThreadTerminalArtifact(2, 2,
                s_threadParticipantPreimage.evidence, s_threadParticipantPreimage.evidenceLength))
                Reject("thread-main-evidence-custody-event");
            if (s_threadRootProfile && !DistributedThreadTerminalPrepared(1,
                s_threadParticipantPreimage.commitment, s_threadParticipantPreimage.commitmentLength))
                Reject("thread-main-preparation-event");
            TraceThreadParticipantPreimage();
            const auto custodyDeadline = Clock::now() + std::chrono::seconds(10);
            while (!s_workerCustodyReceived.load(std::memory_order_acquire) && !s_aborted.load() &&
                   Ready() && Clock::now() < custodyDeadline) usleep(1000);
            if (!s_workerCustodyReceived.load(std::memory_order_acquire) || s_aborted.load() || !Ready())
                Reject("thread-main-worker-custody");
            if (!DistributedThreadTerminalCommitLocal()) Reject("thread-main-terminal-commitment");
            s_coordinatorCommitted.store(true,std::memory_order_release);
            while (!s_workerCommitmentReceived.load(std::memory_order_acquire) && !s_aborted.load() &&
                   Ready() && Clock::now() < custodyDeadline) usleep(1000);
            if (!s_workerCommitmentReceived.load(std::memory_order_acquire) || s_aborted.load() || !Ready())
                Reject("thread-main-worker-terminal-commitment");
            // Admission is irreversibly closed on both members. Revalidate the
            // source-owned local cut: no application/service obligation may have
            // appeared since preparation. The failure serializer checks the
            // remote commitment, byte custody and logical roots atomically below.
            DistributedAccessQuiescentSnapshot retirement{};
            const auto& preparedCut = s_threadRootInventory.cut;
            if (!s_threadRootProfile || !s_threadRootInventoryPublished.load(std::memory_order_acquire) ||
                !s_threadParticipantPreimagePublished.load(std::memory_order_acquire) ||
                !DistributedAccessCaptureQuiescentSnapshot(&retirement) ||
                retirement.admissionGeneration != preparedCut.admissionGeneration ||
                retirement.lastAcceptedOperationSequence != preparedCut.lastAcceptedOperationSequence ||
                retirement.authorityFrontier != preparedCut.authorityFrontier ||
                retirement.publicationFrontier != preparedCut.publicationFrontier ||
                retirement.identity.localNode != 1 || retirement.identity.peerNode != 2 ||
                !Same(retirement.identity.run,preparedCut.identity.run,16) ||
                !Same(retirement.identity.localInc,preparedCut.identity.localInc,16) ||
                !Same(retirement.identity.peerInc,preparedCut.identity.peerInc,16) ||
                !Same(retirement.identity.assemblyHash,preparedCut.identity.assemblyHash,32) ||
                !Same(retirement.identity.mvid,preparedCut.identity.mvid,16))
                Reject("thread-main-retirement-cut");
            if (!DistributedThreadTerminalRetireWorker()) Reject("thread-main-worker-retirement");
            if (!DistributedThreadTerminalPrepareDrain()) Reject("thread-main-seal-and-drain");
            // Retirement discharged application obligations. Stop the sole producer,
            // then let the service validate its queue before any record publication.
            if (DistributedControlNative(4,0,nullptr,0)!=0) Reject("thread-main-transport-stop");
            if (!s_created || pthread_join(s_service,nullptr)!=0) Reject("thread-main-service-join");
            s_created=false;
            if(s_aborted.load() || !DistributedThreadTerminalHealthy() ||
                DistributedControlNative(3,0,nullptr,0)!=4 || DistributedControlNative(3,12,nullptr,0)!=0 ||
                DistributedControlNative(3,9,nullptr,0)!=0) Reject("thread-main-terminal-drain");
            if(DistributedThreadTerminalPublishRecord()==DCG01Terminal::PublicationResult::Failed)
                Reject("thread-main-terminal-publication");
            recordPublished=true;
            NewArrayHolder<BYTE> lifecycle(new BYTE[DCG01Events::Stream::MaxBytes]);
            size_t lifecycleBytes = 0;
            uint64_t lifecycleCount = 0;
            unsigned char lifecycleDigest[32]{};
            if (DistributedThreadTerminalCopyTrace(lifecycle, DCG01Events::Stream::MaxBytes,
                    &lifecycleBytes, &lifecycleCount) && lifecycleCount != 0 &&
                SHA256(lifecycle,lifecycleBytes,lifecycleDigest))
            {
                char lifecycleHex[65]{};
                const char hexDigits[] = "0123456789abcdef";
                for (size_t i = 0; i < sizeof(lifecycleDigest); ++i)
                {
                    lifecycleHex[i * 2] = hexDigits[lifecycleDigest[i] >> 4];
                    lifecycleHex[i * 2 + 1] = hexDigits[lifecycleDigest[i] & 15];
                }
                std::fprintf(stderr, "DC_THREAD phase=r3-lifecycle-export events=%llu bytes=%zu sha256=%s terminal=0\n",
                    static_cast<unsigned long long>(lifecycleCount), lifecycleBytes, lifecycleHex);
            }
            else
                std::fprintf(stderr,"DC_THREAD phase=r3-lifecycle-export status=incomplete record=published terminal=0\n");
        }
        // A bounded native diagnostic, collected automatically after ordinary Main.
        // This is not an application helper or an authoritative completed record.
        NewArrayHolder<char> encoded(new char[length * 2 + 1]);
        const char digits[] = "0123456789abcdef";
        for (unsigned i = 0; i < length; i++)
        {
            encoded[i * 2] = digits[history[i] >> 4];
            encoded[i * 2 + 1] = digits[history[i] & 15];
        }
        encoded[length * 2] = 0;
        std::fprintf(stderr, "DC_THREAD phase=access-history status=%s bytes=%u hex=%s\n",
            success ? "LOCAL_EXPERIMENT" : "ABORTED", length, static_cast<char*>(encoded));
    }
    EX_CATCH
    {
        if(recordPublished)
            std::fprintf(stderr,"DC_THREAD phase=finish-diagnostic-export status=incomplete record=published terminal=0\n");
        else { Abort("thread-main-finish-exception"); success = false; }
    }
    EX_END_CATCH
    return success && !s_aborted.load();
}

void DistributedAccessShutdown()
{
    s_shutdown.store(true);
    if (s_created)
    {
        pthread_join(s_service, nullptr);
        s_created = false;
    }
}
