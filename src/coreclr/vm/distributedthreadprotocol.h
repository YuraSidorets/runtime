// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#ifndef __DISTRIBUTEDTHREADPROTOCOL_H__
#define __DISTRIBUTEDTHREADPROTOCOL_H__

#include <cstddef>
#include <cstdint>

namespace DistributedThreadProtocol
{
constexpr std::size_t CommonHeaderBytes = 84;
constexpr std::size_t ThreadIdBytes = 44;
constexpr std::size_t ObjectIdBytes = 44;
constexpr std::size_t MaxGraphBytes = 3050;
constexpr std::size_t MaxPrepareBytes = 196 + MaxGraphBytes;
constexpr std::size_t MaxSeeds = 16;
constexpr std::uint64_t MaxObjectCounter = 64;
constexpr std::uint32_t MaxHistorySequence = 2048;
constexpr std::uint32_t MaxDuplicates = 64;
constexpr std::size_t LifecycleRecordCount = 7;

enum class Role : std::uint8_t { Coordinator, Worker };
enum class Kind : std::uint8_t { Prepare, Ready, Grant, Entry, EntryAck, Completion, CompletionAck };
enum class Disposition : std::uint8_t { Recorded, Duplicate, DuplicateWithCachedReply };

struct ExpectedIdentity
{
    std::uint8_t run[16];
    std::uint8_t creatorIncarnation[16];
    std::uint32_t creatorNode;
    std::uint64_t threadCounter;
    std::uint8_t assemblySha256[32];
    std::uint8_t mvid[16];
    std::uint32_t typeDefToken;
    std::uint32_t methodDefToken;
};

// Runtime-only local evidence. DTC1 sender flags still carry the associated
// facts, but a local DTC1 is recorded only after the worker observed them.
struct LocalCompletionFacts
{
    bool callbackReturned;
    bool pendingTransferRootsZero;
    bool physicalChildJoined;
    std::uint64_t workerSequence;
    std::uint64_t authorityFrontier;
};

// Coordinator-side authority facts. The worker's physical-join and callback
// fields are authenticated runtime attestation from DTC1; coordinator validates
// exact values and its own committed history/publication state.
struct AuthorityCompletionFacts
{
    bool noActivePublication;
    bool noAbort;
    std::uint64_t committedWorkerSequence;
    std::uint64_t committedAuthorityFrontier;
};

struct DecodedFrame
{
    Kind kind;
    std::uint8_t descriptorDigest[32];
    std::uint8_t seedDigest[32];
    std::uint8_t rootId[ObjectIdBytes];
    std::uint32_t seedCount;
    std::uint64_t osThreadId;
    std::uint64_t workerSequence;
    std::uint64_t authorityFrontier;
};

struct Observation
{
    Disposition disposition;
    bool hasCachedReply;
    Kind cachedReplyKind;
};

// All APIs use caller-owned buffers, allocate nothing and perform no I/O.
// The existing graph codec must validate DTP1 graph membership before import.
bool BuildPrepare(std::uint8_t* out, std::size_t capacity, std::size_t* written,
    const ExpectedIdentity& identity, const std::uint8_t rootId[ObjectIdBytes],
    const std::uint8_t* graph, std::size_t graphBytes);
bool BuildReady(std::uint8_t* out, std::size_t capacity, std::size_t* written,
    const ExpectedIdentity& identity, const std::uint8_t descriptorDigest[32],
    const std::uint8_t seedDigest[32], std::uint32_t seedCount, std::uint32_t retainedRootCount,
    std::uint32_t forcedCollections, std::uint32_t moved);
bool BuildGrant(std::uint8_t* out, std::size_t capacity, std::size_t* written,
    const ExpectedIdentity& identity, const std::uint8_t descriptorDigest[32],
    const std::uint8_t seedDigest[32], std::uint32_t seedCount);
bool BuildEntry(std::uint8_t* out, std::size_t capacity, std::size_t* written,
    const ExpectedIdentity& identity, const std::uint8_t descriptorDigest[32],
    const std::uint8_t rootId[ObjectIdBytes], std::uint64_t osThreadId, std::uint32_t invocationOrdinal);
bool BuildAcknowledgement(Kind acknowledgementKind, std::uint8_t* out, std::size_t capacity,
    std::size_t* written, const ExpectedIdentity& identity, const std::uint8_t descriptorDigest[32],
    const std::uint8_t* acknowledgedFrame, std::size_t acknowledgedLength);
bool BuildCompletion(std::uint8_t* out, std::size_t capacity, std::size_t* written,
    const ExpectedIdentity& identity, const std::uint8_t descriptorDigest[32],
    std::uint64_t workerSequence, std::uint64_t authorityFrontier,
    std::uint32_t pendingTransferRoots, std::uint32_t callbackSuccess,
    std::uint32_t physicalChildJoined, std::uint32_t invocationOrdinal);
bool ValidateFrame(const std::uint8_t* frame, std::size_t length, const ExpectedIdentity& identity,
    const std::uint8_t* expectedDescriptorDigest, const std::uint8_t* expectedRootId,
    const LocalCompletionFacts* localFacts, const AuthorityCompletionFacts* authorityFacts,
    DecodedFrame* decoded);

// Caller serializes every call. The ledger stores the seven exact frames in
// fixed buffers, latches abort on malformed/conflicting/out-of-order input,
// and caps identical prior-frame duplicates at 64. It has no locks, waits,
// transport, runtime roots, receiver, or scheduler.
class Ledger final
{
public:
    explicit Ledger(Role role, const ExpectedIdentity& identity);
    bool RecordLocal(const std::uint8_t* frame, std::size_t length,
        const LocalCompletionFacts* localFacts, Observation* observation);
    bool AcceptRemote(const std::uint8_t* frame, std::size_t length,
        const AuthorityCompletionFacts* authorityFacts, Observation* observation);
    bool ClaimExecution();
    bool CopyRecord(Kind kind, std::uint8_t* out, std::size_t capacity, std::size_t* written) const;
    void Abort();
    bool IsAborted() const;
    std::uint32_t DuplicateCount() const;

private:
    bool Observe(bool local, const std::uint8_t* frame, std::size_t length,
        const LocalCompletionFacts* localFacts, const AuthorityCompletionFacts* authorityFacts,
        Observation* observation);
    bool Fail();

    Role m_role;
    ExpectedIdentity m_identity;
    std::uint8_t m_records[LifecycleRecordCount][MaxPrepareBytes];
    std::size_t m_lengths[LifecycleRecordCount];
    std::uint8_t m_descriptorDigest[32];
    std::uint8_t m_seedDigest[32];
    std::uint8_t m_rootId[ObjectIdBytes];
    std::uint32_t m_seedCount;
    std::size_t m_next;
    std::uint32_t m_duplicates;
    bool m_hasPrepare;
    bool m_hasSeedSet;
    bool m_executionClaimed;
    bool m_aborted;
};
} // namespace DistributedThreadProtocol

#endif // __DISTRIBUTEDTHREADPROTOCOL_H__
