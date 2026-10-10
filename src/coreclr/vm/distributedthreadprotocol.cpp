// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#include "distributedthreadprotocol.h"

#include <cstring>
#include <openssl/sha.h>

namespace DistributedThreadProtocol
{
namespace
{
constexpr std::size_t PrepareFixedBytes = 196;
constexpr std::size_t ReadyBytes = 136;
constexpr std::size_t GrantBytes = 124;
constexpr std::size_t EntryBytes = 144;
constexpr std::size_t AckBytes = 120;
constexpr std::size_t CompletionBytes = 120;
constexpr std::size_t DigestOffset = 52;
constexpr std::size_t DigestBytes = 32;
constexpr std::size_t RootOffset = 144;
constexpr std::size_t EntryRootOffset = 84;
constexpr char Magics[LifecycleRecordCount][4] = {
    {'D','T','P','1'}, {'D','T','R','1'}, {'D','T','G','1'}, {'D','T','E','1'},
    {'D','T','A','1'}, {'D','T','C','1'}, {'D','T','D','1'}
};

void Put32(std::uint8_t* p, std::uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = static_cast<std::uint8_t>(value >> (8 * i));
}
std::uint32_t Get32(const std::uint8_t* p)
{
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
        (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}
void Put64(std::uint8_t* p, std::uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) p[i] = static_cast<std::uint8_t>(value >> (8 * i));
}
std::uint64_t Get64(const std::uint8_t* p)
{
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= static_cast<std::uint64_t>(p[i]) << (8 * i);
    return value;
}
bool Equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t length)
{
    return std::memcmp(a, b, length) == 0;
}
bool Zero(const std::uint8_t* bytes, std::size_t length)
{
    std::uint8_t value = 0;
    for (std::size_t i = 0; i < length; ++i) value = static_cast<std::uint8_t>(value | bytes[i]);
    return value == 0;
}
void Hash(const std::uint8_t* bytes, std::size_t length, std::uint8_t digest[DigestBytes])
{
    (void)SHA256(bytes, length, digest);
}
bool ValidIdentity(const ExpectedIdentity& identity)
{
    return identity.creatorNode == 1 && identity.threadCounter == 1 &&
        !Zero(identity.run, sizeof(identity.run)) && !Zero(identity.creatorIncarnation, sizeof(identity.creatorIncarnation)) &&
        !Zero(identity.assemblySha256, sizeof(identity.assemblySha256)) && !Zero(identity.mvid, sizeof(identity.mvid)) &&
        identity.typeDefToken != 0 && identity.methodDefToken != 0;
}
bool ValidObjectId(const std::uint8_t id[ObjectIdBytes], const ExpectedIdentity& identity)
{
    const std::uint64_t counter = Get64(id + 36);
    return !Zero(id, ObjectIdBytes) && Equal(id, identity.run, 16) &&
        Get32(id + 16) == identity.creatorNode && Equal(id + 20, identity.creatorIncarnation, 16) &&
        counter >= 1 && counter <= MaxObjectCounter;
}
std::size_t IndexOf(Kind kind) { return static_cast<std::size_t>(kind); }
bool ValidKind(Kind kind) { return IndexOf(kind) < LifecycleRecordCount; }
Kind KindFromMagic(const std::uint8_t* frame)
{
    for (std::size_t i = 0; i < LifecycleRecordCount; ++i)
        if (std::memcmp(frame, Magics[i], 4) == 0) return static_cast<Kind>(i);
    return static_cast<Kind>(LifecycleRecordCount);
}
std::size_t ExactLength(Kind kind, const std::uint8_t* frame)
{
    switch (kind)
    {
        case Kind::Prepare: return PrepareFixedBytes + Get32(frame + 188);
        case Kind::Ready: return ReadyBytes;
        case Kind::Grant: return GrantBytes;
        case Kind::Entry: return EntryBytes;
        case Kind::EntryAck: return AckBytes;
        case Kind::Completion: return CompletionBytes;
        case Kind::CompletionAck: return AckBytes;
    }
    return 0;
}
void BuildHeader(std::uint8_t* out, Kind kind, const ExpectedIdentity& identity,
    const std::uint8_t descriptorDigest[DigestBytes])
{
    std::memcpy(out, Magics[IndexOf(kind)], 4);
    Put32(out + 4, 1);
    std::memcpy(out + 8, identity.run, 16);
    Put32(out + 24, identity.creatorNode);
    std::memcpy(out + 28, identity.creatorIncarnation, 16);
    Put64(out + 44, identity.threadCounter);
    std::memcpy(out + DigestOffset, descriptorDigest, DigestBytes);
}
bool ValidateCommon(const std::uint8_t* frame, std::size_t length, Kind kind,
    const ExpectedIdentity& identity, const std::uint8_t* descriptorDigest)
{
    if (frame == nullptr || length < CommonHeaderBytes || !ValidIdentity(identity) ||
        std::memcmp(frame, Magics[IndexOf(kind)], 4) != 0 || Get32(frame + 4) != 1 ||
        !Equal(frame + 8, identity.run, 16) || Get32(frame + 24) != identity.creatorNode ||
        !Equal(frame + 28, identity.creatorIncarnation, 16) || Get64(frame + 44) != identity.threadCounter)
        return false;
    return descriptorDigest == nullptr ? kind == Kind::Prepare :
        Equal(frame + DigestOffset, descriptorDigest, DigestBytes);
}
bool ValidateCompletionFacts(const std::uint8_t* frame, const LocalCompletionFacts* localFacts,
    const AuthorityCompletionFacts* authorityFacts)
{
    if ((localFacts == nullptr) == (authorityFacts == nullptr)) return false;
    const std::uint64_t sequence = Get64(frame + 84);
    const std::uint64_t frontier = Get64(frame + 92);
    if (localFacts != nullptr)
        return localFacts->callbackReturned && localFacts->pendingTransferRootsZero &&
            localFacts->physicalChildJoined && localFacts->workerSequence == sequence &&
            localFacts->authorityFrontier == frontier;
    return authorityFacts->noActivePublication && authorityFacts->noAbort &&
        authorityFacts->committedWorkerSequence == sequence &&
        authorityFacts->committedAuthorityFrontier == frontier;
}
bool HashMatches(const std::uint8_t* frame, std::size_t length, const std::uint8_t* expected)
{
    std::uint8_t digest[DigestBytes]{};
    Hash(frame, length, digest);
    return Equal(digest, expected, DigestBytes);
}
void InitializeDecoded(DecodedFrame* decoded, Kind kind, const std::uint8_t* frame)
{
    std::memset(decoded, 0, sizeof(*decoded));
    decoded->kind = kind;
    std::memcpy(decoded->descriptorDigest, frame + DigestOffset, DigestBytes);
}
bool DirectionAllows(Role role, bool local, Kind kind)
{
    const bool coordinatorLocal = kind == Kind::Prepare || kind == Kind::Grant ||
        kind == Kind::EntryAck || kind == Kind::CompletionAck;
    return (role == Role::Coordinator) == (local == coordinatorLocal);
}
} // namespace

bool BuildPrepare(std::uint8_t* out, std::size_t capacity, std::size_t* written,
    const ExpectedIdentity& identity, const std::uint8_t rootId[ObjectIdBytes],
    const std::uint8_t* graph, std::size_t graphBytes)
{
    if (out == nullptr || written == nullptr || rootId == nullptr || graph == nullptr ||
        !ValidIdentity(identity) || !ValidObjectId(rootId, identity) ||
        graphBytes == 0 || graphBytes > MaxGraphBytes || capacity < PrepareFixedBytes + graphBytes)
        return false;
    const std::size_t length = PrepareFixedBytes + graphBytes;
    std::memset(out, 0, length);
    BuildHeader(out, Kind::Prepare, identity, out + DigestOffset);
    std::memcpy(out + 84, identity.assemblySha256, 32);
    std::memcpy(out + 116, identity.mvid, 16);
    Put32(out + 132, identity.typeDefToken);
    Put32(out + 136, identity.methodDefToken);
    std::memcpy(out + RootOffset, rootId, ObjectIdBytes);
    Put32(out + 188, static_cast<std::uint32_t>(graphBytes));
    std::memcpy(out + PrepareFixedBytes, graph, graphBytes);
    std::uint8_t canonical[MaxPrepareBytes]{};
    std::uint8_t digest[DigestBytes]{};
    std::memcpy(canonical, out, length);
    std::memset(canonical + DigestOffset, 0, DigestBytes);
    Hash(canonical, length, digest);
    std::memcpy(out + DigestOffset, digest, DigestBytes);
    *written = length;
    return true;
}
bool BuildReady(std::uint8_t* out, std::size_t capacity, std::size_t* written,
    const ExpectedIdentity& identity, const std::uint8_t descriptorDigest[32],
    const std::uint8_t seedDigest[32], std::uint32_t seedCount, std::uint32_t retainedRootCount,
    std::uint32_t forcedCollections, std::uint32_t moved)
{
    if (out == nullptr || written == nullptr || descriptorDigest == nullptr || seedDigest == nullptr ||
        !ValidIdentity(identity) || capacity < ReadyBytes || seedCount == 0 || seedCount > MaxSeeds ||
        retainedRootCount != seedCount || forcedCollections == 0 || moved > 1) return false;
    std::memset(out, 0, ReadyBytes);
    BuildHeader(out, Kind::Ready, identity, descriptorDigest);
    std::memcpy(out + 84, seedDigest, 32);
    Put32(out + 116, seedCount); Put32(out + 120, retainedRootCount);
    Put32(out + 124, forcedCollections); Put32(out + 128, moved);
    *written = ReadyBytes;
    return true;
}
bool BuildGrant(std::uint8_t* out, std::size_t capacity, std::size_t* written,
    const ExpectedIdentity& identity, const std::uint8_t descriptorDigest[32],
    const std::uint8_t seedDigest[32], std::uint32_t seedCount)
{
    if (out == nullptr || written == nullptr || descriptorDigest == nullptr || seedDigest == nullptr ||
        !ValidIdentity(identity) || capacity < GrantBytes || seedCount == 0 || seedCount > MaxSeeds) return false;
    std::memset(out, 0, GrantBytes);
    BuildHeader(out, Kind::Grant, identity, descriptorDigest);
    std::memcpy(out + 84, seedDigest, 32); Put32(out + 116, seedCount);
    *written = GrantBytes;
    return true;
}
bool BuildEntry(std::uint8_t* out, std::size_t capacity, std::size_t* written,
    const ExpectedIdentity& identity, const std::uint8_t descriptorDigest[32],
    const std::uint8_t rootId[ObjectIdBytes], std::uint64_t osThreadId, std::uint32_t invocationOrdinal)
{
    if (out == nullptr || written == nullptr || descriptorDigest == nullptr || rootId == nullptr ||
        !ValidIdentity(identity) || !ValidObjectId(rootId, identity) || capacity < EntryBytes ||
        osThreadId == 0 || invocationOrdinal != 1) return false;
    std::memset(out, 0, EntryBytes);
    BuildHeader(out, Kind::Entry, identity, descriptorDigest);
    std::memcpy(out + EntryRootOffset, rootId, ObjectIdBytes);
    Put64(out + 128, osThreadId); Put32(out + 136, invocationOrdinal);
    *written = EntryBytes;
    return true;
}
bool BuildAcknowledgement(Kind acknowledgementKind, std::uint8_t* out, std::size_t capacity,
    std::size_t* written, const ExpectedIdentity& identity, const std::uint8_t descriptorDigest[32],
    const std::uint8_t* acknowledgedFrame, std::size_t acknowledgedLength)
{
    const Kind expected = acknowledgementKind == Kind::EntryAck ? Kind::Entry :
        (acknowledgementKind == Kind::CompletionAck ? Kind::Completion : static_cast<Kind>(LifecycleRecordCount));
    if (out == nullptr || written == nullptr || descriptorDigest == nullptr || acknowledgedFrame == nullptr ||
        !ValidIdentity(identity) || !ValidKind(expected) || capacity < AckBytes || acknowledgedLength < 4 ||
        KindFromMagic(acknowledgedFrame) != expected ||
        acknowledgedLength != ExactLength(expected, acknowledgedFrame)) return false;
    std::memset(out, 0, AckBytes);
    BuildHeader(out, acknowledgementKind, identity, descriptorDigest);
    Hash(acknowledgedFrame, acknowledgedLength, out + 84);
    *written = AckBytes;
    return true;
}
bool BuildCompletion(std::uint8_t* out, std::size_t capacity, std::size_t* written,
    const ExpectedIdentity& identity, const std::uint8_t descriptorDigest[32],
    std::uint64_t workerSequence, std::uint64_t authorityFrontier,
    std::uint32_t pendingTransferRoots, std::uint32_t callbackSuccess,
    std::uint32_t physicalChildJoined, std::uint32_t invocationOrdinal)
{
    if (out == nullptr || written == nullptr || descriptorDigest == nullptr || !ValidIdentity(identity) ||
        capacity < CompletionBytes || workerSequence > MaxHistorySequence ||
        authorityFrontier > MaxHistorySequence || pendingTransferRoots != 0 ||
        callbackSuccess != 1 || physicalChildJoined != 1 || invocationOrdinal != 1 ||
        ((workerSequence == 0) != (authorityFrontier == 0))) return false;
    std::memset(out, 0, CompletionBytes);
    BuildHeader(out, Kind::Completion, identity, descriptorDigest);
    Put64(out + 84, workerSequence); Put64(out + 92, authorityFrontier);
    Put32(out + 100, pendingTransferRoots); Put32(out + 104, callbackSuccess);
    Put32(out + 108, physicalChildJoined); Put32(out + 112, invocationOrdinal);
    *written = CompletionBytes;
    return true;
}
bool ValidateFrame(const std::uint8_t* frame, std::size_t length, const ExpectedIdentity& identity,
    const std::uint8_t* expectedDescriptorDigest, const std::uint8_t* expectedRootId,
    const LocalCompletionFacts* localFacts, const AuthorityCompletionFacts* authorityFacts,
    DecodedFrame* decoded)
{
    if (frame == nullptr || length < CommonHeaderBytes || decoded == nullptr || !ValidIdentity(identity)) return false;
    const Kind kind = KindFromMagic(frame);
    if (!ValidKind(kind) || !ValidateCommon(frame, length, kind, identity, expectedDescriptorDigest)) return false;
    if (kind == Kind::Prepare)
    {
        if (expectedDescriptorDigest != nullptr || length < PrepareFixedBytes || length > MaxPrepareBytes ||
            Get32(frame + 140) != 0 || Get32(frame + 192) != 0 ||
            Get32(frame + 188) == 0 || Get32(frame + 188) > MaxGraphBytes ||
            length != PrepareFixedBytes + Get32(frame + 188) ||
            !Equal(frame + 84, identity.assemblySha256, 32) || !Equal(frame + 116, identity.mvid, 16) ||
            Get32(frame + 132) != identity.typeDefToken || Get32(frame + 136) != identity.methodDefToken ||
            !ValidObjectId(frame + RootOffset, identity)) return false;
        std::uint8_t canonical[MaxPrepareBytes]{}, digest[DigestBytes]{};
        std::memcpy(canonical, frame, length);
        std::memset(canonical + DigestOffset, 0, DigestBytes);
        Hash(canonical, length, digest);
        if (!Equal(digest, frame + DigestOffset, DigestBytes)) return false;
        InitializeDecoded(decoded, kind, frame);
        std::memcpy(decoded->rootId, frame + RootOffset, ObjectIdBytes);
        return true;
    }
    if (expectedDescriptorDigest == nullptr || length != ExactLength(kind, frame)) return false;
    InitializeDecoded(decoded, kind, frame);
    switch (kind)
    {
        case Kind::Ready:
            if (Get32(frame + 116) == 0 || Get32(frame + 116) > MaxSeeds ||
                Get32(frame + 120) != Get32(frame + 116) || Get32(frame + 124) == 0 ||
                Get32(frame + 128) > 1 || Get32(frame + 132) != 0) return false;
            std::memcpy(decoded->seedDigest, frame + 84, 32);
            decoded->seedCount = Get32(frame + 116);
            return true;
        case Kind::Grant:
            if (Get32(frame + 116) == 0 || Get32(frame + 116) > MaxSeeds || Get32(frame + 120) != 0) return false;
            std::memcpy(decoded->seedDigest, frame + 84, 32);
            decoded->seedCount = Get32(frame + 116);
            return true;
        case Kind::Entry:
            if (expectedRootId == nullptr || !Equal(frame + EntryRootOffset, expectedRootId, ObjectIdBytes) ||
                !ValidObjectId(frame + EntryRootOffset, identity) || Get64(frame + 128) == 0 ||
                Get32(frame + 136) != 1 || Get32(frame + 140) != 0) return false;
            std::memcpy(decoded->rootId, frame + EntryRootOffset, ObjectIdBytes);
            decoded->osThreadId = Get64(frame + 128);
            return true;
        case Kind::EntryAck:
        case Kind::CompletionAck:
            return Get32(frame + 116) == 0;
        case Kind::Completion:
            if (Get32(frame + 100) != 0 || Get32(frame + 104) != 1 ||
                Get32(frame + 108) != 1 || Get32(frame + 112) != 1 || Get32(frame + 116) != 0 ||
                Get64(frame + 84) > MaxHistorySequence || Get64(frame + 92) > MaxHistorySequence ||
                ((Get64(frame + 84) == 0) != (Get64(frame + 92) == 0)) ||
                !ValidateCompletionFacts(frame, localFacts, authorityFacts)) return false;
            decoded->workerSequence = Get64(frame + 84);
            decoded->authorityFrontier = Get64(frame + 92);
            return true;
        case Kind::Prepare:
            return false;
    }
    return false;
}

Ledger::Ledger(Role role, const ExpectedIdentity& identity)
    : m_role(role), m_identity(identity), m_records{}, m_lengths{}, m_descriptorDigest{},
      m_seedDigest{}, m_rootId{}, m_seedCount(0), m_next(0), m_duplicates(0),
      m_hasPrepare(false), m_hasSeedSet(false), m_executionClaimed(false), m_aborted(false)
{
}
bool Ledger::RecordLocal(const std::uint8_t* frame, std::size_t length,
    const LocalCompletionFacts* localFacts, Observation* observation)
{
    return Observe(true, frame, length, localFacts, nullptr, observation);
}
bool Ledger::AcceptRemote(const std::uint8_t* frame, std::size_t length,
    const AuthorityCompletionFacts* authorityFacts, Observation* observation)
{
    return Observe(false, frame, length, nullptr, authorityFacts, observation);
}
bool Ledger::Observe(bool local, const std::uint8_t* frame, std::size_t length,
    const LocalCompletionFacts* localFacts, const AuthorityCompletionFacts* authorityFacts,
    Observation* observation)
{
    if (m_aborted || frame == nullptr || length < 4 || observation == nullptr) return Fail();
    const Kind kind = KindFromMagic(frame);
    if (!ValidKind(kind) || !DirectionAllows(m_role, local, kind)) return Fail();
    const std::size_t index = IndexOf(kind);
    if (m_lengths[index] != 0)
    {
        if (m_lengths[index] != length || !Equal(m_records[index], frame, length) || m_duplicates == MaxDuplicates)
            return Fail();
        ++m_duplicates;
        observation->disposition = Disposition::Duplicate;
        observation->hasCachedReply = false;
        const Kind replyKind = kind == Kind::Prepare ? Kind::Ready :
            (kind == Kind::Grant ? Kind::Entry :
             (kind == Kind::Entry ? Kind::EntryAck :
              (kind == Kind::Completion ? Kind::CompletionAck : static_cast<Kind>(LifecycleRecordCount))));
        if (ValidKind(replyKind) && m_lengths[IndexOf(replyKind)] != 0)
        {
            observation->hasCachedReply = true;
            observation->cachedReplyKind = replyKind;
            observation->disposition = Disposition::DuplicateWithCachedReply;
        }
        return true;
    }
    if (index != m_next) return Fail();

    DecodedFrame decoded{};
    const std::uint8_t* expectedDigest = m_hasPrepare ? m_descriptorDigest : nullptr;
    const std::uint8_t* expectedRoot = m_hasPrepare ? m_rootId : nullptr;
    if (!ValidateFrame(frame, length, m_identity, expectedDigest, expectedRoot, localFacts, authorityFacts, &decoded))
        return Fail();
    if (kind == Kind::Ready)
    {
        if (!m_hasPrepare) return Fail();
        std::memcpy(m_seedDigest, decoded.seedDigest, 32);
        m_seedCount = decoded.seedCount;
        m_hasSeedSet = true;
    }
    if (kind == Kind::Grant && (!m_hasSeedSet || decoded.seedCount != m_seedCount ||
        !Equal(decoded.seedDigest, m_seedDigest, 32))) return Fail();
    if (kind == Kind::Entry && ((m_role == Role::Worker && (!local || !m_executionClaimed)) || (m_role == Role::Coordinator && local))) return Fail();
    if (kind == Kind::Completion &&
        ((m_role == Role::Worker && (localFacts == nullptr || authorityFacts != nullptr)) ||
         (m_role == Role::Coordinator && (authorityFacts == nullptr || localFacts != nullptr)))) return Fail();
    if (kind == Kind::EntryAck || kind == Kind::CompletionAck)
    {
        const std::size_t predecessor = kind == Kind::EntryAck ? IndexOf(Kind::Entry) : IndexOf(Kind::Completion);
        if (m_lengths[predecessor] == 0 || !HashMatches(m_records[predecessor], m_lengths[predecessor], frame + 84))
            return Fail();
    }

    std::memcpy(m_records[index], frame, length);
    m_lengths[index] = length;
    if (kind == Kind::Prepare)
    {
        std::memcpy(m_descriptorDigest, decoded.descriptorDigest, 32);
        std::memcpy(m_rootId, decoded.rootId, ObjectIdBytes);
        m_hasPrepare = true;
    }
    ++m_next;
    observation->disposition = Disposition::Recorded;
    observation->hasCachedReply = false;
    return true;
}
bool Ledger::ClaimExecution()
{
    if (m_aborted || m_role != Role::Worker || m_next != 3 || !m_hasPrepare || m_executionClaimed)
        return Fail();
    m_executionClaimed = true;
    return true;
}
bool Ledger::CopyRecord(Kind kind, std::uint8_t* out, std::size_t capacity, std::size_t* written) const
{
    const std::size_t index = IndexOf(kind);
    if (m_aborted || out == nullptr || written == nullptr || !ValidKind(kind) ||
        m_lengths[index] == 0 || capacity < m_lengths[index]) return false;
    std::memcpy(out, m_records[index], m_lengths[index]);
    *written = m_lengths[index];
    return true;
}
void Ledger::Abort() { m_aborted = true; }
bool Ledger::IsAborted() const { return m_aborted; }
std::uint32_t Ledger::DuplicateCount() const { return m_duplicates; }
bool Ledger::Fail() { m_aborted = true; return false; }
} // namespace DistributedThreadProtocol
