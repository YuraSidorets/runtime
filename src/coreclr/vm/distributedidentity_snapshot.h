#ifndef DCG01_IDENTITY_SNAPSHOT_H
#define DCG01_IDENTITY_SNAPSHOT_H

#include <cstring>
#include <stdint.h>

namespace dcg01_identity_snapshot
{
static_assert(sizeof(uint32_t) == 4, "snapshot requires 32-bit fixed-width fields");
static_assert(sizeof(uint64_t) == 8, "snapshot requires 64-bit fixed-width fields");
constexpr unsigned kMaxEntries = 64;
constexpr unsigned kMaxPublicationNodes = 16;
constexpr unsigned kObjectIdBytes = 44;
constexpr uint32_t kMaxRetainedBytes = 64 * 1024;

enum PublicationPhase : unsigned { Idle = 0, Prepared = 1, Activated = 2 };
enum EvidenceState : unsigned { UnsupportedOpen = 1, NotCapturedOpen = 2 };

struct Entry
{
    unsigned char id[kObjectIdBytes];
    uint32_t owner;
    uint32_t version;
    uint32_t bytes;
    uint32_t retention;
};

struct Publication
{
    uint32_t phase;
    uint64_t transaction;
    uint64_t sourceFrontier;
    uint32_t count;
    uint32_t bytes;
    unsigned char root[kObjectIdBytes];
    unsigned char nodeIds[kMaxPublicationNodes][kObjectIdBytes];
    uint32_t nodeBytes[kMaxPublicationNodes];
};

// This is a plain-value view of source fields. It intentionally has no handle,
// OBJECTREF, Thread*, or other native/runtime address fields.
struct SourceState
{
    unsigned char run[16];
    uint32_t localNode;
    uint32_t peerNode;
    unsigned char localInc[16];
    unsigned char peerInc[16];
    unsigned char assemblyHash[32];
    unsigned char mvid[16];
    uint32_t entryCount;
    uint32_t retainedBytes;
    uint32_t failed;
    uint32_t frozen;
    uint32_t pendingPublicationRootCount;
    Entry entries[kMaxEntries];
    Publication publication;
};

struct Snapshot
{
    uint32_t schemaVersion;
    unsigned char run[16];
    uint32_t localNode;
    uint32_t peerNode;
    unsigned char localInc[16];
    unsigned char peerInc[16];
    unsigned char assemblyHash[32];
    unsigned char mvid[16];
    uint32_t entryCount;
    uint32_t retainedBytes;
    uint32_t failed;
    uint32_t frozen;
    uint32_t pendingPublicationRootCount;
    uint32_t logicalRootCensusState;
    uint32_t accessPublicationState;
    uint32_t terminalEligible;
    Entry entries[kMaxEntries];
    Publication publication;
};

inline bool IsZeroId(const unsigned char* id)
{
    unsigned char any = 0;
    for (unsigned i = 0; i < kObjectIdBytes; ++i) any |= id[i];
    return any == 0;
}

inline uint32_t Read32(const unsigned char* value)
{
    return static_cast<uint32_t>(value[0]) |
        (static_cast<uint32_t>(value[1]) << 8) |
        (static_cast<uint32_t>(value[2]) << 16) |
        (static_cast<uint32_t>(value[3]) << 24);
}

inline uint64_t Read64(const unsigned char* value)
{
    uint64_t result = 0;
    for (unsigned i = 0; i < 8; ++i)
        result |= static_cast<uint64_t>(value[i]) << (8 * i);
    return result;
}

inline bool ValidId(const unsigned char* id, const SourceState& source, uint32_t expectedOwner)
{
    if (IsZeroId(id) || std::memcmp(id, source.run, sizeof(source.run)) != 0)
        return false;
    const uint32_t encodedOwner = Read32(id + 16);
    if (encodedOwner != expectedOwner ||
        (expectedOwner != source.localNode && expectedOwner != source.peerNode))
        return false;
    const unsigned char* expectedIncarnation =
        expectedOwner == source.localNode ? source.localInc : source.peerInc;
    if (std::memcmp(id + 20, expectedIncarnation, sizeof(source.localInc)) != 0)
        return false;
    const uint64_t counter = Read64(id + 36);
    return counter != 0 && counter <= kMaxEntries;
}

inline bool HasDuplicateIds(const Entry* entries, unsigned count)
{
    for (unsigned i = 0; i < count; ++i)
        for (unsigned j = i + 1; j < count; ++j)
            if (std::memcmp(entries[i].id, entries[j].id, kObjectIdBytes) == 0) return true;
    return false;
}

inline bool HasDuplicatePublicationIds(const Publication& publication)
{
    for (unsigned i = 0; i < publication.count; ++i)
        for (unsigned j = i + 1; j < publication.count; ++j)
            if (std::memcmp(publication.nodeIds[i], publication.nodeIds[j], kObjectIdBytes) == 0) return true;
    return false;
}

inline bool AllZero(const unsigned char* value, unsigned length)
{
    unsigned char any = 0;
    for (unsigned i = 0; i < length; ++i) any |= value[i];
    return any == 0;
}

inline bool IdlePublicationIsZero(const Publication& publication)
{
    if (publication.transaction != 0 || publication.sourceFrontier != 0 ||
        publication.count != 0 || publication.bytes != 0 || !AllZero(publication.root, kObjectIdBytes))
        return false;
    return AllZero(reinterpret_cast<const unsigned char*>(publication.nodeIds),
        sizeof(publication.nodeIds)) &&
        AllZero(reinterpret_cast<const unsigned char*>(publication.nodeBytes),
        sizeof(publication.nodeBytes));
}

inline bool Valid(const SourceState& source)
{
    if (source.entryCount > kMaxEntries || source.publication.count > kMaxPublicationNodes ||
        source.publication.phase > Activated || source.failed > 1 || source.frozen > 1 ||
        source.pendingPublicationRootCount > kMaxPublicationNodes ||
        source.retainedBytes > kMaxRetainedBytes || HasDuplicateIds(source.entries, source.entryCount) ||
        HasDuplicatePublicationIds(source.publication)) return false;

    uint64_t retainedBytes = 0;
    for (unsigned i = 0; i < source.entryCount; ++i)
    {
        const Entry& entry = source.entries[i];
        if (!ValidId(entry.id, source, entry.owner) || entry.version != 0 || entry.bytes == 0 ||
            entry.retention == 0 || (entry.retention & ~7u) != 0)
            return false;
        retainedBytes += entry.bytes;
        if (retainedBytes > kMaxRetainedBytes) return false;
    }
    if (retainedBytes != source.retainedBytes) return false;

    if (source.publication.phase == Idle)
        return source.pendingPublicationRootCount == 0 && IdlePublicationIsZero(source.publication);

    if (source.publication.count == 0 || source.publication.transaction == 0 ||
        source.pendingPublicationRootCount != source.publication.count ||
        !ValidId(source.publication.root, source, source.localNode) ||
        std::memcmp(source.publication.root, source.publication.nodeIds[0], kObjectIdBytes) != 0)
        return false;

    uint64_t publicationBytes = 0;
    for (unsigned i = 0; i < source.publication.count; ++i)
    {
        if (!ValidId(source.publication.nodeIds[i], source, source.localNode) ||
            source.publication.nodeBytes[i] == 0)
            return false;
        publicationBytes += source.publication.nodeBytes[i];
        if (publicationBytes > kMaxRetainedBytes) return false;
        for (unsigned j = source.publication.count; j < kMaxPublicationNodes; ++j)
            if (source.publication.nodeBytes[j] != 0 ||
                !AllZero(source.publication.nodeIds[j], kObjectIdBytes))
                return false;
    }
    if (publicationBytes != source.publication.bytes) return false;

    for (unsigned i = 0; i < source.publication.count; ++i)
    {
        int entryIndex = -1;
        for (unsigned j = 0; j < source.entryCount; ++j)
            if (std::memcmp(source.publication.nodeIds[i], source.entries[j].id,
                    kObjectIdBytes) == 0)
            {
                entryIndex = static_cast<int>(j);
                break;
            }
        if (source.publication.phase == Prepared)
        {
            if (entryIndex >= 0) return false;
        }
        else
        {
            if (entryIndex < 0) return false;
            const Entry& entry = source.entries[entryIndex];
            if (entry.owner != source.localNode || entry.version != 0 ||
                entry.bytes != source.publication.nodeBytes[i] || entry.retention != 3)
                return false;
        }
    }
    return source.publication.phase != Prepared ||
        static_cast<uint64_t>(source.retainedBytes) + source.publication.bytes <= kMaxRetainedBytes;
}

// Copies only represented plain values. On every failure, output is unchanged.
// root census/access publication remain open and terminalEligible is always false.
inline bool Capture(const SourceState& source, bool callerIsOwner, Snapshot* output,
    unsigned outputEntryCapacity)
{
    if (!callerIsOwner || output == nullptr || outputEntryCapacity < source.entryCount || !Valid(source))
        return false;
    Snapshot captured{};
    captured.schemaVersion = 1;
    std::memcpy(captured.run, source.run, sizeof(captured.run));
    captured.localNode = source.localNode;
    captured.peerNode = source.peerNode;
    std::memcpy(captured.localInc, source.localInc, sizeof(captured.localInc));
    std::memcpy(captured.peerInc, source.peerInc, sizeof(captured.peerInc));
    std::memcpy(captured.assemblyHash, source.assemblyHash, sizeof(captured.assemblyHash));
    std::memcpy(captured.mvid, source.mvid, sizeof(captured.mvid));
    captured.entryCount = source.entryCount;
    captured.retainedBytes = source.retainedBytes;
    captured.failed = source.failed;
    captured.frozen = source.frozen;
    captured.pendingPublicationRootCount = source.pendingPublicationRootCount;
    captured.logicalRootCensusState = UnsupportedOpen;
    captured.accessPublicationState = NotCapturedOpen;
    captured.terminalEligible = 0;
    for (unsigned i = 0; i < source.entryCount; ++i) captured.entries[i] = source.entries[i];
    captured.publication = source.publication;
    *output = captured;
    return true;
}
}

#endif
