#ifndef DCG01_RAW_FRAME_JOURNAL_H
#define DCG01_RAW_FRAME_JOURNAL_H

// Candidate-only in-memory journal for the inspected DCC1 v1 transport.
// This is not a durable artifact encoding and does not authenticate its producer.
#include <openssl/sha.h>

#include <atomic>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace dcg01_raw
{
static const uint32_t kDccHeaderBytes = 128;
static const uint32_t kDccPayloadBytes = 4096;
static const uint32_t kMaxFrameBytes = kDccHeaderBytes + kDccPayloadBytes;
static const uint32_t kRawByteLimit = 4 * 1024 * 1024;
// DCC1 frames are at least 128 bytes; this count bound is raw-frame specific,
// independent of canonical-r3's 2,048 event limit.
static const uint32_t kRawFrameLimit = kRawByteLimit / kDccHeaderBytes;
static const uint32_t kTls13Version = 0x0304;

enum Direction : uint8_t { Outbound = 1, Inbound = 2 };
enum class ReceiveMark : uint8_t { NewFrame = 0, DuplicateAccepted = 1 };
enum class CaptureResult : uint8_t { Captured, Rejected, Capacity, ProducerConflict };

struct SessionContext
{
    uint32_t localMember;
    uint32_t peerMember;
    uint32_t tlsVersion;
    uint8_t peerCertificateVerified;
    uint8_t sessionReused;
    uint8_t reserved[2];
    uint64_t processId;
    uint64_t processStartTicks;
    uint64_t executableDevice;
    uint64_t executableInode;
    uint64_t executableBytes;
    unsigned char runId[16];
    unsigned char manifestSha256[32];
    unsigned char localIncarnation[16];
    unsigned char peerIncarnation[16];
    unsigned char peerCertificateSha256[32];
    char executablePath[512];
};

// In-memory metadata only. Do not fwrite this ABI struct as a portable artifact;
// a separately reviewed serializer is required for durable evidence.
struct FrameMeta
{
    uint32_t byteOffset;
    uint16_t frameBytes;
    uint16_t kind;
    uint64_t outerSequence;
    unsigned char frameSha256[32];
    uint8_t direction;
    uint8_t duplicateAccepted;
    uint8_t reserved[6];
};

struct SnapshotInfo
{
    uint32_t frameCount;
    uint32_t frameBytes;
    uint8_t configured;
    uint8_t transportStopped;
    uint8_t overflow;
    uint8_t incomplete;
    uint8_t complete;
    uint8_t reserved[3];
};

class Journal final
{
public:
    Journal()
        : publishedFrames_(0), configured_(false), stopped_(false), overflow_(false),
          incomplete_(false), appendBusy_(ATOMIC_FLAG_INIT), session_(), rows_(), bytes_()
    {
    }

    Journal(const Journal&) = delete;
    Journal& operator=(const Journal&) = delete;

    // Call exactly once, after TLS peer pin verification and before exchange().
    // Context remains immutable for the process/run; this class has no reset.
    bool Configure(const SessionContext& context)
    {
        if (configured_.load(std::memory_order_acquire) || stopped_.load(std::memory_order_acquire) ||
            incomplete_.load(std::memory_order_acquire) || !ValidContext(context))
        {
            incomplete_.store(true, std::memory_order_release);
            return false;
        }
        session_ = context;
        configured_.store(true, std::memory_order_release);
        return true;
    }

    // Only the one transport worker may append. The caller marks receive rows
    // duplicate only after existing DCC1 duplicate checks accepted identical bytes.
    CaptureResult Capture(Direction direction, ReceiveMark receiveMark,
        const unsigned char* frame, size_t frameBytes)
    {
        if (!configured_.load(std::memory_order_acquire) || stopped_.load(std::memory_order_acquire) ||
            !ValidFrame(direction, receiveMark, frame, frameBytes))
        {
            incomplete_.store(true, std::memory_order_release);
            return CaptureResult::Rejected;
        }
        if (appendBusy_.test_and_set(std::memory_order_acquire))
        {
            incomplete_.store(true, std::memory_order_release);
            return CaptureResult::ProducerConflict;
        }

        const uint32_t rowIndex = publishedFrames_.load(std::memory_order_relaxed);
        uint32_t byteOffset = 0;
        if (rowIndex != 0)
        {
            const FrameMeta& previous = rows_[rowIndex - 1];
            byteOffset = previous.byteOffset + previous.frameBytes;
        }
        if (rowIndex >= kRawFrameLimit || frameBytes > kMaxFrameBytes ||
            byteOffset > kRawByteLimit || frameBytes > kRawByteLimit - byteOffset)
        {
            overflow_.store(true, std::memory_order_release);
            incomplete_.store(true, std::memory_order_release);
            appendBusy_.clear(std::memory_order_release);
            return CaptureResult::Capacity;
        }

        FrameMeta& row = rows_[rowIndex];
        memset(&row, 0, sizeof(row));
        row.byteOffset = byteOffset;
        row.frameBytes = static_cast<uint16_t>(frameBytes);
        row.kind = static_cast<uint16_t>(Get(frame + 6, 2));
        row.outerSequence = Get(frame + 24, 8);
        row.direction = static_cast<uint8_t>(direction);
        row.duplicateAccepted = receiveMark == ReceiveMark::DuplicateAccepted ? 1 : 0;
        if (SHA256(frame, frameBytes, row.frameSha256) == nullptr)
        {
            incomplete_.store(true, std::memory_order_release);
            appendBusy_.clear(std::memory_order_release);
            return CaptureResult::Rejected;
        }
        memcpy(bytes_ + byteOffset, frame, frameBytes);
        // Publish only after the exact frame and its metadata are immutable.
        publishedFrames_.store(rowIndex + 1, std::memory_order_release);
        appendBusy_.clear(std::memory_order_release);
        return CaptureResult::Captured;
    }

    void MarkIncomplete()
    {
        incomplete_.store(true, std::memory_order_release);
    }

    // Caller must invoke only after the transport worker has been joined. There
    // is intentionally no reset/freeze operation that can race a producer.
    void MarkTransportStopped()
    {
        stopped_.store(true, std::memory_order_release);
    }

    // Active snapshots copy only a published immutable prefix and report complete=0.
    // Once stopped, a successful snapshot is final. On rejection, caller buffers and
    // the info output remain untouched.
    bool Snapshot(SessionContext* session, FrameMeta* rows, size_t rowCapacity,
        unsigned char* frameBytes, size_t byteCapacity, SnapshotInfo* info) const
    {
        if (session == nullptr || info == nullptr || !configured_.load(std::memory_order_acquire))
            return false;
        const bool stoppedBefore = stopped_.load(std::memory_order_acquire);
        const uint32_t count = publishedFrames_.load(std::memory_order_acquire);
        uint32_t usedBytes = 0;
        if (count != 0)
        {
            const FrameMeta& last = rows_[count - 1];
            usedBytes = last.byteOffset + last.frameBytes;
        }
        if (rowCapacity < count || byteCapacity < usedBytes ||
            (count != 0 && (rows == nullptr || frameBytes == nullptr)))
            return false;

        *session = session_;
        if (count != 0)
        {
            memcpy(rows, rows_, static_cast<size_t>(count) * sizeof(FrameMeta));
            memcpy(frameBytes, bytes_, usedBytes);
        }
        SnapshotInfo result{};
        result.frameCount = count;
        result.frameBytes = usedBytes;
        result.configured = 1;
        result.transportStopped = stopped_.load(std::memory_order_acquire) ? 1 : 0;
        result.overflow = overflow_.load(std::memory_order_acquire) ? 1 : 0;
        result.incomplete = incomplete_.load(std::memory_order_acquire) ? 1 : 0;
        result.complete = stoppedBefore && result.transportStopped && !result.overflow && !result.incomplete;
        *info = result;
        return true;
    }

    uint32_t PublishedFrameCount() const
    {
        return publishedFrames_.load(std::memory_order_acquire);
    }

    static size_t ResidentBytes()
    {
        return sizeof(Journal);
    }

private:
    static uint64_t Get(const unsigned char* bytes, unsigned count)
    {
        uint64_t result = 0;
        for (unsigned i = 0; i < count; ++i) result = (result << 8) | bytes[i];
        return result;
    }

    static bool NonZero(const unsigned char* bytes, size_t count)
    {
        unsigned char value = 0;
        for (size_t i = 0; i < count; ++i) value |= bytes[i];
        return value != 0;
    }

    static bool ValidContext(const SessionContext& value)
    {
        const bool pathTerminated = memchr(value.executablePath, '\0', sizeof(value.executablePath)) != nullptr;
        return value.localMember >= 1 && value.localMember <= 2 && value.peerMember >= 1 &&
            value.peerMember <= 2 && value.localMember != value.peerMember &&
            value.tlsVersion == kTls13Version && value.peerCertificateVerified == 1 &&
            value.sessionReused == 0 && value.processId != 0 && value.processStartTicks != 0 &&
            value.executableDevice != 0 && value.executableInode != 0 && value.executableBytes != 0 &&
            value.executablePath[0] == '/' && pathTerminated && NonZero(value.runId, sizeof(value.runId)) &&
            NonZero(value.manifestSha256, sizeof(value.manifestSha256)) &&
            NonZero(value.localIncarnation, sizeof(value.localIncarnation)) &&
            NonZero(value.peerIncarnation, sizeof(value.peerIncarnation)) &&
            NonZero(value.peerCertificateSha256, sizeof(value.peerCertificateSha256));
    }

    bool ValidFrame(Direction direction, ReceiveMark receiveMark,
        const unsigned char* frame, size_t frameBytes) const
    {
        if (frame == nullptr || frameBytes < kDccHeaderBytes || frameBytes > kMaxFrameBytes ||
            memcmp(frame, "DCC1", 4) != 0 || Get(frame + 4, 2) != 1 ||
            Get(frame + 8, 4) != frameBytes - kDccHeaderBytes || Get(frame + 20, 4) != 0 ||
            Get(frame + 112, 8) != 1 || memcmp(frame + 32, session_.runId, 16) != 0 ||
            memcmp(frame + 48, session_.manifestSha256, 32) != 0)
            return false;
        const bool outbound = direction == Outbound;
        if (!outbound && direction != Inbound) return false;
        if (receiveMark == ReceiveMark::DuplicateAccepted && outbound) return false;
        const uint32_t sourceMember = static_cast<uint32_t>(Get(frame + 12, 4));
        const uint32_t targetMember = static_cast<uint32_t>(Get(frame + 16, 4));
        const unsigned char* sourceInc = outbound ? session_.localIncarnation : session_.peerIncarnation;
        const unsigned char* targetInc = outbound ? session_.peerIncarnation : session_.localIncarnation;
        if (sourceMember != (outbound ? session_.localMember : session_.peerMember) ||
            targetMember != (outbound ? session_.peerMember : session_.localMember) ||
            memcmp(frame + 80, sourceInc, 16) != 0 || memcmp(frame + 96, targetInc, 16) != 0)
            return false;
        const uint64_t kind = Get(frame + 6, 2);
        const uint64_t sequence = Get(frame + 24, 8);
        const uint64_t correlation = Get(frame + 120, 8);
        const uint64_t payload = Get(frame + 8, 4);
        const bool control = kind >= 1 && kind <= 4 && payload == 0 && sequence == 0 && correlation != 0;
        const bool data = kind >= 16 && kind <= 23 && payload > 0 && sequence != 0 && correlation == sequence;
        return control || data;
    }

    std::atomic<uint32_t> publishedFrames_;
    std::atomic<bool> configured_;
    std::atomic<bool> stopped_;
    std::atomic<bool> overflow_;
    std::atomic<bool> incomplete_;
    std::atomic_flag appendBusy_;
    SessionContext session_;
    FrameMeta rows_[kRawFrameLimit];
    unsigned char bytes_[kRawByteLimit];
};

} // namespace dcg01_raw

// Private native control-layer snapshot seam. It never writes a file; callers
// provide all buffers. Include this C++ header for the matching declaration.
extern "C" bool DistributedControlFrameJournalSnapshot(dcg01_raw::SessionContext* session,
    dcg01_raw::FrameMeta* rows, size_t rowCapacity, unsigned char* frameBytes,
    size_t byteCapacity, dcg01_raw::SnapshotInfo* info);

#endif // DCG01_RAW_FRAME_JOURNAL_H
