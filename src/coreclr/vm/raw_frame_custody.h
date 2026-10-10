#ifndef DCG01_RAW_FRAME_CUSTODY_H
#define DCG01_RAW_FRAME_CUSTODY_H

// Candidate-only local persistence for the existing bounded DCC1 raw-frame
// snapshot. This is not a coordinator receipt, terminal commitment, or success
// record. The caller must stop and join the transport producer before Snapshot.
#include "raw_frame_journal.h"

#include <openssl/evp.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace dcg01_raw
{
namespace custody
{
static const uint16_t kFormatVersion = 1;
static const uint32_t kFixedHeaderBytes = 20;
static const uint32_t kSessionFixedBytes = 170;
static const uint32_t kFrameRecordBytes = 56;
static const uint32_t kFooterBytes = 48;
static const uint64_t kMaxCustodyArtifactBytes = kFixedHeaderBytes + 8 +
    kSessionFixedBytes + 511 + kRawByteLimit +
    static_cast<uint64_t>(kFrameRecordBytes) * kRawFrameLimit + kFooterBytes;
static const unsigned char kSourceComplete = 1;
static const unsigned char kSourceIncomplete = 2;

enum class ResultCode : uint8_t
{
    StoredComplete,
    StoredIncomplete,
    Rejected,
    AlreadyExists,
    Failed
};

struct Result
{
    ResultCode code;
    uint8_t fileCreated;
    int errorNumber;
    uint64_t bytesWritten;
};

// DCCJ v1 is byte encoded, big-endian and independent of C++ struct layout:
// 20-byte header, SES1 metadata record, repeated FRM1 metadata + exact DCC1
// bytes, then an ENDJ footer. SHA-256 covers every byte before the footer.
// The footer status describes source journal completeness, not terminal
// eligibility. No footer means the file is incomplete regardless of its length.
static void Put16(unsigned char* out, uint16_t value)
{
    out[0] = static_cast<unsigned char>(value >> 8);
    out[1] = static_cast<unsigned char>(value);
}

static void Put32(unsigned char* out, uint32_t value)
{
    out[0] = static_cast<unsigned char>(value >> 24);
    out[1] = static_cast<unsigned char>(value >> 16);
    out[2] = static_cast<unsigned char>(value >> 8);
    out[3] = static_cast<unsigned char>(value);
}

static void Put64(unsigned char* out, uint64_t value)
{
    for (unsigned i = 0; i != 8; ++i)
        out[i] = static_cast<unsigned char>(value >> (56 - i * 8));
}

static uint16_t Get16(const unsigned char* in)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(in[0]) << 8) | in[1]);
}

static uint32_t Get32(const unsigned char* in)
{
    return (static_cast<uint32_t>(in[0]) << 24) |
        (static_cast<uint32_t>(in[1]) << 16) |
        (static_cast<uint32_t>(in[2]) << 8) | in[3];
}

static uint64_t Get64(const unsigned char* in)
{
    uint64_t value = 0;
    for (unsigned i = 0; i != 8; ++i) value = (value << 8) | in[i];
    return value;
}

class Digest final
{
public:
    Digest() : context_(EVP_MD_CTX_new()), ready_(false)
    {
        ready_ = context_ != nullptr && EVP_DigestInit_ex(context_, EVP_sha256(), nullptr) == 1;
    }

    ~Digest()
    {
        EVP_MD_CTX_free(context_);
    }

    bool Ready() const { return ready_; }

    bool Update(const void* bytes, size_t count)
    {
        return ready_ && EVP_DigestUpdate(context_, bytes, count) == 1;
    }

    bool Finish(unsigned char output[32])
    {
        unsigned int length = 0;
        return ready_ && EVP_DigestFinal_ex(context_, output, &length) == 1 && length == 32;
    }

private:
    Digest(const Digest&);
    Digest& operator=(const Digest&);
    EVP_MD_CTX* context_;
    bool ready_;
};

static bool WriteAll(int fd, const void* input, size_t count, uint64_t* total)
{
    const unsigned char* bytes = static_cast<const unsigned char*>(input);
    size_t offset = 0;
    while (offset < count)
    {
        const ssize_t written = write(fd, bytes + offset, count - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        offset += static_cast<size_t>(written);
        *total += static_cast<uint64_t>(written);
    }
    return true;
}

static bool WriteHashed(int fd, Digest& digest, const void* bytes, size_t count, uint64_t* total)
{
    return digest.Update(bytes, count) && WriteAll(fd, bytes, count, total);
}

static bool ValidName(const char* name)
{
    if (name == nullptr) return false;
    const size_t length = strnlen(name, 128);
    if (length < 6 || length >= 128 || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return false;
    if (strcmp(name + length - 5, ".dccj") != 0) return false;
    for (size_t i = 0; i != length; ++i)
    {
        const char c = name[i];
        const bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
        if (!allowed) return false;
    }
    return true;
}

static bool NonZero(const unsigned char* value, size_t length)
{
    unsigned char combined = 0;
    for (size_t i = 0; i != length; ++i) combined |= value[i];
    return combined != 0;
}

static uint64_t FrameField(const unsigned char* bytes, unsigned count)
{
    uint64_t value = 0;
    for (unsigned i = 0; i != count; ++i) value = (value << 8) | bytes[i];
    return value;
}

static bool ValidContext(const SessionContext& c, uint16_t* pathBytes)
{
    const void* end = memchr(c.executablePath, '\0', sizeof(c.executablePath));
    if (end == nullptr) return false;
    const size_t length = static_cast<const char*>(end) - c.executablePath;
    if (length == 0 || length > 511 || c.executablePath[0] != '/' ||
        c.localMember < 1 || c.localMember > 2 || c.peerMember < 1 ||
        c.peerMember > 2 || c.localMember == c.peerMember ||
        c.tlsVersion != kTls13Version || c.peerCertificateVerified != 1 ||
        c.sessionReused != 0 || c.processId == 0 || c.processStartTicks == 0 ||
        c.executableDevice == 0 || c.executableInode == 0 || c.executableBytes == 0 ||
        !NonZero(c.runId, sizeof(c.runId)) || !NonZero(c.manifestSha256, sizeof(c.manifestSha256)) ||
        !NonZero(c.localIncarnation, sizeof(c.localIncarnation)) ||
        !NonZero(c.peerIncarnation, sizeof(c.peerIncarnation)) ||
        !NonZero(c.peerCertificateSha256, sizeof(c.peerCertificateSha256)))
        return false;
    *pathBytes = static_cast<uint16_t>(length);
    return true;
}

static bool ValidSnapshot(const SessionContext& session, const FrameMeta* rows,
    const unsigned char* frames, const SnapshotInfo& info, uint16_t* pathBytes)
{
    if (info.configured != 1 || info.transportStopped != 1 ||
        info.frameCount > kRawFrameLimit || info.frameBytes > kRawByteLimit ||
        info.overflow > 1 || info.incomplete > 1 || info.complete > 1 ||
        (info.frameCount != 0 && (rows == nullptr || frames == nullptr)) ||
        !ValidContext(session, pathBytes))
        return false;

    const bool expectedComplete = info.transportStopped && !info.overflow && !info.incomplete;
    if ((info.complete != 0) != expectedComplete) return false;
    if (info.frameCount == 0 && info.frameBytes != 0) return false;

    uint32_t expectedOffset = 0;
    for (uint32_t i = 0; i != info.frameCount; ++i)
    {
        const FrameMeta& row = rows[i];
        if (row.byteOffset != expectedOffset || row.frameBytes < kDccHeaderBytes ||
            row.frameBytes > kMaxFrameBytes || row.direction < Outbound || row.direction > Inbound ||
            row.duplicateAccepted > 1 || (row.direction == Outbound && row.duplicateAccepted != 0) ||
            row.frameBytes > info.frameBytes - expectedOffset)
            return false;
        const unsigned char* frame = frames + expectedOffset;
        if (memcmp(frame, "DCC1", 4) != 0 || Get16(frame + 4) != 1 ||
            Get32(frame + 8) != row.frameBytes - kDccHeaderBytes ||
            Get32(frame + 20) != 0 || Get64(frame + 112) != 1 ||
            memcmp(frame + 32, session.runId, 16) != 0 ||
            memcmp(frame + 48, session.manifestSha256, 32) != 0 ||
            FrameField(frame + 6, 2) != row.kind || FrameField(frame + 24, 8) != row.outerSequence)
            return false;
        const bool outbound = row.direction == Outbound;
        if (FrameField(frame + 12, 4) != (outbound ? session.localMember : session.peerMember) ||
            FrameField(frame + 16, 4) != (outbound ? session.peerMember : session.localMember) ||
            memcmp(frame + 80, outbound ? session.localIncarnation : session.peerIncarnation, 16) != 0 ||
            memcmp(frame + 96, outbound ? session.peerIncarnation : session.localIncarnation, 16) != 0)
            return false;
        const uint64_t kind = row.kind;
        const uint64_t sequence = row.outerSequence;
        const uint64_t correlation = FrameField(frame + 120, 8);
        const uint32_t payload = Get32(frame + 8);
        const bool control = kind >= 1 && kind <= 4 && payload == 0 && sequence == 0 && correlation != 0;
        const bool data = kind >= 16 && kind <= 23 && payload > 0 && sequence != 0 && correlation == sequence;
        unsigned char actualHash[32];
        if (!(control || data) || SHA256(frame, row.frameBytes, actualHash) == nullptr ||
            memcmp(actualHash, row.frameSha256, sizeof(actualHash)) != 0)
            return false;
        expectedOffset += row.frameBytes;
    }
    return expectedOffset == info.frameBytes &&
        (info.complete != 0 || info.incomplete != 0 || info.overflow != 0);
}

static Result PersistStoppedSnapshot(int directoryFd, const char* name,
    const SessionContext* session, const FrameMeta* rows, const unsigned char* frames,
    const SnapshotInfo* info)
{
    Result result = { ResultCode::Rejected, 0, 0, 0 };
    if (directoryFd < 0 || session == nullptr || info == nullptr || !ValidName(name))
        return result;

    uint16_t pathBytes = 0;
    if (!ValidSnapshot(*session, rows, frames, *info, &pathBytes)) return result;

    struct stat directoryInfo;
    if (fstat(directoryFd, &directoryInfo) != 0)
    {
        result.code = ResultCode::Failed;
        result.errorNumber = errno;
        return result;
    }
    if (!S_ISDIR(directoryInfo.st_mode) || directoryInfo.st_uid != geteuid() ||
        (directoryInfo.st_mode & 0077) != 0)
        return result;

    const int fd = openat(directoryFd, name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
    {
        result.errorNumber = errno;
        result.code = errno == EEXIST ? ResultCode::AlreadyExists : ResultCode::Failed;
        return result;
    }
    result.fileCreated = 1;

    struct stat fileInfo;
    if (fstat(fd, &fileInfo) != 0)
    {
        result.code = ResultCode::Failed;
        result.errorNumber = errno;
        close(fd);
        return result;
    }
    if (!S_ISREG(fileInfo.st_mode) || fileInfo.st_uid != geteuid() || fileInfo.st_nlink != 1)
    {
        result.code = ResultCode::Failed;
        result.errorNumber = EPERM;
        close(fd);
        return result;
    }
    if (fchmod(fd, 0600) != 0)
    {
        result.code = ResultCode::Failed;
        result.errorNumber = errno;
        close(fd);
        return result;
    }

    Digest digest;
    if (!digest.Ready())
    {
        result.code = ResultCode::Failed;
        result.errorNumber = ENOMEM;
        close(fd);
        return result;
    }

    unsigned char header[kFixedHeaderBytes] = {};
    memcpy(header, "DCCJ", 4);
    Put16(header + 4, kFormatVersion);
    Put16(header + 6, kFixedHeaderBytes);
    Put32(header + 8, info->frameCount);
    Put32(header + 12, info->frameBytes);
    uint32_t flags = 1; // transport stopped is a required caller precondition
    if (info->overflow) flags |= 2;
    if (info->incomplete) flags |= 4;
    if (info->complete) flags |= 8;
    Put32(header + 16, flags);

    unsigned char sessionRecord[8 + kSessionFixedBytes + 511] = {};
    memcpy(sessionRecord, "SES1", 4);
    Put32(sessionRecord + 4, kSessionFixedBytes + pathBytes);
    unsigned char* metadata = sessionRecord + 8;
    Put32(metadata, session->localMember);
    Put32(metadata + 4, session->peerMember);
    Put32(metadata + 8, session->tlsVersion);
    metadata[12] = session->peerCertificateVerified;
    metadata[13] = session->sessionReused;
    Put64(metadata + 16, session->processId);
    Put64(metadata + 24, session->processStartTicks);
    Put64(metadata + 32, session->executableDevice);
    Put64(metadata + 40, session->executableInode);
    Put64(metadata + 48, session->executableBytes);
    memcpy(metadata + 56, session->runId, 16);
    memcpy(metadata + 72, session->manifestSha256, 32);
    memcpy(metadata + 104, session->localIncarnation, 16);
    memcpy(metadata + 120, session->peerIncarnation, 16);
    memcpy(metadata + 136, session->peerCertificateSha256, 32);
    Put16(metadata + 168, pathBytes);
    memcpy(metadata + kSessionFixedBytes, session->executablePath, pathBytes);
    const size_t sessionRecordBytes = 8 + kSessionFixedBytes + pathBytes;

    bool ok = WriteHashed(fd, digest, header, sizeof(header), &result.bytesWritten) &&
        WriteHashed(fd, digest, sessionRecord, sessionRecordBytes, &result.bytesWritten);
    for (uint32_t i = 0; ok && i != info->frameCount; ++i)
    {
        const FrameMeta& row = rows[i];
        unsigned char record[kFrameRecordBytes] = {};
        memcpy(record, "FRM1", 4);
        Put32(record + 4, row.byteOffset);
        Put16(record + 8, row.frameBytes);
        Put16(record + 10, row.kind);
        Put64(record + 12, row.outerSequence);
        record[20] = row.direction;
        record[21] = row.duplicateAccepted;
        memcpy(record + 24, row.frameSha256, 32);
        ok = WriteHashed(fd, digest, record, sizeof(record), &result.bytesWritten) &&
            WriteHashed(fd, digest, frames + row.byteOffset, row.frameBytes, &result.bytesWritten);
    }

    unsigned char bodyDigest[32];
    if (ok) ok = digest.Finish(bodyDigest);
    unsigned char footer[kFooterBytes] = {};
    if (ok)
    {
        memcpy(footer, "ENDJ", 4);
        footer[4] = info->complete ? kSourceComplete : kSourceIncomplete;
        Put32(footer + 8, info->frameCount);
        Put32(footer + 12, info->frameBytes);
        memcpy(footer + 16, bodyDigest, sizeof(bodyDigest));
        ok = WriteAll(fd, footer, sizeof(footer), &result.bytesWritten);
    }

    if (ok && fsync(fd) != 0) { ok = false; result.errorNumber = errno; }
    if (close(fd) != 0 && ok) { ok = false; result.errorNumber = errno; }
    if (!ok)
    {
        result.code = ResultCode::Failed;
        if (result.errorNumber == 0) result.errorNumber = errno != 0 ? errno : EIO;
        return result; // Preserve the no-clobber incomplete file for diagnosis.
    }
    if (fsync(directoryFd) != 0)
    {
        result.code = ResultCode::Failed;
        result.errorNumber = errno;
        return result; // Content may exist; durability was not established.
    }

    result.code = info->complete ? ResultCode::StoredComplete : ResultCode::StoredIncomplete;
    return result;
}

} // namespace custody
} // namespace dcg01_raw

#endif // DCG01_RAW_FRAME_CUSTODY_H
